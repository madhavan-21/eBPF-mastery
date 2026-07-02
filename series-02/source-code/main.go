package main

// Series 02: Tracepoint-Based Execve Auditor
// User-space loader & interactive monitor using the cilium/ebpf library.
//
// Attaches to: tracepoint/syscalls/sys_enter_execve
// Reads events via: Perf Event Array (per-CPU ring buffers)
// CLI commands: watchuid, unwatchuid, stats, clear, exit

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// ─────────────────────────────────────────────────────────────────────────────
// Event struct — must match the C struct event_t layout byte-for-byte.
// C struct uses explicit __u32 _pad between uid and comm[], so we mirror that.
// ─────────────────────────────────────────────────────────────────────────────
type Event struct {
	PID      uint32
	PPID     uint32
	UID      uint32
	_        uint32   // mirrors __u32 _pad in C struct (alignment padding)
	Comm     [16]byte
	Filename [256]byte
}

// Counter indices — must match #define values in main.bpf.c
const (
	CtrTotal    = 0
	CtrEmitted  = 1
	CtrFiltered = 2
)

// filterActiveSentinel is the key stored in uid_filter to mark it as "active".
// The eBPF program checks for key 0xFFFFFFFF to know if filtering is on.
const filterActiveSentinel = uint32(0xFFFFFFFF)

func main() {
	log.Println("==================================================")
	log.Println("  eBPF Mastery Series: Lesson 02 — Execve Auditor")
	log.Println("==================================================")

	// Remove the kernel memory lock limit (needed for older kernels <5.11)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load the compiled eBPF ELF object file
	spec, err := ebpf.LoadCollectionSpec("main.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF spec from main.bpf.o: %v\nHave you run 'make' first?", err)
	}

	// Load all programs and maps into the kernel
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to instantiate eBPF collection: %v", err)
	}
	defer coll.Close()

	// Extract program handles
	prog := coll.Programs["trace_execve"]
	if prog == nil {
		log.Fatal("eBPF program 'trace_execve' not found in object file")
	}

	// Extract map handles
	eventsMap   := coll.Maps["events"]
	uidFilter   := coll.Maps["uid_filter"]
	countersMap := coll.Maps["counters"]

	if eventsMap == nil || uidFilter == nil || countersMap == nil {
		log.Fatal("One or more required BPF maps not found. Check map names in main.bpf.c")
	}

	// ── Attach to the tracepoint ──────────────────────────────────────────
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint syscalls/sys_enter_execve: %v", err)
	}
	defer func() {
		log.Println("Detaching tracepoint...")
		tp.Close()
	}()

	log.Println("Tracepoint attached to sys_enter_execve successfully!")

	// ── Create Perf reader — 16 pages per-CPU buffer ──────────────────────
	rd, err := perf.NewReader(eventsMap, os.Getpagesize()*16)
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}
	defer rd.Close()

	numCPUs := runtime.NumCPU()

	// ── Print column header ───────────────────────────────────────────────
	fmt.Printf("\n%-7s %-7s %-5s %-16s %s\n", "PID", "PPID", "UID", "COMM", "PATH")
	fmt.Println(strings.Repeat("─", 80))

	// ── Background: stream events from perf buffer ────────────────────────
	go func() {
		var ev Event
		for {
			record, err := rd.Read()
			if err != nil {
				if perf.IsClosed(err) {
					return
				}
				log.Printf("perf read error: %v", err)
				continue
			}

			// LostSamples > 0 means the per-CPU ring buffer overflowed.
			// Increase the buffer size (os.Getpagesize()*16 → *64) if this fires often.
			if record.LostSamples > 0 {
				log.Printf("⚠  Lost %d events — perf buffer overflow! Consider increasing buffer size.\n", record.LostSamples)
				continue
			}

			// Deserialize raw bytes into the Event struct using little-endian byte order
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ev); err != nil {
				continue
			}

			comm     := string(bytes.TrimRight(ev.Comm[:], "\x00"))
			filename := string(bytes.TrimRight(ev.Filename[:], "\x00"))

			fmt.Printf("%-7d %-7d %-5d %-16s %s\n",
				ev.PID, ev.PPID, ev.UID, comm, filename)
		}
	}()

	// ── Background: print stats every 5 seconds ───────────────────────────
	stopStats := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				printStats(countersMap, numCPUs)
			case <-stopStats:
				return
			}
		}
	}()

	// ── Interactive CLI ───────────────────────────────────────────────────
	log.Println("")
	log.Println("Commands:")
	log.Println("  watchuid   <uid>  — Only show execve events from this UID")
	log.Println("  unwatchuid <uid>  — Remove a UID from the watch filter")
	log.Println("  clearfilter       — Remove all UID filters (monitor everyone)")
	log.Println("  stats             — Print event counters")
	log.Println("  exit              — Detach and quit")
	log.Println("──────────────────────────────────────────────────────────────")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("\n> ")
			if !scanner.Scan() {
				break
			}
			input := strings.TrimSpace(scanner.Text())
			if input == "" {
				continue
			}

			parts := strings.Fields(input)
			cmd   := strings.ToLower(parts[0])

			switch cmd {
			case "exit", "quit":
				sigChan <- syscall.SIGTERM
				return

			case "watchuid":
				if len(parts) < 2 {
					fmt.Println("Usage: watchuid <uid>")
					continue
				}
				uid, err := strconv.ParseUint(parts[1], 10, 32)
				if err != nil {
					fmt.Printf("Invalid UID: %v\n", err)
					continue
				}
				key := uint32(uid)
				val := uint8(1)
				if err := uidFilter.Put(&key, &val); err != nil {
					fmt.Printf("Failed to add UID %d to filter: %v\n", uid, err)
					continue
				}
				// Mark filter as active by inserting sentinel key
				sentinelKey := filterActiveSentinel
				sentinelVal := uint8(1)
				_ = uidFilter.Put(&sentinelKey, &sentinelVal)
				fmt.Printf("✔ Now watching execve events from UID %d only.\n", uid)

			case "unwatchuid":
				if len(parts) < 2 {
					fmt.Println("Usage: unwatchuid <uid>")
					continue
				}
				uid, err := strconv.ParseUint(parts[1], 10, 32)
				if err != nil {
					fmt.Printf("Invalid UID: %v\n", err)
					continue
				}
				key := uint32(uid)
				if err := uidFilter.Delete(&key); err != nil {
					fmt.Printf("UID %d not in filter (already removed?): %v\n", uid, err)
				} else {
					fmt.Printf("✔ Removed UID %d from watch filter.\n", uid)
				}

			case "clearfilter":
				// Iterate and delete all entries including the sentinel
				var k, v uint32
				iter := uidFilter.Iterate()
				var keys []uint32
				for iter.Next(&k, &v) {
					keys = append(keys, k)
				}
				for _, key := range keys {
					_ = uidFilter.Delete(&key)
				}
				fmt.Println("✔ All UID filters cleared. Monitoring all processes.")

			case "stats":
				printStats(countersMap, numCPUs)

			default:
				fmt.Printf("Unknown command: %q. Type 'exit' to quit.\n", cmd)
			}
		}
	}()

	// Wait for Ctrl+C or SIGTERM
	<-sigChan
	fmt.Println("\nExiting. Cleaning up...")
	close(stopStats)
	rd.Close()
	time.Sleep(50 * time.Millisecond)

	// Final stats
	fmt.Println("\n── Final Statistics ──")
	printStats(countersMap, numCPUs)
	fmt.Println("Goodbye!")
}

// printStats reads the per-CPU counters and prints aggregated totals.
// Per-CPU maps return one value per CPU — we sum them to get the global total.
func printStats(m *ebpf.Map, numCPUs int) {
	labels := []string{"Total seen", "Emitted to user-space", "Filtered (UID filter)"}
	indices := []uint32{CtrTotal, CtrEmitted, CtrFiltered}

	fmt.Println("\n── Event Counters ──")
	for i, idx := range indices {
		values := make([]uint64, numCPUs)
		if err := m.Lookup(&idx, &values); err != nil {
			fmt.Printf("  %s: <read error: %v>\n", labels[i], err)
			continue
		}
		var total uint64
		for _, v := range values {
			total += v
		}
		fmt.Printf("  %-28s: %d\n", labels[i], total)
	}
	fmt.Println()
}
