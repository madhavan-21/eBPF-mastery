package main

// Series 03: Block Device Latency Profiler
// User-space loader and interactive monitor.
//
// Attaches kprobes to: blk_account_io_start + blk_account_io_done
// Reads histograms from: latencies (ARRAY map, 64 buckets)
//
// CLI commands: clear, show, device, exit

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	log.Println("==================================================")
	log.Println("  eBPF Mastery Series: Lesson 03 — I/O Profiler  ")
	log.Println("==================================================")

	// Remove kernel memory lock limit (needed on kernels <5.11)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Remove memlock: %v", err)
	}

	// Load the compiled eBPF ELF object file
	spec, err := ebpf.LoadCollectionSpec("main.bpf.o")
	if err != nil {
		log.Fatalf("Load spec from main.bpf.o: %v\nHave you run 'make' first?", err)
	}

	// Load all programs and maps into the running kernel
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Load collection: %v", err)
	}
	defer coll.Close()

	// Extract program handles from the loaded collection
	progStart := coll.Programs["trace_io_start"]
	progDone  := coll.Programs["trace_io_done"]
	if progStart == nil || progDone == nil {
		log.Fatal("BPF programs not found — check SEC() names in main.bpf.c")
	}

	// Extract map handles
	latMap  := coll.Maps["latencies"]
	readMap := coll.Maps["read_lat"]
	if latMap == nil || readMap == nil {
		log.Fatal("BPF maps not found — check map names in main.bpf.c")
	}

	// ── Attach kprobe to blk_account_io_start ────────────────────────────
	// If this fails with "no such function", check /proc/kallsyms:
	//   sudo cat /proc/kallsyms | grep blk_account
	kpStart, err := link.Kprobe("blk_account_io_start", progStart, nil)
	if err != nil {
		log.Fatalf("kprobe attach (blk_account_io_start): %v\n"+
			"Try: sudo cat /proc/kallsyms | grep blk_account to find the correct name", err)
	}
	defer kpStart.Close()

	// ── Attach kprobe to blk_account_io_done ─────────────────────────────
	kpDone, err := link.Kprobe("blk_account_io_done", progDone, nil)
	if err != nil {
		log.Fatalf("kprobe attach (blk_account_io_done): %v", err)
	}
	defer kpDone.Close()

	log.Println("✔ kprobes attached. Histogram auto-refreshes every 2 seconds.")
	log.Println("")
	log.Println("Generate I/O to see results:")
	log.Println("  dd if=/dev/urandom of=/tmp/test.bin bs=1M count=100")
	log.Println("")
	log.Println("Commands:")
	log.Println("  show    — Print histogram immediately")
	log.Println("  clear   — Reset all histogram counters")
	log.Println("  reads   — Show read-only histogram")
	log.Println("  exit    — Detach kprobes and quit")
	log.Println("──────────────────────────────────────────────────────────────")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// ── Auto-print histogram every 2 seconds ─────────────────────────────
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// ── Interactive CLI goroutine ─────────────────────────────────────────
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("\n> ")
			if !scanner.Scan() {
				break
			}
			cmd := strings.TrimSpace(scanner.Text())
			switch cmd {
			case "show":
				printHistogram(latMap, "Combined I/O Latency")
			case "reads":
				printHistogram(readMap, "Read Latency")
			case "clear":
				clearHistogram(latMap)
				clearHistogram(readMap)
				fmt.Println("✔ All histogram counters reset to zero.")
			case "exit", "quit":
				sigChan <- syscall.SIGTERM
				return
			default:
				if cmd != "" {
					fmt.Println("Commands: show, clear, reads, exit")
				}
			}
		}
	}()

	// ── Main event loop ───────────────────────────────────────────────────
	for {
		select {
		case <-ticker.C:
			printHistogram(latMap, "Block I/O Latency Histogram")
		case <-sigChan:
			fmt.Println("\nDetaching kprobes...")
			fmt.Println("\n── Final Histogram ──")
			printHistogram(latMap, "Combined I/O Latency")
			fmt.Println("Goodbye!")
			return
		}
	}
}

// printHistogram reads all 64 buckets from the given map and renders
// a scaled ASCII bar chart showing the latency distribution.
func printHistogram(m *ebpf.Map, title string) {
	counts := make([]uint64, 64)
	var maxCount uint64

	for i := uint32(0); i < 64; i++ {
		_ = m.Lookup(&i, &counts[i])
		if counts[i] > maxCount {
			maxCount = counts[i]
		}
	}

	if maxCount == 0 {
		fmt.Printf("\n[%s] No I/O recorded yet.\n", title)
		fmt.Println("  Tip: dd if=/dev/urandom of=/tmp/test.bin bs=1M count=50")
		return
	}

	fmt.Printf("\n── %s ──\n", title)
	fmt.Printf("%-10s %-12s %s\n", "Latency", "Count", "Distribution")
	fmt.Println(strings.Repeat("─", 65))

	for i := uint32(0); i < 64; i++ {
		if counts[i] == 0 {
			continue
		}
		// Scale bar to max width 40 characters
		barLen := int(counts[i] * 40 / maxCount)
		if barLen == 0 && counts[i] > 0 {
			barLen = 1 // Always show at least one block for non-zero
		}
		bar := strings.Repeat("█", barLen)

		// Add a note for tail latency outliers (>20ms)
		note := ""
		if i >= 20 {
			note = " ← tail latency outlier"
		}
		fmt.Printf("[%3d ms]   %-12d %s%s\n", i, counts[i], bar, note)
	}
}

// clearHistogram resets all 64 buckets to zero.
func clearHistogram(m *ebpf.Map) {
	var zero uint64
	for i := uint32(0); i < 64; i++ {
		_ = m.Update(&i, &zero, ebpf.UpdateExist)
	}
}
