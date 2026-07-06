package main

// Series 04: Uprobe-Based SSL/TLS Plaintext Interceptor
// Attaches to SSL_write in the system libssl.so to capture plaintext
// HTTP request bodies BEFORE they are encrypted.
//
// Usage: sudo ./loader [--lib /path/to/libssl.so]
// Commands: stats, filter <pid>, clear, exit

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

const maxDataSize = 4096

// TLSEvent must match struct tls_event in main.bpf.c byte-for-byte.
type TLSEvent struct {
	PID     uint32
	UID     uint32
	DataLen uint32
	Comm    [16]byte
	Data    [maxDataSize]byte
}

func main() {
	libPath := flag.String("lib", "/usr/lib/x86_64-linux-gnu/libssl.so.3", "Path to libssl.so")
	flag.Parse()

	log.Println("==================================================")
	log.Println("  eBPF Mastery: Lesson 04 — SSL Plaintext Monitor")
	log.Println("==================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Remove memlock: %v", err)
	}

	// Find SSL_write symbol offset in the ELF binary
	offset, err := findSymbolOffset(*libPath, "SSL_write")
	if err != nil {
		log.Fatalf("Cannot find SSL_write in %s: %v\nTry: ldconfig -p | grep libssl", *libPath, err)
	}
	log.Printf("Found SSL_write at offset 0x%x in %s", offset, *libPath)

	// Load eBPF collection
	spec, err := ebpf.LoadCollectionSpec("main.bpf.o")
	if err != nil {
		log.Fatalf("Load spec: %v — run 'make' first", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Load collection: %v", err)
	}
	defer coll.Close()

	prog     := coll.Programs["capture_ssl_write"]
	evMap    := coll.Maps["events"]
	ctrMap   := coll.Maps["counters"]

	// Open the ELF binary and attach uprobe at the computed offset
	ex, err := link.OpenExecutable(*libPath)
	if err != nil {
		log.Fatalf("OpenExecutable: %v", err)
	}
	up, err := ex.Uprobe("SSL_write", prog, &link.UprobeOptions{Offset: offset})
	if err != nil {
		log.Fatalf("Uprobe attach: %v", err)
	}
	defer up.Close()
	log.Printf("Uprobe attached to SSL_write. Capturing plaintext TLS writes...")

	// Create perf reader
	rd, err := perf.NewReader(evMap, os.Getpagesize()*16)
	if err != nil {
		log.Fatalf("Perf reader: %v", err)
	}
	defer rd.Close()

	numCPUs := runtime.NumCPU()

	log.Println("")
	log.Println("Commands: stats, exit")
	log.Println("──────────────────────────────────────────────────────────")
	fmt.Printf("\n%-7s %-5s %-16s %s\n", "PID", "UID", "COMM", "DATA (first 80 chars)")
	fmt.Println(strings.Repeat("─", 80))

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Stream events
	go func() {
		var ev TLSEvent
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) { return }
				continue
			}
			if rec.LostSamples > 0 {
				log.Printf("⚠ Lost %d events — increase perf buffer size", rec.LostSamples)
				continue
			}
			if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &ev); err != nil {
				continue
			}
			comm := string(bytes.TrimRight(ev.Comm[:], "\x00"))
			data := string(bytes.TrimRight(ev.Data[:ev.DataLen], "\x00"))
			if len(data) > 80 { data = data[:80] + "…" }
			// Replace newlines for clean terminal output
			data = strings.ReplaceAll(data, "\n", "↵")
			data = strings.ReplaceAll(data, "\r", "")
			fmt.Printf("%-7d %-5d %-16s %s\n", ev.PID, ev.UID, comm, data)
		}
	}()

	// CLI
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("\n> ")
			if !sc.Scan() { break }
			switch strings.TrimSpace(sc.Text()) {
			case "stats":
				printStats(ctrMap, numCPUs)
			case "exit", "quit":
				sigChan <- syscall.SIGTERM
			}
		}
	}()

	<-sigChan
	fmt.Println("\nDetaching uprobe...")
	printStats(ctrMap, numCPUs)
	time.Sleep(50 * time.Millisecond)
	fmt.Println("Goodbye!")
}

func printStats(m *ebpf.Map, n int) {
	labels := []string{"Intercepted", "Read errors"}
	for i, lbl := range labels {
		idx := uint32(i)
		vals := make([]uint64, n)
		_ = m.Lookup(&idx, &vals)
		var total uint64
		for _, v := range vals { total += v }
		fmt.Printf("  %-20s: %d\n", lbl, total)
	}
}

// findSymbolOffset reads the ELF dynamic symbol table to find the offset of a symbol.
func findSymbolOffset(path, sym string) (uint64, error) {
	f, err := elf.Open(path)
	if err != nil { return 0, err }
	defer f.Close()
	syms, err := f.DynamicSymbols()
	if err != nil { return 0, err }
	for _, s := range syms {
		if s.Name == sym { return s.Value, nil }
	}
	return 0, fmt.Errorf("symbol %q not found", sym)
}
