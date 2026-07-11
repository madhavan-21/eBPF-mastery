package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type Event struct {
	PID  uint32
	UID  uint32
	Comm [16]byte
	Path [256]byte
}

func main() {
	log.Println("=================================================")
	log.Println("  eBPF Mastery: Lesson 06 — Ring Buffer Streamer")
	log.Println("=================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Remove memlock: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpec("main.bpf.o")
	if err != nil {
		log.Fatalf("Load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Load collection: %v", err)
	}
	defer coll.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", coll.Programs["trace_openat"], nil)
	if err != nil {
		log.Fatalf("Attach tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(coll.Maps["rb"])
	if err != nil {
		log.Fatalf("Ring buffer reader: %v", err)
	}
	defer rd.Close()

	dropMap := coll.Maps["drop_count"]
	numCPUs := runtime.NumCPU()

	var received uint64
	log.Println("Streaming file open events via Ring Buffer...")
	log.Println("Commands: stats, exit")
	fmt.Printf("\n%-7s %-5s %-16s %s\n", "PID", "UID", "COMM", "PATH")
	fmt.Println(strings.Repeat("─", 80))

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) { return }
				continue
			}
			if len(rec.RawSample) < int(unsafe.Sizeof(Event{})) { continue }
			e := (*Event)(unsafe.Pointer(&rec.RawSample[0]))
			received++
			comm := strings.TrimRight(string(e.Comm[:]), "\x00")
			path := strings.TrimRight(string(e.Path[:]), "\x00")
			fmt.Printf("%-7d %-5d %-16s %s\n", e.PID, e.UID, comm, path)
		}
	}()

	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("\n> ")
			if !sc.Scan() { break }
			switch strings.TrimSpace(sc.Text()) {
			case "stats":
				printStats(dropMap, numCPUs, received)
			case "exit", "quit":
				sigChan <- syscall.SIGTERM
			}
		}
	}()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			printStats(dropMap, numCPUs, received)
		case <-sigChan:
			fmt.Println("\nExiting...")
			printStats(dropMap, numCPUs, received)
			return
		}
	}
}

func printStats(m *ebpf.Map, n int, rx uint64) {
	k := uint32(0)
	vals := make([]uint64, n)
	_ = m.Lookup(&k, &vals)
	var drops uint64
	for _, v := range vals { drops += v }
	fmt.Printf("\n  Events received : %d\n  Kernel drops    : %d\n", rx, drops)
	if rx+drops > 0 {
		fmt.Printf("  Drop rate       : %.2f%%\n", float64(drops)/float64(rx+drops)*100)
	}
}
