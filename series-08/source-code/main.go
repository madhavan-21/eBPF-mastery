package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	MetricTCP   = 0
	MetricUDP   = 1
	MetricICMP  = 2
	MetricOther = 3
	MetricMax   = 4
)

func main() {
	log.Println("==================================================")
	log.Println("  eBPF Mastery: Lesson 08 — Per-CPU Metrics     ")
	log.Println("==================================================")

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

	iface, err := net.InterfaceByName("lo")
	if err != nil {
		log.Fatalf("Get lo interface: %v", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs["count_packets"],
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Attach XDP: %v", err)
	}
	defer l.Close()

	metMap := coll.Maps["metrics"]
	numCPUs := runtime.NumCPU()

	log.Println("Metrics active on lo. Commands: stats, cores, exit")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("\n> ")
			if !sc.Scan() { break }
			cmd := strings.TrimSpace(sc.Text())
			switch cmd {
			case "stats":
				printAggregatedStats(metMap, numCPUs)
			case "cores":
				printCoreBreakdown(metMap, numCPUs)
			case "exit", "quit":
				sigChan <- syscall.SIGTERM
			}
		}
	}()

	for {
		select {
		case <-ticker.C:
			printAggregatedStats(metMap, numCPUs)
		case <-sigChan:
			fmt.Println("\nDetaching program...")
			return
		}
	}
}

func printAggregatedStats(m *ebpf.Map, numCPUs int) {
	protocols := []string{"TCP", "UDP", "ICMP", "Other"}
	fmt.Println("\n── Aggregated Packet Metrics ──")
	for i, proto := range protocols {
		key := uint32(i)
		vals := make([]uint64, numCPUs)
		if err := m.Lookup(&key, &vals); err != nil {
			log.Printf("Err looking up %s: %v", proto, err)
			continue
		}
		var sum uint64
		for _, v := range vals {
			sum += v
		}
		fmt.Printf("  %-8s: %d packets\n", proto, sum)
	}
}

func printCoreBreakdown(m *ebpf.Map, numCPUs int) {
	protocols := []string{"TCP", "UDP", "ICMP", "Other"}
	fmt.Println("\n── Core-by-Core Breakdown ──")
	for i, proto := range protocols {
		key := uint32(i)
		vals := make([]uint64, numCPUs)
		_ = m.Lookup(&key, &vals)
		fmt.Printf("  %-6s: ", proto)
		for cpu, val := range vals {
			fmt.Printf("CPU %d=[%d] ", cpu, val)
		}
		fmt.Println()
	}
}
