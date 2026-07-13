package main

// Series 07: LRU Connection Tracker
// Commands: top, stats, exit

import (
	"bufio"
	"encoding/binary"
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

type FlowKey struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
}

type FlowStats struct {
	Packets    uint64
	Bytes      uint64
	LastSeenNs uint64
}

func ip4(n uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, n)
	return net.IP(b).String()
}

func main() {
	log.Println("=================================================")
	log.Println("  eBPF Mastery: Lesson 07 — LRU ConnTrack       ")
	log.Println("=================================================")

	if err := rlimit.RemoveMemlock(); err != nil { log.Fatalf("%v", err) }

	spec, err := ebpf.LoadCollectionSpec("main.bpf.o")
	if err != nil { log.Fatalf("Load: %v", err) }
	coll, err := ebpf.NewCollection(spec)
	if err != nil { log.Fatalf("Collection: %v", err) }
	defer coll.Close()

	iface, _ := net.InterfaceByName("lo")
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs["track_flows"],
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil { log.Fatalf("XDP attach: %v", err) }
	defer l.Close()

	flowMap := coll.Maps["flows"]
	metMap  := coll.Maps["metrics"]
	n       := runtime.NumCPU()

	log.Println("Tracking flows on lo. Commands: top, stats, exit")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("\n> ")
			if !sc.Scan() { break }
			switch strings.TrimSpace(sc.Text()) {
			case "top":   showTopFlows(flowMap)
			case "stats": showMetrics(metMap, n)
			case "exit":  sigChan <- syscall.SIGTERM
			}
		}
	}()

	for {
		select {
		case <-ticker.C: showMetrics(metMap, n)
		case <-sigChan:
			fmt.Println("\nFinal flow table:")
			showTopFlows(flowMap)
			return
		}
	}
}

func showTopFlows(m *ebpf.Map) {
	fmt.Printf("\n%-20s %-20s %-8s %-12s\n", "SRC", "DST", "PKTS", "BYTES")
	fmt.Println(strings.Repeat("─", 65))
	var k FlowKey
	var v FlowStats
	count := 0
	iter := m.Iterate()
	for iter.Next(&k, &v) && count < 10 {
		src := fmt.Sprintf("%s:%d", ip4(k.SrcIP), k.SrcPort)
		dst := fmt.Sprintf("%s:%d", ip4(k.DstIP), k.DstPort)
		fmt.Printf("%-20s %-20s %-8d %-12d\n", src, dst, v.Packets, v.Bytes)
		count++
	}
}

func showMetrics(m *ebpf.Map, n int) {
	labels := []string{"Total packets", "Flows updated", "New flows"}
	fmt.Println("\n── XDP Metrics ──")
	for i, l := range labels {
		idx := uint32(i)
		vals := make([]uint64, n)
		_ = m.Lookup(&idx, &vals)
		var total uint64
		for _, v := range vals { total += v }
		fmt.Printf("  %-20s: %d\n", l, total)
	}
}
