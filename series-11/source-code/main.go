package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	log.Println("=================================================")
	log.Println("  eBPF Mastery: Lesson 11 — TC Rate Limiter      ")
	log.Println("=================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("memlock: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("main.bpf.o")
	if err != nil {
		log.Fatalf("Load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["rate_limiter"]
	pktMap := coll.Maps["pkt_count"]
	metMap := coll.Maps["metrics"]
	numCPUs := runtime.NumCPU()

	iface := "lo"

	// Setup clsact qdisc
	exec.Command("tc", "qdisc", "del", "dev", iface, "clsact").Run()
	if out, err := exec.Command("tc", "qdisc", "add", "dev", iface, "clsact").CombinedOutput(); err != nil {
		log.Fatalf("tc qdisc add: %s %v", out, err)
	}

	// Pin and attach
	pinPath := "/sys/fs/bpf/rate_limiter"
	os.Remove(pinPath)
	if err := prog.Pin(pinPath); err != nil {
		log.Fatalf("Pin: %v", err)
	}
	defer os.Remove(pinPath)

	fd := prog.FD()
	cmd := exec.Command("tc", "filter", "add", "dev", iface, "egress",
		"bpf", "da", "fd", fmt.Sprintf("%d", fd), "name", "rate_limiter")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Fatalf("tc filter add: %s %v", out, err)
	}
	defer exec.Command("tc", "qdisc", "del", "dev", iface, "clsact").Run()

	log.Printf("TC rate limiter on %s egress. Limit: 100 pkts/interval\n", iface)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			showMetrics(metMap, numCPUs)
			showRates(pktMap)
			resetCounters(pktMap)
		case <-sigChan:
			fmt.Println("\nDetaching. Goodbye!")
			return
		}
	}
}

func showMetrics(m *ebpf.Map, n int) {
	labels := []string{"Total packets", "Dropped packets"}
	fmt.Println("\n── TC Metrics ──")
	for i, l := range labels {
		idx := uint32(i)
		vals := make([]uint64, n)
		_ = m.Lookup(&idx, &vals)
		var total uint64
		for _, v := range vals {
			total += v
		}
		fmt.Printf("  %-20s: %d\n", l, total)
	}
}

func showRates(m *ebpf.Map) {
	fmt.Println("\n── Per-IP Packet Counts ──")
	var key uint32
	var val uint64
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, key)
		fmt.Printf("  %s: %d pkts\n", ip.String(), val)
	}
}

func resetCounters(m *ebpf.Map) {
	var key uint32
	var val uint64
	var keys []uint32
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		m.Delete(&k)
	}
}
