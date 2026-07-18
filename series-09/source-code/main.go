package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	log.Println("==================================================")
	log.Println("  eBPF Mastery: Lesson 09 — Map-in-Map Routing  ")
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
		log.Fatalf("Interface: %v", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs["xdp_routing"],
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Link XDP: %v", err)
	}
	defer l.Close()

	outerMap := coll.Maps["outer_map"]

	// Create and swap routing table v1
	log.Println("Activating policy v1 (block 8.8.8.8)...")
	if err := swapPolicy(outerMap, map[string]uint32{"8.8.8.8": 1}); err != nil {
		log.Fatalf("Swap: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("\n> ")
			if !sc.Scan() { break }
			cmd := strings.TrimSpace(sc.Text())
			if cmd == "swap" {
				log.Println("Swapping atomically to policy v2 (block 1.1.1.1)...")
				_ = swapPolicy(outerMap, map[string]uint32{"1.1.1.1": 1})
			} else if cmd == "exit" {
				sigChan <- syscall.SIGTERM
			}
		}
	}()

	<-sigChan
	log.Println("Exiting...")
}

func swapPolicy(outer *ebpf.Map, rules map[string]uint32) error {
	innerSpec := &ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10240,
	}
	innerMap, err := ebpf.NewMap(innerSpec)
	if err != nil {
		return err
	}
	defer innerMap.Close()

	for ipStr, act := range rules {
		ip := binary.BigEndian.Uint32(net.ParseIP(ipStr).To4())
		if err := innerMap.Update(&ip, &act, ebpf.UpdateAny); err != nil {
			return err
		}
	}

	key := uint32(0)
	return outer.Update(&key, innerMap, ebpf.UpdateAny)
}
