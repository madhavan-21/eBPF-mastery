package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	log.Println("==================================================")
	log.Println("  eBPF Mastery: Lesson 10 — Queue & Stack Maps  ")
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

	queueMap := coll.Maps["packet_queue"]

	log.Println("Queue shaper active. Commands: pop, exit")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("\n> ")
			if !sc.Scan() { break }
			cmd := strings.TrimSpace(sc.Text())
			if cmd == "pop" {
				var val uint32
				err := queueMap.LookupAndDelete(nil, &val)
				if err != nil {
					fmt.Println("Queue is empty.")
				} else {
					fmt.Printf("Popped packet size: %d bytes\n", val)
				}
			} else if cmd == "exit" {
				sigChan <- syscall.SIGTERM
			}
		}
	}()

	<-sigChan
	log.Println("Exiting...")
}
