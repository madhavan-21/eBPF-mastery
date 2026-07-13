package main

// Series 05: Sockmap-Based Socket Redirection
// Demonstrates zero-copy TCP acceleration between local sockets.
//
// Attaches:
//   sock_ops program to a cgroup (tracks active TCP connections)
//   sk_msg program to the sockmap (redirects messages)
//
// Commands: stats, exit

import (
	"bufio"
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
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	log.Println("==================================================")
	log.Println("  eBPF Mastery: Lesson 05 — Sockmap Redirection  ")
	log.Println("==================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Remove memlock: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec("main.bpf.o")
	if err != nil {
		log.Fatalf("Load spec: %v — run 'make' first", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Load collection: %v", err)
	}
	defer coll.Close()

	sockOpsMap := coll.Maps["sock_ops_map"]
	metricsMap := coll.Maps["metrics"]
	sockOpsProg := coll.Programs["track_sockets"]
	skMsgProg := coll.Programs["redirect_msg"]

	// Attach sock_ops to root cgroup — tracks all TCP sockets on the host
	cgroupPath := "/sys/fs/cgroup"
	cgroupLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: sockOpsProg,
	})
	if err != nil {
		log.Fatalf("Attach sock_ops to cgroup %s: %v", cgroupPath, err)
	}
	defer cgroupLink.Close()

	// Attach sk_msg to the sockmap — intercepts send() calls
	sockMapLink, err := link.AttachRawLink(link.RawLinkOptions{
		Program: skMsgProg,
		Attach:  ebpf.AttachSkMsgVerdict,
		Target:  sockOpsMap.FD(),
	})
	if err != nil {
		log.Fatalf("Attach sk_msg to sockmap: %v", err)
	}
	defer sockMapLink.Close()

	log.Println("Sockmap active. TCP sockets auto-registered on connect.")
	log.Println("Commands: stats, exit")
	log.Println("──────────────────────────────────────────────────────────")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	numCPUs := runtime.NumCPU()

	go func() {
		sc := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("\n> ")
			if !sc.Scan() { break }
			switch strings.TrimSpace(sc.Text()) {
			case "stats":
				printMetrics(metricsMap, numCPUs)
			case "exit", "quit":
				sigChan <- syscall.SIGTERM
			}
		}
	}()

	for {
		select {
		case <-ticker.C:
			printMetrics(metricsMap, numCPUs)
		case <-sigChan:
			fmt.Println("\nDetaching programs...")
			printMetrics(metricsMap, numCPUs)
			fmt.Println("Goodbye!")
			return
		}
	}
}

func printMetrics(m *ebpf.Map, n int) {
	labels := []string{"Messages redirected", "Bytes redirected"}
	fmt.Println("\n── Sockmap Metrics ──")
	for i, lbl := range labels {
		idx := uint32(i)
		vals := make([]uint64, n)
		_ = m.Lookup(&idx, &vals)
		var total uint64
		for _, v := range vals { total += v }
		fmt.Printf("  %-22s: %d\n", lbl, total)
	}
}
