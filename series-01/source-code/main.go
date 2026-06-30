package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
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
	ifaceName := flag.String("iface", "lo", "Network interface to attach the XDP program to")
	flag.Parse()

	log.Println("==================================================")
	log.Println("     eBPF Mastery Series: Lesson 01 - Firewall     ")
	log.Println("==================================================")

	// 1. Remove lock memory limits (necessary for older kernels)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// 2. Load the compiled eBPF ELF binary
	bpfObjPath := "main.bpf.o"
	spec, err := ebpf.LoadCollectionSpec(bpfObjPath)
	if err != nil {
		log.Fatalf("Failed to load eBPF collection spec from %s: %v\nHave you run 'make' first?", bpfObjPath, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to load collection: %v", err)
	}
	defer coll.Close()

	// 3. Extract program and maps
	program := coll.Programs["xdp_firewall"]
	if program == nil {
		log.Fatal("Failed to find XDP program: xdp_firewall")
	}

	blocklistMap := coll.Maps["blocklist"]
	if blocklistMap == nil {
		log.Fatal("Failed to find blocklist map")
	}

	metricsMap := coll.Maps["metrics"]
	if metricsMap == nil {
		log.Fatal("Failed to find metrics map")
	}

	// 4. Attach XDP program to the network interface
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Failed to find interface %s: %v", *ifaceName, err)
	}

	log.Printf("Attaching XDP program to interface: %s (Index: %d)...\n", iface.Name, iface.Index)
	
	// We use Generic/driver mode. Generic works everywhere including loopback and containers
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   program,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer func() {
		log.Println("Detaching XDP program...")
		l.Close()
	}()

	log.Println("XDP program successfully attached!")
	log.Println("Type commands to interact with the blocklist:")
	log.Println("  block <IP>   - Block an IPv4 address (e.g. block 127.0.0.1)")
	log.Println("  unblock <IP> - Unblock an IPv4 address (e.g. unblock 127.0.0.1)")
	log.Println("  list         - List all currently blocked IP addresses")
	log.Println("  exit         - Detach program and exit")
	log.Println("--------------------------------------------------")

	// Get possible CPU count for aggregating per-CPU metrics
	numCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		log.Fatalf("Failed to get CPU count: %v", err)
	}

	// 5. Start a background goroutine to poll and display packet metrics
	stopChan := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				var passCounter []uint64 = make([]uint64, numCPUs)
				var dropCounter []uint64 = make([]uint64, numCPUs)

				// Index 0 tracks PASS metrics
				if err := metricsMap.Lookup(uint32(0), &passCounter); err != nil {
					log.Printf("Error reading PASS metrics: %v", err)
					continue
				}

				// Index 1 tracks DROP metrics
				if err := metricsMap.Lookup(uint32(1), &dropCounter); err != nil {
					log.Printf("Error reading DROP metrics: %v", err)
					continue
				}

				var totalPass, totalDrop uint64
				for _, val := range passCounter {
					totalPass += val
				}
				for _, val := range dropCounter {
					totalDrop += val
				}

				fmt.Printf("\r[Metrics] Packets Accepted: %-8d | Packets Blocked/Dropped: %-8d", totalPass, totalDrop)
			case <-stopChan:
				return
			}
		}
	}()

	// 6. Handle interactive shell & exit signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Spin CLI scanner in a separate goroutine
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			fmt.Print("\n> ")
			input, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			input = strings.TrimSpace(input)
			if input == "" {
				continue
			}

			parts := strings.SplitN(input, " ", 2)
			cmd := strings.ToLower(parts[0])

			switch cmd {
			case "exit", "quit":
				sigChan <- syscall.SIGTERM
				return
			case "block":
				if len(parts) < 2 {
					fmt.Println("Usage: block <IP>")
					continue
				}
				ipStr := parts[1]
				ipBytes, err := parseIPToBytes(ipStr)
				if err != nil {
					fmt.Printf("Error: %v\n", err)
					continue
				}

				// Write value 1 (blocked) to blocklist map
				var val uint8 = 1
				if err := blocklistMap.Put(ipBytes, val); err != nil {
					fmt.Printf("Failed to block IP %s: %v\n", ipStr, err)
				} else {
					fmt.Printf("Successfully blocked IP: %s\n", ipStr)
				}

			case "unblock":
				if len(parts) < 2 {
					fmt.Println("Usage: unblock <IP>")
					continue
				}
				ipStr := parts[1]
				ipBytes, err := parseIPToBytes(ipStr)
				if err != nil {
					fmt.Printf("Error: %v\n", err)
					continue
				}

				if err := blocklistMap.Delete(ipBytes); err != nil {
					fmt.Printf("Failed to unblock IP %s (might not be in blocklist): %v\n", ipStr, err)
				} else {
					fmt.Printf("Successfully unblocked IP: %s\n", ipStr)
				}

			case "list":
				var keys [][4]byte
				var key [4]byte
				var val uint8

				iterator := blocklistMap.Iterate()
				for iterator.Next(&key, &val) {
					keys = append(keys, key)
				}

				if err := iterator.Err(); err != nil {
					fmt.Printf("Error iterating map: %v\n", err)
					continue
				}

				if len(keys) == 0 {
					fmt.Println("No IP addresses blocked currently.")
				} else {
					fmt.Println("Blocked IP Addresses:")
					for _, k := range keys {
						ip := net.IPv4(k[0], k[1], k[2], k[3])
						fmt.Printf(" - %s\n", ip.String())
					}
				}

			default:
				fmt.Println("Unknown command. Supported commands: block <IP>, unblock <IP>, list, exit")
			}
		}
	}()

	// Wait for terminate signal
	<-sigChan
	fmt.Println("\nExiting. Detaching program...")
	close(stopChan)
	// Give a split second for stats goroutine to terminate cleanly
	time.Sleep(100 * time.Millisecond)
	fmt.Println("Goodbye!")
}

// Parses an IPv4 address string into a 4-byte array preserving network byte order
func parseIPToBytes(ipStr string) ([4]byte, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return [4]byte{}, fmt.Errorf("invalid IP format")
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return [4]byte{}, fmt.Errorf("only IPv4 is supported")
	}
	var res [4]byte
	copy(res[:], ipv4)
	return res, nil
}
