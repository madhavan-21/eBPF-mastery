# eBPF Mastery Series 🐝

> **The open-source eBPF learning platform** — from absolute beginner to production-level kernel engineering.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![eBPF](https://img.shields.io/badge/eBPF-Powered-orange)](https://ebpf.io/)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org/)
[![Kernel](https://img.shields.io/badge/Linux-5.15+-FCC624?logo=linux)](https://kernel.org/)

---

## About This Repository

This repository contains the **complete source code and PDF guides** for the eBPF Mastery Series — a curriculum covering real-world eBPF engineering from fundamentals to production-level patterns used at companies like **Meta, Cloudflare, Cilium, Netflix, and Datadog**.

Each series is a self-contained module with:
- 📄 **PDF Guide** — in-depth lesson with architecture diagrams, code walkthroughs, and debugging guides
- 💻 **Source Code** — compile-ready eBPF C program (`main.bpf.c`) + Go loader (`main.go`)
- 🛠 **Makefile** — one-command build

---

## Series Index

| # | Title | Topic | PDF |
|:--|:------|:------|:----|
| 01 | **XDP DDoS Mitigation & Dynamic IP Blocklisting** | XDP, Hash Maps, Per-CPU | [series-01.pdf](./series-01/series-01.pdf) |
| 02 | **Tracepoint-Based Execve Auditing** | Tracepoints, Perf Buffers, CO-RE | [series-02.pdf](./series-02/series-02.pdf) |
| 03 | **Kprobe-Based Block Device Latency Profiling** | Kprobes, Kretprobes, Histograms | [series-03.pdf](./series-03/series-03.pdf) |
| 04 | **Uprobe-Based SSL/TLS Plaintext Interception** | Uprobes, Uretprobes, Ring Buffers | [series-04.pdf](./series-04/series-04.pdf) |
| 05 | **Sockmap-Based Socket Redirection** | Sockmap, SK_MSG, Zero-copy IPC | [series-05.pdf](./series-05/series-05.pdf) |
| 06 | **High-Throughput Ring Buffers** | BPF Ring Buffer, Lock-free Streaming | [series-06.pdf](./series-06/series-06.pdf) |
| 07 | **LRU Hash Maps & Connection Tracking** | LRU Maps, Conntrack, XDP | [series-07.pdf](./series-07/series-07.pdf) |
| 08 | **Per-CPU Maps for Lockless Metrics** | Per-CPU Array, Cache Lines, Katran | [series-08.pdf](./series-08/series-08.pdf) |
| 09 | **Map-in-Map Dynamic Routing** | Array-of-Maps, Atomic Swaps, Cilium | [series-09.pdf](./series-09/series-09.pdf) |
| 10 | **Queue & Stack Maps for Packet Shapers** | TC BPF, Token Bucket, QoS | [series-10.pdf](./series-10/series-10.pdf) |

---

## Prerequisites

### Kernel Requirements
- Linux kernel **5.15+** (for all features including Ring Buffer)
- BTF (BPF Type Format) enabled: `CONFIG_DEBUG_INFO_BTF=y`
- Verify: `ls /sys/kernel/btf/vmlinux`

### Tools Required
```bash
# Ubuntu/Debian
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) \
                        golang-go make iproute2 bpftool

# Fedora/RHEL
sudo dnf install -y clang llvm libbpf-devel kernel-headers \
                    golang make iproute bpftool
```

### Go Module Initialization
Each series has its own `go.mod`. Run inside any `source-code/` directory:
```bash
go mod download
```

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/madhavan-21/ebpf-mastery.git
cd ebpf-mastery/series-01/source-code

# Build the eBPF object and Go loader
make

# Run (requires root — eBPF programs need CAP_BPF + CAP_NET_ADMIN)
sudo ./loader -iface lo
```

---

## Series Structure

Each series folder follows this layout:
```
series-XX/
├── series-XX.pdf          # Complete lesson PDF with diagrams and walkthroughs
└── source-code/
    ├── main.bpf.c         # eBPF kernel-space program (C, compiled with clang -target bpf)
    ├── main.go            # User-space loader and controller (Go, cilium/ebpf)
    ├── go.mod             # Go module dependencies
    └── Makefile           # Build rules: make → compiles both C and Go
```

---

## Building All Series

```bash
# Build one series
cd series-02/source-code && make

# Run with elevated privileges
sudo ./loader

# Clean build artifacts
make clean
```

---

## Real-World Production References

The techniques in this series are used in production at:

| Company | Product | Series Used |
|:--------|:--------|:------------|
| **Meta** | Katran Load Balancer | 01, 08 |
| **Cloudflare** | L4Drop / Gatekeeper | 01, 07 |
| **Cilium / Isovalent** | Cilium CNI, Tetragon | 02, 05, 07, 09 |
| **Netflix** | FlameScope, Vector | 03 |
| **Pixie (New Relic)** | Auto-Telemetry | 04 |
| **Datadog** | Agent NPM, CSPM | 02, 03, 08 |
| **Aqua Security** | Tracee | 02, 06 |
| **Falco / Sysdig** | Runtime Security | 06 |

---

## Author

**Madhavan S** — SDE at Atatus
- 🔗 LinkedIn: [linkedin.com/in/madhavan-s21](https://www.linkedin.com/in/madhavan-s21/)
- 🐙 GitHub: [github.com/madhavan-21](https://github.com/madhavan-21)

---

## License

MIT License — free to use, share, and build upon. Attribution appreciated.

---

> ⭐ If this series helped you, please star the repository and share it with your network!
