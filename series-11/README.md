# Series 11: TC Traffic Classifier & Rate Limiting

[![PDF Guide](https://img.shields.io/badge/PDF-Download-red?logo=adobe-acrobat-reader)](./series-11.pdf)
[![eBPF](https://img.shields.io/badge/eBPF-Kernel_Hook-orange)](https://ebpf.io/)

## What You Will Build

Attach an eBPF classifier to the TC `clsact` egress hook to shape outbound traffic on both ingress and egress paths — something XDP cannot do. Count packets per source IP in a BPF hash map (10,000 entries) and drop anything over 100 pkts/interval with `TC_ACT_SHOT`, otherwise forward with `TC_ACT_OK`. Track total vs dropped packets in a lockless per-CPU metrics array and print live per-IP rates from a Go loader that manages the qdisc itself.

## Real-World Usage

Used in production by: **Cilium Bandwidth Manager, Meta Katran**

## BPF Hook

```
TC (Traffic Control)
```

## Files

| File | Description |
|:-----|:------------|
| `series-11.pdf` | Full lesson PDF with architecture diagrams, code walkthrough, debugging guide |
| `source-code/main.bpf.c` | eBPF kernel-space program (C, compiled with `clang -target bpf`) |
| `source-code/main.go` | Go user-space loader using `github.com/cilium/ebpf` |
| `source-code/Makefile` | Build rules for the eBPF object file and Go binary |
| `source-code/go.mod` | Go module dependencies |

## Prerequisites

```bash
# Kernel 4.1+ with TC eBPF (BPF_PROG_TYPE_SCHED_CLS) and clsact qdisc support
ls /sys/kernel/btf/vmlinux   # BTF present (helps the verifier; recommended)

# Install build tools (Ubuntu/Debian)
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) golang-go make iproute2
```

## Build & Run

```bash
cd source-code

# Step 1: Compile eBPF C → .o object + Go loader binary
make

# Step 2: Run (requires root). The loader sets up the clsact qdisc
# and attaches the classifier to the lo egress hook itself — no manual tc needed.
sudo ./loader

# Step 3: In another terminal, flood lo egress to trip the 100-pkt limit.
# Watch the per-IP count cap at 100 while the extras are dropped via TC_ACT_SHOT.
sudo ping -f -c 500 127.0.0.1
```

## Read the Full Lesson

Open [series-11.pdf](./series-11.pdf) for:
- Complete concept explanations from first principles
- Architecture and sequence diagrams
- Line-by-line code walkthrough
- bpftool debugging commands
- Verifier error reference
- Performance benchmarks
- Common mistakes & best practices

---

**Madhavan S** — SDE at Atatus | [LinkedIn](https://www.linkedin.com/in/madhavan-s21/) | [GitHub](https://github.com/madhavan-21)
