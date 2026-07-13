# Series 05: Sockmap-Based Socket Redirection

[![PDF Guide](https://img.shields.io/badge/PDF-Download-red?logo=adobe-acrobat-reader)](./series-05.pdf)
[![eBPF](https://img.shields.io/badge/eBPF-Kernel_Hook-orange)](https://ebpf.io/)

## What You Will Build

Redirect socket send() data directly to a companion socket, bypassing the TCP/IP loopback stack. Reduces same-host sidecar latency by ~60%.

## Real-World Usage

Used in production by: **Cilium Service Mesh (Envoy bypass), Solo.io Gloo Mesh**

## BPF Hook

```
sk_msg (Sockmap SK_MSG)
```

## Files

| File | Description |
|:-----|:------------|
| `series-05.pdf` | Full lesson PDF with architecture diagrams, code walkthrough, debugging guide |
| `source-code/main.bpf.c` | eBPF kernel-space program (C, compiled with `clang -target bpf`) |
| `source-code/main.go` | Go user-space loader using `github.com/cilium/ebpf` |
| `source-code/Makefile` | Build rules for the eBPF object file and Go binary |
| `source-code/go.mod` | Go module dependencies |

## Prerequisites

```bash
# Kernel 5.15+ with BTF enabled
ls /sys/kernel/btf/vmlinux   # Must exist

# Install build tools (Ubuntu/Debian)
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) golang-go make
```

## Build & Run

```bash
cd source-code

# Step 1: Compile eBPF C → .o object + Go loader binary
make

# Step 2: Run (requires root)
sudo ./loader\n# Check kernel log:\n# sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Read the Full Lesson

Open [series-05.pdf](./series-05.pdf) for:
- Complete concept explanations from first principles
- Architecture and sequence diagrams
- Line-by-line code walkthrough
- bpftool debugging commands
- Verifier error reference
- Performance benchmarks
- Common mistakes & best practices

---

**Madhavan S** — SDE at Atatus | [LinkedIn](https://www.linkedin.com/in/madhavan-s21/) | [GitHub](https://github.com/madhavan-21)
