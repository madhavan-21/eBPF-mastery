# Series 06: High-Throughput Ring Buffers

[![PDF Guide](https://img.shields.io/badge/PDF-Download-red?logo=adobe-acrobat-reader)](./series-06.pdf)
[![eBPF](https://img.shields.io/badge/eBPF-Kernel_Hook-orange)](https://ebpf.io/)

## What You Will Build

Stream millions of kernel events/second to user-space using the modern BPF Ring Buffer — zero-copy, lock-free, globally ordered.

## Real-World Usage

Used in production by: **Falco runtime security, Aqua Tracee, Sysdig**

## BPF Hook

```
tp/syscalls/sys_enter_openat
```

## Files

| File | Description |
|:-----|:------------|
| `series-06.pdf` | Full lesson PDF with architecture diagrams, code walkthrough, debugging guide |
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
sudo ./loader\n# Then in another terminal:\n# find / -name '*.conf' 2>/dev/null
```

## Read the Full Lesson

Open [series-06.pdf](./series-06.pdf) for:
- Complete concept explanations from first principles
- Architecture and sequence diagrams
- Line-by-line code walkthrough
- bpftool debugging commands
- Verifier error reference
- Performance benchmarks
- Common mistakes & best practices

---

**Madhavan S** — SDE at Atatus | [LinkedIn](https://www.linkedin.com/in/madhavan-s21/) | [GitHub](https://github.com/madhavan-21)
