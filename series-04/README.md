# Series 04: Uprobe-Based SSL/TLS Plaintext Interception

[![PDF Guide](https://img.shields.io/badge/PDF-Download-red?logo=adobe-acrobat-reader)](./series-04.pdf)
[![eBPF](https://img.shields.io/badge/eBPF-Kernel_Hook-orange)](https://ebpf.io/)

## What You Will Build

Intercept TLS plaintext data from libssl.so before encryption (SSL_write) and after decryption (SSL_read) with uprobes — no cert injection.

## Real-World Usage

Used in production by: **Pixie auto-telemetry, Cilium L7 visibility**

## BPF Hook

```
uprobe/SSL_write + uretprobe/SSL_read
```

## Files

| File | Description |
|:-----|:------------|
| `series-04.pdf` | Full lesson PDF with architecture diagrams, code walkthrough, debugging guide |
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
sudo ./loader\n# Then in another terminal:\n# curl https://httpbin.org/get
```

## Read the Full Lesson

Open [series-04.pdf](./series-04.pdf) for:
- Complete concept explanations from first principles
- Architecture and sequence diagrams
- Line-by-line code walkthrough
- bpftool debugging commands
- Verifier error reference
- Performance benchmarks
- Common mistakes & best practices

---

**Madhavan S** — SDE at Atatus | [LinkedIn](https://www.linkedin.com/in/madhavan-s21/) | [GitHub](https://github.com/madhavan-21)
