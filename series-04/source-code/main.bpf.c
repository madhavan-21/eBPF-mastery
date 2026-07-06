// Series 04: Uprobe-Based SSL/TLS Plaintext Interceptor
#include <linux/bpf.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_DATA_SIZE 4096

struct tls_event {
    __u32 pid;
    __u32 uid;
    __u32 data_len;
    char  comm[16];
    char  data[MAX_DATA_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

// Per-CPU heap buffer to avoid stack limit (512 bytes)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tls_event);
} event_buf SEC(".maps");

SEC("uprobe/SSL_write")
int capture_ssl_write(struct pt_regs *ctx)
{
    __u32 zero = 0;
    struct tls_event *ev = bpf_map_lookup_elem(&event_buf, &zero);
    if (!ev) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->pid = pid_tgid >> 32;
    ev->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    __u32 num = (__u32)PT_REGS_PARM3(ctx);

    ev->data_len = num < MAX_DATA_SIZE ? num : MAX_DATA_SIZE;

    long ret = bpf_probe_read_user(ev->data, ev->data_len, buf);

    __u32 idx = (ret == 0) ? 0 : 1;
    __u64 *cnt = bpf_map_lookup_elem(&counters, &idx);
    if (cnt) *cnt += 1;

    if (ret != 0) return 0;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ev, sizeof(*ev));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
