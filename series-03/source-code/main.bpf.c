// Series 03: Block Device Latency Profiler
#include <linux/bpf.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, void *);
	__type(value, __u64);
} start_times SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} latencies SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} read_lat SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} write_lat SEC(".maps");

SEC("kprobe/blk_account_io_start")
int trace_io_start(struct pt_regs *ctx)
{
	void *req = (void *)PT_REGS_PARM1(ctx);
	__u64 ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&start_times, &req, &ts, BPF_ANY);
	return 0;
}

SEC("kprobe/blk_account_io_done")
int trace_io_done(struct pt_regs *ctx)
{
	void *req = (void *)PT_REGS_PARM1(ctx);
	__u64 *start_ts = bpf_map_lookup_elem(&start_times, &req);
	if (!start_ts)
		return 0;

	__u64 delta_ns = bpf_ktime_get_ns() - *start_ts;
	bpf_map_delete_elem(&start_times, &req);

	__u32 bucket = (__u32)(delta_ns / 1000000ULL);
	if (bucket >= 64)
		bucket = 63;

	__u64 *count = bpf_map_lookup_elem(&latencies, &bucket);
	if (count)
		__sync_fetch_and_add(count, 1);

	__u64 *rc = bpf_map_lookup_elem(&read_lat, &bucket);
	if (rc)
		__sync_fetch_and_add(rc, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
