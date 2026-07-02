// Series 02: Tracepoint-Based Execve Auditor
// eBPF kernel-space program that hooks sys_enter_execve to capture
// every process execution on the host in real time.
//
// Hook: tracepoint/syscalls/sys_enter_execve
// Maps: events (PERF_EVENT_ARRAY), uid_filter (HASH), counters (PERCPU_ARRAY)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─────────────────────────────────────────────────────────────────────────────
// Shared type definitions
// ─────────────────────────────────────────────────────────────────────────────

// Event sent to user-space for every execve syscall.
// IMPORTANT: Layout must match the Go Event struct byte-for-byte.
struct event_t {
	__u32 pid;           // Thread Group ID  — the user-space process "PID"
	__u32 ppid;          // Parent process TID (via task_struct->real_parent->tgid)
	__u32 uid;           // Effective UID of the calling process
	__u32 _pad;          // Explicit 4-byte pad to keep comm[] 8-byte aligned
	char  comm[16];      // Process command name  (kernel limit: TASK_COMM_LEN = 16)
	char  filename[256]; // Full executable path from the execve argument
};

// Per-CPU counter indices
#define CTR_TOTAL   0   // Total execve events seen
#define CTR_EMITTED 1   // Events successfully pushed to perf buffer
#define CTR_FILTERED 2  // Events suppressed by UID filter

// ─────────────────────────────────────────────────────────────────────────────
// BPF Maps
// ─────────────────────────────────────────────────────────────────────────────

// Perf Event Array — high-speed per-CPU ring buffers for streaming events
// to user-space. Each CPU core writes independently (no locks).
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

// UID filter — user-space inserts UIDs to monitor; empty = monitor all.
// Key: UID (u32), Value: 1 (present = monitor this UID)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
} uid_filter SEC(".maps");

// Per-CPU counters — track total, emitted, and filtered event counts
// without any lock contention between CPU cores.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

// ─────────────────────────────────────────────────────────────────────────────
// Helper: increment a per-CPU counter by index
// ─────────────────────────────────────────────────────────────────────────────
static __always_inline void inc_counter(__u32 idx) {
	__u64 *count = bpf_map_lookup_elem(&counters, &idx);
	if (count)
		*count += 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// eBPF Program: fires at sys_enter_execve tracepoint
// ─────────────────────────────────────────────────────────────────────────────
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	// ── Step 1: Count every execve regardless of filters ─────────────────
	inc_counter(CTR_TOTAL);

	// ── Step 2: Extract the calling process's identity ───────────────────
	// bpf_get_current_pid_tgid() packs [TGID:32 | TID:32] into a u64.
	// Right-shifting by 32 extracts the TGID, which is what user-space
	// sees as the process PID (getpid() returns TGID, not TID).
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;

	// bpf_get_current_uid_gid() packs [GID:32 | UID:32] — mask low 32 bits.
	__u32 uid = (__u32)bpf_get_current_uid_gid();

	// ── Step 3: Apply UID filter ──────────────────────────────────────────
	// If the uid_filter map has entries, only report UIDs that are present.
	// If the map is empty (max_entries never exceeded), report all UIDs.
	__u8 *filter_val = bpf_map_lookup_elem(&uid_filter, &uid);

	// Attempt to determine if the map has any entries by checking a sentinel
	// key (0xFFFFFFFF) — if uid_filter is non-empty and this UID is not in it, skip.
	// A simpler approach: user-space sets a "filter active" flag in a separate map.
	// For this implementation, the absence of the UID in uid_filter means "skip"
	// only if at least one UID has been added. User-space logic handles this.
	//
	// If filter_val is NULL AND uid_filter is populated, skip.
	// We check this by looking for a "filter_active" marker at key 0xFFFFFFFF.
	__u32 sentinel = 0xFFFFFFFF;
	__u8 *active = bpf_map_lookup_elem(&uid_filter, &sentinel);
	if (active && !filter_val) {
		// uid_filter is active but this UID is not in it — skip
		inc_counter(CTR_FILTERED);
		return 0;
	}

	// ── Step 4: Build the event struct ───────────────────────────────────
	// Initialize to zero to avoid leaking kernel stack bytes in padding regions.
	struct event_t event = {};
	event.pid = pid;
	event.uid = uid;

	// Read the parent PID using CO-RE safe struct access.
	// BPF_CORE_READ patches the byte offset at load time to match the running kernel.
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	event.ppid = BPF_CORE_READ(task, real_parent, tgid);

	// Read the 16-byte process name from the kernel's task struct.
	bpf_get_current_comm(&event.comm, sizeof(event.comm));

	// ctx->args[0] is the filename pointer (first arg to execve).
	// It lives in user-space memory — must use bpf_probe_read_user_str.
	const char *filename_ptr = (const char *)ctx->args[0];
	bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename_ptr);

	// ── Step 5: Submit event to the per-CPU perf ring buffer ─────────────
	// BPF_F_CURRENT_CPU: write to the ring buffer owned by the current CPU core.
	int ret = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
	                                 &event, sizeof(event));
	if (ret == 0)
		inc_counter(CTR_EMITTED);

	return 0;
}

char _license[] SEC("license") = "GPL";
