// Series 05: Sockmap-Based Socket Redirection
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, __u32);
} sock_ops_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} metrics SEC(".maps");

SEC("sock_ops")
int track_sockets(struct bpf_sock_ops *skops)
{
    if (skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB &&
        skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
        return 0;

    __u32 key = bpf_ntohl(skops->local_port);
    bpf_sock_map_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
    return 0;
}

SEC("sk_msg")
int redirect_msg(struct sk_msg_md *msg)
{
    __u32 dest_key = bpf_ntohl(msg->remote_port);

    __u32 idx = 0;
    __u64 *cnt = bpf_map_lookup_elem(&metrics, &idx);
    if (cnt) *cnt += 1;
    idx = 1;
    __u64 *bytes = bpf_map_lookup_elem(&metrics, &idx);
    if (bytes) *bytes += msg->size;

    return bpf_msg_redirect_map(msg, &sock_ops_map, dest_key, 0);
}

char LICENSE[] SEC("license") = "GPL";
