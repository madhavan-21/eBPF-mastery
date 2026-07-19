// Series 10: Queue/Stack Packet Limiter
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 512);
    __type(value, __u32); // Packet sizes
} packet_queue SEC(".maps");

SEC("tc")
int tc_shaper(struct __sk_buff *skb) {
    __u32 len = skb->len;
    // Try to enqueue packet size
    if (bpf_map_push_elem(&packet_queue, &len, 0) != 0) {
        return TC_ACT_SHOT; // Drop packet if queue is full
    }
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
