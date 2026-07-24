// Series 11: TC Traffic Classifier & Rate Limiter
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define RATE_LIMIT 100  // Max packets per interval per source IP

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u64);
} pkt_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} metrics SEC(".maps");

static __always_inline void inc_metric(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&metrics, &idx);
    if (v) __sync_fetch_and_add(v, 1);
}

SEC("tc")
int rate_limiter(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __u32 src_ip = iph->saddr;
    inc_metric(0); // Total packets seen

    __u64 *count = bpf_map_lookup_elem(&pkt_count, &src_ip);
    if (count) {
        if (*count >= RATE_LIMIT) {
            inc_metric(1); // Dropped packets
            return TC_ACT_SHOT;
        }
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init_val = 1;
        bpf_map_update_elem(&pkt_count, &src_ip, &init_val, BPF_ANY);
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
