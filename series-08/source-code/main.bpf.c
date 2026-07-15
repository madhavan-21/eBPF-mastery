// Series 08: Per-CPU Metrics Collector
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

enum {
    METRIC_TCP = 0,
    METRIC_UDP = 1,
    METRIC_ICMP = 2,
    METRIC_OTHER = 3,
    METRIC_MAX = 4
};

// Lockless per-CPU metrics map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, METRIC_MAX);
    __type(key, __u32);
    __type(value, __u64);
} metrics SEC(".maps");

static __always_inline void inc_metric(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&metrics, &idx);
    if (v) {
        // No lock or atomic instruction needed
        *v += 1;
    }
}

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        inc_metric(METRIC_OTHER);
        return XDP_PASS;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    switch (iph->protocol) {
        case IPPROTO_TCP:
            inc_metric(METRIC_TCP);
            break;
        case IPPROTO_UDP:
            inc_metric(METRIC_UDP);
            break;
        case IPPROTO_ICMP:
            inc_metric(METRIC_ICMP);
            break;
        default:
            inc_metric(METRIC_OTHER);
            break;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
