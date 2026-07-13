// Series 07: LRU Hash Map Connection Tracker
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct flow_stats {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} metrics SEC(".maps");

static __always_inline void inc_metric(__u32 idx) {
    __u64 *v = bpf_map_lookup_elem(&metrics, &idx);
    if (v) __sync_fetch_and_add(v, 1);
}

SEC("xdp")
int track_flows(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_metric(0);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    if (iph->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)(iph + 1);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    struct flow_key key = {
        .src_ip   = iph->saddr,
        .dst_ip   = iph->daddr,
        .src_port = tcp->source,
        .dst_port = tcp->dest,
    };

    __u32 pkt_len = bpf_ntohs(iph->tot_len);

    struct flow_stats *s = bpf_map_lookup_elem(&flows, &key);
    if (s) {
        __sync_fetch_and_add(&s->packets, 1);
        __sync_fetch_and_add(&s->bytes, pkt_len);
        s->last_seen_ns = bpf_ktime_get_ns();
        inc_metric(1);
    } else {
        struct flow_stats new_s = {
            .packets     = 1,
            .bytes       = pkt_len,
            .last_seen_ns = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&flows, &key, &new_s, BPF_ANY);
        inc_metric(2);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
