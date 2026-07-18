// Series 09: Map-in-Map Dynamic Routing
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

// Outer map holding references to inner hash maps
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 10240);
        __type(key, __u32);   // Dest IP
        __type(value, __u32); // Action: 0=PASS, 1=DROP
    });
} outer_map SEC(".maps");

SEC("xdp")
int xdp_routing(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 outer_key = 0;
    void *inner_map = bpf_map_lookup_elem(&outer_map, &outer_key);
    if (!inner_map) {
        return XDP_PASS; // No policy loaded
    }

    __u32 ip_key = iph->saddr;
    __u32 *action = bpf_map_lookup_elem(inner_map, &ip_key);
    if (action && *action == 1) {
        return XDP_DROP; // Blacklisted IP
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
