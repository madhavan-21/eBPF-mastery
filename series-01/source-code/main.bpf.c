#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define our eBPF maps

// Hash map storing blocked IP addresses (IPv4)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // IPv4 address in network byte order
    __type(value, __u8);  // Dummy block status flag (e.g. 1)
} blocklist SEC(".maps");

// Per-CPU Array map to count ACCEPT (index 0) and DROP (index 1) packets locklessly
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);   // Metric index: 0 = PASS, 1 = DROP
    __type(value, __u64); // Counter
} metrics SEC(".maps");

// The core XDP entry point
SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    // Pointers to the start and end of packet data in kernel memory
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Boundary check: Parse the Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS; // Packet too small, let the kernel handle it
    }

    // 2. Protocol Check: We are only auditing IPv4 traffic
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS; // Pass non-IP traffic (e.g., ARP, IPv6)
    }

    // 3. Boundary check: Parse the IP header
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 src_ip = iph->saddr;
    __u32 index;
    __u64 *counter;

    // 4. Perform dynamic lookup in the blocklist map
    __u8 *blocked = bpf_map_lookup_elem(&blocklist, &src_ip);

    if (blocked && *blocked == 1) {
        // Source IP is blocked! Increment the DROP counter (index 1)
        index = 1;
        counter = bpf_map_lookup_elem(&metrics, &index);
        if (counter) {
            *counter += 1;
        }
        
        // Instruct the network card driver to drop the packet instantly
        return XDP_DROP;
    }

    // Packet is allowed. Increment the PASS counter (index 0)
    index = 0;
    counter = bpf_map_lookup_elem(&metrics, &index);
    if (counter) {
        *counter += 1;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
