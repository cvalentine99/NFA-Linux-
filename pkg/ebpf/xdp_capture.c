//go:build ignore

// XDP packet capture program for NFA-Linux
// This program is loaded into the kernel to perform high-speed packet capture
// using AF_XDP sockets for zero-copy delivery to userspace.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// XSK (XDP Socket) map for redirecting packets to userspace
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);  // Support up to 64 queues
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

// Statistics map for tracking packet counts per CPU
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} pkt_count SEC(".maps");

// Filter configuration map
struct filter_config {
    __u32 enabled;
    __u32 src_ip;        // Source IP filter (0 = any)
    __u32 dst_ip;        // Destination IP filter (0 = any)
    __u16 src_port;      // Source port filter (0 = any)
    __u16 dst_port;      // Destination port filter (0 = any)
    __u8  protocol;      // Protocol filter (0 = any)
    __u8  pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct filter_config);
} filter_map SEC(".maps");

// Parse Ethernet header and return pointer to next header
static __always_inline int parse_ethhdr(void *data, void *data_end,
                                        __u16 *eth_type, void **next_hdr) {
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    *eth_type = bpf_ntohs(eth->h_proto);
    *next_hdr = (void *)(eth + 1);
    
    // Handle VLAN tags
    if (*eth_type == ETH_P_8021Q || *eth_type == ETH_P_8021AD) {
        struct {
            __u16 tci;
            __u16 inner_type;
        } *vlan = *next_hdr;
        
        if ((void *)(vlan + 1) > data_end)
            return -1;
        
        *eth_type = bpf_ntohs(vlan->inner_type);
        *next_hdr = (void *)(vlan + 1);
    }
    
    return 0;
}

// Check if packet matches filter criteria
static __always_inline int packet_matches_filter(struct filter_config *cfg,
                                                  __u32 src_ip, __u32 dst_ip,
                                                  __u16 src_port, __u16 dst_port,
                                                  __u8 protocol) {
    if (!cfg->enabled)
        return 1;  // No filter, match all
    
    if (cfg->src_ip && cfg->src_ip != src_ip)
        return 0;
    
    if (cfg->dst_ip && cfg->dst_ip != dst_ip)
        return 0;
    
    if (cfg->protocol && cfg->protocol != protocol)
        return 0;
    
    if (cfg->src_port && cfg->src_port != src_port)
        return 0;
    
    if (cfg->dst_port && cfg->dst_port != dst_port)
        return 0;
    
    return 1;
}

// Main XDP program
SEC("xdp")
int xdp_capture(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 key = 0;
    __u16 eth_type;
    void *next_hdr;
    
    // Update packet counter
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
    if (count)
        __sync_fetch_and_add(count, 1);
    
    // Parse Ethernet header
    if (parse_ethhdr(data, data_end, &eth_type, &next_hdr) < 0)
        goto redirect;  // Can't parse, but still capture
    
    // Get filter configuration
    struct filter_config *filter = bpf_map_lookup_elem(&filter_map, &key);
    
    // Parse IP header for filtering
    if (filter && filter->enabled) {
        __u32 src_ip = 0, dst_ip = 0;
        __u16 src_port = 0, dst_port = 0;
        __u8 protocol = 0;
        
        if (eth_type == ETH_P_IP) {
            struct iphdr *ip = next_hdr;
            
            if ((void *)(ip + 1) > data_end)
                goto redirect;
            
            src_ip = ip->saddr;
            dst_ip = ip->daddr;
            protocol = ip->protocol;
            
            // Parse TCP/UDP for port filtering
            if (protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
                if ((void *)(tcp + 1) <= data_end) {
                    src_port = bpf_ntohs(tcp->source);
                    dst_port = bpf_ntohs(tcp->dest);
                }
            } else if (protocol == IPPROTO_UDP) {
                struct udphdr *udp = (void *)ip + (ip->ihl * 4);
                if ((void *)(udp + 1) <= data_end) {
                    src_port = bpf_ntohs(udp->source);
                    dst_port = bpf_ntohs(udp->dest);
                }
            }
        }
        
        // Check filter
        if (!packet_matches_filter(filter, src_ip, dst_ip, src_port, dst_port, protocol))
            return XDP_PASS;  // Don't capture, let kernel handle
    }

redirect:
    // Redirect to AF_XDP socket
    // Use the RX queue index to select the socket
    __u32 rx_queue = ctx->rx_queue_index;
    
    // Try to redirect to the XSK socket for this queue
    if (bpf_map_lookup_elem(&xsks_map, &rx_queue)) {
        return bpf_redirect_map(&xsks_map, rx_queue, XDP_PASS);
    }
    
    // Fallback to queue 0 if specific queue not found
    rx_queue = 0;
    return bpf_redirect_map(&xsks_map, rx_queue, XDP_PASS);
}

// License declaration required for eBPF programs
char _license[] SEC("license") = "GPL";
