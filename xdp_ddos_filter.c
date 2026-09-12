#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>

struct telemetry_data {
    u64 packet_count;    // Total Fwd Packet (ingress = client→server)
    u64 syn_count;       // SYN Flag Count
    u64 byte_count;      // Total Length of Fwd Packet (IP payload bytes)
    u64 first_seen_ns;   // Flow start timestamp for Flow Duration computation
    u64 active_connections;  // NEW: incremented on SYN, decremented on FIN/RST
};

BPF_HASH(blacklist_map, u32, u64, 100000);
BPF_PERCPU_HASH(telemetry_map, u32, struct telemetry_data, 100000);

int xdp_ddos_mitigation(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);

    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    u32 src_ip = ip->saddr;
    u64 *drop_counter = blacklist_map.lookup(&src_ip);

    if (drop_counter) {
        lock_xadd(drop_counter, 1);
        return XDP_DROP;
    }

    u64 pkt_bytes = bpf_ntohs(ip->tot_len); 
    u8 is_syn = 0;
    u8 is_fin_rst = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        
        if ((void *)(tcp + 1) <= data_end) {
            if (tcp->syn && !tcp->ack) {
                is_syn = 1;
            }
            if (tcp->fin || tcp->rst) {
                is_fin_rst = 1;
            }
        }
    }

    struct telemetry_data zero_tel = {}; 
    struct telemetry_data *tel;

    tel = telemetry_map.lookup_or_try_init(&src_ip, &zero_tel);
    if (tel) {

        tel->packet_count += 1;
        tel->byte_count += pkt_bytes;

        // Record flow start time on first packet for this IP.
        // Uses bpf_ktime_get_ns() for nanosecond-resolution monotonic clock.
        if (tel->first_seen_ns == 0) {
            tel->first_seen_ns = bpf_ktime_get_ns();
        }
        
        if (is_syn) {
            tel->syn_count += 1;
            tel->active_connections += 1;
        }

        // Decrement connection count on FIN or RST (connection teardown)
        if (is_fin_rst && tel->active_connections > 0) {
            tel->active_connections -= 1;
        }
    }

    return XDP_PASS;
}