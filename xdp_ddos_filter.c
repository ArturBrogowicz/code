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
};
// NOTE: a per-IP connection gauge was intentionally removed. On an ingress-only
// XDP hook it cannot be decremented reliably (server-side FIN is egress, SYNs
// are retransmitted), so it drifts upward and false-bans legit clients. Slow-
// connection abuse is now detected in userspace from the kernel socket table
// (see get_established_conns_by_ip in control_plane.py), which is authoritative.

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
        // bpf_trace_printk("[XDP] DROPPED packet from %x\\n", src_ip);
        return XDP_DROP;
    }

    u64 pkt_bytes = bpf_ntohs(ip->tot_len);
    u8 is_syn = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);

        if ((void *)(tcp + 1) <= data_end) {
            if (tcp->syn && !tcp->ack) {
                is_syn = 1;
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
        }

        // bpf_trace_printk("[XDP] src=%x pkts=%llu bytes=%llu\\n", src_ip, tel->packet_count, tel->byte_count);
        // bpf_trace_printk("[XDP] src=%x syn=%llu\\n", src_ip, tel->syn_count);
    }

    return XDP_PASS;
}