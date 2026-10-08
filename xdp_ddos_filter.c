#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

// --- Per-source-IP telemetry (drives the L4 SYN/volumetric heuristics) ---
struct telemetry_data {
    u64 packet_count;    // fwd packets this IP
    u64 syn_count;       // SYN flags
    u64 byte_count;      // IP tot_len bytes (volumetric heuristic)
    u64 first_seen_ns;   // for aggregate rate/duration
};

// --- Per-FLOW (5-tuple) forward features for the GRU (Phase C) ---
// Keyed by the forward 5-tuple; XDP sees only ingress (client->server) packets,
// which is exactly the forward direction CICFlowMeter's Fwd* features use. These
// mirror the 8 selected features (computed in userspace from these raw fields):
//   Init_Win_bytes_forward      = init_win
//   Total Length of Fwd Packets = fwd_payload_bytes   (L4 PAYLOAD, not tot_len)
//   Fwd Packet Length Max       = fwd_pkt_len_max      (L4 payload)
//   Fwd Header Length           = fwd_hdr_bytes        (sum of L4 header bytes)
//   Fwd IAT Total/Max/Mean      = from first/last_seen + iat_max   (nanoseconds)
//   Fwd Packets/s               = fwd_packets / duration
struct flow_key {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8  proto;
};
struct flow_feat {
    u64 first_seen_ns;
    u64 last_seen_ns;
    u64 iat_max_ns;
    u64 fwd_packets;
    u64 fwd_payload_bytes;
    u64 fwd_hdr_bytes;
    u32 fwd_pkt_len_max;
    u32 init_win;
};

BPF_HASH(blacklist_map, u32, u64, 100000);
BPF_PERCPU_HASH(telemetry_map, u32, struct telemetry_data, 100000);
// LRU so the flow table self-bounds under floods (oldest flows evicted first).
BPF_TABLE("lru_hash", struct flow_key, struct flow_feat, flow_map, 262144);

int xdp_ddos_mitigation(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    u32 src_ip = ip->saddr;
    u64 *drop_counter = blacklist_map.lookup(&src_ip);
    if (drop_counter) {
        lock_xadd(drop_counter, 1);
        return XDP_DROP;                // banned IP: drop before anything else
    }

    u16 tot_len   = bpf_ntohs(ip->tot_len);
    u32 ihl_bytes = ip->ihl * 4;
    u8  proto     = ip->protocol;

    // --- L4 parse (ports / header length / window), bounds-checked ---
    u8  is_syn = 0;
    u8  have_l4 = 0;
    u16 src_port = 0, dst_port = 0, l4_hdr_len = 0, win = 0;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ihl_bytes;
        if ((void *)(tcp + 1) <= data_end) {
            src_port   = tcp->source;
            dst_port   = tcp->dest;
            l4_hdr_len = tcp->doff * 4;
            win        = bpf_ntohs(tcp->window);
            if (tcp->syn && !tcp->ack)
                is_syn = 1;
            have_l4 = 1;
        }
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ihl_bytes;
        if ((void *)(udp + 1) <= data_end) {
            src_port   = udp->source;
            dst_port   = udp->dest;
            l4_hdr_len = sizeof(struct udphdr);   // 8
            have_l4 = 1;
        }
    }

    // L4 payload length (CICFlowMeter "Fwd Packet Length" semantics)
    u32 payload_len = 0;
    if (tot_len > ihl_bytes + l4_hdr_len)
        payload_len = tot_len - ihl_bytes - l4_hdr_len;

    // --- Per-source-IP telemetry (unchanged; L4 heuristics) ---
    struct telemetry_data zero_tel = {};
    struct telemetry_data *tel = telemetry_map.lookup_or_try_init(&src_ip, &zero_tel);
    if (tel) {
        tel->packet_count += 1;
        tel->byte_count   += tot_len;
        if (tel->first_seen_ns == 0)
            tel->first_seen_ns = bpf_ktime_get_ns();
        if (is_syn)
            tel->syn_count += 1;
    }

    // --- Per-FLOW forward feature accumulation (TCP/UDP only) ---
    if (have_l4) {
        struct flow_key fk = {};
        fk.src_ip   = src_ip;
        fk.dst_ip   = ip->daddr;
        fk.src_port = src_port;
        fk.dst_port = dst_port;
        fk.proto    = proto;

        struct flow_feat zero_ff = {};
        struct flow_feat *ff = flow_map.lookup_or_try_init(&fk, &zero_ff);
        if (ff) {
            u64 now = bpf_ktime_get_ns();
            if (ff->first_seen_ns == 0) {
                ff->first_seen_ns = now;
                ff->init_win = win;
            } else {
                u64 gap = now - ff->last_seen_ns;
                if (gap > ff->iat_max_ns)
                    ff->iat_max_ns = gap;
            }
            ff->last_seen_ns     = now;
            ff->fwd_packets     += 1;
            ff->fwd_payload_bytes += payload_len;
            ff->fwd_hdr_bytes   += l4_hdr_len;
            if (payload_len > ff->fwd_pkt_len_max)
                ff->fwd_pkt_len_max = payload_len;
        }
    }

    return XDP_PASS;
}
