typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(NAME) __attribute__((section(NAME), used))

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
    const void *value, __u64 flags) = (void *)2;

#define BPF_ANY     0
#define BPF_NOEXIST 1

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

#define XDP_DROP  1
#define XDP_PASS  2
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

struct ethhdr {
    __u8 h_dest[6]; __u8 h_source[6]; __u16 h_proto;
} __attribute__((packed));

struct iphdr {
    __u8 version_ihl; __u8 tos; __u16 tot_len; __u16 id; __u16 frag_off;
    __u8 ttl; __u8 protocol; __u16 check; __u32 saddr; __u32 daddr;
} __attribute__((packed));

struct tcphdr {
    __u16 source; __u16 dest; __u32 seq; __u32 ack_seq;
    __u16 doff_flags; __u16 window; __u16 check; __u16 urg_ptr;
} __attribute__((packed));

#define bpf_ntohs(x) __builtin_bswap16(x)

#define ETH_P_IP     0x0800
#define IPPROTO_TCP  6

// ---- Port Definitions: common to all roles ----

#define MFA_PORT     9001   // MFA agent attestation — always entropy-checked
#define SSH_PORT     22     // DEV-ONLY — bypasses entropy, removed at Phase C3

// ---- ROLE-SPECIFIC PORT POLICIES ----
#if defined(ROLE_CIRCUIT)
// destination ports carrying ENCRYPTED traffic
#define ROLE_CHECK_DP(dp) (0)
// source ports (return) carrying ENCRYPTED traffic
#define ROLE_CHECK_SP(sp) (0)
// destination ports with PLAINTEXT traffic (TEMPORARY)
#define ROLE_BYPASS_DP(dp) (0)
// source ports (return) with PLAINTEXT traffic (TEMPORARY)
#define ROLE_BYPASS_SP(sp) (0)

#elif defined(ROLE_VERIFIED_CLIENT)
// VM1: Chain entry + INITIATE receiver
#define INITIATE_PORT 9003
#define ROLE_CHECK_DP(dp) ((dp) == INITIATE_PORT)
#define ROLE_CHECK_SP(sp) ((sp) == INITIATE_PORT)
#define ROLE_BYPASS_DP(dp) (0)
#define ROLE_BYPASS_SP(sp) (0)

#elif defined(ROLE_VERIFIER)
// VM2, VM3: Verification endpoints + log forwarding 
#define LOG_FWD_PORT 9100
#define DA_RESULT_PORT 9005
#define ROLE_CHECK_DP(dp) ((dp) == DA_RESULT_PORT)
#define ROLE_CHECK_SP(sp) ((sp) == LOG_FWD_PORT || (sp) == DA_RESULT_PORT)
#define ROLE_BYPASS_DP(dp) (0)
#define ROLE_BYPASS_SP(sp) (0)

#elif defined(ROLE_MONITOR)
// VM5: Monitoring station 
#define LOG_RECV_PORT 9100
#define DASH_PORT     8443
#define ROLE_CHECK_DP(dp) ((dp) == LOG_RECV_PORT)
#define ROLE_CHECK_SP(sp) ((sp) == LOG_RECV_PORT)
#define ROLE_BYPASS_DP(dp) ((dp) == DASH_PORT)
#define ROLE_BYPASS_SP(sp) ((sp) == DASH_PORT)

#elif defined(ROLE_ORCHESTRATOR)
// VM0: Primary orchestrator 
#define INITIATE_PORT 9003
#define MUTUAL_ATTEST_PORT 9004
#define ROLE_CHECK_DP(dp) ((dp) == INITIATE_PORT || (dp) == MUTUAL_ATTEST_PORT)
#define ROLE_CHECK_SP(sp) ((sp) == INITIATE_PORT || (sp) == MUTUAL_ATTEST_PORT)
#define ROLE_BYPASS_DP(dp) (0)
#define ROLE_BYPASS_SP(sp) (0)

#elif defined(ROLE_WEBSERVER)
// VM6: Web server endpoint (yet to be implemented)
#define WEB_PORT 8080
#define ROLE_CHECK_DP(dp) ((dp) == WEB_PORT)
#define ROLE_CHECK_SP(sp) ((sp) == WEB_PORT)
#define ROLE_BYPASS_DP(dp) (0)
#define ROLE_BYPASS_SP(sp) (0)
#elif defined(ROLE_DUAL_AUTHORITY)
// VM4: Dual authority, second orchestrator 
#define MUTUAL_ATTEST_PORT 9004
#define DA_RESULT_PORT 9005
#define ROLE_CHECK_DP(dp) ((dp) == MUTUAL_ATTEST_PORT || (dp) == DA_RESULT_PORT)
#define ROLE_CHECK_SP(sp) ((sp) == MUTUAL_ATTEST_PORT || (sp) == DA_RESULT_PORT)
#define ROLE_BYPASS_DP(dp) (0)
#define ROLE_BYPASS_SP(sp) (0)
#else
#error "Must define a role: ROLE_CIRCUIT, ROLE_VERIFIED_CLIENT, ROLE_VERIFIER, ROLE_MONITOR, ROLE_ORCHESTRATOR, or ROLE_WEBSERVER"
#endif

// ---- ENTROPY ANALYSIS PARAMETERS ----
#define MAX_ANALYZE  1500
#define MIN_PAYLOAD  128

// Thresholds (unique byte values out of 256 possible):
//   Handshake: 65 (generous for Kyber + bincode mix)
//   Authenticated: 80 (requires near-random encrypted data)
#define THRESH_HANDSHAKE     80
#define THRESH_AUTHENTICATED 85
#define HANDSHAKE_PKT_LIMIT  20

#define STAT_PASSED   0
#define STAT_DROP_ENT 1
#define STAT_DROP_PRO 2
#define STAT_DROP_PRT 3
#define STAT_TOTAL    4
#define STAT_EXEMPT   5
#define STAT_SIZE     6

struct conn_state { __u32 pkt_count; __u8 phase; __u8 _pad[3]; };

// ---- Maps ----
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct conn_state));
    __uint(max_entries, 64);
} conn_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, STAT_SIZE);
} stats SEC(".maps");

// Histogram: unique byte count distribution (26 buckets of 10: 0-9, 10-19, ..., 250-259)
// Only populated for entropy-checked packets (not bypass/exempt)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 26);
} entropy_hist SEC(".maps");

// Histogram: packet payload size distribution (16 buckets of 100: 0-99, 100-199, ..., 1500+)
// Populated for ALL TCP packets that reach entropy check (not bypass)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 16);
} size_hist SEC(".maps");

// ---- Helpers ----

static __attribute__((always_inline)) void inc_stat(__u32 idx) {
    __u64 *c = bpf_map_lookup_elem(&stats, &idx);
    if (c) (*c) += 1;
}

static __attribute__((always_inline)) void inc_entropy_hist(__u32 unique) {
    __u32 bucket = unique / 10;
    if (bucket > 25) bucket = 25;
    __u64 *c = (void *)bpf_map_lookup_elem(&entropy_hist, &bucket);
    if (c) (*c) += 1;
}

static __attribute__((always_inline)) void inc_size_hist(__u32 plen) {
    __u32 bucket = plen / 100;
    if (bucket > 15) bucket = 15;
    __u64 *c = (void *)bpf_map_lookup_elem(&size_hist, &bucket);
    if (c) (*c) += 1;
}

static __attribute__((always_inline))
__u64 conn_key(__u32 sip, __u16 sp, __u16 dp) {
    return ((__u64)sip << 32) | ((__u64)sp << 16) | (__u64)dp;
}

static __attribute__((always_inline)) __u32 get_pkt_count(__u64 key) {
    struct conn_state *cs = bpf_map_lookup_elem(&conn_map, &key);
    if (cs) {
        __u32 c = cs->pkt_count;
        if (cs->pkt_count < 0xFFFFFFFF) cs->pkt_count++;
        if (c >= HANDSHAKE_PKT_LIMIT && cs->phase < 2) cs->phase = 2;
        return c;
    }
    struct conn_state ns = { .pkt_count = 1, .phase = 1, ._pad = {0,0,0} };
    bpf_map_update_elem(&conn_map, &key, &ns, BPF_NOEXIST);
    return 0;
}

// ---- Unique byte count using stack bitmap ----

static __attribute__((always_inline))
__u32 count_unique(struct xdp_md *ctx, __u32 off, __u32 len) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    // 256-bit bitmap on stack
    __u32 seen[8] = {0,0,0,0,0,0,0,0};

    #pragma clang loop unroll(disable)
    for (__u32 i = 0; i < MAX_ANALYZE; i++) {
        if (i >= len) break;
        __u8 *p = (__u8 *)(data + off + i);
        if ((void *)(p + 1) > data_end) break;
        __u8 b = *p;
        seen[b >> 5] |= (1u << (b & 31));
    }
    // Parallel popcount  branch-free, 8 iterations
    __u32 unique = 0;
    #pragma clang loop unroll(disable)
    for (int i = 0; i < 8; i++) {
        __u32 v = seen[i];
        v = v - ((v >> 1) & 0x55555555u);
        v = (v & 0x33333333u) + ((v >> 2) & 0x33333333u);
        v = (v + (v >> 4)) & 0x0F0F0F0Fu;
        unique += (v * 0x01010101u) >> 24;
    }
    return unique;
}

// ---- XDP entry ----
SEC("xdp")
int xdp_entropy(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    inc_stat(STAT_TOTAL);

    if (data + sizeof(struct ethhdr) > data_end) {
        inc_stat(STAT_DROP_PRO); return XDP_DROP;
    }
    struct ethhdr *eth = data;
    __u16 proto = bpf_ntohs(eth->h_proto);

    if (proto == 0x0806) { inc_stat(STAT_PASSED); return XDP_PASS; } // ARP
    if (proto != ETH_P_IP) { inc_stat(STAT_DROP_PRO); return XDP_DROP; }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) { inc_stat(STAT_DROP_PRO); return XDP_DROP; }
    if ((ip->version_ihl >> 4) != 4) { inc_stat(STAT_DROP_PRO); return XDP_DROP; }
    if (ip->protocol != IPPROTO_TCP) { inc_stat(STAT_DROP_PRO); return XDP_DROP; }

    __u8 ihl = ip->version_ihl & 0x0F;
    if (ihl < 5) { inc_stat(STAT_DROP_PRO); return XDP_DROP; }
    __u32 ip_hlen = (__u32)ihl * 4;

    void *tcp_start = (void *)ip + ip_hlen;
    if (tcp_start + sizeof(struct tcphdr) > data_end) {
        inc_stat(STAT_DROP_PRO); return XDP_DROP;
    }
    struct tcphdr *tcp = tcp_start;
    __u16 dp = bpf_ntohs(tcp->dest);
    __u16 sp = bpf_ntohs(tcp->source);
    // Port filtering 
    if (dp == SSH_PORT || sp == SSH_PORT) {
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }
    // Role-specific bypass
    if (ROLE_BYPASS_DP(dp) || ROLE_BYPASS_SP(sp)) {
        inc_stat(STAT_EXEMPT);
        return XDP_PASS;
    }
    // Category 2: Entropy-checked ports 
    int port_allowed = 0;
    // Common: MFA agent port (both directions), always entropy-checked
    if (dp == MFA_PORT || sp == MFA_PORT) port_allowed = 1;
    // Role-specific encrypted ports  entropy-checked
    if (ROLE_CHECK_DP(dp) || ROLE_CHECK_SP(sp)) port_allowed = 1;
    // Category 3: Drop (wrong port for this role) 
    if (!port_allowed) {
        inc_stat(STAT_DROP_PRT);
        return XDP_DROP;
    }
    // Entropy verification 
    __u16 doff_f = bpf_ntohs(tcp->doff_flags);
    __u8 doff = (doff_f >> 12) & 0x0F;
    if (doff < 5) { inc_stat(STAT_DROP_PRO); return XDP_DROP; }
    __u32 tcp_hlen = (__u32)doff * 4;

    void *payload = tcp_start + tcp_hlen;
    if (payload >= data_end) {
        inc_stat(STAT_EXEMPT); inc_stat(STAT_PASSED); return XDP_PASS;
    }
    __u32 plen = data_end - payload;
    inc_size_hist(plen);    
    if (plen < MIN_PAYLOAD) {
        inc_stat(STAT_EXEMPT); inc_stat(STAT_PASSED); return XDP_PASS;
    }
    __u32 sip = ip->saddr;
    __u64 ck = conn_key(sip, sp, dp);
    __u32 pkts = get_pkt_count(ck);
    __u32 thresh = (pkts < HANDSHAKE_PKT_LIMIT) ? THRESH_HANDSHAKE : THRESH_AUTHENTICATED;
    // Cap threshold at 70% of analyzable bytes
    if (thresh > (plen * 7) / 10) thresh = (plen * 7) / 10;
    __u32 alen = plen;
    if (alen > MAX_ANALYZE) alen = MAX_ANALYZE;
    __u32 poff = 14 + ip_hlen + tcp_hlen;
    __u32 unique = count_unique(ctx, poff, alen);
    inc_entropy_hist(unique);
    if (unique >= thresh) { inc_stat(STAT_PASSED); return XDP_PASS; }

    inc_stat(STAT_DROP_ENT);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";

