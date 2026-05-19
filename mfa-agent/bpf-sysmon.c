// ---- BPF type definitions ----
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef long long __s64;

#define SEC(NAME) __attribute__((section(NAME), used))

// ---- BPF helper function pointers ----
static long (*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
    const void *value, __u64 flags) = (void *)2;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size,
    const void *unsafe_ptr) = (void *)114;
static long (*bpf_probe_read_user)(void *dst, __u32 size,
    const void *unsafe_ptr) = (void *)112;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *)16;

// ---- BPF macros ----
#define BPF_ANY     0
#define BPF_NOEXIST 1

#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_HASH 1

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// ---- Counter Indices ----
#define STAT_EXECVE         0   // execve(): ALWAYS anomalous post-boot
#define STAT_PTRACE         1   // ptrace(): ALWAYS anomalous
#define STAT_MOUNT          2   // mount(): ALWAYS anomalous post-boot
#define STAT_SOCKET         3   // socket(): counted, role-filtered
#define STAT_OPEN_SENS      4   // openat() on sensitive paths
#define STAT_CONNECT        5   // connect(): outbound connections
#define STAT_CONNECT_UNAUTH 6   // connect() to unauthorized destinations
#define STAT_SOCKET_EXOTIC  7   // socket() with non-INET/UNIX family
#define STAT_TOTAL_HOOKS    8   // total tracepoint hits
#define STAT_EXECVE_AGENT   9
#define STAT_SIZE           10

// ---- EVENT TYPES (for event log) ---- 
#define EVT_EXECVE          0
#define EVT_PTRACE          1
#define EVT_MOUNT           2
#define EVT_SOCKET_EXOTIC   3
#define EVT_OPEN_SENSITIVE  4
#define EVT_CONNECT_UNAUTH  5

// ---- Event Log ----
#define MAX_EVENTS 32

struct sysmon_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u8  event_type;
    __u8  _pad[3];
    char  comm[16];
    char  arg[64];
};

// ---- Maps ----
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, STAT_SIZE);
} sysmon_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct sysmon_event));
    __uint(max_entries, MAX_EVENTS);
} sysmon_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} sysmon_event_idx SEC(".maps");

// ---- Helpers ----
static __attribute__((always_inline)) void inc_stat(__u32 idx) {
    __u64 *c = (void *)bpf_map_lookup_elem(&sysmon_stats, &idx);
    if (c) (*c) += 1;
}

static __attribute__((always_inline)) void log_event(
    __u8 event_type,
    const char *arg_ptr
) {
    __u32 zero = 0;
    __u32 *idx_ptr = (void *)bpf_map_lookup_elem(&sysmon_event_idx, &zero);
    if (!idx_ptr) return;
    __u32 idx = *idx_ptr % MAX_EVENTS;
    *idx_ptr = idx + 1;

    struct sysmon_event evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = (__u32)pid_tgid;
    evt.tgid = (__u32)(pid_tgid >> 32);
    evt.event_type = event_type;

    bpf_get_current_comm(evt.comm, sizeof(evt.comm));
    if (arg_ptr) {
        bpf_probe_read_user_str(evt.arg, sizeof(evt.arg), arg_ptr);
    }
    bpf_map_update_elem(&sysmon_events, &idx, &evt, BPF_ANY);
}

static __attribute__((always_inline)) void log_event_ip(
    __u8 event_type,
    __u32 ip_be,
    __u16 port_be
) {
    __u32 zero = 0;
    __u32 *idx_ptr = (void *)bpf_map_lookup_elem(&sysmon_event_idx, &zero);
    if (!idx_ptr) return;

    __u32 idx = *idx_ptr % MAX_EVENTS;
    *idx_ptr = idx + 1;

    struct sysmon_event evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = (__u32)pid_tgid;
    evt.tgid = (__u32)(pid_tgid >> 32);
    evt.event_type = event_type;

    bpf_get_current_comm(evt.comm, sizeof(evt.comm));
    // Raw IP + port in arg for agent-side formatting
    __u8 *a = (__u8 *)evt.arg;
    a[0] = (ip_be) & 0xff;
    a[1] = (ip_be >> 8) & 0xff;
    a[2] = (ip_be >> 16) & 0xff;
    a[3] = (ip_be >> 24) & 0xff;
    a[4] = (port_be) & 0xff;
    a[5] = (port_be >> 8) & 0xff;
    bpf_map_update_elem(&sysmon_events, &idx, &evt, BPF_ANY);
}

// ---- Sensitive Path Detection ----
static __attribute__((always_inline)) int match_prefix(
    const char *buf, const char *prefix, int len
) {
    for (int i = 0; i < len; i++) {
        if (buf[i] != prefix[i]) return 0;
    }
    return 1;
}

static __attribute__((always_inline)) int is_sensitive_path(const char *path) {
    char buf[80] = {};
    long ret = bpf_probe_read_user_str(buf, sizeof(buf), path);
    if (ret <= 0) return 0;
    // Credential and key material
    if (match_prefix(buf, "/etc/shadow", 11)) return 1;
    if (match_prefix(buf, "/dev/tpm0", 9)) return 1;
    if (match_prefix(buf, "/dev/tpmrm0", 11)) return 1;
    if (match_prefix(buf, "/opt/mfa-agent/credentials", 26)) return 1;
    if (match_prefix(buf, "/opt/mfa-agent/vm0_ak", 21)) return 1;
    // Kernel memory access
    if (match_prefix(buf, "/dev/mem", 8)) return 1;
    if (match_prefix(buf, "/dev/kmem", 9)) return 1;
    if (match_prefix(buf, "/proc/kcore", 11)) return 1;
    if (match_prefix(buf, "/proc/kallsyms", 14)) return 1;
    // Rootkit injection vectors
    if (match_prefix(buf, "/etc/ld.so.preload", 18)) return 1;
    if (match_prefix(buf, "/etc/ld.so.conf", 15)) return 1;
    // MFA system file tampering
    if (match_prefix(buf, "/opt/mfa-agent/audit", 20)) return 1;
    if (match_prefix(buf, "/opt/mfa-agent/baselines", 24)) return 1;
    if (match_prefix(buf, "/opt/mfa-agent/node.json", 23)) return 1;

    return 0;
}

// ---- Network Topology: Authorized destinations per role ----
#define IP4(a,b,c,d) ((__u32)(a) | ((__u32)(b)<<8) | ((__u32)(c)<<16) | ((__u32)(d)<<24))

#define IP_VM0   IP4(192,168,18,109)
#define IP_VM1   IP4(192,168,18,110)
#define IP_PR1   IP4(192,168,18,111)
#define IP_PR2   IP4(192,168,18,112)
#define IP_PR3   IP4(192,168,18,113)
#define IP_VM2   IP4(192,168,18,114)
#define IP_PR4   IP4(192,168,18,115)
#define IP_PR5   IP4(192,168,18,116)
#define IP_PR6   IP4(192,168,18,117)
#define IP_VM3   IP4(192,168,18,118)
#define IP_VM4   IP4(192,168,18,119)
#define IP_VM5   IP4(192,168,18,120)
#define IP_LO    IP4(127,0,0,1)

struct sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
    __u8  sin_zero[8];
};

static __attribute__((always_inline)) int is_authorized_dest(__u32 ip_be) {
    if (ip_be == IP_LO) return 1;

#if defined(ROLE_CIRCUIT)
    // Proxies relay between adjacent topology nodes
    if (ip_be == IP_VM1 || ip_be == IP_PR1 || ip_be == IP_PR2 ||
        ip_be == IP_PR3 || ip_be == IP_VM2 || ip_be == IP_PR4 ||
        ip_be == IP_PR5 || ip_be == IP_PR6 || ip_be == IP_VM3) return 1;

#elif defined(ROLE_CLIENT)
    // VM1: connects to PR1 (chain entry), responds to VM0 (INITIATE)
    if (ip_be == IP_PR1 || ip_be == IP_VM0) return 1;

#elif defined(ROLE_VERIFIER)
    // VM2: connects to PR4 (chain2 entry), VM5 (logfwd)
    // VM3: accepts from PR6, connects to VM5 (logfwd), VM4 (quorum)
    if (ip_be == IP_PR4 || ip_be == IP_PR5 || ip_be == IP_PR6 ||
        ip_be == IP_VM3 || ip_be == IP_VM5 || ip_be == IP_VM4) return 1;

#elif defined(ROLE_ORCHESTRATOR)
    // VM0: connects to VM1 only
    // VM4: connects to VM3
    if (ip_be == IP_VM1 || ip_be == IP_VM3) return 1;

#elif defined(ROLE_MONITOR)
    // VM5: accepts from VM2/VM3, no outbound expected
    if (ip_be == IP_VM2 || ip_be == IP_VM3) return 1;

#elif defined(ROLE_DUAL_AUTHORITY)
    // VM4: mutual attestation with vm0, chain results from vm3
    if (ip_be == IP_VM0 || ip_be == IP_VM3) return 1;

#else
    #error "Must define a role"
#endif

    return 0;
}


// ---- Tracepoint Context Structures ----
struct trace_sys_enter_execve {
    __u64 __unused;
    __s64 __syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

struct trace_sys_enter_ptrace {
    __u64 __unused;
    __s64 __syscall_nr;
    __s64 request;
    __s64 pid;
};

struct trace_sys_enter_mount {
    __u64 __unused;
    __s64 __syscall_nr;
    const char *dev_name;
    const char *dir_name;
    const char *type;
    __u64 flags;
};

struct trace_sys_enter_socket {
    __u64 __unused;
    __s64 __syscall_nr;
    __s64 family;
    __s64 type;
    __s64 protocol;
};

struct trace_sys_enter_openat {
    __u64 __unused;
    __s64 __syscall_nr;
    __s64 dfd;
    const char *filename;
    __s64 flags;
    __s64 mode;
};

struct trace_sys_enter_connect {
    __u64 __unused;
    __s64 __syscall_nr;
    __s64 fd;
    const void *uservaddr;
    __s64 addrlen;
};

// ---- Tracepoint Hooks ----

// EXECVE: ALWAYS anomalous post-boot
SEC("tracepoint/syscalls/sys_enter_execve")
int sysmon_execve(struct trace_sys_enter_execve *ctx) {
    inc_stat(STAT_TOTAL_HOOKS);

    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    // Only iptables/iptables-save remain as agent subprocesses
    // At sys_enter_execve, comm is still the parent (mfa-agent)
    if (comm[0]=='m' && comm[1]=='f' && comm[2]=='a' && comm[3]=='-' &&
        comm[4]=='a' && comm[5]=='g' && comm[6]=='e' && comm[7]=='n' &&
        comm[8]=='t') {
        inc_stat(STAT_EXECVE_AGENT);
        return 0;
    }
    inc_stat(STAT_EXECVE);
    log_event(EVT_EXECVE, ctx->filename);
    return 0;
}

// PTRACE: ALWAYS anomalous
SEC("tracepoint/syscalls/sys_enter_ptrace")
int sysmon_ptrace(struct trace_sys_enter_ptrace *ctx) {
    inc_stat(STAT_TOTAL_HOOKS);
    inc_stat(STAT_PTRACE);
    log_event(EVT_PTRACE, 0);
    return 0;
}

// MOUNT: ALWAYS anomalous post-boot
SEC("tracepoint/syscalls/sys_enter_mount")
int sysmon_mount(struct trace_sys_enter_mount *ctx) {
    inc_stat(STAT_TOTAL_HOOKS);
    inc_stat(STAT_MOUNT);
    log_event(EVT_MOUNT, ctx->dir_name);
    return 0;
}

// SOCKET: Count all, log exotic families
SEC("tracepoint/syscalls/sys_enter_socket")
int sysmon_socket(struct trace_sys_enter_socket *ctx) {
    inc_stat(STAT_TOTAL_HOOKS);
    inc_stat(STAT_SOCKET);

    __s64 family = ctx->family;
    // Only AF_INET (2), AF_UNIX (1), AF_NETLINK (16) are legitimate
    if (family != 2 && family != 1 && family != 16) {
        inc_stat(STAT_SOCKET_EXOTIC);
        log_event(EVT_SOCKET_EXOTIC, 0);
    }

    return 0;
}

// OPENAT: Monitor sensitive file access 
SEC("tracepoint/syscalls/sys_enter_openat")
int sysmon_openat(struct trace_sys_enter_openat *ctx) {
    inc_stat(STAT_TOTAL_HOOKS);

    if (is_sensitive_path(ctx->filename)) {
        inc_stat(STAT_OPEN_SENS);
        log_event(EVT_OPEN_SENSITIVE, ctx->filename);
    }

    return 0;
}

// CONNECT: Verify destination against topology
SEC("tracepoint/syscalls/sys_enter_connect")
int sysmon_connect(struct trace_sys_enter_connect *ctx) {
    inc_stat(STAT_TOTAL_HOOKS);
    inc_stat(STAT_CONNECT);

    struct sockaddr_in addr = {};
    long ret = bpf_probe_read_user(&addr, sizeof(addr), ctx->uservaddr);
    if (ret != 0) return 0;

    // Only check AF_INET
    if (addr.sin_family != 2) return 0;

    if (!is_authorized_dest(addr.sin_addr)) {
        inc_stat(STAT_CONNECT_UNAUTH);
        log_event_ip(EVT_CONNECT_UNAUTH, addr.sin_addr, addr.sin_port);
    }

    return 0;
}
char _license[] SEC("license") = "GPL";


