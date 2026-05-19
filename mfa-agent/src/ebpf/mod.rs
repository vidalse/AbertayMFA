use anyhow::Result;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::os::unix::io::RawFd;

const KERNEL_THREAD_PREFIXES: &[&str] = &[
    "kworker/", "kworker/R-",
    "cpuhp/", "ksoftirqd/", "migration/",
    "scsi_eh_", "scsi_tmf_",
    "kthreadd", "kswapd", "kcompactd",
    "kdevtmpfs", "kauditd", "oom_reaper",
    "rcu_", "hwrng", "irq/",
    "jbd2/", "pool_workqueue",
    "ksoftirqd", "kblockd",
];

const SENSITIVE_PATHS: &[&str] = &[
    "/dev/mem",
    "/dev/kmem",
    "/proc/kcore",
    "/proc/kallsyms",
    "/etc/shadow",
    "/etc/ld.so.preload",
];

const EXPECTED_BPF_NAMES: &[&str] = &[
    "xdp_entropy",
    "sysmon_execve",
    "sysmon_ptrace",
    "sysmon_mount",
    "sysmon_socket",
    "sysmon_openat",
    "sysmon_connect",
];

const SYS_BPF: i64 = 321; // x86_64
const BPF_PROG_GET_NEXT_ID: u32 = 11;
const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
const BPF_PROG_GET_FD_BY_ID: u32 = 13;
const BPF_MAP_GET_FD_BY_ID: u32 = 14;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const STAT_PASSED: u32 = 0;
const STAT_DROP_ENT: u32 = 1;
const STAT_DROP_PRO: u32 = 2;
const STAT_DROP_PRT: u32 = 3;
const STAT_TOTAL: u32 = 4;
const STAT_EXEMPT: u32 = 5;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EbpfState {
    pub loaded_programs: Vec<BpfProgramInfo>,
    pub process_count: usize,
    pub process_list_hash: Vec<u8>,
    pub network_connections: usize,
    pub state_hash: Vec<u8>,
    #[serde(default)]
    pub iptables_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub binary_hashes: Option<BTreeMap<String, Vec<u8>>>,
    #[serde(default)]
    pub binary_dir_listing_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub listening_ports: Option<Vec<u16>>,
    #[serde(default)]
    pub mount_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub config_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub sysctl_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub userspace_processes: Option<Vec<ProcessIdentity>>,
    #[serde(default)]
    pub userspace_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub kernel_thread_types: Option<Vec<String>>,
    #[serde(default)]
    pub kernel_thread_types_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub masquerade_alerts: Option<Vec<MasqueradeAlert>>,
    #[serde(default)]
    pub kernel_modules: Option<Vec<String>>,
    #[serde(default)]
    pub connection_tuples: Option<Vec<String>>,
    #[serde(default)]
    pub connection_tuples_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub xdp_attached: Option<bool>,
    #[serde(default)]
    pub xdp_stats: Option<XdpStats>,
    #[serde(default)]
    pub passwd_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub ssh_config_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub ld_preload_safe: Option<bool>,
    #[serde(default)]
    pub entropy_available: Option<u32>,
    #[serde(default)]
    pub sysmon: Option<crate::sysmon::SysmonState>,
    #[serde(default)]
    pub boot_params_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub dev_inventory_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub passwd_content: Option<String>,
    #[serde(default)]
    pub shadow_content: Option<String>,
    #[serde(default)]
    pub sshd_config_content: Option<String>,
    #[serde(default)]
    pub authorized_keys_content: Option<String>,
    #[serde(default)]
    pub ld_preload_content: Option<String>,
    #[serde(default)]
    pub boot_params_content: Option<String>,
    #[serde(default)]
    pub dev_inventory_list: Option<Vec<String>>,
    #[serde(default)]
    pub iptables_content: Option<String>,
    #[serde(default)]
    pub mount_content: Option<String>,
    #[serde(default)]
    pub sysctl_content: Option<String>,
    #[serde(default)]
    pub fd_audit: Option<FdAuditSummary>,
    #[serde(default)]
    pub kernel_integrity: Option<KernelIntegrity>,
    #[serde(default)]
    pub init_integrity: Option<InitIntegrity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessIdentity {
    pub comm: String,
    pub exe_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MasqueradeAlert {
    pub pid: u32,
    pub comm: String,
    pub exe_path: String,
    pub ppid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfProgramInfo {
    pub id: u32,
    pub prog_type: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfProgInfo {
    pub id: u32,
    pub prog_type: u32,
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KernelIntegrity {
    pub bpf_programs: Vec<BpfProgInfo>,
    pub bpf_program_count: usize,
    pub unexpected_bpf: Vec<BpfProgInfo>,
    pub kprobes: Vec<String>,
    pub kprobe_count: usize,
    pub modules: Vec<String>,
    pub module_count: usize,
    pub anomalies: Vec<String>,
    pub clean: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct XdpStats {
    pub active: bool,
    pub passed: u64,
    pub drop_entropy: u64,
    pub drop_protocol: u64,
    pub drop_port: u64,
    pub total: u64,
    pub exempt: u64,
    pub entropy_histogram: Vec<u64>,
    pub size_histogram: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FdEntry {
    pub fd: u32,
    pub fd_type: String,    
    pub target: String,     
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFdAudit {
    pub pid: u32,
    pub comm: String,
    pub fd_count: usize,
    pub socket_count: usize,
    pub pipe_count: usize,
    pub file_count: usize,
    pub suspicious: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FdAuditSummary {
    pub processes_audited: usize,
    pub total_fds: usize,
    pub total_sockets: usize,
    pub total_pipes: usize,
    pub total_files: usize,
    pub anomalies: Vec<String>,
    pub process_details: Vec<ProcessFdAudit>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InitIntegrity {
    pub init_scripts_hash: Option<Vec<u8>>,
    pub active_script_count: usize,
    pub active_scripts: Vec<String>,
    pub runlevel_hash: Option<Vec<u8>>,
    pub runlevel_map: BTreeMap<String, String>,
    pub local_d_hash: Option<Vec<u8>>,
    pub local_d_scripts: Vec<String>,
    pub conf_d_hash: Option<Vec<u8>>,
    pub total_initd_count: usize,
    pub inactive_scripts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessDetail {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub exe_path: String,
    pub cmdline: String,
    pub uid: u32,
    pub start_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessVolatileEvidence {
    pub pid: u32,
    pub comm: String,
    pub memory_maps: Vec<String>,
    pub open_fds: Vec<String>,
    pub environment: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeForensicData {
    pub timestamp: u64,
    pub process_tree: Vec<ProcessDetail>,
    pub process_volatile: Vec<ProcessVolatileEvidence>,
    pub tcp_connections: Vec<String>,
    pub arp_table: Vec<String>,
    pub dmesg_tail: Vec<String>,
    pub ima_tail: Vec<String>,
    pub uptime_seconds: u64,
    pub load_average: String,
}

// ===Internal BPF/kernel ABI structs ===
/// 	Some are scoped within their calling functions for clarity.

#[repr(C)]
struct AttrGetNextId {
    start_id: u32,
    next_id: u32,
    open_flags: u32,
}

#[repr(C)]
struct AttrGetFdById {
    id: u32,
    next_id: u32,
    open_flags: u32,
}

#[repr(C)]
struct AttrObjGetInfo {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

#[repr(C)]
struct AttrMapLookup {
    map_fd: u32,
    _pad0: u32,
    key: u64,
    value: u64,
}

#[repr(C)]
struct BpfProgInfoKernel {
    prog_type: u32,
    id: u32,
    tag: [u8; 8],
    jited_prog_len: u32,
    xlated_prog_len: u32,
    jited_prog_insns: u64,
    xlated_prog_insns: u64,
    load_time: u64,
    created_by_uid: u32,
    nr_map_ids: u32,
    map_ids: u64,
    name: [u8; 16],
    _pad: [u8; 128],
}

#[repr(C)]
struct BpfMapInfoKernel {
    map_type: u32,
    id: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    name: [u8; 16],
    _pad: [u8; 64],
}

// === Role Config Section ===
static NODE_ROLE: OnceLock<String> = OnceLock::new();

pub fn set_node_role(role: &str) {
    let _ = NODE_ROLE.set(role.to_string());
}

fn get_node_role() -> &'static str {
    NODE_ROLE.get().map(|s| s.as_str()).unwrap_or("unknown")
}

fn expected_binaries_for_role(role: &str) -> Vec<&'static str> {
    match role {
        "orchestrator" => vec![
            "/opt/mfa-agent/target/release/mfa-agent",
            "/opt/mfa-agent/target/release/vm0-cli",
            "/opt/mfa-agent/target/release/baseline-tool",
            "/opt/mfa-agent/xdp-entropy.o",
        ],
        "client" => vec![
            "/opt/mfa-agent/target/release/mfa-agent",
            "/opt/mfa-agent/target/release/baseline-tool",
            "/opt/mfa-agent/xdp-entropy.o",
        ],
        "proxy" => vec![
            "/opt/mfa-agent/target/release/mfa-agent",
            "/opt/mfa-agent/target/release/baseline-tool",
            "/opt/mfa-agent/xdp-entropy.o",
        ],
        "zts" => vec![
            "/opt/mfa-agent/target/release/mfa-agent",
            "/opt/mfa-agent/target/release/baseline-tool",
            "/opt/mfa-agent/mfa-logfwd",
            "/opt/mfa-agent/xdp-entropy.o",
        ],
        "da" => vec![
            "/opt/mfa-agent/target/release/mfa-agent",
            "/opt/mfa-agent/target/release/baseline-tool",
            "/opt/mfa-agent/mfa-logfwd",
            "/opt/mfa-agent/xdp-entropy.o",
        ],
        _ => vec![
            "/opt/mfa-agent/target/release/mfa-agent",
            "/opt/mfa-agent/xdp-entropy.o",
        ],
    }
}

// === Main Entry Point Section ===

pub fn collect_state() -> Result<EbpfState> {
    let loaded_programs = list_loaded_bpf_programs()?;
    let process_list_hash = hash_process_list()?;
    let process_count = count_processes()?;
    let network_connections = count_network_connections()?;
    let iptables_hash = hash_iptables();
    let binary_hashes = hash_binaries_for_role(get_node_role());
    let binary_dir_listing_hash = hash_binary_directory();    let listening_ports = get_listening_ports();
    let mount_hash = hash_mounts();
    let config_hash = hash_config();
    let sysctl_hash = hash_sysctl();
    let init_integrity = Some(collect_init_integrity());
    let fd_pids = get_userspace_pids();
    let fd_audit = Some(collect_fd_audit(&fd_pids));
    let kernel_integrity = Some(collect_kernel_integrity());
    let (userspace_procs, kthread_types, masquerade) = collect_process_manifest()?;
    const TRANSIENT_CONSOLE: &[&str] = &["bash", "agetty"];
    let userspace_procs_filtered: Vec<_> = userspace_procs.iter()
        .filter(|p| !TRANSIENT_CONSOLE.contains(&p.comm.as_str()))
        .collect();
    let userspace_hash = {
        let mut h = Sha256::new();
        for p in &userspace_procs_filtered {
            h.update(p.comm.as_bytes());
            h.update(b"\x00");
            h.update(p.exe_path.as_bytes());
            h.update(b"\x00");
        }
        Some(h.finalize().to_vec())
    };
    let kernel_thread_types_hash = {
        let mut h = Sha256::new();
        for t in &kthread_types {
            h.update(t.as_bytes());
            h.update(b"\x00");
        }
        Some(h.finalize().to_vec())
    };
    let kernel_modules = collect_kernel_modules();
    let (conn_tuples, conn_hash) = collect_connection_tuples();
    let xdp_attached = check_xdp_attached();
    let passwd_hash = hash_passwd();
    let ssh_config_hash = hash_ssh_config();
    let ld_preload_safe = Some(check_ld_preload());
    let entropy_available = read_entropy_available();
    let xdp_stats = Some(read_xdp_stats());
    let sysmon = Some(crate::sysmon::read_sysmon_state());
    let boot_params_hash = hash_boot_params();
    let dev_inventory_hash = hash_dev_inventory();
    let passwd_content = collect_passwd_content();
    let shadow_content = collect_shadow_content();
    let sshd_config_content = collect_sshd_config_content();
    let authorized_keys_content = collect_authorized_keys_content();
    let ld_preload_content = collect_ld_preload_content();
    let boot_params_content = collect_boot_params_content();
    let dev_inventory_list = collect_dev_inventory_list();
    let iptables_content = collect_iptables_content();
    let mount_content = collect_mount_content();
    let sysctl_content = collect_sysctl_content();
    let mut hasher = Sha256::new();
    hasher.update(&process_list_hash);
    hasher.update(process_count.to_le_bytes());
    hasher.update(network_connections.to_le_bytes());
    for prog in &loaded_programs {
        hasher.update(prog.id.to_le_bytes());
        hasher.update(&prog.name);
    }
    if let Some(ref h) = iptables_hash { hasher.update(h); }
    if let Some(ref map) = binary_hashes {
        for (k, v) in map {
            hasher.update(k.as_bytes());
            hasher.update(v);
        }
    }
    if let Some(ref h) = binary_dir_listing_hash { hasher.update(h); }
    if let Some(ref ports) = listening_ports {
        for p in ports { hasher.update(p.to_le_bytes()); }
    }
    if let Some(ref h) = mount_hash { hasher.update(h); }
    if let Some(ref h) = config_hash { hasher.update(h); }
    if let Some(ref h) = sysctl_hash { hasher.update(h); }
    if let Some(ref h) = userspace_hash { hasher.update(h); }
    if let Some(ref h) = kernel_thread_types_hash { hasher.update(h); }
    if let Some(ref h) = conn_hash { hasher.update(h); }
    if let Some(xdp) = xdp_attached { hasher.update(&[xdp as u8]); }
    if let Some(ref h) = passwd_hash { hasher.update(h); }
    if let Some(ref h) = ssh_config_hash { hasher.update(h); }
    if let Some(safe) = ld_preload_safe { hasher.update(&[safe as u8]); }
    if let Some(ent) = entropy_available { hasher.update(&ent.to_le_bytes()); }
    if let Some(ref sm) = sysmon {
        hasher.update(&[sm.active as u8]);
        hasher.update(&sm.execve_count.to_le_bytes());
        hasher.update(&sm.ptrace_count.to_le_bytes());
        hasher.update(&sm.mount_count.to_le_bytes());
        hasher.update(&sm.connect_unauthorized_count.to_le_bytes());
        hasher.update(&sm.socket_exotic_count.to_le_bytes());
    }
    if let Some(ref h) = boot_params_hash { hasher.update(h); }
    if let Some(ref h) = dev_inventory_hash { hasher.update(h); }
    let state_hash = hasher.finalize().to_vec();
    Ok(EbpfState {
        loaded_programs,
        process_count,
        process_list_hash,
        network_connections,
        state_hash,
        iptables_hash,
        binary_hashes,
        binary_dir_listing_hash,
        listening_ports,
        mount_hash,
        config_hash,
        sysctl_hash,
        userspace_processes: Some(userspace_procs),
        userspace_hash,
        kernel_thread_types: Some(kthread_types),
        kernel_thread_types_hash,
        masquerade_alerts: Some(masquerade),
        kernel_modules: Some(kernel_modules),
        connection_tuples: Some(conn_tuples),
        connection_tuples_hash: conn_hash,
        xdp_attached,
        passwd_hash,
        ssh_config_hash,
        ld_preload_safe,
        entropy_available,
        boot_params_hash,
        dev_inventory_hash,
        passwd_content,
        shadow_content,
        sshd_config_content,
        authorized_keys_content,
        ld_preload_content,
        boot_params_content,
        dev_inventory_list,
        iptables_content,
        mount_content,
        sysctl_content,
        sysmon,
        fd_audit,
        kernel_integrity,
        xdp_stats,
        init_integrity,
    })
}

// === Process Monitoring Section ===
fn collect_process_manifest() -> Result<(Vec<ProcessIdentity>, Vec<String>, Vec<MasqueradeAlert>)> {
    use std::collections::BTreeSet;
    let own_pid = std::process::id();
    let self_exe = fs::read_link("/proc/self/exe")
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let exclude_self = !self_exe.ends_with("/mfa-agent");
    let mut userspace_set: BTreeSet<ProcessIdentity> = BTreeSet::new();
    let mut kthread_set: BTreeSet<String> = BTreeSet::new();
    let mut masquerade_alerts: Vec<MasqueradeAlert> = Vec::new();
    let proc_entries = fs::read_dir("/proc")?;
    for entry in proc_entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        if exclude_self && pid == own_pid {
            continue;
        }
        let pid_path = format!("/proc/{}", pid);
        let comm = match fs::read_to_string(format!("{}/comm", pid_path)) {
            Ok(c) => c.trim().to_string(),
            Err(_) => continue,
        };
        let ppid = read_ppid(&pid_path).unwrap_or(0);
        let exe_path = fs::read_link(format!("{}/exe", pid_path))
            .map(|p| p.to_string_lossy().to_string())
            .ok();
        let is_kernel_thread = ppid == 0 || ppid == 2;
        if is_kernel_thread {
            let normalized = normalize_kernel_thread(&comm);
            kthread_set.insert(normalized);
        } else {
            let exe = exe_path.clone().unwrap_or_else(|| "[none]".to_string());
            let exe_clean = exe.trim_end_matches(" (deleted)").to_string();
            if ppid != 1 {
                let is_monitored = exe_clean.ends_with("/mfa-agent");
                if !is_monitored {
                    continue;
                }
            }
            userspace_set.insert(ProcessIdentity {
                comm: comm.clone(),
                exe_path: exe_clean.clone(),
            });
            if looks_like_kernel_thread(&comm) {
                masquerade_alerts.push(MasqueradeAlert {
                    pid,
                    comm: comm.clone(),
                    exe_path: exe_clean,
                    ppid,
                });
            }
        }
    }
    let userspace_procs: Vec<ProcessIdentity> = userspace_set.into_iter().collect();
    let kthread_types: Vec<String> = kthread_set.into_iter().collect();
    Ok((userspace_procs, kthread_types, masquerade_alerts))
}

fn read_ppid(pid_path: &str) -> Option<u32> {
    let status = fs::read_to_string(format!("{}/status", pid_path)).ok()?;
    for line in status.lines() {
        if line.starts_with("PPid:") {
            return line.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

fn looks_like_kernel_thread(comm: &str) -> bool {
    KERNEL_THREAD_PREFIXES.iter().any(|prefix| comm.starts_with(prefix))
}

fn normalize_kernel_thread(comm: &str) -> String {
    if comm.starts_with("kworker/") {
        return "kworker".to_string();
    }
    for prefix in &["cpuhp", "ksoftirqd", "migration"] {
        if comm.starts_with(prefix) && comm.get(prefix.len()..prefix.len()+1) == Some("/") {
            return prefix.to_string();
        }
    }
    if comm.starts_with("rcu_exp_par_gp_kthread_worker/") {
        return "rcu_exp_par_gp_kthread_worker".to_string();
    }
    for prefix in &["scsi_eh", "scsi_tmf"] {
        if comm.starts_with(prefix) {
            if let Some(rest) = comm.get(prefix.len()..) {
                if rest.starts_with('_') && rest[1..].chars().all(|c| c.is_ascii_digit()) {
                    return prefix.to_string();
                }
            }
        }
    }
    comm.to_string()
}

pub fn get_userspace_pids() -> Vec<(u32, String)> {
    let mut result = Vec::new();
    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return result,
    };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.chars().all(|c| c.is_numeric()) { continue; }
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let stat_path = format!("/proc/{}/stat", pid);
        if let Ok(stat) = fs::read_to_string(&stat_path) {
            let parts: Vec<&str> = stat.split_whitespace().collect();
            if parts.len() > 3 {
                let ppid: u32 = parts[3].parse().unwrap_or(0);
                if ppid == 2 || pid == 2 { continue; } // kernel thread
            }
        }
        let comm_path = format!("/proc/{}/comm", pid);
        let comm = fs::read_to_string(&comm_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if !comm.is_empty() {
            result.push((pid, comm));
        }
    }
    result
}

fn count_processes() -> Result<usize> {
    let count = fs::read_dir("/proc")?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().chars().all(|c| c.is_numeric()))
        .count();
    Ok(count)
}

fn hash_process_list() -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.chars().all(|c| c.is_numeric()) { continue; }
        let comm_path = entry.path().join("comm");
        if let Ok(comm) = fs::read_to_string(&comm_path) {
            hasher.update(name_str.as_bytes());
            hasher.update(b",");
            hasher.update(comm.trim().as_bytes());
            hasher.update(b"\n");
        }
    }
    Ok(hasher.finalize().to_vec())
}

// === Network Monitoring Section ===
fn collect_connection_tuples() -> (Vec<String>, Option<Vec<u8>>) {
    let mut tuples: Vec<String> = Vec::new();
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                if let Some(tuple) = parse_tcp_line_normalized(line) {
                    tuples.push(tuple);
                }
            }
        }
    }
    tuples.sort();
    tuples.dedup();
    let hash = {
        let mut h = Sha256::new();
        if tuples.is_empty() {
            h.update(b"empty");
        } else {
            for t in &tuples {
                h.update(t.as_bytes());
                h.update(b"\n");
            }
        }
        Some(h.finalize().to_vec())
    };
    (tuples, hash)
}

fn parse_tcp_line_normalized(line: &str) -> Option<String> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 4 {
        return None;
    }
    let state = fields[3];
    let local = fields[1];
    let local_port = parse_hex_port(local)?;
    match state {
        "0A" => Some(format!("LISTEN:{}", local_port)),
        _ => None,
    }
}

fn parse_hex_port(addr: &str) -> Option<u16> {
    let port_hex = addr.split(':').nth(1)?;
    u16::from_str_radix(port_hex, 16).ok()
}

fn count_network_connections() -> Result<usize> {
    let tcp = fs::read_to_string("/proc/net/tcp")
        .map(|s| s.lines().count().saturating_sub(1))
        .unwrap_or(0);
    let tcp6 = fs::read_to_string("/proc/net/tcp6")
        .map(|s| s.lines().count().saturating_sub(1))
        .unwrap_or(0);
    Ok(tcp + tcp6)
}

fn get_listening_ports() -> Option<Vec<u16>> {
    let mut ports = Vec::new();
    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() >= 4 && fields[3] == "0A" {
                    if let Some(port_hex) = fields[1].split(':').nth(1) {
                        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                            if !ports.contains(&port) {
                                ports.push(port);
                            }
                        }
                    }
                }
            }
        }
    }
    ports.sort();
    Some(ports)
}

// === Filesystem Integrity Section ===
pub fn hash_passwd() -> Option<Vec<u8>> {
    let mut hasher = Sha256::new();
    let mut has_data = false;
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        hasher.update(b"PASSWD:");
        hasher.update(passwd.as_bytes());
        has_data = true;
    }
    if let Ok(shadow) = fs::read_to_string("/etc/shadow") {
        hasher.update(b"SHADOW:");
        hasher.update(shadow.as_bytes());
        has_data = true;
    }
    if has_data { Some(hasher.finalize().to_vec()) } else { None }
}

pub fn hash_ssh_config() -> Option<Vec<u8>> {
    let mut hasher = Sha256::new();
    let mut has_data = false;
    if let Ok(config) = fs::read_to_string("/etc/ssh/sshd_config") {
        hasher.update(b"SSHD_CONFIG:");
        hasher.update(config.as_bytes());
        has_data = true;
    }
    if let Ok(entries) = fs::read_dir("/etc/ssh/sshd_config.d") {
        let mut files: Vec<_> = entries.flatten()
            .filter(|e| e.path().extension().map(|x| x == "conf").unwrap_or(false))
            .collect();
        files.sort_by_key(|e| e.file_name());
        for entry in files {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                hasher.update(b"SSHD_CONF_D:");
                hasher.update(entry.file_name().to_string_lossy().as_bytes());
                hasher.update(b":");
                hasher.update(content.as_bytes());
                has_data = true;
            }
        }
    }
    for keys_path in &[
        "/root/.ssh/authorized_keys",
        "/root/.ssh/authorized_keys2",
    ] {
        if let Ok(keys) = fs::read_to_string(keys_path) {
            hasher.update(b"AUTH_KEYS:");
            hasher.update(keys_path.as_bytes());
            hasher.update(b":");
            hasher.update(keys.as_bytes());
            has_data = true;
        }
    }
    for key_path in &[
        "/etc/ssh/ssh_host_ed25519_key.pub",
        "/etc/ssh/ssh_host_ecdsa_key.pub",
        "/etc/ssh/ssh_host_rsa_key.pub",
    ] {
        if let Ok(key) = fs::read_to_string(key_path) {
            hasher.update(b"HOST_KEY:");
            hasher.update(key_path.as_bytes());
            hasher.update(b":");
            hasher.update(key.as_bytes());
            has_data = true;
        }
    }
    if has_data { Some(hasher.finalize().to_vec()) } else { None }
}

pub fn collect_init_integrity() -> InitIntegrity {
    let mut state = InitIntegrity::default();
    let runlevels = ["sysinit", "boot", "default", "nonetwork"];
    let mut active_set: Vec<String> = Vec::new();
    let mut runlevel_map: BTreeMap<String, String> = BTreeMap::new();
    let mut runlevel_hasher = Sha256::new();
    for rl in &runlevels {
        let rl_path = format!("/etc/runlevels/{}", rl);
        if let Ok(entries) = fs::read_dir(&rl_path) {
            let mut sorted_entries: Vec<_> = entries
                .filter_map(|e| e.ok())
                .collect();
            sorted_entries.sort_by_key(|e| e.file_name());
            for entry in sorted_entries {
                let name = entry.file_name().to_string_lossy().to_string();
                let link_target = fs::read_link(entry.path())
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| "unknown".to_string());
                let key = format!("{}/{}", rl, name);
                runlevel_hasher.update(key.as_bytes());
                runlevel_hasher.update(b"->");
                runlevel_hasher.update(link_target.as_bytes());
                runlevel_hasher.update(b"\n");
                runlevel_map.insert(key, link_target.clone());
                if !active_set.contains(&name) {
                    active_set.push(name);
                }
            }
        }
    }
    state.runlevel_hash = Some(runlevel_hasher.finalize().to_vec());
    state.runlevel_map = runlevel_map;
    active_set.sort();
    let mut scripts_hasher = Sha256::new();
    for script_name in &active_set {
        let script_path = format!("/etc/init.d/{}", script_name);
        if let Ok(content) = fs::read(&script_path) {
            scripts_hasher.update(script_name.as_bytes());
            scripts_hasher.update(b":");
            scripts_hasher.update(&content);
            scripts_hasher.update(b"\n");
        }
    }
    state.active_script_count = active_set.len();
    state.active_scripts = active_set.clone();
    state.init_scripts_hash = Some(scripts_hasher.finalize().to_vec());
    let mut local_d_hasher = Sha256::new();
    let mut local_d_scripts = Vec::new();
    if let Ok(entries) = fs::read_dir("/etc/local.d") {
        let mut sorted: Vec<_> = entries.filter_map(|e| e.ok()).collect();
        sorted.sort_by_key(|e| e.file_name());
        for entry in sorted {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "README" { continue; }
            let path = entry.path();
            if let Ok(content) = fs::read(&path) {
                local_d_hasher.update(name.as_bytes());
                local_d_hasher.update(b":");
                local_d_hasher.update(&content);
                local_d_hasher.update(b"\n");
                local_d_scripts.push(name);
            }
        }
    }
    state.local_d_hash = Some(local_d_hasher.finalize().to_vec());
    state.local_d_scripts = local_d_scripts;
    let mut conf_d_hasher = Sha256::new();
    let conf_d_files = ["local", "net", "iptables", "hwclock", "keymaps"];
    for name in &conf_d_files {
        let path = format!("/etc/conf.d/{}", name);
        if let Ok(content) = fs::read(&path) {
            conf_d_hasher.update(name.as_bytes());
            conf_d_hasher.update(b":");
            conf_d_hasher.update(&content);
            conf_d_hasher.update(b"\n");
        }
    }
    state.conf_d_hash = Some(conf_d_hasher.finalize().to_vec());
    let mut all_initd: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir("/etc/init.d") {
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "functions.sh" { continue; }
            if name.starts_with('.') { continue; }
            all_initd.push(name);
        }
    }
    all_initd.sort();
    state.total_initd_count = all_initd.len();
    state.inactive_scripts = all_initd
        .iter()
        .filter(|s| !active_set.contains(s))
        .cloned()
        .collect();

    state
}

pub fn check_ld_preload() -> bool {
    match fs::read_to_string("/etc/ld.so.preload") {
        Ok(content) => content.trim().is_empty(),
        Err(_) => true, // File doesn't exist = safe
    }
}

pub fn hash_boot_params() -> Option<Vec<u8>> {
    let cmdline = fs::read_to_string("/proc/cmdline").ok()?;
    let mut hasher = Sha256::new();
    hasher.update(cmdline.as_bytes());
    Some(hasher.finalize().to_vec())
}

pub fn hash_dev_inventory() -> Option<Vec<u8>> {
    let entries = fs::read_dir("/dev").ok()?;
    let skip_prefixes = ["pts", "shm", "mqueue", "hugepages", "fd"];
    let mut names: Vec<String> = entries.flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if skip_prefixes.iter().any(|p| name.starts_with(p)) { return None; }
            let ft = e.file_type().ok()?;
            let type_char = if ft.is_block_device() { 'b' }
                else if ft.is_char_device() { 'c' }
                else if ft.is_symlink() { 'l' }
                else { return None };
            Some(format!("{}:{}", type_char, name))
        })
        .collect();
    names.sort();

    let mut hasher = Sha256::new();
    for name in &names {
        hasher.update(name.as_bytes());
        hasher.update(b"\n");
    }
    Some(hasher.finalize().to_vec())
}

fn hash_mounts() -> Option<Vec<u8>> {
    let mounts = fs::read_to_string("/proc/mounts").ok()?;
    let significant: String = mounts.lines()
        .filter(|l| {
            l.starts_with("/dev/") || l.starts_with("tmpfs") || l.starts_with("nfs")
                || l.starts_with("cifs") || l.starts_with("overlay")
        })
        .map(|l| {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() >= 2 { format!("{} {}", parts[0], parts[1]) }
            else { l.to_string() }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut hasher = Sha256::new();
    hasher.update(significant.as_bytes());
    Some(hasher.finalize().to_vec())
}

fn hash_config() -> Option<Vec<u8>> {
    let paths = [
        "/opt/mfa-agent/node.json",
        "/etc/crontab",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/hostname",
    ];
    let mut hasher = Sha256::new();
    let mut found = false;
    for path in &paths {
        hasher.update(path.as_bytes());
        if let Ok(data) = fs::read(path) {
            hasher.update(&data);
            found = true;
        } else {
            hasher.update(b"ABSENT");
        }
    }
    if found { Some(hasher.finalize().to_vec()) } else { None }
}

fn hash_sysctl() -> Option<Vec<u8>> {
    let keys = [
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.all.send_redirects",
        "net.ipv4.conf.all.accept_source_route",
        "net.ipv4.tcp_syncookies",
        "kernel.kptr_restrict",
        "kernel.dmesg_restrict",
        "kernel.sysrq",
        "kernel.randomize_va_space",
        "fs.suid_dumpable",
    ];
    let mut values = String::new();
    for key in &keys {
        let path = format!("/proc/sys/{}", key.replace('.', "/"));
        if let Ok(val) = fs::read_to_string(&path) {
            values.push_str(key);
            values.push('=');
            values.push_str(val.trim());
            values.push('\n');
        }
    }
    if values.is_empty() { return None; }
    let mut hasher = Sha256::new();
    hasher.update(values.as_bytes());
    Some(hasher.finalize().to_vec())
}

fn hash_iptables() -> Option<Vec<u8>> {
    crate::netfilter::hash_iptables_kernel()
}

pub fn hash_binaries_for_role(role: &str) -> Option<BTreeMap<String, Vec<u8>>> {
    let paths = expected_binaries_for_role(role);
    let mut map = BTreeMap::new();
    for path in paths {
        match fs::read(path) {
            Ok(data) => {
                let hash = Sha256::digest(&data);
                map.insert(path.to_string(), hash.to_vec());
            }
            Err(_) => {
                map.insert(path.to_string(), Vec::new());
            }
        }
    }
    Some(map)
}

pub fn hash_binary_directory() -> Option<Vec<u8>> {
    let dirs = [
        "/opt/mfa-agent/target/release",
        "/opt/mfa-agent",
    ];
    let mut all_entries: Vec<String> = Vec::new();
    for dir in &dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        if let Some(name) = entry.file_name().to_str() {
                            all_entries.push(format!("{}/{}", dir, name));
                        }
                    }
                }
            }
        }
    }
    all_entries.sort();
    all_entries.dedup();
    let mut hasher = Sha256::new();
    for e in &all_entries {
        hasher.update(e.as_bytes());
        hasher.update(b"\n");
    }
    Some(hasher.finalize().to_vec())
}

// === Content collectors Section ===
fn collect_passwd_content() -> Option<String> {
    fs::read_to_string("/etc/passwd").ok()
}

fn collect_shadow_content() -> Option<String> {
    fs::read_to_string("/etc/shadow").ok()
}

fn collect_sshd_config_content() -> Option<String> {
    fs::read_to_string("/etc/ssh/sshd_config").ok()
}

fn collect_authorized_keys_content() -> Option<String> {
    let mut content = String::new();
    for path in &["/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2"] {
        if let Ok(keys) = fs::read_to_string(path) {
            content.push_str(&format!("=== {} ===\n{}\n", path, keys));
        }
    }
    if content.is_empty() { None } else { Some(content) }
}

fn collect_ld_preload_content() -> Option<String> {
    fs::read_to_string("/etc/ld.so.preload").ok()
}

fn collect_boot_params_content() -> Option<String> {
    fs::read_to_string("/proc/cmdline").ok().map(|s| s.trim().to_string())
}

fn collect_dev_inventory_list() -> Option<Vec<String>> {
    let entries = fs::read_dir("/dev").ok()?;
    let skip_prefixes = ["pts", "shm", "mqueue", "hugepages", "fd"];
    let mut names: Vec<String> = entries.flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if skip_prefixes.iter().any(|p| name.starts_with(p)) { return None; }
            let ft = e.file_type().ok()?;
            let type_char = if ft.is_block_device() { 'b' }
                else if ft.is_char_device() { 'c' }
                else if ft.is_symlink() { 'l' }
                else { return None };
            Some(format!("{}:{}", type_char, name))
        })
        .collect();
    names.sort();
    Some(names)
}

fn collect_iptables_content() -> Option<String> {
    crate::netfilter::read_iptables_content()
}

fn collect_mount_content() -> Option<String> {
    let mounts = fs::read_to_string("/proc/mounts").ok()?;
    let significant: String = mounts.lines()
        .filter(|l| {
            l.starts_with("/dev/") || l.starts_with("tmpfs") || l.starts_with("nfs")
                || l.starts_with("cifs") || l.starts_with("overlay")
        })
        .collect::<Vec<_>>()
        .join("\n");
    if significant.is_empty() { None } else { Some(significant) }
}

fn collect_sysctl_content() -> Option<String> {
    let keys = [
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.all.send_redirects",
        "net.ipv4.conf.all.accept_source_route",
        "net.ipv4.tcp_syncookies",
        "kernel.kptr_restrict",
        "kernel.dmesg_restrict",
        "kernel.sysrq",
        "kernel.randomize_va_space",
        "fs.suid_dumpable",
    ];
    let mut values = String::new();
    for key in &keys {
        let path = format!("/proc/sys/{}", key.replace('.', "/"));
        if let Ok(val) = fs::read_to_string(&path) {
            values.push_str(key);
            values.push('=');
            values.push_str(val.trim());
            values.push('\n');
        }
    }
    if values.is_empty() { None } else { Some(values) }
}

// === Kernel integrity Section ===
pub fn collect_kernel_integrity() -> KernelIntegrity {
    let bpf_programs = enumerate_bpf_programs();
    let unexpected_bpf: Vec<BpfProgInfo> = bpf_programs
        .iter()
        .filter(|p| !is_expected_bpf(p) && !p.name.is_empty())
        .cloned()
        .collect();
    let kprobes = read_kprobes();
    let modules = read_kernel_modules();
    let mut anomalies = Vec::new();
    for prog in &unexpected_bpf {
        anomalies.push(format!(
            "unexpected BPF program: id={} type={} name='{}'",
            prog.id, bpf_prog_type_name(prog.prog_type), prog.name
        ));
    }
    for kp in &kprobes {
        anomalies.push(format!("kprobe detected: {}", kp));
    }
    for m in &modules {
        anomalies.push(format!("kernel module loaded: {}", m));
    }
    let clean = anomalies.is_empty();
    KernelIntegrity {
        bpf_program_count: bpf_programs.len(),
        bpf_programs,
        unexpected_bpf,
        kprobe_count: kprobes.len(),
        kprobes,
        module_count: modules.len(),
        modules,
        anomalies,
        clean,
    }
}

fn enumerate_bpf_programs() -> Vec<BpfProgInfo> {
    let mut programs = Vec::new();
    let mut current_id: u32 = 0;
    loop {
        #[repr(C)]
        struct AttrGetNextId {
            start_id: u32,
            next_id: u32,
            open_flags: u32,
        }
        let mut attr = AttrGetNextId {
            start_id: current_id,
            next_id: 0,
            open_flags: 0,
        };
        let ret = unsafe {
            libc::syscall(
                SYS_BPF,
                BPF_PROG_GET_NEXT_ID,
                &mut attr as *mut _ as *mut libc::c_void,
                std::mem::size_of::<AttrGetNextId>(),
            )
        };
        if ret != 0 {
            break; 
        }
        current_id = attr.next_id;
        if let Some(info) = get_bpf_prog_info(current_id) {
            programs.push(info);
        }
    }
    programs
}

fn get_bpf_prog_info(prog_id: u32) -> Option<BpfProgInfo> {
    #[repr(C)]
    struct AttrGetFdById {
        prog_id: u32,
        next_id: u32,
        open_flags: u32,
    }
    let mut attr_fd = AttrGetFdById {
        prog_id,
        next_id: 0,
        open_flags: 0,
    };
    let fd = unsafe {
        libc::syscall(
            SYS_BPF,
            BPF_PROG_GET_FD_BY_ID,
            &mut attr_fd as *mut _ as *mut libc::c_void,
            std::mem::size_of::<AttrGetFdById>(),
        )
    };
    if fd < 0 { return None; }
    let fd = fd as i32;
    #[repr(C)]
    struct BpfProgInfoKernel {
        prog_type: u32,
        id: u32,
        tag: [u8; 8],
        jited_prog_len: u32,
        xlated_prog_len: u32,
        jited_prog_insns: u64,
        xlated_prog_insns: u64,
        load_time: u64,
        created_by_uid: u32,
        nr_map_ids: u32,
        map_ids: u64,
        name: [u8; 16],
        _padding: [u8; 128], 
    }
    let mut info: BpfProgInfoKernel = unsafe { std::mem::zeroed() };
    let info_len = std::mem::size_of::<BpfProgInfoKernel>() as u32;
    #[repr(C)]
    struct AttrObjGetInfo {
        bpf_fd: u32,
        info_len: u32,
        info: u64,
    }
    let mut attr_info = AttrObjGetInfo {
        bpf_fd: fd as u32,
        info_len,
        info: &mut info as *mut _ as u64,
    };
    let ret = unsafe {
        libc::syscall(
            SYS_BPF,
            BPF_OBJ_GET_INFO_BY_FD,
            &mut attr_info as *mut _ as *mut libc::c_void,
            std::mem::size_of::<AttrObjGetInfo>(),
        )
    };
    unsafe { libc::close(fd); }
    if ret != 0 { return None; }
    let name_end = info.name.iter().position(|&b| b == 0).unwrap_or(16);
    let name = String::from_utf8_lossy(&info.name[..name_end]).to_string();
    Some(BpfProgInfo {
        id: info.id,
        prog_type: info.prog_type,
        name,
    })
}

fn is_expected_bpf(prog: &BpfProgInfo) -> bool {
    EXPECTED_BPF_NAMES.iter().any(|&expected| prog.name == expected)
}

fn bpf_prog_type_name(t: u32) -> &'static str {
    match t {
        0 => "unspec",
        1 => "socket_filter",
        2 => "kprobe",
        3 => "sched_cls",
        4 => "sched_act",
        5 => "tracepoint",
        6 => "xdp",
        7 => "perf_event",
        8 => "cgroup_skb",
        9 => "cgroup_sock",
        10 => "lwt_in",
        11 => "lwt_out",
        12 => "lwt_xmit",
        13 => "sock_ops",
        14 => "sk_skb",
        15 => "cgroup_device",
        17 => "raw_tracepoint",
        18 => "cgroup_sock_addr",
        20 => "tracing",
        22 => "ext",
        23 => "lsm",
        26 => "tracepoint",
        _ => "unknown",
    }
}

fn read_kprobes() -> Vec<String> {
    let paths = [
        "/sys/kernel/tracing/kprobe_events",
        "/sys/kernel/debug/kprobes/list",
        "/sys/kernel/debug/tracing/kprobe_events",
    ];
    for path in &paths {
        if let Ok(content) = fs::read_to_string(path) {
            let probes: Vec<String> = content
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| l.to_string())
                .collect();
            if !probes.is_empty() {
                return probes;
            }
        }
    }
    Vec::new()
}

fn read_kernel_modules() -> Vec<String> {
    match fs::read_to_string("/proc/modules") {
        Ok(content) => {
            content.lines()
                .filter(|l| !l.is_empty())
                .map(|l| {
                    l.split_whitespace()
                        .next()
                        .unwrap_or("unknown")
                        .to_string()
                })
                .collect()
        }
        Err(_) => Vec::new(),
    }
}

fn collect_kernel_modules() -> Vec<String> {
    match fs::read_to_string("/proc/modules") {
        Ok(content) => {
            content.lines()
                .filter(|l| !l.is_empty())
                .map(|l| {
                    l.split_whitespace()
                        .next()
                        .unwrap_or(l)
                        .to_string()
                })
                .collect()
        }
        Err(_) => Vec::new(), 
    }
}

fn list_loaded_bpf_programs() -> Result<Vec<BpfProgramInfo>> {
    let mut programs = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/fs/bpf") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                programs.push(BpfProgramInfo {
                    id: 0,
                    prog_type: "pinned".to_string(),
                    name,
                });
            }
        }
    }
    Ok(programs)
}

// === FD Audit Section ===
pub fn collect_fd_audit(userspace_pids: &[(u32, String)]) -> FdAuditSummary {
    let mut summary = FdAuditSummary::default();
    for (pid, comm) in userspace_pids {
        let fd_path = format!("/proc/{}/fd", pid);
        let fd_dir = match fs::read_dir(&fd_path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let mut audit = ProcessFdAudit {
            pid: *pid,
            comm: comm.clone(),
            fd_count: 0,
            socket_count: 0,
            pipe_count: 0,
            file_count: 0,
            suspicious: Vec::new(),
        };
        for entry in fd_dir.flatten() {
            let fd_num: u32 = match entry.file_name().to_string_lossy().parse() {
                Ok(n) => n,
                Err(_) => continue,
            };
            let link_path = format!("/proc/{}/fd/{}", pid, fd_num);
            let target = match fs::read_link(&link_path) {
                Ok(t) => t.to_string_lossy().to_string(),
                Err(_) => continue,
            };
            let fd_type = classify_fd(&target);
            match fd_type.as_str() {
                "socket" => audit.socket_count += 1,
                "pipe" => audit.pipe_count += 1,
                "file" => audit.file_count += 1,
                _ => {}
            }
            audit.fd_count += 1;
            check_suspicious(&target, &fd_type, fd_num, *pid, comm, &mut audit.suspicious);
        }
        if comm != "mfa-agent" && comm != "mfa-logfwd" && comm != "mfa-monitor"
            && comm != "init" && comm != "bash" && comm != "systemd-udevd"
            && comm != "vm0-cli" && comm != "mfa-cli" && comm != "agetty" {
            audit.suspicious.push(format!(
                "unknown process '{}' (pid {}) has {} open fds",
                comm, pid, audit.fd_count
            ));
        }
        if audit.pipe_count >= 2 {
            audit.suspicious.push(format!(
                "pid {} '{}' has {} pipes (potential reverse shell)",
                pid, comm, audit.pipe_count
            ));
        }
        summary.total_fds += audit.fd_count;
        summary.total_sockets += audit.socket_count;
        summary.total_pipes += audit.pipe_count;
        summary.total_files += audit.file_count;
        summary.anomalies.extend(audit.suspicious.clone());
        summary.process_details.push(audit);
        summary.processes_audited += 1;
    }
    summary
}

fn classify_fd(target: &str) -> String {
    if target.starts_with("socket:") {
        "socket".to_string()
    } else if target.starts_with("pipe:") {
        "pipe".to_string()
    } else if target.starts_with("anon_inode:") {
        "anon_inode".to_string()
    } else if target.starts_with("/dev/") {
        "device".to_string()
    } else if target.starts_with('/') {
        "file".to_string()
    } else {
        "other".to_string()
    }
}

fn check_suspicious(
    target: &str,
    fd_type: &str,
    fd_num: u32,
    pid: u32,
    comm: &str,
    suspicious: &mut Vec<String>,
) {
    for sensitive in SENSITIVE_PATHS {
        if target.starts_with(sensitive) {
            suspicious.push(format!(
                "pid {} '{}' fd {} has sensitive file open: {}",
                pid, comm, fd_num, target
            ));
        }
    }
    if fd_type == "file" {
        let is_expected = target == "/dev/null"
            || target.starts_with("/proc/")
            || target.starts_with("/sys/")
            || target.starts_with("/opt/mfa-agent/audit.jsonl")
            || target.starts_with("/opt/mfa-agent/node.json")
            || target.starts_with("/opt/mfa-agent/baselines.json")
            || target.starts_with("/opt/mfa-agent/credentials.json")
            || target.starts_with("/var/log/")
            || target.starts_with("/run/")
            || target.starts_with("/etc/udev/");
        if !is_expected {
            suspicious.push(format!(
                "pid {} '{}' fd {} has unexpected file open: {}",
                pid, comm, fd_num, target
            ));
        }
    }
    if fd_type == "device" {
        let is_expected = target == "/dev/ttyS0"
            || target == "/dev/null"
            || target == "/dev/tpmrm0"
            || target == "/dev/urandom";
        if !is_expected {
            suspicious.push(format!(
                "pid {} '{}' fd {} has unexpected device open: {}",
                pid, comm, fd_num, target
            ));
        }
    }
}

// === XDP Section ===
fn check_xdp_attached() -> Option<bool> {
    crate::netfilter::check_xdp_kernel("enp6s18")
}

pub fn read_entropy_available() -> Option<u32> {
    fs::read_to_string("/proc/sys/kernel/random/entropy_avail")
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

pub fn read_xdp_stats() -> XdpStats {
    let mut stats = XdpStats::default();
    let (stats_fd, entropy_fd, size_fd) = match find_xdp_maps() {
        Some(fds) => fds,
        None => return stats,
    };
    stats.active = true;
    let cpus = num_cpus();
    stats.passed = read_percpu_counter(stats_fd, STAT_PASSED, cpus);
    stats.drop_entropy = read_percpu_counter(stats_fd, STAT_DROP_ENT, cpus);
    stats.drop_protocol = read_percpu_counter(stats_fd, STAT_DROP_PRO, cpus);
    stats.drop_port = read_percpu_counter(stats_fd, STAT_DROP_PRT, cpus);
    stats.total = read_percpu_counter(stats_fd, STAT_TOTAL, cpus);
    stats.exempt = read_percpu_counter(stats_fd, STAT_EXEMPT, cpus);
    close_fd(stats_fd);
    if entropy_fd >= 0 {
        stats.entropy_histogram = read_percpu_histogram(entropy_fd, 26, cpus);
        close_fd(entropy_fd);
    }
    if size_fd >= 0 {
        stats.size_histogram = read_percpu_histogram(size_fd, 16, cpus);
        close_fd(size_fd);
    }
    stats
}

fn find_xdp_maps() -> Option<(RawFd, RawFd, RawFd)> {
    let mut current_id: u32 = 0;
    loop {
        let mut attr = AttrGetNextId {
            start_id: current_id,
            next_id: 0,
            open_flags: 0,
        };
        let ret = bpf_syscall(
            BPF_PROG_GET_NEXT_ID,
            &mut attr as *mut _ as *mut u8,
            std::mem::size_of::<AttrGetNextId>(),
        );
        if ret != 0 { break; }
        current_id = attr.next_id;
        let mut attr_fd = AttrGetFdById {
            id: current_id,
            next_id: 0,
            open_flags: 0,
        };
        let prog_fd = bpf_syscall(
            BPF_PROG_GET_FD_BY_ID,
            &mut attr_fd as *mut _ as *mut u8,
            std::mem::size_of::<AttrGetFdById>(),
        );
        if prog_fd < 0 { continue; }
        let prog_fd = prog_fd as RawFd;
        let mut map_ids: [u32; 16] = [0; 16];
        let mut info: BpfProgInfoKernel = unsafe { std::mem::zeroed() };
        info.nr_map_ids = 16;
        info.map_ids = map_ids.as_mut_ptr() as u64;
        let mut attr_info = AttrObjGetInfo {
            bpf_fd: prog_fd as u32,
            info_len: std::mem::size_of::<BpfProgInfoKernel>() as u32,
            info: &mut info as *mut _ as u64,
        };
        let ret = bpf_syscall(
            BPF_OBJ_GET_INFO_BY_FD,
            &mut attr_info as *mut _ as *mut u8,
            std::mem::size_of::<AttrObjGetInfo>(),
        );
        close_fd(prog_fd);
        if ret != 0 { continue; }
        let name_end = info.name.iter().position(|&b| b == 0).unwrap_or(16);
        let name = std::str::from_utf8(&info.name[..name_end]).unwrap_or("");
        if name != "xdp_entropy" { continue; }
        let mut stats_fd: RawFd = -1;
        let mut entropy_fd: RawFd = -1;
        let mut size_fd: RawFd = -1;
        for i in 0..info.nr_map_ids as usize {
            if i >= 16 { break; }
            let map_id = map_ids[i];
            if map_id == 0 { continue; }
            let mut attr_mfd = AttrGetFdById {
                id: map_id,
                next_id: 0,
                open_flags: 0,
            };
            let mfd = bpf_syscall(
                BPF_MAP_GET_FD_BY_ID,
                &mut attr_mfd as *mut _ as *mut u8,
                std::mem::size_of::<AttrGetFdById>(),
            );
            if mfd < 0 { continue; }
            let mfd = mfd as RawFd;
            let mut minfo: BpfMapInfoKernel = unsafe { std::mem::zeroed() };
            let mut attr_mi = AttrObjGetInfo {
                bpf_fd: mfd as u32,
                info_len: std::mem::size_of::<BpfMapInfoKernel>() as u32,
                info: &mut minfo as *mut _ as u64,
            };
            let ret = bpf_syscall(
                BPF_OBJ_GET_INFO_BY_FD,
                &mut attr_mi as *mut _ as *mut u8,
                std::mem::size_of::<AttrObjGetInfo>(),
            );
            if ret != 0 { close_fd(mfd); continue; }
            let mname_end = minfo.name.iter().position(|&b| b == 0).unwrap_or(16);
            let mname = std::str::from_utf8(&minfo.name[..mname_end]).unwrap_or("");
            match mname {
                "stats" => stats_fd = mfd,
                "entropy_hist" => entropy_fd = mfd,
                "size_hist" => size_fd = mfd,
                _ => close_fd(mfd),
            }
        }
        if stats_fd >= 0 {
            return Some((stats_fd, entropy_fd, size_fd));
        }
        if entropy_fd >= 0 { close_fd(entropy_fd); }
        if size_fd >= 0 { close_fd(size_fd); }
    }
    None
}

fn read_percpu_counter(map_fd: RawFd, key: u32, cpus: usize) -> u64 {
    let mut values: Vec<u64> = vec![0u64; cpus];
    let key_val = key;
    let mut attr = AttrMapLookup {
        map_fd: map_fd as u32,
        _pad0: 0,
        key: &key_val as *const u32 as u64,
        value: values.as_mut_ptr() as u64,
    };
    let ret = bpf_syscall(
        BPF_MAP_LOOKUP_ELEM,
        &mut attr as *mut _ as *mut u8,
        std::mem::size_of::<AttrMapLookup>(),
    );
    if ret != 0 { return 0; }
    values.iter().sum()
}

fn read_percpu_histogram(map_fd: RawFd, entries: u32, cpus: usize) -> Vec<u64> {
    let mut histogram = Vec::with_capacity(entries as usize);
    for key in 0..entries {
        histogram.push(read_percpu_counter(map_fd, key, cpus));
    }
    histogram
}

fn bpf_syscall(cmd: u32, attr: *mut u8, size: usize) -> i64 {
    unsafe {
        libc::syscall(SYS_BPF, cmd, attr as *mut libc::c_void, size)
    }
}

fn close_fd(fd: RawFd) {
    unsafe { libc::close(fd); }
}

fn num_cpus() -> usize {
    let s = std::fs::read_to_string("/sys/devices/system/cpu/possible")
        .unwrap_or_else(|_| "0-3".to_string());
    if let Some(end) = s.trim().split('-').last() {
        if let Ok(n) = end.parse::<usize>() {
            return n + 1;
        }
    }
    4
}

// === Forensic Snapshot Section ===
pub fn collect_forensic_snapshot() -> NodeForensicData {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let process_tree = collect_process_tree();
    let process_volatile: Vec<ProcessVolatileEvidence> = process_tree.iter()
        .filter(|p| p.exe_path != "[kernel]" && p.ppid != 0)
        .map(|p| ProcessVolatileEvidence {
            pid: p.pid,
            comm: p.comm.clone(),
            memory_maps: collect_process_maps(p.pid),
            open_fds: collect_process_fds(p.pid),
            environment: collect_process_environ(p.pid),
        })
        .collect();
    NodeForensicData {
        timestamp,
        process_tree,
        process_volatile,
        tcp_connections: collect_full_connections(),
        arp_table: collect_arp_table(),
        dmesg_tail: collect_dmesg_tail(50),
        ima_tail: collect_ima_tail(20),
        uptime_seconds: collect_uptime(),
        load_average: collect_load_average(),
    }
}

pub fn collect_process_tree() -> Vec<ProcessDetail> {
    let mut processes = Vec::new();
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return processes,
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let proc_dir = format!("/proc/{}", pid);
        let comm = fs::read_to_string(format!("{}/comm", proc_dir))
            .unwrap_or_default()
            .trim()
            .to_string();
        let exe_path = fs::read_link(format!("{}/exe", proc_dir))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "[kernel]".to_string());
        let cmdline = fs::read_to_string(format!("{}/cmdline", proc_dir))
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();
        let uid = fs::read_to_string(format!("{}/status", proc_dir))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse::<u32>().ok())
            })
            .unwrap_or(0);
        let ppid = fs::read_to_string(format!("{}/status", proc_dir))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("PPid:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse::<u32>().ok())
            })
            .unwrap_or(0);
        let start_time = fs::read_to_string(format!("{}/stat", proc_dir))
            .ok()
            .and_then(|s| {
                let after_comm = s.find(')').map(|i| &s[i + 2..])?;
                after_comm.split_whitespace().nth(19).map(|s| s.to_string())
            })
            .unwrap_or_else(|| "0".to_string());
        processes.push(ProcessDetail {
            pid,
            ppid,
            comm,
            exe_path,
            cmdline,
            uid,
            start_time,
        });
    }
    processes.sort_by_key(|p| p.pid);
    processes
}


pub fn collect_process_maps(pid: u32) -> Vec<String> {
    fs::read_to_string(format!("/proc/{}/maps", pid))
        .unwrap_or_default()
        .lines()
        .map(|l| l.to_string())
        .collect()
}

pub fn collect_process_fds(pid: u32) -> Vec<String> {
    let mut fds = Vec::new();
    if let Ok(entries) = fs::read_dir(format!("/proc/{}/fd", pid)) {
        for entry in entries.flatten() {
            let fd_num = entry.file_name().to_string_lossy().to_string();
            let target = fs::read_link(entry.path())
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "???".to_string());
            fds.push(format!("fd {} -> {}", fd_num, target));
        }
    }
    fds.sort();
    fds
}

pub fn collect_process_environ(pid: u32) -> Vec<String> {
    fs::read_to_string(format!("/proc/{}/environ", pid))
        .unwrap_or_default()
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

pub fn collect_full_connections() -> Vec<String> {
    match fs::read_to_string("/proc/net/tcp") {
        Ok(content) => {
            content.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        }
        Err(_) => Vec::new(),
    }
}

pub fn collect_arp_table() -> Vec<String> {
    match fs::read_to_string("/proc/net/arp") {
        Ok(content) => {
            content.lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        }
        Err(_) => Vec::new(),
    }
}

pub fn collect_dmesg_tail(lines: usize) -> Vec<String> {
    if let Ok(content) = fs::read_to_string("/var/log/dmesg") {
        let all_lines: Vec<&str> = content.lines().collect();
        let start = if all_lines.len() > lines { all_lines.len() - lines } else { 0 };
        return all_lines[start..].iter().map(|l| l.to_string()).collect();
    }
    Vec::new()
}

pub fn collect_ima_tail(lines: usize) -> Vec<String> {
    match fs::read_to_string("/sys/kernel/security/ima/ascii_runtime_measurements") {
        Ok(content) => {
            let all_lines: Vec<&str> = content.lines().collect();
            let start = if all_lines.len() > lines { all_lines.len() - lines } else { 0 };
            all_lines[start..].iter().map(|l| l.to_string()).collect()
        }
        Err(_) => Vec::new(),
    }
}

pub fn collect_uptime() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()
            .and_then(|v| v.parse::<f64>().ok()))
        .map(|v| v as u64)
        .unwrap_or(0)
}

pub fn collect_load_average() -> String {
    fs::read_to_string("/proc/loadavg")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}
