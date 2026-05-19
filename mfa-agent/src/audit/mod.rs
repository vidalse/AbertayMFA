use anyhow::Result;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::io::Write;
use crate::protocol::{NodeVerificationResult, Attestation};
use crate::ebpf;

const GENESIS_HASH: &str = "MFA-AUDIT-GENESIS-v2";
const AUDIT_VERSION: u32 = 2;
const TPM_CHECKPOINT_INTERVAL: u64 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationMeta {
    pub node_id: String,
    pub timestamp: u64,
    pub tpm_quote_bytes: usize,
    pub tpm_signature_bytes: usize,
    pub ak_public_bytes: usize,
    pub tpm_signed: bool,
    pub pcr_count: usize,
    pub ima_count: usize,
    pub ima_aggregate_hash: String,
    pub ima_pcr10: String,
    pub process_count: usize,
    pub network_connections: usize,
    pub xdp_attached: Option<bool>,
    pub userspace_process_count: Option<usize>,
    pub userspace_processes: Option<Vec<String>>,
    pub kernel_thread_types: Option<Vec<String>>,
    pub connection_tuples: Option<Vec<String>>,
    pub binary_hashes: Option<Vec<String>>,
    pub init_active_scripts: Option<Vec<String>>,
    pub init_inactive_scripts: Option<Vec<String>>,
    pub init_scripts_hash: Option<String>,
    pub kernel_thread_type_count: Option<usize>,
    pub kernel_modules_count: Option<usize>,
    pub connection_tuple_count: Option<usize>,
    pub passwd_content: Option<String>,
    pub shadow_content: Option<String>,
    pub sshd_config_content: Option<String>,
    pub authorized_keys_content: Option<String>,
    pub ld_preload_content: Option<String>,
    pub boot_params_content: Option<String>,
    pub dev_inventory_list: Option<Vec<String>>,
    pub iptables_content: Option<String>,
    pub mount_content: Option<String>,
    pub sysctl_content: Option<String>,
    pub entropy_available: Option<u32>,
    pub xdp_passed: Option<u64>,
    pub xdp_drop_entropy: Option<u64>,
    pub xdp_drop_protocol: Option<u64>,
    pub xdp_drop_port: Option<u64>,
    pub xdp_total: Option<u64>,
    pub xdp_exempt: Option<u64>,
    pub xdp_entropy_histogram: Option<Vec<u64>>,
    pub xdp_size_histogram: Option<Vec<u64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntryV2 {
    pub version: u32,
    pub seq: u64,
    pub timestamp: u64,
    pub node_id: String,
    pub heartbeat: u64,
    pub event: AuditEvent,
    pub chain_id: String,
    pub prev_hash: String,
    /// Per-node verification results
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Vec<NodeAuditRecord>>,
    /// Per-node attestation metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_meta: Option<Vec<AttestationMeta>>,
    /// Forensic tier
    pub tier: ForensicTier,
    /// Forensic capture (Mode 2 on failure, Mode 3 always)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forensic: Option<ForensicCapture>,
    /// Timing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_duration_ms: Option<u64>,
    /// Session state
    pub session_status: String,
    pub authorized: bool,
    pub total_nodes_verified: usize,
    /// Session proof 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token_hash: Option<String>,
    /// TPM checkpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tpm_checkpoint: Option<TpmCheckpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmCheckpoint {
    pub chain_hash: String,
    pub signature: String,
    pub entries_covered: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEvent {
    ChainVerified,
    ChainDenied,
    HeartbeatOk,
    HeartbeatFail,
    SessionRevoked,
    AgentStarted,
    SessionEnded,    
}

impl std::fmt::Display for AuditEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditEvent::ChainVerified => write!(f, "CHAIN_VERIFIED"),
            AuditEvent::ChainDenied => write!(f, "CHAIN_DENIED"),
            AuditEvent::HeartbeatOk => write!(f, "HEARTBEAT_OK"),
            AuditEvent::HeartbeatFail => write!(f, "HEARTBEAT_FAIL"),
            AuditEvent::SessionRevoked => write!(f, "SESSION_REVOKED"),
            AuditEvent::AgentStarted => write!(f, "AGENT_STARTED"),
            AuditEvent::SessionEnded => write!(f, "SESSION_ENDED"),            
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAuditRecord {
    pub node: String,
    pub chain: u8,
    pub pass: bool,
    
    pub pcr_match: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcr_mismatch_indices: Option<Vec<u8>>,

    pub ima_valid: bool,
    pub ima_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ima_delta: Option<i64>,

    pub userspace_ok: bool,
    pub userspace_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userspace_diff: Option<Vec<String>>,

    pub kernel_threads_ok: bool,
    pub kernel_thread_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_thread_diff: Option<Vec<String>>,

    pub masquerade_detected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub masquerade_details: Option<Vec<String>>,

    pub kernel_modules_empty: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_modules_loaded: Option<Vec<String>>,

    pub connections_ok: bool,
    pub connection_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_diff: Option<Vec<String>>,

    pub fw_ok: bool,
    pub bin_ok: bool,
    pub ports_ok: bool,
    pub ports: Vec<u16>,
    pub mnt_ok: bool,
    pub cfg_ok: bool,
    pub sys_ok: bool,
    pub xdp_attached: bool,
    pub passwd_ok: bool,
    pub ssh_ok: bool,
    pub ld_preload_safe: bool,
    pub boot_params_ok: bool,
    pub dev_inventory_ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_available: Option<u32>,
    /// Sysmon behavioral monitoring
    pub sysmon_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sysmon_hooks: Option<u64>,
    pub sysmon_anomaly: bool,
    pub sysmon_unloaded: bool,
    /// Sysmon deltas
    pub sysmon_exec_delta: Option<u64>,
    pub sysmon_ptrace_delta: Option<u64>,
    pub sysmon_mount_delta: Option<u64>,
    pub sysmon_conn_delta: Option<u64>,
    pub sysmon_sock_delta: Option<u64>,
    /// FD audit, kernel integrity, init integrity
    pub fd_ok: bool,
    pub fd_count: usize,
    pub kern_ok: bool,
    pub kern_details: Option<String>,
    pub init_ok: bool,
    pub init_count: usize,
    pub init_unused: usize,
    pub sig_valid: bool,
    pub ak_match: bool,

    pub raw_details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum ForensicTier {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for ForensicTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForensicTier::Info => write!(f, "INFO"),
            ForensicTier::Warning => write!(f, "WARNING"),
            ForensicTier::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicCapture {
    pub tier: String,
    pub trigger_nodes: Vec<String>,
    pub trigger_checks: Vec<String>,

    /// Full verification details for failing nodes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_details: Option<Vec<String>>,

    /// Deep forensic snapshot of the LOCAL node (verifier).
    /// 	Collected at the moment of detection, captures the verifier's
    /// 	own system state as evidence that the verifier itself was not
    /// 	compromised when it made the detection decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_snapshot: Option<ebpf::NodeForensicData>,
}

pub struct AuditLogger {
    path: String,
    seq: u64,
    prev_hash: String,
    log_mode: u8,
    node_id: String,
    heartbeat_count: u64,
}

pub fn extract_attestation_meta(att: &Attestation) -> AttestationMeta {
    let q = &att.tpm_quote;
    AttestationMeta {
        node_id: att.vm_identity.clone(),
        timestamp: att.timestamp,
        tpm_quote_bytes: q.quote_data.len(),
        tpm_signature_bytes: q.signature.len(),
        ak_public_bytes: q.ak_public.len(),
        tpm_signed: !q.quote_data.is_empty() && !q.signature.is_empty(),
        pcr_count: q.pcr_values.len(),
        ima_count: q.ima_measurements.count,
        ima_aggregate_hash: hex::encode(&q.ima_measurements.aggregate_hash),
        ima_pcr10: hex::encode(&q.ima_measurements.pcr10_value),
        process_count: q.ebpf_state.process_count,
        network_connections: q.ebpf_state.network_connections,
        xdp_attached: q.ebpf_state.xdp_attached,
        userspace_process_count: q.ebpf_state.userspace_processes.as_ref().map(|p| p.len()),
        userspace_processes: q.ebpf_state.userspace_processes.as_ref().map(|procs|
            procs.iter().map(|p| format!("{} ({})", p.comm, p.exe_path)).collect()
        ),
        kernel_thread_type_count: q.ebpf_state.kernel_thread_types.as_ref().map(|t| t.len()),
        kernel_thread_types: q.ebpf_state.kernel_thread_types.clone(),
        kernel_modules_count: q.ebpf_state.kernel_modules.as_ref().map(|m| m.len()),
        connection_tuple_count: q.ebpf_state.connection_tuples.as_ref().map(|c| c.len()),
        connection_tuples: q.ebpf_state.connection_tuples.clone(),
        binary_hashes: q.ebpf_state.binary_hashes.as_ref().map(|m|
            m.iter().map(|(path, hash)| format!("{}: {}", path, hex::encode(hash))).collect()
        ),
        init_active_scripts: q.ebpf_state.init_integrity.as_ref()
            .map(|i| i.active_scripts.clone()),
        init_inactive_scripts: q.ebpf_state.init_integrity.as_ref()
            .map(|i| i.inactive_scripts.clone()),
        init_scripts_hash: q.ebpf_state.init_integrity.as_ref()
            .and_then(|i| i.init_scripts_hash.as_ref().map(|h| hex::encode(h))),
        passwd_content: q.ebpf_state.passwd_content.clone(),
        shadow_content: q.ebpf_state.shadow_content.clone(),
        sshd_config_content: q.ebpf_state.sshd_config_content.clone(),
        authorized_keys_content: q.ebpf_state.authorized_keys_content.clone(),
        ld_preload_content: q.ebpf_state.ld_preload_content.clone(),
        boot_params_content: q.ebpf_state.boot_params_content.clone(),
        dev_inventory_list: q.ebpf_state.dev_inventory_list.clone(),
        iptables_content: q.ebpf_state.iptables_content.clone(),
        mount_content: q.ebpf_state.mount_content.clone(),
        sysctl_content: q.ebpf_state.sysctl_content.clone(),
        entropy_available: q.ebpf_state.entropy_available,
        xdp_passed: q.ebpf_state.xdp_stats.as_ref().map(|x| x.passed),
        xdp_drop_entropy: q.ebpf_state.xdp_stats.as_ref().map(|x| x.drop_entropy),
        xdp_drop_protocol: q.ebpf_state.xdp_stats.as_ref().map(|x| x.drop_protocol),
        xdp_drop_port: q.ebpf_state.xdp_stats.as_ref().map(|x| x.drop_port),
        xdp_total: q.ebpf_state.xdp_stats.as_ref().map(|x| x.total),
        xdp_exempt: q.ebpf_state.xdp_stats.as_ref().map(|x| x.exempt),
        xdp_entropy_histogram: q.ebpf_state.xdp_stats.as_ref().map(|x| x.entropy_histogram.clone()),
        xdp_size_histogram: q.ebpf_state.xdp_stats.as_ref().map(|x| x.size_histogram.clone()),
    }
}

pub fn classify_tier(nodes: &[NodeAuditRecord]) -> ForensicTier {
    let mut tier = ForensicTier::Info;
    for n in nodes {
        let fully_ok = n.pass && n.fw_ok && n.passwd_ok && n.ssh_ok
            && n.ld_preload_safe && n.boot_params_ok && n.dev_inventory_ok
            && n.mnt_ok && n.cfg_ok && n.sys_ok && n.init_ok
            && n.xdp_attached && !n.sysmon_anomaly && !n.sysmon_unloaded
            && n.fd_ok && n.kern_ok && n.userspace_ok && n.connections_ok
            && n.ports_ok;
        if fully_ok { continue; }
        if !n.pcr_match || !n.ak_match || !n.bin_ok || !n.fw_ok || !n.sys_ok {
            return ForensicTier::Critical;
        }
        if n.masquerade_detected { return ForensicTier::Critical; }
        if !n.kernel_modules_empty { return ForensicTier::Critical; }
        if !n.xdp_attached { return ForensicTier::Critical; }
        if n.sysmon_unloaded { return ForensicTier::Critical; }
        if n.sysmon_anomaly { return ForensicTier::Warning; }
        if !n.fd_ok { return ForensicTier::Warning; }
        if !n.kern_ok { return ForensicTier::Critical; }
        if !n.init_ok { return ForensicTier::Critical; }
        if !n.ld_preload_safe { return ForensicTier::Critical; }
        if !n.passwd_ok { return ForensicTier::Critical; }
        if !n.ssh_ok { return ForensicTier::Critical; }
        if !n.boot_params_ok { return ForensicTier::Critical; }
        if !n.ima_valid {
            if let Some(delta) = n.ima_delta {
                if delta < 0 { return ForensicTier::Critical; }
            }
        }
        if !n.userspace_ok || !n.kernel_threads_ok || !n.connections_ok {
            tier = ForensicTier::Warning;
        }
        if !n.mnt_ok || !n.cfg_ok || !n.ports_ok {
            tier = ForensicTier::Warning;
        }
        if !n.dev_inventory_ok {
            tier = ForensicTier::Warning;
        }
        if !n.ima_valid && tier < ForensicTier::Warning {
            tier = ForensicTier::Warning;
        }
    }
    tier
}

pub fn build_forensic_capture(
    tier: &ForensicTier,
    nodes: &[NodeAuditRecord],
    collect_snapshot: bool,
) -> Option<ForensicCapture> {
    if *tier == ForensicTier::Info { return None; }

    let mut trigger_nodes = Vec::new();
    let mut trigger_checks = Vec::new();
    let mut node_details = Vec::new();

    for n in nodes {
        if n.pass { continue; }
        trigger_nodes.push(n.node.clone());

        if !n.pcr_match { trigger_checks.push(format!("{}: PCR mismatch", n.node)); }
        if !n.bin_ok { trigger_checks.push(format!("{}: binary tampered", n.node)); }
        if !n.fw_ok { trigger_checks.push(format!("{}: iptables changed", n.node)); }
        if !n.sys_ok { trigger_checks.push(format!("{}: sysctl changed", n.node)); }
        if !n.ak_match { trigger_checks.push(format!("{}: AK mismatch", n.node)); }
        if !n.sig_valid { trigger_checks.push(format!("{}: signature invalid", n.node)); }
        if !n.ima_valid { trigger_checks.push(format!("{}: IMA anomaly", n.node)); }
        if !n.userspace_ok { trigger_checks.push(format!("{}: userspace changed", n.node)); }
        if !n.kernel_threads_ok { trigger_checks.push(format!("{}: kernel threads changed", n.node)); }
        if n.masquerade_detected { trigger_checks.push(format!("{}: MASQUERADE", n.node)); }
        if !n.kernel_modules_empty { trigger_checks.push(format!("{}: kernel modules loaded", n.node)); }
        if !n.connections_ok { trigger_checks.push(format!("{}: connections changed", n.node)); }
        if !n.mnt_ok { trigger_checks.push(format!("{}: mounts changed", n.node)); }
        if !n.cfg_ok { trigger_checks.push(format!("{}: config tampered", n.node)); }
        if !n.ports_ok { trigger_checks.push(format!("{}: ports changed", n.node)); }
        if !n.xdp_attached { trigger_checks.push(format!("{}: XDP DETACHED", n.node)); }
        if !n.passwd_ok { trigger_checks.push(format!("{}: PASSWD CHANGED", n.node)); }
        if !n.ssh_ok { trigger_checks.push(format!("{}: SSH CONFIG CHANGED", n.node)); }
        if !n.ld_preload_safe { trigger_checks.push(format!("{}: LD_PRELOAD ROOTKIT", n.node)); }
        if !n.boot_params_ok { trigger_checks.push(format!("{}: BOOT PARAMS CHANGED", n.node)); }
        if !n.dev_inventory_ok { trigger_checks.push(format!("{}: DEV INVENTORY CHANGED", n.node)); }

        node_details.push(format!("[{}] {}", n.node, n.raw_details));
    }
    /// Deep snapshot of LOCAL system state (verifier node)
    let local_snapshot = if collect_snapshot {
        println!("    Collecting deep forensic snapshot...");
        Some(ebpf::collect_forensic_snapshot())
    } else {
        None
    };
    Some(ForensicCapture {
        tier: tier.to_string(),
        trigger_nodes,
        trigger_checks,
        node_details: if node_details.is_empty() { None } else { Some(node_details) },
        local_snapshot,
    })
}

// === Node Verification to Audit Conversion ===
pub fn node_to_audit_record(nr: &NodeVerificationResult, chain: u8) -> NodeAuditRecord {
    let d = &nr.details;

    let ima_count = parse_field_usize(d, "IMA:")
        .or_else(|| {
            if let Some(pos) = d.find("IMA SPIKE:") {
                parse_field_usize(&d[pos..], "cur=")
            } else if let Some(pos) = d.find("IMA TAMPER:") {
                parse_field_usize(&d[pos..], "cur=")
            } else {
                parse_field_usize(d, "IMA LOW: ")
            }
        })
        .unwrap_or(0);
    let ima_delta = parse_ima_delta(d);

    let userspace_ok = d.contains("USR:OK") || d.contains("USR:no_baseline");
    let userspace_count = parse_parenthesized_count(d, "USR:OK(")
        .unwrap_or_else(|| {
            /// On USERSPACE CHANGED, count from ebpf_state process list
            /// 	Fallback: count +() and -() entries to estimate
            if d.contains("USERSPACE CHANGED") {
                d.matches("+(").count() + d.matches("-(").count()
            } else { 0 }
        });
    let userspace_diff = if d.contains("USERSPACE CHANGED:") {
        Some(extract_diff_entries(d, "USERSPACE CHANGED:"))
    } else { None };

    let kernel_threads_ok = d.contains("KTH:OK") || d.contains("KTH:no_baseline");
    let kernel_thread_count = parse_parenthesized_count(d, "KTH:OK(").unwrap_or(0);
    let kernel_thread_diff = if d.contains("KTHREAD CHANGED:") {
        Some(extract_diff_entries(d, "KTHREAD CHANGED:"))
    } else { None };

    let masquerade_detected = d.contains("MASQUERADE:");
    let masquerade_details = if masquerade_detected {
        Some(extract_section(d, "MASQUERADE:"))
    } else { None };

    let kernel_modules_empty = d.contains("MOD:empty") || !d.contains("KERNEL MODULES LOADED");
    let kernel_modules_loaded = if d.contains("KERNEL MODULES LOADED:") {
        Some(extract_section(d, "KERNEL MODULES LOADED:"))
    } else { None };

    let connections_ok = d.contains("CONN:OK") || d.contains("CONN:no_baseline");
    let connection_count = parse_parenthesized_count(d, "CONN:OK(")
        .unwrap_or_else(|| {
            if d.contains("CONN CHANGED") || d.contains("CONN ANOMALY") {
                /// Count entries in diff
                d.match_indices("CONN CHANGED:").next()
                    .map(|(pos, _)| {
                        d[pos..].matches('+').count() + d[pos..].matches('-').count()
                    })
                    .unwrap_or(1)
            } else { 0 }
        });
    let connection_diff = if d.contains("CONN CHANGED:") {
        Some(extract_diff_entries(d, "CONN CHANGED:"))
    } else { None };

    let fw_ok = d.contains("FW:OK");
    let bin_ok = d.contains("BIN:OK");
    let mnt_ok = d.contains("MNT:OK");
    let cfg_ok = d.contains("CFG:OK");
    let sys_ok = d.contains("SYS:OK");
    let xdp_attached = d.contains("XDP:OK");
    let passwd_ok = d.contains("PASSWD:OK") || !d.contains("PASSWD CHANGED");
    let ssh_ok = d.contains("SSH:OK") || !d.contains("SSH CONFIG CHANGED");
    let ld_preload_safe = !d.contains("LD_PRELOAD ROOTKIT");
    let boot_params_ok = d.contains("BOOT:OK") || !d.contains("BOOT PARAMS CHANGED");
    let dev_inventory_ok = d.contains("DEV:OK") || !d.contains("DEV INVENTORY CHANGED");
    let entropy_available = parse_field_usize(d, "ENT:")
        .or_else(|| parse_field_usize(d, "ENT:LOW(").map(|v| v))
        .map(|v| v as u32);
    let sysmon_active = d.contains("SYSMON:OK") || d.contains("SYSMON:ANOMALY");
    let sysmon_hooks = parse_field_usize(d, "SYSMON:OK(hooks:").map(|v| v as u64);
    let sysmon_anomaly = d.contains("SYSMON:ANOMALY");
    let sysmon_unloaded = d.contains("SYSMON:UNLOADED");
    let sysmon_exec_delta = parse_sysmon_delta(d, "exec:+");
    let sysmon_ptrace_delta = parse_sysmon_delta(d, "ptrace:+");
    let sysmon_mount_delta = parse_sysmon_delta(d, "mount:+");
    let sysmon_conn_delta = parse_sysmon_delta(d, "conn:+").or_else(|| parse_sysmon_delta(d, "unauth_conn:+"));
    let sysmon_sock_delta = parse_sysmon_delta(d, "sock:+").or_else(|| parse_sysmon_delta(d, "exotic_sock:+"));
    let fd_ok = d.contains("FD:OK");
    let fd_count = parse_parenthesized_count(d, "FD:OK(")
        .or_else(|| {
            /// On anomaly, count total FDs from the anomaly details
            if let Some(start) = d.find("FD:ANOMALY(") {
                /// Extract number from anomaly text if present
                let rest = &d[start + 11..];
                /// Try to find a number pattern like "has N open fds"
                if let Some(pos) = rest.find("has ") {
                    let num_start = pos + 4;
                    let num_rest = &rest[num_start..];
                    let end = num_rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(0);
                    if end > 0 { return num_rest[..end].parse().ok(); }
                }
            }
            None
        })
        .unwrap_or(0);
    let kern_ok = d.contains("KERN:OK");
    let kern_details = if let Some(start) = d.find("KERN:") {
        let rest = &d[start..];
        let end = rest.find(';').unwrap_or(rest.len());
        Some(rest[..end].to_string())
    } else { None };
    let init_ok = d.contains("INIT:OK");
    let init_count = parse_parenthesized_count(d, "INIT:OK(").unwrap_or(0);
    let init_unused = parse_parenthesized_count(d, "INIT:UNUSED(").unwrap_or(0);
    let mut ports = parse_ports(d);
    if ports.is_empty() {
        /// Parse from "got [22, 9003]" in PORTS CHANGED
        if let Some(start) = d.find("got [") {
            let rest = &d[start + 5..];
            if let Some(end) = rest.find(']') {
                ports = rest[..end].split(',')
                    .filter_map(|s| s.trim().parse().ok())
                    .collect();
            }
        }
    }
    let ports_ok = !d.contains("PORTS CHANGED");
    let pcr_mismatches = parse_pcr_mismatches(d);
    let pass = nr.pcr_match && nr.ima_valid && nr.ebpf_valid
        && nr.signature_valid && nr.ak_match;
    NodeAuditRecord {
        node: nr.vm_identity.clone(),
        chain,
        pass,
        pcr_match: nr.pcr_match,
        pcr_mismatch_indices: if pcr_mismatches.is_empty() { None } else { Some(pcr_mismatches) },
        ima_valid: nr.ima_valid,
        ima_count,
        ima_delta,
        userspace_ok,
        userspace_count,
        userspace_diff,
        kernel_threads_ok,
        kernel_thread_count,
        kernel_thread_diff,
        masquerade_detected,
        masquerade_details,
        kernel_modules_empty,
        kernel_modules_loaded,
        connections_ok,
        connection_count,
        connection_diff,
        fw_ok,
        bin_ok,
        ports_ok,
        ports,
        mnt_ok,
        cfg_ok,
        sys_ok,
        xdp_attached,
        passwd_ok,
        ssh_ok,
        ld_preload_safe,
        boot_params_ok,
        dev_inventory_ok,
        entropy_available,
        sysmon_active,
        sysmon_hooks,
        sysmon_anomaly,
        sysmon_unloaded,
        sysmon_exec_delta,
        sysmon_ptrace_delta,
        sysmon_mount_delta,
        sysmon_conn_delta,
        sysmon_sock_delta,
        fd_ok,
        fd_count,
        kern_ok,
        kern_details,
        init_ok,
        init_count,
        init_unused,
        sig_valid: nr.signature_valid,
        ak_match: nr.ak_match,
        raw_details: nr.details.clone(),
    }
}

// === Audit Logger Implementation ===
impl AuditLogger {
    pub fn new(path: &str, node_id: &str, log_mode: u8) -> Self {
        let (seq, prev_hash) = recover_chain_state(path);
        println!("  Audit v2: mode={} seq={} chain={}...",
            log_mode, seq, &prev_hash[..16.min(prev_hash.len())]);
        AuditLogger {
            path: path.to_string(),
            seq,
            prev_hash,
            log_mode,
            node_id: node_id.to_string(),
            heartbeat_count: 0,
        }
    }
    pub fn write(
        &mut self,
        event: AuditEvent,
        heartbeat: u64,
        chain_id: &[u8],
        node_results: &[NodeVerificationResult],
        attestation_metas: Option<&[AttestationMeta]>,
        chain_number: u8,
        session_status: &str,
        authorized: bool,
        timing_ms: Option<u64>,
        session_token_hash: Option<&str>,
        tpm: &crate::tpm::TpmCtx,
    ) -> Result<()> {
        self.seq += 1;
        self.heartbeat_count += 1;
        let audit_nodes: Vec<NodeAuditRecord> = node_results.iter()
            .map(|nr| node_to_audit_record(nr, chain_number))
            .collect();
        let tier = classify_tier(&audit_nodes);
        /// Forensic capture: Mode 2 = on failure, Mode 3 = always if non-info
        /// Deep snapshot collected only when tier >= Warning and mode >= 2
        let forensic = match self.log_mode {
            1 => None,
            2 => {
                if tier != ForensicTier::Info {
                    build_forensic_capture(&tier, &audit_nodes, true)
                } else { None }
            }
            3 => {
                let collect_deep = tier != ForensicTier::Info;
                build_forensic_capture(&tier, &audit_nodes, collect_deep)
            }
            _ => None,
        };
        /// TPM checkpoint
        let tpm_checkpoint = if self.heartbeat_count % TPM_CHECKPOINT_INTERVAL == 0 {
            match crate::tpm::sign_data(tpm, self.prev_hash.as_bytes()) {
                Ok((sig, _)) => {
                    println!("    TPM checkpoint: seq={} entries={}", self.seq, self.heartbeat_count);
                    Some(TpmCheckpoint {
                        chain_hash: self.prev_hash.clone(),
                        signature: hex::encode(sig),
                        entries_covered: TPM_CHECKPOINT_INTERVAL,
                    })
                }
                Err(e) => {
                    eprintln!("    TPM checkpoint failed: {}", e);
                    None
                }
            }
        } else { None };

        let entry = AuditEntryV2 {
            version: AUDIT_VERSION,
            seq: self.seq,
            timestamp: now_secs(),
            node_id: self.node_id.clone(),
            heartbeat,
            event,
            chain_id: hex::encode(chain_id),
            prev_hash: self.prev_hash.clone(),
            nodes: Some(audit_nodes),
            attestation_meta: attestation_metas.map(|m| m.to_vec()),
            tier: tier.clone(),
            forensic,
            verification_duration_ms: timing_ms,
            session_status: session_status.to_string(),
            authorized,
            total_nodes_verified: node_results.len(),
            session_token_hash: session_token_hash.map(|s| s.to_string()),
            tpm_checkpoint,
        };

        let entry_json = serde_json::to_string(&entry)?;
        self.prev_hash = sha256_hex(entry_json.as_bytes());

        let mut file = std::fs::OpenOptions::new()
            .create(true).append(true).open(&self.path)?;
        writeln!(file, "{}", entry_json)?;

        if tier != ForensicTier::Info {
            println!("    AUDIT [{}] {} seq={}", tier, entry.event, self.seq);
        }

        Ok(())
    }
}

// === Detail String Parsers ===
fn parse_sysmon_delta(details: &str, prefix: &str) -> Option<u64> {
    let start = details.find(prefix)? + prefix.len();
    let rest = &details[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    if end == 0 { return None; }
    rest[..end].parse().ok()
}

fn parse_field_usize(details: &str, prefix: &str) -> Option<usize> {
    let start = details.find(prefix)? + prefix.len();
    let rest = &details[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    if end == 0 { return None; }
    rest[..end].parse().ok()
}

fn parse_parenthesized_count(details: &str, prefix: &str) -> Option<usize> {
    let start = details.find(prefix)? + prefix.len();
    let rest = &details[start..];
    let end = rest.find(')').unwrap_or(rest.len());
    if end == 0 { return None; }
    rest[..end].parse().ok()
}

fn parse_ima_delta(details: &str) -> Option<i64> {
    if let Some(pos) = details.find("/d+") {
        let start = pos + 3;
        let rest = &details[start..];
        let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
        if end > 0 { return rest[..end].parse().ok(); }
    }
    if details.contains("/first") { return None; }
    if let Some(pos) = details.find("delta=") {
        let start = pos + 6;
        let rest = &details[start..];
        let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
        if end > 0 { return rest[..end].parse().ok(); }
    }
    None
}

fn parse_ports(details: &str) -> Vec<u16> {
    if let Some(start) = details.find("PORTS:[") {
        let rest = &details[start + 7..];
        if let Some(end) = rest.find(']') {
            return rest[..end].split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
        }
    }
    Vec::new()
}

fn parse_pcr_mismatches(details: &str) -> Vec<u8> {
    let mut indices = Vec::new();
    let mut search = details;
    while let Some(pos) = search.find("PCR") {
        let rest = &search[pos + 3..];
        if let Some(space) = rest.find(' ') {
            if let Ok(idx) = rest[..space].parse::<u8>() {
                if rest[space..].starts_with(" MISMATCH") {
                    indices.push(idx);
                }
            }
        }
        if rest.is_empty() { break; }
        search = &search[pos + 3..];
    }
    indices
}

fn extract_diff_entries(details: &str, prefix: &str) -> Vec<String> {
    if let Some(start) = details.find(prefix) {
        let rest = &details[start + prefix.len()..];
        return rest.split(';')
            .take_while(|s| {
                let trimmed = s.trim();
                trimmed.starts_with('+') || trimmed.starts_with('-')
            })
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    Vec::new()
}

fn extract_section(details: &str, prefix: &str) -> Vec<String> {
    if let Some(start) = details.find(prefix) {
        let rest = &details[start + prefix.len()..];
        let end = rest.find("; ").unwrap_or(rest.len());
        return vec![rest[..end].trim().to_string()];
    }
    Vec::new()
}

// === Utilities ===
fn recover_chain_state(path: &str) -> (u64, String) {
    let genesis = sha256_hex(GENESIS_HASH.as_bytes());
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return (0, genesis),
    };
    let last_line = content.lines().rev().find(|l| !l.trim().is_empty());
    match last_line {
        Some(line) => {
            if let Ok(entry) = serde_json::from_str::<AuditEntryV2>(line) {
                let prev_hash = sha256_hex(line.as_bytes());
                (entry.seq, prev_hash)
            } else {
                let line_count = content.lines().filter(|l| !l.trim().is_empty()).count() as u64;
                (line_count, genesis)
            }
        }
        None => (0, genesis),
    }
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}


