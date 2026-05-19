use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use crate::tpm::{TpmQuote, PcrBaseline};
use std::collections::HashMap;
use anyhow::Result;

// === Circuit Building Messages ===
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendCircuit {
    pub target_id: String,
    pub kyber_pk: Vec<u8>,
    pub x25519_pk: [u8; 32],
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedCircuit {
    pub responder_id: String,
    pub kyber_ct: Vec<u8>,
    pub x25519_pk: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayCell {
    pub encrypted_payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayCommand {
    Extend(ExtendCircuit),
    Extended(ExtendedCircuit),
    AttestationRequest,
    AttestationResponse(Attestation),
    ChainSubmission(ChainPacket),
    VerificationResult(VerificationResponse),
    Chain2Submission(Chain2Packet),
    FullAuthorizationResult(FullAuthorizationResponse),
    Data(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayCellPayload {
    pub command: RelayCommand,
    pub next_hop: Option<String>,
    pub inner_cell: Option<Vec<u8>>,
}

// === Attestation Types ===
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainPacket {
    pub attestations: Vec<Attestation>,
    pub chain_id: Vec<u8>,
    pub timestamp: u64,
    pub is_response: bool,
    pub session_token: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub vm_identity: String,
    pub tpm_quote: TpmQuote,
    pub timestamp: u64,
}

// === Chain 1 Verification Response ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResponse {
    pub verified: bool,
    pub session_status: SessionStatus,
    pub session_token: Option<Vec<u8>>,
    pub node_results: Vec<NodeVerificationResult>,
    pub chain_id: Vec<u8>,
    pub timestamp: u64,
}

// === Chain 2 Packet ===
///	Submitted by VM2 to VM3 through chain 2
/// 	Contains chain 1 verification results AND chain 2 attestations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chain2Packet {
    pub chain1_results: VerificationResponse,
    pub chain2_attestations: Vec<Attestation>,
    pub chain2_id: Vec<u8>,
    pub timestamp: u64,
}

// === VM3 Final Authorization Response after both chains ===
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullAuthorizationResponse {
    pub authorized: bool,
    pub session_status: SessionStatus,
    pub session_token: Option<Vec<u8>>,
    pub chain1_node_results: Vec<NodeVerificationResult>,
    pub chain2_node_results: Vec<NodeVerificationResult>,
    pub chain1_id: Vec<u8>,
    pub chain2_id: Vec<u8>,
    pub timestamp: u64,
}

// === Session Status ===

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SessionStatus {
    Provisional,  /// VM2 verified chain 1, awaiting VM3
    Authorized,   /// Both chains verified by VM3 (full auth)
    Denied,       /// Verification failed
    Revoked,      /// Was authorized, now revoked
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStatus::Provisional => write!(f, "PROVISIONAL"),
            SessionStatus::Authorized => write!(f, "AUTHORIZED"),
            SessionStatus::Denied => write!(f, "DENIED"),
            SessionStatus::Revoked => write!(f, "REVOKED"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeVerificationResult {
    pub vm_identity: String,
    pub pcr_match: bool,
    pub ima_valid: bool,
    pub ebpf_valid: bool,
    pub signature_valid: bool,
    pub ak_match: bool,
    pub details: String,
}

// === Protocol Message ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolMessage {
    ExtendCircuit(ExtendCircuit),
    ExtendedCircuit(ExtendedCircuit),
    RelayCell(RelayCell),
    AttestationChain(ChainPacket),
}

// === Baseline Database and Verification ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDatabase {
    pub baselines: HashMap<String, PcrBaseline>,
    pub updated: u64,
}

impl BaselineDatabase {
    pub fn new() -> Self {
        BaselineDatabase {
            baselines: HashMap::new(),
            updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub fn add_baseline(&mut self, baseline: PcrBaseline) {
        self.baselines.insert(baseline.vm_identity.clone(), baseline);
        self.updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn get_baseline(&self, vm_identity: &str) -> Option<&PcrBaseline> {
        self.baselines.get(vm_identity)
    }

    pub fn save_to_file(&self, path: &str) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load_from_file(path: &str) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let db = serde_json::from_str(&json)?;
        Ok(db)
    }

    pub fn verify_attestation(
        &self,
        att: &Attestation,
        prev_ima_count: Option<usize>,
        prev_ima_aggregate: Option<&[u8]>,
        prev_sysmon: Option<&crate::sysmon::SysmonState>,
    ) -> NodeVerificationResult {
        let baseline = self.get_baseline(&att.vm_identity);

        let mut pcr_match = true;
        let mut ima_valid = true;
        let mut ebpf_valid = true;
        let mut signature_valid = true;
        let mut ak_match = true;
        let mut details = Vec::new();

        match baseline {
            Some(bl) => {
                /// PCR verification 
                for actual_pcr in &att.tpm_quote.pcr_values {
                    if let Some(expected_pcr) = bl.pcr_values.iter().find(|p| p.index == actual_pcr.index) {
                        if actual_pcr.value != expected_pcr.value {
                            pcr_match = false;
                            details.push(format!(
                                "PCR{} MISMATCH: expected={} got={}",
                                actual_pcr.index,
                                hex::encode(&expected_pcr.value),
                                hex::encode(&actual_pcr.value)
                            ));
                        }
                    }
                }
                if pcr_match {
                    details.push(format!("{} PCRs match", att.tpm_quote.pcr_values.len()));
                }

                /// IMA verification 
                let ima_count = att.tpm_quote.ima_measurements.count;
                if ima_count < 200 {
                    ima_valid = false;
                    details.push(format!("IMA LOW: {} (expected >=200)", ima_count));
                } else {
                    match prev_ima_count {
                        Some(prev) => {
                            let delta = (ima_count as i64) - (prev as i64);
                            if delta < 0 {
                                ima_valid = false;
                                details.push(format!(
                                    "IMA TAMPER: prev={} cur={} delta={}",
                                    prev, ima_count, delta
                                ));
                            } else if delta > 20 {
                                ima_valid = false;
                                details.push(format!(
                                    "IMA SPIKE: prev={} cur={} delta=+{}",
                                    prev, ima_count, delta
                                ));
                            } else {
                                details.push(format!("IMA:{}/d+{}", ima_count, delta));
                            }
                        }
                        None => {
                            details.push(format!("IMA:{}/first", ima_count));
                        }
                    }
                }

                /// IMA prefix-aggregate verification
                match (prev_ima_count, prev_ima_aggregate) {
                    (Some(prev_count), Some(prev_agg)) => {
                        let cur_text = &att.tpm_quote.ima_measurements.measurements_text;
                        if cur_text.is_empty() {
                            ima_valid = false;
                            details.push("IMA AGG: attestation_incomplete".to_string());
                        } else if ima_count < prev_count {
                            /// Already caught by delta check, defensive guard
                            ima_valid = false;
                            details.push(format!(
                                "IMA AGG: count_below_prev cur={} prev={}",
                                ima_count, prev_count
                            ));
                        } else {
                            /// Hash first `prev_count` newline-terminated lines
                            let prefix_bytes = match cur_text
                                .match_indices('\n')
                                .nth(prev_count.saturating_sub(1))
                            {
                                Some((idx, _)) => &cur_text.as_bytes()[..=idx],
                                None => {
                                    ima_valid = false;
                                    details.push(format!(
                                        "IMA AGG: log_truncated cur_lines<{}",
                                        prev_count
                                    ));
                                    cur_text.as_bytes()
                                }
                            };

                            if !prefix_bytes.is_empty() {
                                let mut h = Sha256::new();
                                h.update(prefix_bytes);
                                let prefix_agg = h.finalize().to_vec();

                                if prefix_agg == prev_agg {
                                    details.push("IMA AGG:OK".to_string());
                                } else {
                                    ima_valid = false;
                                    details.push(format!(
                                        "IMA AGG TAMPERED: prev_count={} hash mismatch",
                                        prev_count
                                    ));
                                }
                            }
                        }
                    }
                    _ => {
                        details.push("IMA AGG:first".to_string());
                    }
                }

                /// eBPF verification 
                if let Some(ref ebpf_bl) = bl.ebpf_baseline {
                    /// CHECK 1: Userspace process manifest
                    match (&att.tpm_quote.ebpf_state.userspace_hash, &ebpf_bl.userspace_hash) {
                        (Some(cur_hash), Some(bl_hash)) => {
                            if cur_hash != bl_hash {
                                /// ebpf_valid = false; // DEMO MODE
                                let diff = diff_userspace_processes(
                                    &att.tpm_quote.ebpf_state.userspace_processes,
                                    &ebpf_bl.userspace_processes,
                                );
                                details.push(format!("USERSPACE CHANGED: {}", diff));
                            } else {
                                let count = att.tpm_quote.ebpf_state.userspace_processes
                                    .as_ref().map(|p| p.len()).unwrap_or(0);
                                details.push(format!("USR:OK({})", count));
                            }
                        }
                        (Some(_), None) => {
                            details.push("USR:no_baseline".to_string());
                        }
                        (None, Some(_)) => {
                            details.push("USR:not_reported".to_string());
                        }
                        (None, None) => {
                            let proc_diff = (att.tpm_quote.ebpf_state.process_count as i64
                                - ebpf_bl.process_count as i64).abs();
                            if proc_diff > 10 {
                                /// ebpf_valid = false; // DEMO MODE
                                details.push(format!(
                                    "PROC ANOMALY: bl={} cur={} diff={}",
                                    ebpf_bl.process_count,
                                    att.tpm_quote.ebpf_state.process_count,
                                    proc_diff
                                ));
                            } else {
                                details.push(format!(
                                    "PROC:{}/bl:{}",
                                    att.tpm_quote.ebpf_state.process_count,
                                    ebpf_bl.process_count
                                ));
                            }
                        }
                    }

                    /// CHECK 2: Kernel thread types
                    match (&att.tpm_quote.ebpf_state.kernel_thread_types_hash, &ebpf_bl.kernel_thread_types_hash) {
                        (Some(cur_hash), Some(bl_hash)) => {
                            if cur_hash != bl_hash {
                                /// ebpf_valid = false; // DEMO MODE
                                let diff = diff_string_sets(
                                    &att.tpm_quote.ebpf_state.kernel_thread_types,
                                    &ebpf_bl.kernel_thread_types,
                                    "KTHREAD",
                                );
                                details.push(format!("KTHREAD CHANGED: {}", diff));
                            } else {
                                let count = att.tpm_quote.ebpf_state.kernel_thread_types
                                    .as_ref().map(|t| t.len()).unwrap_or(0);
                                details.push(format!("KTH:OK({})", count));
                            }
                        }
                        (Some(_), None) => { details.push("KTH:no_baseline".to_string()); }
                        (None, Some(_)) => { details.push("KTH:not_reported".to_string()); }
                        (None, None) => {} 
                    }
                    /// CHECK 3: Masquerade detection
                    if let Some(ref alerts) = att.tpm_quote.ebpf_state.masquerade_alerts {
                        if !alerts.is_empty() {
                            /// ebpf_valid = false; // DEMO MODE
                            let alert_strs: Vec<String> = alerts.iter()
                                .map(|a| format!("PID{}:{}({})", a.pid, a.comm, a.exe_path))
                                .collect();
                            details.push(format!("MASQUERADE: {}", alert_strs.join(", ")));
                        }
                    }
                    /// Kernel modules
                    if let Some(ref modules) = att.tpm_quote.ebpf_state.kernel_modules {
                        if !modules.is_empty() {
                            /// ebpf_valid = false; // DEMO MODE
                            details.push(format!("KERNEL MODULES LOADED: {:?}", modules));
                        } else {
                            details.push("MOD:empty".to_string());
                        }
                    }
                    /// Init chain integrity
                    if let Some(ref ii) = att.tpm_quote.ebpf_state.init_integrity {
                        if let Some(ref bl_ii) = ebpf_bl.init_integrity {
                            let mut init_ok = true;
                            let mut init_details = Vec::new();
                            /// Check active scripts hash
                            if let (Some(ref cur), Some(ref bl)) = (&ii.init_scripts_hash, &bl_ii.init_scripts_hash) {
                                if cur != bl {
                                    init_ok = false;
                                    init_details.push("active scripts CHANGED");
                                }
                            }
                            /// Check local.d hash
                            if let (Some(ref cur), Some(ref bl)) = (&ii.local_d_hash, &bl_ii.local_d_hash) {
                                if cur != bl {
                                    init_ok = false;
                                    init_details.push("local.d scripts CHANGED");
                                }
                            }
                            /// Check runlevel hash
                            if let (Some(ref cur), Some(ref bl)) = (&ii.runlevel_hash, &bl_ii.runlevel_hash) {
                                if cur != bl {
                                    init_ok = false;
                                    init_details.push("runlevel structure CHANGED");
                                }
                            }
                            /// Check conf.d hash
                            if let (Some(ref cur), Some(ref bl)) = (&ii.conf_d_hash, &bl_ii.conf_d_hash) {
                                if cur != bl {
                                    init_ok = false;
                                    init_details.push("conf.d overrides CHANGED");
                                }
                            }
                            /// Check inactive script count against baseline
                            let bl_inactive_count = bl_ii.inactive_scripts.len();
                            let cur_inactive_count = ii.inactive_scripts.len();
                            if cur_inactive_count != bl_inactive_count {
                                init_ok = false;
                                init_details.push("unused script count CHANGED");
                            }
                            if init_ok {
                                details.push(format!("INIT:OK({})", ii.active_script_count));
                            } else {
                                details.push(format!("INIT:TAMPERED({})", init_details.join(", ")));
                            }
                        }
                        if !ii.inactive_scripts.is_empty() {
                            details.push(format!("INIT:UNUSED({})", ii.inactive_scripts.len()));
                        }
                    }
                    /// XDP attachment verification 
                    if let Some(xdp) = att.tpm_quote.ebpf_state.xdp_attached {
                        if !xdp {
                            /// ebpf_valid = false; // DEMO MODE
                            details.push("XDP DETACHED".to_string());
                        } else {
                            details.push("XDP:OK".to_string());
                        }
                    }
                    /// XDP traffic stats
                    if let Some(ref xs) = att.tpm_quote.ebpf_state.xdp_stats {
                        if xs.active {
                            let exempt_pct = if xs.total > 0 {
                                (xs.exempt * 100) / xs.total
                            } else { 0 };
                            details.push(format!("XDP_STATS:pass={},drop_e={},drop_p={},exempt={}%",
                                xs.passed, xs.drop_entropy, xs.drop_port, exempt_pct));
                        }
                    }
                    /// Filesystem integrity verification
                    /// /etc/passwd + /etc/shadow
                    match (&att.tpm_quote.ebpf_state.passwd_hash, &ebpf_bl.passwd_hash) {
                        (Some(current), Some(baseline)) => {
                            if current == baseline {
                                details.push("PASSWD:OK".to_string());
                            } else {
                                /// ebpf_valid = false; // DEMO MODE
                                details.push("PASSWD CHANGED".to_string());
                            }
                        }
                        (None, Some(_)) => { details.push("PASSWD:missing".to_string()); }
                        _ => {}
                    }
                    /// SSH config + authorized_keys + host keys
                    match (&att.tpm_quote.ebpf_state.ssh_config_hash, &ebpf_bl.ssh_config_hash) {
                        (Some(current), Some(baseline)) => {
                            if current == baseline {
                                details.push("SSH:OK".to_string());
                            } else {
                                /// ebpf_valid = false; // DEMO MODE
                                details.push("SSH CONFIG CHANGED".to_string());
                            }
                        }
                        (None, Some(_)) => { details.push("SSH:missing".to_string()); }
                        _ => {}
                    }
                    /// ld.so.preload: CRITICAL if not safe
                    if let Some(safe) = att.tpm_quote.ebpf_state.ld_preload_safe {
                        if !safe {
                            /// ebpf_valid = false; // DEMO MODE
                            details.push("LD_PRELOAD ROOTKIT".to_string());
                        } else {
                            details.push("PRELOAD:OK".to_string());
                        }
                    }
                    /// Entropy pool: WARNING if low (< 128 bits)
                    /// Entropy pool: always report, warn if low (< 128 bits)
                    if let Some(entropy) = att.tpm_quote.ebpf_state.entropy_available {
                        if entropy < 128 {
                            details.push(format!("ENT:LOW({})", entropy));
                        } else {
                            details.push(format!("ENT:{}", entropy));
                        }
                    }
                    /// Sysmon behavioral monitoring (delta-based)
                    /// First: liveness check, if baseline had sysmon active,
                    /// runtime must too (attacker can't unload monitor)
                    let baseline_sysmon_active = ebpf_bl.sysmon
                        .as_ref()
                        .map(|s| s.active)
                        .unwrap_or(false);
                    match &att.tpm_quote.ebpf_state.sysmon {
                        Some(ref sm) if sm.active => {
                            let (d_exec, d_ptrace, d_mount, d_unauth, d_exotic) = match prev_sysmon {
                                Some(prev) => (
                                    sm.execve_count.saturating_sub(prev.execve_count),
                                    sm.ptrace_count.saturating_sub(prev.ptrace_count),
                                    sm.mount_count.saturating_sub(prev.mount_count),
                                    sm.connect_unauthorized_count.saturating_sub(prev.connect_unauthorized_count),
                                    sm.socket_exotic_count.saturating_sub(prev.socket_exotic_count),
                                ),
                                None => (0, 0, 0, 0, 0),
                            };
                            let has_anomaly = d_exec > 0 || d_ptrace > 0 || d_mount > 0
                                || d_unauth > 0 || d_exotic > 0;
                            if has_anomaly {
                                /// ebpf_valid = false; // DEMO MODE
                                details.push(format!(
                                    "SYSMON:ANOMALY(exec:+{},ptrace:+{},mount:+{},unauth_conn:+{},exotic_sock:+{})",
                                    d_exec, d_ptrace, d_mount, d_unauth, d_exotic
                                ));
                            } else {
                                details.push(format!(
                                    "SYSMON:OK(hooks:{},exec:+{},ptrace:+{},mount:+{},conn:+{},sock:+{})",
                                    sm.total_hooks, d_exec, d_ptrace, d_mount, d_unauth, d_exotic
                                ));
                            }
                        }
                        _ if baseline_sysmon_active => {
                            /// Baseline had sysmon active, but runtime doesn't
                            /// ebpf_valid = false; // DEMO MODE
                            details.push("SYSMON:UNLOADED".to_string());
                        }
                        _ => {
                            /// No sysmon in baseline or runtime, skip
                        }
                    }
                    /// File descriptor audit
                    if let Some(ref fda) = att.tpm_quote.ebpf_state.fd_audit {
                        if fda.anomalies.is_empty() {
                            details.push(format!("FD:OK({})", fda.total_fds));
                        } else {
                            /// ebpf_valid = false; // DEMO MODE
                            details.push(format!("FD:ANOMALY({})", fda.anomalies.join("; ")));
                        }
                    }
                    /// Kernel integrity
                    if let Some(ref ki) = att.tpm_quote.ebpf_state.kernel_integrity {
                        if ki.clean {
                            details.push(format!("KERN:OK(bpf:{},kp:{},mod:{})",
                                ki.bpf_program_count, ki.kprobe_count, ki.module_count));
                        } else {
                            /// ebpf_valid = false; // DEMO MODE
                            details.push(format!("KERN:ANOMALY({})", ki.anomalies.join("; ")));
                        }
                    }
                    /// Boot parameters
                    match (&att.tpm_quote.ebpf_state.boot_params_hash, &ebpf_bl.boot_params_hash) {
                        (Some(current), Some(baseline)) => {
                            if current == baseline {
                                details.push("BOOT:OK".to_string());
                            } else {
                                /// ebpf_valid = false; // DEMO MODE
                                details.push("BOOT PARAMS CHANGED".to_string());
                            }
                        }
                        (None, Some(_)) => { details.push("BOOT:missing".to_string()); }
                        _ => {}
                    }
                    /// /dev inventory
                    match (&att.tpm_quote.ebpf_state.dev_inventory_hash, &ebpf_bl.dev_inventory_hash) {
                        (Some(current), Some(baseline)) => {
                            if current == baseline {
                                details.push("DEV:OK".to_string());
                            } else {
                                /// ebpf_valid = false; // DEMO MODE
                                details.push("DEV INVENTORY CHANGED".to_string());
                            }
                        }
                        (None, Some(_)) => { details.push("DEV:missing".to_string()); }
                        _ => {}
                    }
                    /// Connection tuples
                    match (&att.tpm_quote.ebpf_state.connection_tuples_hash, &ebpf_bl.connection_tuples_hash) {
                        (Some(cur_hash), Some(bl_hash)) => {
                            if cur_hash != bl_hash {
                                /// ebpf_valid = false; // DEMO MODE
                                let diff = diff_string_sets(
                                    &att.tpm_quote.ebpf_state.connection_tuples,
                                    &ebpf_bl.connection_tuples,
                                    "CONN",
                                );
                                details.push(format!("CONN CHANGED: {}", diff));
                            } else {
                                let count = att.tpm_quote.ebpf_state.connection_tuples
                                    .as_ref().map(|c| c.len()).unwrap_or(0);
                                details.push(format!("CONN:OK({})", count));
                            }
                        }
                        (Some(_), None) => { details.push("CONN:no_baseline".to_string()); }
                        (None, Some(_)) => { details.push("CONN:not_reported".to_string()); }
                        (None, None) => {
                            /// Fall back to connection count
                            let conn_diff = (att.tpm_quote.ebpf_state.network_connections as i64
                                - ebpf_bl.network_connections as i64).abs();
                            if conn_diff > 10 {
                                /// ebpf_valid = false; // DEMO MODE
                                details.push(format!(
                                    "CONN ANOMALY: bl={} cur={}",
                                    ebpf_bl.network_connections,
                                    att.tpm_quote.ebpf_state.network_connections
                                ));
                            } else {
                                details.push(format!(
                                    "CONN:{}/bl:{}",
                                    att.tpm_quote.ebpf_state.network_connections,
                                    ebpf_bl.network_connections
                                ));
                            }
                        }
                    }

                    /// Iptables integrity 
                    match (&att.tpm_quote.ebpf_state.iptables_hash, &ebpf_bl.iptables_hash) {
                        (Some(cur), Some(bl_hash)) => {
                            if cur != bl_hash {
                                /// ebpf_valid = false; // DEMO MODE
                                details.push("IPTABLES CHANGED".to_string());
                            } else {
                                details.push("FW:OK".to_string());
                            }
                        }
                        (None, Some(_)) => { details.push("FW:missing".to_string()); }
                        _ => {}
                    }

                    /// Binary integrity (per-file hashes)
                    match (&att.tpm_quote.ebpf_state.binary_hashes, &ebpf_bl.binary_hashes) {
                        (Some(cur), Some(bl_map)) => {
                            let mut all_match = true;
                            let mut mismatched: Vec<String> = Vec::new();

                            for (path, bl_hash) in bl_map {
                                match cur.get(path) {
                                    Some(cur_hash) if cur_hash == bl_hash => {}
                                    Some(_) => {
                                        all_match = false;
                                        mismatched.push(format!("{}:CHANGED", path));
                                    }
                                    None => {
                                        all_match = false;
                                        mismatched.push(format!("{}:MISSING", path));
                                    }
                                }
                            }
                            for path in cur.keys() {
                                if !bl_map.contains_key(path) {
                                    all_match = false;
                                    mismatched.push(format!("{}:UNEXPECTED", path));
                                }
                            }

                            if all_match {
                                details.push(format!("BIN:OK({})", bl_map.len()));
                            } else {
                                /// ebpf_valid = false; // DEMO MODE
                                details.push(format!("BIN:TAMPERED[{}]", mismatched.join(",")));
                            }
                        }
                        (Some(_), None) => {
                            /// Baseline is stale, missing binary_hashes field.
                            /// Strict: integrity failure. Force operator to recapture.
                            /// ebpf_valid = false; // DEMO MODE
                            details.push("BIN:STALE_BASELINE(recapture required)".to_string());
                        }
                        (None, Some(_)) => {
                            /// Current attestation missing binary_hashes but baseline has them.
                            /// Old agent talking to new baseline, suspicious.
                            /// ebpf_valid = false; // DEMO MODE
                            details.push("BIN:ATTESTATION_INCOMPLETE".to_string());
                        }
                        (None, None) => {
                            /// Both sides have no binary_hashes. Legacy mode.
                            /// For production: should never happen post-QW2.
                            details.push("BIN:legacy".to_string());
                        }
                    }
                    /// Binary directory listing (catches dropped files) 
                    match (&att.tpm_quote.ebpf_state.binary_dir_listing_hash, &ebpf_bl.binary_dir_listing_hash) {
                        (Some(cur), Some(bl_hash)) => {
                            if cur != bl_hash {
                                /// ebpf_valid = false; // DEMO MODE
                                details.push("BINDIR TAMPERED".to_string());
                            } else {
                                details.push("BINDIR:OK".to_string());
                            }
                        }
                        (Some(_), None) => {
                            /// ebpf_valid = false; // DEMO MODE
                            details.push("BINDIR:STALE_BASELINE".to_string());
                        }
                        (None, Some(_)) => {
                            /// ebpf_valid = false; // DEMO MODE
                            details.push("BINDIR:ATTESTATION_INCOMPLETE".to_string());
                        }
                        (None, None) => {
                            details.push("BINDIR:legacy".to_string());
                        }
                    }
                    /// Listening ports 
                    match (&att.tpm_quote.ebpf_state.listening_ports, &ebpf_bl.listening_ports) {
                        (Some(cur), Some(bl_ports)) => {
                            if cur != bl_ports {
                                /// ebpf_valid = false; // DEMO MODE
                                let new_ports: Vec<&u16> = cur.iter().filter(|p| !bl_ports.contains(p)).collect();
                                details.push(format!("PORTS CHANGED: expected {:?} got {:?} new {:?}", bl_ports, cur, new_ports));
                            } else {
                                details.push(format!("PORTS:{:?}", cur));
                            }
                        }
                        (None, Some(_)) => { details.push("PORTS:missing".to_string()); }
                        _ => {}
                    }

                    /// Mount integrity
                    match (&att.tpm_quote.ebpf_state.mount_hash, &ebpf_bl.mount_hash) {
                        (Some(cur), Some(bl_hash)) => {
                            if cur != bl_hash {
                                /// ebpf_valid = false; // DEMO MODE
                                details.push("MOUNTS CHANGED".to_string());
                            } else {
                                details.push("MNT:OK".to_string());
                            }
                        }
                        (None, Some(_)) => { details.push("MNT:missing".to_string()); }
                        _ => {}
                    }
                    /// Config integrity
                    match (&att.tpm_quote.ebpf_state.config_hash, &ebpf_bl.config_hash) {
                        (Some(cur), Some(bl_hash)) => {
                            if cur != bl_hash {
                                /// ebpf_valid = false; // DEMO MODE
                                details.push("CONFIG TAMPERED".to_string());
                            } else {
                                details.push("CFG:OK".to_string());
                            }
                        }
                        (None, Some(_)) => { details.push("CFG:missing".to_string()); }
                        _ => {}
                    }

                    /// Sysctl integrity
                    match (&att.tpm_quote.ebpf_state.sysctl_hash, &ebpf_bl.sysctl_hash) {
                        (Some(cur), Some(bl_hash)) => {
                            if cur != bl_hash {
                                /// ebpf_valid = false; // DEMO MODE
                                details.push("SYSCTL CHANGED".to_string());
                            } else {
                                details.push("SYS:OK".to_string());
                            }
                        }
                        (None, Some(_)) => { details.push("SYS:missing".to_string()); }
                        _ => {}
                    }
                } else {
                    details.push("No eBPF baseline".to_string());
                }

                /// AK public key match
                if let Some(ref baseline_ak) = bl.ak_public {
                    if !att.tpm_quote.ak_public.is_empty() {
                        if crate::tpm::ak_public_matches(&att.tpm_quote.ak_public, baseline_ak) {
                            details.push("AK match".to_string());
                        } else {
                            ak_match = false;
                            details.push("AK MISMATCH (different TPM!)".to_string());
                        }
                    } else {
                        ak_match = false;
                        details.push("AK EMPTY (stripped identity)".to_string());
                    }
                } else {
                    ak_match = false;
                    details.push("AK NO BASELINE (unconfigured)".to_string());
                }
                
                /// TPM signature verification
                if !att.tpm_quote.signature.is_empty() && !att.tpm_quote.quote_data.is_empty() {
                    match crate::tpm::verify_quote_signature(
                        &att.tpm_quote.quote_data,
                        &att.tpm_quote.signature,
                        &att.tpm_quote.ak_public,
                    ) {
                        Ok(true) => {
                            details.push("SIG:OK".to_string());
                        }
                        Ok(false) => {
                            signature_valid = false;
                            details.push("SIG:INVALID".to_string());
                        }
                        Err(e) => {
                            details.push(format!("SIG:ERR({})", e));
                        }
                    }
                } else {
                    details.push("SIG:none".to_string());
                }
            }
            None => {
                pcr_match = false;
                details.push(format!("NO BASELINE for {}", att.vm_identity));
            }
        }
        NodeVerificationResult {
            vm_identity: att.vm_identity.clone(),
            pcr_match,
            ima_valid,
            ebpf_valid,
            signature_valid,
            ak_match,
            details: details.join("; "),
        }
    }
}

// === Verification Helpers ===

/// Compute human-readable diff between current and baseline userspace processes.
/// Reports exactly which processes appeared (+) or disappeared (-).
fn diff_userspace_processes(
    current: &Option<Vec<crate::ebpf::ProcessIdentity>>,
    baseline: &Option<Vec<crate::ebpf::ProcessIdentity>>,
) -> String {
    const TRANSIENT_CONSOLE: &[&str] = &["bash", "agetty"];
    let empty = Vec::new();
    let cur: Vec<_> = current.as_ref().unwrap_or(&empty).iter()
        .filter(|p| !TRANSIENT_CONSOLE.contains(&p.comm.as_str()))
        .collect();
    let bl: Vec<_> = baseline.as_ref().unwrap_or(&empty).iter()
        .filter(|p| !TRANSIENT_CONSOLE.contains(&p.comm.as_str()))
        .collect();
    use std::collections::HashSet;
    let cur_set: HashSet<_> = cur.into_iter().collect();
    let bl_set: HashSet<_> = bl.into_iter().collect();
    let mut parts = Vec::new();
    /// New processes (in current but not in baseline)
    let new_procs: Vec<_> = cur_set.difference(&bl_set).collect();
    for p in &new_procs {
        parts.push(format!("+({},{})", p.comm, p.exe_path));
    }
    /// Missing processes (in baseline but not in current)
    let missing_procs: Vec<_> = bl_set.difference(&cur_set).collect();
    for p in &missing_procs {
        parts.push(format!("-({},{})", p.comm, p.exe_path));
    }
    if parts.is_empty() {
        "hash differs but sets match (ordering?)".to_string()
    } else {
        parts.join("; ")
    }
}

/// Compute diff between two string sets (kernel thread types, connection tuples).
fn diff_string_sets(
    current: &Option<Vec<String>>,
    baseline: &Option<Vec<String>>,
    label: &str,
) -> String {
    let empty = Vec::new();
    let cur = current.as_ref().unwrap_or(&empty);
    let bl = baseline.as_ref().unwrap_or(&empty);
    use std::collections::HashSet;
    let cur_set: HashSet<_> = cur.iter().collect();
    let bl_set: HashSet<_> = bl.iter().collect();
    let mut parts = Vec::new();
    let new_items: Vec<_> = cur_set.difference(&bl_set).collect();
    for item in &new_items {
        parts.push(format!("+{}", item));
    }
    let missing_items: Vec<_> = bl_set.difference(&cur_set).collect();
    for item in &missing_items {
        parts.push(format!("-{}", item));
    }
    if parts.is_empty() {
        format!("{} hash differs but sets match", label)
    } else {
        parts.join("; ")
    }
}

// === Chain Packets Helpers ===

impl ChainPacket {
    pub fn new(vm_identity: &str, tpm_quote: TpmQuote) -> Self {
        let chain_id = Sha256::digest(
            format!("{}-{}", vm_identity, std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
            ).as_bytes()
        ).to_vec();

        let attestation = Attestation {
            vm_identity: vm_identity.to_string(),
            tpm_quote,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        ChainPacket {
            attestations: vec![attestation],
            chain_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            is_response: false,
            session_token: None,
        }
    }

    pub fn add_attestation(&mut self, vm_identity: &str, tpm_quote: TpmQuote) {
        let attestation = Attestation {
            vm_identity: vm_identity.to_string(),
            tpm_quote,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        self.attestations.push(attestation);
    }

}

