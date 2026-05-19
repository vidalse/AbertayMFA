use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::sync::RwLock;
use std::sync::Arc;
use std::collections::HashMap;
use sha2::{Sha256, Digest};
use mfa_agent::audit::{AuditEntryV2, AttestationMeta};
use mfa_agent::tpm::PcrBaseline;
use mfa_monitor::{
    LogFwdMessage, LogFwdResponse,
    establish_session_responder, receive_message, send_response,
};
use mfa_monitor::session_tracker::SessionTracker;

type SharedTracker = Arc<tokio::sync::Mutex<SessionTracker>>;

const DEFAULT_CONFIG: &str = "monitor.json";
const MAX_RECENT_ENTRIES: usize = 200;
const MAX_FULL_ENTRIES: usize = 200;
const MAX_ALERTS: usize = 50;

// === Config ===
#[derive(Debug, Clone, Deserialize)]
struct MonitorConfig {
    node_id: String,
    log_receiver_port: u16,
    dashboard_port: u16,
    #[allow(dead_code)]
    attestation_port: u16,
    authorized_sources: Vec<AuthorizedSource>,
    verified_log_path: String,
    baselines_path: String,
    cross_verify: bool,
    #[allow(dead_code)]
    reconnect_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthorizedSource {
    node_id: String,
    ip: String,
    chain: u8,
}

impl MonitorConfig {
    fn load(path: &str) -> Result<Self> {
        let json = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path))?;
        serde_json::from_str(&json)
            .with_context(|| format!("Failed to parse config: {}", path))
    }

    fn is_authorized(&self, ip: &str) -> Option<&AuthorizedSource> {
        self.authorized_sources.iter().find(|s| s.ip == ip)
    }
}

// === Baseline Database (read-only copy for display purposes) ===
#[derive(Debug, Clone, Deserialize)]
struct BaselineDatabase {
    baselines: Vec<PcrBaseline>,
}

impl BaselineDatabase {
    fn load(path: &str) -> Option<Self> {
        let data = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }

    fn get(&self, node_id: &str) -> Option<&PcrBaseline> {
        self.baselines.iter().find(|b| b.vm_identity == node_id)
    }
}

// === Shared State ===
#[derive(Debug, Clone, Serialize)]
struct SystemState {
    sources: HashMap<String, SourceState>,
    cross_verified: bool,
    cross_verify_details: String,
    recent_entries: Vec<DashboardEntry>,
    full_entries: Vec<AuditEntryV2>,
    alerts: Vec<Alert>,
    node_status: HashMap<String, NodeStatus>,
    total_entries_received: u64,
    total_chain_breaks: u64,
    total_cross_mismatches: u64,
    total_forensic_snapshots: u64,
    uptime_secs: u64,
    start_time: u64,
    avg_verification_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct SourceState {
    node_id: String,
    connected: bool,
    last_seq: u64,
    last_heartbeat: u64,
    last_timestamp: u64,
    prev_hash: String,
    entries_received: u64,
    chain_intact: bool,
}

#[derive(Debug, Clone, Serialize)]
struct DashboardEntry {
    seq: u64,
    timestamp: u64,
    source: String,
    heartbeat: u64,
    authorized: bool,
    tier: String,
    node_count: usize,
    all_pass: bool,
    has_checkpoint: bool,
    verification_ms: Option<u64>,
    has_forensic: bool,
}

#[derive(Debug, Clone, Serialize)]
struct NodeStatus {
    node_id: String,
    chain: u8,
    pass: bool,
    pcr_match: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcr_mismatch_indices: Option<Vec<u8>>,
    ima_valid: bool,
    ima_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    ima_delta: Option<i64>,
    userspace_ok: bool,
    userspace_count: usize,
    kernel_threads_ok: bool,
    kernel_thread_count: usize,
    masquerade_detected: bool,
    kernel_modules_empty: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    kernel_modules_loaded: Option<Vec<String>>,
    connections_ok: bool,
    connection_count: usize,
    fw_ok: bool,
    bin_ok: bool,
    ports_ok: bool,
    ports: Vec<u16>,
    mnt_ok: bool,
    cfg_ok: bool,
    sys_ok: bool,
    xdp_attached: bool,
    passwd_ok: bool,
    ssh_ok: bool,
    ld_preload_safe: bool,
    boot_params_ok: bool,
    dev_inventory_ok: bool,
    entropy_available: Option<u32>,
    sysmon_active: bool,
    sysmon_hooks: Option<u64>,
    sysmon_anomaly: bool,
    sysmon_unloaded: bool,
    sysmon_exec_delta: Option<u64>,
    sysmon_ptrace_delta: Option<u64>,
    sysmon_mount_delta: Option<u64>,
    sysmon_conn_delta: Option<u64>,
    sysmon_sock_delta: Option<u64>,
    fd_ok: bool,
    fd_count: usize,
    kern_ok: bool,
    kern_details: Option<String>,
    init_ok: bool,
    init_count: usize,
    init_unused: usize,
    sig_valid: bool,
    ak_match: bool,
    raw_details: String,
    last_seen: u64,
    tpm_signed: Option<bool>,
    ima_aggregate_hash: Option<String>,
    process_count: Option<usize>,
    full_meta: Option<AttestationMeta>,
}

#[derive(Debug, Clone, Serialize)]
struct Alert {
    timestamp: u64,
    severity: String,
    message: String,
    seq: Option<u64>,
}

impl SystemState {
    fn new() -> Self {
        SystemState {
            sources: HashMap::new(),
            cross_verified: false,
            cross_verify_details: "Waiting for both sources".to_string(),
            recent_entries: Vec::new(),
            full_entries: Vec::new(),
            alerts: Vec::new(),
            node_status: HashMap::new(),
            total_entries_received: 0,
            total_chain_breaks: 0,
            total_cross_mismatches: 0,
            total_forensic_snapshots: 0,
            uptime_secs: 0,
            start_time: now_secs(),
            avg_verification_ms: 0,
        }
    }
}

type SharedState = Arc<RwLock<SystemState>>;
type SharedBaselines = Arc<Option<BaselineDatabase>>;

// === Log Reciever === 
async fn handle_source(
    mut stream: TcpStream,
    peer_ip: String,
    source_info: AuthorizedSource,
    state: SharedState,
    config: MonitorConfig,
    tracker: SharedTracker,
) -> Result<()> {
    println!("  Key exchange with {}...", peer_ip);
    let session_key = establish_session_responder(&mut stream, &config.node_id).await
        .context("Key exchange failed")?;
    println!("  Session established with {}", peer_ip);

    let hello = receive_message(&mut stream, &session_key).await?;
    let source_node_id = match hello {
        LogFwdMessage::Hello { node_id } => {
            if node_id != source_info.node_id {
                let reason = format!("Expected {} got {}", source_info.node_id, node_id);
                send_response(&mut stream, &session_key, &LogFwdResponse::Reject {
                    reason: reason.clone(),
                }).await?;
                return Err(anyhow::anyhow!("Identity mismatch: {}", reason));
            }
            println!("  Authenticated: {}", node_id);
            node_id
        }
        _ => {
            send_response(&mut stream, &session_key, &LogFwdResponse::Reject {
                reason: "Expected Hello".to_string(),
            }).await?;
            return Err(anyhow::anyhow!("Expected Hello message"));
        }
    };
    send_response(&mut stream, &session_key, &LogFwdResponse::Welcome).await?;
    {
        let mut st = state.write().await;
        st.sources.insert(source_node_id.clone(), SourceState {
            node_id: source_node_id.clone(),
            connected: true,
            last_seq: 0,
            last_heartbeat: 0,
            last_timestamp: 0,
            prev_hash: String::new(),
            entries_received: 0,
            chain_intact: true,
        });
    }
    let stream_path = format!("{}-stream.jsonl", source_node_id);
    println!("  Receiving from {} ...", source_node_id);
    loop {
        let msg = match receive_message(&mut stream, &session_key).await {
            Ok(m) => m,
            Err(e) => {
                println!("  {} disconnected: {}", source_node_id, e);
                let mut st = state.write().await;
                if let Some(src) = st.sources.get_mut(&source_node_id) {
                    src.connected = false;
                }
                return Err(e);
            }
        };
        match msg {
            LogFwdMessage::Entry { json } => {
                let entry: AuditEntryV2 = match serde_json::from_str(&json) {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("  Invalid entry from {}: {}", source_node_id, e);
                        send_response(&mut stream, &session_key, &LogFwdResponse::Reject {
                            reason: format!("Parse error: {}", e),
                        }).await?;
                        continue;
                    }
                };
                /// Verify hash chain
                let chain_ok = {
                    let st = state.read().await;
                    if let Some(src) = st.sources.get(&source_node_id) {
                        if src.entries_received == 0 { true }
                        else { entry.prev_hash == src.prev_hash }
                    } else { true }
                };
                if !chain_ok {
                    let mut st = state.write().await;
                    st.total_chain_breaks += 1;
                    if let Some(src) = st.sources.get_mut(&source_node_id) {
                        src.chain_intact = false;
                    }
                    st.alerts.push(Alert {
                        timestamp: now_secs(),
                        severity: "CRITICAL".to_string(),
                        message: format!("Hash chain BROKEN from {} at seq {}", source_node_id, entry.seq),
                        seq: Some(entry.seq),
                    });
                    if st.alerts.len() > MAX_ALERTS { st.alerts.remove(0); }
                    println!("  HASH CHAIN BROKEN from {} at seq {}!", source_node_id, entry.seq);
                }
                let entry_hash = sha256_hex(json.as_bytes());
                let has_checkpoint = entry.tpm_checkpoint.is_some();
                let has_forensic = entry.forensic.is_some();
                if has_checkpoint {
                    println!("  TPM checkpoint from {} at seq {}", source_node_id, entry.seq);
                }
                if has_forensic {
                    println!("  FORENSIC SNAPSHOT from {} at seq {} [{}]",
                        source_node_id, entry.seq, entry.tier);
                }
                let tier_str = format!("{:?}", entry.tier);
                if tier_str != "Info" {
                    let mut st = state.write().await;
                    st.alerts.push(Alert {
                        timestamp: now_secs(),
                        severity: tier_str.clone(),
                        message: format!("{} from {} HB#{}: {}",
                            entry.event, source_node_id, entry.heartbeat,
                            if entry.authorized { "authorized" } else { "DENIED" }),
                        seq: Some(entry.seq),
                    });
                    if st.alerts.len() > MAX_ALERTS { st.alerts.remove(0); }
                }
                
                {
                    let mut st = state.write().await;
                    st.total_entries_received += 1;

                    if has_forensic {
                        st.total_forensic_snapshots += 1;
                        /// Store forensic snapshot to disk
                        let forensic_path = format!("/opt/mfa-monitor/forensics/forensic_{}_{}.json",
                            source_node_id, entry.seq);
                        if let Ok(pretty) = serde_json::to_string_pretty(&entry) {
                            let fhash = sha256_hex(pretty.as_bytes());
                            let _ = std::fs::write(&forensic_path, &pretty);
                            /// Update forensic index
                            let idx_path = "/opt/mfa-monitor/forensics/index.json";
                            let mut idx: Vec<serde_json::Value> = std::fs::read_to_string(idx_path)
                                .ok()
                                .and_then(|s| serde_json::from_str(&s).ok())
                                .unwrap_or_default();
                            idx.push(serde_json::json!({
                                "seq": entry.seq,
                                "source": source_node_id,
                                "timestamp": entry.timestamp,
                                "heartbeat": entry.heartbeat,
                                "tier": format!("{:?}", entry.tier),
                                "authorized": entry.authorized,
                                "filename": format!("forensic_{}_{}.json", source_node_id, entry.seq),
                                "file_hash": fhash,
                            }));
                            let _ = std::fs::write(idx_path, serde_json::to_string_pretty(&idx).unwrap_or_default());
                        }
                    }
                    if let Some(src) = st.sources.get_mut(&source_node_id) {
                        src.last_seq = entry.seq;
                        src.last_heartbeat = entry.heartbeat;
                        src.last_timestamp = entry.timestamp;
                        src.prev_hash = entry_hash;
                        src.entries_received += 1;
                    }
                    if let Some(ref nodes) = entry.nodes {
                        for n in nodes {
                            let meta = entry.attestation_meta.as_ref()
                                .and_then(|metas| metas.iter().find(|m| m.node_id == n.node));

                            let existing = st.node_status.get(&n.node);
                            let tpm_signed = meta.map(|m| m.tpm_signed)
                                .or_else(|| existing.and_then(|e| e.tpm_signed));
                            let ima_aggregate_hash = meta.map(|m| m.ima_aggregate_hash.clone())
                                .or_else(|| existing.and_then(|e| e.ima_aggregate_hash.clone()));
                            let process_count = meta.map(|m| m.process_count)
                                .or_else(|| existing.and_then(|e| e.process_count));
                            let full_meta = meta.cloned()
                                .or_else(|| existing.and_then(|e| e.full_meta.clone()));

                            st.node_status.insert(n.node.clone(), NodeStatus {
                                node_id: n.node.clone(),
                                chain: n.chain,
                                pass: n.pass,
                                pcr_match: n.pcr_match,
                                pcr_mismatch_indices: n.pcr_mismatch_indices.clone(),
                                ima_valid: n.ima_valid,
                                ima_count: n.ima_count,
                                ima_delta: n.ima_delta,
                                userspace_ok: n.userspace_ok,
                                userspace_count: n.userspace_count,
                                kernel_threads_ok: n.kernel_threads_ok,
                                kernel_thread_count: n.kernel_thread_count,
                                masquerade_detected: n.masquerade_detected,
                                kernel_modules_empty: n.kernel_modules_empty,
                                kernel_modules_loaded: n.kernel_modules_loaded.clone(),
                                connections_ok: n.connections_ok,
                                connection_count: n.connection_count,
                                fw_ok: n.fw_ok,
                                bin_ok: n.bin_ok,
                                ports_ok: n.ports_ok,
                                ports: n.ports.clone(),
                                mnt_ok: n.mnt_ok,
                                cfg_ok: n.cfg_ok,
                                sys_ok: n.sys_ok,
                                xdp_attached: n.xdp_attached,
                                passwd_ok: n.passwd_ok,
                                ssh_ok: n.ssh_ok,
                                ld_preload_safe: n.ld_preload_safe,
                                boot_params_ok: n.boot_params_ok,
                                dev_inventory_ok: n.dev_inventory_ok,
                                entropy_available: n.entropy_available,
                                sysmon_active: n.sysmon_active,
                                sysmon_hooks: n.sysmon_hooks,
                                sysmon_anomaly: n.sysmon_anomaly,
                                sysmon_unloaded: n.sysmon_unloaded,
                                sysmon_exec_delta: n.sysmon_exec_delta,
                                sysmon_ptrace_delta: n.sysmon_ptrace_delta,
                                sysmon_mount_delta: n.sysmon_mount_delta,
                                sysmon_conn_delta: n.sysmon_conn_delta,
                                sysmon_sock_delta: n.sysmon_sock_delta,
                                fd_ok: n.fd_ok,
                                fd_count: n.fd_count,
                                kern_ok: n.kern_ok,
                                kern_details: n.kern_details.clone(),
                                init_ok: n.init_ok,
                                init_count: n.init_count,
                                init_unused: n.init_unused,
                                sig_valid: n.sig_valid,
                                ak_match: n.ak_match,
                                raw_details: n.raw_details.clone(),
                                last_seen: entry.timestamp,
                                tpm_signed,
                                ima_aggregate_hash,
                                process_count,
                                full_meta,
                            });
                        }
                    }
                    if let Some(ms) = entry.verification_duration_ms {
                        if st.avg_verification_ms == 0 {
                            st.avg_verification_ms = ms;
                        } else {
                            st.avg_verification_ms = (st.avg_verification_ms * 3 + ms) / 4;
                        }
                    }
                    let node_count = entry.nodes.as_ref().map(|n| n.len()).unwrap_or(0);
                    let all_pass = entry.nodes.as_ref()
                        .map(|nodes| nodes.iter().all(|n| n.pass))
                        .unwrap_or(false);
                    st.recent_entries.push(DashboardEntry {
                        seq: entry.seq,
                        timestamp: entry.timestamp,
                        source: source_node_id.clone(),
                        heartbeat: entry.heartbeat,
                        authorized: entry.authorized,
                        tier: format!("{:?}", entry.tier),
                        node_count,
                        all_pass,
                        has_checkpoint,
                        verification_ms: entry.verification_duration_ms,
                        has_forensic,
                    });
                    if st.recent_entries.len() > MAX_RECENT_ENTRIES {
                        st.recent_entries.remove(0);
                    }
                    st.full_entries.push(entry);
                    if st.full_entries.len() > MAX_FULL_ENTRIES {
                        st.full_entries.remove(0);
                    }
                    if config.cross_verify && st.sources.len() >= 2 {
                        cross_verify_sources(&mut st);
                    }
                    st.uptime_secs = now_secs() - st.start_time;
                }
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true).append(true).open(&stream_path)
                {
                    use std::io::Write;
                    let _ = writeln!(file, "{}", json);
                }
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true).append(true).open(&config.verified_log_path)
                {
                    use std::io::Write;
                    let _ = writeln!(file, "{}", json);
                }
                /// Session tracking
                {
                    let entry_val: serde_json::Value = serde_json::from_str(&json)
                        .unwrap_or_default();
                    let mut trk = tracker.lock().await;
                    if let Some(session_id) = trk.process_entry(
                        &source_node_id, &json, &entry_val,
                    ) {
                        println!("  SESSION COMPLETED: {}", session_id);
                    }
                }

                send_response(&mut stream, &session_key, &LogFwdResponse::Ack).await?;
                

            }
            LogFwdMessage::Ping => {
                send_response(&mut stream, &session_key, &LogFwdResponse::Ack).await?;
            }
            LogFwdMessage::Hello { .. } => {}
        }
    }
}

fn cross_verify_sources(state: &mut SystemState) {
    let vm2 = state.sources.get("vm2");
    let vm3 = state.sources.get("vm3");
    match (vm2, vm3) {
        (Some(s2), Some(s3)) => {
            if !s2.connected || !s3.connected {
                state.cross_verified = false;
                state.cross_verify_details = format!("VM2:{} VM3:{}",
                    if s2.connected { "connected" } else { "DISCONNECTED" },
                    if s3.connected { "connected" } else { "DISCONNECTED" });
                return;
            }
            if !s2.chain_intact || !s3.chain_intact {
                state.cross_verified = false;
                state.cross_verify_details = format!("CHAIN: VM2:{} VM3:{}",
                    if s2.chain_intact { "OK" } else { "BROKEN" },
                    if s3.chain_intact { "OK" } else { "BROKEN" });
                state.total_cross_mismatches += 1;
                return;
            }
            let gap = (s2.last_heartbeat as i64 - s3.last_heartbeat as i64).abs();
            if gap > 2 {
                state.cross_verified = false;
                state.cross_verify_details = format!("DRIFT: VM2=HB#{} VM3=HB#{} gap={}",
                    s2.last_heartbeat, s3.last_heartbeat, gap);
            } else {
                state.cross_verified = true;
                state.cross_verify_details = format!("VM2:HB#{}/seq{} VM3:HB#{}/seq{} ✓",
                    s2.last_heartbeat, s2.last_seq, s3.last_heartbeat, s3.last_seq);
            }
        }
        _ => {
            state.cross_verified = false;
            state.cross_verify_details = "Waiting for both sources".to_string();
        }
    }
}

// === Dashboard ===
async fn run_dashboard(port: u16, state: SharedState, baselines: SharedBaselines) -> Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("Dashboard: http://0.0.0.0:{}", port);

    loop {
        let (mut stream, peer) = listener.accept().await?;
        println!("Dashboard request from {}", peer);
        let state = state.clone();
        let baselines = baselines.clone();
        tokio::spawn(async move {
            let _ = handle_http(&mut stream, &state, &baselines).await;
        });
    }
}

async fn handle_http(
    stream: &mut TcpStream,
    state: &SharedState,
    baselines: &SharedBaselines,
) -> Result<()> {
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).await?;
    if n == 0 { return Ok(()); }
    let request = String::from_utf8_lossy(&buf[..n]);
    let first_line = request.lines().next().unwrap_or("");

    /// Parse path
    let path = first_line.split_whitespace().nth(1).unwrap_or("/");

    let (status, content_type, body) = route(path, state, baselines).await;

    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status, content_type, body.len(), body
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

async fn route(
    path: &str,
    state: &SharedState,
    baselines: &SharedBaselines,
) -> (&'static str, &'static str, String) {
    /// API routes
    if path == "/api/state" {
        let st = state.read().await;
        let json = serde_json::to_string_pretty(&*st).unwrap_or_default();
        return ("200 OK", "application/json", json);
    }
    if path == "/api/latest" {
        let st = state.read().await;
        let json = st.full_entries.last()
            .and_then(|e| serde_json::to_string_pretty(e).ok())
            .unwrap_or_else(|| "{}".to_string());
        return ("200 OK", "application/json", json);
    }
    if path == "/api/nodes" {
        let st = state.read().await;
        let json = serde_json::to_string_pretty(&st.node_status).unwrap_or_default();
        return ("200 OK", "application/json", json);
    }
    if path == "/api/forensics" {
        let st = state.read().await;
        let forensic_entries: Vec<&AuditEntryV2> = st.full_entries.iter()
            .filter(|e| e.forensic.is_some())
            .collect();
        let json = serde_json::to_string_pretty(&forensic_entries).unwrap_or_default();
        return ("200 OK", "application/json", json);
    }
    if path == "/api/forensic-index" {
        let content = std::fs::read_to_string("/opt/mfa-monitor/forensics/index.json")
            .unwrap_or_else(|_| "[]".into());
        return ("200 OK", "application/json", content);
    }
    if path == "/api/sessions" {
        let index = mfa_monitor::session_tracker::SessionTracker::load_index();
        let json = serde_json::to_string_pretty(&index).unwrap_or("null".into());
        return ("200 OK", "application/json", json);
    }
    if let Some(id) = path.strip_prefix("/api/session/") {
        let index = mfa_monitor::session_tracker::SessionTracker::load_index();
        if let Some(idx) = index {
            if let Some(entry) = idx.sessions.iter().find(|s| s.session_id == id) {
                if let Some(session) = mfa_monitor::session_tracker::SessionTracker::load_session(&entry.filename) {
                    let json = serde_json::to_string_pretty(&session).unwrap_or("null".into());
                    return ("200 OK", "application/json", json);
                }
            }
        }
        return ("404 Not Found", "application/json", r#"{"error":"session not found"}"#.into());
    }
    /// Forensic detail download
    if let Some(seq_str) = path.strip_prefix("/forensics/").and_then(|s| s.strip_suffix("/download")) {
        if let Ok(seq) = seq_str.parse::<u64>() {
            let st = state.read().await;
            if let Some(entry) = st.full_entries.iter().find(|e| e.seq == seq) {
                let json = serde_json::to_string_pretty(entry).unwrap_or_default();
                return ("200 OK", "application/json", json);
            }
        }
        return ("404 Not Found", "text/plain", "Not found".to_string());
    }
    /// Forensic detail page
    if let Some(seq_str) = path.strip_prefix("/forensics/") {
        if let Ok(seq) = seq_str.parse::<u64>() {
            let st = state.read().await;
            if let Some(entry) = st.full_entries.iter().find(|e| e.seq == seq) {
                let html = render_forensic_detail(entry, baselines.as_ref().as_ref());
                return ("200 OK", "text/html; charset=utf-8", html);
            }
        }
        return ("404 Not Found", "text/plain", "Forensic event not found".to_string());
    }
    /// Forensics list
    if path == "/forensics" {
        let st = state.read().await;
        let html = render_forensics_list(&st);
        return ("200 OK", "text/html; charset=utf-8", html);
    }
    /// Node detail page
    if let Some(node_id) = path.strip_prefix("/node/") {
        let st = state.read().await;
        if let Some(node) = st.node_status.get(node_id) {
            let baseline = baselines.as_ref().as_ref()
                .and_then(|db| db.get(node_id));
            let html = render_node_detail(node, baseline);
            return ("200 OK", "text/html; charset=utf-8", html);
        }
        return ("404 Not Found", "text/plain", "Node not found".to_string());
    }
    /// Diff view
    if let Some(node_id) = path.strip_prefix("/diff/") {
        let st = state.read().await;
        if let Some(node) = st.node_status.get(node_id) {
            let baseline = baselines.as_ref().as_ref()
                .and_then(|db| db.get(node_id));
            let html = render_diff(node, baseline);
            return ("200 OK", "text/html; charset=utf-8", html);
        }
        return ("404 Not Found", "text/plain", "Node not found".to_string());
    }
    if path == "/sessions" {
        let html = render_sessions();
        return ("200 OK", "text/html; charset=utf-8", html);
    }
    /// Main dashboard
    let st = state.read().await;
    let html = render_dashboard(&st);
    ("200 OK", "text/html; charset=utf-8", html)
}

// === COMMON STYLES & LAYOUT ===
const COMMON_STYLES: &str = r#"
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'JetBrains Mono', 'Consolas', 'Courier New', monospace;
    background: #0c0c0c; color: #d4d4d4; padding: 16px; font-size: 12px; line-height: 1.5;
}
a { color: #4a9eff; text-decoration: none; } a:hover { text-decoration: underline; }
 
/* Header */
.header { display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; background: #141414; border: 1px solid #2a2a2a; border-left: 3px solid #4a9eff; margin-bottom: 14px; }
.header h1 { font-size: 13px; font-weight: 600; color: #4a9eff; letter-spacing: 1px; text-transform: uppercase; }
.hstats { display: flex; gap: 16px; font-size: 11px; color: #999; flex-wrap: wrap; }
.hstats .v { color: #d4d4d4; font-weight: 600; }
.hstats .ok { color: #3ddc84; } .hstats .fl { color: #f44336; }
 
/* Nav */
.nav { margin-bottom: 14px; display: flex; gap: 3px; flex-wrap: wrap; }
.nav a { padding: 3px 10px; background: #141414; border: 1px solid #2a2a2a; color: #999; text-decoration: none; font-size: 11px; }
.nav a:hover { border-color: #4a9eff; color: #4a9eff; background: #0d1b2a; }
 
/* Banners */
.banner { padding: 8px 14px; margin-bottom: 14px; font-size: 11px; font-weight: 600; letter-spacing: 0.5px; }
.banner.ok { background: #0a1a0a; border: 1px solid #1a3a1a; border-left: 3px solid #3ddc84; color: #3ddc84; }
.banner.fl { background: #1a0808; border: 1px solid #3a1a1a; border-left: 3px solid #f44336; color: #f44336; }
 
/* Status bar (top) */
.sbar { display: flex; justify-content: space-between; align-items: center; padding: 6px 12px; margin-bottom: 14px; font-size: 11px; background: #141414; border: 1px solid #2a2a2a; }
.sbar .sl { color: #999; } .sbar .sv { color: #d4d4d4; font-weight: 600; }
.sbar .sg { color: #3ddc84; } .sbar .sr { color: #f44336; }
 
/* Panels */
.pnl { background: #141414; border: 1px solid #2a2a2a; margin-bottom: 14px; }
.pnl-h { display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; background: #1a1a1a; border-bottom: 1px solid #2a2a2a; font-size: 10px; font-weight: 600; color: #999; text-transform: uppercase; letter-spacing: 1px; }
.pnl-h .ct { color: #4a9eff; text-transform: none; font-weight: 400; }
.pnl-b { padding: 10px; }
 
/* Grid layouts */
.g2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.g3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; }
@media (max-width: 1200px) { .g2, .g3 { grid-template-columns: 1fr; } }
 
/* Tables */
table { width: 100%; border-collapse: collapse; }
th { text-align: left; padding: 3px 5px; font-size: 9px; font-weight: 600; color: #777; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #2a2a2a; white-space: nowrap; }
td { padding: 3px 5px; border-bottom: 1px solid #1a1a1a; font-size: 11px; vertical-align: middle; }
 
/* Grid group headers */
th.gh { text-align: center; color: #4a9eff; font-size: 9px; padding: 5px 3px 2px; border-bottom: 2px solid #2a4a6a; white-space: normal; }
th.gs, td.gs { border-left: 1px solid #2a2a2a; padding-left: 7px; }
 
/* Group description (under group header) */
.gd { display: block; font-size: 8px; color: #888; font-weight: 400; text-transform: none; letter-spacing: 0; line-height: 1.3; margin-top: 2px; white-space: normal; }
 
/* Value cells with background colors */
.cp { background: #0a1a0a; color: #3ddc84; text-align: center; font-size: 10px; font-family: monospace; }
.cf { background: #1a0808; color: #f44336; text-align: center; font-size: 10px; font-family: monospace; }
.cw { background: #1a1408; color: #ff9800; text-align: center; font-size: 10px; font-family: monospace; }
.cn { background: #111; color: #666; text-align: center; font-size: 10px; font-family: monospace; }
 
/* Node rows */
tr.rp td:first-child { border-left: 2px solid #3ddc84; }
tr.rf td { background: #1a0808; } tr.rf td:first-child { border-left: 2px solid #f44336; }
td.nn { font-weight: 600; } td.nn a { color: #d4d4d4; text-decoration: none; } td.nn a:hover { color: #4a9eff; }
 
/* Heartbeat rows */
tr.hp td { } tr.hf td { background: #1a0808; color: #f44336; }
 
/* Alert rows */
tr.ac td { color: #f44336; background: #1a0808; } tr.aw td { color: #ff9800; background: #1a1408; }
 
/* Tier badges */
.tier { display: inline-block; padding: 1px 5px; font-size: 9px; font-weight: 600; border-radius: 2px; }
.ti { background: #0d1b2a; color: #4a9eff; border: 1px solid #1a3a5a; }
.tw { background: #1a1408; color: #ff9800; border: 1px solid #4a3a1a; }
.tc { background: #1a0808; color: #f44336; border: 1px solid #4a1a1a; }
 
/* Descriptions and legends */
.ldesc { font-size: 10px; color: #999; padding: 6px 8px; line-height: 1.6; background: #111; border-top: 1px solid #2a2a2a; }
.ldesc b { color: #4a9eff; }
 
/* Hash display */
.hash { font-family: monospace; color: #888; font-size: 9px; word-break: break-all; }
 
/* Content blocks */
.cb { background: #0a0a0a; border: 1px solid #222; padding: 6px; font-size: 11px; white-space: pre-wrap; max-height: 400px; overflow-y: auto; color: #999; }
 
/* Expandable */
details { margin: 3px 0; } summary { cursor: pointer; color: #4a9eff; padding: 2px 0; font-size: 11px; } summary:hover { color: #6ab8ff; }
 
/* Buttons */
.btn { display: inline-block; padding: 2px 8px; background: #141414; border: 1px solid #4a9eff; color: #4a9eff; text-decoration: none; font-size: 10px; } .btn:hover { background: #0d1b2a; }
 
/* API links */
.api { color: #888; font-size: 10px; margin-top: 6px; padding-top: 6px; border-top: 1px solid #1a1a1a; } .api a { color: #888; margin-right: 10px; } .api a:hover { color: #4a9eff; }
 
/* Scrollable grid container */
.grid-scroll { overflow-x: auto; }
.grid-scroll table { min-width: 1400px; }
.grid-scroll td:first-child, .grid-scroll th:first-child { position: sticky; left: 0; background: #141414; z-index: 1; }
 
/* Pass/fail text (non-cell) */
.p { color: #3ddc84; } .f { color: #f44336; } .w { color: #ff9800; } .n { color: #666; }
"#;

// === HELPER FUNCTIONS ===
fn status_cell(ok: bool) -> &'static str {
    if ok { "<td class=\"p\">PASS</td>" } else { "<td class=\"f\">FAIL</td>" }
}
 
fn status_val(ok: bool, val: &str) -> String {
    if ok { format!("<td class=\"p\">{}</td>", val) } else { format!("<td class=\"f\">{}</td>", val) }
}
 
fn nav_bar() -> String {
    r#"<div class="nav">
    <a href="/">Overview</a>
    <a href="/sessions">Sessions</a>
    <a href="/forensics">Forensics</a>
    <a href="/api/state">API</a>
</div>"#.to_string()
}
fn render_circuit_proof(state: &SystemState) -> String {
    let vm2_entry = state.full_entries.iter().rev().find(|e| e.node_id == "vm2");
    let vm3_entry = state.full_entries.iter().rev().find(|e| e.node_id == "vm3");
    let latest = match vm3_entry.or(vm2_entry) {
        Some(e) => e,
        None => return String::new(),
    };
    let nodes = match &latest.nodes {
        Some(n) => n,
        None => return String::new(),
    };
    /// Merge meta from both sources
    let mut all_metas: Vec<&mfa_agent::audit::AttestationMeta> = Vec::new();
    if let Some(e) = vm2_entry {
        if let Some(ref m) = e.attestation_meta {
            for meta in m { all_metas.push(meta); }
        }
    }
    if let Some(e) = vm3_entry {
        if let Some(ref m) = e.attestation_meta {
            for meta in m {
                if !all_metas.iter().any(|x| x.node_id == meta.node_id) {
                    all_metas.push(meta);
                }
            }
        }
    }
    let chain_id = if latest.chain_id.len() >= 16 { &latest.chain_id[..16] } else { &latest.chain_id };
    let chain1_order = ["vm1", "pr1", "pr2", "pr3", "vm2"];
    let chain2_order = ["vm2", "pr4", "pr5", "pr6", "vm3"];

    let render_hop = |node_id: &str, hop_num: usize, onion_layers: usize, chain_color: &str| -> String {
        let nr = nodes.iter().find(|n| n.node == node_id);
        let meta = all_metas.iter().find(|a| a.node_id == node_id);
        let (pcr, sig, ak) = match nr {
            Some(n) => (n.pcr_match, n.sig_valid, n.ak_match),
            None => (false, false, false),
        };
        let (quote_b, sig_b, ak_b) = match meta {
            Some(m) => (m.tpm_quote_bytes, m.tpm_signature_bytes, m.ak_public_bytes),
            None => (0, 0, 0),
        };
        let ak_fp = match meta {
            Some(m) => {
                let h = &m.ima_aggregate_hash;
                if h.len() >= 8 { format!("{}...", &h[..8]) } else { h.clone() }
            }
            None => "--".into(),
        };
        let all_ok = pcr && sig && ak;
        let sc = if all_ok { "cp" } else { "cf" };
        let role = match node_id {
            "vm1" => "Client (circuit origin)",
            "vm2" => "Chain 1 Verifier (ZTS)",
            "vm3" => "Chain 2 Verifier (DA)",
            _ if node_id.starts_with("pr") => "Relay proxy",
            _ => "",
        };

        format!(
            "<tr>\
            <td style=\"color:{chain_color};font-weight:600;\">{hop}</td>\
            <td class=\"nn\">{node}</td>\
            <td style=\"color:#888;font-size:9px;\">{role}</td>\
            <td class=\"{sc}\">{layers}</td>\
            <td class=\"{sc}\">{quote}B</td>\
            <td class=\"{sc}\">{sig}B</td>\
            <td class=\"{sc}\">{ak}B</td>\
            <td class=\"hash\">{ak_fp}</td>\
            </tr>\n",
            chain_color=chain_color, hop=hop_num, node=node_id, role=role,
            sc=sc, layers=onion_layers, quote=quote_b, sig=sig_b, ak=ak_b,
            ak_fp=ak_fp,
        )
    };
    let mut rows = String::new();
    /// Chain 1
    for (i, node_id) in chain1_order.iter().enumerate() {
        let layers = i + 1; /// vm1=1, pr1=1, pr2=2, pr3=3, vm2=4
        let onion = match i {
            0 => 0, /// vm1 is origin, not a relay
            _ => i,
        };
        rows.push_str(&render_hop(node_id, i + 1, if i == 0 { 0 } else { i }, "rgb(61,220,132)"));
    }
    /// Separator
    rows.push_str("<tr><td colspan=\"8\" style=\"border-top:1px solid #2a2a2a;padding:4px;color:#555;font-size:8px;\">Chain 2 circuit (independent key exchange from chain 1)</td></tr>\n");
    /// Chain 2
    for (i, node_id) in chain2_order.iter().enumerate() {
        if i == 0 { continue; } /// vm2 already shown
        rows.push_str(&render_hop(node_id, 5 + i, i, "rgb(255,152,0)"));
    }
    let verified_count = nodes.iter().filter(|n| n.pcr_match && n.sig_valid && n.ak_match).count();
    format!(r#"
<div class="pnl">
    <div class="pnl-h"><span>Circuit Attestation Proof</span><span class="ct">{verified}/{total} nodes cryptographically verified</span></div>
    <table>
    <tr><th>Hop</th><th>Node</th><th>Role</th><th>Onion Layers</th><th>TPM Quote</th><th>Signature</th><th>AK Public</th><th>Identity</th></tr>
    {rows}
    </table>
</div>"#,
        verified = verified_count, total = nodes.len(),
        rows = rows,
    )
}

// === Main Dashboard Render ===
fn render_dashboard(state: &SystemState) -> String {
    let now = now_secs();
    let total = state.node_status.len();
    let passing = state.node_status.values().filter(|n| {
        n.pass && n.fw_ok && n.passwd_ok && n.ssh_ok && n.ld_preload_safe
        && n.boot_params_ok && n.dev_inventory_ok && n.mnt_ok && n.cfg_ok
        && n.sys_ok && n.init_ok && n.xdp_attached && !n.sysmon_anomaly
        && !n.sysmon_unloaded && n.fd_ok && n.kern_ok && n.userspace_ok
        && n.connections_ok && n.ports_ok
    }).count();
    let all_ok = state.node_status.values().all(|n| {
        n.pass && n.fw_ok && n.passwd_ok && n.ssh_ok && n.ld_preload_safe
        && n.boot_params_ok && n.dev_inventory_ok && n.mnt_ok && n.cfg_ok
        && n.sys_ok && n.init_ok && n.xdp_attached && !n.sysmon_anomaly
        && !n.sysmon_unloaded && n.fd_ok && n.kern_ok && n.userspace_ok
        && n.connections_ok && n.ports_ok
    }) && total > 0;
    let xv_ok = state.cross_verified;
    let xv_short = if xv_ok { "CONSISTENT" } else { "MISMATCH" };
    let mut nodes: Vec<&NodeStatus> = state.node_status.values().collect();
    nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    let vc = |ok: bool, val: &str| -> String {
        let c = if ok { "cp" } else { "cf" };
        format!("<td class=\"{}\">{}</td>", c, val)
    };
    let vc_gs = |ok: bool, val: &str| -> String {
        let c = if ok { "cp" } else { "cf" };
        format!("<td class=\"{} gs\">{}</td>", c, val)
    };
    /// Primary Grid
    let mut primary_rows = String::new();
    for n in &nodes {
        let rc = if n.pass { "rp" } else { "rf" };
        let age = now.saturating_sub(n.last_seen);
        let pcr = vc_gs(n.pcr_match, if n.pcr_match { "8/8" } else { "FAIL" });
        let ak = vc(n.ak_match, if n.ak_match { "280B" } else { "MISS" });
        let sig = vc(n.sig_valid, if n.sig_valid { "262B" } else { "INV" });
        let ima_val = if !n.ima_valid {
            if let Some(pos) = n.raw_details.find("IMA SPIKE:") {
                let rest = &n.raw_details[pos + 11..];
                let end = rest.find(';').unwrap_or(rest.len());
                format!("SPIKE {}", &rest[..end].trim())
            } else if n.raw_details.contains("IMA TAMPER") {
                format!("{} TAMPER", n.ima_count)
            } else if n.raw_details.contains("IMA LOW") {
                format!("{} LOW", n.ima_count)
            } else {
                format!("{}{}", n.ima_count,
                    n.ima_delta.map(|d| format!(" d{:+}", d)).unwrap_or_default())
            }
        } else {
            format!("{}{}", n.ima_count,
                n.ima_delta.map(|d| format!(" d{:+}", d)).unwrap_or_default())
        };
        let ima = vc_gs(n.ima_valid, &ima_val);
        let ima = vc_gs(n.ima_valid, &ima_val);
        let agg = n.ima_aggregate_hash.as_ref()
            .map(|h| if h.len() >= 8 { &h[..8] } else { h.as_str() })
            .unwrap_or("--");
        let agg_td = vc(n.ima_valid, agg);
        let bin = vc(n.bin_ok, if n.bin_ok { "OK" } else { "TAMPER" });
        let sysm_ok = n.sysmon_active && !n.sysmon_anomaly && !n.sysmon_unloaded;
        let sysm_val = if n.sysmon_unloaded { "UNLOAD".into() }
            else if n.sysmon_anomaly { "ANOMALY".into() }
            else { format!("{}h", n.sysmon_hooks.unwrap_or(0)) };
        let sysm = vc_gs(sysm_ok, &sysm_val);
        let fd = vc(n.fd_ok, &format!("{}", n.fd_count));
        let kern_short = n.kern_details.as_deref().unwrap_or("--")
            .replace("KERN:OK(", "").replace("KERN:", "").trim_end_matches(')').to_string();
        let kern = vc(n.kern_ok, &kern_short);
        let xdp = vc(n.xdp_attached, if n.xdp_attached { "ACTIVE" } else { "OFF" });
        let fw = vc_gs(n.fw_ok, if n.fw_ok { "OK" } else { "CHANGED" });
        let conn = vc(n.connections_ok, &format!("{}", n.connection_count));
        let ports_val = if n.ports.is_empty() { "--".into() }
            else { n.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",") };
        let ports = vc(n.ports_ok, &ports_val);
        let ent_ok = n.entropy_available.map(|e| e >= 128).unwrap_or(false);
        let ent = vc_gs(ent_ok, &n.entropy_available.map(|e| format!("{}", e)).unwrap_or("--".into()));
        let masq = vc(!n.masquerade_detected, if n.masquerade_detected { "ALERT" } else { "CLEAR" });
        let age_td = if age > 120 { format!("<td class=\"cw\">{}s</td>", age) }
            else { format!("<td class=\"cn\">{}s</td>", age) };

        primary_rows.push_str(&format!(
            "<tr class=\"{rc}\"><td class=\"nn\"><a href=\"/node/{id}\">{id}</a></td>\
            {pcr}{ak}{sig}{ima}{agg}{bin}{sysm}{fd}{kern}{xdp}{fw}{conn}{ports}{ent}{masq}{age}</tr>\n",
            rc=rc, id=n.node_id, pcr=pcr, ak=ak, sig=sig, ima=ima, agg=agg_td, bin=bin,
            sysm=sysm, fd=fd, kern=kern, xdp=xdp, fw=fw, conn=conn, ports=ports, ent=ent, masq=masq, age=age_td,
        ));
    }
    /// Secondary Grid
    let mut secondary_rows = String::new();
    for n in &nodes {
        let rc = if n.pass { "rp" } else { "rf" };
        let v = |ok: bool, val: &str| -> String {
            format!("<td class=\"{}\">{}</td>", if ok { "cp" } else { "cf" }, val)
        };
        secondary_rows.push_str(&format!(
            "<tr class=\"{rc}\"><td class=\"nn\"><a href=\"/node/{id}\">{id}</a></td>\
            {pw}{ssh}{pre}{boot}{dev}{mnt}{cfg}{sys}{init}{mod_}{usr}{kth}{procs}</tr>\n",
            rc=rc, id=n.node_id,
            pw=v(n.passwd_ok, if n.passwd_ok {"OK"} else {"CHANGED"}),
            ssh=v(n.ssh_ok, if n.ssh_ok {"OK"} else {"CHANGED"}),
            pre=v(n.ld_preload_safe, if n.ld_preload_safe {"SAFE"} else {"INJECT"}),
            boot=v(n.boot_params_ok, if n.boot_params_ok {"OK"} else {"CHANGED"}),
            dev=v(n.dev_inventory_ok, if n.dev_inventory_ok {"OK"} else {"CHANGED"}),
            mnt=v(n.mnt_ok, if n.mnt_ok {"OK"} else {"CHANGED"}),
            cfg=v(n.cfg_ok, if n.cfg_ok {"OK"} else {"TAMPER"}),
            sys=v(n.sys_ok, if n.sys_ok {"OK"} else {"CHANGED"}),
            init=v(n.init_ok, &format!("{}/{}", n.init_count, n.init_unused)),
            mod_=v(n.kernel_modules_empty, if n.kernel_modules_empty {"NONE"} else {"LOADED"}),
            usr=v(n.userspace_ok, &format!("{}", n.userspace_count)),
            kth=v(n.kernel_threads_ok, &format!("{}", n.kernel_thread_count)),
            procs=format!("<td class=\"cn\">{}</td>", n.process_count.map(|c| format!("{}", c)).unwrap_or("--".into())),
        ));
    }
    let circuit_proof = render_circuit_proof(&state);
    let xdp_summary = render_xdp_summary(&nodes);
    /// Source Rows
    let mut source_rows = String::new();
    for (id, src) in &state.sources {
        let cc = if src.connected { "cp" } else { "cf" };
        let ct = if src.connected { "ONLINE" } else { "OFFLINE" };
        let hc = if src.chain_intact { "cp" } else { "cf" };
        let ht = if src.chain_intact { "INTACT" } else { "BROKEN" };
        let age = now.saturating_sub(src.last_timestamp);
        let hash_short = if src.prev_hash.len() >= 16 { &src.prev_hash[..16] } else { &src.prev_hash };
        source_rows.push_str(&format!(
            "<tr><td>{}</td><td class=\"{}\">{}</td><td>#{}</td><td>{}</td><td class=\"{}\">{}</td><td>{}</td><td>{}s</td><td class=\"hash\">{}..</td></tr>\n",
            id, cc, ct, src.last_heartbeat, src.last_seq, hc, ht, src.entries_received, age, hash_short,
        ));
    }
    /// Heartbeat Rows
    let mut hb_rows = String::new();
    let mut hb_shown = 0;
    for e in state.recent_entries.iter().rev() {
        if hb_shown >= 20 { break; }
        let hc = if e.authorized { "hp" } else { "hf" };
        let st = if e.authorized { "<td class=\"cp\">PASS</td>" } else { "<td class=\"cf\">FAIL</td>" };
        let age = now.saturating_sub(e.timestamp);
        let ms = e.verification_ms.map(|m| format!("{}ms", m)).unwrap_or("--".into());
        let tier_html = match e.tier.as_str() {
            "Critical" => "<span class=\"tier tc\">CRITICAL</span>".to_string(),
            "Warning" => "<span class=\"tier tw\">WARNING</span>".to_string(),
            _ => String::new(),
        };
        let mut flags = Vec::new();
        if e.has_checkpoint { flags.push("TPM-SIGNED"); }
        if e.has_forensic { flags.push("FORENSIC"); }
        let flink = if e.has_forensic { format!(" <a href=\"/forensics/{}\">view</a>", e.seq) } else { String::new() };
        hb_rows.push_str(&format!(
            "<tr class=\"{hc}\">{st}<td>{src}</td><td>#{hb}</td><td>{nc}</td><td>{tier}</td><td>{ms}</td><td>{age}s</td><td>{flags}{flink}</td></tr>\n",
            hc=hc, st=st, src=e.source, hb=e.heartbeat, nc=e.node_count,
            tier=tier_html, ms=ms, age=age, flags=flags.join(" "), flink=flink,
        ));
        hb_shown += 1;
    }
    /// Alerts Rows 
    let mut alert_rows = String::new();
    for a in state.alerts.iter().rev().take(15) {
        let age = now.saturating_sub(a.timestamp);
        let ac = match a.severity.as_str() { "CRITICAL"|"Critical" => "ac", "WARNING"|"Warning" => "aw", _ => "" };
        let link = a.seq.map(|s| format!("<a href=\"/forensics/{}\">detail</a>", s)).unwrap_or_default();
        alert_rows.push_str(&format!(
            "<tr class=\"{ac}\"><td>{age}s</td><td>{sev}</td><td>{msg}</td><td>{lk}</td></tr>\n",
            ac=ac, age=age, sev=a.severity, msg=html_escape(&a.message), lk=link,
        ));
    }
    let session_count = mfa_monitor::session_tracker::SessionTracker::load_index()
        .map(|i| i.sessions.len()).unwrap_or(0);
    /// Chain Topology: build per-node status for the diagram 
    let node_st = |id: &str| -> (&str, &str) {
        state.node_status.get(id)
            .map(|n| {
                let fully_ok = n.pass && n.fw_ok && n.passwd_ok && n.ssh_ok 
                    && n.ld_preload_safe && n.boot_params_ok && n.dev_inventory_ok
                    && n.mnt_ok && n.cfg_ok && n.sys_ok && n.init_ok
                    && n.xdp_attached && !n.sysmon_anomaly && !n.sysmon_unloaded
                    && n.fd_ok && n.kern_ok && n.userspace_ok && n.connections_ok
                    && n.ports_ok;
                if fully_ok { ("rgb(61,220,132)", "PASS") } else { ("rgb(244,67,54)", "FAIL") }
            })
            .unwrap_or(("rgb(102,102,102)", "--"))
    };
    let sysmon_panel = render_sysmon_panel(&nodes);
    let anomaly_panel = render_anomaly_panel(&nodes);
    let hash_chain_detail = {
        let mut vm2_entries: Vec<&mfa_agent::audit::AuditEntryV2> = Vec::new();
        let mut vm3_entries: Vec<&mfa_agent::audit::AuditEntryV2> = Vec::new();
        for e in state.full_entries.iter().rev().take(12) {
            if e.node_id == "vm2" && vm2_entries.len() < 6 { vm2_entries.push(e); }
            else if e.node_id == "vm3" && vm3_entries.len() < 6 { vm3_entries.push(e); }
        }
        vm2_entries.reverse();
        vm3_entries.reverse();

        let render_mini = |entries: &[&mfa_agent::audit::AuditEntryV2], color: &str| -> String {
            let mut h = String::new();
            for (i, e) in entries.iter().enumerate() {
                let prev = if e.prev_hash.len() >= 12 { &e.prev_hash[..12] } else { &e.prev_hash };
                let tpm = if e.tpm_checkpoint.is_some() {
                    format!(" <span style=\"color:{};font-size:7px;\">TPM-SIGNED</span>", color)
                } else { String::new() };
                if i > 0 { h.push_str("<span style=\"color:#555;font-size:7px;\"> SHA256 &darr; </span>"); }
                h.push_str(&format!(
                    "<div style=\"padding:2px 4px;margin:1px 0;background:#111;border-left:2px solid {};font-size:9px;\">\
                    <span style=\"color:#999;\">#{}</span> \
                    <span style=\"color:{}\">{}</span> \
                    <span class=\"hash\">{}..</span>{}</div>",
                    color, e.seq, color, e.event, prev, tpm,
                ));
            }
            if h.is_empty() { "<span style=\"color:#555\">No entries</span>".into() } else { h }
        };

        let vm2_html = render_mini(&vm2_entries, "rgb(61,220,132)");
        let vm3_html = render_mini(&vm3_entries, "rgb(255,152,0)");

        format!(r#"<details><summary style="padding:4px 8px;font-size:10px;">Hash chain entries (last 6 per source)</summary>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:6px 8px;">
        <div><div style="font-size:9px;color:rgb(61,220,132);font-weight:600;margin-bottom:3px;">VM2 chain</div>{}</div>
        <div><div style="font-size:9px;color:rgb(255,152,0);font-weight:600;margin-bottom:3px;">VM3 chain</div>{}</div>
        </div></details>"#, vm2_html, vm3_html)
    };
    
// <meta http-equiv="refresh" content="20">
    /// Assemble 
    format!(r#"<!DOCTYPE html>
<html><head>
<title>MFA Zero-Trust Attestation Monitor</title>
<style>{styles}</style>
</head><body>

<div class="header">
    <h1>MFA Zero-Trust Attestation Monitor</h1>
    <div class="hstats">
        <span>Nodes: <span class="{nc}">{passing}/{total}</span></span>
        <span>Heartbeats: <span class="v">{entries}</span></span>
        <span>Verify: <span class="v">{avg_ms}ms</span></span>
        <span>Chain breaks: <span class="{bc}">{breaks}</span></span>
        <span>Cross-verify: <span class="{xvc}">{xvs}</span></span>
        <span><a href="/sessions">{sessions} sessions</a></span>
    </div>
</div>

{nav}

<div class="banner {bnc}">{bnt}</div>

<!-- ═══════════════════ CHAIN TOPOLOGY ═══════════════════ -->
<div class="pnl">
    <div class="pnl-h"><span>Attestation Chain Topology</span><span class="ct">Dual-authority onion-routed verification architecture</span></div>
    <div class="pnl-b">

    <svg viewBox="0 0 800 310" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:800px;height:auto;display:block;margin:0 auto;">
        <rect width="800" height="310" fill="rgb(12,12,12)" rx="4"/>

        <!-- Row 1: Operators -->
        <rect x="30" y="20" width="90" height="36" rx="3" fill="rgb(26,26,42)" stroke="rgb(74,158,255)" stroke-width="1.5"/>
        <text x="75" y="35" fill="rgb(74,158,255)" font-size="9" font-family="monospace" text-anchor="middle">Operator A</text>
        <text x="75" y="48" fill="rgb(153,153,153)" font-size="8" font-family="monospace" text-anchor="middle">vm0 (orchestrator)</text>

        <rect x="680" y="20" width="90" height="36" rx="3" fill="rgb(26,26,42)" stroke="rgb(74,158,255)" stroke-width="1.5"/>
        <text x="725" y="35" fill="rgb(74,158,255)" font-size="9" font-family="monospace" text-anchor="middle">Operator B</text>
        <text x="725" y="48" fill="rgb(153,153,153)" font-size="8" font-family="monospace" text-anchor="middle">vm4 (dual auth)</text>

        <!-- vm0-vm4 mutual attestation -->
        <line x1="120" y1="38" x2="680" y2="38" stroke="rgb(74,158,255)" stroke-width="1" stroke-dasharray="5,3"/>
        <text x="400" y="32" fill="rgb(74,158,255)" font-size="7" font-family="monospace" text-anchor="middle">1. Mutual TPM attestation (direct, pre-chain)</text>

        <!-- Row 2: vm2 center, vm5 center-right -->
        <rect x="340" y="85" width="80" height="36" rx="3" fill="rgb(17,17,17)" stroke="{vm2_c}" stroke-width="1.5"/>
        <text x="380" y="100" fill="{vm2_c}" font-size="9" font-family="monospace" text-anchor="middle">vm2 (ZTS)</text>
        <text x="380" y="112" fill="rgb(102,102,102)" font-size="7" font-family="monospace" text-anchor="middle">Chain 1 Verifier</text>

        <rect x="540" y="85" width="80" height="36" rx="3" fill="rgb(17,17,17)" stroke="rgb(74,158,255)" stroke-width="1"/>
        <text x="580" y="100" fill="rgb(74,158,255)" font-size="9" font-family="monospace" text-anchor="middle">vm5 (monitor)</text>
        <text x="580" y="112" fill="rgb(102,102,102)" font-size="7" font-family="monospace" text-anchor="middle">this dashboard</text>

        <!-- Row 3: Chain 1 left, Chain 2 right -->
        <!-- Chain 1: vm1 -> pr1 -> pr2 -> pr3 -> (up to vm2) -->
        <text x="30" y="155" fill="rgb(61,220,132)" font-size="8" font-family="monospace">CHAIN 1</text>

        <rect x="30" y="162" width="60" height="30" rx="2" fill="rgb(17,17,17)" stroke="{vm1_c}" stroke-width="1.5"/>
        <text x="60" y="181" fill="{vm1_c}" font-size="9" font-family="monospace" text-anchor="middle">vm1</text>

        <line x1="90" y1="177" x2="108" y2="177" stroke="rgb(85,85,85)" stroke-width="1" marker-end="url(#arr)"/>
        <text x="99" y="170" fill="rgb(102,102,102)" font-size="6" font-family="monospace" text-anchor="middle">L1</text>

        <rect x="110" y="162" width="50" height="30" rx="2" fill="rgb(17,17,17)" stroke="{pr1_c}" stroke-width="1"/>
        <text x="135" y="181" fill="{pr1_c}" font-size="9" font-family="monospace" text-anchor="middle">pr1</text>

        <line x1="160" y1="177" x2="178" y2="177" stroke="rgb(85,85,85)" stroke-width="1"/>
        <text x="169" y="170" fill="rgb(102,102,102)" font-size="6" font-family="monospace" text-anchor="middle">L2</text>

        <rect x="180" y="162" width="50" height="30" rx="2" fill="rgb(17,17,17)" stroke="{pr2_c}" stroke-width="1"/>
        <text x="205" y="181" fill="{pr2_c}" font-size="9" font-family="monospace" text-anchor="middle">pr2</text>

        <line x1="230" y1="177" x2="248" y2="177" stroke="rgb(85,85,85)" stroke-width="1"/>
        <text x="239" y="170" fill="rgb(102,102,102)" font-size="6" font-family="monospace" text-anchor="middle">L3</text>

        <rect x="250" y="162" width="50" height="30" rx="2" fill="rgb(17,17,17)" stroke="{pr3_c}" stroke-width="1"/>
        <text x="275" y="181" fill="{pr3_c}" font-size="9" font-family="monospace" text-anchor="middle">pr3</text>

        <line x1="300" y1="177" x2="340" y2="121" stroke="rgb(61,220,132)" stroke-width="1" marker-end="url(#arr)"/>
        <text x="310" y="145" fill="rgb(61,220,132)" font-size="6" font-family="monospace">L4</text>

        <!-- Chain 2: (down from vm2) -> pr4 -> pr5 -> pr6 -> vm3 -->
        <text x="430" y="155" fill="rgb(255,152,0)" font-size="8" font-family="monospace">CHAIN 2</text>

        <line x1="420" y1="121" x2="460" y2="162" stroke="rgb(255,152,0)" stroke-width="1" marker-end="url(#arr)"/>
        <text x="448" y="145" fill="rgb(255,152,0)" font-size="6" font-family="monospace">L1</text>

        <rect x="460" y="162" width="50" height="30" rx="2" fill="rgb(17,17,17)" stroke="{pr4_c}" stroke-width="1"/>
        <text x="485" y="181" fill="{pr4_c}" font-size="9" font-family="monospace" text-anchor="middle">pr4</text>

        <line x1="510" y1="177" x2="528" y2="177" stroke="rgb(85,85,85)" stroke-width="1"/>
        <text x="519" y="170" fill="rgb(102,102,102)" font-size="6" font-family="monospace" text-anchor="middle">L2</text>

        <rect x="530" y="162" width="50" height="30" rx="2" fill="rgb(17,17,17)" stroke="{pr5_c}" stroke-width="1"/>
        <text x="555" y="181" fill="{pr5_c}" font-size="9" font-family="monospace" text-anchor="middle">pr5</text>

        <line x1="580" y1="177" x2="598" y2="177" stroke="rgb(85,85,85)" stroke-width="1"/>
        <text x="589" y="170" fill="rgb(102,102,102)" font-size="6" font-family="monospace" text-anchor="middle">L3</text>

        <rect x="600" y="162" width="50" height="30" rx="2" fill="rgb(17,17,17)" stroke="{pr6_c}" stroke-width="1"/>
        <text x="625" y="181" fill="{pr6_c}" font-size="9" font-family="monospace" text-anchor="middle">pr6</text>

        <line x1="650" y1="177" x2="698" y2="177" stroke="rgb(85,85,85)" stroke-width="1" marker-end="url(#arr)"/>
        <text x="674" y="170" fill="rgb(102,102,102)" font-size="6" font-family="monospace" text-anchor="middle">L4</text>

        <rect x="700" y="162" width="70" height="30" rx="2" fill="rgb(17,17,17)" stroke="{vm3_c}" stroke-width="1.5"/>
        <text x="735" y="177" fill="{vm3_c}" font-size="8" font-family="monospace" text-anchor="middle">vm3 (DA)</text>
        <text x="735" y="187" fill="rgb(102,102,102)" font-size="6" font-family="monospace" text-anchor="middle">Chain 2 Verifier</text>

        <!-- vm0 -> vm1 INITIATE -->
        <line x1="75" y1="56" x2="60" y2="162" stroke="rgb(74,158,255)" stroke-width="1" marker-end="url(#arr)"/>
        <text x="50" y="110" fill="rgb(74,158,255)" font-size="7" font-family="monospace">2. INITIATE</text>

        <!-- vm3 -> vm4 quorum -->
        <line x1="735" y1="162" x2="725" y2="56" stroke="rgb(255,152,0)" stroke-width="1" stroke-dasharray="3,2" marker-end="url(#arr)"/>
        <text x="745" y="110" fill="rgb(255,152,0)" font-size="7" font-family="monospace">6. Quorum</text>

        <!-- vm2 -> vm5 logfwd -->
        <line x1="420" y1="103" x2="540" y2="103" stroke="rgb(85,85,85)" stroke-width="1" stroke-dasharray="2,2"/>
        <text x="480" y="98" fill="rgb(85,85,85)" font-size="6" font-family="monospace" text-anchor="middle">logfwd</text>

        <!-- vm3 -> vm5 logfwd -->
        <line x1="700" y1="185" x2="620" y2="112" stroke="rgb(85,85,85)" stroke-width="1" stroke-dasharray="2,2"/>
        <text x="665" y="140" fill="rgb(85,85,85)" font-size="6" font-family="monospace">logfwd</text>

        <!-- Defense layer bar -->

        <!-- Arrow marker -->
        <defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="rgb(85,85,85)"/></marker></defs>

        <!-- Flow numbers -->
    </svg>

    </div>
</div>

<!-- ═══════════════════ ONION ENCRYPTION PROOF ═══════════════════ -->
<div class="pnl">
    <div class="pnl-h"><span>Telescoping Onion Circuit — Encryption Layers</span><span class="ct">ML-KEM-1024 + X25519 + AES-256-GCM per hop</span></div>
    <div class="pnl-b">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">

    <div>
        <div style="font-size:10px;color:rgb(61,220,132);font-weight:600;margin-bottom:6px;">Chain 1: vm1 → vm2 (4 onion layers)</div>
        <div style="font-size:9px;color:rgb(153,153,153);line-height:1.8;">
            <div style="padding:3px 6px;margin:2px 0;background:rgb(10,26,10);border-left:2px solid rgb(61,220,132);">
                <b>vm1 → pr1:</b> E<sub>k1</sub>(payload) — 1 layer AES-256-GCM<br>
                <span style="color:rgb(102,102,102);">Key: HKDF-SHA256(ML-KEM-1024 || X25519, transcript)</span>
            </div>
            <div style="padding:3px 6px;margin:2px 0;background:rgb(10,26,10);border-left:2px solid rgb(61,220,132);">
                <b>vm1 → pr2:</b> E<sub>k1</sub>(E<sub>k2</sub>(payload)) — 2 layers<br>
                <span style="color:rgb(102,102,102);">pr1 strips layer 1, forwards E<sub>k2</sub>(payload)</span>
            </div>
            <div style="padding:3px 6px;margin:2px 0;background:rgb(10,26,10);border-left:2px solid rgb(61,220,132);">
                <b>vm1 → pr3:</b> E<sub>k1</sub>(E<sub>k2</sub>(E<sub>k3</sub>(payload))) — 3 layers<br>
                <span style="color:rgb(102,102,102);">Each relay only knows prev/next hop, not origin/destination</span>
            </div>
            <div style="padding:3px 6px;margin:2px 0;background:rgb(10,26,10);border-left:2px solid rgb(61,220,132);">
                <b>vm1 → vm2:</b> E<sub>k1</sub>(E<sub>k2</sub>(E<sub>k3</sub>(E<sub>k4</sub>(payload)))) — 4 layers<br>
                <span style="color:rgb(102,102,102);">vm2 decrypts final layer, receives plaintext attestation data</span>
            </div>
        </div>
    </div>

    <div>
        <div style="font-size:10px;color:rgb(255,152,0);font-weight:600;margin-bottom:6px;">Chain 2: vm2 → vm3 (4 onion layers)</div>
        <div style="font-size:9px;color:rgb(153,153,153);line-height:1.8;">
            <div style="padding:3px 6px;margin:2px 0;background:rgb(26,20,8);border-left:2px solid rgb(255,152,0);">
                <b>vm2 → pr4:</b> E<sub>k5</sub>(payload) — 1 layer AES-256-GCM<br>
                <span style="color:rgb(102,102,102);">Independent key exchange from chain 1</span>
            </div>
            <div style="padding:3px 6px;margin:2px 0;background:rgb(26,20,8);border-left:2px solid rgb(255,152,0);">
                <b>vm2 → pr5:</b> E<sub>k5</sub>(E<sub>k6</sub>(payload)) — 2 layers
            </div>
            <div style="padding:3px 6px;margin:2px 0;background:rgb(26,20,8);border-left:2px solid rgb(255,152,0);">
                <b>vm2 → pr6:</b> E<sub>k5</sub>(E<sub>k6</sub>(E<sub>k7</sub>(payload))) — 3 layers
            </div>
            <div style="padding:3px 6px;margin:2px 0;background:rgb(26,20,8);border-left:2px solid rgb(255,152,0);">
                <b>vm2 → vm3:</b> E<sub>k5</sub>(E<sub>k6</sub>(E<sub>k7</sub>(E<sub>k8</sub>(payload)))) — 4 layers<br>
                <span style="color:rgb(102,102,102);">vm3 receives chain 1 results + chain 2 attestations</span>
            </div>
        </div>
    </div>

    </div>

    </div>
</div>

{circuit_proof}

<!-- ═══════════════════ PRIMARY GRID ═══════════════════ -->
<div class="pnl">
    <div class="pnl-h"><span>Primary Security Checks</span><span class="ct">{passing}/{total} nodes &middot; 16 critical checks</span></div>
    <div class="grid-scroll">
    <table>
    <tr>
        <th></th>
        <th class="gh gs" colspan="3">TPM Identity<span class="gd">Hardware root of trust (TPM 2.0)</span></th>
        <th class="gh gs" colspan="3">Code Integrity<span class="gd">IMA kernel measurement + binary hashes</span></th>
        <th class="gh gs" colspan="4">eBPF Runtime<span class="gd">Kernel-level syscall, FD, integrity monitoring</span></th>
        <th class="gh gs" colspan="3">Network<span class="gd">Firewall, connections, port enforcement</span></th>
        <th class="gh gs" colspan="2">Health<span class="gd">Entropy and masquerade detection</span></th>
        <th></th>
    </tr>
    <tr>
        <th>Node</th>
        <th class="gs">PCR</th><th>AK</th><th>SIG</th>
        <th class="gs">IMA</th><th>AGG</th><th>BIN</th>
        <th class="gs">SYSM</th><th>FD</th><th>KERN</th><th>XDP</th>
        <th class="gs">FW</th><th>CONN</th><th>PORTS</th>
        <th class="gs">ENT</th><th>MASQ</th>
        <th>AGE</th>
    </tr>
    {primary_rows}
    </table>
    </div>

</div>
{anomaly_panel}
<!-- ═══════════════════ SECONDARY GRID ═══════════════════ -->
<details>
<summary style="cursor:pointer;color:#4a9eff;padding:6px;font-size:11px;">Filesystem, Configuration &amp; System Integrity ({total} nodes, 13 extended checks)</summary>
<div class="pnl" style="margin-top:4px;">
    <table>
    <tr>
        <th>Node</th>
        <th>PW</th><th>SSH</th><th>PRE</th><th>BOOT</th><th>DEV</th>
        <th>MNT</th><th>CFG</th><th>SYS</th>
        <th>INIT</th>
        <th>MOD</th><th>USR</th><th>KTH</th><th>PROCS</th>
    </tr>
    {secondary_rows}
    </table>

</div>
</details>
{sysmon_panel}
<!-- ═══════════════════ XDP TRAFFIC ═══════════════════ -->
{xdp_summary}

<!-- ═══════════════════ SOURCES + ALERTS ═══════════════════ -->
<div class="g2">
    <div class="pnl">
        <div class="pnl-h"><span>Log Sources &amp; Hash Chain</span><span class="ct">{src_count} sources</span></div>
        <table>
        <tr><th>Source</th><th>Status</th><th>HB</th><th>Seq</th><th>Chain</th><th>Entries</th><th>Age</th><th>Chain Head</th></tr>
        {source_rows}
        </table>
        {hash_chain_detail}
    </div>
    <div class="pnl">
        <div class="pnl-h"><span>Alerts</span><span class="ct">{alert_count}</span></div>
        <table>
        <tr><th>Age</th><th>Level</th><th>Message</th><th></th></tr>
        {alert_rows}
        {no_alerts}
        </table>
    </div>
</div>

<!-- ═══════════════════ HEARTBEAT TIMELINE ═══════════════════ -->
<div class="pnl">
    <div class="pnl-h"><span>Heartbeat Timeline</span><span class="ct">Last 20</span></div>
    <table>
    <tr><th>Status</th><th>Source</th><th>HB</th><th>Nodes</th><th>Tier</th><th>Verify</th><th>Age</th><th>Flags</th></tr>
    {hb_rows}
    </table>
</div>

<!-- ═══════════════════ REFERENCE ═══════════════════ -->
<div class="pnl">
    <div class="pnl-h"><span>System Architecture Reference</span></div>
    <div class="pnl-b">
        <div class="ldesc" style="background:transparent;">
            
            <b>Pages:</b>
            <a href="/">Overview</a> &middot;
            <a href="/sessions">Sessions</a> ({sessions} completed) &middot;
            <a href="/forensics">Forensics</a> &middot;
            Node detail: click any node name
            <br><br>
            <b>API:</b>
            <a href="/api/state">/api/state</a> &middot;
            <a href="/api/nodes">/api/nodes</a> &middot;
            <a href="/api/latest">/api/latest</a> &middot;
            <a href="/api/sessions">/api/sessions</a> &middot;
            <a href="/api/forensics">/api/forensics</a>
        </div>
    </div>
</div>

</body></html>"#,
        styles = COMMON_STYLES,
        nav = nav_bar(),
        nc = if all_ok { "ok" } else { "fl" },
        passing = passing, total = total,
        entries = state.total_entries_received,
        avg_ms = state.avg_verification_ms,
        bc = if state.total_chain_breaks == 0 { "ok" } else { "fl" },
        breaks = state.total_chain_breaks,
        xvc = if xv_ok { "sg" } else { "sr" },
        xvs = xv_short,
        sessions = session_count,
        bnc = if all_ok { "ok" } else { "fl" },
        bnt = if all_ok {
            format!("ALL SYSTEMS NOMINAL -- {} nodes verified across dual independent verification chains", total)
        } else {
            format!("INTEGRITY ALERT -- {}/{} nodes passing", passing, total)
        },
        primary_rows = primary_rows,
        secondary_rows = secondary_rows,
        xdp_summary = xdp_summary,
        src_count = state.sources.len(),
        source_rows = source_rows,
        alert_count = state.alerts.len(),
        alert_rows = alert_rows,
        no_alerts = if state.alerts.is_empty() { "<tr><td colspan=\"4\" style=\"color:#555\">No alerts</td></tr>" } else { "" },
        hb_rows = hb_rows,
        /// Topology node colors
        vm1_c = node_st("vm1").0, pr1_c = node_st("pr1").0, pr2_c = node_st("pr2").0,
        pr3_c = node_st("pr3").0, vm2_c = node_st("vm2").0, pr4_c = node_st("pr4").0,
        pr5_c = node_st("pr5").0, pr6_c = node_st("pr6").0, vm3_c = node_st("vm3").0,
        sysmon_panel = sysmon_panel,
        anomaly_panel = anomaly_panel,
        hash_chain_detail = hash_chain_detail,
        circuit_proof = circuit_proof,
    )
}

fn render_anomaly_panel(nodes: &[&NodeStatus]) -> String {
    let failing: Vec<&&NodeStatus> = nodes.iter()
        .filter(|n| {
            !n.pass || !n.fw_ok || !n.passwd_ok || !n.ssh_ok
            || !n.ld_preload_safe || !n.boot_params_ok || !n.dev_inventory_ok
            || !n.mnt_ok || !n.cfg_ok || !n.sys_ok || !n.init_ok
            || !n.xdp_attached || n.sysmon_anomaly || n.sysmon_unloaded
            || !n.fd_ok || !n.kern_ok || !n.userspace_ok || !n.connections_ok
            || !n.ports_ok
        })
        .collect();
    if failing.is_empty() {
        return String::new();
    }
    let mut rows = String::new();
    for n in &failing {
        let mut anomalies = Vec::new();
        /// PCR
        if !n.pcr_match {
            let detail = n.pcr_mismatch_indices.as_ref()
                .map(|idx| format!("PCR mismatch on registers: {:?}", idx))
                .unwrap_or_else(|| "PCR mismatch (registers unknown)".into());
            anomalies.push(("PCR", "CRITICAL", detail));
        }
        /// IMA
        if !n.ima_valid {
            let detail = if n.ima_count == 0 {
                "IMA count below floor (< 200): possible reboot or measurement bypass".into()
            } else {
                n.ima_delta.map(|d| {
                    if d < 0 { format!("IMA TAMPER: count decreased by {} (append-only violation)", d.abs()) }
                    else if d > 20 { format!("IMA SPIKE: {} new measurements in one heartbeat (unusual file access)", d) }
                    else { format!("IMA anomaly: delta={}", d) }
                }).unwrap_or_else(|| "IMA validation failed".into())
            };
            anomalies.push(("IMA", "CRITICAL", detail));
        }
        /// Userspace
        if !n.userspace_ok {
            let detail = match &n.raw_details.find("USERSPACE CHANGED:") {
                Some(pos) => {
                    let rest = &n.raw_details[*pos..];
                    let end = rest.find(';').unwrap_or(rest.len());
                    rest[..end].to_string()
                }
                None => "Userspace process manifest changed".into(),
            };
            anomalies.push(("USR", "CRITICAL", detail));
        }
        /// Connections
        if !n.connections_ok {
            let detail = match &n.raw_details.find("CONN CHANGED:") {
                Some(pos) => {
                    let rest = &n.raw_details[*pos..];
                    let end = rest.find(';').unwrap_or(rest.len());
                    rest[..end].to_string()
                }
                None => "Connection tuple set changed".into(),
            };
            anomalies.push(("CONN", "CRITICAL", detail));
        }
        /// Ports
        if !n.ports_ok {
            let detail = match &n.raw_details.find("PORTS CHANGED:") {
                Some(pos) => {
                    let rest = &n.raw_details[*pos..];
                    let end = rest.find(';').unwrap_or(rest.len());
                    rest[..end].to_string()
                }
                None => format!("Listening ports changed: {:?}", n.ports),
            };
            anomalies.push(("PORTS", "CRITICAL", detail));
        }
        /// XDP
        if !n.xdp_attached {
            anomalies.push(("XDP", "CRITICAL", 
                "XDP entropy filter DETACHED: Layer 1 defense disabled. Encrypted traffic enforcement inactive. Node accepting unverified packets.".into()));
        }
        /// Sysmon
        if n.sysmon_anomaly {
            let detail = format!(
                "execve:+{} ptrace:+{} mount:+{} connect:+{} socket:+{}",
                n.sysmon_exec_delta.unwrap_or(0),
                n.sysmon_ptrace_delta.unwrap_or(0),
                n.sysmon_mount_delta.unwrap_or(0),
                n.sysmon_conn_delta.unwrap_or(0),
                n.sysmon_sock_delta.unwrap_or(0),
            );
            anomalies.push(("SYSM", "CRITICAL", detail));
        }
        if n.sysmon_unloaded {
            anomalies.push(("SYSM", "CRITICAL", 
                "Sysmon BPF hooks UNLOADED — runtime behavioral monitoring disabled. Syscall tracking inactive.".into()));
        }
        /// FD
        if !n.fd_ok {
            let detail = match &n.raw_details.find("FD:ANOMALY(") {
                Some(pos) => {
                    let rest = &n.raw_details[*pos..];
                    let end = rest.find(';').unwrap_or(rest.len());
                    rest[..end].to_string()
                }
                None => format!("File descriptor anomaly ({} open FDs)", n.fd_count),
            };
            anomalies.push(("FD", "CRITICAL", detail));
        }
 
        /// Kernel integrity
        if !n.kern_ok {
            let detail = n.kern_details.as_deref().unwrap_or("Kernel integrity anomaly");
            anomalies.push(("KERN", "CRITICAL", detail.to_string()));
        }
 
        /// Firewall
        if !n.fw_ok {
            anomalies.push(("FW", "CRITICAL", 
                "Firewall rule hash CHANGED — iptables configuration tampered. Potential unauthorized port opening or rule deletion.".into()));
        }
 
        /// Filesystem
        if !n.passwd_ok { anomalies.push(("PW", "CRITICAL", "/etc/passwd CHANGED: Potential unauthorized user account or UID escalation".into())); }
        if !n.ssh_ok { anomalies.push(("SSH", "WARNING", "sshd_config CHANGED: SSH daemon configuration modified".into())); }
        if !n.ld_preload_safe { anomalies.push(("PRE", "CRITICAL", "/etc/ld.so.preload NOT EMPTY: LD_PRELOAD rootkit injection detected".into())); }
        if !n.boot_params_ok { anomalies.push(("BOOT", "CRITICAL", "/proc/cmdline CHANGED: Kernel boot parameters modified".into())); }
        if !n.dev_inventory_ok { anomalies.push(("DEV", "CRITICAL", "/dev inventory CHANGED: New device nodes detected".into())); }
        if !n.mnt_ok { anomalies.push(("MNT", "CRITICAL", "/proc/mounts CHANGED: Filesystem mount table modified".into())); }
        if !n.cfg_ok { anomalies.push(("CFG", "CRITICAL", "Configuration file hashes CHANGED".into())); }
        if !n.sys_ok { anomalies.push(("SYS", "CRITICAL", "sysctl kernel parameters CHANGED: Runtime kernel configuration modified".into())); }
        if !n.init_ok { anomalies.push(("INIT", "CRITICAL", "Init script integrity FAILED: startup scripts tampered or unauthorized service added".into())); }
        if !n.kernel_modules_empty { 
            let mod_detail = n.kernel_modules_loaded.as_ref()
                .map(|m| format!("Kernel modules LOADED: {:?} (CONFIG_MODULES=n should prevent this)", m))
                .unwrap_or_else(|| "Kernel modules detected on CONFIG_MODULES=n system".into());
            anomalies.push(("MOD", "CRITICAL", mod_detail)); 
        }
        if n.masquerade_detected {
            anomalies.push(("MASQ", "CRITICAL", 
                "Process masquerade detected: Userspace process impersonating kernel thread or system service".into()));
        }
 
        /// Signature/AK
        if !n.sig_valid { anomalies.push(("SIG", "CRITICAL", "TPM quote signature INVALID — possible fabricated attestation".into())); }
        if !n.ak_match { anomalies.push(("AK", "CRITICAL", "Attestation Key MISMATCH — different physical TPM responding".into())); }
 
        if anomalies.is_empty() { continue; }
 
        for (check, severity, detail) in &anomalies {
            let sc = match *severity {
                "CRITICAL" => "cf",
                "WARNING" => "cw",
                _ => "cn",
            };
            let tc = match *severity {
                "CRITICAL" => "tc",
                "WARNING" => "tw",
                _ => "ti",
            };
            rows.push_str(&format!(
                "<tr><td class=\"nn\"><a href=\"/node/{}\">{}</a></td>\
                <td class=\"{}\">{}</td>\
                <td><span class=\"tier {}\">{}</span></td>\
                <td style=\"white-space:normal;color:#ccc;\">{}</td></tr>\n",
                n.node_id, n.node_id, sc, check, tc, severity,
                html_escape(detail),
            ));
        }
    }
 
    format!(r#"
<div class="pnl">
    <div class="pnl-h"><span>Integrity Anomalies Detected</span><span class="ct" style="color:rgb(244,67,54);">{} nodes with anomalies</span></div>
    <table>
    <tr><th>Node</th><th>Check</th><th>Severity</th><th>Detail</th></tr>
    {rows}
    </table>

</div>"#,
        failing.len(),
        rows = rows,
    )
}

fn render_sysmon_panel(nodes: &[&NodeStatus]) -> String {
    let mut rows = String::new();
    for n in nodes {
        let sysm_class = if n.sysmon_unloaded { "cf" }
            else if n.sysmon_anomaly { "cf" }
            else if n.sysmon_active { "cp" }
            else { "cn" };
        let status = if n.sysmon_unloaded { "UNLOADED" }
            else if n.sysmon_anomaly { "ANOMALY" }
            else if n.sysmon_active { "OK" }
            else { "--" };

        let exec = n.sysmon_exec_delta.map(|v| format!("{}", v)).unwrap_or("--".into());
        let ptrace = n.sysmon_ptrace_delta.map(|v| format!("{}", v)).unwrap_or("--".into());
        let mount = n.sysmon_mount_delta.map(|v| format!("{}", v)).unwrap_or("--".into());
        let conn = n.sysmon_conn_delta.map(|v| format!("{}", v)).unwrap_or("--".into());
        let sock = n.sysmon_sock_delta.map(|v| format!("{}", v)).unwrap_or("--".into());

        let exec_c = if n.sysmon_exec_delta.unwrap_or(0) > 0 { "cf" } else { "cp" };
        let ptrace_c = if n.sysmon_ptrace_delta.unwrap_or(0) > 0 { "cf" } else { "cp" };
        let mount_c = if n.sysmon_mount_delta.unwrap_or(0) > 0 { "cf" } else { "cp" };
        let conn_c = if n.sysmon_conn_delta.unwrap_or(0) > 0 { "cf" } else { "cp" };
        let sock_c = if n.sysmon_sock_delta.unwrap_or(0) > 0 { "cf" } else { "cp" };

        let hooks = n.sysmon_hooks.map(|h| format!("{}", h)).unwrap_or("--".into());

        rows.push_str(&format!(
            "<tr><td class=\"nn\"><a href=\"/node/{}\">{}</a></td>\
            <td class=\"{}\">{}</td>\
            <td>{}</td>\
            <td class=\"{}\">{}</td>\
            <td class=\"{}\">{}</td>\
            <td class=\"{}\">{}</td>\
            <td class=\"{}\">{}</td>\
            <td class=\"{}\">{}</td>\
            </tr>\n",
            n.node_id, n.node_id,
            sysm_class, status,
            hooks,
            exec_c, exec,
            ptrace_c, ptrace,
            mount_c, mount,
            conn_c, conn,
            sock_c, sock,
        ));
    }

    format!(r#"
<div class="pnl">
    <div class="pnl-h"><span>Syscall Monitor (eBPF Sysmon)</span><span class="ct">6 tracepoint hooks per node &middot; delta tracking between heartbeats</span></div>
    <table>
    <tr><th>Node</th><th>Status</th><th>Hooks</th><th>execve</th><th>ptrace</th><th>mount</th><th>connect</th><th>socket</th></tr>
    {rows}
    </table>

</div>"#,
        rows = rows,
    )
}

// === NODE DETAIL PAGE ===

fn render_node_detail(node: &NodeStatus, baseline: Option<&PcrBaseline>) -> String {
    let status_class = if node.pass { "ok" } else { "fl" };
    let status_text = if node.pass { "PASSING" } else { "FAILING" };
    let baseline_text = if baseline.is_some() { "Available" } else { "Not loaded" };
 
    /// Build verification table — all 28 checks grouped
    let check = |name: &str, ok: bool, detail: &str| -> String {
        let c = if ok { "p" } else { "f" };
        let s = if ok { "PASS" } else { "FAIL" };
        format!("<tr><td>{}</td><td class=\"{}\">{}</td><td>{}</td></tr>\n", name, c, s, detail)
    };
 
    let ima_detail = format!("{} measurements{}", node.ima_count,
        node.ima_delta.map(|d| format!(", delta {:+}", d)).unwrap_or_default());
    let ent_detail = node.entropy_available
        .map(|e| format!("{} bits", e)).unwrap_or_else(|| "--".into());
    let sysm_detail = if node.sysmon_unloaded { "UNLOADED".into() }
        else if node.sysmon_anomaly { "ANOMALY DETECTED".into() }
        else { format!("{} hooks active", node.sysmon_hooks.unwrap_or(0)) };
    let runtime_html = if let Some(meta) = &node.full_meta {
        let procs = meta.userspace_processes.as_ref()
            .map(|p| p.iter().map(|s| format!("<tr><td>{}</td></tr>", html_escape(s))).collect::<Vec<_>>().join("\n"))
            .unwrap_or_else(|| "<tr><td style=\"color:#555\">Not available</td></tr>".into());
        let procs_count = meta.userspace_process_count.unwrap_or(0);

        let threads = meta.kernel_thread_types.as_ref()
            .map(|t| t.iter().map(|s| format!("<span style=\"display:inline-block;padding:1px 4px;margin:1px;background:#1a1a1a;border:1px solid #2a2a2a;font-size:10px;\">{}</span>", html_escape(s))).collect::<Vec<_>>().join(""))
            .unwrap_or_else(|| "<span style=\"color:#555\">Not available</span>".into());
        let threads_count = meta.kernel_thread_type_count.unwrap_or(0);

        let tuples = meta.connection_tuples.as_ref()
            .map(|c| c.iter().map(|s| format!("<tr><td>{}</td></tr>", html_escape(s))).collect::<Vec<_>>().join("\n"))
            .unwrap_or_else(|| "<tr><td style=\"color:#555\">Not available</td></tr>".into());
        let tuples_count = meta.connection_tuple_count.unwrap_or(0);
        let binaries = meta.binary_hashes.as_ref()
            .map(|b| b.iter().map(|s| {
                let parts: Vec<&str> = s.splitn(2, ": ").collect();
                if parts.len() == 2 {
                    format!("<tr><td style=\"color:#999;font-size:9px;\">{}</td><td class=\"hash\">{}</td></tr>", 
                        html_escape(parts[0]), &parts[1][..16.min(parts[1].len())])
                } else {
                    format!("<tr><td>{}</td></tr>", html_escape(s))
                }
            }).collect::<Vec<_>>().join("\n"))
            .unwrap_or_else(|| "<tr><td style=\"color:#555\">Not available</td></tr>".into());
        let bin_count = meta.binary_hashes.as_ref().map(|b| b.len()).unwrap_or(0);

        let init_active = meta.init_active_scripts.as_ref()
            .map(|scripts| scripts.iter()
                .map(|s| format!("<span style=\"display:inline-block;padding:1px 4px;margin:1px;background:#0a1a0a;border:1px solid #1a3a1a;font-size:9px;color:#3ddc84;\">{}</span>", html_escape(s)))
                .collect::<Vec<_>>().join(""))
            .unwrap_or_else(|| "<span style=\"color:#555\">Not available</span>".into());
        let init_active_count = meta.init_active_scripts.as_ref().map(|s| s.len()).unwrap_or(0);

        let init_inactive = meta.init_inactive_scripts.as_ref()
            .map(|scripts| {
                if scripts.is_empty() { "<span style=\"color:#3ddc84;font-size:9px;\">None</span>".into() }
                else { scripts.iter()
                    .map(|s| format!("<span style=\"display:inline-block;padding:1px 4px;margin:1px;background:#1a1408;border:1px solid #4a3a1a;font-size:9px;color:#ff9800;\">{}</span>", html_escape(s)))
                    .collect::<Vec<_>>().join("") }
            })
            .unwrap_or_else(|| "<span style=\"color:#555\">Not available</span>".into());
        let init_inactive_count = meta.init_inactive_scripts.as_ref().map(|s| s.len()).unwrap_or(0);

        let init_hash = meta.init_scripts_hash.as_deref().unwrap_or("--");

        format!(r#"
<div class="pnl">
    <div class="pnl-h"><span>Runtime State</span><span class="ct">Live process manifest, kernel threads, network connections</span></div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;padding:8px;">
    <div>
        <div style="font-size:10px;color:#4a9eff;font-weight:600;margin-bottom:4px;">Userspace Processes ({procs_count})</div>
        <table>{procs}</table>
        
    </div>
    <div>
        <div style="font-size:10px;color:#4a9eff;font-weight:600;margin-bottom:4px;">Kernel Thread Types ({threads_count})</div>
        <div>{threads}</div>

    </div>
    <div>
        <div style="font-size:10px;color:#4a9eff;font-weight:600;margin-bottom:4px;">Connection Tuples ({tuples_count})</div>
        <table>{tuples}</table>

    </div>
    </div>
</div>
<div class="pnl">
    <div class="pnl-h"><span>Binary &amp; Init Integrity</span><span class="ct">File hashes and boot services</span></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;padding:8px;">
    <div>
        <div style="font-size:10px;color:#4a9eff;font-weight:600;margin-bottom:4px;">Binary Integrity ({bin_count} files)</div>
        <table>{binaries}</table>
        <div style="font-size:8px;color:#888;margin-top:4px;">SHA-256 hashes of critical binaries compared against TPM-sealed baseline every heartbeat.</div>
    </div>
    <div>
        <div style="font-size:10px;color:#4a9eff;font-weight:600;margin-bottom:4px;">Init Scripts (active: {init_active_count}, unused: {init_inactive_count})</div>
        <div style="font-size:9px;color:#999;margin-bottom:2px;">Active (boot-enabled):</div>
        <div>{init_active}</div>
        <div style="font-size:9px;color:#999;margin-top:4px;margin-bottom:2px;">Unused (present but not enabled):</div>
        <div>{init_inactive}</div>
        <div style="font-size:8px;color:#888;margin-top:4px;">Covers /etc/init.d/, /etc/runlevels/, /etc/local.d/. Hash: <span class="hash">{init_hash}</span></div>
    </div>
    </div>
</div>"#,
            procs_count = procs_count, procs = procs,
            threads_count = threads_count, threads = threads,
            tuples_count = tuples_count, tuples = tuples,
            binaries = binaries, bin_count = bin_count,
            init_active = init_active, init_active_count = init_active_count,
            init_inactive = init_inactive, init_inactive_count = init_inactive_count,
            init_hash = init_hash,
        )
    } else { String::new() };
    let fd_detail = format!("{} open descriptors", node.fd_count);
    let kern_detail = node.kern_details.as_deref().unwrap_or("--").to_string();
    let init_detail = format!("{} active, {} unused", node.init_count, node.init_unused);
    let ports_detail = if node.ports.is_empty() { "--".into() }
        else { node.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ") };
    let conn_detail = format!("{} tuples", node.connection_count);
    let usr_detail = format!("{} processes", node.userspace_count);
    let kth_detail = format!("{} types", node.kernel_thread_count);
 
    let checks = format!(r#"
    <tr><td colspan="3" style="color:#4a9eff; font-weight:600; padding-top:8px;">IDENTITY</td></tr>
    {pcr}{ak}{sig}{tpm}
    <tr><td colspan="3" style="color:#4a9eff; font-weight:600; padding-top:8px;">CODE INTEGRITY</td></tr>
    {ima}{bin}
    <tr><td colspan="3" style="color:#4a9eff; font-weight:600; padding-top:8px;">RUNTIME BEHAVIOR</td></tr>
    {sysm}{fd}{kern}
    <tr><td colspan="3" style="color:#4a9eff; font-weight:600; padding-top:8px;">NETWORK</td></tr>
    {xdp}{fw}{conn_c}{ports_c}
    <tr><td colspan="3" style="color:#4a9eff; font-weight:600; padding-top:8px;">FILESYSTEM &amp; CONFIG</td></tr>
    {pw}{ssh}{pre}{boot}{dev}{mnt}{cfg}{sys}{init_c}
    <tr><td colspan="3" style="color:#4a9eff; font-weight:600; padding-top:8px;">SYSTEM HEALTH</td></tr>
    {ent_c}{masq}{mod_}{usr}{kth}
"#,
        pcr = check("PCR Match", node.pcr_match, "Platform Configuration Registers 0-7"),
        ak = check("AK Match", node.ak_match, "Attestation Key identity"),
        sig = check("Signature", node.sig_valid, "TPM quote signature verification"),
        tpm = check("TPM Checkpoint", node.tpm_signed.unwrap_or(false), "TPM-signed audit chain"),
        ima = check("IMA", node.ima_valid, &ima_detail),
        bin = check("Binary Hashes", node.bin_ok, "Agent binary integrity"),
        sysm = check("Syscall Monitor", node.sysmon_active && !node.sysmon_anomaly && !node.sysmon_unloaded, &sysm_detail),
        fd = check("File Descriptors", node.fd_ok, &fd_detail),
        kern = check("Kernel Integrity", node.kern_ok, &kern_detail),
        xdp = check("XDP Entropy Filter", node.xdp_attached, "eBPF packet encryption verification"),
        fw = check("Firewall Rules", node.fw_ok, "iptables rule hash"),
        conn_c = check("Connections", node.connections_ok, &conn_detail),
        ports_c = check("Listening Ports", node.ports_ok, &ports_detail),
        pw = check("/etc/passwd", node.passwd_ok, "User account integrity"),
        ssh = check("sshd_config", node.ssh_ok, "SSH daemon configuration"),
        pre = check("ld.so.preload", node.ld_preload_safe, "Library injection detection"),
        boot = check("Boot Parameters", node.boot_params_ok, "/proc/cmdline"),
        dev = check("/dev Inventory", node.dev_inventory_ok, "Device node enumeration"),
        mnt = check("Mounts", node.mnt_ok, "/proc/mounts hash"),
        cfg = check("Config", node.cfg_ok, "Configuration file hashes"),
        sys = check("Sysctl", node.sys_ok, "Kernel parameter hash"),
        init_c = check("Init Scripts", node.init_ok, &init_detail),
        ent_c = check("Entropy Pool", node.entropy_available.map(|e| e >= 128).unwrap_or(false), &ent_detail),
        masq = check("Process Masquerade", !node.masquerade_detected,
            if node.masquerade_detected { "MASQUERADE DETECTED" } else { "No masquerade" }),
        mod_ = check("Kernel Modules", node.kernel_modules_empty, "No loadable modules"),
        usr = check("Userspace Manifest", node.userspace_ok, &usr_detail),
        kth = check("Kernel Threads", node.kernel_threads_ok, &kth_detail),
    );
 
    /// Attestation metadata
    let meta_html = if let Some(meta) = &node.full_meta {
        format!(r#"
<div class="pnl">
    <div class="pnl-h"><span>Attestation Metadata</span></div>
    <table style="padding: 8px;">
    <tr><th>Field</th><th>Value</th></tr>
    <tr><td>TPM Quote</td><td>{} bytes</td></tr>
    <tr><td>TPM Signature</td><td>{} bytes</td></tr>
    <tr><td>AK Public Key</td><td>{} bytes</td></tr>
    <tr><td>PCR Values</td><td>{} registers</td></tr>
    <tr><td>IMA Measurements</td><td>{}</td></tr>
    <tr><td>IMA Aggregate Hash</td><td class="hash">{}</td></tr>
    <tr><td>IMA PCR10</td><td class="hash">{}</td></tr>
    <tr><td>Userspace Processes</td><td>{}</td></tr>
    <tr><td>Kernel Thread Types</td><td>{}</td></tr>
    <tr><td>Kernel Modules</td><td>{}</td></tr>
    <tr><td>Network Connections</td><td>{}</td></tr>
    <tr><td>Connection Tuples</td><td>{}</td></tr>
    <tr><td>XDP Attached</td><td>{}</td></tr>
    <tr><td>Entropy Available</td><td>{}</td></tr>
    </table>
</div>"#,
            meta.tpm_quote_bytes,
            meta.tpm_signature_bytes,
            meta.ak_public_bytes,
            meta.pcr_count,
            meta.ima_count,
            meta.ima_aggregate_hash,
            meta.ima_pcr10,
            meta.userspace_process_count.map(|c| c.to_string()).unwrap_or_else(|| "--".into()),
            meta.kernel_thread_type_count.map(|c| c.to_string()).unwrap_or_else(|| "--".into()),
            meta.kernel_modules_count.map(|c| c.to_string()).unwrap_or_else(|| "--".into()),
            meta.network_connections,
            meta.connection_tuple_count.map(|c| c.to_string()).unwrap_or_else(|| "--".into()),
            meta.xdp_attached.map(|b| b.to_string()).unwrap_or_else(|| "--".into()),
            meta.entropy_available.map(|e| format!("{} bits", e)).unwrap_or_else(|| "--".into()),
        )
    } else {
        r#"<div class="pnl"><div class="pnl-h"><span>Attestation Metadata</span></div><div style="padding:10px;color:#555;">No attestation metadata received yet.</div></div>"#.to_string()
    };
    
    let xdp_html = if let Some(meta) = &node.full_meta {
        xdp_stats_panel(meta)
    } else { String::new() };
    
    /// Raw content snapshots
    let raw_html = if let Some(meta) = &node.full_meta {
        let content_block = |label: &str, content: &Option<String>| -> String {
            let bytes = content.as_ref().map(|s| s.len()).unwrap_or(0);
            let text = html_escape(content.as_deref().unwrap_or("(not collected)"));
            format!("<details><summary>{} ({} bytes)</summary><div class=\"cb\">{}</div></details>\n",
                label, bytes, text)
        };
 
        let preload_status = if meta.ld_preload_content.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false) {
            " -- NOT EMPTY"
        } else { " -- empty" };
 
        format!(r#"
<div class="pnl">
    <div class="pnl-h"><span>Raw Content Snapshots</span><span class="ct">Transmitted per heartbeat</span></div>
    <div style="padding: 8px;">
    {}{}{}{}
    <details><summary>ld.so.preload ({} bytes){}</summary><div class="cb">{}</div></details>
    {}{}{}{}
    <details><summary>/dev inventory ({} entries)</summary><div class="cb">{}</div></details>
    <div style="margin-top:8px;"><a class="btn" href="/diff/{}">Compare Against Baseline</a></div>
    </div>
</div>"#,
            content_block("/etc/passwd", &meta.passwd_content),
            content_block("/etc/shadow", &meta.shadow_content),
            content_block("sshd_config", &meta.sshd_config_content),
            content_block("authorized_keys", &meta.authorized_keys_content),
            meta.ld_preload_content.as_ref().map(|s| s.len()).unwrap_or(0),
            preload_status,
            html_escape(meta.ld_preload_content.as_deref().unwrap_or("(missing -- safe)")),
            content_block("/proc/cmdline", &meta.boot_params_content),
            content_block("iptables rules", &meta.iptables_content),
            content_block("/proc/mounts", &meta.mount_content),
            content_block("sysctl", &meta.sysctl_content),
            meta.dev_inventory_list.as_ref().map(|l| l.len()).unwrap_or(0),
            html_escape(&meta.dev_inventory_list.as_ref()
                .map(|l| l.join("\n")).unwrap_or_else(|| "(not collected)".into())),
            node.node_id,
        )
    } else { String::new() };
 
    /// Raw details string
    let raw_details_html = format!(r#"
<div class="pnl">
    <div class="pnl-h"><span>Raw Verification String</span></div>
    <div class="cb" style="margin:8px;">{}</div>
</div>"#, html_escape(&node.raw_details));
 
    format!(r#"<!DOCTYPE html>
<html><head>
<title>Node {id} — Detail</title>
<meta http-equiv="refresh" content="10">
<style>{styles}</style>
</head><body>
 
<div class="header">
    <h1>Node: {id}</h1>
    <div class="hstats">
        <span>Chain: <span class="v">{chain}</span></span>
        <span>Status: <span class="{sc}">{st}</span></span>
        <span>Baseline: <span class="v">{bl}</span></span>
        <span>Last seen: <span class="v">{age}s ago</span></span>
    </div>
</div>
 
{nav}
 
<div class="pnl">
    <div class="pnl-h"><span>Verification Status</span><span class="ct">28 checks</span></div>
    <table style="padding: 8px;">
    <tr><th>Check</th><th>Result</th><th>Detail</th></tr>
    {checks}
    </table>
</div>
 
{meta_html}

{xdp_html}

{runtime_html}

{raw_html}
 
{raw_details}
 
</body></html>"#,
        id = node.node_id,
        styles = COMMON_STYLES,
        chain = node.chain,
        sc = status_class,
        st = status_text,
        bl = baseline_text,
        age = now_secs().saturating_sub(node.last_seen),
        nav = nav_bar(),
        checks = checks,
        meta_html = meta_html,
        xdp_html = xdp_html,
        raw_html = raw_html,
        raw_details = raw_details_html,
        runtime_html = runtime_html,
    )
}

// === DIFF VIEW (baseline vs current) ===

fn render_diff(node: &NodeStatus, baseline: Option<&PcrBaseline>) -> String {
    let baseline = match baseline {
        Some(b) => b,
        None => return format!(r#"<!DOCTYPE html><html><head><style>{}</style></head><body>
{}<div class="pnl"><div style="padding:10px;color:#555;">No baseline loaded for this node.</div></div>
</body></html>"#, COMMON_STYLES, nav_bar()),
    };
 
    let current = match &node.full_meta {
        Some(m) => m,
        None => return format!(r#"<!DOCTYPE html><html><head><style>{}</style></head><body>
{}<div class="pnl"><div style="padding:10px;color:#555;">No attestation metadata available.</div></div>
</body></html>"#, COMMON_STYLES, nav_bar()),
    };
 
    let bl_ebpf = baseline.ebpf_baseline.as_ref();
 
    let diff_row = |label: &str, bl_content: &str, cur_content: &str| -> String {
        let same = bl_content == cur_content;
        let status = if same { "IDENTICAL" } else { "CHANGED" };
        let sc = if same { "p" } else { "f" };
        format!(r#"
<div class="pnl" style="margin-bottom:8px;">
    <div class="pnl-h"><span>{}</span><span class="{}">{}</span></div>
    <table><tr>
    <td style="width:50%;vertical-align:top;padding:4px;"><div style="font-size:9px;color:#555;margin-bottom:2px;">BASELINE</div><div class="cb">{}</div></td>
    <td style="width:50%;vertical-align:top;padding:4px;"><div style="font-size:9px;color:#555;margin-bottom:2px;">CURRENT</div><div class="cb">{}</div></td>
    </tr></table>
</div>"#,
            label, sc, status,
            html_escape(bl_content), html_escape(cur_content))
    };
 
    let mut diffs = String::new();
    if let Some(bl) = bl_ebpf {
        diffs.push_str(&diff_row("/etc/passwd",
            bl.passwd_content.as_deref().unwrap_or("(missing)"),
            current.passwd_content.as_deref().unwrap_or("(missing)")));
        diffs.push_str(&diff_row("sshd_config",
            bl.sshd_config_content.as_deref().unwrap_or("(missing)"),
            current.sshd_config_content.as_deref().unwrap_or("(missing)")));
        diffs.push_str(&diff_row("authorized_keys",
            bl.authorized_keys_content.as_deref().unwrap_or("(none)"),
            current.authorized_keys_content.as_deref().unwrap_or("(none)")));
        diffs.push_str(&diff_row("ld.so.preload",
            bl.ld_preload_content.as_deref().unwrap_or("(empty)"),
            current.ld_preload_content.as_deref().unwrap_or("(empty)")));
        diffs.push_str(&diff_row("/proc/cmdline",
            bl.boot_params_content.as_deref().unwrap_or("(missing)"),
            current.boot_params_content.as_deref().unwrap_or("(missing)")));
        diffs.push_str(&diff_row("iptables",
            bl.iptables_content.as_deref().unwrap_or("(missing)"),
            current.iptables_content.as_deref().unwrap_or("(missing)")));
        diffs.push_str(&diff_row("mounts",
            bl.mount_content.as_deref().unwrap_or("(missing)"),
            current.mount_content.as_deref().unwrap_or("(missing)")));
        diffs.push_str(&diff_row("sysctl",
            bl.sysctl_content.as_deref().unwrap_or("(missing)"),
            current.sysctl_content.as_deref().unwrap_or("(missing)")));
        let bl_dev = bl.dev_inventory_list.as_ref()
            .map(|l| l.join("\n")).unwrap_or_else(|| "(missing)".into());
        let cur_dev = current.dev_inventory_list.as_ref()
            .map(|l| l.join("\n")).unwrap_or_else(|| "(missing)".into());
        diffs.push_str(&diff_row("/dev inventory", &bl_dev, &cur_dev));
    } else {
        diffs.push_str(r#"<div class="pnl"><div style="padding:10px;color:#f44336;">No eBPF baseline data available.</div></div>"#);
    }
 
    format!(r#"<!DOCTYPE html>
<html><head>
<title>Diff: {id}</title>
<style>{styles}</style>
</head><body>
 
<div class="header">
    <h1>Baseline vs Current: {id}</h1>
    <div class="hstats">
        <span>Baseline: <span class="v">{bl_ts} (unix)</span></span>
        <span>Current: <span class="v">{cur_ts} (unix)</span></span>
        <span><a class="btn" href="/node/{id}">Back to Node</a></span>
    </div>
</div>
 
{nav}
 
{diffs}
 
</body></html>"#,
        id = node.node_id,
        styles = COMMON_STYLES,
        nav = nav_bar(),
        bl_ts = baseline.timestamp,
        cur_ts = node.last_seen,
        diffs = diffs,
    )
}

// === FORENSICS LIST ===

fn render_forensics_list(state: &SystemState) -> String {
    let disk_index: Vec<serde_json::Value> = std::fs::read_to_string("/opt/mfa-monitor/forensics/index.json")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let mut rows = String::new();
    /// Disk entries
    for entry in disk_index.iter().rev() {
        let seq = entry.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
        let tier = entry.get("tier").and_then(|v| v.as_str()).unwrap_or("Info");
        let src = entry.get("source").and_then(|v| v.as_str()).unwrap_or("?");
        let hb = entry.get("heartbeat").and_then(|v| v.as_u64()).unwrap_or(0);
        let auth = entry.get("authorized").and_then(|v| v.as_bool()).unwrap_or(false);
        let fname = entry.get("filename").and_then(|v| v.as_str()).unwrap_or("");
        let fhash = entry.get("file_hash").and_then(|v| v.as_str()).unwrap_or("");
        let ts = entry.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);
        let tc = match tier { "Critical" => "tc", "Warning" => "tw", _ => "ti" };
        let auth_c = if auth { "cp" } else { "cf" };
        let auth_t = if auth { "YES" } else { "NO" };

        rows.push_str(&format!(
            "<tr><td>{seq}</td><td><span class=\"tier {tc}\">{tier}</span></td><td>#{hb}</td>\
            <td>{src}</td><td class=\"{auth_c}\">{auth_t}</td>\
            <td>{time}</td>\
            <td class=\"hash\">{hash}..</td>\
            <td><a class=\"btn\" href=\"/forensics/{seq}\">View</a> <a class=\"btn\" href=\"/forensics/{seq}/download\">JSON</a></td></tr>\n",
            seq=seq, tc=tc, tier=tier, hb=hb, src=src, auth_c=auth_c, auth_t=auth_t,
            time=format_timestamp(ts),
            hash=if fhash.len() >= 16 { &fhash[..16] } else { fhash },
        ));
    }
    let count = disk_index.len();
    format!(r#"<!DOCTYPE html>
<html><head>
<title>Forensic Events</title>
<style>{styles}</style>
</head><body>
<div class="header">
    <h1>Forensic Events</h1>
    <div class="hstats"><span>Total: <span class="v">{count}</span></span></div>
</div>
{nav}
<div class="pnl">
    <div class="pnl-h"><span>Stored Forensic Snapshots</span><span class="ct">{count} events</span></div>
    <table>
    <tr><th>Seq</th><th>Tier</th><th>HB</th><th>Source</th><th>Auth</th><th>Time</th><th>File Hash</th><th>Actions</th></tr>
    {rows}
    {empty}
    </table>
</div>
</body></html>"#,
        styles = COMMON_STYLES,
        nav = nav_bar(),
        count = count,
        rows = rows,
        empty = if count == 0 { "<tr><td colspan=\"8\" style=\"color:#555\">No forensic events captured. Forensic snapshots trigger automatically on Warning or Critical tier integrity failures.</td></tr>" } else { "" },
    )
}

// === Forensic Detail Page ===
fn render_forensic_detail(entry: &AuditEntryV2, _baselines: Option<&BaselineDatabase>) -> String {
    let f = match &entry.forensic {
        Some(f) => f,
        None => return format!(r#"<!DOCTYPE html><html><head><style>{}</style></head><body>{}<div class="pnl"><div style="padding:10px;">No forensic data in this entry.</div></div></body></html>"#, COMMON_STYLES, nav_bar()),
    };
 
    let tc = match f.tier.as_str() {
        "CRITICAL" => "tc", "WARNING" => "tw", _ => "ti"
    };
 
    let trigger_list = f.trigger_checks.iter()
        .map(|c| format!("<li>{}</li>", html_escape(c)))
        .collect::<Vec<_>>().join("\n");
 
    let node_details = f.node_details.as_ref()
        .map(|details| details.iter()
            .map(|d| format!("<div class=\"cb\" style=\"margin:4px 0;\">{}</div>", html_escape(d)))
            .collect::<Vec<_>>().join("\n"))
        .unwrap_or_default();
 
    let snapshot_html = if let Some(snap) = &f.local_snapshot {
        let proc_rows = snap.process_tree.iter()
            .map(|p| format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                p.pid, p.ppid, html_escape(&p.comm),
                html_escape(&p.exe_path), p.uid, p.start_time))
            .collect::<Vec<_>>().join("\n");
 
        let volatile_html = snap.process_volatile.iter().map(|pv| {
            format!(r#"
<details>
<summary>PID {} ({}) -- {} maps, {} fds, {} env</summary>
<div class="cb">{}</div>
<div class="cb">{}</div>
</details>"#,
                pv.pid, html_escape(&pv.comm),
                pv.memory_maps.len(), pv.open_fds.len(), pv.environment.len(),
                html_escape(&pv.open_fds.join("\n")),
                html_escape(&pv.memory_maps.join("\n")),
            )
        }).collect::<Vec<_>>().join("\n");
 
        format!(r#"
<div class="pnl">
    <div class="pnl-h"><span>Local System Snapshot (Verifier Node)</span></div>
    <div style="padding:8px;">
    <table><tr><td>Timestamp</td><td>{}</td></tr><tr><td>Uptime</td><td>{}s</td></tr><tr><td>Load</td><td>{}</td></tr></table>
 
    <details><summary>Process Tree ({} processes)</summary>
    <table>
    <tr><th>PID</th><th>PPID</th><th>Comm</th><th>Exe</th><th>UID</th><th>Start</th></tr>
    {}
    </table>
    </details>
 
    <details><summary>Per-Process Volatile Evidence ({} processes)</summary>
    {}
    </details>
 
    <details><summary>TCP Connections ({} entries)</summary>
    <div class="cb">{}</div>
    </details>
 
    <details><summary>ARP Table ({} entries)</summary>
    <div class="cb">{}</div>
    </details>
 
    <details><summary>dmesg ({} lines)</summary>
    <div class="cb">{}</div>
    </details>
 
    <details><summary>IMA Measurements ({} entries)</summary>
    <div class="cb">{}</div>
    </details>
    </div>
</div>"#,
            snap.timestamp, snap.uptime_seconds, html_escape(&snap.load_average),
            snap.process_tree.len(), proc_rows,
            snap.process_volatile.len(), volatile_html,
            snap.tcp_connections.len(), html_escape(&snap.tcp_connections.join("\n")),
            snap.arp_table.len(), html_escape(&snap.arp_table.join("\n")),
            snap.dmesg_tail.len(), html_escape(&snap.dmesg_tail.join("\n")),
            snap.ima_tail.len(), html_escape(&snap.ima_tail.join("\n")),
        )
    } else {
        String::new()
    };
 
    format!(r#"<!DOCTYPE html>
<html><head>
<title>Forensic Event #{seq}</title>
<style>{styles}</style>
</head><body>
 
<div class="header">
    <h1>Forensic Event #{seq}</h1>
    <div class="hstats">
        <span><span class="tier {tc}">{tier}</span></span>
        <span><a class="btn" href="/forensics/{seq}/download">Download JSON</a></span>
    </div>
</div>
 
{nav}
 
<div class="pnl">
    <div class="pnl-h"><span>Event Summary</span></div>
    <table style="padding:8px;">
    <tr><td>Sequence</td><td>{seq}</td></tr>
    <tr><td>Timestamp</td><td>{ts} (unix)</td></tr>
    <tr><td>Verifier</td><td>{verifier}</td></tr>
    <tr><td>Heartbeat</td><td>#{hb}</td></tr>
    <tr><td>Event</td><td>{event}</td></tr>
    <tr><td>Session Status</td><td>{status}</td></tr>
    <tr><td>Authorized</td><td class="{auth_c}">{auth}</td></tr>
    <tr><td>Verification</td><td>{ms}</td></tr>
    <tr><td>Previous Hash</td><td class="hash">{prev}</td></tr>
    </table>
</div>
 
<div class="pnl">
    <div class="pnl-h"><span>Trigger Analysis</span></div>
    <div style="padding:8px;">
    <p>Failing nodes: <b>{trigger_nodes}</b></p>
    <p>Failed checks ({check_count}):</p>
    <ul style="margin:4px 0 4px 20px;">{trigger_list}</ul>
    </div>
</div>
 
<div class="pnl">
    <div class="pnl-h"><span>Failing Node Details</span></div>
    <div style="padding:8px;">
    {node_details}
    </div>
</div>
 
{snapshot}
 
</body></html>"#,
        styles = COMMON_STYLES,
        nav = nav_bar(),
        seq = entry.seq,
        tc = tc,
        tier = f.tier,
        ts = entry.timestamp,
        verifier = entry.node_id,
        hb = entry.heartbeat,
        event = entry.event,
        status = entry.session_status,
        auth_c = if entry.authorized { "p" } else { "f" },
        auth = if entry.authorized { "Yes" } else { "No" },
        ms = entry.verification_duration_ms.map(|m| format!("{}ms", m)).unwrap_or_else(|| "--".into()),
        prev = entry.prev_hash,
        trigger_nodes = f.trigger_nodes.join(", "),
        check_count = f.trigger_checks.len(),
        trigger_list = trigger_list,
        node_details = node_details,
        snapshot = snapshot_html,
    )
}

/// Helper 
fn format_timestamp(ts: u64) -> String {
    let secs = ts % 60;
    let mins = (ts / 60) % 60;
    let hours = (ts / 3600) % 24;
    let days = ts / 86400;
    let years = days / 365;
    let year = 1970 + years;
    let remaining_days = days % 365;
    let month_days = [31,28,31,30,31,30,31,31,30,31,30,31];
    let mut month = 0;
    let mut day = remaining_days;
    for (i, &md) in month_days.iter().enumerate() {
        if day < md { month = i + 1; break; }
        day -= md;
    }
    if month == 0 { month = 12; }
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day + 1, hours, mins, secs)
}

fn render_sessions() -> String {
    let index = mfa_monitor::session_tracker::SessionTracker::load_index();
 
    let mut rows = String::new();
    if let Some(ref idx) = index {
        for s in idx.sessions.iter().rev() {
            let sc = if s.all_authorized { "p" } else { "f" };
            let st = if s.all_authorized { "PASS" } else { "FAIL" };
            let dur_min = s.duration_secs / 60;
            let dur_sec = s.duration_secs % 60;
            rows.push_str(&format!(
                "<tr>\
                <td><a href=\"/api/session/{}\">{}</a></td>\
                <td>{}</td>\
                <td class=\"{}\">{}</td>\
                <td>{}</td>\
                <td>{}m {}s</td>\
                <td>{}</td>\
                <td>{}</td>\
                <td class=\"hash\">{}</td>\
                </tr>\n",
                s.session_id, &s.session_id[..8],
                s.source, sc, st, s.heartbeats,
                dur_min, dur_sec,
                s.node_count,
                format_timestamp(s.start_time),
                &s.file_hash[..16],
            ));
        }
    }
 
    let session_count = index.as_ref().map(|i| i.sessions.len()).unwrap_or(0);
    let index_hash = index.as_ref()
        .map(|i| &i.index_hash[..16])
        .unwrap_or("--");
 
    format!(r#"<!DOCTYPE html>
<html><head>
<title>Session History</title>
<meta http-equiv="refresh" content="30">
<style>{styles}</style>
</head><body>
 
<div class="header">
    <h1>Session History</h1>
    <div class="hstats">
        <span>Sessions: <span class="v">{count}</span></span>
        <span>Index hash: <span class="hash">{idx_hash}...</span></span>
    </div>
</div>
 
{nav}
 
<div class="pnl">
    <div class="pnl-h"><span>Completed Sessions</span><span class="ct">{count}</span></div>
    <table>
    <tr><th>ID</th><th>Source</th><th>Result</th><th>Heartbeats</th><th>Duration</th><th>Nodes</th><th>File Hash</th></tr>
    {rows}
    {empty}
    </table>
</div>
 
<div style="padding:8px;">
    <div class="api">
        API: <a href="/api/sessions">/api/sessions</a>
    </div>
</div>
 
</body></html>"#,
        styles = COMMON_STYLES,
        nav = nav_bar(),
        count = session_count,
        idx_hash = index_hash,
        rows = rows,
        empty = if session_count == 0 {
            "<tr><td colspan=\"7\" style=\"color:#444\">No completed sessions yet. Run an authentication session and wait for it to complete.</td></tr>"
        } else { "" },
    )
}

// === Utilities ===
fn icon(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
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
 
fn xdp_stats_panel(meta: &AttestationMeta) -> String {
    let has_xdp = meta.xdp_passed.is_some();
    if !has_xdp {
        return r#"<div class="pnl"><div class="pnl-h"><span>XDP Traffic Statistics</span></div><div style="padding:10px;color:#555;">No XDP statistics available for this node.</div></div>"#.to_string();
    }
 
    let passed = meta.xdp_passed.unwrap_or(0);
    let drop_ent = meta.xdp_drop_entropy.unwrap_or(0);
    let drop_pro = meta.xdp_drop_protocol.unwrap_or(0);
    let drop_prt = meta.xdp_drop_port.unwrap_or(0);
    let total = meta.xdp_total.unwrap_or(1).max(1); /// avoid div by zero
    let exempt = meta.xdp_exempt.unwrap_or(0);
 
    let pass_pct = (passed * 100) / total;
    let exempt_pct = (exempt * 100) / total;
    let drop_ent_pct = (drop_ent * 100) / total;
 
    let drop_ent_class = if drop_ent > 0 { "f" } else { "p" };
 
    /// Build entropy histogram bars
    let ent_hist = meta.xdp_entropy_histogram.as_ref();
    let ent_hist_html = if let Some(hist) = ent_hist {
        let max_val = hist.iter().max().copied().unwrap_or(1).max(1);
        let mut bars = String::new();
        for (i, &count) in hist.iter().enumerate() {
            if count == 0 { continue; }
            let lo = i * 10;
            let hi = lo + 9;
            let bar_width = ((count as f64 / max_val as f64) * 200.0) as u32;
            let pct = (count * 100) / hist.iter().sum::<u64>().max(1);
            bars.push_str(&format!(
                r#"<div style="display:flex;align-items:center;margin:1px 0;">
                <span style="width:60px;text-align:right;color:#666;font-size:10px;">{}-{}:</span>
                <div style="background:#4a9eff;height:12px;width:{}px;margin:0 6px;border-radius:1px;"></div>
                <span style="color:#888;font-size:10px;">{} ({}%)</span>
                </div>"#,
                lo, hi, bar_width, count, pct
            ));
        }
        if bars.is_empty() {
            "<div style=\"color:#555;padding:4px;\">No entropy-checked packets recorded.</div>".to_string()
        } else {
            bars
        }
    } else {
        "<div style=\"color:#555;padding:4px;\">Histogram data not available.</div>".to_string()
    };
 
    /// Build size histogram bars
    let size_hist = meta.xdp_size_histogram.as_ref();
    let size_hist_html = if let Some(hist) = size_hist {
        let max_val = hist.iter().max().copied().unwrap_or(1).max(1);
        let mut bars = String::new();
        for (i, &count) in hist.iter().enumerate() {
            if count == 0 { continue; }
            let lo = i * 100;
            let hi = lo + 99;
            let label = if i == 15 { format!("{}+", lo) } else { format!("{}-{}", lo, hi) };
            let bar_width = ((count as f64 / max_val as f64) * 200.0) as u32;
            let pct = (count * 100) / hist.iter().sum::<u64>().max(1);
            bars.push_str(&format!(
                r#"<div style="display:flex;align-items:center;margin:1px 0;">
                <span style="width:60px;text-align:right;color:#666;font-size:10px;">{}:</span>
                <div style="background:#ff9800;height:12px;width:{}px;margin:0 6px;border-radius:1px;"></div>
                <span style="color:#888;font-size:10px;">{} ({}%)</span>
                </div>"#,
                label, bar_width, count, pct
            ));
        }
        if bars.is_empty() {
            "<div style=\"color:#555;padding:4px;\">No size data recorded.</div>".to_string()
        } else {
            bars
        }
    } else {
        "<div style=\"color:#555;padding:4px;\">Histogram data not available.</div>".to_string()
    };
 
    format!(r#"
<div class="pnl">
    <div class="pnl-h"><span>XDP Traffic Statistics</span><span class="ct">Layer 1 Defense</span></div>
    <div style="padding:10px;">
 
    <div style="margin-bottom:12px;">
        <div style="color:#4a9eff;font-weight:600;font-size:10px;text-transform:uppercase;margin-bottom:4px;">Traffic Counters</div>
        <table>
        <tr><th>Counter</th><th>Value</th><th>%</th><th>Description</th></tr>
        <tr><td>Total Packets</td><td>{total}</td><td>100%</td><td>All TCP packets received</td></tr>
        <tr><td class="p">Passed</td><td class="p">{passed}</td><td>{pass_pct}%</td><td>Packets verified as encrypted (high entropy) or authorized bypass</td></tr>
        <tr><td class="{dec}">Dropped (Entropy)</td><td class="{dec}">{drop_ent}</td><td>{drop_ent_pct}%</td><td>Packets with insufficient randomness. (blocked) </td></tr>
        <tr><td>Dropped (Protocol)</td><td>{drop_pro}</td><td></td><td>Non-TCP traffic (ICMP, UDP). ONLY TCP is permitted</td></tr>
        <tr><td>Dropped (Port)</td><td>{drop_prt}</td><td></td><td>Traffic on unauthorized ports for this node's role</td></tr>
        <tr><td>Exempt</td><td>{exempt}</td><td>{exempt_pct}%</td><td>Small packets (&lt;128 bytes) bypassing entropy check, such as TCP control segments (ACK, FIN, RST)</td></tr>
        </table>
    </div>
 
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div>
            <div style="color:#4a9eff;font-weight:600;font-size:10px;text-transform:uppercase;margin-bottom:4px;">
                Entropy Distribution (unique bytes per payload)
            </div>
            <div style="font-size:9px;color:#555;margin-bottom:4px;">
                Encrypted traffic produces 250+ unique byte values per 1500-byte payload.
                Plaintext typically shows 40-70. Threshold: 85 (authenticated), 80 (handshake).
            </div>
            {ent_hist}
        </div>
        <div>
            <div style="color:#4a9eff;font-weight:600;font-size:10px;text-transform:uppercase;margin-bottom:4px;">
                Packet Size Distribution (bytes)
            </div>
            <div style="font-size:9px;color:#555;margin-bottom:4px;">
                Encrypted relay traffic clusters at MTU size (1400-1499 bytes).
                Small packets (0-99) are TCP control segments. Anomalous size distributions
                may indicate traffic manipulation.
            </div>
            {size_hist}
        </div>
    </div>
 
    </div>
</div>"#,
        total = total,
        passed = passed,
        pass_pct = pass_pct,
        dec = drop_ent_class,
        drop_ent = drop_ent,
        drop_ent_pct = drop_ent_pct,
        drop_pro = drop_pro,
        drop_prt = drop_prt,
        exempt = exempt,
        exempt_pct = exempt_pct,
        ent_hist = ent_hist_html,
        size_hist = size_hist_html,
    )
}

fn render_xdp_summary(nodes: &[&NodeStatus]) -> String {
    let mut rows = String::new();
    let mut any_data = false;
 
    for n in nodes {
        if let Some(meta) = &n.full_meta {
            if meta.xdp_passed.is_some() {
                any_data = true;
                let total = meta.xdp_total.unwrap_or(0);
                let passed = meta.xdp_passed.unwrap_or(0);
                let drop_ent = meta.xdp_drop_entropy.unwrap_or(0);
                let drop_prt = meta.xdp_drop_port.unwrap_or(0);
                let exempt = meta.xdp_exempt.unwrap_or(0);
                let exempt_pct = if total > 0 { (exempt * 100) / total } else { 0 };
                let dec = if drop_ent > 0 { "f" } else { "p" };
                /// Find peak entropy bucket
                let peak_ent = meta.xdp_entropy_histogram.as_ref().and_then(|h| {
                    h.iter().enumerate()
                        .max_by_key(|(_, &v)| v)
                        .map(|(i, &v)| format!("{}-{}: {}", i*10, i*10+9, v))
                });
                /// Find peak size bucket
                let peak_size = meta.xdp_size_histogram.as_ref().and_then(|h| {
                    h.iter().enumerate()
                        .max_by_key(|(_, &v)| v)
                        .map(|(i, &v)| {
                            if i == 15 { format!("1500+: {}", v) }
                            else { format!("{}-{}: {}", i*100, i*100+99, v) }
                        })
                });
 
                rows.push_str(&format!(
                    "<tr>\
                    <td><a href=\"/node/{}\">{}</a></td>\
                    <td>{}</td>\
                    <td class=\"p\">{}</td>\
                    <td class=\"{}\">{}</td>\
                    <td>{}</td>\
                    <td>{}</td>\
                    <td>{}%</td>\
                    <td class=\"hash\">{}</td>\
                    <td class=\"hash\">{}</td>\
                    </tr>\n",
                    n.node_id, n.node_id,
                    total, passed, dec, drop_ent, drop_prt,
                    exempt, exempt_pct,
                    peak_ent.as_deref().unwrap_or("--"),
                    peak_size.as_deref().unwrap_or("--"),
                ));
            }
        }
    }
 
    if !any_data {
        return String::new();
    }
 
    format!(r#"
<div class="pnl">
    <div class="pnl-h"><span>XDP Traffic Analysis</span><span class="ct">Layer 1 Encryption Enforcement</span></div>
    <table>
    <tr><th>Node</th><th>Total</th><th>Passed</th><th>Drop(Ent)</th><th>Drop(Port)</th><th>Exempt</th><th>Exempt%</th><th>Peak Entropy</th><th>Peak Size</th></tr>
    {rows}
    </table>

</div>"#,
        rows = rows,
    )
}

// === Main ===
#[tokio::main]
async fn main() -> Result<()> {
    let config_path = std::env::args().nth(1)
        .unwrap_or_else(|| DEFAULT_CONFIG.to_string());

    let config = MonitorConfig::load(&config_path)?;
    let _ = std::fs::create_dir_all("/opt/mfa-monitor/forensics");
    println!("MFA Monitor v3 — Forensic Dashboard");
    println!("   Node:      {}", config.node_id);
    println!("   Receiver:  port {}", config.log_receiver_port);
    println!("   Dashboard: port {}", config.dashboard_port);

    let baselines: Arc<Option<BaselineDatabase>> = Arc::new(
        BaselineDatabase::load(&config.baselines_path)
    );
    match baselines.as_ref() {
        Some(db) => println!("   Baselines: loaded ({} nodes)", db.baselines.len()),
        None => println!("   Baselines: not available ({})", config.baselines_path),
    }

    println!("   Sources:   {}", config.authorized_sources.len());
    for src in &config.authorized_sources {
        println!("     {} ({}) chain {}", src.node_id, src.ip, src.chain);
    }
    println!();

    let state = Arc::new(RwLock::new(SystemState::new()));
    
    let tracker = Arc::new(tokio::sync::Mutex::new(SessionTracker::new()));

    let dashboard_state = state.clone();
    let dashboard_baselines = baselines.clone();
    let dashboard_port = config.dashboard_port;
    tokio::spawn(async move {
        if let Err(e) = run_dashboard(dashboard_port, dashboard_state, dashboard_baselines).await {
            eprintln!("Dashboard error: {}", e);
        }
    });

    let receiver_addr = format!("0.0.0.0:{}", config.log_receiver_port);
    let listener = TcpListener::bind(&receiver_addr).await
        .context("Failed to bind log receiver")?;
    println!("Log receiver listening on {}", receiver_addr);
    println!("Ready\n");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let peer_ip = peer_addr.ip().to_string();
        println!("Connection from {}", peer_ip);

        let source_info = match config.is_authorized(&peer_ip) {
            Some(src) => src.clone(),
            None => {
                eprintln!("  Unauthorized: {}", peer_ip);
                drop(stream);
                continue;
            }
        };

        println!("  Authorized: {} ({})", source_info.node_id, peer_ip);

        let state = state.clone();
        let cfg = config.clone();
        let trk = tracker.clone();
        tokio::spawn(async move {
            match handle_source(stream, peer_ip.clone(), source_info, state, cfg, trk).await {
                Ok(()) => println!("{} disconnected", peer_ip),
                Err(e) => eprintln!("{} error: {}", peer_ip, e),
            }
        });
    }
}
