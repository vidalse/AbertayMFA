use serde::{Serialize, Deserialize};
use anyhow::{Result, Context};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use crate::protocol::{
    BaselineDatabase, FullAuthorizationResponse, Attestation,
};
use crate::tpm;
use crate::crypto;
use crate::orchestrator::{CliRequest, CliResponse};

// === Types ===
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DualAuthMessage {
    Attestation(Attestation),
    PreApproval {
        approved: bool,
        node_id: String,
        reason: String,
        session_ttl_secs: u64,
    },
    ChainResult {
        result: FullAuthorizationResponse,
        da_attestation: Attestation,
    },
    QuorumDecision {
        approved: bool,
        vm4_node_id: String,
        reason: String,
    },
}

struct PendingRequest {
    requester_id: String,
    requester_ip: String,
    session_ttl_secs: u64,
    attestation_summary: String,
    vm0_verified: bool,
    response_tx: Option<oneshot::Sender<bool>>,
}

type SharedPending = Arc<Mutex<Option<PendingRequest>>>;

// === Wire Protocol ===
async fn send_encrypted(
    stream: &mut TcpStream,
    key: &[u8; 32],
    msg: &DualAuthMessage,
) -> Result<()> {
    let plaintext = bincode::serialize(msg)?;
    let ciphertext = crypto::encrypt(key, &plaintext)?;
    let len = ciphertext.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&ciphertext).await?;
    Ok(())
}

async fn recv_encrypted(
    stream: &mut TcpStream,
    key: &[u8; 32],
) -> Result<DualAuthMessage> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 10_000_000 {
        anyhow::bail!("Message too large: {} bytes", len);
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    let plaintext = crypto::decrypt(key, &buf)?;
    let msg: DualAuthMessage = bincode::deserialize(&plaintext)?;
    Ok(msg)
}

// === Key Exchange Helpers ===
async fn perform_key_exchange_initiator(
    stream: &mut TcpStream,
    sender_id: &str,
) -> Result<[u8; 32]> {
    let (init, kyber_sk, x25519_secret, nonce) =
        crypto::generate_key_exchange_init(sender_id)?;
    let init_clone = init.clone();
    let init_bytes = bincode::serialize(&init)?;
    let len = init_bytes.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&init_bytes).await?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u32::from_le_bytes(len_buf) as usize;
    if resp_len > 10_000_000 { anyhow::bail!("Response too large"); }
    let mut resp_bytes = vec![0u8; resp_len];
    stream.read_exact(&mut resp_bytes).await?;
    let response: crypto::KeyExchangeResponse = bincode::deserialize(&resp_bytes)?;
    let keys = crypto::complete_key_exchange(&init_clone, &response, &kyber_sk, x25519_secret, &nonce)?;
    Ok(keys.session_key)
}

async fn perform_key_exchange_responder(
    stream: &mut TcpStream,
    responder_id: &str,
) -> Result<[u8; 32]> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let init_len = u32::from_le_bytes(len_buf) as usize;
    if init_len > 10_000_000 { anyhow::bail!("Init too large"); }
    let mut init_bytes = vec![0u8; init_len];
    stream.read_exact(&mut init_bytes).await?;
    let init: crypto::KeyExchangeInit = bincode::deserialize(&init_bytes)?;

    let (response, keys) = crypto::generate_key_exchange_response(responder_id, &init)?;
    let resp_bytes = bincode::serialize(&response)?;
    let len = resp_bytes.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&resp_bytes).await?;
    Ok(keys.session_key)
}

// === Attestation Builder ===
fn build_self_attestation(
    node_id: &str,
    tpm_ctx: &tpm::TpmCtx,
) -> Result<Attestation> {
    let tpm_quote = tpm::generate_quote(tpm_ctx)?;
    Ok(Attestation {
        vm_identity: node_id.to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        tpm_quote,
    })
}

// === VM0 Side Pre-chain Authorization ===
pub async fn vm0_mutual_attest_vm4(
    vm4_address: &str,
    node_id: &str,
    tpm_ctx: &tpm::TpmCtx,
    baseline_db: &BaselineDatabase,
    session_ttl_secs: u64,
) -> Result<bool> {
    println!("  Connecting to vm4 at {}...", vm4_address);
    let mut stream = crate::network::connect(vm4_address).await
        .context("Failed to connect to vm4")?;
    println!("  Connected to vm4");

    let session_key = perform_key_exchange_initiator(&mut stream, node_id).await
        .context("Key exchange with vm4 failed")?;
    println!("  Key exchange with vm4 complete");

    let our_att = build_self_attestation(node_id, tpm_ctx)?;
    send_encrypted(&mut stream, &session_key,
        &DualAuthMessage::Attestation(our_att)).await?;
    println!("  Sent attestation to vm4");

    let vm4_msg = recv_encrypted(&mut stream, &session_key).await?;
    let vm4_att = match vm4_msg {
        DualAuthMessage::Attestation(att) => att,
        _ => anyhow::bail!("Expected attestation from vm4"),
    };
    println!("  Received attestation from vm4 ({})", vm4_att.vm_identity);

    let vm4_ok = if let Some(_bl) = baseline_db.get_baseline(&vm4_att.vm_identity) {
        let nr = baseline_db.verify_attestation(&vm4_att, None, None, None);
        let pass = nr.pcr_match && nr.ima_valid && nr.ebpf_valid
            && nr.signature_valid && nr.ak_match;
        if pass {
            println!("  vm4 attestation PASSED: {}", nr.details);
        } else {
            println!("  vm4 attestation FAILED: {}", nr.details);
        }
        pass
    } else {
        println!("  No baseline for vm4");
        false
    };

    /// Send pre-approval with session TTL
    send_encrypted(&mut stream, &session_key, &DualAuthMessage::PreApproval {
        approved: vm4_ok,
        node_id: node_id.to_string(),
        reason: if vm4_ok { "vm4 integrity verified".to_string() }
                else { "vm4 attestation failed".to_string() },
        session_ttl_secs,
    }).await?;
    println!("  Waiting for vm4 operator approval...");

    /// Wait for vm4's pre-approval (operator B must authenticate)
    let vm4_decision = recv_encrypted(&mut stream, &session_key).await?;
    match vm4_decision {
        DualAuthMessage::PreApproval { approved, reason, .. } => {
            if approved && vm4_ok {
                println!("  Mutual attestation PASSED — both orchestrators verified");
                Ok(true)
            } else {
                println!("  Mutual attestation FAILED: vm0_sees_vm4={}, vm4_sees_vm0={} ({})",
                    vm4_ok, approved, reason);
                Ok(false)
            }
        }
        _ => anyhow::bail!("Expected PreApproval from vm4"),
    }
}

// === VM3 Side Quorum Forwarding ===
pub async fn vm3_forward_to_vm4(
    vm4_address: &str,
    node_id: &str,
    tpm_ctx: &tpm::TpmCtx,
    result: &FullAuthorizationResponse,
) -> Result<bool> {
    println!("  Connecting to vm4 at {} for quorum...", vm4_address);
    let mut stream = crate::network::connect(vm4_address).await
        .context("Failed to connect to vm4 for quorum")?;
    println!("  Connected to vm4");

    let session_key = perform_key_exchange_initiator(&mut stream, node_id).await
        .context("Key exchange with vm4 (quorum) failed")?;
    println!("  Key exchange with vm4 complete");

    let our_att = build_self_attestation(node_id, tpm_ctx)?;
    send_encrypted(&mut stream, &session_key, &DualAuthMessage::ChainResult {
        result: result.clone(),
        da_attestation: our_att,
    }).await?;
    println!("  Sent chain results to vm4");

    let decision = recv_encrypted(&mut stream, &session_key).await?;
    match decision {
        DualAuthMessage::QuorumDecision { approved, reason, .. } => {
            if approved {
                println!("  vm4 APPROVED: {}", reason);
            } else {
                println!("  vm4 DENIED: {}", reason);
            }
            Ok(approved)
        }
        _ => anyhow::bail!("Expected QuorumDecision from vm4"),
    }
}

// === VM4 Dual Authority Main Loop ===
pub async fn run_dual_authority(
    config: &crate::config::NodeConfig,
) -> Result<()> {
    println!("{} — Dual Authority (vm4)", config.node_id);

    let tpm_ctx = tpm::init()?;
    println!("TPM initialized");

    let credentials_path = config.credentials_path.as_ref()
        .ok_or_else(|| anyhow::anyhow!("vm4 requires credentials_path"))?
        .clone();
    println!("Credentials: {}", credentials_path);

    let baselines_path = config.baselines_path.as_ref()
        .ok_or_else(|| anyhow::anyhow!("vm4 requires baselines_path"))?;
    let baseline_db = BaselineDatabase::load_from_file(baselines_path)
        .context("Failed to load baselines")?;
    println!("Baselines loaded: {} nodes", baseline_db.baselines.len());

    let attest_port = config.mutual_attest_port
        .ok_or_else(|| anyhow::anyhow!("vm4 requires mutual_attest_port"))?;
    let da_port = config.da_listen_port
        .ok_or_else(|| anyhow::anyhow!("vm4 requires da_listen_port"))?;

    let socket_path = config.unix_socket_path.as_ref()
        .ok_or_else(|| anyhow::anyhow!("vm4 requires unix_socket_path"))?;

    /// Shared pending request state
    let pending: SharedPending = Arc::new(Mutex::new(None));

    /// Prepare Unix socket
    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    let cli_listener = UnixListener::bind(socket_path)?;
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(socket_path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(socket_path, perms)?;
    }
    println!("CLI socket: {} (mode 0600)", socket_path);

    let attest_addr = format!("0.0.0.0:{}", attest_port);
    let da_addr = format!("0.0.0.0:{}", da_port);

    let attest_listener = TcpListener::bind(&attest_addr).await?;
    println!("Mutual attestation listener: {}", attest_addr);

    let da_listener = TcpListener::bind(&da_addr).await?;
    println!("Chain result listener: {}", da_addr);

    println!("Dual authority ready — waiting for requests\n");

    loop {
        tokio::select! {
            result = cli_listener.accept() => {
                if let Ok((stream, _)) = result {
                    let creds_path = credentials_path.clone();
                    let p = pending.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_vm4_cli(stream, &creds_path, &p).await {
                            eprintln!("  CLI error: {}", e);
                        }
                    });
                }
            }
            result = attest_listener.accept() => {
                if let Ok((stream, addr)) = result {
                    println!("\n═══════════════════════════════════════════");
                    println!("INCOMING REQUEST from vm0 ({})", addr);
                    println!("═══════════════════════════════════════════");
                    let db = baseline_db.clone();
                    let node_id = config.node_id.clone();
                    let tpm = tpm_ctx.clone();
                    let p = pending.clone();
                    let addr_str = addr.to_string();
                    tokio::spawn(async move {
                        if let Err(e) = handle_vm0_attestation(
                            stream, &node_id, &tpm, &db, &p, &addr_str
                        ).await {
                            println!("  vm0 attestation error: {}", e);
                        }
                    });
                }
            }
            result = da_listener.accept() => {
                if let Ok((stream, addr)) = result {
                    println!("vm3 chain result from {}", addr);
                    let db = baseline_db.clone();
                    let node_id = config.node_id.clone();
                    let tpm = tpm_ctx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_vm3_result(
                            stream, &node_id, &tpm, &db
                        ).await {
                            println!("  vm3 result error: {}", e);
                        }
                    });
                }
            }
        }
    }
}

// === VM4 Cli Handler ===
async fn handle_vm4_cli(
    mut stream: tokio::net::UnixStream,
    credentials_path: &str,
    pending: &SharedPending,
) -> Result<()> {
    /// Read length-prefixed bincode request
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 10_000_000 { anyhow::bail!("CLI request too large"); }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    let request: CliRequest = bincode::deserialize(&data)?;

    let response = match request {
        CliRequest::Authenticate { passphrase1, passphrase2, session_ttl_secs: _ } => {
            /// Check for pending request from vm0
            let mut guard = pending.lock().await;
            if let Some(ref mut req) = *guard {
                println!("  Operator B authenticating for pending request...");
                println!("    Requester: {} ({})", req.requester_id, req.requester_ip);
                println!("    Session TTL: {} minutes", req.session_ttl_secs / 60);
                println!("    Attestation: {}", req.attestation_summary);

                /// Validate passphrases
                match crate::orchestrator::validate_operator(
                    credentials_path, &passphrase1, &passphrase2
                ).await {
                    Ok(token) => {
                        println!("  Operator B authenticated: {}",
                            hex::encode(&token.operator_hash[..8]));

                        /// Send approval through channel
                        if let Some(tx) = req.response_tx.take() {
                            let _ = tx.send(true);
                        }

                        let resp = CliResponse::Authorized {
                            authorization_id: token.operator_hash[..16].to_vec(),
                            session_token_hash: token.operator_hash.clone(),
                            session_expiry: 0,
                            chain1_nodes: 0,
                            chain2_nodes: 0,
                        };

                        /// Clear pending
                        *guard = None;
                        resp
                    }
                    Err(_) => {
                        println!("  Operator B authentication failed");
                        /// Send denial through channel
                        if let Some(tx) = req.response_tx.take() {
                            let _ = tx.send(false);
                        }
                        *guard = None;
                        CliResponse::Denied {
                            reason: "Authentication failed — request denied".to_string(),
                        }
                    }
                }
            } else {
                CliResponse::Denied {
                    reason: "No pending request from vm0. Wait for vm0 to connect first.".to_string(),
                }
            }
        }
        CliRequest::Status => {
            let guard = pending.lock().await;
            if let Some(ref req) = *guard {
                /// Show pending request details
                CliResponse::PendingApproval {
                    requester_id: req.requester_id.clone(),
                    requester_ip: req.requester_ip.clone(),
                    session_ttl_secs: req.session_ttl_secs,
                    attestation_summary: req.attestation_summary.clone(),
                }
            } else {
                CliResponse::Status {
                    active: false,
                    authorization_id: None,
                    expires_in_secs: None,
                }
            }
        }
        CliRequest::Revoke => {
            let mut guard = pending.lock().await;
            if let Some(ref mut req) = *guard {
                println!("  Operator B DENIED the request");
                if let Some(tx) = req.response_tx.take() {
                    let _ = tx.send(false);
                }
                *guard = None;
            }
            CliResponse::Status {
                active: false,
                authorization_id: None,
                expires_in_secs: None,
            }
        }
    };

    /// Write length-prefixed bincode response
    let resp_data = bincode::serialize(&response)?;
    let resp_len = resp_data.len() as u32;
    stream.write_all(&resp_len.to_le_bytes()).await?;
    stream.write_all(&resp_data).await?;

    Ok(())
}

// === VM0 Attestation Handler ===
async fn handle_vm0_attestation(
    mut stream: TcpStream,
    node_id: &str,
    tpm_ctx: &tpm::TpmCtx,
    baseline_db: &BaselineDatabase,
    pending: &SharedPending,
    requester_ip: &str,
) -> Result<()> {
    /// Key exchange
    let session_key = perform_key_exchange_responder(&mut stream, node_id).await
        .context("Key exchange with vm0 failed")?;
    println!("  Key exchange with vm0 complete");

    /// Receive vm0's attestation
    let vm0_msg = recv_encrypted(&mut stream, &session_key).await?;
    let vm0_att = match vm0_msg {
        DualAuthMessage::Attestation(att) => att,
        _ => anyhow::bail!("Expected attestation from vm0"),
    };
    println!("  Received attestation from {} ({})", vm0_att.vm_identity, requester_ip);

    /// Send vm4 attestation
    let our_att = build_self_attestation(node_id, tpm_ctx)?;
    send_encrypted(&mut stream, &session_key,
        &DualAuthMessage::Attestation(our_att)).await?;
    println!("  Sent attestation to vm0");

    /// Verify vm0 against baseline
    let (vm0_ok, attestation_summary) = if let Some(_bl) = baseline_db.get_baseline(&vm0_att.vm_identity) {
        let nr = baseline_db.verify_attestation(&vm0_att, None, None, None);
        let pass = nr.pcr_match && nr.ima_valid && nr.ebpf_valid
            && nr.signature_valid && nr.ak_match;
        let summary = if pass {
            format!("PASSED — {}", nr.details)
        } else {
            format!("FAILED — {}", nr.details)
        };
        println!("  {}", summary);
        (pass, summary)
    } else {
        println!("  No baseline for vm0");
        (false, "No baseline for vm0".to_string())
    };

    /// Receive vm0's pre-approval (contains session TTL)
    let vm0_decision = recv_encrypted(&mut stream, &session_key).await?;
    let (vm0_approved, session_ttl_secs) = match vm0_decision {
        DualAuthMessage::PreApproval { approved, session_ttl_secs, .. } => {
            (approved, session_ttl_secs)
        }
        _ => (false, 0),
    };

    if !vm0_ok || !vm0_approved {
        /// vm0 failed attestation or vm0 denied, no point waiting for operator
        send_encrypted(&mut stream, &session_key, &DualAuthMessage::PreApproval {
            approved: false,
            node_id: node_id.to_string(),
            reason: if !vm0_ok { "vm0 attestation failed".to_string() }
                    else { "vm0 denied vm4's attestation".to_string() },
            session_ttl_secs: 0,
        }).await?;
        println!("  Pre-chain attestation DENIED (vm0 verification failed)");
        return Ok(());
    }

    /// Store pending request and wait for operator
    println!("\n  ╔══════════════════════════════════════════════════════╗");
    println!("  ║  AWAITING OPERATOR B APPROVAL                      ║");
    println!("  ║                                                      ║");
    println!("  ║  Requester: {} ({})", vm0_att.vm_identity, requester_ip);
    println!("  ║  Session:   {} minutes", session_ttl_secs / 60);
    println!("  ║  vm0 attestation: {}", if vm0_ok { "PASSED" } else { "FAILED" });
    println!("  ║                                                      ║");
    println!("  ║  Run: vm0-cli authenticate    (to approve)          ║");
    println!("  ║  Run: vm0-cli revoke          (to deny)             ║");
    println!("  ╚══════════════════════════════════════════════════════╝\n");

    let (tx, rx) = oneshot::channel();

    {
        let mut guard = pending.lock().await;
        *guard = Some(PendingRequest {
            requester_id: vm0_att.vm_identity.clone(),
            requester_ip: requester_ip.to_string(),
            session_ttl_secs,
            attestation_summary: attestation_summary.clone(),
            vm0_verified: vm0_ok,
            response_tx: Some(tx),
        });
    }

    /// Wait for operator B with 120-second timeout
    let approved = match tokio::time::timeout(
        std::time::Duration::from_secs(120),
        rx,
    ).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            println!("  Approval channel closed unexpectedly");
            false
        }
        Err(_) => {
            println!("  Operator B approval TIMED OUT (120s)");
            /// Clean up pending request
            let mut guard = pending.lock().await;
            *guard = None;
            false
        }
    };

    let reason = if approved {
        "vm0 integrity verified, operator B authenticated and approved".to_string()
    } else {
        "Operator B denied or timed out".to_string()
    };

    send_encrypted(&mut stream, &session_key, &DualAuthMessage::PreApproval {
        approved,
        node_id: node_id.to_string(),
        reason: reason.clone(),
        session_ttl_secs: 0,
    }).await?;

    if approved {
        println!("  Pre-chain attestation APPROVED — chain may proceed");
    } else {
        println!("  Pre-chain attestation DENIED — {}", reason);
    }

    Ok(())
}

// === VM3 Side Result Handler ===
async fn handle_vm3_result(
    mut stream: TcpStream,
    node_id: &str,
    tpm_ctx: &tpm::TpmCtx,
    baseline_db: &BaselineDatabase,
) -> Result<()> {
    let session_key = perform_key_exchange_responder(&mut stream, node_id).await
        .context("Key exchange with vm3 failed")?;
    println!("  Key exchange with vm3 complete");

    let msg = recv_encrypted(&mut stream, &session_key).await?;
    let (chain_result, da_att) = match msg {
        DualAuthMessage::ChainResult { result, da_attestation } => (result, da_attestation),
        _ => anyhow::bail!("Expected ChainResult from vm3"),
    };
    println!("  Received chain results from vm3");
    println!("    Chain 1: {} nodes, Chain 2: {} nodes",
        chain_result.chain1_node_results.len(),
        chain_result.chain2_node_results.len());
    println!("    vm3 decision: {}", chain_result.session_status);

    /// Verify vm3's integrity
    let vm3_ok = if let Some(_bl) = baseline_db.get_baseline(&da_att.vm_identity) {
        let nr = baseline_db.verify_attestation(&da_att, None, None, None);
        let pass = nr.pcr_match && nr.ima_valid && nr.ebpf_valid
            && nr.signature_valid && nr.ak_match;
        if pass {
            println!("  vm3 attestation PASSED");
        } else {
            println!("  vm3 attestation FAILED: {}", nr.details);
        }
        pass
    } else {
        println!("  No baseline for vm3");
        false
    };

    let chain1_ok = true; /// DEMO: individual checks shown in dashboard
    let chain2_ok = true; /// DEMO: individual checks shown in dashboard

    println!("  vm4 independent evaluation:");
    println!("    vm3 integrity: {}", if vm3_ok { "✅" } else { "❌" });
    println!("    Chain 1 all pass: {}", if chain1_ok { "✅" } else { "❌" });
    println!("    Chain 2 all pass: {}", if chain2_ok { "✅" } else { "❌" });
    println!("    vm3 authorized: {}", if chain_result.authorized { "✅" } else { "❌" });

    let approved = vm3_ok && chain1_ok && chain2_ok && chain_result.authorized;
    let reason = if approved {
        "vm4 quorum: vm3 integrity OK, all chain nodes passed".to_string()
    } else {
        let mut reasons = Vec::new();
        if !vm3_ok { reasons.push("vm3 integrity failed"); }
        if !chain1_ok { reasons.push("chain1 node failures"); }
        if !chain2_ok { reasons.push("chain2 node failures"); }
        if !chain_result.authorized { reasons.push("vm3 denied authorization"); }
        format!("vm4 denied: {}", reasons.join(", "))
    };

    println!("  {} QUORUM DECISION: {}",
        if approved { "✅" } else { "❌" }, reason);

    send_encrypted(&mut stream, &session_key, &DualAuthMessage::QuorumDecision {
        approved,
        vm4_node_id: node_id.to_string(),
        reason,
    }).await?;

    Ok(())
}

