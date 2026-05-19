use anyhow::Result;
use std::collections::HashMap;
use std::time::Instant;
use anyhow::Context;
use mfa_agent::{tpm, network, protocol, crypto, config};
use config::{NodeConfig, NodeRole};
use tokio::net::TcpStream;
use tokio::net::UnixListener;
use tokio::time::{Duration, timeout, interval};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use protocol::{
    BaselineDatabase, ProtocolMessage, Attestation, ChainPacket,
    ExtendCircuit, ExtendedCircuit, RelayCell, RelayCellPayload, RelayCommand,
    VerificationResponse, SessionStatus,
    NodeVerificationResult, Chain2Packet, FullAuthorizationResponse,
};
use mfa_agent::audit::{AuditLogger, AuditEvent, extract_attestation_meta, AttestationMeta};
use mfa_agent::orchestrator::{
    InitiatePayload, sign_initiate,
    verify_initiate, ReplayCache,
    SessionTokenReturn, OrchestratorMessage,
    CliRequest, CliResponse,
};

const HEARTBEAT_INTERVAL_SECS: u64 = 60;
const AUDIT_LOG_PATH: &str = "audit.jsonl";

// === Main entry point ===
#[tokio::main]
async fn main() -> Result<()> {
    let config_path = std::env::args().nth(1);
    let config = NodeConfig::load(config_path.as_deref())?;
    /// Register role with ebpf module so integrity checks use correct manifest
    mfa_agent::ebpf::set_node_role(&config.role.to_string());
    config.print_summary();
    println!();
    match config.role {
        NodeRole::Client => run_client(&config).await?,
        NodeRole::Proxy => run_proxy(&config).await?,
        NodeRole::Zts => run_zts(&config).await?,
        NodeRole::Da => run_da(&config).await?,
        NodeRole::Orchestrator => {
            if config.mutual_attest_port.is_some() {
                /// vm4, dual authority listener
                mfa_agent::dual_authority::run_dual_authority(&config).await?
            } else {
                // vm0, primary orchestrator
                run_orchestrator(&config).await?
            }
        }
    }
    Ok(())
}


// ===== Shared Helpers =====
fn wrap_payload_for_hop(
    session_keys: &[[u8; 32]],
    target_depth: usize,
    payload: &RelayCellPayload,
) -> Result<Vec<u8>> {
    let mut encrypted = crypto::encrypt(
        &session_keys[target_depth],
        &bincode::serialize(payload)?,
    )?;
    for i in (0..target_depth).rev() {
        let wrapper = RelayCellPayload {
            command: RelayCommand::Data(vec![]),
            next_hop: None,
            inner_cell: Some(encrypted),
        };
        encrypted = crypto::encrypt(
            &session_keys[i],
            &bincode::serialize(&wrapper)?,
        )?;
    }
    Ok(encrypted)
}

fn unwrap_response_from_hop(
    session_keys: &[[u8; 32]],
    target_depth: usize,
    encrypted: &[u8],
) -> Result<RelayCellPayload> {
    let mut data = encrypted.to_vec();
    for i in 0..target_depth {
        let decrypted = crypto::decrypt(&session_keys[i], &data)?;
        let payload: RelayCellPayload = bincode::deserialize(&decrypted)?;
        data = payload.inner_cell
            .ok_or_else(|| anyhow::anyhow!("Expected inner_cell at layer {}", i))?;
    }
    let decrypted = crypto::decrypt(&session_keys[target_depth], &data)?;
    let payload: RelayCellPayload = bincode::deserialize(&decrypted)?;
    Ok(payload)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ===== Circuit Building =====
/// Build a telescoping circuit from a list of hops
async fn build_circuit(
    conn: &mut TcpStream,
    hops: &[config::CircuitHop],
) -> Result<(Vec<[u8; 32]>, Vec<String>)> {
    let mut session_keys: Vec<[u8; 32]> = Vec::new();
    let mut node_ids: Vec<String> = Vec::new();

    for (i, hop) in hops.iter().enumerate() {
        if i == 0 {
            println!("\n[{}/{}] Direct handshake with {} ({})",
                i + 1, hops.len(), hop.node_id, hop.address);
            let key = do_extend_direct(conn, &hop.node_id).await?;
            session_keys.push(key);
            node_ids.push(hop.node_id.clone());
            println!("  K{} established with {}", i + 1, hop.node_id);
        } else {
            println!("\n[{}/{}] Extending to {} through {} hop(s)",
                i + 1, hops.len(), hop.node_id, i);
            let key = do_extend_relay(
                conn, &session_keys, &hop.node_id, &hop.address, i - 1,
            ).await?;
            session_keys.push(key);
            node_ids.push(hop.node_id.clone());
            println!("  K{} established with {}", i + 1, hop.node_id);
        }
    }

    Ok((session_keys, node_ids))
}

async fn do_extend_direct(conn: &mut TcpStream, target_id: &str) -> Result<[u8; 32]> {
    let (init, kyber_sk, x25519_secret, nonce) =
        crypto::generate_key_exchange_init("vm1")?;
    let init_clone = init.clone();
    let extend = ExtendCircuit {
        target_id: target_id.to_string(),
        kyber_pk: init.kyber_pk,
        x25519_pk: init.x25519_pk,
        nonce: init.nonce,
    };
    network::send_message(conn, &ProtocolMessage::ExtendCircuit(extend)).await?;
    println!("  Sent EXTEND");
    let response = network::receive_message(conn).await?;
    if let ProtocolMessage::ExtendedCircuit(extended) = response {
        println!("  EXTENDED from {}", extended.responder_id);
        let resp = crypto::KeyExchangeResponse {
            responder_id: extended.responder_id,
            kyber_ct: extended.kyber_ct,
            x25519_pk: extended.x25519_pk,
        };
        let keys = crypto::complete_key_exchange(&init_clone, &resp, &kyber_sk, x25519_secret, &nonce)?;
        Ok(keys.session_key)
    } else {
        Err(anyhow::anyhow!("Expected ExtendedCircuit"))
    }
}

async fn do_extend_relay(
    conn: &mut TcpStream,
    session_keys: &[[u8; 32]],
    target_id: &str,
    target_addr: &str,
    last_hop_depth: usize,
) -> Result<[u8; 32]> {
    let (init, kyber_sk, x25519_secret, nonce) =
        crypto::generate_key_exchange_init("vm1")?;
    let init_clone = init.clone();
    let extend = ExtendCircuit {
        target_id: target_id.to_string(),
        kyber_pk: init.kyber_pk,
        x25519_pk: init.x25519_pk,
        nonce: init.nonce,
    };
    let payload = RelayCellPayload {
        command: RelayCommand::Extend(extend),
        next_hop: Some(target_addr.to_string()),
        inner_cell: None,
    };
    let encrypted = wrap_payload_for_hop(session_keys, last_hop_depth, &payload)?;
    network::send_message(conn, &ProtocolMessage::RelayCell(RelayCell {
        encrypted_payload: encrypted,
    })).await?;
    println!("  Sent RELAY[EXTEND {}] ({} layers)", target_id, last_hop_depth + 1);
    let response = network::receive_message(conn).await?;
    if let ProtocolMessage::RelayCell(relay) = response {
        let resp_payload = unwrap_response_from_hop(
            session_keys, last_hop_depth, &relay.encrypted_payload
        )?;
        if let RelayCommand::Extended(extended) = resp_payload.command {
            println!("  EXTENDED from {}", extended.responder_id);
            let resp = crypto::KeyExchangeResponse {
                responder_id: extended.responder_id,
                kyber_ct: extended.kyber_ct,
                x25519_pk: extended.x25519_pk,
            };
            let keys = crypto::complete_key_exchange(&init_clone, &resp, &kyber_sk, x25519_secret, &nonce)?;
            Ok(keys.session_key)
        } else {
            Err(anyhow::anyhow!("Expected Extended for {}", target_id))
        }
    } else {
        Err(anyhow::anyhow!("Expected RelayCell"))
    }
}

async fn request_attestation(
    conn: &mut TcpStream,
    session_keys: &[[u8; 32]],
    target_depth: usize,
) -> Result<Attestation> {
    let payload = RelayCellPayload {
        command: RelayCommand::AttestationRequest,
        next_hop: None,
        inner_cell: None,
    };
    let encrypted = wrap_payload_for_hop(session_keys, target_depth, &payload)?;
    network::send_message(conn, &ProtocolMessage::RelayCell(RelayCell {
        encrypted_payload: encrypted,
    })).await?;
    let response = network::receive_message(conn).await?;
    if let ProtocolMessage::RelayCell(relay) = response {
        let resp_payload = unwrap_response_from_hop(
            session_keys, target_depth, &relay.encrypted_payload
        )?;
        if let RelayCommand::AttestationResponse(att) = resp_payload.command {
            Ok(att)
        } else {
            Err(anyhow::anyhow!("Expected AttestationResponse at depth {}", target_depth))
        }
    } else {
        Err(anyhow::anyhow!("Expected RelayCell"))
    }
}

/// Collect attestations from proxy hops (not the last hop which is endpoint)
async fn collect_proxy_attestations(
    conn: &mut TcpStream,
    session_keys: &[[u8; 32]],
    node_ids: &[String],
) -> Result<Vec<(String, Attestation)>> {
    let proxy_count = session_keys.len() - 1;
    let mut attestations = Vec::new();

    for depth in 0..proxy_count {
        println!("  Requesting attestation from {} (depth {})...", node_ids[depth], depth);
        let att = request_attestation(conn, session_keys, depth).await?;
        println!("    {} PCRs, {} IMA, {} procs",
            att.tpm_quote.pcr_values.len(),
            att.tpm_quote.ima_measurements.count,
            att.tpm_quote.ebpf_state.process_count);
        attestations.push((node_ids[depth].clone(), att));
    }

    Ok(attestations)
}

// ===== Client (VM1) =====
async fn run_client(config: &NodeConfig) -> Result<()> {
    println!("{} — Verified Client (waiting for INITIATE)", config.node_id);
    let tpm_ctx = tpm::init()?;
    println!("TPM initialized");
    let initiate_port = config.initiate_port.unwrap_or(9003);
    /// Load expected vm0 AK public key if configured
    let expected_vm0_ak = match &config.vm0_ak_public_path {
        Some(path) => match std::fs::read(path) {
            Ok(bytes) => {
                println!("vm0 AK public key loaded ({} bytes)", bytes.len());
                Some(bytes)
            }
            Err(e) => {
                eprintln!("Cannot read vm0_ak_public ({}): {}", path, e);
                eprintln!("    Proceeding WITHOUT AK verification (FIRST-RUN mode)");
                eprintln!("    vm1 will capture AK from first INITIATE for future verification");
                None
            }
        },
        None => {
            eprintln!("No vm0_ak_public_path configured — AK match check disabled");
            None
        }
    };
    let bind_addr = format!("0.0.0.0:{}", initiate_port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await
        .with_context(|| format!("Failed to bind INITIATE port {}", initiate_port))?;
    println!("Listening for INITIATE on {}", bind_addr);
    let mut replay_cache = ReplayCache::new();
    println!("Waiting for authorization from vm0...\n");
    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("Accept error: {}", e);
                continue;
            }
        };
        println!("Incoming INITIATE connection from {}", peer);
        match handle_initiate_connection(
            &mut stream,
            config,
            &tpm_ctx,
            &mut replay_cache,
            expected_vm0_ak.as_deref(),
        ).await {
            Ok(()) => println!("Authorization flow complete\n"),
            Err(e) => eprintln!("Authorization flow failed: {}\n", e),
        }
    }
}


// === Single authorization flow === 
///one INITIATE → chain → session token)
async fn handle_initiate_connection(
    stream: &mut tokio::net::TcpStream,
    config: &NodeConfig,
    tpm_ctx: &tpm::TpmCtx,
    replay_cache: &mut ReplayCache,
    expected_vm0_ak: Option<&[u8]>,
) -> Result<()> {
    /// Steps 1-6: Key exchange, attestation, verify INITIATE, replay check 
    println!("  Key exchange...");
    let session_key = perform_vm1_key_exchange(stream, &config.node_id).await?;
    println!("  Session established");
    let msg = recv_orch_message(stream, &session_key).await?;
    let nonce = match msg {
        OrchestratorMessage::AttestationRequest { nonce } => nonce,
        other => anyhow::bail!("Expected AttestationRequest, got {:?}", other),
    };
    println!("  AttestationRequest received (nonce {} bytes)", nonce.len());
    let quote = tpm::generate_quote(tpm_ctx)?;
    let attestation = Attestation {
        vm_identity: config.node_id.clone(),
        tpm_quote: quote,
        timestamp: now_secs(),
    };
    send_orch_message(stream, &session_key,
        &OrchestratorMessage::AttestationResponse(attestation)).await?;
    println!("  Attestation sent");
    let msg = recv_orch_message(stream, &session_key).await?;
    let signed = match msg {
        OrchestratorMessage::Initiate(s) => s,
        other => anyhow::bail!("Expected Initiate, got {:?}", other),
    };
    match verify_initiate(&signed, expected_vm0_ak) {
        Ok(()) => (),
        Err(rejection) => {
            let reason = format!("{}", rejection);
            println!("  INITIATE rejected: {}", reason);
            send_orch_message(stream, &session_key,
                &OrchestratorMessage::InitiateRejected { reason: reason.clone() }).await?;
            anyhow::bail!("INITIATE rejected: {}", reason);
        }
    }
    if !replay_cache.check_and_record(&signed.payload.authorization_id) {
        let reason = "authorization_id already used (replay)".to_string();
        println!("  {}", reason);
        send_orch_message(stream, &session_key,
            &OrchestratorMessage::InitiateRejected { reason: reason.clone() }).await?;
        anyhow::bail!(reason);
    }
    let authorization_id = signed.payload.authorization_id.clone();
    let session_ttl_secs = signed.payload.session_ttl_secs;
    let session_expiry = now_secs() + session_ttl_secs;

    println!("  INITIATE accepted (auth_id={})", signed.payload.short_auth_id());
    println!("     session_ttl = {} seconds", session_ttl_secs);
    println!("     operator = {}", hex::encode(&signed.payload.operator_hash[..8]));

    send_orch_message(stream, &session_key, &OrchestratorMessage::InitiateAck {
        authorization_id: authorization_id.clone(),
    }).await?;
    /// Step 7: Execute chain establishment 
    println!("\n============================================================");
    println!("  AUTHORIZED CHAIN ESTABLISHMENT");
    println!("============================================================");

    let chain_result = match execute_chain_establishment(config, tpm_ctx).await {
        Ok(r) => r,
        Err(e) => {
            let reason = format!("Chain establishment failed: {}", e);
            send_orch_message(stream, &session_key,
                &OrchestratorMessage::ChainFailed {
                    authorization_id: authorization_id.clone(),
                    reason: reason.clone(),
                }).await?;
            anyhow::bail!(reason);
        }
    };

    if !chain_result.authorized {
        send_orch_message(stream, &session_key,
            &OrchestratorMessage::ChainFailed {
                authorization_id: authorization_id.clone(),
                reason: "Chain completed but not authorized".to_string(),
            }).await?;
        anyhow::bail!("Chain not authorized");
    }

    let mut chain_conn = chain_result.chain_conn
        .ok_or_else(|| anyhow::anyhow!("Chain connection not preserved"))?;
    let chain_session_keys = chain_result.chain_session_keys
        .ok_or_else(|| anyhow::anyhow!("Chain session keys not preserved"))?;
    let chain_circuit_node_ids = chain_result.chain_circuit_node_ids
        .ok_or_else(|| anyhow::anyhow!("Chain circuit node IDs not preserved"))?;

    /// Step 8: Send SessionTokenReturn 
    let token_return = SessionTokenReturn {
        authorization_id: authorization_id.clone(),
        session_token: chain_result.session_token.clone().unwrap_or_default(),
        session_expiry,
        chain1_node_count: chain_result.chain1_nodes,
        chain2_node_count: chain_result.chain2_nodes,
        authorized: true,
    };

    send_orch_message(stream, &session_key,
        &OrchestratorMessage::SessionToken(token_return)).await?;
    println!("  SessionTokenReturn sent to vm0");

    /// Step 9: Heartbeat loop for session duration
    println!("\n============================================================");
    println!("  HEARTBEAT LOOP ACTIVE");
    println!("  TTL: {} seconds | Expiry: unix {}", session_ttl_secs, session_expiry);
    println!("============================================================\n");
    /// IMA delta tracker across heartbeats for this session
    let session_end_time = tokio::time::Instant::now() +
        tokio::time::Duration::from_secs(session_ttl_secs);
        
    let end_reason = loop {
        /// Sleep until one of: TTL expiry, heartbeat timer, or vm0 message
        tokio::select! {
            _ = tokio::time::sleep_until(session_end_time) => {
                break "TTL expired".to_string();
            }
            result = recv_orch_message(stream, &session_key) => {
                match result {
                    Ok(OrchestratorMessage::HeartbeatPing { sequence }) => {
                        println!("  HeartbeatPing #{} received", sequence);
                        /// Run chain heartbeat through preserved connection
                        let hb_result = match heartbeat_chain1(
                            &mut chain_conn,
                            &chain_session_keys,
                            tpm_ctx,
                            &config.node_id,
                            &chain_circuit_node_ids,
                        ).await {
                            Ok(status) => {
                                let ok = matches!(status,
                                    SessionStatus::Authorized | SessionStatus::Provisional);
                                (ok, format!("chain heartbeat: {:?}", status))
                            }
                            Err(e) => (false, format!("heartbeat error: {}", e)),
                        };
                        let response = OrchestratorMessage::HeartbeatResult {
                            sequence,
                            chain_ok: hb_result.0,
                            node_count: chain_circuit_node_ids.len() + 1,
                            details: hb_result.1.clone(),
                        };
                        if let Err(e) = send_orch_message(stream, &session_key, &response).await 
                            eprintln!("  Failed to send HeartbeatResult: {}", e);
                            break format!("connection error: {}", e);
                        }
                        if !hb_result.0 {
                            break format!("integrity failure: {}", hb_result.1);
                        }
                    }
                    Ok(OrchestratorMessage::Revoke { reason }) => {
                        println!("  Session REVOKE received: {}", reason);
                        break format!("revoked: {}", reason);
                    }
                    Ok(other) => {
                        eprintln!("  Unexpected message during session: {:?}", other);
                        /// Continue — don't terminate session on unexpected message
                    }
                    Err(e) => {
                        /// Connection closed or error — terminate session
                        println!("  vm0 connection closed: {}", e);
                        break format!("vm0 disconnect: {}", e);
                    }
                }
            }
        }
    };

    /// Step 10: Session teardown 
    println!("\n============================================================");
    println!("  SESSION ENDING: {}", end_reason);
    println!("============================================================");

    /// Try to notify vm0 (may fail if connection already closed)
    let _ = send_orch_message(stream, &session_key,
        &OrchestratorMessage::SessionEnded { reason: end_reason.clone() }).await;

    /// Chain connection will close when chain_conn drops
    drop(chain_conn);

    println!("Session ended cleanly\n");
    Ok(())
}

// === Chain execution helper ===
struct ChainExecutionResult {
    authorized: bool,
    session_token: Option<Vec<u8>>,
    chain1_nodes: usize,
    chain2_nodes: usize,
    /// Chain TCP connection (to pr1), must stay open for heartbeats
    chain_conn: Option<TcpStream>,
    /// Session keys for onion encryption to each hop in chain 1
    chain_session_keys: Option<Vec<[u8; 32]>>,
    /// Node IDs in chain 1 (for heartbeat attestation)
    chain_circuit_node_ids: Option<Vec<String>>,
}

async fn execute_chain_establishment(
    config: &NodeConfig,
    tpm_ctx: &tpm::TpmCtx,
) -> Result<ChainExecutionResult> {
    let entry_addr = config.entry_address()?;
    println!("Connecting to entry: {}", entry_addr);
    let mut conn = network::connect(entry_addr).await?;
    println!("Connected");

    println!("\n  PHASE 1: CIRCUIT ESTABLISHMENT ({} hops)", config.circuit.len());
    let (session_keys, circuit_node_ids) = build_circuit(&mut conn, &config.circuit).await?;
    println!("  CIRCUIT COMPLETE - {} session keys", session_keys.len());

    println!("\n  PHASE 2: ATTESTATION & VERIFICATION");
    let own_quote = tpm::generate_quote(tpm_ctx)?;

    let proxy_atts = collect_proxy_attestations(&mut conn, &session_keys, &circuit_node_ids).await?;

    let mut chain = ChainPacket::new(&config.node_id, own_quote);
    for (node_id, att) in &proxy_atts {
        chain.add_attestation(node_id, att.tpm_quote.clone());
    }

    let zts_depth = session_keys.len().saturating_sub(1);
    let submit = RelayCellPayload {
        command: RelayCommand::ChainSubmission(chain),
        next_hop: None,
        inner_cell: None,
    };
    let encrypted = wrap_payload_for_hop(&session_keys, zts_depth, &submit)?;
    network::send_message(&mut conn, &ProtocolMessage::RelayCell(RelayCell {
        encrypted_payload: encrypted,
    })).await?;
    println!("  Chain submitted to ZTS");

    let response = network::receive_message(&mut conn).await?;
    if let ProtocolMessage::RelayCell(relay) = response {
        let payload = unwrap_response_from_hop(&session_keys, zts_depth, &relay.encrypted_payload)?;
        match payload.command {
            RelayCommand::FullAuthorizationResult(full_result) => {
                println!("\n  FULL AUTH: {} | {}",
                    full_result.session_status,
                    if full_result.authorized { "AUTHORIZED" } else { "DENIED" });

                return Ok(ChainExecutionResult {
                    authorized: full_result.authorized,
                    session_token: full_result.session_token,
                    chain1_nodes: full_result.chain1_node_results.len(),
                    chain2_nodes: full_result.chain2_node_results.len(),
                    chain_conn: if full_result.authorized { Some(conn) } else { None },
                    chain_session_keys: if full_result.authorized { Some(session_keys) } else { None },
                    chain_circuit_node_ids: if full_result.authorized { Some(circuit_node_ids) } else { None },
                });
            }
            RelayCommand::VerificationResult(result) => {
                println!("\n  CHAIN 1 ONLY: {}", result.session_status);
                return Ok(ChainExecutionResult {
                    authorized: result.verified,
                    session_token: None,
                    chain1_nodes: result.node_results.len(),
                    chain2_nodes: 0,
                    chain_conn: if result.verified { Some(conn) } else { None },
                    chain_session_keys: if result.verified { Some(session_keys) } else { None },
                    chain_circuit_node_ids: if result.verified { Some(circuit_node_ids) } else { None },
                });
            }
            other => anyhow::bail!("Unexpected response: {:?}", other),
        }
    }

    anyhow::bail!("Did not receive expected RelayCell response");
}

// === Key exchange, responder side (vm1) ===
async fn perform_vm1_key_exchange(
    stream: &mut tokio::net::TcpStream,
    node_id: &str,
) -> anyhow::Result<[u8; 32]> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Receive init
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let init_len = u32::from_le_bytes(len_buf) as usize;
    if init_len > 10_000_000 {
        anyhow::bail!("init too large: {}", init_len);
    }
    let mut init_bytes = vec![0u8; init_len];
    stream.read_exact(&mut init_bytes).await?;
    let init: crypto::KeyExchangeInit = bincode::deserialize(&init_bytes)?;

    // Respond
    let (response, keys) = crypto::generate_key_exchange_response(node_id, &init)?;
    let resp_bytes = bincode::serialize(&response)?;
    let len = resp_bytes.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&resp_bytes).await?;

    Ok(keys.session_key)
}

async fn heartbeat_chain1(
    conn: &mut TcpStream,
    session_keys: &[[u8; 32]],
    tpm_ctx: &tpm::TpmCtx,
    own_node_id: &str,
    circuit_node_ids: &[String],
) -> Result<SessionStatus> {
    let own_quote = tpm::generate_quote(tpm_ctx)?;
    let mut chain = ChainPacket::new(own_node_id, own_quote);

    let proxy_count = session_keys.len() - 1;
    for depth in 0..proxy_count {
        let att = request_attestation(conn, session_keys, depth).await?;
        chain.add_attestation(&circuit_node_ids[depth], att.tpm_quote);
    }

    let zts_depth = session_keys.len() - 1;
    let submit = RelayCellPayload {
        command: RelayCommand::ChainSubmission(chain),
        next_hop: None,
        inner_cell: None,
    };
    let encrypted = wrap_payload_for_hop(session_keys, zts_depth, &submit)?;
    network::send_message(conn, &ProtocolMessage::RelayCell(RelayCell {
        encrypted_payload: encrypted,
    })).await?;

    let response = network::receive_message(conn).await?;
    if let ProtocolMessage::RelayCell(relay) = response {
        let payload = unwrap_response_from_hop(session_keys, zts_depth, &relay.encrypted_payload)?;
        match payload.command {
            RelayCommand::VerificationResult(result) => {
                if result.verified {
                    println!("{} nodes OK | {}", result.node_results.len(), result.session_status);
                } else {
                    println!("INTEGRITY FAILURE | {}", result.session_status);
                    for nr in &result.node_results {
                        if !nr.pcr_match || !nr.ima_valid || !nr.ebpf_valid
                            || !nr.signature_valid || !nr.ak_match {
                            println!("  {} → {}", nr.vm_identity, nr.details);
                        }
                    }
                }
                Ok(result.session_status)
            }
            RelayCommand::FullAuthorizationResult(result) => {
                if result.authorized {
                    let total = result.chain1_node_results.len() + result.chain2_node_results.len();
                    println!("{} nodes OK | {}", total, result.session_status);
                } else {
                    println!("AUTHORIZATION FAILURE | {}", result.session_status);
                }
                Ok(result.session_status)
            }
            _ => Err(anyhow::anyhow!("Unexpected heartbeat response")),
        }
    } else {
        Err(anyhow::anyhow!("Expected RelayCell"))
    }
}

// ===== Proxies =====
async fn run_proxy(config: &NodeConfig) -> Result<()> {
    let listen_addr = format!("0.0.0.0:{}", config.listen_port);
    println!("{} Proxy - Telescoping stateful relay", config.node_id);
    println!("Listening on {}", listen_addr);

    let tpm_ctx = tpm::init()?;
    println!("TPM initialized");

    let listener = network::listen(&listen_addr).await?;
    println!("Listening\n");

    loop {
        let mut upstream = network::accept(&listener).await?;
        let peer = upstream.peer_addr().map(|a| a.to_string()).unwrap_or("unknown".into());
        println!("Upstream: {}", peer);
        match handle_proxy_circuit(&config.node_id, &mut upstream, &tpm_ctx).await {
            Ok(()) => println!("Circuit closed"),
            Err(e) => eprintln!("Error: {}", e),
        }
        println!("Ready\n");
    }
}

async fn handle_proxy_circuit(
    proxy_id: &str,
    upstream: &mut TcpStream,
    tpm_ctx: &tpm::TpmCtx,
) -> Result<()> {
    let message = network::receive_message(upstream).await?;
    let session_key = match message {
        ProtocolMessage::ExtendCircuit(extend) => {
            println!("  EXTEND for {}", extend.target_id);
            let init = crypto::KeyExchangeInit {
                sender_id: "vm1".to_string(),
                kyber_pk: extend.kyber_pk,
                x25519_pk: extend.x25519_pk,
                nonce: extend.nonce,
            };
            let (response, keys) = crypto::generate_key_exchange_response(
                &proxy_id.to_lowercase(), &init
            )?;
            let extended = ExtendedCircuit {
                responder_id: proxy_id.to_lowercase(),
                kyber_ct: response.kyber_ct,
                x25519_pk: response.x25519_pk,
            };
            network::send_message(upstream, &ProtocolMessage::ExtendedCircuit(extended)).await?;
            println!("  EXTENDED - key established");
            keys.session_key
        }
        other => return Err(anyhow::anyhow!("Expected ExtendCircuit, got {:?}", other)),
    };

    let mut downstream: Option<TcpStream> = None;
    println!("  Relay loop active");

    loop {
        let message = match network::receive_message(upstream).await {
            Ok(msg) => msg,
            Err(e) => { println!("  Upstream closed: {}", e); break; }
        };

        match message {
            ProtocolMessage::RelayCell(relay) => {
                let decrypted = crypto::decrypt(&session_key, &relay.encrypted_payload)?;
                let payload: RelayCellPayload = bincode::deserialize(&decrypted)?;

                if let RelayCommand::Extend(ref extend_cmd) = payload.command {
                    let addr = payload.next_hop.as_ref()
                        .ok_or_else(|| anyhow::anyhow!("EXTEND missing next_hop"))?;
                    println!("  EXTEND → {} at {}", extend_cmd.target_id, addr);
                    let mut next = network::connect(addr).await?;
                    network::send_message(&mut next, &ProtocolMessage::ExtendCircuit(
                        extend_cmd.clone()
                    )).await?;
                    let resp = network::receive_message(&mut next).await?;
                    if let ProtocolMessage::ExtendedCircuit(extended) = resp {
                        println!("  EXTENDED from {}", extended.responder_id);
                        downstream = Some(next);
                        let rp = RelayCellPayload {
                            command: RelayCommand::Extended(extended),
                            next_hop: None, inner_cell: None,
                        };
                        let enc = crypto::encrypt(&session_key, &bincode::serialize(&rp)?)?;
                        network::send_message(upstream, &ProtocolMessage::RelayCell(RelayCell {
                            encrypted_payload: enc,
                        })).await?;
                    } else {
                        return Err(anyhow::anyhow!("Expected ExtendedCircuit"));
                    }
                } else if let Some(inner_cell) = payload.inner_cell {
                    let ds = downstream.as_mut()
                        .ok_or_else(|| anyhow::anyhow!("No downstream"))?;
                    network::send_message(ds, &ProtocolMessage::RelayCell(RelayCell {
                        encrypted_payload: inner_cell,
                    })).await?;
                    let resp = network::receive_message(ds).await?;
                    match resp {
                        ProtocolMessage::RelayCell(r) => {
                            let rp = RelayCellPayload {
                                command: RelayCommand::Data(vec![]),
                                next_hop: None, inner_cell: Some(r.encrypted_payload),
                            };
                            let enc = crypto::encrypt(&session_key, &bincode::serialize(&rp)?)?;
                            network::send_message(upstream, &ProtocolMessage::RelayCell(RelayCell {
                                encrypted_payload: enc,
                            })).await?;
                        }
                        ProtocolMessage::ExtendedCircuit(extended) => {
                            let rp = RelayCellPayload {
                                command: RelayCommand::Extended(extended),
                                next_hop: None, inner_cell: None,
                            };
                            let enc = crypto::encrypt(&session_key, &bincode::serialize(&rp)?)?;
                            network::send_message(upstream, &ProtocolMessage::RelayCell(RelayCell {
                                encrypted_payload: enc,
                            })).await?;
                        }
                        other => return Err(anyhow::anyhow!("Unexpected: {:?}", other)),
                    }
                } else if let RelayCommand::AttestationRequest = payload.command {
                    println!("  Attestation requested");
                    let quote = tpm::generate_quote(tpm_ctx)?;
                    let att = Attestation {
                        vm_identity: proxy_id.to_lowercase(),
                        tpm_quote: quote,
                        timestamp: now_secs(),
                    };
                    let rp = RelayCellPayload {
                        command: RelayCommand::AttestationResponse(att),
                        next_hop: None, inner_cell: None,
                    };
                    let enc = crypto::encrypt(&session_key, &bincode::serialize(&rp)?)?;
                    network::send_message(upstream, &ProtocolMessage::RelayCell(RelayCell {
                        encrypted_payload: enc,
                    })).await?;
                    println!("  Attestation → upstream");
                } else {
                    println!("  Other: {:?}", payload.command);
                }
            }
            other => println!("  Unexpected: {:?}", other),
        }
    }
    Ok(())
}

// === ZTS (VM2): Dual role: verify chain 1, then build chain 2 to VM3 ===

async fn run_zts(config: &NodeConfig) -> Result<()> {
    let listen_addr = format!("0.0.0.0:{}", config.listen_port);
    println!("{} ZTS - Zero Trust Server", config.node_id);
    if config.has_chain2() {
        println!("Chain 2 configured → will forward to distributed authority");
    }
    println!("Listening on {}", listen_addr);

    let baseline_db = match BaselineDatabase::load_from_file("baselines.json") {
        Ok(db) => {
            println!("Loaded baselines: {} VMs", db.baselines.len());
            Some(db)
        }
        Err(e) => {
            eprintln!("No baselines: {}", e);
            None
        }
    };

    let tpm_ctx = tpm::init()?;
    println!("TPM initialized");

    let listener = network::listen(&listen_addr).await?;
    println!("Listening\n");

    loop {
        let mut conn = network::accept(&listener).await?;
        let peer = conn.peer_addr().map(|a| a.to_string()).unwrap_or("unknown".into());
        println!("Connection from {}", peer);
        match handle_zts_circuit(&mut conn, &baseline_db, &tpm_ctx, config).await {
            Ok(()) => println!("Circuit closed"),
            Err(e) => eprintln!("Error: {}", e),
        }
        println!("Ready\n");
    }
}

async fn handle_zts_circuit(
    conn: &mut TcpStream,
    baseline_db: &Option<BaselineDatabase>,
    tpm_ctx: &tpm::TpmCtx,
    config: &NodeConfig,
) -> Result<()> {
    /// Key exchange with VM1 (via chain 1)
    let message = network::receive_message(conn).await?;
    let session_key = match message {
        ProtocolMessage::ExtendCircuit(extend) => {
            println!("  EXTEND for {} (endpoint)", extend.target_id);
            let init = crypto::KeyExchangeInit {
                sender_id: "vm1".to_string(),
                kyber_pk: extend.kyber_pk,
                x25519_pk: extend.x25519_pk,
                nonce: extend.nonce,
            };
            let (response, keys) = crypto::generate_key_exchange_response(&config.node_id, &init)?;
            let extended = ExtendedCircuit {
                responder_id: config.node_id.clone(),
                kyber_ct: response.kyber_ct,
                x25519_pk: response.x25519_pk,
            };
            network::send_message(conn, &ProtocolMessage::ExtendedCircuit(extended)).await?;
            println!("  EXTENDED - session key established");
            keys.session_key
        }
        other => return Err(anyhow::anyhow!("Expected ExtendCircuit, got {:?}", other)),
    };
    /// Build chain 2 if configured
    let mut chain2_state: Option<Chain2State> = None;

    if config.has_chain2() {
        println!("\n  Building Chain 2 to Distributed Authority...");
        let entry_addr = config.chain2_entry_address()?;
        let mut c2_conn = network::connect(entry_addr).await?;
        println!("  Connected to chain 2 entry: {}", entry_addr);

        let (c2_keys, c2_node_ids) = build_circuit(&mut c2_conn, &config.chain2_circuit).await?;
        println!("  Chain 2 circuit complete - {} keys", c2_keys.len());

        chain2_state = Some(Chain2State {
            conn: c2_conn,
            session_keys: c2_keys,
            node_ids: c2_node_ids,
        });
    }
    println!("  Waiting for attestation data...");
    let mut session_active = false;
    let mut verification_count: u64 = 0;
    /// IMA delta tracker: tracks per-node IMA count between heartbeats
    /// Key = node_id, Value = last seen IMA count
    /// Persists across heartbeats within a single circuit session
    let mut ima_tracker: HashMap<String, usize> = HashMap::new();
    let mut ima_agg_tracker: HashMap<String, Vec<u8>> = HashMap::new();
    let mut sysmon_tracker: HashMap<String, mfa_agent::sysmon::SysmonState> = HashMap::new();
    let mut audit_logger = AuditLogger::new(AUDIT_LOG_PATH, &config.node_id, config.log_mode);
    loop {
        let message = match network::receive_message(conn).await {
            Ok(msg) => msg,
            Err(e) => { println!("  Disconnected: {}", e); break; }
        };
        match message {
            ProtocolMessage::RelayCell(relay) => {
                let decrypted = crypto::decrypt(&session_key, &relay.encrypted_payload)?;
                let payload: RelayCellPayload = bincode::deserialize(&decrypted)?;

                match payload.command {
                    RelayCommand::ChainSubmission(chain) => {
                        verification_count += 1;
                        let is_heartbeat = session_active;
                        if !is_heartbeat {
                            println!("\n  CHAIN 1 VERIFICATION (#{}) - {} attestations",
                                verification_count, chain.attestations.len());
                        } else {
                            print!("  #{} ", verification_count);
                        }
                        /// Verify chain 1 with IMA delta tracking
                        let verify_start = Instant::now();
                        let chain1_result = verify_chain_against_db(
                            &chain, baseline_db, tpm_ctx, session_active,
                            &config.node_id, &mut ima_tracker, &mut ima_agg_tracker, &mut sysmon_tracker,
                        )?;
                        if !is_heartbeat {
                            for nr in &chain1_result.node_results {
                                let icon = if nr.pcr_match && nr.ima_valid && nr.ebpf_valid
                                    && nr.signature_valid && nr.ak_match { "✅" } else { "❌" };
                                println!("  {} [{}] {}", icon, nr.vm_identity, nr.details);
                            }
                        }
                        /// If chain 1 passes AND we have chain 2, forward to VM3
                        if chain1_result.verified && chain2_state.is_some() {
                            let c2 = chain2_state.as_mut().unwrap();

                            if !is_heartbeat {
                                println!("\n  FORWARDING TO DISTRIBUTED AUTHORITY (Chain 2)...");
                            }

                            let c2_proxy_atts = collect_proxy_attestations(
                                &mut c2.conn, &c2.session_keys, &c2.node_ids,
                            ).await?;
                            /// Extract chain 1 attestation metadata before data is consumed
                            let chain1_att_metas: Vec<AttestationMeta> = chain.attestations.iter()
                                .map(|a| extract_attestation_meta(a))
                                .collect();
                            let vm2_quote = tpm::generate_quote(tpm_ctx)?;
                            let vm2_att = Attestation {
                                vm_identity: config.node_id.clone(),
                                tpm_quote: vm2_quote,
                                timestamp: now_secs(),
                            };

                            let mut c2_attestations = vec![vm2_att];
                            for (node_id, att) in &c2_proxy_atts {
                                c2_attestations.push(Attestation {
                                    vm_identity: node_id.clone(),
                                    tpm_quote: att.tpm_quote.clone(),
                                    timestamp: att.timestamp,
                                });
                            }
                            /// Extract chain 2 attestation metadata before c2_attestations is moved
                            let chain2_att_metas: Vec<AttestationMeta> = c2_attestations.iter()
                                .map(|a| extract_attestation_meta(a))
                                .collect();
                            let chain2_id = {
                                use sha2::Digest;
                                sha2::Sha256::digest(
                                    format!("chain2-{}", now_secs()).as_bytes()
                                ).to_vec()
                            };
                            let c2_packet = Chain2Packet {
                                chain1_results: chain1_result.clone(),
                                chain2_attestations: c2_attestations,
                                chain2_id: chain2_id.clone(),
                                timestamp: now_secs(),
                            };
                            let da_depth = c2.session_keys.len() - 1;
                            let submit = RelayCellPayload {
                                command: RelayCommand::Chain2Submission(c2_packet),
                                next_hop: None,
                                inner_cell: None,
                            };
                            let enc = wrap_payload_for_hop(&c2.session_keys, da_depth, &submit)?;
                            network::send_message(&mut c2.conn, &ProtocolMessage::RelayCell(RelayCell {
                                encrypted_payload: enc,
                            })).await?;
                            let c2_response = network::receive_message(&mut c2.conn).await?;
                            if let ProtocolMessage::RelayCell(c2_relay) = c2_response {
                                let c2_payload = unwrap_response_from_hop(
                                    &c2.session_keys, da_depth, &c2_relay.encrypted_payload
                                )?;

                                if let RelayCommand::FullAuthorizationResult(full_result) = c2_payload.command {
                                    if !is_heartbeat {
                                        println!("\n  DISTRIBUTED AUTHORITY: {} | {}",
                                            full_result.session_status,
                                            if full_result.authorized { "AUTHORIZED" } else { "DENIED" });
                                    } else {
                                        let total = full_result.chain1_node_results.len()
                                            + full_result.chain2_node_results.len();
                                        if full_result.authorized {
                                            println!("{} nodes OK | {}", total, full_result.session_status);
                                        } else {
                                            println!("{} | {}", full_result.session_status,
                                                if full_result.authorized { "OK" } else { "FAIL" });
                                        }
                                    }

                                    if full_result.authorized {
                                        session_active = true;
                                    }
                                    /// AuditA Full authorization (both chains)
                                    let verify_elapsed = verify_start.elapsed().as_millis() as u64;
                                    let all_results: Vec<NodeVerificationResult> = full_result.chain1_node_results.iter()
                                        .chain(full_result.chain2_node_results.iter())
                                        .cloned()
                                        .collect();
                                    let all_metas: Vec<AttestationMeta> = chain1_att_metas.iter()
                                        .chain(chain2_att_metas.iter())
                                        .cloned()
                                        .collect();
                                    let _ = audit_logger.write(
                                        if full_result.authorized { AuditEvent::HeartbeatOk }
                                        else { AuditEvent::HeartbeatFail },
                                        verification_count,
                                        &chain.chain_id,
                                        &all_results,
                                        Some(&all_metas),
                                        1,
                                        &full_result.session_status.to_string(),
                                        full_result.authorized,
                                        Some(verify_elapsed),
                                        None, /// session_token_hash — add when token is available
                                        tpm_ctx,
                                    );                                                                   
                                   
                                    let resp_payload = RelayCellPayload {
                                        command: RelayCommand::FullAuthorizationResult(full_result),
                                        next_hop: None,
                                        inner_cell: None,
                                    };
                                    let enc = crypto::encrypt(
                                        &session_key, &bincode::serialize(&resp_payload)?
                                    )?;
                                    network::send_message(conn, &ProtocolMessage::RelayCell(RelayCell {
                                        encrypted_payload: enc,
                                    })).await?;
                                } else {
                                    return Err(anyhow::anyhow!("Expected FullAuthorizationResult from DA"));
                                }
                            }
                        } else if chain1_result.verified && chain2_state.is_none() {
                            session_active = true;
                            if is_heartbeat {
                                println!("{} nodes OK | {}",
                                    chain1_result.node_results.len(), chain1_result.session_status);
                            } else {
                                println!("\n  {} | PASS", chain1_result.session_status);
                            }

                            /// AuditB: chain1 only, passed
                            let verify_elapsed = verify_start.elapsed().as_millis() as u64;
                            let att_metas: Vec<AttestationMeta> = chain.attestations.iter()
                                .map(|a| extract_attestation_meta(a))
                                .collect();
                            let _ = audit_logger.write(
                                AuditEvent::HeartbeatOk,
                                verification_count,
                                &chain.chain_id,
                                &chain1_result.node_results,
                                Some(&att_metas),
                                1,
                                &chain1_result.session_status.to_string(),
                                true,
                                Some(verify_elapsed),
                                None,
                                tpm_ctx,
                            );                           

                            let resp = RelayCellPayload {
                                command: RelayCommand::VerificationResult(chain1_result),
                                next_hop: None, inner_cell: None,
                            };
                            let enc = crypto::encrypt(&session_key, &bincode::serialize(&resp)?)?;
                            network::send_message(conn, &ProtocolMessage::RelayCell(RelayCell {
                                encrypted_payload: enc,
                            })).await?;
                        } else {
                            if is_heartbeat {
                                println!("CHAIN 1 FAILURE | {}", chain1_result.session_status);
                            } else {
                                println!("\n  {} | FAIL", chain1_result.session_status);
                            }

                            /// AuditC: chain1 failed
                            let verify_elapsed = verify_start.elapsed().as_millis() as u64;
                            let att_metas: Vec<AttestationMeta> = chain.attestations.iter()
                                .map(|a| extract_attestation_meta(a))
                                .collect();
                            let _ = audit_logger.write(
                                AuditEvent::HeartbeatFail,
                                verification_count,
                                &chain.chain_id,
                                &chain1_result.node_results,
                                Some(&att_metas),
                                1,
                                &chain1_result.session_status.to_string(),
                                false,
                                Some(verify_elapsed),
                                None,
                                tpm_ctx,
                            );                       
                            
                            let resp = RelayCellPayload {
                                command: RelayCommand::VerificationResult(chain1_result),
                                next_hop: None, inner_cell: None,
                            };
                            let enc = crypto::encrypt(&session_key, &bincode::serialize(&resp)?)?;
                            network::send_message(conn, &ProtocolMessage::RelayCell(RelayCell {
                                encrypted_payload: enc,
                            })).await?;
                        }
                    }
                    other => println!("  Received: {:?}", other),
                }
            }
            other => println!("  Unexpected: {:?}", other),
        }
    }
    /// Session ended, chain disconnected
    if verification_count > 0 {
        let _ = audit_logger.write(
            AuditEvent::SessionEnded,
            verification_count,
            &[0u8; 8], /// no chain_id for end signal
            &[],        /// no node results
            None,
            1,
            "SESSION_ENDED",
            true,
            None,
            None,
            tpm_ctx,
        );
        println!("  SESSION ENDED after {} verifications", verification_count);
    }

    Ok(())
}

struct Chain2State {
    conn: TcpStream,
    session_keys: Vec<[u8; 32]>,
    node_ids: Vec<String>,
}

// === VM3 Distributed Authority: final verification of both chains ===

async fn run_da(config: &NodeConfig) -> Result<()> {
    let listen_addr = format!("0.0.0.0:{}", config.listen_port);
    println!("{} DA - Distributed Authority", config.node_id);
    println!("Listening on {}", listen_addr);
    let baseline_db = match BaselineDatabase::load_from_file("baselines.json") {
        Ok(db) => {
            println!("Loaded baselines: {} VMs", db.baselines.len());
            Some(db)
        }
        Err(e) => {
            eprintln!("No baselines: {}", e);
            None
        }
    };
    let tpm_ctx = tpm::init()?;
    println!("TPM initialized");
    let listener = network::listen(&listen_addr).await?;
    println!("Listening\n");
    loop {
        let mut conn = network::accept(&listener).await?;
        let peer = conn.peer_addr().map(|a| a.to_string()).unwrap_or("unknown".into());
        println!("Connection from {}", peer);
        match handle_da_circuit(&mut conn, &baseline_db, &tpm_ctx, &config.node_id, config.vm4_address.as_deref()).await {
            Ok(()) => println!("Circuit closed"),
            Err(e) => eprintln!("Error: {}", e),
        }
        println!("Ready\n");
    }
}

async fn handle_da_circuit(
    conn: &mut TcpStream,
    baseline_db: &Option<BaselineDatabase>,
    tpm_ctx: &tpm::TpmCtx,
    node_id: &str,
    vm4_address: Option<&str>,
) -> Result<()> {
    let message = network::receive_message(conn).await?;
    let session_key = match message {
        ProtocolMessage::ExtendCircuit(extend) => {
            println!("  EXTEND for {} (DA endpoint)", extend.target_id);
            let init = crypto::KeyExchangeInit {
                sender_id: "vm1".to_string(),
                kyber_pk: extend.kyber_pk,
                x25519_pk: extend.x25519_pk,
                nonce: extend.nonce,
            };
            let (response, keys) = crypto::generate_key_exchange_response(node_id, &init)?;
            let extended = ExtendedCircuit {
                responder_id: node_id.to_string(),
                kyber_ct: response.kyber_ct,
                x25519_pk: response.x25519_pk,
            };
            network::send_message(conn, &ProtocolMessage::ExtendedCircuit(extended)).await?;
            println!("  EXTENDED - DA session key established");
            keys.session_key
        }
        other => return Err(anyhow::anyhow!("Expected ExtendCircuit, got {:?}", other)),
    };

    println!("  Waiting for chain 2 submissions...");

    /// IMA delta tracker for chain 2 nodes (persists across heartbeats)
    let mut ima_tracker: HashMap<String, usize> = HashMap::new();
    let mut ima_agg_tracker: HashMap<String, Vec<u8>> = HashMap::new();
    let mut sysmon_tracker: HashMap<String, mfa_agent::sysmon::SysmonState> = HashMap::new();    
    let mut audit_logger = AuditLogger::new(AUDIT_LOG_PATH, node_id, 2); /// mode 2 default for DA
    let mut da_verification_count: u64 = 0;

    loop {
        let message = match network::receive_message(conn).await {
            Ok(msg) => msg,
            Err(e) => { println!("  Disconnected: {}", e); break; }
        };

        match message {
            ProtocolMessage::RelayCell(relay) => {
                let decrypted = crypto::decrypt(&session_key, &relay.encrypted_payload)?;
                let payload: RelayCellPayload = bincode::deserialize(&decrypted)?;

                match payload.command {
                    RelayCommand::Chain2Submission(c2_packet) => {
                        da_verification_count += 1;
                        let verify_start = Instant::now();
                        println!("\n  CHAIN 2 SUBMISSION - {} chain2 attestations",
                            c2_packet.chain2_attestations.len());
                        println!("  Chain 1 had {} node results (from VM2)",
                            c2_packet.chain1_results.node_results.len());

                        let (mut full_result, da_meta) = verify_full_authorization(
                            &c2_packet, baseline_db, tpm_ctx, node_id,
                            &mut ima_tracker, &mut ima_agg_tracker, &mut sysmon_tracker,
                        )?;

                        println!("\n  --- Chain 1 Results (from VM2) ---");
                        for nr in &full_result.chain1_node_results {
                            let icon = if nr.pcr_match && nr.ima_valid && nr.ebpf_valid
                                && nr.signature_valid && nr.ak_match { "✅" } else { "❌" };
                            println!("  {} [{}] {}", icon, nr.vm_identity, nr.details);
                        }

                        println!("\n  --- Chain 2 Results (verified by DA) ---");
                        for nr in &full_result.chain2_node_results {
                            let icon = if nr.pcr_match && nr.ima_valid && nr.ebpf_valid
                                && nr.signature_valid && nr.ak_match { "✅" } else { "❌" };
                            println!("  {} [{}] {}", icon, nr.vm_identity, nr.details);
                        }

                        println!("\n  FINAL: {} | {}",
                            full_result.session_status,
                            if full_result.authorized { "AUTHORIZED ✅" } else { "DENIED ❌" });

                        
                        ///  Dual authority quorum 
                        if let Some(v4_addr) = vm4_address {
                            match mfa_agent::dual_authority::vm3_forward_to_vm4(
                                v4_addr, node_id, tpm_ctx, &full_result,
                            ).await {
                                Ok(true) => {
                                    println!("  vm4 quorum APPROVED");
                                }
                                Ok(false) => {
                                    println!("  vm4 quorum DENIED");
                                    full_result.authorized = false;
                                    full_result.session_status = crate::protocol::SessionStatus::Denied;
                                }
                                Err(e) => {
                                    println!("  vm4 unreachable: {} — denying", e);
                                    full_result.authorized = false;
                                    full_result.session_status = crate::protocol::SessionStatus::Denied;
                                }
                            }
                        }
                        /// Audit, DA logs both chains
                        /// 	DA has chain 2 attestations (from c2_packet) but NOT chain 1
                        /// 	attestations (those were consumed by VM2 during verification).
                        /// Chain 1 results come pre-verified from VM2.
                        let all_results: Vec<NodeVerificationResult> = full_result.chain1_node_results.iter()
                            .chain(full_result.chain2_node_results.iter())
                            .cloned()
                            .collect();
                        let mut chain2_metas: Vec<AttestationMeta> = c2_packet.chain2_attestations.iter()
                            .map(|a| extract_attestation_meta(a))
                            .collect();
                            chain2_metas.push(da_meta);
                        let _ = audit_logger.write(
                            if full_result.authorized { AuditEvent::ChainVerified }
                            else { AuditEvent::ChainDenied },
                            da_verification_count,  
                            &c2_packet.chain2_id,
                            &all_results,
                            Some(&chain2_metas),
                            2,
                            &full_result.session_status.to_string(),
                            full_result.authorized,
                            Some(verify_start.elapsed().as_millis() as u64),
                            None, /// session_token_hash
                            tpm_ctx,
                        );                     

                        let resp = RelayCellPayload {
                            command: RelayCommand::FullAuthorizationResult(full_result),
                            next_hop: None,
                            inner_cell: None,
                        };
                        let enc = crypto::encrypt(&session_key, &bincode::serialize(&resp)?)?;
                        network::send_message(conn, &ProtocolMessage::RelayCell(RelayCell {
                            encrypted_payload: enc,
                        })).await?;
                    }
                    other => println!("  Received: {:?}", other),
                }
            }
            other => println!("  Unexpected: {:?}", other),
        }
    }
    /// Session ended, chain disconnected
    if da_verification_count > 0 {
        let _ = audit_logger.write(
            AuditEvent::SessionEnded,
            da_verification_count,
            &[0u8; 8],
            &[],
            None,
            2,
            "SESSION_ENDED",
            true,
            None,
            None,
            tpm_ctx,
        );
        println!("  SESSION ENDED after {} verifications", da_verification_count);
    }

    Ok(())
}


// === run_orchestrator and helpers ===
async fn run_orchestrator(config: &NodeConfig) -> Result<()> {
    println!("{} — Orchestrator (vm0)", config.node_id);
    let tpm_ctx = tpm::init()?;
    println!("TPM initialized");

    let credentials_path = config.credentials_path.as_ref()
        .ok_or_else(|| anyhow::anyhow!("orchestrator requires credentials_path in config"))?;
    println!("Credentials: {}", credentials_path);

    let baselines_path = config.baselines_path.as_ref()
        .ok_or_else(|| anyhow::anyhow!("orchestrator requires baselines_path in config"))?;
    let baseline_db = BaselineDatabase::load_from_file(baselines_path)
        .context("Failed to load baselines")?;
    println!("Baselines loaded: {} nodes", baseline_db.baselines.len());

    if baseline_db.get_baseline("vm1").is_none() {
        return Err(anyhow::anyhow!("No baseline found for vm1 in {}", baselines_path));
    }

    let vm1_address = config.vm1_address.as_ref()
        .ok_or_else(|| anyhow::anyhow!("orchestrator requires vm1_address in config"))?;

    let socket_path = config.unix_socket_path.as_ref()
        .ok_or_else(|| anyhow::anyhow!("orchestrator requires unix_socket_path"))?;

    let mut audit_logger = AuditLogger::new(AUDIT_LOG_PATH, &config.node_id, 2);
    println!("Audit log: {}", AUDIT_LOG_PATH);

    let session_state = Arc::new(tokio::sync::Mutex::new(OrchestratorSessionState::None));

    /// Prepare Unix socket
    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create socket dir: {:?}", parent))?;
    }
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("Failed to bind Unix socket: {}", socket_path))?;

    /// Restrict permissions (0600)
    let mut perms = std::fs::metadata(socket_path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(socket_path, perms)?;
    println!("Unix socket: {} (mode 0600)", socket_path);

    println!("Orchestrator ready — waiting for CLI requests\n");

    loop {
        let (mut cli_stream, _addr) = listener.accept().await?;
        println!("CLI connection received");

        let req = match read_cli_request(&mut cli_stream).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  Failed to read CLI request: {}", e);
                let _ = write_cli_response(&mut cli_stream,
                    &CliResponse::Error { message: format!("Read error: {}", e) }).await;
                continue;
            }
        };

        let response = match req {
            CliRequest::Authenticate { passphrase1, passphrase2, session_ttl_secs } => {
                handle_authenticate(
                    &config.node_id,
                    &tpm_ctx,
                    credentials_path,
                    vm1_address,
                    config.vm4_address.as_deref(),
                    &baseline_db,
                    session_ttl_secs,
                    passphrase1,
                    passphrase2,
                    &session_state,
                    &mut audit_logger,
                ).await
            }
            CliRequest::Status => {
                let state = session_state.lock().await;
                build_status_response(&state)
            }
            CliRequest::Revoke => {
                let mut state = session_state.lock().await;
                match &*state {
                    OrchestratorSessionState::Active { revoke_flag, session_ended, .. } => {
                        if session_ended.load(Ordering::Relaxed) {
                            println!("  Revoke requested but session already ended");
                            *state = OrchestratorSessionState::None;
                            CliResponse::Status {
                                active: false,
                                authorization_id: None,
                                expires_in_secs: None,
                            }
                        } else {
                            revoke_flag.store(true, Ordering::Relaxed);
                            println!("  Revoke flag set — heartbeat driver will terminate");
                            CliResponse::Status {
                                active: false,
                                authorization_id: None,
                                expires_in_secs: None,
                            }
                        }
                    }
                    _ => {
                        CliResponse::Status {
                            active: false,
                            authorization_id: None,
                            expires_in_secs: None,
                        }
                    }
                }
            }

        };

        let _ = write_cli_response(&mut cli_stream, &response).await;
    }
}

enum OrchestratorSessionState {
    None,
    Active {
        authorization_id: Vec<u8>,
        session_token: Vec<u8>,
        session_expiry: u64,
        operator_hash: Vec<u8>,
        /// Driver coordination flags shared with spawned heartbeat task
        revoke_flag: Arc<AtomicBool>,
        last_heartbeat_seq: Arc<AtomicU64>,
        last_heartbeat_ok: Arc<AtomicBool>,
        last_heartbeat_at: Arc<AtomicU64>,
        session_ended: Arc<AtomicBool>,        
    },
}

fn build_status_response(state: &OrchestratorSessionState) -> CliResponse {
    match state {
        OrchestratorSessionState::None => CliResponse::Status {
            active: false,
            authorization_id: None,
            expires_in_secs: None,
        },
        OrchestratorSessionState::Active {
            authorization_id,
            session_expiry,
            session_ended,
            last_heartbeat_seq: _,
            last_heartbeat_ok: _,
            last_heartbeat_at: _,
            ..
        } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let expires_in = session_expiry.saturating_sub(now);
            let is_ended = session_ended.load(Ordering::Relaxed);

            /// Report active/inactive based on session_ended flag and expiry
            CliResponse::Status {
                active: !is_ended && expires_in > 0,
                authorization_id: Some(authorization_id.clone()),
                expires_in_secs: Some(expires_in),
            }
        }
    }
}

async fn handle_authenticate(
    node_id: &str,
    tpm_ctx: &tpm::TpmCtx,
    credentials_path: &str,
    vm1_address: &str,
    vm4_address: Option<&str>,
    baseline_db: &BaselineDatabase,
    session_ttl_secs: u64,
    passphrase1: String,
    passphrase2: String,
    session_state: &Arc<tokio::sync::Mutex<OrchestratorSessionState>>,
    _audit_logger: &mut AuditLogger,
) -> CliResponse {
    /// Check for existing active session 
    {
        let state = session_state.lock().await;
        if let OrchestratorSessionState::Active { session_ended, session_expiry, .. } = &*state {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if !session_ended.load(Ordering::Relaxed) && *session_expiry > now {
                return CliResponse::Denied {
                    reason: "Session already active. Revoke current session first.".to_string(),
                };
            }
        }
    }

    println!("  Authenticating operator...");

    /// Step 1-2: Validate operator and session TTL 
    let operator_token = match mfa_agent::orchestrator::validate_operator(credentials_path, &passphrase1, &passphrase2).await {
        Ok(t) => t,
        Err(_) => {
            println!("  Operator auth failed");
            return CliResponse::Denied { reason: "Authentication failed".to_string() };
        }
    };
    println!("  Operator authenticated: {}", hex::encode(&operator_token.operator_hash[..8]));

    if !(60..=1200).contains(&session_ttl_secs) {
        return CliResponse::Denied {
            reason: "session_ttl_secs must be between 60 and 1200".to_string(),
        };
    }
    /// Step 2.5: Mutual attestation with vm4 (dual authority) 
    if let Some(v4_addr) = vm4_address {
        match mfa_agent::dual_authority::vm0_mutual_attest_vm4(
            v4_addr, node_id, tpm_ctx, baseline_db, session_ttl_secs,
        ).await {
            Ok(true) => println!("  vm4 mutual attestation PASSED"),
            Ok(false) => {
                return CliResponse::Denied {
                    reason: "vm4 mutual attestation failed — quorum denied".to_string(),
                };
            }
            Err(e) => {
                return CliResponse::Denied {
                    reason: format!("vm4 unreachable: {} — quorum denied", e),
                };
            }
        }
    }
    /// Step 3-4: Connect + key exchange 
    println!("  Connecting to vm1 at {}...", vm1_address);
    let mut stream = match network::connect(vm1_address).await {
        Ok(s) => s,
        Err(e) => return CliResponse::Denied {
            reason: format!("Cannot reach vm1: {}", e),
        },
    };
    println!("  Connected to vm1");

    println!("  Key exchange with vm1...");
    let session_key = match perform_orchestrator_key_exchange(&mut stream, node_id).await {
        Ok(k) => k,
        Err(e) => return CliResponse::Denied {
            reason: format!("Key exchange failed: {}", e),
        },
    };
    println!("  Session established (hybrid post-quantum)");

    /// Step 5: Request and verify vm1 attestation
    println!("  Requesting vm1 attestation...");
    let mut nonce = vec![0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);

    let req = OrchestratorMessage::AttestationRequest { nonce: nonce.clone() };
    if let Err(e) = send_orch_message(&mut stream, &session_key, &req).await {
        return CliResponse::Denied {
            reason: format!("Failed to send attestation request: {}", e),
        };
    }

    let vm1_attestation = match recv_orch_message(&mut stream, &session_key).await {
        Ok(OrchestratorMessage::AttestationResponse(att)) => att,
        Ok(other) => return CliResponse::Denied {
            reason: format!("Expected AttestationResponse, got {:?}", other),
        },
        Err(e) => return CliResponse::Denied {
            reason: format!("Attestation receive error: {}", e),
        },
    };
    println!("  vm1 attestation received");

    println!("  Verifying vm1 attestation...");
    let vm1_verify = baseline_db.verify_attestation(&vm1_attestation, None, None, None);
    let vm1_passed = vm1_verify.pcr_match && vm1_verify.ima_valid
        && vm1_verify.ebpf_valid && vm1_verify.signature_valid && vm1_verify.ak_match;

    if !vm1_passed {
        println!("  vm1 attestation FAILED: {}", vm1_verify.details);
        return CliResponse::Denied {
            reason: format!("vm1 integrity verification failed: {}", vm1_verify.details),
        };
    }
    println!("  vm1 integrity verified");

    /// Step 6-7: Sign INITIATE, send, wait ack
    println!("  Generating vm0 self-attestation...");
    let vm0_quote = match tpm::generate_quote(tpm_ctx) {
        Ok(q) => q,
        Err(e) => return CliResponse::Denied {
            reason: format!("vm0 self-attestation failed: {}", e),
        },
    };
    let vm0_attestation = Attestation {
        vm_identity: node_id.to_string(),
        tpm_quote: vm0_quote.clone(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
    };
    let vm0_ak_public = vm0_quote.ak_public.clone();

    let payload = match InitiatePayload::new(
        session_ttl_secs,
        operator_token.operator_hash.clone(),
        vm0_attestation,
        vm0_ak_public,
    ) {
        Ok(p) => p,
        Err(e) => return CliResponse::Denied {
            reason: format!("Payload construction failed: {}", e),
        },
    };

    let authorization_id = payload.authorization_id.clone();
    println!("  Signing INITIATE (auth_id={})...", payload.short_auth_id());

    let signed = match sign_initiate(tpm_ctx, payload) {
        Ok(s) => s,
        Err(e) => return CliResponse::Denied {
            reason: format!("TPM signing failed: {}", e),
        },
    };

    println!("  Sending INITIATE to vm1...");
    let msg = OrchestratorMessage::Initiate(signed);
    if let Err(e) = send_orch_message(&mut stream, &session_key, &msg).await {
        return CliResponse::Denied {
            reason: format!("Failed to send INITIATE: {}", e),
        };
    }

    match recv_orch_message(&mut stream, &session_key).await {
        Ok(OrchestratorMessage::InitiateAck { authorization_id: ack_id }) => {
            if ack_id != authorization_id {
                return CliResponse::Denied {
                    reason: "vm1 ack auth_id mismatch".to_string(),
                };
            }
            println!("  INITIATE accepted by vm1");
        }
        Ok(OrchestratorMessage::InitiateRejected { reason }) => {
            println!("  vm1 rejected INITIATE: {}", reason);
            return CliResponse::Denied {
                reason: format!("vm1 rejected: {}", reason),
            };
        }
        Ok(other) => return CliResponse::Denied {
            reason: format!("Expected InitiateAck, got {:?}", other),
        },
        Err(e) => return CliResponse::Denied {
            reason: format!("Ack receive error: {}", e),
        },
    }

    /// Step 8: Wait for SessionTokenReturn 
    println!("  Waiting for chain establishment...");
    let session_data = match recv_orch_message(&mut stream, &session_key).await {
        Ok(OrchestratorMessage::SessionToken(st)) => {
            if st.authorization_id != authorization_id {
                return CliResponse::Denied {
                    reason: "session token auth_id mismatch".to_string(),
                };
            }
            if !st.authorized {
                return CliResponse::Denied {
                    reason: "chain establishment completed but not authorized".to_string(),
                };
            }
            st
        }
        Ok(OrchestratorMessage::ChainFailed { reason, .. }) => {
            println!("  Chain failed: {}", reason);
            return CliResponse::Denied {
                reason: format!("Chain establishment failed: {}", reason),
            };
        }
        Ok(other) => return CliResponse::Denied {
            reason: format!("Expected SessionToken, got {:?}", other),
        },
        Err(e) => return CliResponse::Denied {
            reason: format!("Session token receive error: {}", e),
        },
    };

    println!("  SESSION AUTHORIZED");
    println!("     auth_id: {}", hex::encode(&authorization_id[..8]));
    println!("     chain 1: {} nodes", session_data.chain1_node_count);
    println!("     chain 2: {} nodes", session_data.chain2_node_count);

    /// Step 9: Create session state + spawn heartbeat driver 
    let revoke_flag = Arc::new(AtomicBool::new(false));
    let last_heartbeat_seq = Arc::new(AtomicU64::new(0));
    let last_heartbeat_ok = Arc::new(AtomicBool::new(true));
    let last_heartbeat_at = Arc::new(AtomicU64::new(0));
    let session_ended = Arc::new(AtomicBool::new(false));

    {
        let mut state = session_state.lock().await;
        *state = OrchestratorSessionState::Active {
            authorization_id: authorization_id.clone(),
            session_token: session_data.session_token.clone(),
            session_expiry: session_data.session_expiry,
            operator_hash: operator_token.operator_hash.clone(),
            revoke_flag: revoke_flag.clone(),
            last_heartbeat_seq: last_heartbeat_seq.clone(),
            last_heartbeat_ok: last_heartbeat_ok.clone(),
            last_heartbeat_at: last_heartbeat_at.clone(),
            session_ended: session_ended.clone(),
        };
    }

    /// Spawn heartbeat driver (owns stream from here)
    let auth_id_for_task = authorization_id.clone();
    tokio::spawn(async move {
        run_heartbeat_driver(
            stream,
            session_key,
            session_ttl_secs,
            auth_id_for_task,
            revoke_flag,
            last_heartbeat_seq,
            last_heartbeat_ok,
            last_heartbeat_at,
            session_ended,
        ).await;
    });

    /// Step 10: Respond to CLI 
    use sha2::{Sha256, Digest};
    let session_token_hash = Sha256::digest(&session_data.session_token).to_vec();

    CliResponse::Authorized {
        authorization_id,
        session_token_hash,
        session_expiry: session_data.session_expiry,
        chain1_nodes: session_data.chain1_node_count,
        chain2_nodes: session_data.chain2_node_count,
    }
}

async fn run_heartbeat_driver(
    mut stream: tokio::net::TcpStream,
    session_key: [u8; 32],
    session_ttl_secs: u64,
    authorization_id: Vec<u8>,
    revoke_flag: Arc<AtomicBool>,
    last_heartbeat_seq: Arc<AtomicU64>,
    last_heartbeat_ok: Arc<AtomicBool>,
    last_heartbeat_at: Arc<AtomicU64>,
    session_ended: Arc<AtomicBool>,
) {
    println!(
        "\nHeartbeat driver started auth_id={} ttl={}s",
        hex::encode(&authorization_id[..8]),
        session_ttl_secs
    );

    let session_end_instant = tokio::time::Instant::now() + Duration::from_secs(session_ttl_secs);
    let mut sequence: u64 = 0;
    let mut ping_timer = interval(Duration::from_secs(60));
    ping_timer.tick().await; /// skip immediate first tick

    loop {
        /// Check revoke flag
        if revoke_flag.load(Ordering::Relaxed) {
            println!("Driver: revoke flag set, terminating");
            let _ = send_orch_message(
                &mut stream,
                &session_key,
                &OrchestratorMessage::Revoke { reason: "operator revoke".to_string() },
            ).await;
            break;
        }

        tokio::select! {
            _ = tokio::time::sleep_until(session_end_instant) => {
                println!("Driver: TTL expired, terminating");
                break;
            }
            _ = ping_timer.tick() => {
                sequence = sequence.saturating_add(1);
                let ping = OrchestratorMessage::HeartbeatPing { sequence };
                if let Err(e) = send_orch_message(&mut stream, &session_key, &ping).await {
                    eprintln!("Driver: send HeartbeatPing failed: {}", e);
                    break;
                }

                /// Wait for result with timeout
                let result = timeout(
                    Duration::from_secs(30),
                    recv_orch_message(&mut stream, &session_key)
                ).await;

                match result {
                    Ok(Ok(OrchestratorMessage::HeartbeatResult { sequence: seq, chain_ok, node_count, details })) => {
                        last_heartbeat_seq.store(seq, Ordering::Relaxed);
                        last_heartbeat_ok.store(chain_ok, Ordering::Relaxed);
                        last_heartbeat_at.store(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                            Ordering::Relaxed
                        );
                        let icon = if chain_ok { "✅" } else { "❌" };
                        println!("Heartbeat #{}: {} {} nodes — {}", seq, icon, node_count, details);
                        if !chain_ok {
                            println!("Driver: integrity failure detected, terminating session");
                            break;
                        }
                    }
                    Ok(Ok(OrchestratorMessage::SessionEnded { reason })) => {
                        println!("Driver: vm1 ended session: {}", reason);
                        break;
                    }
                    Ok(Ok(other)) => {
                        eprintln!("Driver: unexpected message: {:?}", other);
                    }
                    Ok(Err(e)) => {
                        eprintln!("Driver: recv error: {}", e);
                        break;
                    }
                    Err(_) => {
                        eprintln!("Driver: heartbeat response timeout");
                        break;
                    }
                }
            }
        }
    }

    println!("Heartbeat driver exiting\n");
    session_ended.store(true, Ordering::Relaxed);
    /// Stream drops here, closing connection
}

// === Unix socket I/O, length-prefixed bincode ===
async fn read_cli_request(stream: &mut tokio::net::UnixStream) -> Result<CliRequest> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 10_000_000 {
        anyhow::bail!("CLI request too large: {}", len);
    }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(bincode::deserialize(&data)?)
}

async fn write_cli_response(stream: &mut tokio::net::UnixStream, resp: &CliResponse) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let data = bincode::serialize(resp)?;
    let len = data.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&data).await?;
    Ok(())
}

// === TCP I/O for orchestrator messages, reuse existing crypto ===
async fn perform_orchestrator_key_exchange(
    stream: &mut tokio::net::TcpStream,
    _sender_id: &str,
) -> Result<[u8; 32]> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (init, kyber_sk, x25519_secret, nonce) =
        crypto::generate_key_exchange_init("vm0")?;

    /// Send init (length-prefixed bincode)
    let init_bytes = bincode::serialize(&init)?;
    let len = init_bytes.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&init_bytes).await?;

    /// Receive response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u32::from_le_bytes(len_buf) as usize;
    if resp_len > 10_000_000 {
        anyhow::bail!("Response too large");
    }
    let mut resp_bytes = vec![0u8; resp_len];
    stream.read_exact(&mut resp_bytes).await?;
    let response: crypto::KeyExchangeResponse = bincode::deserialize(&resp_bytes)?;

    let keys = crypto::complete_key_exchange(&init, &response, &kyber_sk, x25519_secret, &nonce)?;    
    Ok(keys.session_key)
}

async fn send_orch_message(
    stream: &mut tokio::net::TcpStream,
    session_key: &[u8; 32],
    msg: &OrchestratorMessage,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let plaintext = bincode::serialize(msg)?;
    let ciphertext = crypto::encrypt(session_key, &plaintext)?;
    let len = ciphertext.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&ciphertext).await?;
    Ok(())
}

async fn recv_orch_message(
    stream: &mut tokio::net::TcpStream,
    session_key: &[u8; 32],
) -> Result<OrchestratorMessage> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 10_000_000 {
        anyhow::bail!("Message too large: {}", len);
    }
    let mut ciphertext = vec![0u8; len];
    stream.read_exact(&mut ciphertext).await?;
    let plaintext = crypto::decrypt(session_key, &ciphertext)?;
    Ok(bincode::deserialize(&plaintext)?)
}


// === Verification ===

/// VM3 verifies both chains and produces final authorization
fn verify_full_authorization(
    c2_packet: &Chain2Packet,
    baseline_db: &Option<BaselineDatabase>,
    tpm_ctx: &tpm::TpmCtx,
    da_node_id: &str,
    ima_tracker: &mut HashMap<String, usize>,
    ima_agg_tracker: &mut HashMap<String, Vec<u8>>,
    sysmon_tracker: &mut HashMap<String, mfa_agent::sysmon::SysmonState>,
) -> Result<(FullAuthorizationResponse, AttestationMeta)> {
    let mut chain2_results = Vec::new();
    let mut all_ok = true;

    /// 1. Verify chain 1 was properly verified by VM2
    let chain1_ok = c2_packet.chain1_results.verified;


    /// 2. Verify each chain 2 attestation (including VM2 itself)
    for att in &c2_packet.chain2_attestations {
        let prev_ima = ima_tracker.get(&att.vm_identity).copied();
        let prev_ima_agg = ima_agg_tracker.get(&att.vm_identity).cloned();
        let prev_sysmon = sysmon_tracker.get(&att.vm_identity);
        let nr = match baseline_db {
            Some(db) => db.verify_attestation(att, prev_ima, prev_ima_agg.as_deref(), prev_sysmon),
            None => NodeVerificationResult {
                vm_identity: att.vm_identity.clone(),
                pcr_match: false, ima_valid: false, ebpf_valid: false,
                signature_valid: false, ak_match: false,
                details: "No baseline database".into(),
            },
        };
        /// Update IMA tracker with current count
        ima_tracker.insert(att.vm_identity.clone(), att.tpm_quote.ima_measurements.count);
        ima_agg_tracker.insert(att.vm_identity.clone(), att.tpm_quote.ima_measurements.aggregate_hash.clone());
        if let Some(ref sm) = att.tpm_quote.ebpf_state.sysmon {
            sysmon_tracker.insert(att.vm_identity.clone(), sm.clone());
        }

        chain2_results.push(nr);
    }

    /// 3. VM3 self-attestation
    let da_quote = tpm::generate_quote(tpm_ctx)?;
    let da_att = Attestation {
        vm_identity: da_node_id.to_string(),
        tpm_quote: da_quote,
        timestamp: now_secs(),
    };
    let da_meta = extract_attestation_meta(&da_att);
    let prev_ima_da = ima_tracker.get(da_node_id).copied();
    let prev_ima_da_agg = ima_agg_tracker.get(da_node_id).cloned();
    let prev_sysmon_da = sysmon_tracker.get(da_node_id);
    let da_nr = match baseline_db {
        Some(db) => db.verify_attestation(&da_att, prev_ima_da, prev_ima_da_agg.as_deref(), prev_sysmon_da),
        None => NodeVerificationResult {
            vm_identity: da_node_id.to_string(),
            pcr_match: false, ima_valid: false, ebpf_valid: false,
            signature_valid: false, ak_match: false,
            details: "No baseline database".into(),
        },
    };
    ima_tracker.insert(da_node_id.to_string(), da_att.tpm_quote.ima_measurements.count);
    ima_agg_tracker.insert(da_node_id.to_string(), da_att.tpm_quote.ima_measurements.aggregate_hash.clone());
    if let Some(ref sm) = da_att.tpm_quote.ebpf_state.sysmon {
        sysmon_tracker.insert(da_node_id.to_string(), sm.clone());
    }

    chain2_results.push(da_nr);

    let authorized = all_ok && chain1_ok;
    let status = if authorized {
        SessionStatus::Authorized
    } else {
        SessionStatus::Denied
    };

    let token = if authorized {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(b"MFA-FULL-AUTH-TOKEN-v1");
        h.update(&c2_packet.chain1_results.chain_id);
        h.update(&c2_packet.chain2_id);
        h.update(now_secs().to_le_bytes());
        Some(h.finalize().to_vec())
    } else {
        None
    };

    Ok((FullAuthorizationResponse {
        authorized,
        session_status: status,
        session_token: token,
        chain1_node_results: c2_packet.chain1_results.node_results.clone(),
        chain2_node_results: chain2_results,
        chain1_id: c2_packet.chain1_results.chain_id.clone(),
        chain2_id: c2_packet.chain2_id.clone(),
        timestamp: now_secs(),
    }, da_meta))
}

/// Verify a chain against baseline database (used by VM2)
/// 	ima_tracker: per-node IMA count from previous heartbeat for delta detection
fn verify_chain_against_db(
    chain: &ChainPacket,
    baseline_db: &Option<BaselineDatabase>,
    tpm_ctx: &tpm::TpmCtx,
    was_active: bool,
    zts_node_id: &str,
    ima_tracker: &mut HashMap<String, usize>,
    ima_agg_tracker: &mut HashMap<String, Vec<u8>>,
    sysmon_tracker: &mut HashMap<String, mfa_agent::sysmon::SysmonState>,
) -> Result<VerificationResponse> {
    let mut node_results = Vec::new();
    let mut all_ok = true;

    for att in &chain.attestations {
        let prev_ima = ima_tracker.get(&att.vm_identity).copied();
        let prev_ima_agg = ima_agg_tracker.get(&att.vm_identity).cloned();
        let prev_sysmon = sysmon_tracker.get(&att.vm_identity);
        let nr = match baseline_db {
            Some(db) => db.verify_attestation(att, prev_ima, prev_ima_agg.as_deref(), prev_sysmon),
            None => NodeVerificationResult {
                vm_identity: att.vm_identity.clone(),
                pcr_match: false, ima_valid: false, ebpf_valid: false,
                signature_valid: false, ak_match: false,
                details: "No baseline database".into(),
            },
        };
        /// Update IMA tracker with current count for next heartbeat
        ima_tracker.insert(att.vm_identity.clone(), att.tpm_quote.ima_measurements.count);
        ima_agg_tracker.insert(att.vm_identity.clone(), att.tpm_quote.ima_measurements.aggregate_hash.clone());
        if let Some(ref sm) = att.tpm_quote.ebpf_state.sysmon {
            sysmon_tracker.insert(att.vm_identity.clone(), sm.clone());
        }

        node_results.push(nr);
    }
    /// Self-attestation
    let self_quote = tpm::generate_quote(tpm_ctx)?;
    let self_att = Attestation {
        vm_identity: zts_node_id.to_string(),
        tpm_quote: self_quote,
        timestamp: now_secs(),
    };
    let prev_ima_self = ima_tracker.get(zts_node_id).copied();
    let prev_ima_self_agg = ima_agg_tracker.get(zts_node_id).cloned();
    let prev_sysmon_self = sysmon_tracker.get(zts_node_id);
    let self_nr = match baseline_db {
        Some(db) => db.verify_attestation(&self_att, prev_ima_self, prev_ima_self_agg.as_deref(), prev_sysmon_self),
        None => NodeVerificationResult {
            vm_identity: zts_node_id.to_string(),
            pcr_match: false, ima_valid: false, ebpf_valid: false,
            signature_valid: false, ak_match: false,
            details: "No baseline database".into(),
        },
    };
    ima_tracker.insert(zts_node_id.to_string(), self_att.tpm_quote.ima_measurements.count);
    ima_agg_tracker.insert(zts_node_id.to_string(), self_att.tpm_quote.ima_measurements.aggregate_hash.clone());
    if let Some(ref sm) = self_att.tpm_quote.ebpf_state.sysmon {
        sysmon_tracker.insert(zts_node_id.to_string(), sm.clone());
    }

    node_results.push(self_nr);

    let status = if !all_ok {
        if was_active { SessionStatus::Revoked } else { SessionStatus::Denied }
    } else {
        SessionStatus::Provisional
    };

    let token = if all_ok {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(b"MFA-SESSION-TOKEN-v1");
        h.update(&chain.chain_id);
        h.update(now_secs().to_le_bytes());
        Some(h.finalize().to_vec())
    } else {
        None
    };

    Ok(VerificationResponse {
        verified: all_ok,
        session_status: status,
        session_token: token,
        node_results,
        chain_id: chain.chain_id.clone(),
        timestamp: now_secs(),
    })
}


