use anyhow::{Result, Context, anyhow};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use rand::RngCore;
use tss_esapi::traits::UnMarshall;
use crate::protocol::Attestation;
use crate::tpm::{TpmCtx, sign_data};
use std::collections::HashMap;

const INITIATE_MAX_AGE_SECS: u64 = 300;
const AUTH_ID_BYTES: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitiatePayload {
    /// Protocol version (for future compatibility)
    pub version: u32,
    /// Single-use authorization identifier (32 random bytes, hex-encoded for logging)
    pub authorization_id: Vec<u8>,
    /// Unix timestamp when vm0 generated this payload
    pub timestamp: u64,
    /// Session TTL in seconds (operator-chosen, 60-1200)
    pub session_ttl_secs: u64,
    /// SHA-256 hash of operator credentials (identifies operator in audit)
    pub operator_hash: Vec<u8>,
    /// vm0's current attestation (TPM quote + eBPF state)
    /// Included so vm1 can see vm0's state at the time of authorization.
    /// 	vm1 does NOT cryptographically verify this (that's vm4's job in Phase 3),
    /// 	but it's recorded in the audit log for forensic analysis.
    pub vm0_attestation: Attestation,
    /// vm0's AK public key (allows vm1 to independently verify the signature
    /// without a separate key distribution step, bound to the attestation)
    pub vm0_ak_public: Vec<u8>,
}

// === Wire format: payload + signature ===
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedInitiate {
    pub payload: InitiatePayload,
    /// RSA-SSA signature over SHA-256 hash of canonical serialization
    pub signature: Vec<u8>,
}


// === Initiate Verification VM1 Side ===
/// Reasons an INITIATE payload can be rejected.
/// Discrete variants allow vm1 to log the exact failure reason for audit.
#[derive(Debug, Clone, PartialEq)]
pub enum InitiateRejection {
    /// Signature does not verify against vm0's AK public key
    InvalidSignature,
    /// Timestamp is too old (replay window exceeded)
    TimestampExpired { age_secs: u64 },
    /// Timestamp is in the future (clock skew or forgery attempt)
    TimestampInFuture { skew_secs: u64 },
    /// authorization_id has been seen before (replay attack)
    DuplicateAuthId,
    /// vm0_ak_public doesn't match vm1's stored expected key
    AkPublicMismatch,
    /// Unknown protocol version
    UnsupportedVersion { version: u32 },
    /// Malformed payload data
    MalformedPayload(String),
    /// session_ttl_secs outside acceptable range
    InvalidSessionTtl,
}

impl std::fmt::Display for InitiateRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature =>
                write!(f, "INITIATE signature verification failed"),
            Self::TimestampExpired { age_secs } =>
                write!(f, "INITIATE timestamp expired ({}s old)", age_secs),
            Self::TimestampInFuture { skew_secs } =>
                write!(f, "INITIATE timestamp in future (+{}s)", skew_secs),
            Self::DuplicateAuthId =>
                write!(f, "INITIATE authorization_id already used"),
            Self::AkPublicMismatch =>
                write!(f, "INITIATE vm0 AK public key does not match expected"),
            Self::UnsupportedVersion { version } =>
                write!(f, "INITIATE unsupported version {}", version),
            Self::MalformedPayload(reason) =>
                write!(f, "INITIATE malformed: {}", reason),
            Self::InvalidSessionTtl =>
                write!(f, "INITIATE session_ttl_secs out of range"),
        }
    }
}

// === Session Token Return Payload ===
/// Sent from vm1 back to vm0 after successful chain establishment.
/// 	Contains the session token that vm3 issued, correlated with
/// 	the original authorization_id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTokenReturn {
    /// Must match the authorization_id from the INITIATE
    pub authorization_id: Vec<u8>,
    /// Session token from vm3 (cryptographic proof of authorization)
    pub session_token: Vec<u8>,
    /// When the session expires (Unix timestamp)
    pub session_expiry: u64,
    /// Chain 1 and chain 2 verification summary (for vm0's audit log)
    pub chain1_node_count: usize,
    pub chain2_node_count: usize,
    pub authorized: bool,
}


// === Wire Protocol ===
/// Messages over the vm0 - vm1 TCP session
/// 	Wraps any protocol message sent between vm0 and vm1.
/// 	The outer serialization is bincode, the inner content is typed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OrchestratorMessage {
    /// vm0 → vm1: requests vm1's current attestation
    AttestationRequest { nonce: Vec<u8> },
    /// vm1 → vm0: vm1's attestation in response to a request
    AttestationResponse(Attestation),
    /// vm0 → vm1: signed authorization to begin chain establishment
    Initiate(SignedInitiate),
    /// vm1 → vm0: acknowledgment of valid INITIATE
    InitiateAck { authorization_id: Vec<u8> },
    /// vm1 → vm0: rejection with specific reason
    InitiateRejected { reason: String },
    /// vm1 → vm0: session token after successful chain establishment
    SessionToken(SessionTokenReturn),
    /// vm1 → vm0: chain establishment failed
    ChainFailed { authorization_id: Vec<u8>, reason: String },

    HeartbeatPing { sequence: u64 },
    HeartbeatResult {
        sequence: u64,
        chain_ok: bool,
        node_count: usize,
        details: String,
    },
    Revoke { reason: String },
    SessionEnded { reason: String },
}

// === Unix Socket Protocol === 
/// vm0 CLI ↔ vm0 orchestrator
/// Messages exchanged between vm0-cli and the vm0 orchestrator agent
/// over the Unix domain socket at /run/mfa-agent/orchestrator.sock.
/// 	The CLI drives the flow; the agent responds. All messages are
/// 	length-prefixed bincode (same framing as TCP messages).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CliRequest {
    /// CLI → agent: request authorization with given session TTL.
    /// Operator passphrases are passed in this message.
    Authenticate {
        passphrase1: String,
        passphrase2: String,
        session_ttl_secs: u64,
    },
    /// CLI → agent: query current session status
    Status,
    /// CLI → agent: revoke current session
    Revoke,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CliResponse {
    /// Authentication succeeded, session established
    Authorized {
        authorization_id: Vec<u8>,
        session_token_hash: Vec<u8>,   /// SHA256 of token (don't expose token)
        session_expiry: u64,
        chain1_nodes: usize,
        chain2_nodes: usize,
    },
    /// Authentication failed (wrong passphrase, vm1 attestation failed, etc.)
    Denied {
        reason: String,
    },
    /// Status response
    Status {
        active: bool,
        authorization_id: Option<Vec<u8>>,
        expires_in_secs: Option<u64>,
    },
    /// Generic error (malformed request, internal failure)
    Error {
        message: String,
    },
    /// vm4: Pending approval request from vm0
    PendingApproval {
        requester_id: String,
        requester_ip: String,
        session_ttl_secs: u64,
        attestation_summary: String,
    },
}

// === Replay Cache === 
/// Tracks recently-used authorization_ids
/// 	In-memory cache of recently seen authorization_ids.
/// 	Prevents replay of captured INITIATE payloads.
/// 		Design note: since INITIATE payloads expire after INITIATE_MAX_AGE_SECS,
/// 		the cache only needs to retain entries for that window. Older entries
/// 		can be pruned automatically.
pub struct ReplayCache {
    seen: HashMap<Vec<u8>, u64>,
}


// === INITIATE: Sign and Verify ===


impl InitiatePayload {
/// Initiate Construction VM0 Side
    /// Construct a new INITIATE payload. Generates a fresh authorization_id
    /// and timestamp. The caller must sign the result before transmission.
    pub fn new(
        session_ttl_secs: u64,
        operator_hash: Vec<u8>,
        vm0_attestation: Attestation,
        vm0_ak_public: Vec<u8>,
    ) -> Result<Self> {
        if session_ttl_secs < 60 || session_ttl_secs > 1200 {
            return Err(anyhow!(
                "session_ttl_secs must be between 60 and 1200 (got {})",
                session_ttl_secs
            ));
        }
        let mut authorization_id = vec![0u8; AUTH_ID_BYTES];
        rand::thread_rng().fill_bytes(&mut authorization_id);
        Ok(InitiatePayload {
            version: 1,
            authorization_id,
            timestamp: now_secs(),
            session_ttl_secs,
            operator_hash,
            vm0_attestation,
            vm0_ak_public,
        })
    }
    /// Canonical serialization for signing.
    /// Uses bincode for deterministic byte ordering (same input → same bytes).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).context("Failed to serialize InitiatePayload")
    }
    /// Short hex identifier for logging
    pub fn short_auth_id(&self) -> String {
        hex::encode(&self.authorization_id[..8])
    }
}

/// Sign an InitiatePayload using vm0's TPM signing key.
/// The signing key's public is written INTO the payload before signing,
/// so the verifier can check the signature against the same key.
pub fn sign_initiate(
    tpm: &TpmCtx,
    mut payload: InitiatePayload,
) -> Result<SignedInitiate> {
    use sha2::Digest;
    let (_, signing_key_public_1) = sign_data(tpm, b"probe")
        .context("TPM key enumeration failed")?;
    payload.vm0_ak_public = signing_key_public_1.clone();
    let bytes = payload.canonical_bytes()?;
    // Diagnostic: what are we actually signing?
    let signed_hash = sha2::Sha256::digest(&bytes);
    eprintln!("  SIGN: signed_bytes_len={} signed_sha256={}",
        bytes.len(),
        hex::encode(&signed_hash));   
    let (signature, _) = sign_data(tpm, &bytes)
        .context("TPM signing failed for INITIATE payload")?;
    eprintln!("  SIGN: signature_len={} sig_sha256={}",
        signature.len(),
        hex::encode(sha2::Sha256::digest(&signature)));

    Ok(SignedInitiate { payload, signature })
}


/// Verify an INITIATE payload on the receiving side (vm1).
/// Checks are ordered cheapest-first for efficiency under attack:
///   1. Version supported
///   2. Timestamp within window
///   3. session_ttl in range
///   4. AK public matches expected (if provided)
///   5. Signature valid
///   6. Duplicate check (caller manages replay cache)
/// 	The caller is responsible for the duplicate check because the
/// 	replay cache is stateful and lives outside this module.
pub fn verify_initiate(
    signed: &SignedInitiate,
    expected_vm0_ak_public: Option<&[u8]>,
) -> Result<(), InitiateRejection> {
    let p = &signed.payload;
    /// 1. Version check
    if p.version != 1 {
        return Err(InitiateRejection::UnsupportedVersion { version: p.version });
    }
    /// 2. Timestamp window check
    let now = now_secs();
    if p.timestamp > now {
        let skew = p.timestamp - now;
        if skew > 10 { /// Small clock skew acceptable, large skew = attack
            return Err(InitiateRejection::TimestampInFuture { skew_secs: skew });
        }
    } else {
        let age = now - p.timestamp;
        if age > INITIATE_MAX_AGE_SECS {
            return Err(InitiateRejection::TimestampExpired { age_secs: age });
        }
    }
    /// 3. Session TTL check
    if p.session_ttl_secs < 60 || p.session_ttl_secs > 1200 {
        return Err(InitiateRejection::InvalidSessionTtl);
    }
    /// 4. authorization_id length check (defense against malformed input)
    if p.authorization_id.len() != AUTH_ID_BYTES {
        return Err(InitiateRejection::MalformedPayload(
            format!("authorization_id length {} != {}",
                p.authorization_id.len(), AUTH_ID_BYTES)));
    }
    /// 5. operator_hash length check
    if p.operator_hash.len() != 32 {
        return Err(InitiateRejection::MalformedPayload(
            format!("operator_hash length {} != 32", p.operator_hash.len())));
    }
    /// 6. AK public match (if vm1 has expected key)
    if let Some(expected) = expected_vm0_ak_public {
        if p.vm0_ak_public != expected {
            use sha2::{Sha256, Digest};
            eprintln!("    AK MISMATCH DEBUG:");
            eprintln!("       payload AK: {} bytes, sha256={}",
                p.vm0_ak_public.len(),
                hex::encode(Sha256::digest(&p.vm0_ak_public)));
            eprintln!("       expected AK: {} bytes, sha256={}",
                expected.len(),
                hex::encode(Sha256::digest(expected)));
            eprintln!("       payload first 16 bytes: {}", hex::encode(&p.vm0_ak_public[..16.min(p.vm0_ak_public.len())]));
            eprintln!("       expected first 16 bytes: {}", hex::encode(&expected[..16.min(expected.len())]));
            return Err(InitiateRejection::AkPublicMismatch);
        }
    }
    // 7. Signature verification
    let bytes = p.canonical_bytes()
        .map_err(|e| InitiateRejection::MalformedPayload(e.to_string()))?;

    use sha2::{Sha256, Digest};
    let check_hash = Sha256::digest(&bytes);
    eprintln!("  VERIFY: bytes_len={} bytes_sha256={}",
        bytes.len(),
        hex::encode(&check_hash));
    eprintln!("  VERIFY: signature_len={} sig_sha256={}",
        signed.signature.len(),
        hex::encode(Sha256::digest(&signed.signature)));
    eprintln!("  VERIFY: ak_public_len={} ak_sha256={}",
        p.vm0_ak_public.len(),
        hex::encode(Sha256::digest(&p.vm0_ak_public)));
        
    let sig_valid = verify_rsa_signature(&bytes, &signed.signature, &p.vm0_ak_public)
        .map_err(|e| InitiateRejection::MalformedPayload(
            format!("Signature verify error: {}", e)))?;
    if !sig_valid {
        return Err(InitiateRejection::InvalidSignature);
    }

    Ok(())
}

/// Verify an RSA-SSA signature (what vm0's sign_data produces).
/// This mirrors verify_quote_signature but for arbitrary data (not TPM quotes).
fn verify_rsa_signature(
    data: &[u8],
    signature_bytes: &[u8],
    ak_public_bytes: &[u8],
) -> Result<bool> {
    if data.is_empty() || signature_bytes.is_empty() || ak_public_bytes.is_empty() {
        return Ok(false);
    }
    let mut context = crate::tpm::create_tpm_context_public()?;
    /// Unmarshall the AK public key
    let ak_public = tss_esapi::structures::Public::unmarshall(ak_public_bytes)
        .context("Failed to unmarshall AK public key")?;
    /// Load as external public key
    let key_handle = context.load_external_public(
        ak_public,
        tss_esapi::interface_types::resource_handles::Hierarchy::Null,
    ).context("Failed to load external public key")?;
    /// Hash the data (same as signing side)
    let digest_bytes = Sha256::digest(data);
    let digest = tss_esapi::structures::Digest::try_from(digest_bytes.as_slice())
        .context("Failed to create digest")?;
    /// Unmarshall the signature
    let signature = tss_esapi::structures::Signature::unmarshall(signature_bytes)
        .context("Failed to unmarshall signature")?;
    /// Verify
    let result = context.verify_signature(key_handle, digest, signature);
    let _ = context.flush_context(key_handle.into());
    match result {
        Ok(_) => Ok(true),
        Err(e) => {
            eprintln!("    RSA signature verification failed: {}", e);
            Ok(false)
        }
    }
}

// === Replay Protection ===

impl ReplayCache {
    pub fn new() -> Self {
        ReplayCache { seen: HashMap::new() }
    }
    /// Check if an authorization_id has been seen. If not, record it.
    /// Returns true if the ID is fresh (new), false if duplicate.
    pub fn check_and_record(&mut self, auth_id: &[u8]) -> bool {
        let now = now_secs();
        self.prune(now);

        if self.seen.contains_key(auth_id) {
            return false;
        }
        self.seen.insert(auth_id.to_vec(), now);
        true
    }
    /// Remove entries older than the replay window.
    fn prune(&mut self, now: u64) {
        self.seen.retain(|_, timestamp| {
            now.saturating_sub(*timestamp) <= INITIATE_MAX_AGE_SECS
        });
    }
    pub fn size(&self) -> usize {
        self.seen.len()
    }
}

impl Default for ReplayCache {
    fn default() -> Self { Self::new() }
}

// === Operator Authentication ===
pub async fn validate_operator(
    credentials_path: &str,
    passphrase1: &str,
    passphrase2: &str,
) -> Result<crate::yubikey::OperatorToken> {
    let credentials = crate::yubikey::StoredCredentials::load(credentials_path)?;
    let hash1 = credentials.passphrase1_hash.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing passphrase1 hash"))?;
    let hash2 = credentials.passphrase2_hash.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing passphrase2 hash"))?;
    let ok1 = crate::yubikey::verify_passphrase(passphrase1, hash1)?;
    let ok2 = crate::yubikey::verify_passphrase(passphrase2, hash2)?;
    if !(ok1 && ok2) {
        anyhow::bail!("Authentication failed");
    }
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(passphrase1.as_bytes());
    hasher.update(b"||");
    hasher.update(passphrase2.as_bytes());
    let operator_hash = hasher.finalize().to_vec();
    Ok(crate::yubikey::OperatorToken {
        operator_hash,
        authenticated_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        backend: "dev-two-passphrase".to_string(),
    })
}

// === Utilities ===
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}


// ===Tests ===
#[cfg(test)]
mod tests {
    use super::*;
    use bincode;
    
    fn dummy_attestation() -> Attestation {
        use crate::tpm::TpmQuote;
        use crate::tpm::{PcrValue, ImaMeasurements};
        use crate::ebpf::EbpfState;

        Attestation {
            vm_identity: "vm0".to_string(),
            tpm_quote: TpmQuote {
                pcr_values: vec![],
                quote_data: vec![0u8; 145],
                signature: vec![0u8; 262],
                ak_public: vec![0u8; 280],
                nonce: vec![0u8; 32],
                ima_measurements: ImaMeasurements {
                    count: 0,
                    aggregate_hash: vec![],
                    pcr10_value: vec![],
                },
                ebpf_state: EbpfState::default(),
            },
            timestamp: now_secs(),
        }
    }

    #[test]
    fn test_orchestrator_message_roundtrip() {
        let msg = OrchestratorMessage::AttestationRequest {
            nonce: vec![1, 2, 3, 4],
        };
        let bytes = bincode::serialize(&msg).unwrap();
        let decoded: OrchestratorMessage = bincode::deserialize(&bytes).unwrap();
        match decoded {
            OrchestratorMessage::AttestationRequest { nonce } => {
                assert_eq!(nonce, vec![1, 2, 3, 4]);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_cli_request_roundtrip() {
        let req = CliRequest::Authenticate {
            passphrase1: "test1".to_string(),
            passphrase2: "test2".to_string(),
            session_ttl_secs: 300,
        };
        let bytes = bincode::serialize(&req).unwrap();
        let decoded: CliRequest = bincode::deserialize(&bytes).unwrap();
        match decoded {
            CliRequest::Authenticate { session_ttl_secs, .. } => {
                assert_eq!(session_ttl_secs, 300);
            }
            _ => panic!("Wrong variant"),
        }
    }
    
    #[test]
    fn test_payload_construction_valid() {
        let op_hash = vec![0u8; 32];
        let ak_pub = vec![0u8; 280];
        let result = InitiatePayload::new(
            300,
            op_hash,
            dummy_attestation(),
            ak_pub,
        );
        assert!(result.is_ok());
        let p = result.unwrap();
        assert_eq!(p.version, 1);
        assert_eq!(p.authorization_id.len(), AUTH_ID_BYTES);
        assert_eq!(p.session_ttl_secs, 300);
    }

    #[test]
    fn test_payload_rejects_bad_ttl() {
        let op_hash = vec![0u8; 32];
        let ak_pub = vec![0u8; 280];
        assert!(InitiatePayload::new(59, op_hash.clone(), dummy_attestation(), ak_pub.clone()).is_err());
        assert!(InitiatePayload::new(1201, op_hash.clone(), dummy_attestation(), ak_pub.clone()).is_err());
        assert!(InitiatePayload::new(60, op_hash.clone(), dummy_attestation(), ak_pub.clone()).is_ok());
        assert!(InitiatePayload::new(1200, op_hash, dummy_attestation(), ak_pub).is_ok());
    }

    #[test]
    fn test_authorization_id_unique() {
        let op_hash = vec![0u8; 32];
        let ak_pub = vec![0u8; 280];
        let p1 = InitiatePayload::new(300, op_hash.clone(), dummy_attestation(), ak_pub.clone()).unwrap();
        let p2 = InitiatePayload::new(300, op_hash, dummy_attestation(), ak_pub).unwrap();
        assert_ne!(p1.authorization_id, p2.authorization_id,
            "authorization_id must be unique per call");
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let op_hash = vec![0u8; 32];
        let ak_pub = vec![0u8; 280];
        let p = InitiatePayload::new(300, op_hash, dummy_attestation(), ak_pub).unwrap();
        let b1 = p.canonical_bytes().unwrap();
        let b2 = p.canonical_bytes().unwrap();
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_replay_cache_detects_duplicate() {
        let mut cache = ReplayCache::new();
        let auth_id = vec![1u8; AUTH_ID_BYTES];
        assert!(cache.check_and_record(&auth_id), "First check should succeed");
        assert!(!cache.check_and_record(&auth_id), "Second check should fail (duplicate)");
    }

    #[test]
    fn test_replay_cache_different_ids_ok() {
        let mut cache = ReplayCache::new();
        let id1 = vec![1u8; AUTH_ID_BYTES];
        let id2 = vec![2u8; AUTH_ID_BYTES];

        assert!(cache.check_and_record(&id1));
        assert!(cache.check_and_record(&id2));
        assert_eq!(cache.size(), 2);
    }

    #[test]
    fn test_verify_rejects_old_timestamp() {
        let op_hash = vec![0u8; 32];
        let ak_pub = vec![0u8; 280];
        let mut p = InitiatePayload::new(300, op_hash, dummy_attestation(), ak_pub).unwrap();
        /// Backdate timestamp beyond max age
        p.timestamp = now_secs().saturating_sub(INITIATE_MAX_AGE_SECS + 100);
        /// Wrap in SignedInitiate with dummy signature — we're testing the
        /// timestamp check which happens before signature verification
        let signed = SignedInitiate {
            payload: p,
            signature: vec![0u8; 256],
        };
        let result = verify_initiate(&signed, None);
        match result {
            Err(InitiateRejection::TimestampExpired { .. }) => (),
            other => panic!("Expected TimestampExpired, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_rejects_future_timestamp() {
        let op_hash = vec![0u8; 32];
        let ak_pub = vec![0u8; 280];
        let mut p = InitiatePayload::new(300, op_hash, dummy_attestation(), ak_pub).unwrap();
        /// Set timestamp far in the future
        p.timestamp = now_secs() + 3600;
        let signed = SignedInitiate {
            payload: p,
            signature: vec![0u8; 256],
        };
        let result = verify_initiate(&signed, None);
        match result {
            Err(InitiateRejection::TimestampInFuture { .. }) => (),
            other => panic!("Expected TimestampInFuture, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_rejects_malformed_auth_id() {
        let op_hash = vec![0u8; 32];
        let ak_pub = vec![0u8; 280];
        let mut p = InitiatePayload::new(300, op_hash, dummy_attestation(), ak_pub).unwrap();
        p.authorization_id = vec![0u8; 16]; /// Wrong length
        let signed = SignedInitiate {
            payload: p,
            signature: vec![0u8; 256],
        };
        let result = verify_initiate(&signed, None);
        match result {
            Err(InitiateRejection::MalformedPayload(_)) => (),
            other => panic!("Expected MalformedPayload, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_rejects_unsupported_version() {
        let op_hash = vec![0u8; 32];
        let ak_pub = vec![0u8; 280];
        let mut p = InitiatePayload::new(300, op_hash, dummy_attestation(), ak_pub).unwrap();
        p.version = 99;

        let signed = SignedInitiate {
            payload: p,
            signature: vec![0u8; 256],
        };
        let result = verify_initiate(&signed, None);
        match result {
            Err(InitiateRejection::UnsupportedVersion { version: 99 }) => (),
            other => panic!("Expected UnsupportedVersion(99), got {:?}", other),
        }
    }

    #[test]
    fn test_verify_ak_mismatch() {
        let op_hash = vec![0u8; 32];
        let ak_pub = vec![1u8; 280];
        let p = InitiatePayload::new(300, op_hash, dummy_attestation(), ak_pub).unwrap();

        let signed = SignedInitiate {
            payload: p,
            signature: vec![0u8; 256],
        };
        /// Pass different expected AK
        let expected = vec![2u8; 280];
        let result = verify_initiate(&signed, Some(&expected));
        match result {
            Err(InitiateRejection::AkPublicMismatch) => (),
            other => panic!("Expected AkPublicMismatch, got {:?}", other),
        }
    }
}


