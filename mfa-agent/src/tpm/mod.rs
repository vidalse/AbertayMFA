use anyhow::{Result, Context};
use tss_esapi::{
    Context as TpmContext,
    tcti_ldr::TctiNameConf,
    interface_types::{
        algorithm::HashingAlgorithm,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        PcrSelectionListBuilder, PcrSlot,
        Data, SignatureScheme,
    },
    traits::{Marshall, UnMarshall},
};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::fs;
use crate::ebpf;

// === Data Structures ===
#[derive(Clone)]
pub struct TpmCtx {
    _marker: std::marker::PhantomData<TpmContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmQuote {
    pub pcr_values: Vec<PcrValue>,
    pub quote_data: Vec<u8>,        /// Marshalled TPMS_ATTEST from TPM2_Quote (empty if unsigned)
    pub signature: Vec<u8>,          /// Marshalled TPMT_SIGNATURE from TPM2_Quote (empty if unsigned)
    pub ak_public: Vec<u8>,          /// Marshalled TPM2B_PUBLIC of the AK (empty if unsigned)
    pub nonce: Vec<u8>,
    pub ima_measurements: ImaMeasurements,
    pub ebpf_state: ebpf::EbpfState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PcrValue {
    pub index: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImaMeasurements {
    pub count: usize,
    pub aggregate_hash: Vec<u8>,
    pub pcr10_value: Vec<u8>,
    /// Raw IMA measurement log for prefix-aggregate verification.
    /// Verifier recomputes hash of first N entries against baseline to detect log tampering.
    #[serde(default)]
    pub measurements_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrBaseline {
    pub vm_identity: String,
    pub pcr_values: Vec<PcrValue>,
    pub ima_baseline: Option<ImaMeasurements>,
    pub ebpf_baseline: Option<ebpf::EbpfState>,
    pub ak_public: Option<Vec<u8>>,   // AK public key for signature verification
    pub timestamp: u64,
    pub description: String,
}

// === TPM Context Management ===

/// Public wrapper around create_tpm_context for use by other modules.
/// Creates a new TPM context for operations like signature verification.
pub fn create_tpm_context_public() -> Result<tss_esapi::Context> {
    create_tpm_context()
}

fn create_tpm_context() -> Result<TpmContext> {
    std::env::set_var("TPM2TOOLS_TCTI", "device:/dev/tpmrm0");

    let tcti = TctiNameConf::from_environment_variable()
        .context("Failed to create TCTI")?;

    TpmContext::new(tcti)
        .context("Failed to create TPM context")
}

pub fn init() -> Result<TpmCtx> {
    /// Verify TPM is accessible by creating a test context
    let _ctx = create_tpm_context()?;
    println!("  TPM ready");
    Ok(TpmCtx {
        _marker: std::marker::PhantomData,
    })
}

// === PCR Reading ===
fn pcr_selection_0_7() -> Result<tss_esapi::structures::PcrSelectionList> {
    PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[
                PcrSlot::Slot0, PcrSlot::Slot1, PcrSlot::Slot2, PcrSlot::Slot3,
                PcrSlot::Slot4, PcrSlot::Slot5, PcrSlot::Slot6, PcrSlot::Slot7,
            ],
        )
        .build()
        .context("Failed to build PCR selection")
}

fn read_pcrs(context: &mut TpmContext) -> Result<Vec<PcrValue>> {
    let pcr_selection = pcr_selection_0_7()?;

    let (_update_counter, _selection_out, digest_list) = context
        .pcr_read(pcr_selection)
        .context("Failed to read PCRs")?;

    let mut pcr_values = Vec::new();
    for (slot, digest) in digest_list.value().iter().enumerate() {
        if slot < 8 {
            pcr_values.push(PcrValue {
                index: slot as u8,
                value: digest.value().to_vec(),
            });
        }
    }

    Ok(pcr_values)
}

fn read_pcr10() -> Result<Vec<u8>> {
    let mut context = create_tpm_context()?;
    let pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot10])
        .build()
        .context("Failed to build PCR10 selection")?;
    let (_update_counter, _selection_out, digest_list) = context
        .pcr_read(pcr_selection)
        .context("Failed to read PCR10")?;
    if let Some(digest) = digest_list.value().get(0) {
        Ok(digest.value().to_vec())
    } else {
        Ok(vec![0u8; 32])
    }
}

// === IMA Measurements ===
fn read_ima_measurements() -> Result<ImaMeasurements> {
    let count_str = fs::read_to_string("/sys/kernel/security/ima/runtime_measurements_count")
        .context("Failed to read IMA count")?;
    let count: usize = count_str.trim().parse()
        .context("Failed to parse IMA count")?;
    let measurements = fs::read_to_string("/sys/kernel/security/ima/ascii_runtime_measurements")
        .context("Failed to read IMA measurements")?;
    let mut hasher = Sha256::new();
    hasher.update(measurements.as_bytes());
    let aggregate_hash = hasher.finalize().to_vec();
    let pcr10_value = read_pcr10()?;
    Ok(ImaMeasurements {
        count,
        aggregate_hash,
        pcr10_value,
        measurements_text: measurements,
    })
}

// === TPM SIGNING: RESTRICTED AK for TPM2_Quote ===
/// Create RESTRICTED AK and sign a PCR quote.
/// Returns (quote_data, signature, ak_public) as marshalled bytes.
fn create_ak_and_sign_quote(nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut context = create_tpm_context()?;
    /// Build RESTRICTED signing key object attributes
    let object_attributes = tss_esapi::attributes::ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(true)
        .build()
        .context("Failed to build restricted AK object attributes")?;
    /// RSA scheme: RSASSA with SHA-256
    let ak_scheme = tss_esapi::structures::RsaScheme::create(
        tss_esapi::interface_types::algorithm::RsaSchemeAlgorithm::RsaSsa,
        Some(HashingAlgorithm::Sha256),
    )
    .context("Failed to create RSA scheme")?;
    /// Build RSA parameters directly using PublicRsaParameters::new()
    let rsa_params = tss_esapi::structures::PublicRsaParameters::new(
        tss_esapi::structures::SymmetricDefinitionObject::Null,
        ak_scheme,
        tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa2048,
        tss_esapi::structures::RsaExponent::default(),
    );
    /// Build the full Public structure
    let ak_template = tss_esapi::structures::PublicBuilder::new()
        .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(tss_esapi::structures::PublicKeyRsa::default())
        .build()
        .context("Failed to build restricted AK template")?;
    /// Create the AK as a primary key (deterministic from TPM seed)
    let ak_result = context.execute_with_session(
        Some(AuthSession::Password),
        |ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                ak_template,
                None,  // auth_value
                None,  // initial_data
                None,  // outside_info
                None,  // creation_pcrs
            )
        },
    )
    .context("Failed to create restricted AK primary key")?;
    /// Marshall the AK public key for storage/verification
    let ak_public_bytes = ak_result.out_public.marshall()
        .context("Failed to marshall AK public key")?;
    /// Build PCR selection for the quote (PCRs 0-7)
    let pcr_selection = pcr_selection_0_7()?;
    /// Create qualifying data (nonce) for freshness
    let qualifying_data = Data::try_from(nonce.to_vec())
        .context("Failed to create qualifying data")?;
    /// Execute TPM2_Quote
    let (attest, signature) = context.execute_with_session(
        Some(AuthSession::Password),
        |ctx| {
            ctx.quote(
                ak_result.key_handle,
                qualifying_data,
                SignatureScheme::Null,  /// Use key's default scheme (RSASSA-SHA256)
                pcr_selection,
            )
        },
    )
    .context("TPM2_Quote with restricted AK failed")?;
    /// Marshall attestation data and signature
    let attest_bytes = attest.marshall()
        .context("Failed to marshall attest data")?;
    let signature_bytes = signature.marshall()
        .context("Failed to marshall signature")?;
    /// Clean up, flush the AK from TPM transient memory
    context.flush_context(ak_result.key_handle.into())
        .context("Failed to flush AK context")?;

    Ok((attest_bytes, signature_bytes, ak_public_bytes))
}

// === QUOTE GENERATION (main entry point) ===
pub fn generate_quote(_tpm: &TpmCtx) -> Result<TpmQuote> {
    let mut context = create_tpm_context()?;
    /// Read PCR values (always works)
    let pcr_values = read_pcrs(&mut context)?;
    println!("  Read {} PCR values", pcr_values.len());
    drop(context);  /// Release context before signing (needs its own context)
    /// Generate nonce for freshness
    let nonce: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    /// Attempt TPM-signed quote with RESTRICTED AK
    let (quote_data, signature, ak_public) = match create_ak_and_sign_quote(&nonce) {
        Ok((qd, sig, ak)) => {
            println!("  RESTRICTED AK quote ({} bytes attest, {} bytes sig, {} bytes AK)",
                qd.len(), sig.len(), ak.len());
            (qd, sig, ak)
        }
        Err(e) => {
            /// Fall back to unsigned quote (preserves existing functionality)
            eprintln!("  TPM signing failed: {} (using unsigned quote)", e);
            (vec![], vec![], vec![])
        }
    };
    /// Read IMA measurements
    let ima_measurements = read_ima_measurements()?;
    println!("  Read {} IMA measurements", ima_measurements.count);
    /// Collect eBPF/system state
    let ebpf_state = ebpf::collect_state()?;
    println!("  Collected eBPF state: {} processes, {} connections",
        ebpf_state.process_count, ebpf_state.network_connections);

    Ok(TpmQuote {
        pcr_values,
        quote_data,
        signature,
        ak_public,
        nonce,
        ima_measurements,
        ebpf_state,
    })
}

// === SIGNATURE VERIFICATION ===
/// Verify the TPM signature on a quote using the local TPM
pub fn verify_quote_signature(
    quote_data: &[u8],
    signature_bytes: &[u8],
    ak_public_bytes: &[u8],
) -> Result<bool> {
    if quote_data.is_empty() || signature_bytes.is_empty() || ak_public_bytes.is_empty() {
        return Ok(false);  // No signature to verify
    }
    let mut context = create_tpm_context()?;
    /// Unmarshall the AK public key
    let ak_public = tss_esapi::structures::Public::unmarshall(ak_public_bytes)
        .context("Failed to unmarshall AK public key")?;
    /// Load the external public key into this TPM for verification
    let key_handle = context.load_external_public(ak_public, Hierarchy::Null)
        .context("Failed to load external public key")?;
    /// Compute SHA-256 digest of the attestation data
    /// (TPM2_VerifySignature expects the digest that was signed)
    let digest_bytes = Sha256::digest(quote_data);
    let digest = tss_esapi::structures::Digest::try_from(digest_bytes.as_slice())
        .context("Failed to create digest")?;
    /// Unmarshall the signature
    let signature = tss_esapi::structures::Signature::unmarshall(signature_bytes)
        .context("Failed to unmarshall signature")?;
    /// Verify the signature
    let result = context.verify_signature(key_handle, digest, signature);
    /// Clean up
    let _ = context.flush_context(key_handle.into());

    match result {
        Ok(_ticket) => Ok(true),
        Err(e) => {
            println!("    Signature verification failed: {}", e);
            Ok(false)
        }
    }
}

/// Check if two AK public keys match (same TPM)
pub fn ak_public_matches(current: &[u8], baseline: &[u8]) -> bool {
    if current.is_empty() || baseline.is_empty() {
        return true;  /// Can't compare if either is missing
    }
    current == baseline
}

// === UNRESTRICTED SIGNING KEY — for audit log signatures ===
/// Sign arbitrary data using a fresh unrestricted RSA-2048 signing key.
/// 	Returns (signature_bytes, signing_key_public_bytes).
/// 	Both are needed by the verifier, signature to check, public key to check with.
pub fn sign_data(_tpm: &TpmCtx, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut context = create_tpm_context()?;
    let ak_scheme = tss_esapi::structures::RsaScheme::create(
        tss_esapi::interface_types::algorithm::RsaSchemeAlgorithm::RsaSsa,
        Some(tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256),
    ).context("Failed to create RSA scheme")?;
    let ak_template = tss_esapi::utils::create_unrestricted_signing_rsa_public(
        ak_scheme,
        tss_esapi::interface_types::key_bits::RsaKeyBits::Rsa2048,
        tss_esapi::structures::RsaExponent::default(),
    ).context("Failed to create unrestricted signing key template")?;
    let ak_result = context.execute_with_session(
        Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
        |ctx| {
            ctx.create_primary(
                tss_esapi::interface_types::resource_handles::Hierarchy::Owner,
                ak_template, None, None, None, None,
            )
        },
    ).context("Failed to create unrestricted signing key")?;
    /// Extract the public key bytes (needed by the verifier)
    let signing_public_bytes = ak_result.out_public.marshall()
        .context("Failed to marshall signing public key")?;
    let digest_bytes = Sha256::digest(data);
    let digest = tss_esapi::structures::Digest::try_from(digest_bytes.as_slice())
        .context("Failed to create digest")?;
    let ticket = tss_esapi::structures::HashcheckTicket::try_from(
        tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
            tag: 0x8024,
            hierarchy: 0x40000007,
            digest: Default::default(),
        }
    ).context("Failed to create null ticket")?;
    let signature = context.execute_with_session(
        Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
        |ctx| {
            ctx.sign(
                ak_result.key_handle,
                digest.clone(),
                tss_esapi::structures::SignatureScheme::Null,
                ticket.clone(),
            )
        },
    ).context("TPM sign failed")?;
    let sig_bytes = signature.marshall()
        .context("Failed to marshall signature")?;
    context.flush_context(ak_result.key_handle.into())
        .context("Failed to flush signing key")?;

    Ok((sig_bytes, signing_public_bytes))
}

// === BASELINE CAPTURE ===
pub fn capture_baseline(tpm: &TpmCtx, vm_identity: &str, description: &str) -> Result<PcrBaseline> {
    let quote = generate_quote(tpm)?;
    /// The AK public key from the quote will be stored in the baseline
    /// for future signature verification
    let ak_public = if quote.ak_public.is_empty() {
        None
    } else {
        println!("  AK public key captured: {} bytes (restricted)", quote.ak_public.len());
        Some(quote.ak_public)
    };

    Ok(PcrBaseline {
        vm_identity: vm_identity.to_string(),
        pcr_values: quote.pcr_values,
        ima_baseline: Some(quote.ima_measurements),
        ebpf_baseline: Some(quote.ebpf_state),
        ak_public,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        description: description.to_string(),
    })
}

pub fn display_pcrs(pcrs: &[PcrValue]) {
    println!("  PCR Values:");
    for pcr in pcrs {
        println!("    PCR{:02}: {}", pcr.index, hex::encode(&pcr.value));
    }
}


