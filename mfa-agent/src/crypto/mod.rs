use anyhow::Result;
use serde::{Serialize, Deserialize};
use rand::rngs::OsRng;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey, SecretKey, Ciphertext, SharedSecret};
use x25519_dalek::{PublicKey as X25519PublicKey, EphemeralSecret};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangeInit {
    pub sender_id: String,
    pub kyber_pk: Vec<u8>,
    pub x25519_pk: [u8; 32],
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangeResponse {
    pub responder_id: String,
    pub kyber_ct: Vec<u8>,
    pub x25519_pk: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SessionKeys {
    pub session_key: [u8; 32],
}

// === Key Exchange ===
pub fn generate_key_exchange_init(sender_id: &str) -> Result<(KeyExchangeInit, Vec<u8>, EphemeralSecret, [u8; 32])> {
    let (kyber_pk, kyber_sk) = kyber1024::keypair();  
    let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
    let x25519_pk = X25519PublicKey::from(&x25519_secret);   
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce);   
    let init = KeyExchangeInit {
        sender_id: sender_id.to_string(),
        kyber_pk: kyber_pk.as_bytes().to_vec(),
        x25519_pk: x25519_pk.to_bytes(),
        nonce,
    };
    
    Ok((init, kyber_sk.as_bytes().to_vec(), x25519_secret, nonce))
}

pub fn generate_key_exchange_response(
    responder_id: &str,
    init: &KeyExchangeInit,
) -> Result<(KeyExchangeResponse, SessionKeys)> {
    let kyber_pk = kyber1024::PublicKey::from_bytes(&init.kyber_pk)
        .map_err(|_| anyhow::anyhow!("Invalid Kyber public key"))?;
    let (kyber_shared, kyber_ct) = kyber1024::encapsulate(&kyber_pk);
    let ct_bytes = kyber_ct.as_bytes();
    let ss_bytes = kyber_shared.as_bytes();   
    println!("  After swap - CT: {} bytes, SS: {} bytes", ct_bytes.len(), ss_bytes.len());   
    let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
    let x25519_pk = X25519PublicKey::from(&x25519_secret);  
    let init_x25519_pk = X25519PublicKey::from(init.x25519_pk);
    let x25519_shared = x25519_secret.diffie_hellman(&init_x25519_pk);   
    let mut transcript_hasher = Sha256::new();
    transcript_hasher.update(&init.sender_id.as_bytes());
    transcript_hasher.update(&init.kyber_pk);
    transcript_hasher.update(&init.x25519_pk);
    transcript_hasher.update(&init.nonce);
    transcript_hasher.update(responder_id.as_bytes());
    transcript_hasher.update(ct_bytes);
    transcript_hasher.update(&x25519_pk.to_bytes());
    let transcript: [u8; 32] = transcript_hasher.finalize().into();
    let session_key = derive_session_key(
        ss_bytes,
        x25519_shared.as_bytes(),
        &init.nonce,
        &transcript,
    );    
    let response = KeyExchangeResponse {
        responder_id: responder_id.to_string(),
        kyber_ct: ct_bytes.to_vec(),
        x25519_pk: x25519_pk.to_bytes(),
    };    
    println!("  Response kyber_ct: {} bytes", response.kyber_ct.len());    
    let keys = SessionKeys {
        session_key,
    };   
    Ok((response, keys))
}

pub fn complete_key_exchange(
    init: &KeyExchangeInit,
    response: &KeyExchangeResponse,
    kyber_sk_bytes: &[u8],
    x25519_secret: EphemeralSecret,
    nonce: &[u8; 32],
) -> Result<SessionKeys> {
    println!("  Received kyber_ct: {} bytes", response.kyber_ct.len());
    if response.kyber_ct.len() != 1568 {
        return Err(anyhow::anyhow!("Expected 1568 bytes, got {}", response.kyber_ct.len()));
    }
    let kyber_ct = kyber1024::Ciphertext::from_bytes(&response.kyber_ct)
        .map_err(|_| anyhow::anyhow!("Failed to parse ciphertext"))?;
    let kyber_sk = kyber1024::SecretKey::from_bytes(kyber_sk_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid Kyber secret key"))?;
    let kyber_shared = kyber1024::decapsulate(&kyber_ct, &kyber_sk);
    println!("  Decapsulated SS: {} bytes", kyber_shared.as_bytes().len());
    let resp_x25519_pk = X25519PublicKey::from(response.x25519_pk);
    let x25519_shared = x25519_secret.diffie_hellman(&resp_x25519_pk);
    /// Transcript: must match generate_key_exchange_response exactly
    let mut transcript_hasher = Sha256::new();
    transcript_hasher.update(init.sender_id.as_bytes());
    transcript_hasher.update(&init.kyber_pk);
    transcript_hasher.update(&init.x25519_pk);
    transcript_hasher.update(&init.nonce);
    transcript_hasher.update(response.responder_id.as_bytes());
    transcript_hasher.update(&response.kyber_ct);
    transcript_hasher.update(&response.x25519_pk);
    let transcript: [u8; 32] = transcript_hasher.finalize().into();
    let session_key = derive_session_key(
        kyber_shared.as_bytes(),
        x25519_shared.as_bytes(),
        nonce,
        &transcript,
    );

    Ok(SessionKeys {
        session_key,
    })
}

// === Key Derivation ===

fn derive_session_key(
    kyber_shared: &[u8],
    x25519_shared: &[u8],
    nonce: &[u8],
    transcript: &[u8],
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(kyber_shared.len() + x25519_shared.len());
    ikm.extend_from_slice(kyber_shared);
    ikm.extend_from_slice(x25519_shared);
    let prk = hmac_sha256(nonce, &ikm);
    /// Include transcript in the info parameter
    let mut info = Vec::from(&b"MFA-ZeroTrust-Session-v1"[..]);
    info.extend_from_slice(transcript);
    info.push(0x01);
    hmac_sha256(&prk, &info)
}

/// HMAC-SHA256 per RFC 2104. Key can be any length.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    /// If key > block size, hash it first
    let key_block = if key.len() > BLOCK_SIZE {
        let h: [u8; 32] = Sha256::digest(key).into();
        let mut kb = [0u8; BLOCK_SIZE];
        kb[..32].copy_from_slice(&h);
        kb
    } else {
        let mut kb = [0u8; BLOCK_SIZE];
        kb[..key.len()].copy_from_slice(key);
        kb
    };
    /// ipad = key XOR 0x36, opad = key XOR 0x5c
    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    /// inner = SHA256(ipad || message)
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let inner_hash = inner.finalize();
    /// outer = SHA256(opad || inner_hash)
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize().into()
}

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());    
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);   
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;  
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

pub fn decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 12 {
        return Err(anyhow::anyhow!("Ciphertext too short"));
    }   
    let cipher = Aes256Gcm::new(key.into()); 
    let (nonce_bytes, ct) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);   
    let plaintext = cipher.decrypt(nonce, ct)
        .map_err(|_| anyhow::anyhow!("Decryption failed"))?;
    
    Ok(plaintext)
}

