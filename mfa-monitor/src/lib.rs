use serde::{Serialize, Deserialize};
use anyhow::Result;
use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

use mfa_agent::crypto;

// === Wire Protocol Mesagges ===
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFwdMessage {
    /// First message after key exchange, identifies the source node
    Hello { node_id: String },
    /// Audit log entry (raw JSON line from audit.jsonl)
    Entry { json: String },
    /// Keepalive
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFwdResponse {
    /// Monitor accepted the hello
    Welcome,
    /// Entry acknowledged
    Ack,
    /// Connection rejected
    Reject { reason: String },
}

// === Framing, length-prefixed raw bytes ===

pub async fn send_raw(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn receive_raw(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > 10_000_000 {
        return Err(anyhow::anyhow!("Message too large: {} bytes", len));
    }
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    Ok(data)
}

// === Encrypted Message Helpers ===
pub async fn send_message(
    stream: &mut TcpStream,
    key: &[u8; 32],
    msg: &LogFwdMessage,
) -> Result<()> {
    let plaintext = bincode::serialize(msg)?;
    let encrypted = crypto::encrypt(key, &plaintext)?;
    send_raw(stream, &encrypted).await
}

pub async fn receive_message(
    stream: &mut TcpStream,
    key: &[u8; 32],
) -> Result<LogFwdMessage> {
    let encrypted = receive_raw(stream).await?;
    let plaintext = crypto::decrypt(key, &encrypted)?;
    let msg: LogFwdMessage = bincode::deserialize(&plaintext)?;
    Ok(msg)
}

pub async fn send_response(
    stream: &mut TcpStream,
    key: &[u8; 32],
    msg: &LogFwdResponse,
) -> Result<()> {
    let plaintext = bincode::serialize(msg)?;
    let encrypted = crypto::encrypt(key, &plaintext)?;
    send_raw(stream, &encrypted).await
}

pub async fn receive_response(
    stream: &mut TcpStream,
    key: &[u8; 32],
) -> Result<LogFwdResponse> {
    let encrypted = receive_raw(stream).await?;
    let plaintext = crypto::decrypt(key, &encrypted)?;
    let msg: LogFwdResponse = bincode::deserialize(&plaintext)?;
    Ok(msg)
}

// === Key Exchange, initiator side (used by logfwd) ===
pub async fn establish_session_initiator(
    stream: &mut TcpStream,
    node_id: &str,
) -> Result<[u8; 32]> {
    let (init, kyber_sk, x25519_secret, nonce) =
        crypto::generate_key_exchange_init(node_id)?;

    let init_bytes = bincode::serialize(&init)?;
    send_raw(stream, &init_bytes).await?;

    let resp_bytes = receive_raw(stream).await?;
    let response: crypto::KeyExchangeResponse = bincode::deserialize(&resp_bytes)?;

    let keys = crypto::complete_key_exchange(&init, &response, &kyber_sk, x25519_secret, &nonce)?;
    Ok(keys.session_key)
}

// === Key Exchange, responder side (used by monitor) ===
pub async fn establish_session_responder(
    stream: &mut TcpStream,
    node_id: &str,
) -> Result<[u8; 32]> {
    let init_bytes = receive_raw(stream).await?;
    let init: crypto::KeyExchangeInit = bincode::deserialize(&init_bytes)?;

    let (response, keys) = crypto::generate_key_exchange_response(node_id, &init)?;

    let resp_bytes = bincode::serialize(&response)?;
    send_raw(stream, &resp_bytes).await?;

    Ok(keys.session_key)
}
pub mod session_tracker;

