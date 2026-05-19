use anyhow::{Result, Context};
use serde::Deserialize;
use tokio::net::TcpStream;
use std::io::{BufRead, Seek, SeekFrom};

use mfa_monitor::{
    LogFwdMessage, LogFwdResponse,
    establish_session_initiator, send_message, receive_response,
};

const DEFAULT_CONFIG: &str = "logfwd.json";

// === Config ===
#[derive(Debug, Clone, Deserialize)]
struct LogFwdConfig {
    node_id: String,
    audit_log_path: String,
    monitor_address: String,
    reconnect_interval_secs: u64,
    poll_interval_ms: u64,
}

impl LogFwdConfig {
    fn load(path: &str) -> Result<Self> {
        let json = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path))?;
        serde_json::from_str(&json)
            .with_context(|| format!("Failed to parse config: {}", path))
    }
}

// === File Tailing, polls for new content ===
struct FileTailer {
    path: String,
    position: u64,
}
impl FileTailer {
    fn new(path: &str) -> Self {
        /// Start from end of file (only forward new entries)
        let position = std::fs::metadata(path)
            .map(|m| m.len())
            .unwrap_or(0);

        FileTailer {
            path: path.to_string(),
            position,
        }
    }
    /// Read new lines since last check. Returns empty vec if nothing new.
    fn read_new_lines(&mut self) -> Vec<String> {
        let mut lines = Vec::new();

        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return lines,
        };
        /// Check if file was truncated (log rotation or reset)
        if let Ok(metadata) = file.metadata() {
            if metadata.len() < self.position {
                self.position = 0;
            }
        }
        let mut reader = std::io::BufReader::new(file);
        if reader.seek(SeekFrom::Start(self.position)).is_err() {
            return lines;
        }
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(n) => {
                    self.position += n as u64;
                    let trimmed = line.trim().to_string();
                    if !trimmed.is_empty() {
                        lines.push(trimmed);
                    }
                }
                Err(_) => break,
            }
        }
        lines
    }
}

// === Main ===
#[tokio::main]
async fn main() -> Result<()> {
    let config_path = std::env::args().nth(1)
        .unwrap_or_else(|| DEFAULT_CONFIG.to_string());
    let config = LogFwdConfig::load(&config_path)?;
    println!("MFA Log Forwarder");
    println!("   Node:   {}", config.node_id);
    println!("   Source: {}", config.audit_log_path);
    println!("   Target: {}", config.monitor_address);
    /// Retry loop, reconnect on failure
    loop {
        match run_forwarding(&config).await {
            Ok(()) => println!("Connection closed cleanly"),
            Err(e) => eprintln!("Forwarding error: {}", e),
        }

        println!("Reconnecting in {}s...", config.reconnect_interval_secs);
        tokio::time::sleep(tokio::time::Duration::from_secs(
            config.reconnect_interval_secs
        )).await;
    }
}

async fn connect_with_retry(addr: &str) -> Result<TcpStream> {
    let mut delay_secs: u64 = 1;
    let max_delay: u64 = 30;
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match TcpStream::connect(addr).await {
            Ok(s) => {
                if attempt > 1 {
                    println!("Connected to {} after {} attempts", addr, attempt);
                }
                return Ok(s);
            }
            Err(e) => {
                if attempt == 1 || attempt % 5 == 0 {
                    println!("Connecting to {} (attempt {}): {} — retrying in {}s",
                        addr, attempt, e, delay_secs);
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;
                delay_secs = (delay_secs * 2).min(max_delay);
            }
        }
    }
}

async fn run_forwarding(config: &LogFwdConfig) -> Result<()> {
    /// Connect to VM5
    println!("Connecting to {}...", config.monitor_address);
    let mut stream = connect_with_retry(&config.monitor_address).await?;
    println!("Connected");
    /// Key exchange (ML-KEM-768 + X25519)
    println!("Key exchange...");
    let session_key = establish_session_initiator(&mut stream, &config.node_id).await
        .context("Key exchange failed")?;
    println!("Session established (hybrid post-quantum)");
    /// Send Hello
    send_message(&mut stream, &session_key, &LogFwdMessage::Hello {
        node_id: config.node_id.clone(),
    }).await?;
    /// Wait for Welcome
    let response = receive_response(&mut stream, &session_key).await?;
    match response {
        LogFwdResponse::Welcome => println!("Authenticated with monitor"),
        LogFwdResponse::Reject { reason } => {
            return Err(anyhow::anyhow!("Monitor rejected: {}", reason));
        }
        _ => return Err(anyhow::anyhow!("Unexpected response to Hello")),
    }
    /// Start tailing
    let mut tailer = FileTailer::new(&config.audit_log_path);
    let mut entries_sent: u64 = 0;
    let mut ping_counter: u64 = 0;
    
    println!("Tailing {} ...", config.audit_log_path);
    loop {
        let new_lines = tailer.read_new_lines();

        for line in &new_lines {
            send_message(&mut stream, &session_key, &LogFwdMessage::Entry {
                json: line.clone(),
            }).await?;

            let ack = receive_response(&mut stream, &session_key).await?;
            match ack {
                LogFwdResponse::Ack => {
                    entries_sent += 1;
                    if entries_sent % 10 == 0 {
                        println!("  {} entries forwarded", entries_sent);
                    }
                }
                LogFwdResponse::Reject { reason } => {
                    eprintln!("  Entry rejected: {}", reason);
                }
                _ => {}
            }
        }
        /// Periodic ping for dead connection detection (~60s when idle)
        ping_counter += 1;
        if new_lines.is_empty() && ping_counter % 120 == 0 {
            send_message(&mut stream, &session_key, &LogFwdMessage::Ping).await?;
            let _ = receive_response(&mut stream, &session_key).await?;
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(
            config.poll_interval_ms
        )).await;
    }
}
