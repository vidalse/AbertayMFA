use anyhow::{Result, Context};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use std::io::Write;
use mfa_agent::orchestrator::{CliRequest, CliResponse};

const DEFAULT_SOCKET: &str = "/run/mfa-agent/orchestrator.sock";

// === Main + CLI parsing ===
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }
    let socket_path = parse_socket_arg(&args).unwrap_or_else(|| DEFAULT_SOCKET.to_string());
    let command = args[1].as_str();
    match command {
        "authenticate" | "auth" => authenticate_flow(&socket_path).await,
        "status" => status_flow(&socket_path).await,
        "revoke" => revoke_flow(&socket_path).await,
        "-h" | "--help" | "help" => { print_usage(); Ok(()) }
        other => {
            eprintln!("Unknown command: {}", other);
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  vm0-cli authenticate  — start authorization flow");
    eprintln!("  vm0-cli status        — query current session status");
    eprintln!("  vm0-cli revoke        — revoke current session");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --socket PATH         — override default socket path");
}

fn parse_socket_arg(args: &[String]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--socket" {
            return iter.next().map(|s| s.to_string());
        }
    }
    None
}

// === Authenticate Flow ===

async fn authenticate_flow(socket_path: &str) -> Result<()> {
    println!("═══════════════════════════════════════════════════════════");
    println!("    MFA ZERO-TRUST — Operator Authorization");
    println!("═══════════════════════════════════════════════════════════\n");
    /// Prompt for credentials
    let passphrase1 = prompt_secret("Passphrase 1")?;
    let passphrase2 = prompt_secret("Passphrase 2")?;
    /// Prompt for session TTL
    let session_ttl_secs = if socket_path.contains("vm4") {
        0
    } else {
        println!();
        let ttl_str = prompt_with_default("Session duration in minutes (1-20)", "8")?;
        let ttl_minutes: u64 = ttl_str.parse()
            .context("Invalid session duration")?;
        if !(1..=20).contains(&ttl_minutes) {
            anyhow::bail!("Session duration must be between 1 and 20 minutes");
        }
        ttl_minutes * 60
    };
    println!();
    println!("Contacting vm0 orchestrator...");
    let request = CliRequest::Authenticate {
        passphrase1,
        passphrase2,
        session_ttl_secs,
    };
    let response = send_request(socket_path, &request).await?;
    match response {
        CliResponse::Authorized {
            authorization_id,
            session_token_hash,
            session_expiry,
            chain1_nodes,
            chain2_nodes,
        } => {
            println!();
            println!("SESSION AUTHORIZED");
            println!("─────────────────────────────────────────");
            println!("  Authorization ID: {}", hex::encode(&authorization_id[..8]));
            println!("  Session hash:     {}", hex::encode(&session_token_hash[..16]));
            println!("  Expires:          unix {}", session_expiry);
            println!("  Chain 1:          {} nodes verified", chain1_nodes);
            println!("  Chain 2:          {} nodes verified", chain2_nodes);
            println!();
            Ok(())
        }
        CliResponse::Denied { reason } => {
            eprintln!();
            eprintln!("AUTHORIZATION DENIED");
            eprintln!("─────────────────────────────────────────");
            eprintln!("  Reason: {}", reason);
            eprintln!();
            std::process::exit(1);
        }
        CliResponse::Error { message } => {
            eprintln!();
            eprintln!("ERROR: {}", message);
            std::process::exit(2);
        }
        _ => {
            eprintln!("Unexpected response from orchestrator");
            std::process::exit(3);
        }
    }
}

// === Status Flow ===

async fn status_flow(socket_path: &str) -> Result<()> {
    let response = send_request(socket_path, &CliRequest::Status).await?;
    match response {
        CliResponse::Status { active, authorization_id, expires_in_secs } => {
            if active {
                let auth_id = authorization_id
                    .map(|a| hex::encode(&a[..8]))
                    .unwrap_or_else(|| "unknown".to_string());
                let exp = expires_in_secs.unwrap_or(0);
                println!("Active session");
                println!("   Authorization ID: {}", auth_id);
                println!("   Expires in: {} seconds ({} minutes)", exp, exp / 60);
            } else {
                println!("⚫ No active session");
            }
            Ok(())
        }
        CliResponse::PendingApproval {
            requester_id, requester_ip, session_ttl_secs, attestation_summary
        } => {
            println!();
            println!("═══════════════════════════════════════════");
            println!(" PENDING APPROVAL REQUEST");
            println!("═══════════════════════════════════════════════");
            println!("  Requester:   {} ({})", requester_id, requester_ip);
            println!("  Session TTL: {} minutes", session_ttl_secs / 60);
            println!("  Attestation: {}", attestation_summary);
            println!();
            println!("  → Run 'vm0-cli authenticate' to APPROVE");
            println!("  → Run 'vm0-cli revoke' to DENY");
            println!();
            Ok(())
        }
        CliResponse::Error { message } => {
            eprintln!("ERROR: {}", message);
            std::process::exit(2);
        }
        _ => {
            eprintln!("Unexpected response");
            std::process::exit(3);
        }
    }
}

// === Revoke Flow ===

async fn revoke_flow(socket_path: &str) -> Result<()> {
    let response = send_request(socket_path, &CliRequest::Revoke).await?;

    match response {
        CliResponse::Status { active: false, .. } => {
            println!("Session revoked");
            Ok(())
        }
        CliResponse::Error { message } => {
            eprintln!("ERROR: {}", message);
            std::process::exit(2);
        }
        _ => {
            println!("Revoke acknowledged");
            Ok(())
        }
    }
}

// === Socket I/O ===

async fn send_request(socket_path: &str, req: &CliRequest) -> Result<CliResponse> {
    let mut stream = UnixStream::connect(socket_path).await
        .with_context(|| format!("Failed to connect to {}", socket_path))?;

    let data = bincode::serialize(req)?;
    let len = data.len() as u32;
    stream.write_all(&len.to_le_bytes()).await?;
    stream.write_all(&data).await?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u32::from_le_bytes(len_buf) as usize;
    if resp_len > 10_000_000 {
        anyhow::bail!("Response too large: {}", resp_len);
    }
    let mut resp_bytes = vec![0u8; resp_len];
    stream.read_exact(&mut resp_bytes).await?;

    Ok(bincode::deserialize(&resp_bytes)?)
}

fn prompt(label: &str) -> Result<String> {
    print!("{}: ", label);
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

// === Input Helpers ===

fn prompt_with_default(label: &str, default: &str) -> Result<String> {
    print!("{} [{}]: ", label, default);
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed)
    }
}
fn prompt_secret(label: &str) -> Result<String> {
    print!("{}: ", label);
    std::io::stdout().flush()?;
    let mut old_termios: libc::termios = unsafe { std::mem::zeroed() };
    unsafe { libc::tcgetattr(0, &mut old_termios); }
    let mut new_termios = old_termios;
    new_termios.c_lflag &= !libc::ECHO;
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &new_termios); }
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &old_termios); }
    println!();
    Ok(line.trim().to_string())
}

