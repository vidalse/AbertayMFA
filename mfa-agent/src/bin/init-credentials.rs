use anyhow::{Result, Context, anyhow};
use std::io::{Write, BufRead};
use mfa_agent::yubikey::{init_dev_credentials, StoredCredentials};

const DEFAULT_PATH: &str = "/opt/mfa-agent/credentials.json";
const MIN_LENGTH: usize = 12;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let path = parse_path_arg(&args).unwrap_or_else(|| DEFAULT_PATH.to_string());

    println!("═══════════════════════════════════════════════════════════");
    println!("    MFA ZERO-TRUST — Operator Credential Initialization");
    println!("═══════════════════════════════════════════════════════════\n");
    /// Check if credentials already exist
    if std::path::Path::new(&path).exists() {
        println!("Credentials file already exists: {}", path);
        let overwrite = prompt("Overwrite existing credentials? (yes/no)")?;
        if overwrite.to_lowercase() != "yes" {
            println!("Aborted. Existing credentials preserved.");
            return Ok(());
        }
    }
    println!("This tool sets up operator credentials for vm0 authorization.");
    println!("Two passphrases are required (development mode).");
    println!();
    println!("Requirements:");
    println!("  - Each passphrase at least {} characters", MIN_LENGTH);
    println!("  - Passphrases must be different from each other");
    println!("  - Choose strong, memorable passphrases");
    println!();
    println!("If you forget these passphrases, there is NO recovery.");
    println!("    The system will be unable to authenticate until re-initialized.");
    println!();

    let passphrase1 = read_passphrase_confirmed("Passphrase 1")?;
    let passphrase2 = read_passphrase_confirmed("Passphrase 2")?;

    if passphrase1 == passphrase2 {
        return Err(anyhow!("Passphrases must be different"));
    }
    println!();
    println!("Hashing passphrases with Argon2id (may take a few seconds)...");
    let credentials = init_dev_credentials(&passphrase1, &passphrase2)
        .context("Failed to initialize credentials")?;
    credentials.save(&path)
        .context("Failed to save credentials")?;
    println!();
    println!("Credentials stored: {}", path);
    println!("   Permissions: 0600 (root only)");
    println!("   Backend: dev-two-passphrase");
    println!();
    println!("Reminder: If these passphrases are lost, you must run");
    println!("    init-credentials again to set new ones.");
    println!();
    /// Clear passphrase memory (best-effort; Rust doesn't guarantee zeroing)
    drop(passphrase1);
    drop(passphrase2);

    Ok(())
}

fn parse_path_arg(args: &[String]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--path" {
            return iter.next().map(|s| s.to_string());
        }
    }
    None
}

fn read_passphrase_confirmed(label: &str) -> Result<String> {
    loop {
        let p1 = prompt(&format!("{}", label))?;
        if p1.len() < MIN_LENGTH {
            println!("Too short ({} chars). Minimum: {}", p1.len(), MIN_LENGTH);
            continue;
        }
        let p2 = prompt(&format!("Confirm {}", label))?;
        if p1 != p2 {
            println!("Passphrases do not match. Try again.");
            continue;
        }

        return Ok(p1);
    }
}

fn prompt(label: &str) -> Result<String> {
    print!("{}: ", label);
    std::io::stdout().flush()?;
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}
