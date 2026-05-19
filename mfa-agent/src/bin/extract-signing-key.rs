use anyhow::Result;
use mfa_agent::tpm;
use std::io::Write;

fn main() -> Result<()> {
    /// Redirect stdout temporarily so tpm::init's println doesn't pollute
    /// We write the binary to a file instead of stdout. (no contamination)
    let tpm_ctx = tpm::init()?;
    let (_sig, public) = tpm::sign_data(&tpm_ctx, b"probe")?;
    let out_path = std::env::args().nth(1)
        .unwrap_or_else(|| "/tmp/vm0_signing_key.bin".to_string());
    std::fs::write(&out_path, &public)?;
    eprintln!("Wrote {} bytes to {}", public.len(), out_path);
    Ok(())
}
