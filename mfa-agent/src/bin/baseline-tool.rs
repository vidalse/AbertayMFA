use anyhow::{Context, Result};
use std::env;
use mfa_agent::tpm;
use mfa_agent::protocol::BaselineDatabase;
use mfa_agent::config::NodeConfig;
use mfa_agent::ebpf;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "init" => {
            if args.len() < 3 {
                eprintln!("Usage: {} init <baseline-file>", args[0]);
                std::process::exit(1);
            }
            cmd_init(&args[2])?;
        }
        "capture" => {
            if args.len() < 4 {
                eprintln!("Usage: {} capture <vm-identity> <description>", args[0]);
                std::process::exit(1);
            }
            cmd_capture(&args[2], &args[3])?;
        }
        "show" => {
            if args.len() < 3 {
                eprintln!("Usage: {} show <baseline-file>", args[0]);
                std::process::exit(1);
            }
            cmd_show(&args[2])?;
        }
        "merge" => {
            if args.len() < 4 {
                eprintln!("Usage: {} merge <database-file> <baseline-1.json> [baseline-2.json ...]", args[0]);
                std::process::exit(1);
            }
            cmd_merge(&args[2], &args[3..])?;
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage(&args[0]);
            std::process::exit(1);
        }
    }
    Ok(())
}

fn print_usage(prog: &str) {
    eprintln!("Baseline Management Tool");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  {} capture <vm-identity> <description>", prog);
    eprintln!("  {} show <baseline-file>", prog);
    eprintln!("  {} init <baseline-file>", prog);
    eprintln!("  {} merge <database-file> <baseline-1.json> [baseline-2.json ...]", prog);
    eprintln!();
    eprintln!("Examples:");
    eprintln!("  {} capture vm1 \"Golden baseline with eBPF and AK\"", prog);
    eprintln!("  {} show baselines.json", prog);
    eprintln!("  {} merge baselines.json baseline-vm1.json baseline-pr1.json", prog);
}

fn cmd_init(path: &str) -> Result<()> {
    println!("Initializing baseline database: {}", path);
    let db = BaselineDatabase::new();
    db.save_to_file(path)?;
    println!("Empty baseline database created");
    Ok(())
}

fn cmd_capture(vm_identity: &str, description: &str) -> Result<()> {
    std::env::set_var("TCTI", "device:/dev/tpmrm0");
    println!("Capturing baseline for: {}", vm_identity);
    println!("Description: {}", description);
    let config = NodeConfig::load(None)
        .context("Failed to load node config, baseline-tool needs node.json to determine this node's role")?;
    ebpf::set_node_role(&config.role.to_string());
    println!("Role: {} (binary manifest will match agent attestation)", config.role);
    let tpm_ctx = tpm::init()?;
    let baseline = tpm::capture_baseline(&tpm_ctx, vm_identity, description)?;
    println!("\nBaseline captured:");
    println!("   VM: {}", baseline.vm_identity);
    println!("   PCRs: {}", baseline.pcr_values.len());
    println!("   IMA: {} measurements", baseline.ima_baseline.as_ref().map(|i| i.count).unwrap_or(0));
    if let Some(ref ebpf) = baseline.ebpf_baseline {
        println!("   eBPF: {} processes, {} connections", ebpf.process_count, ebpf.network_connections);
    } else {
        println!("   eBPF: not captured");
    }
    if let Some(ref ak) = baseline.ak_public {
        println!("   AK: {} bytes (TPM signature verification enabled)", ak.len());
    } else {
        println!("   AK: not captured (TPM signing unavailable)");
    }
    println!("   Timestamp: {}", baseline.timestamp);
    tpm::display_pcrs(&baseline.pcr_values);
    let filename = format!("baseline-{}.json", vm_identity);
    let json = serde_json::to_string_pretty(&baseline)?;
    std::fs::write(&filename, json)?;
    println!("\nSaved to: {}", filename);
    println!("\nTo add to database:");
    println!("  1. Copy {} to VM2", filename);
    println!("  2. On VM2: ./target/release/baseline-tool merge baselines.json {}", filename);
    Ok(())
}

fn cmd_show(path: &str) -> Result<()> {
    println!("Loading: {}", path);
    if let Ok(db) = BaselineDatabase::load_from_file(path) {
        println!("\nBaseline Database:");
        println!("   VMs: {}", db.baselines.len());
        println!("   Updated: {}", db.updated);
        println!();
        for (vm_id, baseline) in &db.baselines {
            print_baseline_summary(vm_id, baseline);
        }
    } else {
        let json = std::fs::read_to_string(path)?;
        let baseline: mfa_agent::tpm::PcrBaseline = serde_json::from_str(&json)?;
        println!("\nIndividual Baseline:");
        print_baseline_summary(&baseline.vm_identity, &baseline);
    }
    Ok(())
}

fn cmd_merge(db_path: &str, baseline_files: &[String]) -> Result<()> {
    let mut db = if std::path::Path::new(db_path).exists() {
        println!("📖 Loading existing database: {}", db_path);
        BaselineDatabase::load_from_file(db_path)?
    } else {
        println!("Creating new database: {}", db_path);
        BaselineDatabase::new()
    };
    println!("   Current entries: {}", db.baselines.len());
    if !db.baselines.is_empty() {
        for (id, bl) in &db.baselines {
            let ebpf_info = bl.ebpf_baseline.as_ref()
                .map(|e| format!("{} procs", e.process_count))
                .unwrap_or("no eBPF".into());
            let ak_info = bl.ak_public.as_ref()
                .map(|a| format!("AK:{}", a.len()))
                .unwrap_or("no AK".into());
            println!("   {} → {} PCRs, {}, {}", id, bl.pcr_values.len(), ebpf_info, ak_info);
        }
    }
    println!();
    let mut merged_count = 0;
    let mut error_count = 0;
    for file in baseline_files {
        print!("  {} → ", file);
        match std::fs::read_to_string(file) {
            Ok(json) => {
                match serde_json::from_str::<mfa_agent::tpm::PcrBaseline>(&json) {
                    Ok(baseline) => {
                        let vm_id = baseline.vm_identity.clone();
                        let had_existing = db.baselines.contains_key(&vm_id);
                        let ebpf_info = baseline.ebpf_baseline.as_ref()
                            .map(|e| format!("{} procs, {} conns", e.process_count, e.network_connections))
                            .unwrap_or("no eBPF".into());
                        let ak_info = baseline.ak_public.as_ref()
                            .map(|a| format!("AK:{}", a.len()))
                            .unwrap_or("no AK".into());
                        db.add_baseline(baseline);
                        merged_count += 1;
                        if had_existing {
                            println!("{} UPDATED ({} PCRs, {}, {})", vm_id,
                                db.baselines.get(&vm_id).unwrap().pcr_values.len(), ebpf_info, ak_info);
                        } else {
                            println!("{} ADDED ({} PCRs, {}, {})", vm_id,
                                db.baselines.get(&vm_id).unwrap().pcr_values.len(), ebpf_info, ak_info);
                        }
                    }
                    Err(e) => {
                        println!("Parse error: {}", e);
                        error_count += 1;
                    }
                }
            }
            Err(e) => {
                println!("Read error: {}", e);
                error_count += 1;
            }
        }
    }
    db.save_to_file(db_path)?;
    println!("\nSummary:");
    println!("   Merged: {}", merged_count);
    if error_count > 0 {
        println!("   Errors: {}", error_count);
    }
    println!("   Total entries: {}", db.baselines.len());
    println!("Saved to: {}", db_path);
    println!("\nDatabase contents:");
    for (id, bl) in &db.baselines {
        let ebpf_info = bl.ebpf_baseline.as_ref()
            .map(|e| format!("{} procs, {} conns", e.process_count, e.network_connections))
            .unwrap_or("no eBPF".into());
        let ak_info = bl.ak_public.as_ref()
            .map(|a| format!("{} bytes", a.len()))
            .unwrap_or("no AK".into());
        println!("   {} → {} PCRs, IMA: {}, eBPF: {}, AK: {}",
            id,
            bl.pcr_values.len(),
            bl.ima_baseline.as_ref().map(|i| format!("{}", i.count)).unwrap_or("none".into()),
            ebpf_info,
            ak_info);
    }
    Ok(())
}

fn print_baseline_summary(vm_id: &str, baseline: &mfa_agent::tpm::PcrBaseline) {
    println!("{}", vm_id);
    println!("   Description: {}", baseline.description);
    println!("   Captured: {}", baseline.timestamp);
    println!("   PCRs: {}", baseline.pcr_values.len());
    if let Some(ref ima) = baseline.ima_baseline {
        println!("   IMA: {} measurements", ima.count);
    }
    if let Some(ref ebpf) = baseline.ebpf_baseline {
        println!("   eBPF: {} processes, {} connections", ebpf.process_count, ebpf.network_connections);
    } else {
        println!("   eBPF: not captured");
    }
    if let Some(ref ak) = baseline.ak_public {
        println!("   AK: {} bytes (signature verification enabled)", ak.len());
    } else {
        println!("   AK: not captured");
    }
    println!("   PCR values:");
    for pcr in &baseline.pcr_values {
        println!("     PCR{:02}: {}", pcr.index, hex::encode(&pcr.value[..8]));
    }
    println!();
}
