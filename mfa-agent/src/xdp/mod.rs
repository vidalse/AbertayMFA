use anyhow::{Result, Context};
use libbpf_rs::{MapCore, MapFlags, Object, ObjectBuilder};

/// Must match xdp-entropy.c
const STAT_PASSED: u32 = 0;
const STAT_DROPPED_ENTROPY: u32 = 1;
const STAT_DROPPED_PROTOCOL: u32 = 2;
const STAT_TOTAL: u32 = 3;
const STAT_ENTROPY_EXEMPT: u32 = 4;

const INTERFACE: &str = "enp6s18";
const XDP_PROG_PATH: &str = "/opt/mfa-agent/xdp-entropy.o";

// === Types ===
#[derive(Debug, Clone, Default)]
pub struct XdpStats {
    pub total: u64,
    pub passed: u64,
    pub dropped_entropy: u64,
    pub dropped_protocol: u64,
    pub entropy_exempt: u64,
}

pub struct XdpHandle {
    obj: Object,
    _link: libbpf_rs::Link,
}


/// Load XDP entropy program, populate lookup table, attach to interface.
/// No per-node configuration — identical on all VMs.
pub fn load_and_attach() -> Result<XdpHandle> {
    println!("  🛡️  Loading XDP entropy program from {}", XDP_PROG_PATH);
    let mut builder = ObjectBuilder::default();
    let open_obj = builder
        .open_file(XDP_PROG_PATH)
        .context("Failed to open XDP BPF object file")?;
    let mut obj = open_obj
        .load()
        .context("Failed to load XDP program into kernel")?;
    populate_entropy_table(&mut obj)
        .context("Failed to populate entropy table")?;
    let ifindex = get_ifindex(INTERFACE)
        .context(format!("Failed to get interface index for {}", INTERFACE))?;
    let prog = obj.progs_mut()
        .find(|p| p.name() == "xdp_entropy")
        .ok_or_else(|| anyhow::anyhow!("XDP program 'xdp_entropy' not found"))?;
    let link = prog
        .attach_xdp(ifindex as i32)
        .context(format!("Failed to attach XDP to {}", INTERFACE))?;
    println!("  XDP entropy attached to {} (ifindex {})", INTERFACE, ifindex);
    println!("  🛡️  Layer 1 active: entropy verification on all TCP payloads");

    Ok(XdpHandle { obj, _link: link })
}

fn get_ifindex(name: &str) -> Result<u32> {
    let c_name = std::ffi::CString::new(name)
        .context("Invalid interface name")?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        Err(anyhow::anyhow!("Interface '{}' not found", name))
    } else {
        Ok(idx)
    }
}

// === Entropy Table ===
/// T[i] = floor(i × log₂(i) × 1024). 1501 entries, ~12 KB. One-time cost.
fn populate_entropy_table(obj: &mut Object) -> Result<()> {
    let map = obj.maps_mut()
        .find(|m| m.name() == "n_log2_n")
        .ok_or_else(|| anyhow::anyhow!("n_log2_n map not found"))?;
    let zero: u64 = 0;
    map.update(&0u32.to_ne_bytes(), &zero.to_ne_bytes(), MapFlags::ANY)?;
    map.update(&1u32.to_ne_bytes(), &zero.to_ne_bytes(), MapFlags::ANY)?;
    for i in 2u32..=1500 {
        let f = i as f64;
        let val = (f * f.log2() * 1024.0) as u64;
        map.update(&i.to_ne_bytes(), &val.to_ne_bytes(), MapFlags::ANY)?;
    }
    println!("  🛡️  Entropy lookup table populated (1501 entries)");
    Ok(())
}

// === Statistics ===
impl XdpHandle {
    pub fn read_stats(&self) -> Result<XdpStats> {
        let map = self.obj.maps()
            .find(|m| m.name() == "stats")
            .ok_or_else(|| anyhow::anyhow!("stats map not found"))?;

        let cpus = num_cpus()?;
        Ok(XdpStats {
            total:            percpu_sum(&map, STAT_TOTAL, cpus)?,
            passed:           percpu_sum(&map, STAT_PASSED, cpus)?,
            dropped_entropy:  percpu_sum(&map, STAT_DROPPED_ENTROPY, cpus)?,
            dropped_protocol: percpu_sum(&map, STAT_DROPPED_PROTOCOL, cpus)?,
            entropy_exempt:   percpu_sum(&map, STAT_ENTROPY_EXEMPT, cpus)?,
        })
    }
    pub fn format_stats(&self) -> Result<String> {
        let s = self.read_stats()?;
        Ok(format!(
            "XDP[T:{} P:{} D:ent={},proto={} E:{}]",
            s.total, s.passed,
            s.dropped_entropy, s.dropped_protocol,
            s.entropy_exempt
        ))
    }
}

fn percpu_sum(map: &libbpf_rs::Map<'_>, index: u32, cpus: usize) -> Result<u64> {
    let key = index.to_ne_bytes();
    match map.lookup_percpu(&key, MapFlags::ANY) {
        Ok(Some(values)) => {
            let mut sum: u64 = 0;
            for val in values.iter() {
                if val.len() >= 8 {
                    let bytes: [u8; 8] = val[..8].try_into().unwrap_or([0u8; 8]);
                    sum += u64::from_ne_bytes(bytes);
                }
            }
            Ok(sum)
        }
        Ok(None) => Ok(0),
        Err(e) => {
            match map.lookup(&key, MapFlags::ANY) {
                Ok(Some(raw)) => {
                    let mut sum: u64 = 0;
                    let raw_bytes: &[u8] = &raw;
                    for i in 0..cpus {
                        let off = i * 8;
                        if off + 8 <= raw_bytes.len() {
                            let bytes: [u8; 8] = raw_bytes[off..off+8]
                                .try_into().unwrap_or([0u8; 8]);
                            sum += u64::from_ne_bytes(bytes);
                        }
                    }
                    Ok(sum)
                }
                _ => { eprintln!("  XDP stat read error: {}", e); Ok(0) }
            }
        }
    }
}

fn num_cpus() -> Result<usize> {
    let s = std::fs::read_to_string("/sys/devices/system/cpu/possible")
        .unwrap_or_else(|_| "0-3".to_string());
    if let Some(end) = s.trim().split('-').last() {
        if let Ok(n) = end.parse::<usize>() { return Ok(n + 1); }
    }
    Ok(4)
}

// === Anomaly Detector ===
pub fn check_anomalies(stats: &XdpStats) -> Vec<String> {
    let mut out = Vec::new();
    if stats.dropped_entropy > 0 {
        out.push(format!("XDP: {} packets failed entropy check", stats.dropped_entropy));
    }
    if stats.total > 100 {
        let good = stats.passed + stats.entropy_exempt;
        let drop_rate = ((stats.total - good) as f64) / (stats.total as f64);
        if drop_rate > 0.1 {
            out.push(format!("XDP: {:.1}% drop rate over {} packets", drop_rate * 100.0, stats.total));
        }
    }
    out
}

impl std::fmt::Display for XdpStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "XDP[T:{} P:{} D:ent={},proto={} E:{}]",
            self.total, self.passed,
            self.dropped_entropy, self.dropped_protocol,
            self.entropy_exempt)
    }
}
