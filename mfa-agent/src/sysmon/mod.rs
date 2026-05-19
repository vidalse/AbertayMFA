use serde::{Serialize, Deserialize};
use std::os::unix::io::RawFd;

/// Must match bpf-sysmon.c counter indices
const STAT_EXECVE: u32 = 0;
const STAT_PTRACE: u32 = 1;
const STAT_MOUNT: u32 = 2;
const STAT_SOCKET: u32 = 3;
const STAT_OPEN_SENS: u32 = 4;
const STAT_CONNECT: u32 = 5;
const STAT_CONNECT_UNAUTH: u32 = 6;
const STAT_SOCKET_EXOTIC: u32 = 7;
const STAT_TOTAL_HOOKS: u32 = 8;
const STAT_EXECVE_AGENT: u32 = 9;
const STAT_SIZE: u32 = 10;

/// Must match bpf-sysmon.c event types
const EVT_EXECVE: u8 = 0;
const EVT_PTRACE: u8 = 1;
const EVT_MOUNT: u8 = 2;
const EVT_SOCKET_EXOTIC: u8 = 3;
const EVT_OPEN_SENSITIVE: u8 = 4;
const EVT_CONNECT_UNAUTH: u8 = 5;

const MAX_EVENTS: u32 = 32;

const PIN_PATH_STATS: &str = "/sys/fs/bpf/sysmon/sysmon_stats";
const PIN_PATH_EVENTS: &str = "/sys/fs/bpf/sysmon/sysmon_events";

// === BPF syscall constants ===
const SYS_BPF: i64 = 321; // x86_64
const BPF_OBJ_GET: u32 = 7;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;

// === Public Types ===
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SysmonState {
    /// Whether sysmon is loaded and readable
    pub active: bool,
    /// Cumulative counters (summed across all CPUs)
    pub execve_count: u64,
    pub ptrace_count: u64,
    pub mount_count: u64,
    pub socket_count: u64,
    pub sensitive_open_count: u64,
    pub connect_count: u64,
    pub connect_unauthorized_count: u64,
    pub socket_exotic_count: u64,
    pub total_hooks: u64,
    /// Any non-zero value here is an anomaly in production
    pub anomalies_detected: bool,
    /// Recent suspicious events (from event log map)
    pub recent_events: Vec<SysmonEvent>,
    #[serde(default)]
    pub execve_agent_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysmonEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub event_type: String,
    pub comm: String,
    pub arg: String,
}


// === RAW BPF SYSCALL INTERFACE ===

/// Representation of bpf_attr union for BPF_OBJ_GET
#[repr(C)]
struct BpfAttrObjGet {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

/// Representation of bpf_attr union for BPF_MAP_LOOKUP_ELEM
#[repr(C)]
struct BpfAttrMapLookup {
    map_fd: u32,
    _pad0: u32,
    key: u64,
    value_or_next: u64, /// value pointer for lookup
}

fn bpf_obj_get(path: &str) -> Result<RawFd, String> {
    let c_path = std::ffi::CString::new(path)
        .map_err(|e| format!("Invalid path: {}", e))?;
    let attr = BpfAttrObjGet {
        pathname: c_path.as_ptr() as u64,
        bpf_fd: 0,
        file_flags: 0,
    };
    let fd = unsafe {
        libc::syscall(
            SYS_BPF,
            BPF_OBJ_GET,
            &attr as *const _ as *const libc::c_void,
            std::mem::size_of::<BpfAttrObjGet>(),
        )
    };
    if fd < 0 {
        Err(format!("BPF_OBJ_GET {} failed: {}", path,
            std::io::Error::last_os_error()))
    } else {
        Ok(fd as RawFd)
    }
}

fn bpf_map_lookup_percpu(
    map_fd: RawFd,
    key: u32,
    num_cpus: usize,
) -> Result<Vec<u64>, String> {
    /// Per-CPU array: value buffer must hold num_cpus * value_size bytes
    /// Value size is u64 (8 bytes)
    let mut values: Vec<u64> = vec![0u64; num_cpus];
    let key_val = key;
    let attr = BpfAttrMapLookup {
        map_fd: map_fd as u32,
        _pad0: 0,
        key: &key_val as *const u32 as u64,
        value_or_next: values.as_mut_ptr() as u64,
    };
    let ret = unsafe {
        libc::syscall(
            SYS_BPF,
            BPF_MAP_LOOKUP_ELEM,
            &attr as *const _ as *const libc::c_void,
            std::mem::size_of::<BpfAttrMapLookup>(),
        )
    };
    if ret < 0 {
        Err(format!("BPF_MAP_LOOKUP_ELEM failed for key {}: {}",
            key, std::io::Error::last_os_error()))
    } else {
        Ok(values)
    }
}

/// Raw event struct matching bpf-sysmon.c layout exactly
#[repr(C)]
struct RawSysmonEvent {
    timestamp_ns: u64,
    pid: u32,
    tgid: u32,
    event_type: u8,
    _pad: [u8; 3],
    comm: [u8; 16],
    arg: [u8; 64],
}

fn bpf_map_lookup_hash(
    map_fd: RawFd,
    key: u32,
) -> Result<Option<RawSysmonEvent>, String> {
    let mut value = RawSysmonEvent {
        timestamp_ns: 0,
        pid: 0,
        tgid: 0,
        event_type: 0,
        _pad: [0; 3],
        comm: [0; 16],
        arg: [0; 64],
    };
    let key_val = key;
    let attr = BpfAttrMapLookup {
        map_fd: map_fd as u32,
        _pad0: 0,
        key: &key_val as *const u32 as u64,
        value_or_next: &mut value as *mut RawSysmonEvent as u64,
    };
    let ret = unsafe {
        libc::syscall(
            SYS_BPF,
            BPF_MAP_LOOKUP_ELEM,
            &attr as *const _ as *const libc::c_void,
            std::mem::size_of::<BpfAttrMapLookup>(),
        )
    };
    if ret < 0 {
        /// Key not found is normal for sparse event map
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

fn close_fd(fd: RawFd) {
    unsafe { libc::close(fd); }
}


// === Helpers ===

fn num_cpus() -> usize {
    let s = std::fs::read_to_string("/sys/devices/system/cpu/possible")
        .unwrap_or_else(|_| "0-3".to_string());
    if let Some(end) = s.trim().split('-').last() {
        if let Ok(n) = end.parse::<usize>() {
            return n + 1;
        }
    }
    4
}

fn sum_percpu(values: &[u64]) -> u64 {
    values.iter().sum()
}

fn event_type_name(t: u8) -> String {
    match t {
        EVT_EXECVE => "execve".to_string(),
        EVT_PTRACE => "ptrace".to_string(),
        EVT_MOUNT => "mount".to_string(),
        EVT_SOCKET_EXOTIC => "socket_exotic".to_string(),
        EVT_OPEN_SENSITIVE => "open_sensitive".to_string(),
        EVT_CONNECT_UNAUTH => "connect_unauthorized".to_string(),
        _ => format!("unknown({})", t),
    }
}

fn bytes_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

fn parse_ip_arg(arg: &[u8]) -> String {
    if arg.len() >= 6 {
        let ip = format!("{}.{}.{}.{}", arg[0], arg[1], arg[2], arg[3]);
        let port = (arg[4] as u16) | ((arg[5] as u16) << 8);
        format!("{}:{}", ip, port)
    } else {
        bytes_to_string(arg)
    }
}

fn parse_event(raw: &RawSysmonEvent) -> SysmonEvent {
    let arg = if raw.event_type == EVT_CONNECT_UNAUTH {
        parse_ip_arg(&raw.arg)
    } else {
        bytes_to_string(&raw.arg)
    };

    SysmonEvent {
        timestamp_ns: raw.timestamp_ns,
        pid: raw.pid,
        tgid: raw.tgid,
        event_type: event_type_name(raw.event_type),
        comm: bytes_to_string(&raw.comm),
        arg,
    }
}

// === Public API ===

/// Read current sysmon state from pinned BPF maps.
/// 	Called by collect_state() at each heartbeat.
/// 	Returns Default (active=false) if sysmon is not loaded.
pub fn read_sysmon_state() -> SysmonState {
    let mut state = SysmonState::default();
    /// Open stats map
    let stats_fd = match bpf_obj_get(PIN_PATH_STATS) {
        Ok(fd) => fd,
        Err(_) => return state, // Sysmon not loaded
    };
    state.active = true;
    let cpus = num_cpus();
    /// Read all counters
    let read_counter = |idx: u32| -> u64 {
        bpf_map_lookup_percpu(stats_fd, idx, cpus)
            .map(|v| sum_percpu(&v))
            .unwrap_or(0)
    };
    state.execve_count = read_counter(STAT_EXECVE);
    state.ptrace_count = read_counter(STAT_PTRACE);
    state.mount_count = read_counter(STAT_MOUNT);
    state.socket_count = read_counter(STAT_SOCKET);
    state.sensitive_open_count = read_counter(STAT_OPEN_SENS);
    state.connect_count = read_counter(STAT_CONNECT);
    state.connect_unauthorized_count = read_counter(STAT_CONNECT_UNAUTH);
    state.socket_exotic_count = read_counter(STAT_SOCKET_EXOTIC);
    state.total_hooks = read_counter(STAT_TOTAL_HOOKS);
    state.execve_agent_count = read_counter(STAT_EXECVE_AGENT);
    close_fd(stats_fd);
    /// Anomaly detection: in production, execve/ptrace/mount should be ZERO
    state.anomalies_detected =
        state.execve_count > 0 ||
        state.ptrace_count > 0 ||
        state.mount_count > 0 ||
        state.connect_unauthorized_count > 0 ||
        state.socket_exotic_count > 0;
    /// Read recent events from event hash map
    let events_fd = match bpf_obj_get(PIN_PATH_EVENTS) {
        Ok(fd) => fd,
        Err(_) => return state,
    };
    let mut events = Vec::new();
    for i in 0..MAX_EVENTS {
        if let Ok(Some(raw)) = bpf_map_lookup_hash(events_fd, i) {
            if raw.timestamp_ns > 0 {
                events.push(parse_event(&raw));
            }
        }
    }
    /// Sort by timestamp descending (most recent first)
    events.sort_by(|a, b| b.timestamp_ns.cmp(&a.timestamp_ns));
    state.recent_events = events;
    close_fd(events_fd);
    state
}

