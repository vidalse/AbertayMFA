use sha2::{Sha256, Digest};

/// CONSTANTS from linux/netfilter_ipv4/ip_tables.h, kernel ABI
const IPT_SO_GET_INFO: libc::c_int = 64;
const IPT_SO_GET_ENTRIES: libc::c_int = 65;
const XT_TABLE_MAXNAMELEN: usize = 32;
/// ipt_entry layout
const COUNTERS_OFFSET: usize = 96;  // offset of xt_counters in ipt_entry
const COUNTERS_SIZE: usize = 16;    // sizeof(xt_counters) = 2 x u64
/// Hook indices
const NF_INET_LOCAL_IN: usize = 1;
const NF_INET_FORWARD: usize = 2;
const NF_INET_LOCAL_OUT: usize = 3;
const NF_INET_NUMHOOKS: usize = 5;
/// ipt_ip field offsets (within ipt_entry)
const IP_SRC_OFFSET: usize = 0;
const IP_DST_OFFSET: usize = 4;
const IP_SMASK_OFFSET: usize = 8;
const IP_DMASK_OFFSET: usize = 12;
const IP_INIFACE_OFFSET: usize = 16;   // 16 bytes
const IP_OUTIFACE_OFFSET: usize = 32;  // 16 bytes
const IP_PROTO_OFFSET: usize = 72;     // u16
const IP_FLAGS_OFFSET: usize = 74;     // u8 flags
const IP_INVFLAGS_OFFSET: usize = 75;  // u8 invflags
/// Entry header fields after ipt_ip (84 bytes)
const TARGET_OFFSET_FIELD: usize = 88;  // u16 - offset to target
const NEXT_OFFSET_FIELD: usize = 90;    // u16 - offset to next entry
/// Standard target
const XT_STANDARD_TARGET: &str = "";
const XT_ERROR_TARGET: &str = "ERROR";

#[repr(C)]
struct IptGetInfo {
    name: [u8; XT_TABLE_MAXNAMELEN],
    valid_hooks: u32,
    hook_entry: [u32; NF_INET_NUMHOOKS],
    underflow: [u32; NF_INET_NUMHOOKS],
    num_entries: u32,
    size: u32,
}

// === Core (read raw entries from kernel) ===
fn read_filter_table_raw() -> Option<(IptGetInfo, Vec<u8>)> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
        if fd < 0 { return None; }

        let mut info: IptGetInfo = std::mem::zeroed();
        let table_name = b"filter\0";
        info.name[..table_name.len()].copy_from_slice(table_name);

        let mut info_len: libc::socklen_t = std::mem::size_of::<IptGetInfo>() as u32;
        let ret = libc::getsockopt(
            fd,
            libc::IPPROTO_IP,
            IPT_SO_GET_INFO,
            &mut info as *mut _ as *mut libc::c_void,
            &mut info_len,
        );
        if ret != 0 {
            libc::close(fd);
            return None;
        }

        let header_size: usize = 40;
        let total_size = header_size + info.size as usize;
        let mut buf: Vec<u8> = vec![0u8; total_size];
        buf[..table_name.len()].copy_from_slice(table_name);
        buf[32..36].copy_from_slice(&info.size.to_ne_bytes());

        let mut buf_len: libc::socklen_t = total_size as u32;
        let ret = libc::getsockopt(
            fd,
            libc::IPPROTO_IP,
            IPT_SO_GET_ENTRIES,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut buf_len,
        );
        libc::close(fd);

        if ret != 0 { return None; }

        let entry_data = buf[header_size..].to_vec();
        Some((info, entry_data))
    }
}

pub fn hash_iptables_kernel() -> Option<Vec<u8>> {
    eprintln!("  NF: hash_iptables_kernel called");    
    let (info, entry_data) = read_filter_table_raw()?;
    eprintln!("  NF: got {} entries, {} bytes", info.num_entries, entry_data.len());
    let mut hasher = Sha256::new();
    /// Hash table metadata (hook entries and underflows define chain structure)
    hasher.update(&info.valid_hooks.to_le_bytes());
    for h in &info.hook_entry {
        hasher.update(&h.to_le_bytes());
    }
    for u in &info.underflow {
        hasher.update(&u.to_le_bytes());
    }
    hasher.update(&info.num_entries.to_le_bytes());
    /// Hash entries with counters zeroed
    let mut offset: usize = 0;
    while offset < entry_data.len() {
        if offset + NEXT_OFFSET_FIELD + 2 > entry_data.len() { break; }
        let next_offset = u16::from_ne_bytes([
            entry_data[offset + NEXT_OFFSET_FIELD],
            entry_data[offset + NEXT_OFFSET_FIELD + 1],
        ]) as usize;
        if next_offset == 0 || offset + next_offset > entry_data.len() { break; }
        /// Hash everything except the counter bytes
        let entry = &entry_data[offset..offset + next_offset];
        if entry.len() > COUNTERS_OFFSET + COUNTERS_SIZE {
            /// Before counters
            hasher.update(&entry[..COUNTERS_OFFSET]);
            /// Skip counters (16 bytes of zeros instead)
            hasher.update(&[0u8; COUNTERS_SIZE]);
            /// After counters
            hasher.update(&entry[COUNTERS_OFFSET + COUNTERS_SIZE..]);
        } else {
            /// Entry too small to have counters, hash as-is
            hasher.update(entry);
        }
        offset += next_offset;
    }
    Some(hasher.finalize().to_vec())
}

pub fn read_iptables_content() -> Option<String> {
    let (info, entry_data) = read_filter_table_raw()?;
    let mut output = String::new();
    let chain_names = ["PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"];
    for hook_idx in [NF_INET_LOCAL_IN, NF_INET_FORWARD, NF_INET_LOCAL_OUT] {
        if info.valid_hooks & (1 << hook_idx) == 0 { continue; }
        let chain_name = chain_names[hook_idx];
        let chain_start = info.hook_entry[hook_idx] as usize;
        let chain_underflow = info.underflow[hook_idx] as usize;
        /// Determine default policy from underflow target
        let policy = if chain_underflow < entry_data.len() {
            read_target_name(&entry_data, chain_underflow)
                .unwrap_or_else(|| "ACCEPT".to_string())
        } else {
            "ACCEPT".to_string()
        };
        output.push_str(&format!("Chain {} (policy {})\n", chain_name, policy));
        let mut offset = chain_start;
        let mut rule_num: u32 = 0;
        while offset < entry_data.len() {
            if offset + NEXT_OFFSET_FIELD + 2 > entry_data.len() { break; }
            let next_offset = u16::from_ne_bytes([
                entry_data[offset + NEXT_OFFSET_FIELD],
                entry_data[offset + NEXT_OFFSET_FIELD + 1],
            ]) as usize;
            if next_offset == 0 || offset + next_offset > entry_data.len() { break; }
            /// Check if this is a chain boundary (ERROR target = end of chain)
            let target = read_target_name(&entry_data, offset);
            if let Some(ref t) = target {
                if t == "ERROR" { break; }
            }
            /// Skip underflow/policy entries (they define default policy)
            if offset == chain_underflow {
                offset += next_offset;
                continue;
            }
            rule_num += 1;
            /// Parse counters
            let (pkts, bytes) = if offset + COUNTERS_OFFSET + COUNTERS_SIZE <= entry_data.len() {
                let p = u64::from_ne_bytes(entry_data[offset + COUNTERS_OFFSET..offset + COUNTERS_OFFSET + 8].try_into().unwrap_or([0u8; 8]));
                let b = u64::from_ne_bytes(entry_data[offset + COUNTERS_OFFSET + 8..offset + COUNTERS_OFFSET + 16].try_into().unwrap_or([0u8; 8]));
                (p, b)
            } else {
                (0, 0)
            };
            /// Parse IP header fields
            let src = read_ip(&entry_data[offset + IP_SRC_OFFSET..]);
            let dst = read_ip(&entry_data[offset + IP_DST_OFFSET..]);
            let src_mask = read_ip(&entry_data[offset + IP_SMASK_OFFSET..]);
            let dst_mask = read_ip(&entry_data[offset + IP_DMASK_OFFSET..]);
            let proto = if offset + IP_PROTO_OFFSET + 2 <= entry_data.len() {
                u16::from_ne_bytes([
                    entry_data[offset + IP_PROTO_OFFSET],
                    entry_data[offset + IP_PROTO_OFFSET + 1],
                ])
            } else { 0 };
            let iniface = read_iface(&entry_data[offset + IP_INIFACE_OFFSET..]);
            let outiface = read_iface(&entry_data[offset + IP_OUTIFACE_OFFSET..]);

            let target_name = target.unwrap_or_else(|| "UNKNOWN".to_string());
            let proto_str = match proto {
                6 => "tcp", 17 => "udp", 1 => "icmp", 0 => "all", _ => "?",
            };
            let src_str = format_addr(&src, &src_mask);
            let dst_str = format_addr(&dst, &dst_mask);
            output.push_str(&format!(
                "{:<4} {:>8} {:>8} {:<8} {:<5} {:<4} {:<4} {:<20} {:<20}\n",
                rule_num, pkts, bytes, target_name, proto_str,
                iniface, outiface, src_str, dst_str
            ));
            offset += next_offset;
            /// Stop if we've passed the underflow point
            if offset > chain_underflow { break; }
        }
        output.push('\n');
    }
    if output.is_empty() { None } else { Some(output) }
}

pub fn check_xdp_kernel(interface: &str) -> Option<bool> {
    let c_name = std::ffi::CString::new(interface).ok()?;
    let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if ifindex == 0 { return None; }
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK as i32, libc::SOCK_RAW, 0 /* NETLINK_ROUTE */);
        if fd < 0 { return None; }
        /// Bind
        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as u16;
        libc::bind(fd, &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32);
        /// Build RTM_GETLINK request for specific interface
        let mut buf = [0u8; 1024];
        /// nlmsghdr: len(4) type(2) flags(2) seq(4) pid(4) = 16 bytes
        /// ifinfomsg: family(1) pad(1) type(2) index(4) flags(4) change(4) = 16 bytes
        let total_len: u32 = 32;
        buf[0..4].copy_from_slice(&total_len.to_ne_bytes()); // nlmsg_len
        buf[4..6].copy_from_slice(&18u16.to_ne_bytes());     // RTM_GETLINK
        buf[6..8].copy_from_slice(&1u16.to_ne_bytes());      // NLM_F_REQUEST
        buf[8..12].copy_from_slice(&1u32.to_ne_bytes());     // seq
        /// ifinfomsg at offset 16
        buf[16] = 0; // family AF_UNSPEC
        buf[20..24].copy_from_slice(&(ifindex as i32).to_ne_bytes()); // ifi_index
        let sent = libc::send(fd, buf.as_ptr() as *const _, total_len as usize, 0);
        if sent < 0 { libc::close(fd); return None; }
        /// Receive response
        let mut resp = vec![0u8; 32768];
        let n = libc::recv(fd, resp.as_mut_ptr() as *mut _, resp.len(), 0);
        libc::close(fd);
        if n <= 0 { return None; }
        let n = n as usize;
        /// Parse response, find IFLA_XDP attribute
        /// 	nlmsghdr is 16 bytes, ifinfomsg is 16 bytes, attrs start at 32
        if n < 32 { return None; }
        /// Check message type
        let msg_type = u16::from_ne_bytes([resp[4], resp[5]]);
        if msg_type != 16 { return None; } // RTM_NEWLINK = 16
        let msg_len = u32::from_ne_bytes([resp[0], resp[1], resp[2], resp[3]]) as usize;
        let attr_start = 32;
        let attr_end = msg_len.min(n);
        let mut offset = attr_start;
        while offset + 4 <= attr_end {
            let attr_len = u16::from_ne_bytes([resp[offset], resp[offset + 1]]) as usize;
            let attr_type = u16::from_ne_bytes([resp[offset + 2], resp[offset + 3]]);
            if attr_len < 4 { break; }
            /// IFLA_XDP = 43
            if attr_type == 43 {
                /// IFLA_XDP is a nested attribute containing IFLA_XDP_PROG_ID (4)
                let nested_start = offset + 4;
                let nested_end = (offset + attr_len).min(attr_end);
                let mut noff = nested_start;
                while noff + 4 <= nested_end {
                    let na_len = u16::from_ne_bytes([resp[noff], resp[noff + 1]]) as usize;
                    let na_type = u16::from_ne_bytes([resp[noff + 2], resp[noff + 3]]);
                    if na_len < 4 { break; }
                    /// IFLA_XDP_PROG_ID = 4
                    if na_type == 4 && na_len >= 8 && noff + 8 <= nested_end {
                        let prog_id = u32::from_ne_bytes([
                            resp[noff + 4], resp[noff + 5],
                            resp[noff + 6], resp[noff + 7],
                        ]);
                        return Some(prog_id > 0);
                    }
                    noff += (na_len + 3) & !3; /// align to 4 bytes
                }
                /// Found IFLA_XDP but no prog_id → not attached
                return Some(false);
            }
            offset += (attr_len + 3) & !3; // align to 4 bytes
        }
        /// No IFLA_XDP attribute at all → not attached
        Some(false)
    }
}

// === Helper Functions ===
fn read_ip(data: &[u8]) -> [u8; 4] {
    if data.len() >= 4 {
        [data[0], data[1], data[2], data[3]]
    } else {
        [0, 0, 0, 0]
    }
}

fn read_iface(data: &[u8]) -> String {
    let end = data.iter().take(16).position(|&b| b == 0).unwrap_or(16);
    if end == 0 { "*".to_string() }
    else { String::from_utf8_lossy(&data[..end]).to_string() }
}

fn format_addr(ip: &[u8; 4], mask: &[u8; 4]) -> String {
    let is_any = ip == &[0, 0, 0, 0] && mask == &[0, 0, 0, 0];
    if is_any {
        "0.0.0.0/0".to_string()
    } else {
        let cidr = mask.iter().map(|b| b.count_ones()).sum::<u32>();
        if cidr == 32 {
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        } else {
            format!("{}.{}.{}.{}/{}", ip[0], ip[1], ip[2], ip[3], cidr)
        }
    }
}

fn read_target_name(entry_data: &[u8], entry_offset: usize) -> Option<String> {
    if entry_offset + TARGET_OFFSET_FIELD + 2 > entry_data.len() { return None; }
    let target_offset = u16::from_ne_bytes([
        entry_data[entry_offset + TARGET_OFFSET_FIELD],
        entry_data[entry_offset + TARGET_OFFSET_FIELD + 1],
    ]) as usize;
    let abs_target = entry_offset + target_offset;
    if abs_target + 4 > entry_data.len() { return None; }
    let target_size = u16::from_ne_bytes([
        entry_data[abs_target],
        entry_data[abs_target + 1],
    ]) as usize;
    if target_size < 4 { return None; }
    /// Read target name (starts at offset +2, up to 29 bytes)
    let name_start = abs_target + 2;
    let name_end = (name_start + 29).min(entry_data.len());
    let name_bytes = &entry_data[name_start..name_end];
    let name_len = name_bytes.iter().position(|&b| b == 0).unwrap_or(29);
    let name = String::from_utf8_lossy(&name_bytes[..name_len]).to_string();
    if name.is_empty() {
        /// Standard target: read verdict (int at name + 29 + 1 padding = +32 from target start)
        let verdict_offset = abs_target + 32;  /// sizeof(xt_entry_target) with padding
        if verdict_offset + 4 <= entry_data.len() {
            let verdict = i32::from_ne_bytes([
                entry_data[verdict_offset],
                entry_data[verdict_offset + 1],
                entry_data[verdict_offset + 2],
                entry_data[verdict_offset + 3],
            ]);
            /// Negative verdicts are standard targets
            match -verdict - 1 {
                0 => Some("DROP".to_string()),
                1 => Some("ACCEPT".to_string()),
                /// 2 = STOLEN, 3 = QUEUE, 4 = REPEAT, 5 = STOP
                _ => {
                    if verdict >= 0 {
                        Some("JUMP".to_string()) /// positive = jump to offset
                    } else {
                        Some(format!("VERDICT({})", verdict))
                    }
                }
            }
        } else {
            None
        }
    } else {
        Some(name)
    }
}

