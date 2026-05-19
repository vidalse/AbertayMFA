# MFA Zero-Trust Multi-Factor Authentication System

Zero-trust remote attestation system built on hardened Gentoo Linux with TPM 2.0 hardware root of trust, telescoping onion-routed circuits, and continuous integrity verification across a 10-node Proxmox VM topology.

## Architecture

- **10 nodes** on hardened minimal Gentoo Linux (source-compiled, USE="-*")
- **Dual-authority** model requiring two independent human operators
- **Dual verification chains** every node attested by at least two independent verifiers
- **Three defense layers**: XDP entropy filter (driver) → iptables (netfilter) → Agent attestation (TPM)
- **Post-quantum cryptography**: ML-KEM-1024 + X25519 hybrid key exchange with AES-256-GCM

## Node Roles

| Node | IP | Role |
|------|-----|------|
| vm0 | 192.168.18.109 | Orchestrator (Operator A) |
| vm1 | 192.168.18.110 | Verified Client |
| pr1 | 192.168.18.111 | Relay Proxy (Chain 1) |
| pr2 | 192.168.18.112 | Relay Proxy (Chain 1) |
| pr3 | 192.168.18.113 | Relay Proxy (Chain 1) |
| vm2 | 192.168.18.114 | Chain 1 Verifier (ZTS) |
| pr4 | 192.168.18.115 | Relay Proxy (Chain 2) |
| pr5 | 192.168.18.116 | Relay Proxy (Chain 2) |
| pr6 | 192.168.18.117 | Relay Proxy (Chain 2) |
| vm3 | 192.168.18.118 | Chain 2 Verifier (DA) |
| vm4 | 192.168.18.119 | Dual Authority (Operator B) |
| vm5 | 192.168.18.120 | Monitor (Dashboard) |

## Attestation Checks (30 per node)

**TPM Identity:** PCR (8 registers), AK (280B key), SIG (262B signature)
**Code Integrity:** IMA (kernel measurement), AGG (aggregate hash), BIN (binary hashes)
**eBPF Runtime:** SYSM (6 syscall hooks), FD (file descriptors), KERN (BPF/kprobe/modules), XDP (entropy filter)
**Network:** FW (iptables hash), CONN (connection tuples), PORTS (listening ports)
**Filesystem:** PW, SSH, PRE, BOOT, DEV, MNT, CFG, SYS, INIT
**System Health:** ENT (entropy), MASQ (masquerade detection), MOD, USR, KTH

## Build

Requires: Rust toolchain, Gentoo Linux with TPM 2.0, kernel CONFIG_IMA=y, CONFIG_BPF=y, CONFIG_MODULES=n

```bash
# Agent (on vm1 — build machine)
cd /opt/mfa-agent
cargo build --release

# Monitor (on vm1)
cd /opt/mfa-monitor
cargo build --release

# XDP program (on vm1)
clang -O2 -target bpf -c xdp-entropy.c -o xdp-entropy.o

# Sysmon BPF (on vm1)
clang -O2 -target bpf -c bpf-sysmon.c -o bpf-sysmon.o
```

## Binary Deployment

| Binary | Source | Deploy To | Path |
|--------|--------|-----------|------|
| mfa-agent | mfa-agent/target/release/ | All nodes except vm5 | /opt/mfa-agent/mfa-agent |
| mfa-logfwd | mfa-agent/target/release/ | vm2, vm3 | /opt/mfa-agent/mfa-logfwd |
| mfa-cli | mfa-agent/target/release/vm0-cli | vm0, vm4 | /usr/local/bin/mfa-cli |
| baseline-tool | mfa-agent/target/release/ | vm1 | /opt/mfa-agent/target/release/baseline-tool |
| mfa-monitor | mfa-monitor/target/release/ | vm5 | /opt/mfa-monitor/mfa-monitor |
| xdp-entropy.o | compiled per role | All nodes | /opt/mfa-agent/xdp-entropy.o |
| bpf-sysmon.o | compiled per role | All nodes | /opt/mfa-agent/bpf-sysmon.o |

## Configuration

Each node has `/opt/mfa-agent/node.json`:

```json
{
  "node_id": "pr1",
  "role": "proxy",
  "listen_port": 9001
}
```

## Baseline Capture & Deployment

```bash
# On vm1 — capture each node's baseline
cd /opt/mfa-agent
./target/release/baseline-tool capture

# Merge all baselines
./target/release/baseline-tool merge baselines.json baseline-*.json

# Distribute to verifiers
scp baselines.json root@vm2:/opt/mfa-agent/
scp baselines.json root@vm3:/opt/mfa-agent/
scp baselines.json root@vm4:/opt/mfa-agent/
scp baselines.json root@vm5:/opt/mfa-monitor/
```

## Boot Sequence (per node)
iptables → net.enp6s18 → xdp-entropy → sysmon-loader → local (mfa-agent)

## Firewall Policy (per role)

All nodes: policy DROP on INPUT/OUTPUT, conntrack ESTABLISHED/RELATED accepts return traffic.
Table shows NEW inbound connections only, return traffic on established connections (SYN-ACK, data, FIN) is automatically accepted by conntrack state tracking. This means a node only needs an inbound rule for services it HOSTS, not for connections it initiates to others.

| Role | Inbound (NEW) | Initiates outbound to |
|------|--------------|----------------------|
| Orchestrator (vm0) | 22 (SSH, dev only) | vm1:9003, vm4:9004 |
| Client (vm1) | 9003 from vm0 | pr1:9001 |
| Proxy (pr1) | 9001 from vm1 | pr2:9001 |
| Proxy (pr2) | 9001 from pr1 | pr3:9001 |
| Proxy (pr3) | 9001 from pr2 | vm2:9001 |
| Verifier (vm2) | 9001 from pr3 | pr4:9001, vm5:9100 |
| Proxy (pr4) | 9001 from vm2 | pr5:9001 |
| Proxy (pr5) | 9001 from pr4 | pr6:9001 |
| Proxy (pr6) | 9001 from pr5 | vm3:9001 |
| DA (vm3) | 9001 from pr6 | vm4:9005, vm5:9100 |
| Dual Auth (vm4) | 9004 from vm0, 9005 from vm3 | none |
| Monitor (vm5) | 8443 (dashboard), 9100 from vm2/vm3 | none |

Each proxy only accepts from its predecessor and initiates to its successor, no proxy can communicate with non-adjacent nodes. vm4 and vm5 never initiate outbound connections.

## BPF Programs (per role)

**xdp-entropy.o** — Attached at NIC driver level (pre-iptables). Role-specific configuration:

| Role | Allowed Ports | Entropy Threshold |
|------|--------------|-------------------|
| Proxy | 9001 | 85 (auth), 80 (handshake) |
| Client | 9003 | 85 (auth), 80 (handshake) |
| Verifier | 9001, 9100 | 85 (auth), 80 (handshake) |
| Orchestrator | 9003, 9004 | 85 (auth), 80 (handshake) |
| Dual Auth | 9004, 9005 | 85 (auth), 80 (handshake) |
| Monitor | 8443, 9100 | 85 (auth), 80 (handshake) |

Packets on unauthorized ports are dropped before reaching iptables. Packets with insufficient entropy (plaintext, exploit payloads) are dropped at wire speed.

**bpf-sysmon.o** — Six tracepoint hooks, identical on all nodes:

| Hook | Syscall | Monitors |
|------|---------|----------|
| 1 | sys_enter_execve | Process execution (zero post-boot policy) |
| 2 | sys_enter_ptrace | Debugger attachment, process injection |
| 3 | sys_enter_mount | Filesystem manipulation |
| 4 | sys_enter_socket | Network socket creation (exotic types) |
| 5 | sys_enter_connect | Outbound connections (per-role IP whitelist) |
| 6 | sys_enter_openat | Sensitive file access (/etc/shadow, /dev/mem) |

Connect hook has per-role IP whitelists matching the firewall policy, unauthorized destinations are counted at kernel level before the connection completes.

## Operation

```bash
# On vm0 — initiate authentication
mfa-cli authenticate

# On vm4 — approve (after vm0 request appears)
mfa-cli authenticate

# Dashboard
http://192.168.18.120:8443
```

## Dashboard Pages

- `/` —> Main overview with topology, integrity grid, anomaly detection
- `/node/<id>` —> Per-node detail with runtime state, XDP stats, raw content
- `/sessions` —> Session history with integrity hashes
- `/forensics` —> Forensic event log with deep system snapshots

## API Endpoints

- `/api/state` —> Full system state
- `/api/nodes` —> Per-node verification status
- `/api/latest` —> Latest audit entry
- `/api/sessions` —> Session index
- `/api/forensics` —> Forensic event index

## Project Structure

```
mfa-agent/
  src/
    main.rs               Node roles: client, proxy, ZTS, DA, orchestrator
    lib.rs                Module declarations
    ebpf/mod.rs           System state collection (30 integrity checks)
    protocol/mod.rs       Wire protocol, baseline verification
    audit/mod.rs          Tamper-evident audit log with TPM checkpoints
    crypto/mod.rs         ML-KEM-1024 + X25519 + AES-256-GCM
    tpm/mod.rs            TPM 2.0 operations (quote, sign, verify)
    sysmon/mod.rs         BPF syscall monitor state reader
    netfilter/mod.rs      Direct kernel iptables + XDP status
    dual_authority/mod.rs  VM4 interactive dual-operator approval
    orchestrator/mod.rs   INITIATE protocol, replay cache, credentials
    config/mod.rs         Node configuration
    network/mod.rs        TCP framing and message transport
    xdp/mod.rs            XDP program loader (development only)
  src/bin/
    vm0-cli.rs            Operator CLI (authenticate, status, revoke)
    baseline-tool.rs      Baseline capture, merge, display
    init-credentials.rs   Credential initialization
  xdp-entropy.c           XDP entropy filter (eBPF C)
  bpf-sysmon.c            Syscall monitor (eBPF C)

mfa-monitor/
  src/
    lib.rs                Log forwarding protocol
    session_tracker.rs    Session detection and storage
  src/bin/
    monitor.rs            Dashboard, log receiver, cross-verification
    logfwd.rs             Encrypted log forwarder (vm2/vm3 → vm5)
```

