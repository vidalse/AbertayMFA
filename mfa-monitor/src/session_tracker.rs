use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const SESSIONS_DIR: &str = "/opt/mfa-monitor/sessions";

// === Session Data Structures ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedSession {
    pub session_id: String,
    pub source: String,
    pub start_time: u64,
    pub end_time: u64,
    pub duration_secs: u64,
    pub heartbeat_count: u64,
    pub all_authorized: bool,
    pub total_nodes_verified: usize,

    /// Chain integrity within this session
    pub chain_integrity: ChainIntegrity,

    /// All entries in this session (full AuditEntryV2)
    pub entries: Vec<serde_json::Value>,

    /// Session summary for quick display
    pub summary: SessionSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainIntegrity {
    pub first_hash: String,
    pub last_hash: String,
    pub entry_count: usize,
    pub all_hashes_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub nodes_seen: Vec<String>,
    pub failing_nodes: Vec<String>,
    pub forensic_captures: usize,
    pub tpm_checkpoints: usize,
    pub avg_verification_ms: u64,
    pub max_verification_ms: u64,
    pub denial_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionIndexEntry {
    pub session_id: String,
    pub source: String,
    pub start_time: u64,
    pub end_time: u64,
    pub duration_secs: u64,
    pub heartbeats: u64,
    pub all_authorized: bool,
    pub node_count: usize,
    pub filename: String,
    /// SHA256 of the session file contents, tamper detection
    pub file_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionIndex {
    pub sessions: Vec<SessionIndexEntry>,
    /// SHA256 of all session hashes concatenated, index integrity
    pub index_hash: String,
}

// === ACTIVE SESSION (in-memory, not yet written to disk) ===

pub struct ActiveSession {
    pub source: String,
    pub start_time: u64,
    pub last_time: u64,
    pub last_heartbeat: u64,
    pub all_authorized: bool,
    pub entries: Vec<serde_json::Value>,
    pub prev_hashes: Vec<String>,
    pub nodes_seen: Vec<String>,
    pub forensic_count: usize,
    pub checkpoint_count: usize,
    pub verification_times: Vec<u64>,
    pub total_nodes: usize,
    pub denial_reason: Option<String>,
}

// === SESSION TRACKER ===

pub struct SessionTracker {
    /// Active sessions per source
    active: HashMap<String, ActiveSession>,
    /// Sessions directory path
    sessions_dir: PathBuf,
}

impl SessionTracker {
    pub fn new() -> Self {
        let sessions_dir = PathBuf::from(SESSIONS_DIR);
        if !sessions_dir.exists() {
            let _ = std::fs::create_dir_all(&sessions_dir);
            /// Restrict permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &sessions_dir,
                    std::fs::Permissions::from_mode(0o700),
                );
            }
        }
        SessionTracker {
            active: HashMap::new(),
            sessions_dir,
        }
    }

    /// Process an incoming audit entry. Returns Some(session_id) if a
    /// session was just completed and written to disk.
    pub fn process_entry(
        &mut self,
        source: &str,
        entry_json: &str,
        entry: &serde_json::Value,
    ) -> Option<String> {
        let now = now_secs();
        let heartbeat = entry.get("heartbeat")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let authorized = entry.get("authorized")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let timestamp = entry.get("timestamp")
            .and_then(|v| v.as_u64())
            .unwrap_or(now);
        let prev_hash = entry.get("prev_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let event = entry.get("event")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let has_forensic = entry.get("forensic").is_some()
            && !entry.get("forensic").unwrap().is_null();
        let has_checkpoint = entry.get("tpm_checkpoint").is_some()
            && !entry.get("tpm_checkpoint").unwrap().is_null();
        let verify_ms = entry.get("verification_duration_ms")
            .and_then(|v| v.as_u64());
        let total_nodes = entry.get("total_nodes_verified")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let session_status = entry.get("session_status")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        /// Extract node names from this entry
        let mut entry_nodes: Vec<String> = Vec::new();
        if let Some(nodes) = entry.get("nodes").and_then(|v| v.as_array()) {
            for n in nodes {
                if let Some(name) = n.get("node").and_then(|v| v.as_str()) {
                    entry_nodes.push(name.to_string());
                }
            }
        }

        let mut completed_id = None;

        let is_new_session = heartbeat == 1
            && (event == "ChainVerified" || event == "ChainDenied");

        let is_session_end = event == "SessionEnded" || event == "SESSION_ENDED";

        if is_session_end {
            if let Some(old_session) = self.active.remove(source) {
                return Some(self.finalize_session(old_session));
            }
            return None;
        }

        if is_new_session {
            /// Finalize any existing session for this source
            if let Some(old_session) = self.active.remove(source) {
                completed_id = Some(self.finalize_session(old_session));
            }
        }


        /// Get or create active session
        let session = self.active.entry(source.to_string()).or_insert_with(|| {
            ActiveSession {
                source: source.to_string(),
                start_time: timestamp,
                last_time: timestamp,
                last_heartbeat: 0,
                all_authorized: true,
                entries: Vec::new(),
                prev_hashes: Vec::new(),
                nodes_seen: Vec::new(),
                forensic_count: 0,
                checkpoint_count: 0,
                verification_times: Vec::new(),
                total_nodes: 0,
                denial_reason: None,
            }
        });

        /// Update session state
        session.last_time = timestamp;
        session.last_heartbeat = heartbeat;
        if !authorized {
            session.all_authorized = false;
            if session.denial_reason.is_none() {
                session.denial_reason = Some(session_status.to_string());
            }
        }
        session.prev_hashes.push(prev_hash);
        if has_forensic { session.forensic_count += 1; }
        if has_checkpoint { session.checkpoint_count += 1; }
        if let Some(ms) = verify_ms { session.verification_times.push(ms); }
        if total_nodes > session.total_nodes { session.total_nodes = total_nodes; }

        for node in &entry_nodes {
            if !session.nodes_seen.contains(node) {
                session.nodes_seen.push(node.clone());
            }
        }

        /// Store the full entry
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(entry_json) {
            session.entries.push(val);
        } else {
            session.entries.push(entry.clone());
        }

        /// Check for session-ending events
        if !authorized && (event == "ChainDenied" || event == "HeartbeatFail") {
            /// Session terminated by failure, finalize
            let ended = self.active.remove(source).unwrap();
            let id = self.finalize_session(ended);
            return Some(id);
        }

        completed_id
    }

    /// Finalize an active session: build CompletedSession, write to disk.
    fn finalize_session(&self, session: ActiveSession) -> String {
        let end_time = session.last_time;
        let duration = end_time.saturating_sub(session.start_time);

        /// Verify hash chain continuity within session
        let chain_ok = self.verify_internal_chain(&session.entries);

        let first_hash = session.prev_hashes.first()
            .cloned().unwrap_or_default();
        let last_hash = session.prev_hashes.last()
            .cloned().unwrap_or_default();

        /// Compute session ID from first entry hash + source + start time
        let session_id = {
            let mut h = Sha256::new();
            h.update(session.source.as_bytes());
            h.update(session.start_time.to_le_bytes());
            h.update(first_hash.as_bytes());
            hex::encode(&h.finalize()[..8])
        };

        /// Compute summary
        let avg_ms = if session.verification_times.is_empty() { 0 }
            else { session.verification_times.iter().sum::<u64>()
                / session.verification_times.len() as u64 };
        let max_ms = session.verification_times.iter().max().copied().unwrap_or(0);

        /// Find failing nodes across all entries
        let mut failing_nodes: Vec<String> = Vec::new();
        for entry in &session.entries {
            if let Some(nodes) = entry.get("nodes").and_then(|v| v.as_array()) {
                for n in nodes {
                    let pass = n.get("pass").and_then(|v| v.as_bool()).unwrap_or(true);
                    if !pass {
                        let name = n.get("node").and_then(|v| v.as_str()).unwrap_or("?");
                        if !failing_nodes.contains(&name.to_string()) {
                            failing_nodes.push(name.to_string());
                        }
                    }
                }
            }
        }

        let completed = CompletedSession {
            session_id: session_id.clone(),
            source: session.source.clone(),
            start_time: session.start_time,
            end_time,
            duration_secs: duration,
            heartbeat_count: session.last_heartbeat,
            all_authorized: session.all_authorized,
            total_nodes_verified: session.total_nodes,
            chain_integrity: ChainIntegrity {
                first_hash,
                last_hash,
                entry_count: session.entries.len(),
                all_hashes_valid: chain_ok,
            },
            entries: session.entries,
            summary: SessionSummary {
                nodes_seen: session.nodes_seen,
                failing_nodes,
                forensic_captures: session.forensic_count,
                tpm_checkpoints: session.checkpoint_count,
                avg_verification_ms: avg_ms,
                max_verification_ms: max_ms,
                denial_reason: session.denial_reason,
            },
        };

        /// Write to disk
        if let Err(e) = self.write_session(&completed) {
            eprintln!("  !! Failed to write session {}: {}", session_id, e);
        } else {
            println!("  SESSION STORED: {} ({} source={} hb={} duration={}s {})",
                session_id, 
                if completed.all_authorized { "PASS" } else { "FAIL" },
                completed.source,
                completed.heartbeat_count,
                duration,
                if completed.summary.failing_nodes.is_empty() { "".into() }
                else { format!("failures={}", completed.summary.failing_nodes.join(",")) },
            );
        }

        session_id
    }

    /// Write completed session to disk and update index.
    fn write_session(&self, session: &CompletedSession) -> Result<(), Box<dyn std::error::Error>> {
        let filename = format!("session_{}_{}.json",
            session.source, session.session_id);
        let filepath = self.sessions_dir.join(&filename);

        let json = serde_json::to_string_pretty(session)?;

        /// Compute file hash before writing
        let file_hash = hex::encode(Sha256::digest(json.as_bytes()));

        std::fs::write(&filepath, &json)?;

        /// Update index
        let index_path = self.sessions_dir.join("index.json");
        let mut index = if index_path.exists() {
            let content = std::fs::read_to_string(&index_path)?;
            serde_json::from_str::<SessionIndex>(&content).unwrap_or(SessionIndex {
                sessions: Vec::new(),
                index_hash: String::new(),
            })
        } else {
            SessionIndex {
                sessions: Vec::new(),
                index_hash: String::new(),
            }
        };

        index.sessions.push(SessionIndexEntry {
            session_id: session.session_id.clone(),
            source: session.source.clone(),
            start_time: session.start_time,
            end_time: session.end_time,
            duration_secs: session.duration_secs,
            heartbeats: session.heartbeat_count,
            all_authorized: session.all_authorized,
            node_count: session.summary.nodes_seen.len(),
            filename: filename.clone(),
            file_hash: file_hash.clone(),
        });

        /// Recompute index integrity hash
        let mut idx_hasher = Sha256::new();
        for s in &index.sessions {
            idx_hasher.update(s.file_hash.as_bytes());
        }
        index.index_hash = hex::encode(idx_hasher.finalize());

        let index_json = serde_json::to_string_pretty(&index)?;
        std::fs::write(&index_path, index_json)?;

        Ok(())
    }

    /// Verify hash chain within session entries.
    fn verify_internal_chain(&self, entries: &[serde_json::Value]) -> bool {
        if entries.len() <= 1 { return true; }

        for i in 1..entries.len() {
            let prev_entry_json = serde_json::to_string(&entries[i - 1]).unwrap_or_default();
            let expected_hash = hex::encode(Sha256::digest(prev_entry_json.as_bytes()));
            let actual_prev = entries[i].get("prev_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if actual_prev != expected_hash {
                return false;
            }
        }
        true
    }

    /// Get number of active sessions
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Load session index from disk
    pub fn load_index() -> Option<SessionIndex> {
        let index_path = Path::new(SESSIONS_DIR).join("index.json");
        let content = std::fs::read_to_string(index_path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Load a specific session from disk
    pub fn load_session(filename: &str) -> Option<CompletedSession> {
        let filepath = Path::new(SESSIONS_DIR).join(filename);
        let content = std::fs::read_to_string(filepath).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Verify integrity of a session file against index hash
    pub fn verify_session_integrity(filename: &str) -> Option<bool> {
        let index = Self::load_index()?;
        let entry = index.sessions.iter().find(|s| s.filename == filename)?;

        let filepath = Path::new(SESSIONS_DIR).join(filename);
        let content = std::fs::read_to_string(filepath).ok()?;
        let actual_hash = hex::encode(Sha256::digest(content.as_bytes()));

        Some(actual_hash == entry.file_hash)
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

