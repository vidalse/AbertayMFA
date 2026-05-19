use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};

const DEFAULT_CONFIG_PATH: &str = "node.json";

fn default_log_mode() -> u8 { 2 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: String,
    pub role: NodeRole,
    pub listen_port: u16,
    /// Circuit path used by client role (chain 1)
    #[serde(default)]
    pub circuit: Vec<CircuitHop>,
    /// Chain 2 circuit used by ZTS role (VM2 → P4 → P5 → P6 → VM3)
    /// Only populated on VM2 when it acts as chain 2 client
    #[serde(default)]
    pub chain2_circuit: Vec<CircuitHop>,
    /// Audit log mode: 1=attestation only, 2=forensic trigger (default), 3=continuous full
    #[serde(default = "default_log_mode")]
    pub log_mode: u8,
    /// Orchestrator fields (vm0 only)
    #[serde(default)]
    pub unix_socket_path: Option<String>,
    #[serde(default)]
    pub vm1_address: Option<String>,
    #[serde(default)]
    pub credentials_path: Option<String>,
    #[serde(default)]
    pub baselines_path: Option<String>,
    /// Verified client fields (vm1 only)
    #[serde(default)]
    pub initiate_port: Option<u16>,    
    /// Dual authority fields (vm4)
    #[serde(default)]
    pub vm4_address: Option<String>,   /// vm0 uses this to connect to vm4
    #[serde(default)]
    pub vm0_address: Option<String>,   /// vm4 uses this to know vm0's identity
    #[serde(default)]
    pub vm3_address: Option<String>,   /// vm4 uses this to listen for vm3 results
    #[serde(default)]
    pub da_listen_port: Option<u16>,   /// vm4 listens on this for vm3 connections (9005)
    #[serde(default)]
    pub mutual_attest_port: Option<u16>, /// vm4 listens on this for vm0 attestation (9004)
    #[serde(default)]
    pub vm0_ak_public_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    Client,
    Proxy,
    Zts,
    Da,  /// Distributed Authority (VM3)
    Orchestrator,  ///vm0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitHop {
    pub node_id: String,
    pub address: String,
}

impl NodeConfig {
    pub fn load(path: Option<&str>) -> Result<Self> {
        let config_path = path.unwrap_or(DEFAULT_CONFIG_PATH);
        let json = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config: {}", config_path))?;
        let config: NodeConfig = serde_json::from_str(&json)
            .with_context(|| format!("Failed to parse config: {}", config_path))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.node_id.is_empty() {
            return Err(anyhow::anyhow!("node_id cannot be empty"));
        }

        match self.role {
            NodeRole::Client => {
                if self.circuit.is_empty() {
                    return Err(anyhow::anyhow!("Client role requires non-empty circuit"));
                }
                if self.circuit.len() < 2 {
                    return Err(anyhow::anyhow!(
                        "Circuit must have at least 2 hops, got {}",
                        self.circuit.len()
                    ));
                }
            }
            NodeRole::Zts => {
                if !self.chain2_circuit.is_empty() && self.chain2_circuit.len() < 2 {
                    return Err(anyhow::anyhow!(
                        "chain2_circuit must have at least 2 hops, got {}",
                        self.chain2_circuit.len()
                    ));
                }
            }
            NodeRole::Proxy => {}
            NodeRole::Da => {}
            NodeRole::Orchestrator => {
                if self.unix_socket_path.is_none() {
                    return Err(anyhow::anyhow!("Orchestrator role requires unix_socket_path"));
                }
                if self.vm1_address.is_none() && self.mutual_attest_port.is_none() {
                    return Err(anyhow::anyhow!("Orchestrator requires vm1_address (vm0) or mutual_attest_port (vm4)"));
                }
                if self.credentials_path.is_none() {
                    return Err(anyhow::anyhow!("Orchestrator role requires credentials_path"));
                }
                if self.baselines_path.is_none() {
                    return Err(anyhow::anyhow!("Orchestrator role requires baselines_path"));
                }
            }
        }

        Ok(())
    }

    pub fn entry_address(&self) -> Result<&str> {
        self.circuit.first()
            .map(|h| h.address.as_str())
            .ok_or_else(|| anyhow::anyhow!("No circuit defined"))
    }

    pub fn chain2_entry_address(&self) -> Result<&str> {
        self.chain2_circuit.first()
            .map(|h| h.address.as_str())
            .ok_or_else(|| anyhow::anyhow!("No chain2_circuit defined"))
    }

    pub fn has_chain2(&self) -> bool {
        !self.chain2_circuit.is_empty()
    }

    pub fn print_summary(&self) {
        println!("Node Configuration:");
        println!("   ID:   {}", self.node_id);
        println!("   Role: {:?}", self.role);
        println!("   Port: {}", self.listen_port);
        println!("   Log mode: {}", self.log_mode);
        if !self.circuit.is_empty() {
            println!("   Circuit 1 ({} hops):", self.circuit.len());
            for (i, hop) in self.circuit.iter().enumerate() {
                println!("     [{}] {} → {}", i, hop.node_id, hop.address);
            }
        }
        if !self.chain2_circuit.is_empty() {
            println!("   Circuit 2 ({} hops):", self.chain2_circuit.len());
            for (i, hop) in self.chain2_circuit.iter().enumerate() {
                println!("     [{}] {} → {}", i, hop.node_id, hop.address);
            }
        }
    }
}

impl std::fmt::Display for NodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeRole::Client => write!(f, "client"),
            NodeRole::Proxy => write!(f, "proxy"),
            NodeRole::Zts => write!(f, "zts"),
            NodeRole::Da => write!(f, "da"),
            NodeRole::Orchestrator => write!(f, "orchestrator"),            
        }
    }
}

