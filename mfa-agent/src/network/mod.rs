use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};

/// Connect with exponential backoff retry.
/// 	Starts at 1s, doubles each attempt, caps at 30s, retries indefinitely.
/// 	Enables listen-first deployment where VMs can be started in any order.
pub async fn connect(addr: &str) -> Result<TcpStream> {
    let mut delay_secs: u64 = 1;
    let max_delay: u64 = 30;
    let mut attempt: u32 = 0;

    loop {
        attempt += 1;
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                if attempt > 1 {
                    println!("  Connected to {} after {} attempts", addr, attempt);
                }
                return Ok(stream);
            }
            Err(e) => {
                if attempt == 1 || attempt % 5 == 0 {
                    println!("  Connecting to {} (attempt {}): {} — retrying in {}s",
                        addr, attempt, e, delay_secs);
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;
                delay_secs = (delay_secs * 2).min(max_delay);
            }
        }
    }
}

pub async fn listen(addr: &str) -> Result<TcpListener> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(addr.parse()?)?;
    let listener = socket.listen(128)?;
    Ok(listener)
}

pub async fn accept(listener: &TcpListener) -> Result<TcpStream> {
    let (stream, _) = listener.accept().await?;
    Ok(stream)
}

use crate::protocol::ProtocolMessage;

/// === Send protocol message ===
pub async fn send_message(
    stream: &mut TcpStream,
    message: &ProtocolMessage,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    
    let data = bincode::serialize(message)?;
    let len = data.len() as u32;
    
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&data).await?;
    stream.flush().await?;
    
    Ok(())
}

// === Receive protocol message ===
pub async fn receive_message(
    stream: &mut TcpStream,
) -> Result<ProtocolMessage> {
    use tokio::io::AsyncReadExt;
    
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    
    if len > 10_000_000 {
        return Err(anyhow::anyhow!("Message too large"));
    }
    
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await?;
    
    let message: ProtocolMessage = bincode::deserialize(&data)?;
    Ok(message)
}


