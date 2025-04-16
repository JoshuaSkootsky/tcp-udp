use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct Packet {
    pub id: u16,
    pub payload: Vec<u8>,
}

const INT_SIZE: usize = 2;

impl Packet {

    /// Serialize packet to bytes: [id (2 bytes)] + [payload]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(INT_SIZE + self.payload.len());
        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Deserialize bytes to packet
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < INT_SIZE {
            return None;
        }
        let id = u16::from_be_bytes([data[0], data[1]]);
        let payload = data[INT_SIZE..].to_vec();
        Some(Self { id, payload })
    }

    /// new creates a new packet with an id and payload
    pub fn new(id: u16,payload: Vec<u8>) -> Self {
        Self { payload, id }
    }

    // send packet over a TcpStream
    pub async fn send(&self, stream: &mut TcpStream) -> tokio::io::Result<()> {
        let len = (INT_SIZE + self.payload.len()) as u16; 
        stream.write_u16(len).await?;
        stream.write_u16(self.id).await?;
        stream.write_all(&self.payload).await?;

        Ok(())
    }

    // Receive a packet from a TcpStream
    pub async fn recv(stream: &mut TcpStream) -> tokio::io::Result<Self> {
        let len = stream.read_u16().await? as usize;
        if len < INT_SIZE {
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::InvalidData,
                "Packet too short",
            ));
        }

        let id = stream.read_u16().await?;
        let payload_len = len - INT_SIZE;
        let mut payload = vec![0u8; payload_len as usize];
        stream.read_exact(&mut payload).await?;
        Ok(Self { payload, id })
    }
}


