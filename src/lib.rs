
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use sha2::{Sha256, Digest};

use rand::RngCore; // Trait for RngCore

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


    /// Encrypts a payload using AES-256-GCM.
    /// Returns an EncryptedMessage struct.
    pub fn encrypt_payload(password: &str, plaintext: &[u8]) -> Result<EncryptedMessage, String> {
        // 1. Derive a 32-byte key from the password using SHA256
        let mut hasher = sha2::Sha256::new();
        hasher.update(password.as_bytes());
        let key_bytes: [u8; 32] = hasher.finalize().into(); // Converts GenericArray to [u8; 32]

        let key    = Key::<Aes256Gcm>::from_slice(&key_bytes);

        
        let cipher = Aes256Gcm::new(key);



        use rand::rngs::OsRng;
        // 2. Generate a random 12-byte Nonce (Initialization Vector)    use rand::RngCore; // Ensure the RngCore trait is in scope
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        // 3. Encrypt the plaintext
        // The `encrypt` method returns a Vec<u8> which contains the ciphertext
        // followed by the 16-byte authentication tag.
        match cipher.encrypt(nonce, plaintext) {
            Ok(ciphertext_with_tag) => {
                // AES-GCM's encrypt method for `Aead` returns ciphertext || tag
                // The tag is always 16 bytes for GCM.
                let tag_start_index = ciphertext_with_tag.len() - 16;
                let ciphertext = ciphertext_with_tag[..tag_start_index].to_vec();
                let tag = ciphertext_with_tag[tag_start_index..].to_vec();

                Ok(EncryptedMessage {
                    nonce: nonce_bytes.to_vec(),
                    ciphertext,
                    tag,
                })
            }
            Err(e) => Err(format!("Encryption failed: {:?}", e)),
        }
    }

    /// Decrypts an EncryptedMessage using AES-256-GCM.
    /// Returns the original plaintext if successful, or an error if decryption fails
    /// (e.g., incorrect password, corrupted data).
    pub fn decrypt_payload(password: &str, encrypted_msg: &EncryptedMessage) -> Result<Vec<u8>, String> {
        // 1. Derive the key from the password (must be same derivation as encryption)
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let key_bytes: [u8; 32] = hasher.finalize().into();

        // Create an AES-GCM cipher instance
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let nonce = Nonce::from_slice(&encrypted_msg.nonce);

        // Combine ciphertext and tag for decryption
        let mut ciphertext_with_tag = encrypted_msg.ciphertext.clone();
        ciphertext_with_tag.extend_from_slice(&encrypted_msg.tag);

        // Decrypt the combined ciphertext and tag
        match cipher.decrypt(nonce, ciphertext_with_tag.as_ref()) {
            Ok(plaintext) => Ok(plaintext),
            Err(e) => Err(format!("Decryption failed (incorrect password or corrupted data): {:?}", e)),
        }
    }
}

/// This structure is designed to be sent as the payload of a `Packet`.
pub struct EncryptedMessage {
    pub nonce: Vec<u8>,       // The unique nonce (12 bytes for AES-GCM)
    pub ciphertext: Vec<u8>,  // The encrypted data
    pub tag: Vec<u8>,         // The authentication tag (16 bytes for AES-GCM)
}

impl EncryptedMessage {
    /// Combines nonce, ciphertext, and tag into a single byte vector for transmission.
    /// Format: [nonce_len (1 byte)] + [tag_len (1 byte)] + [nonce] + [tag] + [ciphertext]
    /// We'll explicitly store lengths to make parsing robust, as `nonce` and `tag`
    /// might conceptually be fixed sizes for AES-GCM, but this makes the format
    /// more flexible if other AEADs are used later.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.nonce.len() as u8);
        buf.push(self.tag.len() as u8);
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.tag);
        buf.extend_from_slice(&self.ciphertext);
        buf
    }

    /// Deserializes a byte vector back into an EncryptedMessage.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 2 { // Need at least nonce_len and tag_len bytes
            return None;
        }

        let nonce_len = data[0] as usize;
        let tag_len = data[1] as usize;
        let header_offset = 2; // Offset for nonce_len and tag_len bytes

        if data.len() < header_offset + nonce_len + tag_len {
            return None; // Not enough data for nonce, tag, and possibly ciphertext
        }

        let nonce_start = header_offset;
        let nonce_end = nonce_start + nonce_len;
        let tag_start = nonce_end;
        let tag_end = tag_start + tag_len;
        let ciphertext_start = tag_end;

        let nonce = data[nonce_start..nonce_end].to_vec();
        let tag = data[tag_start..tag_end].to_vec();
        let ciphertext = data[ciphertext_start..].to_vec();

        Some(Self {
            nonce,
            ciphertext,
            tag,
        })
    }
}

