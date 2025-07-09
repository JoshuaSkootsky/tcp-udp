// src/main.rs
use chrono::Local;
use tcp_udp::{Packet, EncryptedMessage};
use tokio::net::UdpSocket;
use tokio::time::{interval, Duration};
use std::io::{self, Write}; // For stdin/stdout interaction

const LOCAL_HOST: &str = "127.0.0.1";
const LOCAL_PORT: u16 = 8080;

const FIVE: u64 = 5;

/// tokio:main allows your main function to be async
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind((LOCAL_HOST, LOCAL_PORT)).await?;
    let mut buf = [0u8; 1024];
    let mut heartbeat_interval = interval(Duration::from_secs(FIVE));

    println!("UDP Server listening on {}:{}. Waiting for encrypted messages...", LOCAL_HOST, LOCAL_PORT);
    loop {
        tokio::select! {
            _ = heartbeat_interval.tick() => {

            println!(
              "[{}] Sending heartbeat",
              Local::now().format("%Y-%m-%d %H:%M:%S")
             );
           },
            result = socket.recv_from(&mut buf) => {
                    let (len, addr) = result?;
                
                    if let Some(packet) = Packet::deserialize(&buf[..len]) {
                        println!("\nReceived packet from {}: ID={}, Payload Length={}", addr, packet.id, packet.payload.len());

                        if packet.id == 1 {
                            println!("Attempting to decrypt message...");

                            if let Some(encrypted_msg) = EncryptedMessage::deserialize(&packet.payload) {
                            println!("- Nonce (hex): {}", hex::encode(&encrypted_msg.nonce));
                            println!("- Ciphertext (hex): {}", hex::encode(&encrypted_msg.ciphertext));
                            println!("- Tag (hex): {}", hex::encode(&encrypted_msg.tag));

                            let mut password_input = String::new();
                            print!("Enter decryption password: ");
                            io::stdout().flush()?; // Ensure the prompt is displayed immediately
                            io::stdin().read_line(&mut password_input)?;
                            let password = password_input.trim();

                            match Packet::decrypt_payload(password, &encrypted_msg) {
                                Ok(plaintext_bytes) => {
                                    let plaintext = String::from_utf8_lossy(&plaintext_bytes);
                                    println!("\n>>> Decryption SUCCESSFUL! <<<");
                                    println!("Original Plaintext: \"{}\"", plaintext);
                                    // You could potentially echo back a success message or the plaintext itself
                                    let response_payload = format!("Decrypted: {}", plaintext).as_bytes().to_vec();
                                    let response_packet = Packet::new(2, response_payload); // ID 2 for decryption success
                                    socket.send_to(&response_packet.serialize(), &addr).await?;
                                },
                                Err(e) => {
                                    println!("\n!!! Decryption FAILED: {}", e);
                                    println!("(Incorrect password, corrupted data, or invalid nonce/tag)");
                                    let response_payload = format!("Decryption failed: {}", e).as_bytes().to_vec();
                                    let response_packet = Packet::new(3, response_payload); // ID 3 for decryption failure
                                    socket.send_to(&response_packet.serialize(), &addr).await?;
                                }
                            }
                        } else {
                            println!("Error: Could not deserialize payload into EncryptedMessage.");
                            let response_packet = Packet::new(4, b"Error: Invalid EncryptedMessage format".to_vec());
                            socket.send_to(&response_packet.serialize(), &addr).await?;
                        }
                    } else {
                        println!("Error: Could not deserialize received bytes into a Packet.");
                    }
                } 
            }
    }
    };
}
