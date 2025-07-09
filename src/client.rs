// src/client.rs
use tcp_udp::{Packet, EncryptedMessage};
use tokio::net::UdpSocket;
use std::io::{self, Write}; // For stdin/stdout interaction
use hex; // For converting bytes to hex for display

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?; // Bind to an ephemeral port
    let server_addr = "127.0.0.1:8080";

    println!("UDP Client started. Sending encrypted messages to {}", server_addr);

    loop {
        let mut plaintext_input = String::new();
        print!("\nEnter plaintext message (or 'quit' to exit): ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut plaintext_input)?;
        let plaintext = plaintext_input.trim();

        if plaintext.eq_ignore_ascii_case("quit") {
            println!("Exiting client.");
            break;
        }

        let mut password_input = String::new();
        print!("Enter encryption password: ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut password_input)?;
        let password = password_input.trim();

        println!("Encrypting message...");
        match Packet::encrypt_payload(password, plaintext.as_bytes()) {
            Ok(encrypted_msg) => {
                println!("Encryption successful!");
                println!("- Nonce (hex): {}", hex::encode(&encrypted_msg.nonce));
                println!("- Ciphertext (hex): {}", hex::encode(&encrypted_msg.ciphertext));
                println!("- Tag (hex): {}", hex::encode(&encrypted_msg.tag));

                // Serialize the EncryptedMessage into the payload of a Packet
                let packet_payload = encrypted_msg.serialize();
                // Use packet ID 1 to signify an encrypted message
                let packet_to_send = Packet::new(1, packet_payload);

                println!("Sending packet to server...");
                socket.send_to(&packet_to_send.serialize(), server_addr).await?;
                println!("Packet sent. Waiting for response...");

                let mut buf = [0u8; 1024];
                match socket.recv_from(&mut buf).await {
                    Ok((len, _addr)) => {
                        if let Some(response_packet) = Packet::deserialize(&buf[..len]) {
                            match response_packet.id {
                                2 => println!("Server response (Decryption Success): {}", String::from_utf8_lossy(&response_packet.payload)),
                                3 => println!("Server response (Decryption Failed): {}", String::from_utf8_lossy(&response_packet.payload)),
                                4 => println!("Server response (Error): {}", String::from_utf8_lossy(&response_packet.payload)),
                                _ => println!("Server response (Other ID {}): {:?}", response_packet.id, response_packet.payload),
                            }
                        } else {
                            println!("Error: Could not deserialize server response packet.");
                        }
                    },
                    Err(e) => {
                        eprintln!("Error receiving response from server: {}", e);
                    }
                }
            },
            Err(e) => {
                eprintln!("Error encrypting message: {}", e);
            }
        }
    }
    Ok(())
}