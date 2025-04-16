// src/main.rs
use chrono::Local;
use tcp_udp::Packet;
use tokio::net::UdpSocket;
use tokio::time::{interval, Duration};

/// tokio:main allows your main function to be async
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:8080").await?;
    let mut buf = [0u8; 1024];
    let mut heartbeat_interval = interval(Duration::from_secs(5));

    loop {
        tokio::select! {
            _ = heartbeat_interval.tick() => {

            println!(
            "[{}] Sending heartbeat",
            Local::now().format("%Y-%m-%d %H:%M:%S")
        );
                    }
                ,
                result = socket.recv_from(&mut buf) => {
                    let (len, addr) = result?;
                    if let Some(packet) = Packet::deserialize(&buf[..len]) {
                        println!("Received packed id: {}, payload: {:?}", packet.id, packet.payload);
                        // then echo back
                        let response = Packet { id: packet.id, payload:  b"back".to_vec()};
                        socket.send_to(&response.serialize(), &addr).await?;
                    }
                }
            };
    }
}
