# tcp-udp

This repository contains a demonstration TCP and UDP packet communication in Rust using `tokio`.

## Overview

The `tcp_udp` crate defines a `Packet` structure that can be serialized and deserialized for network transmission. It provides methods for sending and receiving packets over `tokio::net::TcpStream` and `tokio::net::UdpSocket`.

The `main.rs` example demonstrates a UDP server that:
1. Listens for incoming UDP packets.
2. Deserializes the received packets.
3. Prints the packet ID and payload.
4. Sends an "echo" packet back to the sender.
5. Sends a heartbeat message every 5 seconds.

## Project Structure

- `src/lib.rs`: Defines the `Packet` struct and its associated methods for serialization, deserialization, and sending/receiving over TCP/UDP.
- `src/main.rs`: Contains the main application logic, implementing a UDP server.

## Packet Structure

The `Packet` struct has the following fields:

- `id`: A `u16` representing the packet's identifier.
- `payload`: A `Vec<u8>` containing the packet's data.

### Serialization and Deserialization

- `serialize()`: Converts a `Packet` into a byte vector. The format is `[id (2 bytes)] + [payload]`.
- `deserialize()`: Converts a byte slice back into a `Packet`.

### Network Operations

- `send(&self, stream: &mut TcpStream)`: Asynchronously sends the packet over a `TcpStream`. The packet is prefixed with its total length (including ID and payload) as a `u16`.
- `recv(stream: &mut TcpStream)`: Asynchronously receives a packet from a `TcpStream`. It first reads the packet length, then the ID, and finally the payload.

## Getting Started

### Prerequisites

- Rust and Cargo: If you don't have Rust installed, you can get it from [rustup.rs](https://rustup.rs/).

### Running the UDP Server Example

1. **Clone the repository:**

   ```bash
   git clone <repository_url>
   cd <repository_name>
   ```

2. **Run the example:**

   ```bash
   cargo run
   ```

   This will start the UDP server listening on `127.0.0.1:8080`. You will see heartbeat messages in the console.

### Testing the UDP Server

You can use a tool like `netcat` (or `nc`) or write a simple client to send UDP packets to the server.

**Example using `netcat`:**

Open another terminal and send a message:

```bash
echo -n -e "\x00\x01Hello" | nc -u 127.0.0.1 8080
```

- `\x00\x01`: Represents the 2-byte packet ID (here, `1` in big-endian).
- `Hello`: Is the payload.

The server will then print something

### Rust Ecosystem

To update rust:

```
rustup self update
```

Then run:

```
rustup update
```

Then try:

```bash
cargo clean
cargo build
cargo run
```

