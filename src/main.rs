use std::{env::args, net::UdpSocket};

use crate::model::{BytePacketBuffer, DnsPacket, DnsQuestion, DnsRecord, QueryType};

mod model;

pub const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
];

#[tokio::main]
async fn main() {
    let argv: Vec<String> = args().collect();

    if argv.len() < 2 {
        eprintln!("Usage: {} <domain>", argv[0]);
        return;
    }
    if argv.len() > 2 {
        eprintln!("Error: expected exactly one domain argument");
        return;
    }

    let domain = argv[1].clone();

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to bind UDP socket: {e}");
            return;
        }
    };

    // Build request packet: QNAME=domain, QTYPE=A.
    let mut request = DnsPacket::new();
    request.header.id = 1234;
    request
        .questions
        .push(DnsQuestion::new(domain.clone(), QueryType::A));

    // Serialize request into bytes.
    let mut out_buf = BytePacketBuffer::new();
    if let Err(e) = request.write(&mut out_buf) {
        eprintln!("Failed to build DNS query packet: {e}");
        return;
    }
    let size = out_buf.pos;

    // Send to root server.
    if let Err(e) = socket.send_to(&out_buf.buf[..size], (ROOT_SERVERS[0], 53)) {
        eprintln!("Failed to send DNS query: {e}");
        return;
    }

    // Receive response bytes.
    let mut raw = [0u8; 512];
    let (bytes_received, server_addr) = match socket.recv_from(&mut raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to receive DNS response: {e}");
            return;
        }
    };
    println!("\nReceived {} bytes from {}.", bytes_received, server_addr);

    // Parse response into a DnsPacket.
    let mut in_buf = BytePacketBuffer::new();
    in_buf.buf[..bytes_received].copy_from_slice(&raw[..bytes_received]);
    in_buf.pos = 0;

    let response = match DnsPacket::from_buffer(&mut in_buf) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to parse DNS response: {e}");
            return;
        }
    };

    println!(
        "Header: id={}, response={}, questions={}, answers={}, authorities={}, resources={}",
        response.header.id,
        response.header.response,
        response.header.questions,
        response.header.answers,
        response.header.authoritative_entries,
        response.header.resource_entries
    );

    // Print IPv4 addresses (A records) from all sections we parsed.
    let mut any_a = false;
    for rec in response
        .answers
        .iter()
        .chain(response.authorities.iter())
        .chain(response.resources.iter())
    {
        if let DnsRecord::A {
            domain,
            addr,
            ttl: _,
        } = rec
        {
            any_a = true;
            println!("  {} -> {}", domain, addr);
        }
    }

    if !any_a {
        println!("No IPv4 (A) records found in the response.");
    }
}
