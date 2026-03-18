use std::{
    env::args,
    net::{SocketAddrV4, UdpSocket},
};

use crate::model::{DnsHeader, DnsQuestion, ResultCode, parse_ipv4_addrs};

mod model;

pub struct Cache {
    #[allow(dead_code)]
    map: std::collections::HashMap<String, SocketAddrV4>,
}

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
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();

    // taking domain name input from user
    let args: Vec<String> = args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <domain>", args[0]);
        return;
    }
    if args.len() > 2 {
        eprintln!("Error: expected exactly one domain argument");
        return;
    }

    let query = &args[1];

    let header = DnsHeader {
        id: 1234,
        recursion_desired: false,
        truncated_message: false,
        authoritative_answer: false,
        opcode: 0,
        response: false,
        rescode: ResultCode::NOERROR,
        checking_disabled: false,
        authed_data: false,
        z: false,
        recursion_available: false,
        questions: 1,
        answers: 0,
        authoritative_entries: 0,
        resource_entries: 0,
    };

    let question = DnsQuestion {
        name: query.to_string(),
        qtype: 1, // Type 1 = A Record (IPv4)
        qclass: 1,
    };

    let mut dns_packet = Vec::new();
    dns_packet.extend(header.to_bytes());
    dns_packet.extend(question.to_bytes());

    socket.send_to(&dns_packet, (ROOT_SERVERS[0], 53)).unwrap();

    let mut buffer = [0u8; 512];
    let (bytes_recieved, server_addr) = socket.recv_from(&mut buffer).unwrap();

    println!("\nReceived {} bytes from {}.", bytes_recieved, server_addr);

    // Try to parse the response into a readable form.
    match parse_ipv4_addrs(&buffer[..bytes_recieved]) {
        Some((resp_header, addrs)) => {
            println!(
                "Header: id={}, response={}, questions={}, answers={}, authorities={}, additionals={}",
                resp_header.id,
                resp_header.response,
                resp_header.questions,
                resp_header.answers,
                resp_header.authoritative_entries,
                resp_header.resource_entries,
            );

            if addrs.is_empty() {
                println!("No IPv4 (A) records found in the response.");
            } else {
                println!("IPv4 addresses found:");
                for ip in addrs {
                    println!("  {}", ip);
                }
            }
        }
        None => {
            println!("Failed to parse DNS response, raw bytes:");
            println!("{:?}", &buffer[..bytes_recieved]);
        }
    }
}
