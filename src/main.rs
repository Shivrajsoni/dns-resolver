use std::{collections::HashMap, env::args, net::{Ipv4Addr, SocketAddrV4, UdpSocket}};

use crate::model::{DnsHeader, DnsQuestion};

mod model;


pub struct cache {
    map: HashMap<String,SocketAddrV4>
}

pub  const root_servers : &[&str] = &[
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
     "202.12.27.33"
 ];


#[tokio::main]
async fn main() {

    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();

    // taking domain name input from user 
    let args: Vec<String> = args().collect();


    if args.len() > 2 {
        eprintln!("Found more than 1 arguments");
        return ;
    }

    let _query =  &args[0];

    let header = DnsHeader {
        id: 1234,
        flags: 0x0000,
        num_questions: 1,
        num_answers:0,
        num_authorities: 0,
        num_additionals: 0 
    };

    let question = DnsQuestion {
        name: _query.to_string(),
        qtype: 1, /// Type 1 = A Record (IPv4)
        qclass : 1 // // Class 1 = IN (Internet) 
    };

    let mut dns_packet = Vec::new();
    dns_packet.extend(header.to_bytes());
    dns_packet.extend(question.to_bytes());

    socket.send_to(&dns_packet,(root_servers[0],53)).unwrap();
    let mut buffer = [0u8;512];
    let (bytes_recieved,server_addr ) = socket.recv_from(&mut buffer).unwrap();

    println!("\nReceived {} bytes from {}.", bytes_recieved, server_addr);
    println!("Raw Response Bytes: {:?}\n", &buffer[..bytes_recieved]);

}
