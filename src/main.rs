use std::{env, error::Error, io};


use std::net::UdpSocket;



// DNS PROTOCOL STRUCTURE 
#[derive(Debug)]
pub struct DnsPacket {
    header: DnsHeader , // 12 bytes 
    question: Vec<DnsQuestion>, // variable bytes for (QNAME ) + 2 BYTES QTYPE + 2 BYTES QCLASS 
//    answer: , 
 //   authority: ,
  //  additional: ,
}

impl DnsPacket {
    fn serialize(&self) -> Vec<u8>{
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.header.serialize());
        
        for question in &self.question {
            bytes.extend_from_slice(&question.serialize());
        }

        bytes
    }

}

// Total 12 Bytes , 2 bytes each 
#[derive(Debug)]
pub struct DnsHeader {
    id: u16,// Random ID to match replies to queries ,
    flags: DnsFlags, // QR, Opcode, AA, TC, RD, RA, Z, RCODE ,
    qd_count:u16 , // Number of questions (usually 1) , 
    an_count: u16,  // Number of answers (0 in a query)
    ns_count: u16, // Number of authority records (0 in query)
    ar_count: u16, // Number of additional records (0 in query)
}

impl DnsHeader {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_u16().to_be_bytes());
        bytes.extend_from_slice(&self.qd_count.to_be_bytes());
        bytes.extend_from_slice(&self.an_count.to_be_bytes());
        bytes.extend_from_slice(&self.an_count.to_be_bytes());
        bytes.extend_from_slice(&self.ns_count.to_be_bytes());
        bytes.extend_from_slice(&self.ar_count.to_be_bytes());
        bytes
    }

}



#[derive(Debug)]
pub struct DnsQuestion {
    qname: String,
    qtype: u16 , // 2 bytes  Type: 1 = A record (IPv4)
    qclass: u16, // 2 bytes  Class: 1 =  IN (Internet)
}

impl DnsQuestion {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.qname.clone().into_bytes());
        bytes.extend_from_slice(&self.qtype.to_be_bytes());
        bytes.extend_from_slice(&self.qclass.to_be_bytes());
        bytes
    }


}


// Total 16 bits in FLAG(2bytes )
// Bit(s),  Name,    Description
//  15        QR,    Query (0) or Response (1).
//  11-14,  Opcode  ,Usually 0 (Standard query).
//  10      ,AA,    Authoritative Answer (only in responses).
//  9,      TC,     Truncated (set if the packet exceeds 512 bytes).
//  8       ,RD,    Recursion Desired. Set this to 1 if you want the server to do the work for you.
//  7,      RA,     Recursion Available (set by server).
//  4-6,    Z,      Reserved for future use (must be 0).
//  0-3,    RCODE,  "Response Code (0 for No Error, 3 for NXDomain)."

#[derive(Debug,Default)]
pub struct DnsFlags {
    pub query_response: bool, // QR 
    pub opcode: u8, // 4 BITS 
    pub authorative: bool, // AA 
    pub truncated: bool, // TC
    pub recursion_desired: bool, // RD 
    pub recursion_available: bool, // RA 
    pub z: u8, // Z 
    pub response_code: u8, // RCODE 
}

impl DnsFlags {

    pub fn to_u16(&self) -> u16 {
        let mut res = 0u16;
        res |= (self.query_response as u16 ) << 15;
        res |= (self.opcode as u16 ) << 11;
        res |= (self.authorative as u16 ) << 10;
        res |= (self.truncated as u16 ) << 9;
        res |= (self.recursion_desired as u16 ) << 8;
        res |= (self.recursion_available as u16 ) << 7;
        res |= ((self.z & 0x07) as u16 ) << 4;
        res |= (self.response_code & 0x0F) as u16;
        res
    }


    pub fn from_u16(bits:u16)-> Self {
        Self {
            query_response: (bits >> 15) & 1 == 1,
            opcode: (bits >> 11 & 0x0F) as u8,
            authorative: (bits >> 10) & 1 == 1 ,
            truncated: (bits >> 9) & 1 == 1,
            recursion_desired: (bits >> 8) & 1 == 1,
            recursion_available: (bits >> 7) & 1 == 1 ,
            z: ((bits >> 4) & 0x07 ) as u8,
            response_code: (bits & 0x0F) as u8 
        }

    }
}

fn main() -> std::io::Result<()> {
    // 1. Setup the UDP socket (bind to any available local port)
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;

    // 2. Build the Header (12 bytes total)
    let mut packet = Vec::new();
    
    // ID (2 bytes): Any random number
    packet.extend_from_slice(&0x1234u16.to_be_bytes());
    
    // Flags (2 bytes): Standard query, no recursion (RD=0)
    // Binary: 0000 0000 0000 0000
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    
    // Counts: 1 question, 0 answers, 0 authority, 0 additional
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // 3. Build the Question Section: "google.com"
    // DNS uses length-prefixed labels: [6]google[3]com[0]
    for part in "google.com".split('.') {
        packet.push(part.len() as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0); // Null terminator for the domain name

    // QTYPE (2 bytes): 1 for A record (IPv4)
    packet.extend_from_slice(&1u16.to_be_bytes());
    // QCLASS (2 bytes): 1 for Internet (IN)
    packet.extend_from_slice(&1u16.to_be_bytes());

    // 4. Send to a Root Server (a.root-servers.net: 198.41.0.4)
    let root_ip = "198.41.0.4:53";
    socket.send_to(&packet, root_ip)?;
    println!("Sent query for google.com to {}", root_ip);

    // 5. Receive the response
    let mut buf = [0u8; 512];
    let (size, _) = socket.recv_from(&mut buf)?;

    println!("Received {} bytes of response!", size);
    println!("First few bytes (ID & Flags): {:02x}{:02x} {:02x}{:02x}", 
             buf[0], buf[1], buf[2], buf[3]);

    Ok(())
}


