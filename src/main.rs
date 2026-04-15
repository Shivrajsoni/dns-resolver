use std::env;
use std::net::UdpSocket;

#[derive(Debug)]
pub struct DnsPacket {
    header: DnsHeader,
    question: Vec<DnsQuestion>,
    answer: Option<DnsAnswer>,
}

impl DnsPacket {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.header.serialize());

        for question in &self.question {
            bytes.extend_from_slice(&question.serialize());
        }

        bytes
    }
}

#[derive(Debug)]
pub struct DnsHeader {
    id: u16,
    flags: DnsFlags,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

impl DnsHeader {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_u16().to_be_bytes());
        bytes.extend_from_slice(&self.qd_count.to_be_bytes());
        bytes.extend_from_slice(&self.an_count.to_be_bytes());
        bytes.extend_from_slice(&self.ns_count.to_be_bytes());
        bytes.extend_from_slice(&self.ar_count.to_be_bytes());
        bytes
    }
}

#[derive(Debug)]
pub struct DnsQuestion {
    qname: Vec<u8>,
    qtype: u16,
    qclass: u16,
}

impl DnsQuestion {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.qname);
        bytes.extend_from_slice(&self.qtype.to_be_bytes());
        bytes.extend_from_slice(&self.qclass.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Default)]
pub struct DnsFlags {
    pub query_response: bool,
    pub opcode: u8,
    pub authorative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub z: u8,
    pub response_code: u8,
}

impl DnsFlags {
    pub fn to_u16(&self) -> u16 {
        let mut res = 0u16;
        res |= (self.query_response as u16) << 15;
        res |= (self.opcode as u16) << 11;
        res |= (self.authorative as u16) << 10;
        res |= (self.truncated as u16) << 9;
        res |= (self.recursion_desired as u16) << 8;
        res |= (self.recursion_available as u16) << 7;
        res |= ((self.z & 0x07) as u16) << 4;
        res |= (self.response_code & 0x0F) as u16;
        res
    }

    pub fn from_u16(bits: u16) -> Self {
        Self {
            query_response: (bits >> 15) & 1 == 1,
            opcode: ((bits >> 11) & 0x0F) as u8,
            authorative: (bits >> 10) & 1 == 1,
            truncated: (bits >> 9) & 1 == 1,
            recursion_desired: (bits >> 8) & 1 == 1,
            recursion_available: (bits >> 7) & 1 == 1,
            z: ((bits >> 4) & 0x07) as u8,
            response_code: (bits & 0x0F) as u8,
        }
    }
}

#[derive(Debug)]
pub struct DnsAnswer {
    pub name: Vec<u8>,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: Vec<u8>,
}

impl DnsAnswer {
    fn deserialize(bytes: &[u8]) -> Option<(Self, usize)> {
        let mut offset = 0;
        let name = Vec::new();
        offset += 2;

        if bytes.len() < offset + 10 {
            return None;
        }

        let record_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        offset += 2;

        let class = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        offset += 2;

        let ttl = u32::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;

        let rdlength = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        offset += 2;

        if bytes.len() < offset + rdlength as usize {
            return None;
        }

        let rdata = bytes[offset..offset + rdlength as usize].to_vec();
        offset += rdlength as usize;

        Some((
            Self {
                name,
                record_type,
                class,
                ttl,
                rdlength,
                rdata,
            },
            offset,
        ))
    }
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: dns_resolver <domain>");
        return Ok(());
    }

    let domain = &args[1];

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;

    let header = DnsHeader {
        id: 0x1234,
        flags: DnsFlags {
            recursion_desired: true,
            ..Default::default()
        },
        qd_count: 1,
        an_count: 0,
        ns_count: 0,
        ar_count: 0,
    };

    let mut name = Vec::new();
    for part in domain.split('.') {
        name.push(part.len() as u8);
        name.extend_from_slice(part.as_bytes());
    }
    name.push(0);

    let question = DnsQuestion {
        qname: name,
        qtype: 1,
        qclass: 1,
    };

    let packet = DnsPacket {
        header,
        question: vec![question],
        answer: None,
    };

    let query_data = packet.serialize();

    let dns_server = "8.8.8.8:53";
    socket.send_to(&query_data, dns_server)?;
    println!("Sent query for {} to {}", domain, dns_server);

    let mut buf = [0u8; 512];
    let (size, _) = socket.recv_from(&mut buf)?;

    println!("Received {} bytes of response!", size);

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let dns_flags = DnsFlags::from_u16(flags);
    println!("Response code: {}", dns_flags.response_code);

    let an_count = u16::from_be_bytes([buf[6], buf[7]]);
    println!("Answers count: {}", an_count);

    let mut offset = 12;

    while offset < size && buf[offset] != 0 {
        offset += 1 + buf[offset] as usize;
    }
    offset += 5;

    if an_count > 0 && offset + 10 <= size {
        for _ in 0..an_count {
            let name_ptr = u16::from_be_bytes([buf[offset], buf[offset + 1]]);

            if (name_ptr & 0xC000) == 0xC000 {
                offset += 2;
            } else {
                while offset < size && buf[offset] != 0 {
                    offset += 1 + buf[offset] as usize;
                }
                offset += 1;
            }

            if offset + 10 > size {
                break;
            }

            offset += 8;
            let rdlength = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            offset += 2;

            if rdlength == 4 && offset + 4 <= size {
                let ip = format!(
                    "{}.{}.{}.{}",
                    buf[offset],
                    buf[offset + 1],
                    buf[offset + 2],
                    buf[offset + 3]
                );
                println!("Resolved IP: {}", ip);
            }
            offset += rdlength as usize;
        }
    }

    Ok(())
}
