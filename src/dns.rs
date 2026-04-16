use rand::Rng;

#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub question: Vec<DnsQuestion>,
}

impl DnsPacket {
    pub fn serialize(&self) -> Vec<u8> {
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
    pub id: u16,
    pub flags: DnsFlags,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
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
    pub qname: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsQuestion {
    pub fn serialize(&self) -> Vec<u8> {
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

pub fn generate_id() -> u16 {
    let mut rng = rand::thread_rng();
    rng.r#gen::<u16>()
}

pub fn build_question(domain: &str, record_type: u16) -> DnsQuestion {
    let mut name = Vec::new();
    for part in domain.split('.') {
        name.push(part.len() as u8);
        name.extend_from_slice(part.as_bytes());
    }
    name.push(0);

    DnsQuestion {
        qname: name,
        qtype: record_type,
        qclass: 1,
    }
}
