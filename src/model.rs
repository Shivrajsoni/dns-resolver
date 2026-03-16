pub struct DnsHeader {
    pub id : u16,
    pub flags: u16,
    pub num_questions: u16,
    pub num_answers: u16,
    pub num_authorities: u16,
    pub num_additionals: u16
}
impl DnsHeader {
   pub fn to_bytes(&self)->Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.num_questions.to_be_bytes());
        bytes.extend_from_slice(&self.num_answers.to_be_bytes());
        bytes.extend_from_slice(&self.num_authorities.to_be_bytes());
        bytes.extend_from_slice(&self.num_additionals.to_be_bytes());
        bytes
    }
}

pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16
}

impl DnsQuestion {
    pub fn to_bytes(&self)-> Vec<u8> {
        let mut bytes = Vec::new();
        // for google.com we need to store as -> \x06google\x03com\x00)

        for part in self.name.split("."){
            bytes.push(part.len() as u8);
            bytes.extend_from_slice(part.as_bytes());
        }
        bytes.push(0); // terminating the domain name with null byte 
        bytes.extend_from_slice(&self.qtype.to_be_bytes());
        bytes.extend_from_slice(&self.qclass.to_be_bytes());
        bytes
    }
}
