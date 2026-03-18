type Result<T> = std::result::Result<T, String>;

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    /// This gives us a fresh buffer for holding the packet contents, and a
    /// field for keeping track of where we are.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Current position within buffer
    fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position forward a specific number of steps
    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }

    /// Change the buffer position
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    /// Read a single byte and move the position one step forward
    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;
        Ok(res)
    }

    /// Get a single byte, without changing the buffer position
    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    /// Read two bytes, stepping two steps forward
    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    /// Read four bytes, stepping four steps forward
    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut pos = self.pos();

        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        let mut delim = "";
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            // At this point, we're always at the beginning of a label. Recall
            // that labels start with a length byte.
            let len = self.get(pos)?;

            // If len has the two most significant bit are set, it represents a
            // jump to some other offset in the packet:
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current
                // label. We don't need to touch it any further.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // The base scenario, where we're reading a single label and
            // appending it to the output:
            else {
                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0,
                // so if the length is zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them
                // to the output buffer.
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

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

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        Ok(())
    }

    /// Serialize the DNS header into the first 12 bytes of a DNS message.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&self.id.to_be_bytes());

        // Build the 16-bit flags field byte-by-byte using the same bit layout
        // that `read()` decodes.
        let mut a: u8 = 0; // high byte of flags
        let mut b: u8 = 0; // low byte of flags

        if self.recursion_desired {
            a |= 1 << 0;
        }
        if self.truncated_message {
            a |= 1 << 1;
        }
        if self.authoritative_answer {
            a |= 1 << 2;
        }
        a |= (self.opcode as u8 & 0x0F) << 3;
        if self.response {
            a |= 1 << 7;
        }

        b |= self.rescode as u8 & 0x0F;
        if self.checking_disabled {
            b |= 1 << 4;
        }
        if self.authed_data {
            b |= 1 << 5;
        }
        if self.z {
            b |= 1 << 6;
        }
        if self.recursion_available {
            b |= 1 << 7;
        }

        let flags = u16::from_be_bytes([a, b]);
        bytes.extend_from_slice(&flags.to_be_bytes());

        bytes.extend_from_slice(&self.questions.to_be_bytes());
        bytes.extend_from_slice(&self.answers.to_be_bytes());
        bytes.extend_from_slice(&self.authoritative_entries.to_be_bytes());
        bytes.extend_from_slice(&self.resource_entries.to_be_bytes());
        bytes
    }

    /// Parse a DNS header from the first 12 bytes of a DNS message.
    /// Returns `(header, offset_after_header)`.
    pub fn from_bytes(buf: &[u8]) -> Option<(DnsHeader, usize)> {
        if buf.len() < 12 {
            return None;
        }
        let mut packet = BytePacketBuffer::new();
        let len = buf.len().min(512);
        packet.buf[..len].copy_from_slice(&buf[..len]);
        packet.pos = 0;

        let mut header = DnsHeader::new();
        header.read(&mut packet).ok()?;
        Some((header, 12))
    }
}

// Dns Name + qtype (2bytes)+ qclass(2 bytes)
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsQuestion {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // for google.com we need to store as -> \x06google\x03com\x00)

        for part in self.name.split(".") {
            bytes.push(part.len() as u8);
            bytes.extend_from_slice(part.as_bytes());
        }
        bytes.push(0); // terminating the domain name with null byte 
        bytes.extend_from_slice(&self.qtype.to_be_bytes());
        bytes.extend_from_slice(&self.qclass.to_be_bytes());
        bytes
    }

    /// Skip over a question in a DNS response buffer.
    /// Returns the new offset after the question, or None on error.
    pub fn skip_in_response(buf: &[u8], mut offset: usize) -> Option<usize> {
        offset = skip_name(buf, offset)?;

        // Skip QTYPE (2 bytes) and QCLASS (2 bytes)
        if offset + 4 > buf.len() {
            return None;
        }

        Some(offset + 4)
    }
}

fn skip_name(buf: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        if offset >= buf.len() {
            return None;
        }
        let len = buf[offset];

        // Compression pointer (two bytes)
        if len & 0b1100_0000 == 0b1100_0000 {
            if offset + 1 >= buf.len() {
                return None;
            }
            return Some(offset + 2);
        }

        // End of name
        if len == 0 {
            return Some(offset + 1);
        }

        // Normal label
        let label_len = len as usize;
        offset += 1;
        if offset + label_len > buf.len() {
            return None;
        }
        offset += label_len;
    }
}

/// Parse all IPv4 addresses from A records (answer + authority + additional).
///
/// This intentionally ignores record owner names to keep learning simple.
pub fn parse_ipv4_addrs(buf: &[u8]) -> Option<(DnsHeader, Vec<std::net::Ipv4Addr>)> {
    let (header, mut offset) = DnsHeader::from_bytes(buf)?;

    // Skip questions
    for _ in 0..header.questions {
        offset = DnsQuestion::skip_in_response(buf, offset)?;
    }

    let total_rrs = header.answers as usize
        + header.authoritative_entries as usize
        + header.resource_entries as usize;

    let mut addrs = Vec::new();

    for _ in 0..total_rrs {
        offset = skip_name(buf, offset)?;

        if offset + 10 > buf.len() {
            return None;
        }

        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let _class = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let _ttl = u32::from_be_bytes([
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > buf.len() {
            return None;
        }

        if rtype == 1 && rdlength == 4 {
            let addr = std::net::Ipv4Addr::new(
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            );
            addrs.push(addr);
        }

        offset += rdlength;
    }

    Some((header, addrs))
}
