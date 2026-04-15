# DNS Resolver - A Custom DNS Query Implementation in Rust

This is a minimal DNS resolver implemented in Rust that sends DNS queries to a recursive DNS server and parses the response to extract IP addresses.

## Table of Contents

1. [How It Works](#how-it-works)
2. [DNS Packet Structure](#dns-packet-structure)
3. [Component Breakdown](#component-breakdown)
4. [DNS Name Encoding](#dns-name-encoding)
5. [Name Compression](#name-compression)
6. [Code Flow](#code-flow)
7. [Usage](#usage)
8. [Record Types](#record-types)
9. [Response Codes](#response-codes)

---

## How It Works

The DNS resolver follows this basic flow:

```
┌─────────────┐      UDP Query       ┌─────────────┐
│   Client    │ ───────────────────► │  DNS Server │
│ (This App)  │    port 53           │  (8.8.8.8)  │
└─────────────┘                      └─────────────┘
       │                                   │
       │      UDP Response                 │
       │ ◄───────────────────────────────── │
       │                                   │
       ▼                                   ▼
┌─────────────┐                      ┌─────────────┐
│ Parse IP    │                      │ Return IP   │
│ Addresses   │                      │ for domain  │
└─────────────┘                      └─────────────┘
```

1. Takes a domain name as command-line argument
2. Encodes the domain name in DNS label format
3. Builds a DNS query packet with proper header and question
4. Sends the query to Google's public DNS server (8.8.8.8:53)
5. Receives the response and parses it to extract IP addresses

---

## DNS Packet Structure

A DNS packet is divided into 5 main sections:

```
┌─────────────────┬──────────────────────┬───────────────────┐
│    Header       │     Question         │      Answer       │
│   (12 bytes)   │    (variable)        │    (variable)     │
├─────────────────┼──────────────────────┼───────────────────┤
│                 │                      │                   │
│  ID             │  QNAME               │  NAME             │
│  Flags          │  QTYPE               │  TYPE             │
│  QDCOUNT        │  QCLASS              │  CLASS            │
│  ANCOUNT        │                      │  TTL              │
│  NSCOUNT        │                      │  RDLENGTH         │
│  ARCOUNT        │                      │  RDATA            │
│                 │                      │                   │
└─────────────────┴──────────────────────┴───────────────────┘
```

### Byte Layout

```
Byte positions in DNS packet:

Offset 0-1:   ID (transaction identifier)
Offset 2-3:   Flags (16-bit flags field)
Offset 4-5:   QDCOUNT (number of questions)
Offset 6-7:   ANCOUNT (number of answers)
Offset 8-9:   NSCOUNT (number of authority records)
Offset 10-11: ARCOUNT (number of additional records)
Offset 12+:   Questions, Answers, etc.
```

---

## Component Breakdown

### DnsHeader (12 bytes total - 2 bytes each field)

The header contains metadata about the DNS packet.

```rust
pub struct DnsHeader {
    id: u16,         // Transaction ID - matches query with response
    flags: DnsFlags, // 16-bit flags field
    qd_count: u16,  // Number of questions (usually 1)
    an_count: u16,   // Number of answers (0 in query)
    ns_count: u16,   // Number of authority records
    ar_count: u16,   // Number of additional records
}
```

**Fields:**

| Field | Size | Description |
|-------|------|-------------|
| `id` | 2 bytes | Random transaction ID. Used to match responses to queries. |
| `flags` | 2 bytes | Contains multiple flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE) |
| `qd_count` | 2 bytes | Number of questions in the packet |
| `an_count` | 2 bytes | Number of answers (0 in query, >0 in response) |
| `ns_count` | 2 bytes | Number of authority (NS) records |
| `ar_count` | 2 bytes | Number of additional records |

---

### DnsFlags (16 bits - 2 bytes)

The flags field contains 8 different flags packed into 16 bits:

```
Bit:    15  14 13 12  11  10   9   8   7   6   5   4   3   2   1   0
        ┌───┬──────┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
        │ QR│ Opcode│ AA│ TC│ RD│ RA│ Z │ RCODE                      │
        └───┴──────┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
```

```rust
pub struct DnsFlags {
    pub query_response: bool,    // Bit 15: 0=Query, 1=Response
    pub opcode: u8,               // Bits 11-14: Query type (0=standard)
    pub authorative: bool,        // Bit 10: Authoritative answer
    pub truncated: bool,          // Bit 9: Message truncated
    pub recursion_desired: bool,  // Bit 8: Request recursive resolution
    pub recursion_available: bool,// Bit 7: Server supports recursion
    pub z: u8,                    // Bits 4-6: Reserved (must be 0)
    pub response_code: u8,        // Bits 0-3: Response code
}
```

**Flag Details:**

| Bit | Name | Description |
|-----|------|-------------|
| 15 | QR | Query (0) or Response (1) |
| 11-14 | Opcode | Operation code: 0=Standard, 1=Inverse, 2=Status |
| 10 | AA | Authoritative Answer - only valid in responses |
| 9 | TC | Truncated - set if packet exceeds 512 bytes |
| 8 | RD | Recursion Desired - set to 1 to request server to do recursive lookup |
| 7 | RA | Recursion Available - set by server in responses |
| 4-6 | Z | Reserved for future use - must be 0 |
| 0-3 | RCODE | Response code: 0=No error, 1=Format error, 2=Server failure, 3=NXDOMAIN |

**Flag to u16 Conversion:**

```rust
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
}
```

---

### DnsQuestion (variable length)

A question describes what we're asking the DNS server.

```rust
pub struct DnsQuestion {
    qname: Vec<u8>,  // Domain name in DNS label format
    qtype: u16,      // Record type (1=A, 28=AAAA, etc.)
    qclass: u16,     // Class (1=IN for Internet)
}
```

**Fields:**

| Field | Size | Description |
|-------|------|-------------|
| `qname` | Variable | Domain name encoded in DNS format |
| `qtype` | 2 bytes | Type of DNS record being queried |
| `qclass` | 2 bytes | Class (almost always 1 = IN) |

**Serialization:**

```rust
impl DnsQuestion {
    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.qname);  // DNS-encoded name
        bytes.extend_from_slice(&self.qtype.to_be_bytes());
        bytes.extend_from_slice(&self.qclass.to_be_bytes());
        bytes
    }
}
```

---

### DnsAnswer (variable length)

An answer contains the actual DNS data returned by the server.

```rust
pub struct DnsAnswer {
    pub name: Vec<u8>,        // Name pointer or labels
    pub record_type: u16,     // Type of record (1=A, 2=NS, etc.)
    pub class: u16,           // Class (1=IN)
    pub ttl: u32,             // Time to live (seconds)
    pub rdlength: u16,        // Length of rdata
    pub rdata: Vec<u8>,       // Actual data (IP address for A records)
}
```

**Fields:**

| Field | Size | Description |
|-------|------|-------------|
| `name` | Variable | Pointer to domain name or inline labels |
| `record_type` | 2 bytes | Type of record (1=A, 5=CNAME, etc.) |
| `class` | 2 bytes | Class (1=IN for Internet) |
| `ttl` | 4 bytes | Time-to-live - how long the record can be cached |
| `rdlength` | 2 bytes | Length of the rdata field |
| `rdata` | Variable | The actual data (4 bytes for IPv4, 16 for IPv6) |

**For A records (IPv4):**
- `record_type` = 1
- `rdlength` = 4
- `rdata` = 4 bytes representing IPv4 address

---

## DNS Name Encoding

DNS uses a special format for domain names called **DNS labels**:

### Format: `[length][label][length][label]...[0]`

Each label consists of:
- 1 byte: length of the label (0-63)
- N bytes: the label text
- Terminal 0 byte: ends the name

### Example: `google.com`

```
Original: google.com
Encoding:
┌─────┬─────┬─────┬─────┬─────┬─────┬─────┐
│  6  │ g o o g l e │  3  │ c o m │  0  │
└─────┴─────┴─────┴─────┴─────┴─────┴─────┘
 06 67 6f 6f 67 6c 65 03 63 6f 6d 00
```

### Rust Implementation:

```rust
let mut name = Vec::new();
for part in domain.split('.') {
    name.push(part.len() as u8);           // Add length byte
    name.extend_from_slice(part.as_bytes()); // Add label bytes
}
name.push(0);                              // Add null terminator
```

---

## Name Compression

To reduce packet size, DNS uses **pointers** to reference previously seen names.

### Pointer Format

A pointer is 2 bytes where:
- First 2 bits are `11` (binary: 11000000 = 0xC0)
- Remaining 14 bits indicate offset from start of packet

```
┌──────────┬─────────────────────┐
│ 11000000 │   Offset (14 bits)  │
└──────────┴─────────────────────┘
     0xC0     offset from byte 0
```

### How It Works

If the domain name `google.com` appears at offset 12 in the packet:
- Any subsequent reference uses pointer: `0xC00C` (0xC0 << 8 | 0x0C)

### Parsing with Compression

```rust
let name_ptr = u16::from_be_bytes([buf[offset], buf[offset + 1]]);

// Check if it's a pointer (top 2 bits are 11)
if (name_ptr & 0xC000) == 0xC000 {
    offset += 2;  // Just skip the pointer
} else {
    // It's a regular name, parse label by label
    while offset < size && buf[offset] != 0 {
        offset += 1 + buf[offset] as usize;
    }
    offset += 1;
}
```

---

## Code Flow

### Step 1: Parse CLI Arguments

```rust
let args: Vec<String> = env::args().collect();
if args.len() < 2 {
    eprintln!("Usage: dns_resolver <domain>");
    return Ok(());
}
let domain = &args[1];
```

### Step 2: Create UDP Socket

```rust
let socket = UdpSocket::bind("0.0.0.0:0")?;
socket.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
```

- Binds to any available local port
- Sets 2-second timeout for receiving response

### Step 3: Build DnsHeader

```rust
let header = DnsHeader {
    id: 0x1234,  // Transaction ID
    flags: DnsFlags {
        recursion_desired: true,  // Request recursive lookup
        ..Default::default()
    },
    qd_count: 1,   // One question
    an_count: 0,   // No answers (this is a query)
    ns_count: 0,
    ar_count: 0,
};
```

### Step 4: Encode Domain Name

```rust
let mut name = Vec::new();
for part in domain.split('.') {
    name.push(part.len() as u8);
    name.extend_from_slice(part.as_bytes());
}
name.push(0);
```

### Step 5: Create DnsQuestion

```rust
let question = DnsQuestion {
    qname: name,
    qtype: 1,   // 1 = A record (IPv4 address)
    qclass: 1,  // 1 = IN (Internet class)
};
```

### Step 6: Serialize and Send

```rust
let packet = DnsPacket {
    header,
    question: vec![question],
    answer: None,
};

let query_data = packet.serialize();
let dns_server = "8.8.8.8:53";
socket.send_to(&query_data, dns_server)?;
```

### Step 7: Receive and Parse Response

```rust
let mut buf = [0u8; 512];
let (size, _) = socket.recv_from(&mut buf)?;

// Extract flags and answer count from header
let flags = u16::from_be_bytes([buf[2], buf[3]]);
let an_count = u16::from_be_bytes([buf[6], buf[7]]);

// Skip past question section to reach answers
let mut offset = 12;
while offset < size && buf[offset] != 0 {
    offset += 1 + buf[offset] as usize;
}
offset += 5;  // Skip null byte + QTYPE + QCLASS

// Parse each answer record
for _ in 0..an_count {
    // Handle name pointer
    // Extract RDATA (IP address)
}
```

---

## Usage

### Basic Usage

```bash
cargo run google.com
```

### Expected Output

```
Sent query for google.com to 8.8.8.8:53
Received 44 bytes of response!
Response code: 0
Answers count: 1
Resolved IP: 142.250.185.46
```

### Test with Different Domains

```bash
cargo run example.com
cargo run github.com
cargo run rust-lang.org
```

---

## Record Types

Common DNS record types (used in QTYPE field):

| Type | Value | Description |
|------|-------|-------------|
| A | 1 | IPv4 Address |
| NS | 2 | Name Server |
| CNAME | 5 | Canonical Name (alias) |
| SOA | 6 | Start of Authority |
| PTR | 12 | Pointer (reverse DNS) |
| MX | 15 | Mail Exchange |
| TXT | 16 | Text Record |
| AAAA | 28 | IPv6 Address |
| SRV | 33 | Service location |

This resolver currently queries for **A records** (type 1) which return IPv4 addresses.

---

## Response Codes

The RCODE field in DNS response indicates success or type of error:

| Code | Name | Description |
|------|------|-------------|
| 0 | NoError | Success - response contains data |
| 1 | FormErr | Format error - server couldn't parse query |
| 2 | ServFail | Server failure - internal error |
| 3 | NXDomain | Non-existent domain - domain doesn't exist |
| 4 | NotImp | Not implemented - server doesn't support query type |
| 5 | Refused | Query refused - server policy prohibits response |

---

## Packet Size Note

The resolver uses a 512-byte buffer, which is the traditional DNS UDP packet limit. If a response exceeds this size:

- The TC (Truncated) flag will be set in the response
- The client should retry over TCP to get the full response

This implementation currently doesn't handle TCP fallback.

---

## Future Improvements

Areas for enhancement:

1. **Caching** - Store resolved IPs with TTL and check cache before querying
2. **Multiple Record Types** - Support AAAA (IPv6), MX, CNAME, etc.
3. **Error Handling** - Retry logic, fallback DNS servers
4. **TCP Support** - Handle truncated responses over TCP
5. **CLI Options** - Configurable DNS server, timeout, record type
6. **Random Query ID** - Security improvement

---

## References

- [RFC 1035](https://tools.ietf.org/html/rfc1035) - Domain Names: Implementation and Specification
- [DNS Packet Format](https://www.ietf.org/rfc/rfc1035.txt) - Official specification
- [DNS Flags](https://www.cloudflare.com/learning/dns/dns-records/) - Overview of DNS record types
