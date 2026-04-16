use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::UdpSocket;

use crate::dns::{build_question, generate_id, DnsFlags, DnsHeader, DnsPacket};

const DNS_SERVER: &str = "8.8.8.8:53";
const CACHE_FILE: &str = "dns_cache.txt";

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub ip: String,
    pub record_type: String,
}

fn cache_path() -> std::path::PathBuf {
    std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(CACHE_FILE)
}

pub fn match_record_type(r_type: u16) -> String {
    match r_type {
        1 => "A".to_string(),
        5 => "CNAME".to_string(),
        15 => "MX".to_string(),
        28 => "AAAA".to_string(),
        _ => "UNKNOWN".to_string(),
    }
}

pub fn load_cache() -> std::io::Result<HashMap<String, CacheEntry>> {
    let path = cache_path();
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let file = File::open(&path)?;
    let reader = BufReader::new(file);

    let mut map = HashMap::new();
    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 3 {
            let rtype = match parts[2] {
                "A" => 1,
                "MX" => 15,
                "CNAME" => 5,
                "AAAA" => 28,
                _ => 0,
            };
            let key = format!("{}:{}", parts[0], rtype);
            map.insert(
                key,
                CacheEntry {
                    ip: parts[1].to_string(),
                    record_type: parts[2].to_string(),
                },
            );
        }
    }
    Ok(map)
}

pub fn write_entry(domain: String, ip: String, record_type: String) -> std::io::Result<()> {
    let path = cache_path();
    let mut file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .append(true)
        .open(&path)?;

    writeln!(file, "{} {} {}", domain, ip, record_type)?;
    Ok(())
}

fn parse_dns_name(buf: &[u8], start: usize, packet_size: usize) -> String {
    let mut result = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut first_label = true;

    while pos < packet_size {
        let label = buf[pos];

        if label == 0 {
            break;
        }

        if label & 0xC0 == 0xC0 {
            if !jumped {
                jumped = true;
            }
            let ptr = ((label as usize & 0x3F) << 8) | (buf[pos + 1] as usize);
            pos = ptr;
        } else {
            if !first_label {
                result.push(b'.');
            }
            result.extend_from_slice(&buf[pos + 1..pos + 1 + label as usize]);
            pos += 1 + label as usize;
            first_label = false;
        }
    }

    String::from_utf8_lossy(&result).trim().to_string()
}

pub fn resolve(domain: &str, record_type: u16) -> std::io::Result<CacheEntry> {
    let cache = load_cache()?;

    let key = format!("{}:{}", domain, record_type);
    if let Some(entry) = cache.get(&key) {
        println!("Cache hit");
        return Ok(entry.clone());
    }

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;

    let header = DnsHeader {
        id: generate_id(),
        flags: DnsFlags {
            recursion_desired: true,
            ..Default::default()
        },
        qd_count: 1,
        an_count: 0,
        ns_count: 0,
        ar_count: 0,
    };

    let question = build_question(domain, record_type);

    let packet = DnsPacket {
        header,
        question: vec![question],
    };

    let query_data = packet.serialize();

    socket.send_to(&query_data, DNS_SERVER)?;

    let mut buf = [0u8; 512];
    let (size, _) = socket.recv_from(&mut buf)?;

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let dns_flags = DnsFlags::from_u16(flags);

    if dns_flags.response_code != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("DNS error: {}", dns_flags.response_code),
        ));
    }

    let an_count = u16::from_be_bytes([buf[6], buf[7]]);
    let qd_count = u16::from_be_bytes([buf[4], buf[5]]);
    let mut offset = 12;

    for _ in 0..qd_count {
        while offset < size && buf[offset] != 0 {
            offset += 1 + buf[offset] as usize;
        }
        offset += 5;
    }

    let mut resolved_entry: Option<CacheEntry> = None;

    if an_count > 0 && offset + 10 <= size {
        for _ in 0..an_count {
            let name_ptr = u16::from_be_bytes([buf[offset], buf[offset + 1]]);

            if name_ptr & 0xC000 == 0xC000 {
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

            let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let record_type_str = match_record_type(rtype);

            offset += 8;

            let rdlength = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            offset += 2;

            let ip = if rtype == 1 && rdlength == 4 && offset + 4 <= size {
                format!(
                    "{}.{}.{}.{}",
                    buf[offset],
                    buf[offset + 1],
                    buf[offset + 2],
                    buf[offset + 3]
                )
            } else if rtype == 15 && rdlength >= 2 {
                let priority = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
                let mx_name = parse_dns_name(&buf, offset + 2, size);
                format!("{} {}", priority, mx_name)
            } else if rtype == 5 {
                let cname = parse_dns_name(&buf, offset, size);
                cname
            } else if rtype == 28 && rdlength == 16 && offset + 16 <= size {
                format!(
                    "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                    buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3],
                    buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7],
                    buf[offset + 8], buf[offset + 9], buf[offset + 10], buf[offset + 11],
                    buf[offset + 12], buf[offset + 13], buf[offset + 14], buf[offset + 15]
                )
            } else {
                offset += rdlength as usize;
                continue;
            };

            resolved_entry = Some(CacheEntry {
                ip,
                record_type: record_type_str,
            });

            offset += rdlength as usize;
        }
    }

    let entry = resolved_entry
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "No record found"))?;

    write_entry(
        domain.to_string(),
        entry.ip.clone(),
        entry.record_type.clone(),
    )?;

    Ok(entry)
}
