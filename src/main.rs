use std::env;

use crate::cache::resolve;

mod cache;
mod dns;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: dns_resolver <domain> [record_type]");
        return;
    }

    let domain = &args[1];
    let record_type = args.get(2).map(|s| s.as_str()).unwrap_or("A");

    let rtype = match record_type {
        "A" => 1,
        "MX" => 15,
        "CNAME" => 5,
        "AAAA" => 28,
        _ => {
            eprintln!("Unknown record type: {}", record_type);
            return;
        }
    };

    match resolve(domain, rtype) {
        Ok(entry) => {
            println!("{} {} {}", domain, entry.record_type, entry.ip);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
        }
    }
}
