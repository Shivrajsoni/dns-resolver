## DNS Resolver Roadmap

This file tracks the remaining work for the DNS resolver, from simple learning steps to a more complete recursive resolver.

### Phase 1 – Polish the current basic resolver

1. **Improve CLI UX**
   - [ ] Add a short `--help` message describing usage and current limitations.
   - [ ] Print a clear error when the domain argument is empty or obviously invalid.

2. **Replace `unwrap()` with proper error handling**
   - [ ] Handle socket bind errors with a friendly message.
   - [ ] Handle send/receive errors (e.g., network issues, permission issues).
   - [ ] Propagate parse errors from `parse_ipv4_addrs` with context.

3. **Add a simple debug mode**
   - [ ] Add a `--debug` flag to print internal steps:
     - [ ] Header values (already partially printed).
     - [ ] Offsets before/after `skip_name` and RR parsing.
     - [ ] Each RR’s `TYPE`, `RDLENGTH`, and whether it produced an IPv4 address.

4. **Unit tests for core primitives**
   - [ ] Test `DnsQuestion::to_bytes` for a few domains (e.g., `google.com`, `www.example.org`).
   - [ ] Test `skip_name` with:
     - [ ] A normal name (no compression).
     - [ ] A compressed name (pointer).
   - [ ] Test `parse_ipv4_addrs` on small, hand-crafted buffers that contain exactly one A record.

---

### Phase 2 – Decode and show domain names

5. **Introduce a `read_name` helper (learning-focused)**
   - [ ] Implement `read_name(buf, offset) -> Option<(String, usize)>` that:
     - [ ] Handles regular labels (no compression).
     - [ ] Handles a single compression pointer in a simple, readable way.
   - [ ] Keep the old `skip_name` as a low-level helper; use `read_name` where you want to display names.

6. **Reintroduce an `ARecord` model**
   - [ ] Define `ARecord { name: String, addr: Ipv4Addr }`.
   - [ ] Implement `parse_a_records` that:
     - [ ] Uses `read_name` to decode the RR owner name.
     - [ ] Collects `(name, addr)` pairs for A records.
   - [ ] Update `main.rs` to print `name -> ip` instead of only IPs when using this parser.

7. **Enhance debug output with names**
   - [ ] In debug mode, print each RR as:
     - [ ] `NAME TYPE CLASS TTL RDLENGTH` (with decoded `NAME` where possible).
   - [ ] Clearly show when a name could not be fully decoded (e.g., due to complex compression).

---

### Phase 3 – Follow NS referrals (towards a recursive resolver)

8. **Parse more RR types**
   - [ ] Add minimal models for:
     - [ ] `NS` records (nameserver).
     - [ ] `CNAME` records (canonical name).
   - [ ] Extend the parser to:
     - [ ] Collect NS records from the **authority** section.
     - [ ] Collect A records (glue) for those NS names from the **additional** section.

9. **Implement a `resolve_once(domain, server_ip)` helper**
   - [ ] Input: a domain and a DNS server IP.
   - [ ] Behavior:
     - [ ] Build and send a query to `server_ip`.
     - [ ] Parse header and all sections.
     - [ ] Return a structured result containing:
       - [ ] Any A answers for the original domain.
       - [ ] Any NS referrals (with their glue A records if present).
       - [ ] Relevant status (NOERROR, NXDOMAIN, etc.).

10. **Implement a simple recursive `resolve(domain)`**
    - [ ] Start from a root server IP.
    - [ ] Loop:
      - [ ] Call `resolve_once(domain, current_server_ip)`.
      - [ ] If you get final A records for `domain`, return them.
      - [ ] Else, pick one referred NS IP and continue with that server.
      - [ ] Stop if:
        - [ ] You hit NXDOMAIN or another terminal error.
        - [ ] You exceed a maximum recursion depth/hop count.

---

### Phase 4 – Caching and robustness

11. **In-memory cache**
    - [ ] Use the `Cache` struct to store:
      - [ ] `domain -> list of (Ipv4Addr, expiry_time)` based on TTL.
    - [ ] On each `resolve(domain)`:
      - [ ] Check the cache first and filter out expired entries.
      - [ ] Only query the network when the cache miss/expired.

12. **Timeouts and retry strategy**
    - [ ] Use Tokio or standard timeouts for UDP `recv`.
    - [ ] Retry with another nameserver when one doesn’t respond.
    - [ ] Define reasonable global limits (max retries, max total time).

13. **Better error types**
    - [ ] Create a custom `Error` enum for the resolver:
      - [ ] Network errors.
      - [ ] Parse errors.
      - [ ] NXDOMAIN / SERVFAIL / timeouts.
    - [ ] Make `resolve(domain)` return `Result<Vec<Ipv4Addr>, Error>`.

---

### Phase 5 – Library and nicer CLI

14. **Refactor into library + binary**
    - [ ] Move reusable logic into `src/lib.rs`:
      - [ ] Public functions like `resolve(domain: &str) -> Result<Vec<Ipv4Addr>, Error>`.
    - [ ] Keep `src/main.rs` as a small CLI that:
      - [ ] Parses args.
      - [ ] Calls into the library.
      - [ ] Formats and prints results.

15. **CLI improvements**
    - [ ] Support flags:
      - [ ] `--type A|AAAA` (query record type).
      - [ ] `--server <ip>` (use a specific upstream DNS server).
      - [ ] `--debug` for detailed tracing.
    - [ ] Optional JSON output mode for scripting.

16. **Documentation and examples**
    - [ ] Keep `README.md` in sync with new features.
    - [ ] Add example commands and sample outputs for common domains.
    - [ ] Document high-level architecture (how the resolver walks root → TLD → authoritative).
