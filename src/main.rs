use std::io::Write as _;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

// ============================================================
// CONFIGURATION — edit these to suit your needs
// ============================================================

/// How long to sleep between full scan rounds (seconds).
const POLL_INTERVAL_SECS: u64 = 5;

/// Print a heartbeat dot every N rounds so you know the process is alive.
const HEARTBEAT_EVERY_N_ROUNDS: u32 = 12; // ~1 minute at 5 s interval

/// Set to false to disable ICMP ping checks against TARGET_IPS.
const ICMP_CHECK_ENABLED: bool = true;

/// IPs to watch. If ANY of them responds to a ping, notification is triggered.
const ICMP_TARGETS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220"
];

/// Set to false to disable the DNS check entirely.
const DNS_CHECK_ENABLED: bool = true;

/// Domains to resolve for DNS connectivity check. All probes run in parallel;
/// the first to return a valid A-record response triggers the alert.
const DNS_TARGETS: &[&str] = &[
    "example.com",
    "google.com",
    "cloudflare.com",
    "github.com",
    "microsoft.com",
];

/// Set to false to disable all HTTP probes.
const HTTP_CHECK_ENABLED: bool = true;

/// HTTP probe table: (host, path, expected_http_status, required_body_substring).
/// An empty body string means only the status code is checked.
/// All probes run in parallel; the first to succeed triggers the alert.
const HTTP_TARGETS: &[(&str, &str, u16, &str)] = &[
    ("www.msftconnecttest.com",        "/connecttest.txt",      200, "Microsoft Connect Test"),
    ("www.msftncsi.com",               "/ncsi.txt",             200, "Microsoft NCSI"),
    ("clients3.google.com",            "/generate_204",         204, ""),
    ("connectivitycheck.gstatic.com",  "/generate_204",         204, ""),
    ("detectportal.firefox.com",       "/success.txt",          200, "success"),
    ("captive.apple.com",              "/hotspot-detect.html",  200, "Success"),
    ("connectivity-check.ubuntu.com",  "/",                     204, ""),
];

/// Set to false to disable all HTTPS probes.
const HTTPS_CHECK_ENABLED: bool = true;

/// HTTPS probe table: (host, path, expected_http_status, required_body_substring).
/// Each probe performs a full TLS handshake with certificate chain validation —
/// a MITM proxy returning a self-signed certificate will cause the probe to fail.
/// All probes run in parallel; the first to succeed triggers the alert.
const HTTPS_TARGETS: &[(&str, &str, u16, &str)] = &[
    ("clients3.google.com",           "/generate_204",  204, ""),
    ("connectivitycheck.gstatic.com", "/generate_204",  204, ""),
    ("detectportal.firefox.com",      "/success.txt",   200, "success"),
    ("www.cloudflare.com",            "/cdn-cgi/trace", 200, ""),
    ("one.one.one.one",               "/cdn-cgi/trace", 200, ""),
    ("github.com",                    "/",              200, ""),
    ("www.google.com",                "/generate_204",  204, ""),
];

/// Set to false to disable all IPv6 checks.
const IPV6_CHECK_ENABLED: bool = true;

/// IPv6 resolver addresses to probe. Any successful probe on any address = connected.
const IPV6_TARGETS: &[&str] = &[
    "2606:4700:4700::1111", // Cloudflare
    "2606:4700:4700::1001", // Cloudflare
    "2001:4860:4860::8888", // Google Public DNS
    "2001:4860:4860::8844", // Google Public DNS
    "2620:fe::fe",          // Quad9
    "2620:fe::9",           // Quad9
    "2620:119:35::35",      // Cisco Umbrella
    "2620:119:53::53",      // Cisco Umbrella
];

/// Set to false to disable writing detection events to disk.
const LOG_ENABLED: bool = true;

/// Path of the append-only detection log. The file is created if it does not exist.
/// Adjust for your deployment (e.g. "/var/log/netkiller.log" when running as root).
const LOG_FILE_PATH: &str = "netkiller.log";

// ============================================================

fn main() {
    if std::env::args().any(|a| a == "--test" || a == "-t") {
        run_tests(); // never returns
    }

    if ICMP_CHECK_ENABLED && ICMP_TARGETS.is_empty() {
        eprintln!("[!] ICMP_CHECK_ENABLED is true but TARGET_IPS is empty.");
        std::process::exit(1);
    }
    if DNS_CHECK_ENABLED && DNS_TARGETS.is_empty() {
        eprintln!("[!] Warning: DNS_CHECK_ENABLED is true but DNS_TARGETS is empty.");
        std::process::exit(1);
    }
    if HTTP_CHECK_ENABLED && HTTP_TARGETS.is_empty() {
        eprintln!("[!] Warning: HTTP_CHECK_ENABLED is true but HTTP_TARGETS is empty.");
        std::process::exit(1);
    }
    if HTTPS_CHECK_ENABLED && HTTPS_TARGETS.is_empty() {
        eprintln!("[!] Warning: HTTPS_CHECK_ENABLED is true but HTTPS_TARGETS is empty.");
        std::process::exit(1);
    }
    if IPV6_CHECK_ENABLED && IPV6_TARGETS.is_empty() {
        eprintln!("[!] Warning: IPV6_CHECK_ENABLED is true but IPV6_TARGETS is empty.");
        std::process::exit(1);
    }

    println!("=== NetKiller started ===");
    println!("Running checks every {} seconds", POLL_INTERVAL_SECS);
    if ICMP_CHECK_ENABLED {
        println!("ICMP check enabled — monitoring {} IP(s)", ICMP_TARGETS.len());
    }
    if DNS_CHECK_ENABLED {
        println!("DNS check enabled ({} targets).", DNS_TARGETS.len());
    }
    if HTTP_CHECK_ENABLED {
        println!("HTTP check enabled ({} targets).", HTTP_TARGETS.len());
    }
    if HTTPS_CHECK_ENABLED {
        println!("HTTPS check enabled ({} targets).", HTTPS_TARGETS.len());
    }
    if IPV6_CHECK_ENABLED {
        println!("IPv6 check enabled ({} targets).", IPV6_TARGETS.len());
    }
    println!("Alert will trigger on first positive detection.");
    if LOG_ENABLED {
        println!("Detection events logged to: {}", LOG_FILE_PATH);
    }
    println!();

    let mut round: u32 = 0;

    loop {
        if ICMP_CHECK_ENABLED {
            if let Some(ip) = icmp_check() {
                trigger_alert(&format!("ICMP: host {} responded — connectivity detected!", ip));
            }
        }

        if DNS_CHECK_ENABLED {
            if let Some(host) = dns_check() {
                trigger_alert(&format!("DNS: resolved {} — connectivity detected!", host));
            }
        }

        if HTTP_CHECK_ENABLED {
            if let Some(host) = http_check() {
                trigger_alert(&format!("HTTP: hit {} — connectivity detected!", host));
            }
        }

        if HTTPS_CHECK_ENABLED {
            if let Some(host) = https_check() {
                trigger_alert(&format!("HTTPS: verified cert on {} — connectivity detected!", host));
            }
        }

        if IPV6_CHECK_ENABLED {
            if let Some(addr) = ipv6_check() {
                trigger_alert(&format!("IPv6: probe succeeded on {} — connectivity detected!", addr));
            }
        }

        round = round.wrapping_add(1);
        if round % HEARTBEAT_EVERY_N_ROUNDS == 0 {
            print!(".");
            let _ = std::io::stdout().flush();
        }

        thread::sleep(Duration::from_secs(POLL_INTERVAL_SECS));
    }
}

// ── ICMP ─────────────────────────────────────────────────────────────────────

/// Probes all `TARGET_IPS` entries with an ICMP echo in parallel.
/// Returns the first IP that responds, or `None` if all are silent.
fn icmp_check() -> Option<&'static str> {
    let (tx, rx) = mpsc::channel();

    for (i, &ip) in ICMP_TARGETS.iter().enumerate() {
        let tx = tx.clone();
        let id = (i as u16) + 1;
        thread::spawn(move || {
            let _ = tx.send(if icmp_ping(ip, id) { Some(ip) } else { None });
        });
    }
    drop(tx);

    while let Ok(result) = rx.recv_timeout(Duration::from_secs(2)) {
        if result.is_some() {
            return result;
        }
    }
    None
}

/// Compute the RFC 792 one's-complement checksum over `data`.
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += (u32::from(data[i]) << 8) | u32::from(data[i + 1]);
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a 16-byte ICMP echo-request packet (type=8, code=0) with the given id and seq.
fn build_icmp_echo_request(id: u16, seq: u16) -> [u8; 16] {
    let mut pkt = [0u8; 16];
    pkt[0] = 8; // type: echo request
    pkt[1] = 0; // code
    // pkt[2..4] = checksum, filled in below
    pkt[4] = (id >> 8) as u8;
    pkt[5] = (id & 0xff) as u8;
    pkt[6] = (seq >> 8) as u8;
    pkt[7] = (seq & 0xff) as u8;
    // pkt[8..16] = zero payload
    let csum = icmp_checksum(&pkt);
    pkt[2] = (csum >> 8) as u8;
    pkt[3] = (csum & 0xff) as u8;
    pkt
}

#[cfg(unix)]
mod icmp_sys {
    // ── Constants ──────────────────────────────────────────────────────────
    pub const IPPROTO_ICMP: i32 = 1;
    pub const SOCK_DGRAM: i32 = 2;
    pub const SOCK_RAW: i32 = 3;

    #[cfg(target_os = "linux")]
    pub const AF_INET: i32 = 2;
    #[cfg(target_os = "macos")]
    pub const AF_INET: i32 = 2;  // same on macOS

    // ── sockaddr_in ─────────────────────────────────────────────────────────
    // Linux: sin_family is u16; no sin_len field.
    // macOS: sin_len (u8) comes first, then sin_family is u8.
    // Both structs are 16 bytes total.
    #[cfg(target_os = "linux")]
    #[repr(C)]
    pub struct SockAddrIn {
        pub sin_family: u16,
        pub sin_port:   u16,
        pub sin_addr:   u32,  // network byte order
        pub sin_zero:   [u8; 8],
    }
    #[cfg(target_os = "macos")]
    #[repr(C)]
    pub struct SockAddrIn {
        pub sin_len:    u8,
        pub sin_family: u8,
        pub sin_port:   u16,
        pub sin_addr:   u32,  // network byte order
        pub sin_zero:   [u8; 8],
    }

    // setsockopt constants for SO_RCVTIMEO
    #[cfg(target_os = "linux")]
    pub const SOL_SOCKET: i32 = 1;
    #[cfg(target_os = "linux")]
    pub const SO_RCVTIMEO: i32 = 20;

    #[cfg(target_os = "macos")]
    pub const SOL_SOCKET: i32 = 0xffffu32 as i32;
    #[cfg(target_os = "macos")]
    pub const SO_RCVTIMEO: i32 = 0x1006;

    // timeval layout differs: Linux uses two i64s; macOS uses i64 + i32 + 4-byte pad.
    #[cfg(target_os = "linux")]
    #[repr(C)]
    pub struct Timeval {
        pub tv_sec:  i64,
        pub tv_usec: i64,
    }
    #[cfg(target_os = "macos")]
    #[repr(C)]
    pub struct Timeval {
        pub tv_sec:  i64,
        pub tv_usec: i32,
        pub _pad:    i32,
    }

    // ── syscalls ────────────────────────────────────────────────────────────
    unsafe extern "C" {
        pub fn socket(domain: i32, type_: i32, protocol: i32) -> i32;
        pub fn close(fd: i32) -> i32;
        pub fn sendto(
            sockfd: i32,
            buf:    *const u8,
            len:    usize,
            flags:  i32,
            addr:   *const SockAddrIn,
            addrlen: u32,
        ) -> isize;
        pub fn recvfrom(
            sockfd:  i32,
            buf:     *mut u8,
            len:     usize,
            flags:   i32,
            addr:    *mut SockAddrIn,
            addrlen: *mut u32,
        ) -> isize;
        pub fn setsockopt(
            sockfd:  i32,
            level:   i32,
            optname: i32,
            optval:  *const u8,
            optlen:  u32,
        ) -> i32;
    }
}

#[cfg(target_os = "windows")]
mod icmp_sys {
    // IcmpSendEcho from iphlpapi.dll — no admin required, no raw socket needed.
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        pub fn IcmpCreateFile() -> *mut core::ffi::c_void;
        pub fn IcmpCloseHandle(icmp_handle: *mut core::ffi::c_void) -> u32;
        pub fn IcmpSendEcho(
            icmp_handle:         *mut core::ffi::c_void,
            destination_address: u32,   // IPv4 in network byte order
            request_data:        *const u8,
            request_size:        u16,
            request_options:     *const u8, // pass null
            reply_buffer:        *mut u8,
            reply_size:          u32,
            timeout:             u32,       // milliseconds
        ) -> u32;                           // number of replies, 0 = failure
    }
}

/// Returns `true` if the host at `ip` replies to an ICMP echo request within 1 second.
/// `id` must be unique across concurrent probes so each socket can filter out replies
/// that belong to other parallel pings (raw ICMP sockets receive all ICMP traffic).
/// Uses native socket FFI on Unix, IcmpSendEcho on Windows. No OS binaries required.
fn icmp_ping(ip: &str, id: u16) -> bool {
    use std::net::Ipv4Addr;
    let addr: Ipv4Addr = match ip.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    #[cfg(target_os = "windows")]
    return windows_icmp_ping(addr, id);

    #[cfg(unix)]
    return unix_icmp_ping(addr, id);

    #[allow(unreachable_code)]
    false
}

#[cfg(unix)]
fn unix_icmp_ping(addr: std::net::Ipv4Addr, id: u16) -> bool {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(unix_icmp_ping_raw(addr, id));
    });
    rx.recv_timeout(Duration::from_secs(2)).unwrap_or(false)
}

#[cfg(unix)]
fn unix_icmp_ping_raw(addr: std::net::Ipv4Addr, id: u16) -> bool {
    use icmp_sys::*;

    // Try unprivileged ping socket first; fall back to raw socket (requires root).
    // Track which type we got: SOCK_DGRAM vs SOCK_RAW behave differently for
    // parallel probes (see recvfrom loop below).
    let dgram_fd = unsafe { socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) };
    let (fd, is_raw) = if dgram_fd >= 0 {
        (dgram_fd, false)
    } else {
        let raw_fd = unsafe { socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) };
        if raw_fd < 0 { return false; }
        (raw_fd, true)
    };

    // Set a 2-second receive timeout so recvfrom cannot block the thread indefinitely.
    // We loop recvfrom to skip replies with wrong IDs, so the window needs to be
    // wider than the per-call timeout used by the parent unix_icmp_ping wrapper.
    #[cfg(target_os = "macos")]
    let tv = icmp_sys::Timeval { tv_sec: 2, tv_usec: 0, _pad: 0 };
    #[cfg(not(target_os = "macos"))]
    let tv = icmp_sys::Timeval { tv_sec: 2, tv_usec: 0 };
    unsafe {
        icmp_sys::setsockopt(
            fd,
            icmp_sys::SOL_SOCKET,
            icmp_sys::SO_RCVTIMEO,
            &tv as *const icmp_sys::Timeval as *const u8,
            std::mem::size_of::<icmp_sys::Timeval>() as u32,
        );
    }

    let ip_bytes = addr.octets();
    let sin_addr = u32::from_be_bytes(ip_bytes);

    #[cfg(target_os = "linux")]
    let dest = SockAddrIn {
        sin_family: AF_INET as u16,
        sin_port: 0,
        sin_addr,
        sin_zero: [0; 8],
    };
    #[cfg(target_os = "macos")]
    let dest = SockAddrIn {
        sin_len: std::mem::size_of::<SockAddrIn>() as u8,
        sin_family: AF_INET as u8,
        sin_port: 0,
        sin_addr,
        sin_zero: [0; 8],
    };

    let pkt = build_icmp_echo_request(id, 1);
    let sent = unsafe {
        sendto(
            fd,
            pkt.as_ptr(),
            pkt.len(),
            0,
            &dest as *const SockAddrIn,
            std::mem::size_of::<SockAddrIn>() as u32,
        )
    };
    if sent < 0 {
        unsafe { close(fd) };
        return false;
    }

    // Loop on recvfrom: raw ICMP sockets receive ALL incoming ICMP traffic, not
    // just replies to our own request. When probes run in parallel every socket
    // may receive replies sent to other sockets. We filter by our unique `id`
    // and keep reading until we get a matching reply or the socket times out.
    let mut buf = [0u8; 128];
    loop {
        let mut src: SockAddrIn = unsafe { std::mem::zeroed() };
        let mut src_len = std::mem::size_of::<SockAddrIn>() as u32;
        let received = unsafe {
            recvfrom(
                fd,
                buf.as_mut_ptr(),
                buf.len(),
                0,
                &mut src as *mut SockAddrIn,
                &mut src_len as *mut u32,
            )
        };

        if received < 1 {
            // Timeout or hard error — give up.
            unsafe { close(fd) };
            return false;
        }

        // ICMP reply may or may not be prefixed with the IP header depending on
        // socket type and OS. If the first byte looks like an IPv4 header
        // (version nibble == 4), skip past it using the IHL field.
        let icmp_start = if (buf[0] >> 4) == 4 {
            ((buf[0] & 0x0f) as usize) * 4
        } else {
            0
        };

        let data = &buf[..received as usize];
        let icmp_type = data.get(icmp_start).copied().unwrap_or(1);
        // ICMP echo reply identifier is at bytes 4–5 of the ICMP header.
        let reply_id = {
            let hi = data.get(icmp_start + 4).copied().unwrap_or(0) as u16;
            let lo = data.get(icmp_start + 5).copied().unwrap_or(0) as u16;
            (hi << 8) | lo
        };

        if icmp_type == 0 {
            // On SOCK_DGRAM the kernel has already demultiplexed: only our own
            // echo reply is delivered to this socket, and the kernel overwrites
            // the identifier field, so we cannot match on id.
            // On SOCK_RAW all ICMP traffic goes to every raw socket, so we must
            // check the identifier to avoid accepting another probe's reply.
            if !is_raw || reply_id == id {
                unsafe { close(fd) };
                return true;
            }
        }
        // Otherwise it was another probe's reply (SOCK_RAW only) — keep waiting.
    }
}

#[cfg(target_os = "windows")]
fn windows_icmp_ping(addr: std::net::Ipv4Addr, _id: u16) -> bool {
    use icmp_sys::*;

    let handle = unsafe { IcmpCreateFile() };
    if handle.is_null() {
        return false;
    }

    // IcmpSendEcho takes IPAddr which is the IPv4 address in network byte order (big-endian).
    let dest = u32::from_be_bytes(addr.octets());

    let payload = [0u8; 8];
    // Reply buffer must be at least sizeof(ICMP_ECHO_REPLY) + payload size = 28 + 8 = 36 bytes.
    let mut reply_buf = [0u8; 64];

    let result = unsafe {
        IcmpSendEcho(
            handle,
            dest,
            payload.as_ptr(),
            payload.len() as u16,
            std::ptr::null(),
            reply_buf.as_mut_ptr(),
            reply_buf.len() as u32,
            1000, // 1 second timeout in ms
        )
    };
    unsafe { IcmpCloseHandle(handle) };
    result > 0
}

// ── DNS ──────────────────────────────────────────────────────────────────────

/// Probes all `DNS_TARGETS` in parallel by resolving each domain via the OS
/// stub resolver (`getaddrinfo` / `GetAddrInfoW`).
/// Returns the first domain that resolves to at least one address, or `None`
/// if all targets time out or fail.
///
/// NOTE: The OS resolver may return cached results or consult `/etc/hosts`,
/// which can produce false positives on air-gapped machines.  Treat this as a
/// low-confidence signal and corroborate with HTTPS or ICMP checks.
///
/// Each probe runs in a dedicated thread because `getaddrinfo` can block for
/// 30+ seconds on an unreachable resolver and would otherwise stall the loop.
fn dns_check() -> Option<&'static str> {
    use std::net::ToSocketAddrs;

    let (tx, rx) = mpsc::channel::<Option<&'static str>>();

    for &host in DNS_TARGETS {
        let tx = tx.clone();
        thread::spawn(move || {
            let resolved = format!("{}:80", host)
                .to_socket_addrs()
                .map(|mut addrs| addrs.next().is_some())
                .unwrap_or(false);
            let _ = tx.send(if resolved { Some(host) } else { None });
        });
    }
    drop(tx);

    while let Ok(result) = rx.recv_timeout(Duration::from_secs(5)) {
        if result.is_some() {
            return result;
        }
    }
    None
}

// ── HTTP ─────────────────────────────────────────────────────────────────────

/// Resolve `host_port` (e.g. `"example.com:80"`) to a `SocketAddr` with a
/// 3-second timeout. Returns `None` on failure or timeout.
fn resolve_host(host_port: String) -> Option<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = host_port
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next());
        let _ = tx.send(result);
    });
    rx.recv_timeout(Duration::from_secs(3)).ok().flatten()
}

/// Runs all `HTTP_PROBES` in parallel. Returns the host name of the
/// first probe that succeeds (correct status + optional body match), or `None`.
fn http_check() -> Option<&'static str> {
    let (tx, rx) = mpsc::channel();

    for &(host, path, expected_status, body_substr) in HTTP_TARGETS {
        let tx = tx.clone();
        thread::spawn(move || {
            let hit = http_probe_raw(host, path, expected_status, body_substr);
            // Send Some(host) on success, None on failure; channel closes when
            // all senders are dropped so the collector loop terminates cleanly.
            let _ = tx.send(if hit { Some(host) } else { None });
        });
    }
    // Drop the original sender so the channel closes after all threads finish.
    drop(tx);

    // Collect results as they arrive; return the first success.
    while let Ok(result) = rx.recv_timeout(Duration::from_secs(10)) {
        if result.is_some() {
            return result;
        }
    }
    None
}

/// Perform one HTTP/1.1 GET probe. Returns `true` when:
///   - the server replies with `expected_status`, AND
///   - `body_substr` is empty OR the response body contains `body_substr`.
fn http_probe_raw(
    host: &str,
    path: &str,
    expected_status: u16,
    body_substr: &str,
) -> bool {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpStream;

    let sa = match resolve_host(format!("{}:80", host)) {
        Some(sa) => sa,
        None => return false,
    };

    let stream = match TcpStream::connect_timeout(&sa, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    // Send request — scope the write borrow so `stream` is free for BufReader.
    {
        let mut w = &stream;
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, host
        );
        if w.write_all(req.as_bytes()).is_err() {
            return false;
        }
    }

    let mut reader = BufReader::new(&stream);

    // Parse status line: "HTTP/1.x <code> <reason>\r\n"
    let mut status_line = String::new();
    if reader.read_line(&mut status_line).is_err() {
        return false;
    }
    let status = status_line
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);

    if status != expected_status {
        return false;
    }
    if body_substr.is_empty() {
        return true; // status-only check — done
    }

    // Skip response headers (read until the blank separator line).
    loop {
        let mut hdr = String::new();
        match reader.read_line(&mut hdr) {
            Ok(0) | Err(_) => return false,
            Ok(_) if hdr == "\r\n" || hdr == "\n" => break,
            Ok(_) => {}
        }
    }

    // Read up to 512 bytes of body and search for the expected substring.
    let mut body_buf = [0u8; 512];
    let n = reader.read(&mut body_buf).unwrap_or(0);
    let body = std::str::from_utf8(&body_buf[..n]).unwrap_or("");
    body.contains(body_substr)
}

// ── IPv6 ─────────────────────────────────────────────────────────────────────

/// Probe each IPv6 target using TCP on ports 53 and 853, in parallel.
/// Returns the first address that succeeds on any probe, or `None` if all fail.
fn ipv6_check() -> Option<&'static str> {
    let (tx, rx) = mpsc::channel();

    for &addr in IPV6_TARGETS {
        let tx = tx.clone();
        thread::spawn(move || {
            let hit = tcp_port_open_v6(addr, 53) || tcp_port_open_v6(addr, 853);
            let _ = tx.send(if hit { Some(addr) } else { None });
        });
    }
    drop(tx);

    while let Ok(result) = rx.recv_timeout(Duration::from_secs(4)) {
        if result.is_some() {
            return result;
        }
    }
    None
}

/// Attempt a TCP connection to `[addr]:port` with a 2 s timeout.
/// Pure stdlib — no external binaries, fully cross-platform.
fn tcp_port_open_v6(addr: &str, port: u16) -> bool {
    use std::net::{SocketAddr, TcpStream};
    let sa: SocketAddr = match format!("[{}]:{}", addr, port).parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    TcpStream::connect_timeout(&sa, Duration::from_secs(2)).is_ok()
}

// ── HTTPS ────────────────────────────────────────────────────────────────────

/// Runs all `HTTPS_PROBES` in parallel. Each probe performs a full TLS handshake
/// with certificate chain validation using the bundled Mozilla root CA store.
/// A MITM proxy presenting a self-signed certificate will be rejected.
/// Returns the host name of the first probe that passes cert validation AND returns
/// the expected HTTP status (and optional body substring), or `None` if all fail.
fn https_check() -> Option<&'static str> {
    use rustls::{ClientConfig, RootCertStore};
    use std::sync::Arc;

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let (tx, rx) = mpsc::channel();

    for &(host, path, expected_status, body_substr) in HTTPS_TARGETS {
        let tx = tx.clone();
        let config = Arc::clone(&config);
        thread::spawn(move || {
            let hit = https_probe_raw(&config, host, path, expected_status, body_substr);
            let _ = tx.send(if hit { Some(host) } else { None });
        });
    }
    drop(tx);

    while let Ok(result) = rx.recv_timeout(Duration::from_secs(10)) {
        if result.is_some() {
            return result;
        }
    }
    None
}

/// Perform one HTTPS probe. Establishes a TCP connection, completes a TLS handshake
/// (validating the server certificate chain against Mozilla roots), sends an
/// HTTP/1.1 GET, and checks the status code and optional body substring.
fn https_probe_raw(
    config: &std::sync::Arc<rustls::ClientConfig>,
    host: &str,
    path: &str,
    expected_status: u16,
    body_substr: &str,
) -> bool {
    use rustls::pki_types::ServerName;
    use rustls::{ClientConnection, StreamOwned};
    use std::io::{BufRead, BufReader, Read};
    use std::net::TcpStream;

    let sa = match resolve_host(format!("{}:443", host)) {
        Some(sa) => sa,
        None => return false,
    };
    let tcp = match TcpStream::connect_timeout(&sa, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));

    let server_name = match ServerName::try_from(host.to_owned()) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let conn = match ClientConnection::new(std::sync::Arc::clone(config), server_name) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let mut tls = StreamOwned::new(conn, tcp);

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host
    );
    if tls.write_all(req.as_bytes()).is_err() {
        return false;
    }

    let mut reader = BufReader::new(&mut tls);

    let mut status_line = String::new();
    if reader.read_line(&mut status_line).is_err() {
        return false;
    }
    let status = status_line
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);

    if status != expected_status {
        return false;
    }
    if body_substr.is_empty() {
        return true;
    }

    loop {
        let mut hdr = String::new();
        match reader.read_line(&mut hdr) {
            Ok(0) | Err(_) => return false,
            Ok(_) if hdr == "\r\n" || hdr == "\n" => break,
            Ok(_) => {}
        }
    }

    let mut body_buf = [0u8; 512];
    let n = reader.read(&mut body_buf).unwrap_or(0);
    let body = std::str::from_utf8(&body_buf[..n]).unwrap_or("");
    body.contains(body_substr)
}

// ── Alert ────────────────────────────────────────────────────────────────────

/// Print a detection message then beep continuously until the process is killed.
/// The `-> !` return type confirms to the compiler that this function never returns.
fn trigger_alert(reason: &str) -> ! {
    println!("\n[!] {}", reason);
    log_detection(reason);
    loop {
        beep();
        thread::sleep(Duration::from_secs(5));
    }
}

// ── Test mode ────────────────────────────────────────────────────────────────

/// Run every enabled probe exactly once, collect all individual results, print a
/// per-probe table, then invoke the alert infrastructure (`log_detection` + `beep`)
/// for any detected connectivity before exiting cleanly.
/// Unlike the monitoring loop, this never calls `trigger_alert` — no infinite beep.
///
/// Exit code: 0 = no connectivity detected, 1 = at least one probe passed.
fn run_tests() -> ! {
    println!("=== NetKiller — test mode ===");
    println!("Running all enabled probes. May take up to 15 seconds.\n");

    let mut total: usize = 0;
    let mut detections: Vec<String> = Vec::new();

    // ── ICMP ──
    if ICMP_CHECK_ENABLED {
        let results = test_icmp();
        println!("--- ICMP ({} targets) ---", results.len());
        for (ip, ok) in &results {
            total += 1;
            println!("  {}  {}", pass_fail(*ok), ip);
            if *ok {
                detections.push(format!("ICMP: host {} responded — connectivity detected!", ip));
            }
        }
        println!();
    }

    // ── DNS ──
    if DNS_CHECK_ENABLED {
        let results = test_dns();
        println!("--- DNS ({} targets) ---", results.len());
        for (host, ok) in &results {
            total += 1;
            println!("  {}  {}", pass_fail(*ok), host);
            if *ok {
                detections.push(format!("DNS: resolved {} — connectivity detected!", host));
            }
        }
        println!();
    }

    // ── HTTP ──
    if HTTP_CHECK_ENABLED {
        let results = test_http();
        println!("--- HTTP ({} probes) ---", results.len());
        for (host, path, status, ok) in &results {
            total += 1;
            println!("  {}  {}{}  → {}", pass_fail(*ok), host, path, status);
            if *ok {
                detections.push(format!("HTTP: probe hit {} — connectivity detected!", host));
            }
        }
        println!();
    }

    // ── HTTPS ──
    if HTTPS_CHECK_ENABLED {
        let results = test_https();
        println!("--- HTTPS ({} probes, cert validated) ---", results.len());
        for (host, path, status, ok) in &results {
            total += 1;
            println!("  {}  {}{}  → {}", pass_fail(*ok), host, path, status);
            if *ok {
                detections.push(format!(
                    "HTTPS: verified cert on {} — connectivity detected!", host
                ));
            }
        }
        println!();
    }

    // ── IPv6 ──
    if IPV6_CHECK_ENABLED {
        let results = test_ipv6();
        println!("--- IPv6 ({} targets) ---", results.len());
        for (addr, ok) in &results {
            total += 1;
            println!("  {}  {}", pass_fail(*ok), addr);
            if *ok {
                detections.push(format!(
                    "IPv6: probe succeeded on {} — connectivity detected!", addr
                ));
            }
        }
        println!();
    }

    // ── Alert phase: log + beep for every detection ──
    for reason in &detections {
        log_detection(reason);
    }

    if detections.is_empty() {
        println!("=== 0/{} probes passed — no connectivity detected ===", total);
        std::process::exit(0);
    } else {
        println!("=== {}/{} probe(s) detected connectivity ===", detections.len(), total);
        for reason in &detections {
            println!("[!] {}", reason);
        }
        beep();
        std::process::exit(1);
    }
}

fn pass_fail(ok: bool) -> &'static str {
    if ok { "PASS" } else { "FAIL" }
}

/// Probe all ICMP targets in parallel; return results in original table order.
fn test_icmp() -> Vec<(&'static str, bool)> {
    let (tx, rx) = mpsc::channel();
    for (i, &ip) in ICMP_TARGETS.iter().enumerate() {
        let tx = tx.clone();
        let id = (i as u16) + 1;
        thread::spawn(move || { let _ = tx.send((i, ip, icmp_ping(ip, id))); });
    }
    drop(tx);
    let mut results = Vec::new();
    while let Ok(r) = rx.recv_timeout(Duration::from_secs(3)) { results.push(r); }
    results.sort_by_key(|r| r.0);
    results.into_iter().map(|(_, ip, ok)| (ip, ok)).collect()
}

/// Resolve all DNS targets in parallel; return results in original table order.
fn test_dns() -> Vec<(&'static str, bool)> {
    use std::net::ToSocketAddrs;
    let (tx, rx) = mpsc::channel();
    for (i, &host) in DNS_TARGETS.iter().enumerate() {
        let tx = tx.clone();
        thread::spawn(move || {
            let ok = format!("{}:80", host)
                .to_socket_addrs()
                .map(|mut addrs| addrs.next().is_some())
                .unwrap_or(false);
            let _ = tx.send((i, host, ok));
        });
    }
    drop(tx);
    let mut results = Vec::new();
    while let Ok(r) = rx.recv_timeout(Duration::from_secs(5)) { results.push(r); }
    results.sort_by_key(|r| r.0);
    results.into_iter().map(|(_, host, ok)| (host, ok)).collect()
}

/// Run all HTTP probes in parallel; return results in original table order.
fn test_http() -> Vec<(&'static str, &'static str, u16, bool)> {
    let (tx, rx) = mpsc::channel();
    for (i, &(host, path, status, body)) in HTTP_TARGETS.iter().enumerate() {
        let tx = tx.clone();
        thread::spawn(move || {
            let ok = http_probe_raw(host, path, status, body);
            let _ = tx.send((i, host, path, status, ok));
        });
    }
    drop(tx);
    let mut results = Vec::new();
    while let Ok(r) = rx.recv_timeout(Duration::from_secs(12)) { results.push(r); }
    results.sort_by_key(|r| r.0);
    results.into_iter().map(|(_, h, p, s, ok)| (h, p, s, ok)).collect()
}

/// Run all HTTPS probes in parallel; return results in original table order.
fn test_https() -> Vec<(&'static str, &'static str, u16, bool)> {
    use rustls::{ClientConfig, RootCertStore};
    use std::sync::Arc;
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let (tx, rx) = mpsc::channel();
    for (i, &(host, path, status, body)) in HTTPS_TARGETS.iter().enumerate() {
        let tx = tx.clone();
        let config = Arc::clone(&config);
        thread::spawn(move || {
            let ok = https_probe_raw(&config, host, path, status, body);
            let _ = tx.send((i, host, path, status, ok));
        });
    }
    drop(tx);
    let mut results = Vec::new();
    while let Ok(r) = rx.recv_timeout(Duration::from_secs(15)) { results.push(r); }
    results.sort_by_key(|r| r.0);
    results.into_iter().map(|(_, h, p, s, ok)| (h, p, s, ok)).collect()
}

/// Probe all IPv6 targets in parallel; return results in original table order.
fn test_ipv6() -> Vec<(&'static str, bool)> {
    let (tx, rx) = mpsc::channel();
    for (i, &addr) in IPV6_TARGETS.iter().enumerate() {
        let tx = tx.clone();
        thread::spawn(move || {
            let ok = tcp_port_open_v6(addr, 53) || tcp_port_open_v6(addr, 853);
            let _ = tx.send((i, addr, ok));
        });
    }
    drop(tx);
    let mut results = Vec::new();
    while let Ok(r) = rx.recv_timeout(Duration::from_secs(5)) { results.push(r); }
    results.sort_by_key(|r| r.0);
    results.into_iter().map(|(_, addr, ok)| (addr, ok)).collect()
}

// ── Logging ──────────────────────────────────────────────────────────────────

/// Append a timestamped detection event to `LOG_FILE_PATH`.
/// Silently prints a warning to stderr on I/O error so the alert loop is never
/// blocked by a log write failure.
fn log_detection(reason: &str) {
    if !LOG_ENABLED {
        return;
    }
    use std::fs::OpenOptions;

    let epoch_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let timestamp = format_utc_iso8601(epoch_secs);

    match OpenOptions::new().create(true).append(true).open(LOG_FILE_PATH) {
        Ok(mut f) => {
            let _ = writeln!(f, "{} DETECTION: {}", timestamp, reason);
        }
        Err(e) => {
            eprintln!("[!] Could not write to log {}: {}", LOG_FILE_PATH, e);
        }
    }
}

/// Format Unix epoch seconds as `YYYY-MM-DDTHH:MM:SSZ` (UTC, no external crates).
fn format_utc_iso8601(epoch_secs: u64) -> String {
    let time_of_day = epoch_secs % 86400;
    let hour = time_of_day / 3600;
    let min  = (time_of_day % 3600) / 60;
    let sec  = time_of_day % 60;

    let mut days = epoch_secs / 86400;
    let mut year = 1970u32;
    loop {
        let in_year = if is_leap_year(year) { 366 } else { 365 };
        if days < in_year { break; }
        days -= in_year;
        year += 1;
    }

    const MONTH_DAYS: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0usize;
    for (i, &d) in MONTH_DAYS.iter().enumerate() {
        let d = if i == 1 && is_leap_year(year) { 29 } else { d };
        if days < d { break; }
        days -= d;
        month += 1;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month + 1, days + 1, hour, min, sec
    )
}

fn is_leap_year(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ── Beep ─────────────────────────────────────────────────────────────────────

/// Best-effort PC-speaker / system beep. Never panics.
fn beep() {
    #[cfg(target_os = "windows")]
    windows_beep();

    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("osascript")
            .args(["-e", "beep 3"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        // BEL characters — audible on any terminal connected to the console.
        print!("\x07\x07\x07");
        let _ = std::io::stdout().flush();

        // Also try the `beep` package if installed; ignore failures.
        let _ = Command::new("beep")
            .args(["-f", "750", "-l", "300", "-r", "3"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[cfg(target_os = "windows")]
fn windows_beep() {
    // Directly call Win32 Beep() — no external crates needed.
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn Beep(dwFreq: u32, dwDuration: u32) -> i32;
    }
    for _ in 0..3 {
        let ok = unsafe { Beep(750, 400) };
        if ok == 0 {
            // Beep() unavailable (headless/no speaker) — ignore silently.
            break;
        }
        thread::sleep(Duration::from_millis(150));
    }
}
