# NetKiller

Cross-platform internet-connectivity monitor for air-gapped systems. When any connectivity is detected it sounds a continuous audible alarm and logs the event. The program runs as a persistent background service and never exits on its own.

## Build instructions

Prerequisites: [Rust toolchain](https://rustup.rs) (stable, edition 2024). Dependencies (`rustls`, `webpki-roots`) are fetched automatically by Cargo.

```sh
cargo build --release
```

The compiled binary is placed at `target/release/NetKiller` (or `NetKiller.exe` on Windows).

**Fully static binary (Linux, recommended for deployment):**

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# Binary: target/x86_64-unknown-linux-musl/release/NetKiller
```

`rustls` is pure Rust, so the musl build has no shared-library dependencies and can be copied to any Linux system without a Rust toolchain installed.

## Cross-compilation (batch build)

The following instructions explain how to produce release binaries for all supported platforms from a single Linux host.

### Target matrix

| Platform | Architecture | Rust target triple |
|---|---|---|
| Linux | x86_64 | `x86_64-unknown-linux-musl` |
| Linux | ARM64 | `aarch64-unknown-linux-musl` |
| macOS | x86_64 | `x86_64-apple-darwin` |
| macOS | ARM64 | `aarch64-apple-darwin` |
| Windows | x86_64 | `x86_64-pc-windows-gnu` |
| Windows | ARM64 | `aarch64-pc-windows-gnullvm` |

### Tooling

**Linux and Windows targets** use [`cross`](https://github.com/cross-rs/cross), which handles the musl toolchain and MinGW/LLVM-MinGW toolchains automatically via Docker. Install it with:

```sh
cargo install cross
```

`cross` is a drop-in replacement for `cargo build` for these targets — it pulls the appropriate Docker image and runs the build inside it.

**macOS targets** are not supported by `cross`. Use [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild), which uses the [Zig compiler](https://ziglang.org) as a zero-configuration cross-linker — no macOS SDK or Xcode installation required.

```sh
pip3 install ziglang          # installs the zig binary via pip
cargo install cargo-zigbuild
rustup target add x86_64-apple-darwin aarch64-apple-darwin
```

`cargo-zigbuild` is then used in place of `cargo build` for Apple targets:

```sh
cargo zigbuild --release --target x86_64-apple-darwin
cargo zigbuild --release --target aarch64-apple-darwin
```

**Gatekeeper note:** Binaries cross-compiled on Linux are unsigned. macOS will block them by default. To run them, either ad-hoc sign on a Mac (`codesign -s - netkiller-macos-arm64`) or have end-users right-click → Open the first time.

### rustls crypto backend for cross-compilation

`rustls 0.23` defaults to the `aws-lc-rs` crypto backend. `aws-lc-rs` requires CMake and a C/C++ compiler targeting the build host, which breaks most cross-compilation setups.

Switch to the `ring` backend before cross-compiling. `ring` is pure Rust plus hand-written assembly and cross-compiles cleanly with `cross`. Update `Cargo.toml`:

```toml
[dependencies]
rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12"] }
webpki-roots = "0.26"
```

**Important:** Rebuild after changing this. The local `cargo build --release` workflow is unaffected — `ring` works on all platforms.

### Batch build script

`build-all.sh` (included in the repository root) automates all six targets. Prerequisites: Docker (for `cross`), `zig` on `PATH` (for macOS targets via `cargo-zigbuild`).

```bash
#!/usr/bin/env bash
set -e

BINARY_NAME="NetKiller"
DIST_DIR="dist"

mkdir -p "$DIST_DIR"

# Register all targets with rustup
rustup target add \
  x86_64-unknown-linux-musl \
  aarch64-unknown-linux-musl \
  x86_64-pc-windows-gnu \
  aarch64-pc-windows-gnullvm \
  x86_64-apple-darwin \
  aarch64-apple-darwin

# Linux x86_64
echo "Building linux-x86_64..."
cross build --release --target x86_64-unknown-linux-musl
cp "target/x86_64-unknown-linux-musl/release/$BINARY_NAME" \
   "$DIST_DIR/netkiller-linux-x86_64"

# Linux ARM64
echo "Building linux-arm64..."
cross build --release --target aarch64-unknown-linux-musl
cp "target/aarch64-unknown-linux-musl/release/$BINARY_NAME" \
   "$DIST_DIR/netkiller-linux-arm64"

# Windows x86_64
echo "Building windows-x86_64..."
cross build --release --target x86_64-pc-windows-gnu
cp "target/x86_64-pc-windows-gnu/release/$BINARY_NAME.exe" \
   "$DIST_DIR/netkiller-windows-x86_64.exe"

# Windows ARM64
echo "Building windows-arm64..."
cross build --release --target aarch64-pc-windows-gnullvm
cp "target/aarch64-pc-windows-gnullvm/release/$BINARY_NAME.exe" \
   "$DIST_DIR/netkiller-windows-arm64.exe"

# macOS x86_64 (requires zig on PATH)
echo "Building macos-x86_64..."
cargo zigbuild --release --target x86_64-apple-darwin
cp "target/x86_64-apple-darwin/release/$BINARY_NAME" \
   "$DIST_DIR/netkiller-macos-x86_64"

# macOS ARM64 (requires zig on PATH)
echo "Building macos-arm64..."
cargo zigbuild --release --target aarch64-apple-darwin
cp "target/aarch64-apple-darwin/release/$BINARY_NAME" \
   "$DIST_DIR/netkiller-macos-arm64"

echo ""
echo "Done. Binaries written to $DIST_DIR/:"
ls -lh "$DIST_DIR/"
```

**Gatekeeper:** macOS binaries produced by this script are unsigned. See the tooling section above for signing notes.

## Usage

**Normal monitoring mode** (default):

```sh
./NetKiller
```

Runs all enabled checks every `POLL_INTERVAL_SECS` seconds. On first positive detection, sounds a continuous alarm and appends a timestamped entry to the log file. The process never exits on its own — kill it to stop monitoring.

**Test mode** — run every probe once, print a per-probe pass/fail table, then exit:

```sh
./NetKiller --test
# or
./NetKiller -t
```

All probes run to completion before any result is processed, so every method is exercised regardless of earlier findings. Detections are logged and a single beep is sounded if any probe passes. Exit code: `0` = no connectivity detected, `1` = connectivity detected.

Example output on a connected machine:

```
=== NetKiller — test mode ===
Running all enabled probes. May take up to 15 seconds.

--- ICMP (8 targets) ---
  PASS  1.1.1.1
  PASS  8.8.8.8
  ...

--- DNS ---
  PASS  example.com resolved

--- HTTP (7 probes) ---
  PASS  clients3.google.com/generate_204  → 204
  ...

--- HTTPS (7 probes, cert validated) ---
  PASS  clients3.google.com/generate_204  → 204
  ...

--- IPv6 (8 targets) ---
  PASS  2606:4700:4700::1111
  ...

=== 31/31 probe(s) detected connectivity ===
```

## Configuration

All settings are constants at the top of `src/main.rs`. Edit them and rebuild — there is no runtime config file.

| Constant | Default | Purpose |
|---|---|---|
| `POLL_INTERVAL_SECS` | `5` | Seconds between full scan rounds |
| `HEARTBEAT_EVERY_N_ROUNDS` | `12` | Print a `.` every N rounds (≈1 min at default) |
| `ICMP_CHECK_ENABLED` | `true` | Toggle ICMP checks |
| `ICMP_TARGETS` | 8 public DNS server IPs | IPv4 hosts probed with ICMP each round |
| `DNS_CHECK_ENABLED` | `true` | Toggle DNS check |
| `DNS_CHECK_HOST` | `"example.com"` | Domain resolved for DNS check |
| `HTTP_CHECK_ENABLED` | `true` | Toggle HTTP probes |
| `HTTP_TARGETS` | 7 connectivity-check endpoints | `(host, path, expected_status, body_substring)` |
| `HTTPS_CHECK_ENABLED` | `true` | Toggle HTTPS probes |
| `HTTPS_TARGETS` | 7 connectivity-check endpoints | `(host, path, expected_status, body_substring)` |
| `IPV6_CHECK_ENABLED` | `true` | Toggle IPv6 checks |
| `IPV6_TARGETS` | 8 IPv6 resolver addresses | IPv6 hosts probed via TCP each round |
| `LOG_ENABLED` | `true` | Toggle detection event logging |
| `LOG_FILE_PATH` | `"netkiller.log"` | Append-only log file path |

**Before deploying as a service**, set `LOG_FILE_PATH` to an absolute path appropriate for the platform (see per-platform instructions below), then rebuild.

## Detection methods

All checks run in parallel. The first positive result triggers the alert in normal mode; in test mode all results are collected before any alert is processed. No OS tools (`ping`, `dig`, `curl`) are used — all probes are implemented natively so the binary can be statically linked.

| Method | What is checked | Implementation |
|---|---|---|
| **ICMP** | Each `ICMP_TARGETS` address responds to an echo request | Native socket FFI: `SOCK_DGRAM`/`SOCK_RAW` + `IPPROTO_ICMP` on Unix; `IcmpSendEcho` (iphlpapi) on Windows |
| **DNS** | `DNS_CHECK_HOST` resolves to at least one address | `std::net::ToSocketAddrs` in a thread with a 3 s timeout |
| **HTTP** | Each `HTTP_TARGETS` endpoint returns the expected HTTP status code and body substring | Raw `TcpStream` HTTP/1.1 GET; 7 probes in parallel |
| **HTTPS** | Each `HTTPS_TARGETS` endpoint returns the expected response *and* presents a valid certificate chain | `rustls` + Mozilla root CA bundle (`webpki-roots`); rejects self-signed or MITM certificates |
| **IPv6** | Each `IPV6_TARGETS` address accepts a TCP connection on port 53 or 853 | `TcpStream::connect_timeout`; 8 targets in parallel |

**DNS false-positive note:** The OS resolver may return a cached result or consult `/etc/hosts`, which can produce false positives on air-gapped machines. Treat DNS as a low-confidence signal and corroborate with ICMP or HTTPS results.

## Installation

### Linux

**1. Configure and build a static binary:**

Edit `src/main.rs` and set:
```rust
const LOG_FILE_PATH: &str = "/var/log/netkiller.log";
```

Then build:
```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

**2. Install the binary:**

```sh
sudo install -m 755 target/x86_64-unknown-linux-musl/release/NetKiller /usr/local/bin/netkiller
```

**3. Privileges for ICMP**

NetKiller uses a raw ICMP socket. Either run as root, or grant the binary the `CAP_NET_RAW` capability:

```sh
sudo setcap cap_net_raw+ep /usr/local/bin/netkiller
```

With the capability set, the service can run as a non-root user. Without it, set `User=root` in the unit file below.

**4. Create the systemd unit:**

```sh
sudo tee /etc/systemd/system/netkiller.service > /dev/null << 'EOF'
[Unit]
Description=NetKiller — Internet Connectivity Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/netkiller
Restart=always
RestartSec=5
# Remove the next two lines if running as root instead:
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
```

**5. Enable and start:**

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now netkiller
sudo systemctl status netkiller
```

**Audio note:** When running as a headless service, the terminal BEL character has no effect. Install the `beep` package to enable PC-speaker alerts:

```sh
# Debian/Ubuntu
sudo apt install beep
# Fedora/RHEL
sudo dnf install beep
```

The `beep` binary drives the kernel PC speaker directly and works without a terminal or audio subsystem.

---

### macOS

NetKiller can be installed as either a **LaunchDaemon** (starts at boot, runs as root, no GUI access) or a **LaunchAgent** (starts at login, runs as the current user, has GUI access for audio alerts).

Use a LaunchDaemon if you only need logging. Use a LaunchAgent if audible alerts via `osascript` are required.

**1. Configure and build:**

Edit `src/main.rs` and set:
```rust
const LOG_FILE_PATH: &str = "/var/log/netkiller.log";
```

```sh
cargo build --release
```

**2. Install the binary:**

```sh
sudo install -m 755 target/release/NetKiller /usr/local/bin/netkiller
```

**3a. LaunchDaemon (boot-time, no audio):**

```sh
sudo tee /Library/LaunchDaemons/com.netkiller.plist > /dev/null << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>             <string>com.netkiller</string>
    <key>ProgramArguments</key>  <array><string>/usr/local/bin/netkiller</string></array>
    <key>RunAtLoad</key>         <true/>
    <key>KeepAlive</key>         <true/>
    <key>StandardErrorPath</key> <string>/var/log/netkiller-stderr.log</string>
</dict>
</plist>
EOF

sudo launchctl load -w /Library/LaunchDaemons/com.netkiller.plist
```

**3b. LaunchAgent (login-time, audio works):**

```sh
mkdir -p ~/Library/LaunchAgents
tee ~/Library/LaunchAgents/com.netkiller.plist > /dev/null << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>             <string>com.netkiller</string>
    <key>ProgramArguments</key>  <array><string>/usr/local/bin/netkiller</string></array>
    <key>RunAtLoad</key>         <true/>
    <key>KeepAlive</key>         <true/>
</dict>
</plist>
EOF

launchctl load -w ~/Library/LaunchAgents/com.netkiller.plist
```

**Verify it is running:**
```sh
launchctl list | grep netkiller
```

**To stop / unload:**
```sh
# Daemon
sudo launchctl unload -w /Library/LaunchDaemons/com.netkiller.plist
# Agent
launchctl unload -w ~/Library/LaunchAgents/com.netkiller.plist
```

---

### Windows

Windows services require integration with the Service Control Manager, which plain console applications do not provide natively. The recommended approach is [NSSM](https://nssm.cc) (Non-Sucking Service Manager), a free utility that wraps any executable as a proper Windows service.

**1. Configure and build:**

Edit `src/main.rs` and set:
```rust
const LOG_FILE_PATH: &str = "C:\\ProgramData\\NetKiller\\netkiller.log";
```

```sh
cargo build --release
```

**2. Install the binary:**

Create the installation directory and copy the binary:
```powershell
New-Item -ItemType Directory -Force -Path "C:\Program Files\NetKiller"
New-Item -ItemType Directory -Force -Path "C:\ProgramData\NetKiller"
Copy-Item target\release\NetKiller.exe "C:\Program Files\NetKiller\netkiller.exe"
```

**3. Install NSSM:**

Download `nssm.exe` from https://nssm.cc/download and place it somewhere on your `PATH` (e.g. `C:\Windows\System32\`), then run from an elevated command prompt:

```bat
nssm install NetKiller "C:\Program Files\NetKiller\netkiller.exe"
nssm set NetKiller Description "Internet Connectivity Monitor"
nssm set NetKiller Start SERVICE_AUTO_START
nssm start NetKiller
```

**4. Verify:**

```bat
nssm status NetKiller
sc query NetKiller
```

**To stop / remove:**
```bat
nssm stop NetKiller
nssm remove NetKiller confirm
```

**Audio note:** Windows services run in Session 0, which is isolated from the interactive desktop. The Win32 `Beep()` function (used by NetKiller) drives the internal PC speaker and works in Session 0 on most hardware. Detection events are always written to the log file regardless of whether audio is available.
