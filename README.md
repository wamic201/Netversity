# Netversity

**A Windows desktop network management and security assessment suite, built in Python/Tkinter.**

Netversity is a single-application toolkit that unifies five practical networking and cybersecurity workflows — wired/wireless management, Nmap-based vulnerability scanning, live network topology discovery with intrusion alerting, an HTTP file server, and a real-time network performance monitor — into one cohesive GUI. It was built as a hands-on demonstration of core networking and offensive/defensive security concepts, using Windows-native tooling (`netsh`, the native WLAN API, PowerShell, ARP, and Nmap) rather than abstracting them away.

---

## Table of Contents

- [Features](#features)
  - [1. Networks Tab](#1-networks-tab)
  - [2. Vulnerability Assessment Tab](#2-vulnerability-assessment-tab)
  - [3. Network Discovery Tab](#3-network-discovery-tab)
  - [4. File Server (HTTP) Tab](#4-file-server-http-tab)
  - [5. Network Monitor Tab](#5-network-monitor-tab)
- [Security Risk Rating Methodology](#security-risk-rating-methodology)
- [Technologies & Libraries Used](#technologies--libraries-used)
- [Architecture & Methodology Notes](#architecture--methodology-notes)
- [Repository Structure](#repository-structure)
- [Requirements](#requirements)
- [Installation — Running the Prebuilt .exe](#installation--running-the-prebuilt-exe)
- [Installation — Building from Source](#installation--building-from-source)
  - [Manual build using the .spec file](#manual-build-using-the-spec-file)
- [Known Limitations](#known-limitations)
- [Disclaimer](#disclaimer)

---

## Features

Netversity is organized into five tabs, each targeting a distinct area of network administration or security assessment.

### 1. Networks Tab

The home tab for day-to-day connectivity management.

- **Unified Wi-Fi + Ethernet view** — wireless networks (via the native Windows WLAN API, `wlanapi.dll`, with a `netsh`-based fallback) and wired interfaces are shown side-by-side as cards, with signal strength, security type, and connection state.
- **Connect / Disconnect / Enable / Disable** — connect to a saved or new Wi-Fi profile (prompting for a password when needed), or enable/disable a wired adapter (requires Administrator).
- **Auto-Connect** — scans for all visible networks and automatically reconnects to the strongest *known* (previously saved) network.
- **Adapter Settings dialog** — switch an adapter between DHCP and a manually specified static IP/subnet/gateway/DNS configuration.
- **RSSI/Latency Logging** — a background logger that records signal strength and gateway latency to `wifi_log.csv` every 2 seconds, for tracking connection quality over time.
- **Ping Tool** — a standalone `ping -t`-style continuous ping window against any IP or hostname, with live running statistics (packets sent/received, loss %, min/avg/max RTT).
- **Auto-Scan** — optional 15-second periodic re-scan of visible networks.

### 2. Vulnerability Assessment Tab

A GUI front-end for [Nmap](https://nmap.org/), Netversity's core security-scanning engine.

- **Scan presets** — Fast Scan (`-T4 -F`), Service Version Detection (`-sV`), OS Detection (`-O`), Aggressive (`-A`), Full TCP (`-p-`), or fully Custom flags.
- **Built-in Nmap reference** — an in-app "?" help window documenting scan techniques, timing templates, service/OS detection flags, and the Nmap Scripting Engine (NSE) — including script categories (`vuln`, `safe`, `intrusive`, `discovery`, `auth`, `brute`) and specific useful scripts (`http-title`, `smb-vuln-ms17-010`, `ftp-anon`, `ssl-enum-ciphers`, etc.) with example command strings.
- **Comparison Mode** — runs SYN (`-sS`), UDP (`-sU`), and ARP Ping (`-sn -PR`) scans back-to-back against the same target and generates a differential report: hosts found by ARP vs. other methods, TCP vs. UDP port overlap, and services present on both protocols. Requires Administrator privileges.
- **Automated Security Risk Assessment** — every completed scan (standard or comparison) is automatically followed by a generated `=== SECURITY RISK ASSESSMENT ===` report (see [methodology](#security-risk-rating-methodology) below) that classifies every discovered open port by risk level and produces an overall per-host verdict.
- **Live streaming output** — Nmap's stdout streams into the UI line-by-line as the scan runs, rather than waiting for completion.
- **Save scan output** — export the full raw scan/comparison/risk report to a `.txt` file.

### 3. Network Discovery Tab

Opens a separate live network topology visualizer window.

- **Automatic subnet detection** — identifies the local subnet, gateway, and interface via `ipconfig`.
- **Concurrent host discovery** — sweeps every host in the subnet using a dynamically-sized `ThreadPoolExecutor` (scaling from 25 to 100 worker threads depending on subnet size), pinging each host and reading its TTL to estimate OS family (Linux/Mac/IoT vs. Windows vs. network gear).
- **MAC vendor fingerprinting** — cross-references the ARP table (`arp -a`) against a small internal OUI-prefix table to label devices (Apple, VMware, Raspberry Pi, Espressif/IoT, Intel, Realtek, Dell, etc.).
- **Reverse DNS** — attempts to resolve a hostname for each live host.
- **Graph visualization** — renders the network as a live-updating graph (via `networkx` + `matplotlib`), with the gateway as a hub node and hosts as leaves, color-coded by status.
- **Baseline & rogue-device detection** — save the current set of hosts as a trusted baseline (IP → MAC mapping). On future scans, any host not in the baseline is flagged **New/Rogue**, and any host whose MAC address doesn't match its baselined IP is flagged **Spoofed?** (a basic ARP-spoofing heuristic). Hosts present in the baseline but not currently responding are shown as **Missing**.
- **Real-time security alerting** — when a device is newly flagged as Rogue or Spoofed, a flashing red banner appears in the topology window, the system bell sounds, and the event is appended to an on-disk, timestamped CSV audit log (viewable in-app via the "Alert Log" button). Alerts are deduplicated — a device only re-triggers an alert if it disappears and later reappears.

### 4. File Server (HTTP) Tab

A minimal, configurable HTTP file server for quick LAN file sharing.

- Select any local folder as the served root directory and choose a port.
- Start/Stop controls, with live request logging (client IP, timestamp, request line) streamed into the UI.
- Shutdown is handled off the main GUI thread so stopping the server never freezes the interface, even with other engines (Nmap, Discovery, Monitor) running concurrently.

### 5. Network Monitor Tab

A real-time network performance dashboard.

- **Latency** — ICMP ping to the default gateway, sampled every 1 second (configurable).
- **Jitter** — standard deviation of the last 10 latency samples.
- **Packet Loss %** — rolling 20-sample ping loss ratio.
- **Throughput (Download/Upload)** — computed from adapter byte counters (`Get-NetAdapterStatistics` via PowerShell) sampled in parallel with the ping, so both metrics stay on a precise 1-second cadence regardless of subprocess latency.
- **Live activity graph** — dual-panel chart (throughput fixed 0–100 Mbps scale; latency auto-scaling), rendered in an isolated `matplotlib.figure.Figure` so it can run concurrently with the Topology tab's graph without a renderer race condition.
- Color-coded metric tiles (green/amber/red thresholds) for at-a-glance health assessment.

---

## Security Risk Rating Methodology

After every completed Nmap scan (standard scan or Comparison Mode), Netversity parses the raw scan output for open ports and classifies each one using a two-tier system:

**Tier 1 — Named port profiles** (`PORT_RISK_INFO`): specific, well-known ports are mapped to a risk level *and* a plain-language justification:

| Port | Risk | Service | Rationale |
|---|---|---|---|
| 21 | **HIGH** | FTP | Unencrypted credentials & file transfer |
| 23 | **HIGH** | Telnet | Unencrypted remote administration |
| 137 | **HIGH** | NetBIOS Name Service | Legacy Windows discovery, info leakage |
| 138 | **HIGH** | NetBIOS Datagram Service | Legacy Windows discovery |
| 139 | **HIGH** | NetBIOS Session Service | SMB over NetBIOS, common attack surface |
| 445 | **HIGH** | SMB | Historically exploited (EternalBlue/WannaCry, NotPetya) |
| 3389 | **HIGH** | RDP | Frequent brute-force/ransomware entry point (also BlueKeep) |
| 80 | **MEDIUM** | HTTP | Unencrypted web traffic; verify it doesn't handle sensitive data |
| 1433 | **MEDIUM** | MSSQL | Database listener exposed; restrict to trusted hosts |
| 3306 | **MEDIUM** | MySQL | Database listener exposed; restrict to trusted hosts |
| 1521 | **MEDIUM** | Oracle DB | Database listener exposed; restrict to trusted hosts |
| 5900 | **MEDIUM** | VNC | Remote desktop, often weakly authenticated |
| 53 | **LOW** | DNS | Normal if this host is a resolver; watch for open recursion |
| 443 | **LOW** | HTTPS | Encrypted web traffic, generally lower risk |
| 123 | **LOW** | NTP | Time sync; can be abused for DDoS amplification if misconfigured |

**Tier 2 — Fallback classification:** any open port *not* in the named table above still receives a risk level from three broader sets (`HIGH_RISK_PORTS`, `MEDIUM_RISK_PORTS`, `LOW_RISK_PORTS`), or defaults to **INFO** ("open service — confirm it's intended to be reachable") if it matches nothing.

**Report generation:**
1. Raw Nmap output is parsed into a per-host mapping of `{ip: [(port, protocol, service), ...]}`, using each scan's `"Nmap scan report for ..."` and `"<port>/<proto> open <service>"` lines.
2. Every open port found is classified and sorted by severity (HIGH → MEDIUM → LOW → INFO) within each host.
3. Per-host and total tallies are calculated across risk levels.
4. An **overall verdict** is assigned to the report: `HIGH RISK` if any high-risk port was found, else `MEDIUM RISK`, else `LOW RISK`, else `INFORMATIONAL ONLY` if ports were found with no listed risk, or a note explaining that no open ports were reported (which can also indicate a host-discovery-only scan type, e.g. `-sn`).
5. The result is wrapped in a `=== SECURITY RISK ASSESSMENT ===` banner and appended directly beneath the raw scan output — no separate report to dig up.

In **Comparison Mode**, the same risk engine is reused: SYN and UDP scan results are merged by host before being run through the classifier, so the risk report reflects the union of everything discovered across both protocols.

---

## Technologies & Libraries Used

| Category | Technology |
|---|---|
| Language | Python 3 |
| GUI Framework | Tkinter / ttk |
| Vulnerability Scanning | [Nmap](https://nmap.org/) (external dependency, invoked as a subprocess) |
| Network Graphing | [NetworkX](https://networkx.org/) + [Matplotlib](https://matplotlib.org/) (`FigureCanvasTkAgg`) |
| Image Handling | [Pillow (PIL)](https://python-pillow.org/) (optional — falls back to Tkinter's native `PhotoImage` if unavailable) |
| Windows Wi-Fi API | Native `wlanapi.dll` via `ctypes` (with `netsh wlan` as a fallback scanning method) |
| Networking Utilities | `netsh`, `ipconfig`, `arp`, `ping`, PowerShell (`Get-NetIPConfiguration`, `Get-NetAdapterStatistics`, `Get-DnsClientServerAddress`, `Get-NetAdapter`) |
| HTTP Serving | Python's built-in `http.server` / `socketserver` |
| Concurrency | `threading`, `concurrent.futures.ThreadPoolExecutor`, thread-safe `queue.Queue` |
| Packaging | [PyInstaller](https://pyinstaller.org/) |

---

## Architecture & Methodology Notes

- **Threading model:** every long-running or blocking operation (subnet sweeps, Nmap scans, ping loops, PowerShell calls, the HTTP server) runs on a background daemon thread. Results are placed on thread-safe `queue.Queue` instances and drained exclusively on the Tkinter main thread via `.after()` polling — Tkinter widgets are never touched directly from a background thread.
- **Dynamic thread pooling:** the Network Discovery engine scales its `ThreadPoolExecutor` worker count (25 / 50 / 100) based on subnet size, so a `/24` scans quickly while larger subnets remain stable rather than spawning thousands of simultaneous threads.
- **Isolated rendering contexts:** the Network Monitor's graph uses its own `matplotlib.figure.Figure` instance rather than the shared `pyplot` state machine, specifically so it can run concurrently with the Topology tab's graph without a renderer race condition.
- **Graceful, verified shutdown:** closing the application (via the window's close button) explicitly signals every background engine to stop, tree-kills (`taskkill /F /T`) any spawned Nmap subprocess so child processes can't survive their parent shell wrapper, and performs a hard interpreter exit — ensuring no orphaned scan or subprocess is left running once the window closes, which matters in particular for a packaged `.exe` where a lingering background process isn't visible in an obvious console window.
- **Packaging-aware resource resolution:** bundled assets (icons) are resolved via a helper that checks for PyInstaller's `sys._MEIPASS` extraction path, so icons load correctly both when run as a raw script and when frozen into a single-file executable.
- **Security-conscious input handling:** Wi-Fi profile XML (SSID/password) is built using `xml.sax.saxutils.escape()` to prevent injection into the WLAN profile document.

---

## Repository Structure

```
Netversity/
│
├── Netversity.exe          # Prebuilt, ready-to-run Windows executable
│
├── Source/
│   └── Netversity.py       # Full application source code
│
├── assets/
│   ├── icon.ico             # Application icon (Explorer/taskbar)
│   ├── wifi_icon.png        # In-app Wi-Fi card icon
│   └── ethernet_icon.png    # In-app Ethernet card icon
│
├── build_scripts/
│   └── netversity.spec      # PyInstaller build specification
│
├── requirements.txt
├── README.md
└── .gitignore
```

> **Note:** runtime-generated files (`topology_baseline.json`, `security_alerts.log`, `wifi_log.csv`) are created automatically next to the running executable/script and are not part of the repository.

---

## Requirements

- **Windows 10 or 11** (the application is Windows-only — it relies on `netsh`, `wlanapi.dll`, PowerShell, and Windows-specific process handling)
- **[Nmap](https://nmap.org/download.html)** installed separately and available on your system `PATH` (or in a standard install location) — required for the Vulnerability Assessment tab. The app will detect its absence and disable scanning gracefully if it isn't found.
- **Administrator privileges** — required for: SYN scans (`-sS`), OS detection (`-O`), Aggressive scans (`-A`), Comparison Mode, static IP configuration, and enabling/disabling wired adapters.

---

## Installation — Running the Prebuilt .exe

1. Download `Netversity.exe` from the repository root (or the latest [Release](../../releases)).
2. Ensure [Nmap](https://nmap.org/download.html) is installed on your machine.
3. Double-click `Netversity.exe`. Accept the UAC prompt — the app is configured to request Administrator elevation automatically so all features work without needing to be relaunched.

No Python installation is required to run the prebuilt executable.

---

## Installation — Building from Source

1. Install Python 3.10+ and clone this repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run directly:
   ```bash
   python Source/Netversity.py
   ```

### Manual build using the .spec file

To produce your own `Netversity.exe` from source using the included PyInstaller spec:

1. Make sure the repository folders are laid out as shown in [Repository Structure](#repository-structure) above — the spec file's paths are written relative to `build_scripts/`.
2. Install the build dependency if you haven't already:
   ```bash
   pip install pyinstaller
   ```
3. From inside the `build_scripts/` folder, run:
   ```bash
   pyinstaller netversity.spec
   ```
4. PyInstaller will create `build_scripts/build/` (intermediate cache — safe to ignore/delete) and `build_scripts/dist/Netversity.exe` (the final output).
5. Copy `dist/Netversity.exe` up to the repository root to match the structure above, or run it directly from `dist/`.

The spec file already:
- Bundles `assets/wifi_icon.png` and `assets/ethernet_icon.png` into the executable so the in-app icons render correctly regardless of where the `.exe` is launched from.
- Sets `uac_admin=True`, so the built executable automatically prompts for Administrator elevation on launch.
- Sets `console=False`, producing a clean windowed application with no background console flashes.
- Uses `assets/icon.ico` as the executable's own icon.

If you modify `Source/Netversity.py` or the assets, simply re-run step 3 to rebuild.

---

## Known Limitations

- Nmap itself is **not** bundled with the executable and must be installed separately — Nmap ships its own driver components (Npcap) that are outside the scope of this application's packaging.
- Some scan types and adapter operations require Administrator privileges; the app will prompt or explain when this is the case rather than failing silently.
- The MAC vendor lookup table is a small, illustrative OUI-prefix set rather than a comprehensive IEEE OUI database.

---

## Disclaimer

This application includes active network scanning capabilities (Nmap, ARP sweeps, host discovery) intended for use on networks and systems **you own or have explicit authorization to test**. Unauthorized scanning of third-party networks may violate local laws and terms of service. Use responsibly.
