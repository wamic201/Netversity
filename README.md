# Netversity

**A Windows desktop workspace for network management, device discovery, security scans, diagnostics, and LAN file sharing.**

Netversity 6.0 brings five networking workflows into a redesigned Python/Tkinter interface. A dark theme, persistent sidebar, connection summary, and embedded tools make it possible to manage connections, discover devices, inspect services, monitor performance, and share files from one window.

The application is also a hands-on demonstration of networking and security concepts, using Windows tooling such as the native WLAN API, `netsh`, PowerShell, ARP, and ping, together with the external Nmap scanner.

## Table of Contents

- [What's New in Version 6.0](#whats-new-in-version-60)
- [Features](#features)
  - [1. Networks](#1-networks)
  - [2. Devices](#2-devices)
  - [3. Security Scans](#3-security-scans)
  - [4. Diagnostics](#4-diagnostics)
  - [5. File Sharing](#5-file-sharing)
- [Security Risk Rating Methodology](#security-risk-rating-methodology)
- [Technologies and Libraries Used](#technologies-and-libraries-used)
- [Architecture and Methodology Notes](#architecture-and-methodology-notes)
- [Repository Structure](#repository-structure)
- [Runtime Data and Exports](#runtime-data-and-exports)
- [Requirements](#requirements)
- [Installation: Running a Prebuilt Executable](#installation-running-a-prebuilt-executable)
- [Installation: Running from Source](#installation-running-from-source)
- [Building a Windows Executable](#building-a-windows-executable)
  - [Manual Build Using the Spec File](#manual-build-using-the-spec-file)
- [Known Limitations and Troubleshooting](#known-limitations-and-troubleshooting)
- [Disclaimer](#disclaimer)

## What's New in Version 6.0

- **Five sidebar pages:** Networks, Devices, Security scans, Diagnostics, and File sharing.
- **Connection context:** the current interface and IPv4 address remain visible, with an indicator for standard or Administrator access.
- **Embedded workflows:** discovery, its device map, continuous ping, monitoring, and logging are accessible inside the main window.
- **Structured scan results:** separate results, raw output, and run details; selected-service evidence; TXT and CSV exports.
- **Clear device states:** Unreviewed, Known, Newly observed, Address changed, and Missing.
- **Per-subnet baselines and per-session logs:** stored in the user's local application-data folder.
- **Explicit activity controls:** start/stop actions and status feedback for background tools, including coordinated shutdown when the window closes.

## Features

### 1. Networks

Manage wireless connections and wired adapters from a sortable list with a selected-network details panel.

- **Wi-Fi discovery:** uses Windows' native WLAN API (`wlanapi.dll`), with a `netsh wlan` fallback.
- **Wired adapters:** shows available wired interfaces, including virtual adapters exposed by the underlying Windows commands.
- **Contextual actions:** connect or disconnect Wi-Fi, enable or disable wired adapters, and copy connection details.
- **Saved and new profiles:** connect using an existing Windows Wi-Fi profile, or create a supported open/WPA2-Personal profile when joining a new network.
- **Connect strongest saved:** chooses the strongest saved network among the currently displayed Wi-Fi results. Refresh first to update the candidates.
- **Adapter settings:** inspect the adapter and MAC address, switch to DHCP, or apply a manual IPv4 address, subnet mask, gateway, and DNS configuration. Configuration changes require Administrator access.
- **Auto-refresh:** optional refresh every 15 seconds, with overlapping refresh jobs prevented.
- **Stable selection:** a refresh preserves the selected network when it is still available.

The redesigned interface uses text labels for network types. It does **not** load or require the previous `wifi_icon.png` and `ethernet_icon.png` files.

### 2. Devices

Discover responding IPv4 hosts and review them in an embedded device list or network map.

- **Automatic subnet suggestion:** derives the local subnet from the default-route interface's IPv4 address and subnet mask; the target CIDR can be edited.
- **Bounded discovery:** accepts subnets containing at most **4,096 addresses**.
- **Concurrent ping sweep:** scales its worker pool between 25, 50, and 100 workers according to subnet size.
- **Repeated discovery:** waits 30 seconds between completed sweeps; the total cycle also includes discovery time.
- **Device information:** combines responding addresses, ARP-derived MAC addresses, reverse DNS, a small internal MAC-vendor table, and a TTL-based OS-family estimate.
- **List and map views:** the map places the gateway at the center and responding hosts around it. Graph rendering is limited to 100 nodes; larger discoveries remain available in the list.
- **Per-subnet baseline:** save the current responding devices as an IP-to-MAC reference for that subnet. Saving again replaces the baseline after confirmation.
- **Change history:** newly observed addresses and changed IP-to-MAC mappings are recorded in a timestamped, deduplicated `security_alerts.log`, accessible from the application.
- **Follow-up actions:** copy device details or send a selected address to the Ping or Security scans page. Selecting these actions fills the target without automatically starting a test.

| State | Meaning |
|---|---|
| Unreviewed | No saved baseline is available for comparison. |
| Known | The observed address and MAC match the saved baseline. |
| Newly observed | The responding address is absent from the baseline. |
| Address changed | The observed MAC differs from the baseline for that IP. |
| Missing | A baselined address did not respond in the current discovery. |

These states describe observations. DHCP reassignment, MAC randomization, sleeping devices, and blocked ping responses can explain changes. An address change does not by itself establish spoofing or an intrusion. The map illustrates discovered hosts around a gateway; it does not discover physical switch links or network paths.

### 3. Security Scans

A graphical front end for [Nmap](https://nmap.org/), with structured results and live output.

#### Scan Presets

| Preset | Arguments |
|---|---|
| Fast Scan | `-T4 --max-retries 1 --min-rate 1000 -F` |
| Service Version Detection | `-sV` |
| OS Detection | `-O` |
| Aggressive | `-A` |
| Full TCP | `-p-` |
| Custom | Supply your own flags. |

- **Flexible targets:** enter an IP address, hostname, CIDR subnet, or multiple whitespace-separated targets.
- **Extra flags:** extend a single scan with additional Nmap options. Netversity manages XML output itself, so `-oX`, `-oA`, and `--resume` are reserved.
- **Built-in reference:** the Flags reference covers scan techniques, timing, service/OS detection, and Nmap Scripting Engine categories such as `vuln`, `safe`, `intrusive`, `discovery`, `auth`, and `brute`. Examples include `http-title`, `smb-vuln-ms17-010`, `ftp-anon`, and `ssl-enum-ciphers`.
- **Live raw output:** follow the scan while it runs and stop an active scan from the interface.
- **Structured results:** inspect host, port/protocol, exact Nmap state, service, and review priority. Selecting a result shows available version information and script evidence.
- **Run details:** inspect per-method host status and host/port counts separately from the service table.
- **Export TXT:** save the retained raw output.
- **Export CSV:** save structured results with Host, Port, State, Service, Review priority, Version, and Evidence columns.

#### Compare Methods

Choose **Compare methods** and select one or more techniques:

| Method | Arguments | Purpose |
|---|---|---|
| SYN | `-sS -T4` | TCP SYN scanning |
| UDP | `-sU -T4` | UDP service discovery |
| ARP discovery | `-sn -PR` | Local-network host discovery |

Selected methods run sequentially against the same targets. Comparison mode requires Administrator access and uses these fixed method arguments; the single-scan preset and extra flags do not apply.

Results appear in the service table and **Comparison / run details** view. This version does not generate the previous textual TCP/UDP-overlap report or append an overall security verdict. ARP discovery is a host-discovery method and does not produce a port inventory.

### 4. Diagnostics

Diagnostics groups **Live monitor**, **Ping**, and **Logging** into one page.

#### Live Monitor

- **Gateway latency:** measures round-trip time to the active interface's default gateway.
- **Jitter:** standard deviation of the last 10 successful latency samples; requires at least two successful readings.
- **Packet loss:** calculated over the last 20 ping outcomes.
- **Download/upload throughput:** calculated from adapter byte-counter changes using PowerShell's `Get-NetAdapterStatistics`.
- **Configurable interval:** 1–60 seconds, with a default of one second. Command execution time can extend the effective interval.
- **Live charts:** retain up to 60 samples, with automatically scaled throughput and latency axes. Unavailable measurements appear as gaps.
- **Connection changes:** refreshes interface/gateway information periodically and resets history when the monitored connection changes.

Ping and adapter-counter collection run in parallel. The monitor measures local gateway reachability and adapter traffic; it is not an Internet speed test or a direct measurement of end-to-end Internet quality.

#### Ping

- Continuous ping against an IP address or hostname.
- Embedded output with Start, Stop, and Clear controls.
- Running sent/received counts, packet-loss percentage, and minimum/average/maximum round-trip time.
- A nominal one-second cycle; actual timing depends on replies and command duration.

#### Logging

- Start and stop a CSV logging session from the interface.
- Each session creates `network_log_YYYYMMDD_HHMMSS.csv`.
- Columns: `Timestamp`, `Interface`, `SSID`, `Signal (%)`, and `Latency (ms)`.
- Waits two seconds between collection iterations; Windows queries add to the sampling interval.
- Wi-Fi signal is a **percentage**, not RSSI in dBm. Wireless fields are empty when the active connection is wired.

### 5. File Sharing

Serve a selected local folder over HTTP for simple LAN downloads.

- **Explicit folder selection:** choose the directory to expose before starting.
- **Configurable port:** defaults to `8000`; accepts ports from 1 to 65535.
- **Server states:** Starting, Running, Stopping, or Failed, with configuration controls locked while active.
- **Concurrent requests:** a threaded server handles multiple clients.
- **Copy URL:** copies the address generated from the active IPv4 address and chosen port.
- **Request log:** displays incoming requests in the application.
- **Background stop:** shuts down the server without blocking the main interface.

The server listens on local interfaces and provides plain HTTP without authentication, TLS, or an upload interface. Every accessible file in the chosen directory is potentially available to clients that can reach the port. Use a dedicated sharing folder on a trusted network. Windows Firewall and network isolation rules still control remote reachability.

## Security Risk Rating Methodology

The **Review** column provides a port-based exposure priority. It helps identify services worth investigating; it is not a vulnerability confirmation, CVE detector, or overall host-security score.

### Named Port Profiles

Ports whose exact Nmap state is `open` receive a classification from `PORT_RISK_INFO`:

| Port | Priority | Common service | Review rationale |
|---|---|---|---|
| 21 | HIGH | FTP | Credentials and file transfers may be unencrypted. |
| 23 | HIGH | Telnet | Unencrypted remote administration. |
| 137 | HIGH | NetBIOS Name Service | Legacy discovery and information exposure. |
| 138 | HIGH | NetBIOS Datagram Service | Legacy Windows discovery traffic. |
| 139 | HIGH | NetBIOS Session Service | SMB over NetBIOS creates a sensitive service exposure. |
| 445 | HIGH | SMB | Restrict access and verify configuration and patching. |
| 3389 | HIGH | RDP | Review remote-access exposure, authentication, and patching. |
| 80 | MEDIUM | HTTP | Check whether sensitive data travels without encryption. |
| 1433 | MEDIUM | MSSQL | Restrict database access to intended clients. |
| 3306 | MEDIUM | MySQL | Restrict database access to intended clients. |
| 1521 | MEDIUM | Oracle DB | Restrict database access to intended clients. |
| 5900 | MEDIUM | VNC | Review remote-desktop authentication and encryption. |
| 53 | LOW | DNS | Confirm the service is intended and check recursion policy. |
| 443 | LOW | HTTPS | Review the actual service, TLS configuration, and application. |
| 123 | LOW | NTP | Verify intended access and configuration. |

The service names above describe conventional port assignments. The priority is based on the port number, not proof of the detected service's configuration or vulnerability. LOW does not mean safe, and HIGH does not mean compromised.

### Fallback Classification

The classifier also checks `HIGH_RISK_PORTS`, `MEDIUM_RISK_PORTS`, and `LOW_RISK_PORTS`. An open port without a listed classification receives **INFO**: confirm that the service is intended to be reachable.

### Result Processing

1. Nmap writes an application-managed temporary XML report while its console output streams into the interface.
2. Netversity parses host, port/protocol, state, service/version, and available port-script evidence from XML.
3. Only the exact state `open` receives a port-based priority. Other states, including `open|filtered`, receive **Unconfirmed**.
4. The interface presents structured rows, selected-result evidence, and separate run details. TXT and CSV exports preserve raw output and structured findings respectively.

Comparison scans use the same result-processing path. The application does not append the old `SECURITY RISK ASSESSMENT` banner, severity tallies, or overall HIGH/MEDIUM/LOW verdict to the raw report.

## Technologies and Libraries Used

| Component | Technology |
|---|---|
| Language | Python 3.10+ |
| Desktop interface | Tkinter / ttk |
| Security scanning | [Nmap](https://nmap.org/), installed separately |
| Graphs | [NetworkX](https://networkx.org/) and [Matplotlib](https://matplotlib.org/), using `FigureCanvasTkAgg` |
| Wi-Fi access | Native `wlanapi.dll` through `ctypes`, with `netsh` fallback |
| Windows networking | `netsh`, `ipconfig`, `arp`, `ping`, and PowerShell networking cmdlets |
| HTTP serving | Standard-library `http.server` / `socketserver` |
| Background work | `threading`, `ThreadPoolExecutor`, and `queue.Queue` |
| Structured data | JSON baselines, CSV exports/logs, and Nmap XML parsing |
| Executable packaging | [PyInstaller](https://pyinstaller.org/) |

Install both NetworkX and Matplotlib to enable graphs. Without them, the device list and numerical monitoring remain available. Pillow and `netifaces` remain optional legacy imports; the redesigned UI does not require them for its own image assets. Matplotlib may install Pillow as a dependency.

## Architecture and Methodology Notes

- **Background engines:** discovery, scanning, monitoring, ping, logging, and serving run independently so multiple tools can operate at once.
- **UI coordination:** queues and scheduled Tkinter callbacks deliver background results to the interface.
- **Bounded concurrency:** discovery uses a limited worker pool and a subnet-size limit instead of launching a thread for every address.
- **Independent charts:** discovery and monitoring use separate Matplotlib figures.
- **Nmap process handling:** the new scan engine starts Nmap directly with an argument list, manages temporary XML output, and terminates the active Nmap process on cancellation.
- **Input handling:** adapter settings validate IPv4 fields; generated Wi-Fi profile XML escapes SSIDs/passwords; scan output options managed by the app cannot be overridden through the reserved flags.
- **Shutdown:** the window's close button signals the background engines to stop, cancels scans, stops the HTTP listener, and closes the UI. In-flight Windows commands may take a short time to finish.

A live Windows shutdown check ran discovery, Nmap, monitoring, continuous ping, CSV logging, and HTTP serving together. After closing with the **X** button, the application and tracked subprocesses were gone by the 1.52-second observation, port 8000 had no listener, and no tracked processes reappeared during the 30-second observation period. This verifies that tested source run; packaged builds and other environments should also be checked.

## Repository Structure

The commands below use this layout and the new source filename, `Netversity_new.py`. If the source is stored at the repository root or renamed, adjust the paths accordingly. Executables and build files are optional distribution artifacts.

```text
Netversity/
├── Source/
│   └── Netversity.py       # Version 6.0 application
├── assets/                   # Optional packaging / legacy assets
│   ├── icon.png              # Optional Windows executable icon
│   ├── wifi_icon.png         # Legacy; not loaded by the new UI
│   └── ethernet_icon.png     # Legacy; not loaded by the new UI
├── build_scripts/
│   └── netversity.spec       # Optional; must target the new source
├── requirements.txt          # Optional dependency list
├── Netversity.exe            # Optional published Windows build
├── README.md
└── .gitignore
```

## Runtime Data and Exports

Application-managed data is stored in:

```text
%LOCALAPPDATA%\Netversity\
```

If `LOCALAPPDATA` is unavailable, the application uses a `Netversity` folder under the user's home directory.

| File | Contents |
|---|---|
| `baseline_192.168.1.0_24.json` | Example per-subnet IP-to-MAC baseline. |
| `security_alerts.log` | Plain timestamped text for observed device changes. |
| `network_log_YYYYMMDD_HHMMSS.csv` | One network-quality logging session. |

TXT and CSV scan exports are saved to a location selected by the user. Nmap XML reports and newly generated Wi-Fi profile XML use temporary files. The HTTP request log is displayed in the UI and is not automatically saved to disk.

Older `topology_baseline.json` and `wifi_log.csv` files beside the script/executable are not automatically migrated. Create a new baseline for each subnet and start a new logging session after upgrading. Runtime data and exported network reports do not need to be committed to the repository.

## Requirements

- **Windows 10 or 11:** the application depends on Windows APIs and utilities.
- **Python 3.10+ with Tkinter:** required when running from source; not required for a packaged executable.
- **NetworkX and Matplotlib:** needed for the device map and monitoring charts.
- **Nmap:** required for Security scans; other tools can operate without it. Detection checks `PATH`, common install locations, and Windows registry information.
- **Npcap and appropriate privileges:** needed for relevant Windows Nmap packet-based scan methods. See the official [Nmap Windows installation guide](https://nmap.org/book/inst-windows.html).
- **Administrator access:** required for adapter configuration, wired-adapter enable/disable, and comparison mode; privileged Nmap methods such as SYN and OS detection also need suitable permissions.

The Python script does not automatically elevate itself. For privileged actions, launch it from an Administrator terminal or use **Run as administrator** for a packaged executable. A build configured to request elevation will display a UAC prompt on launch.

## Installation: Running a Prebuilt Executable

If a version 6.0 Windows executable is supplied with the repository or a release:

1. Download and extract the published build as needed.
2. Install [Nmap for Windows](https://nmap.org/download.html) if you intend to use Security scans.
3. Launch `Netversity.exe`.
4. For privileged operations, use **Run as administrator**, or accept the UAC prompt if that build requests elevation.

Python is not needed for a packaged executable. Nmap is installed separately. An older executable does not acquire the new interface merely because the Python source has been updated; rebuild it from version 6.0.

## Installation: Running from Source

Install Python 3.10+ with Tcl/Tk support, then clone or download the repository. From the repository root, create an isolated environment and install the graph dependencies:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install matplotlib networkx
.\.venv\Scripts\python.exe .\Source\Netversity_new.py
```

If the repository includes an up-to-date `requirements.txt`, its installation command can replace the explicit dependency installation:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Tkinter comes with a suitable Windows Python installation; it is not installed with `pip install tkinter`. Install Nmap separately for scanning. To run with Administrator access, open an elevated terminal and execute the same launch command from the repository directory.

## Building a Windows Executable

Build on Windows using the environment containing the application dependencies. From the repository root:

```powershell
.\.venv\Scripts\python.exe -m pip install pyinstaller
.\.venv\Scripts\python.exe -m PyInstaller --clean --onefile --windowed --name Netversity --hidden-import matplotlib.backends.backend_tkagg .\Source\Netversity_new.py
```

The output is `dist\Netversity.exe`; temporary build files are placed in `build\`. Add `--icon .\assets\icon.ico` if that icon exists. Add `--uac-admin` if the executable should request Administrator access at every launch. See the [PyInstaller command reference](https://pyinstaller.org/en/stable/usage.html).

No `--add-data` options are needed for `wifi_icon.png` or `ethernet_icon.png`. Nmap and its driver installation are separate from this build.

### Manual Build Using the Spec File

Before reusing the previous `build_scripts/netversity.spec`:

1. Point `Analysis` at `..\\Source\\Netversity_new.py` instead of the previous source file.
2. Remove the legacy Wi-Fi/Ethernet image entries from `datas`; use `datas=[]` if no other data files are needed.
3. Keep the `matplotlib.backends.backend_tkagg` hidden import and `console=False`.
4. Set the icon path to an existing asset, or omit the custom icon. The previous spec may use `icon.png`; do not assume it matches an `icon.ico` filename in the README.
5. Keep `uac_admin=True` only if every launch should request elevation.

Then build from the spec directory:

```powershell
Set-Location .\build_scripts
..\.venv\Scripts\python.exe -m PyInstaller --clean .\netversity.spec
```

With default output paths, this produces `build_scripts\dist\Netversity.exe` and intermediate files under `build_scripts\build\`. Rebuild after source changes and check the packaged application's workflows before distribution. Spec files carry their own build settings; see [PyInstaller's spec-file documentation](https://pyinstaller.org/en/stable/spec-files.html).

## Known Limitations and Troubleshooting

- **Windows only:** Linux and macOS are unsupported. Windows utility output and behavior may vary with system configuration and language.
- **Nmap unavailable:** install it separately, then restart Netversity. Confirm it is on `PATH` or in a detected installation location. Nmap/Npcap are not bundled with the app.
- **Permission failures:** relaunch with Administrator access for privileged operations. Source mode does not trigger automatic elevation.
- **Graphs unavailable:** install both `matplotlib` and `networkx` in the Python environment used to run or package the app.
- **Wi-Fi authentication:** new-profile creation covers open and WPA2-Personal networks. Configure enterprise or other unsupported authentication profiles through Windows, then use the saved profile.
- **Incomplete discovery:** sleeping hosts, firewalls, and ICMP filtering can hide devices. MAC addresses are generally available only where local ARP information exists. Discovery is IPv4-based and limited to 4,096 addresses.
- **Heuristic device details:** TTL-derived OS guesses and the small vendor-prefix table are illustrative, not authoritative identification. A map is limited to 100 nodes.
- **Baseline interpretation:** address changes and missing devices can be benign. The UI does not reproduce the former flashing intrusion banner or audible alarm.
- **Scan interpretation:** port priorities do not confirm vulnerabilities. Fast scans can miss services, and UDP scans can be slow or ambiguous. Stopping a scan can leave incomplete XML, so structured results may be unavailable even when raw output exists.
- **Display limits:** the visible Nmap output is bounded, while TXT export retains the full collected raw text. Ping and HTTP request views also limit displayed lines.
- **Sampling cadence:** ping, PowerShell, and other command durations affect update intervals. Unavailable gateway measurements are not proof of an Internet outage.
- **HTTP reachability:** verify the selected folder, an unused port, the active IP address, firewall rules, and client network access. The server has no authentication or encryption.
- **Storage:** automatic logs and baselines need a writable application-data directory. Legacy files are not automatically migrated, and accumulated session logs may need manual cleanup.

## Disclaimer

Netversity includes active discovery and scanning tools intended for systems and networks **you own or have explicit authorization to test**. Use scan flags and NSE scripts appropriate to that authorization, especially intrusive or authentication-related scripts.

Findings require interpretation and verification. Device-change alerts and port-based priorities are observations and heuristics, not proof of an attack or a complete security assessment. Use responsibly and follow applicable rules for the systems you administer.
