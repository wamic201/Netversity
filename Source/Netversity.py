# Netversity_new.py — redesigned standalone Windows network workspace
# Based on the supplied Netversity.py; Python 3.10+ and Tkinter required.
# Optional graphs: pip install matplotlib networkx pillow
# Nmap must be installed separately for security scans.
# Netversity_R5_3.py
# Network Manager (Windows) - Full Suite
# Features: 
# - Unified Wired/Wireless Management
# - Nmap Vulnerability Scanning + Comparison Engine
# - HTTP File Server
# - Intelligent Topology (Performance Optimized: ThreadPool + Background Status)
# - Network Performance Logging
# - Network Monitor: Latency, Jitter, Packet Loss, Throughput, Live Activity Graph
#   (R5.2: crash fixes — safe throughput via PowerShell in parallel thread,
#    isolated matplotlib Figure to eliminate renderer race with TopoWindow,
#    redesigned minimalist dashboard layout)
# - Ping Tool: continuous ping -t style window (Networks tab)
 
import ctypes
from ctypes import wintypes
import subprocess
import tempfile
import os
import sys
import re
import time
import threading
from typing import List, Dict, Optional, Tuple
import json
import queue
import ipaddress
import socket
import csv
from datetime import datetime
from shutil import which
from functools import partial
from xml.sax.saxutils import escape as xml_escape
import http.server
import socketserver
import winreg
import statistics
# NEW: Optimized Thread Management
from concurrent.futures import ThreadPoolExecutor
 
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog, scrolledtext
 
# Try to import PIL for better image scaling
try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
 
# Optional third-party libs for Network Discovery
try:
    import netifaces
except Exception:
    netifaces = None
 
try:
    import networkx as nx
    import matplotlib.pyplot as plt
    import matplotlib.figure as mpl_figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except Exception:
    nx = None
    plt = None
    mpl_figure = None
    FigureCanvasTkAgg = None
 
# ---------------------------
# Topology Constants & Heuristics
# ---------------------------
 
MAC_VENDORS = {
    "BC:D0:74": "Apple",
    "DC:A9:04": "Apple",
    "00:0C:29": "VMware",
    "00:50:56": "VMware",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "00:1A:11": "Google",
    "24:77:03": "Intel",
    "18:FE:34": "Espressif (IoT)",
    "60:01:94": "Espressif (IoT)",
    "00:E0:4C": "Realtek",
    "D4:3D:7E": "Micro-Star (MSI)",
    "00:D8:61": "Dell",
}
 
def get_vendor(mac_addr):
    if not mac_addr: return "Unknown"
    prefix = mac_addr.upper()[:8]
    return MAC_VENDORS.get(prefix, "Generic")

def resource_path(relative_path: str) -> str:
    """
    Resolve a bundled resource path (icons, etc.) so it works both when
    running as a plain .py script and when frozen into a PyInstaller exe.

    Dev mode: resolves relative to this script's own folder.
    Frozen (--onefile) mode: PyInstaller unpacks bundled 'datas' into a
    temp folder at runtime and exposes that path via sys._MEIPASS. Using
    a bare relative path (checked against the CWD) only worked by
    coincidence in dev and silently failed once packaged, since the
    exe's CWD is wherever the user launched it from, not the bundle.
    """
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

# Suppresses the console window that would otherwise flash briefly for
# every shell/PowerShell/nmap subprocess call once the app is packaged
# without a console (--windowed). In a normal `python.exe` session this
# has no visible effect since the parent already owns a console.
_NO_WINDOW_FLAGS = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
 
def get_os_from_ttl(ttl):
    if not ttl: return "Unknown"
    if ttl <= 64: return "Linux/Mac/IoT"
    if ttl <= 128: return "Windows"
    if ttl <= 255: return "Network Gear"
    return "Unknown"
 
# ---------------------------
# Utilities / helpers
# ---------------------------
 
 
 
def run_cmd(cmd: str) -> Tuple[int, str, str]:
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                        creationflags=_NO_WINDOW_FLAGS)
    return p.returncode, p.stdout, p.stderr
 
def is_admin() -> bool:
    try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception: return False
 
def signal_to_bars(pct: int) -> str:
    if pct <= 0: return "▁ (0%)"
    if pct <= 20: return f"▁ ({pct}%)"
    if pct <= 40: return f"▂ ({pct}%)"
    if pct <= 60: return f"▃ ({pct}%)"
    if pct <= 80: return f"▅ ({pct}%)"
    return f"▇ ({pct}%)"
 
def is_open_auth(auth_str: str) -> bool:
    if not auth_str: return False
    s = str(auth_str).strip().lower()
    return s == "open" or s.startswith("open")
 
def measure_latency(target_ip):
    try:
        cmd = ['ping', '-n', '1', '-w', '1000', str(target_ip)]
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        proc = subprocess.run(cmd, capture_output=True, text=True, startupinfo=startupinfo)
        if proc.returncode == 0:
            m = re.search(r'time[=<](\d+)ms', proc.stdout, re.IGNORECASE)
            if m: return int(m.group(1))
            elif "time<1ms" in proc.stdout.lower(): return 1
    except: pass
    return None
 
# ---------------------------
# Wired / Interface Parsing
# ---------------------------
 
def get_wired_interfaces() -> List[Dict]:
    code, out, err = run_cmd('netsh interface show interface')
    if code != 0: return []
    interfaces = []
    for line in out.splitlines():
        if "Interface Name" in line or "---" in line: continue
        parts = line.split(maxsplit=3)
        if len(parts) == 4:
            admin_state, state, type_, name = parts
            if "Wi-Fi" in name or "Wireless" in name or "Loopback" in name: continue
            interfaces.append({
                "type": "wired", "name": name, "ssid": name,
                "admin_state": admin_state, "state": state,
                "signal": 100 if state == "Connected" else 0, "auth": "Ethernet"
            })
    return interfaces
 
 
 
# ---------------------------
# netsh parsing utilities (WiFi)
# ---------------------------
 
def parse_scan_output(out: str) -> List[Dict]:
    networks = {}
    current_ssid = None
    for line in out.splitlines():
        s = line.strip()
        m = re.match(r"SSID\s+\d+\s*:\s*(.*)$", s, re.IGNORECASE)
        if m:
            current_ssid = m.group(1).strip()
            if current_ssid and current_ssid not in networks:
                networks[current_ssid] = {"ssid": current_ssid, "signal": 0, "auth": "Unknown", "type": "wifi"}
            continue
        if s.lower().startswith("authentication"):
            parts = s.split(":", 1)
            if len(parts) == 2 and current_ssid: networks[current_ssid]["auth"] = parts[1].strip()
            continue
        if s.lower().startswith("signal"):
            m2 = re.search(r"(\d+)\s*%", s)
            if m2 and current_ssid:
                val = int(m2.group(1))
                if val > networks[current_ssid]["signal"]: networks[current_ssid]["signal"] = val
            continue
    nets = list(networks.values())
    nets.sort(key=lambda x: x["signal"], reverse=True)
    return nets
 
def list_saved_profiles() -> List[str]:
    code, out, err = run_cmd('netsh wlan show profiles')
    if code != 0: return []
    profiles = []
    for line in out.splitlines():
        s = line.strip()
        if "All User Profile" in s or s.startswith("User Profile"):
            parts = s.split(":", 1)
            if len(parts) == 2: profiles.append(parts[1].strip())
    return profiles
 
def parse_status(out: str) -> Dict[str, str]:
    data = {}
    fields = ["State", "SSID", "BSSID", "Authentication", "Receive rate (Mbps)",
              "Transmit rate (Mbps)", "Signal", "Profile", "Physical address"]
    for line in out.splitlines():
        s = line.strip()
        for f in fields:
            if s.lower().startswith(f.lower()):
                parts = s.split(":", 1)
                if len(parts) == 2: data[f] = parts[1].strip()
    return data
 
def wifi_interface_alias() -> Optional[str]:
    code, out, err = run_cmd('netsh wlan show interfaces')
    if code != 0: return None
    m = re.search(r'^\s*Name\s*:\s*(.+)$', out, flags=re.MULTILINE)
    return m.group(1).strip() if m else None
 
 
 
def add_temp_profile_and_connect(ssid: str, password: str) -> bool:
    safe_ssid = xml_escape(ssid)
    safe_password = xml_escape(password)
    xml = f'''<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>{safe_ssid}</name>
  <SSIDConfig><SSID><name>{safe_ssid}</name></SSID></SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>manual</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2PSK</authentication>
        <encryption>AES</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>{safe_password}</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
</WLANProfile>
'''
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xml", mode="w", encoding="utf-8") as f:
        f.write(xml)
        tmp_path = f.name
    try:
        code1, _, _ = run_cmd(f'netsh wlan add profile filename="{tmp_path}" user=current')
        if code1 != 0: return False
        code2, _, _ = run_cmd(f'netsh wlan connect name="{ssid}" ssid="{ssid}"')
        return code2 == 0
    finally:
        try: os.remove(tmp_path)
        except: pass
 
def connect(ssid: str, password: Optional[str] = None) -> bool:
    profiles = list_saved_profiles()
    if ssid in profiles: return connect_with_existing_profile(ssid)
    code, _, _ = run_cmd(f'netsh wlan connect ssid="{ssid}" name="{ssid}"')
    if code == 0: return True
    if password: return add_temp_profile_and_connect(ssid, password)
    return False
 
 
def current_status() -> Dict[str, str]:
    code, out, _ = run_cmd('netsh wlan show interfaces')
    if code != 0: return {}
    return parse_status(out)
 
# ---------------------------
# Native wlanapi
# ---------------------------
try:
    wlanapi = ctypes.WinDLL('wlanapi')
    WLAN_CLIENT_VERSION_LONGHORN = 2
    ERROR_SUCCESS = 0
    class GUID(ctypes.Structure): _fields_ = [('Data1', wintypes.DWORD), ('Data2', wintypes.WORD), ('Data3', wintypes.WORD), ('Data4', ctypes.c_ubyte * 8)]
    class WLAN_INTERFACE_INFO(ctypes.Structure): _fields_ = [('InterfaceGuid', GUID), ('strInterfaceDescription', wintypes.WCHAR * 256), ('isState', wintypes.DWORD)]
    class WLAN_INTERFACE_INFO_LIST(ctypes.Structure): _fields_ = [('dwNumberOfItems', wintypes.DWORD), ('dwIndex', wintypes.DWORD), ('InterfaceInfo', WLAN_INTERFACE_INFO * 1)]
    class DOT11_SSID(ctypes.Structure): _fields_ = [('uSSIDLength', wintypes.ULONG), ('ucSSID', ctypes.c_ubyte * 32)]
    class WLAN_AVAILABLE_NETWORK(ctypes.Structure):
        _fields_ = [('strProfileName', wintypes.WCHAR * 256), ('dot11Ssid', DOT11_SSID), ('dot11BssType', wintypes.DWORD),
                    ('uNumberOfBssids', wintypes.ULONG), ('bNetworkConnectable', wintypes.BOOL), ('wlanNotConnectableReason', wintypes.DWORD),
                    ('uNumberOfPhyTypes', wintypes.ULONG), ('dot11PhyTypes', wintypes.DWORD * 8), ('bMorePhyTypes', wintypes.BOOL),
                    ('wlanSignalQuality', wintypes.DWORD), ('bSecurityEnabled', wintypes.BOOL), ('dot11DefaultAuthAlgorithm', wintypes.DWORD),
                    ('dot11DefaultCipherAlgorithm', wintypes.DWORD), ('dwFlags', wintypes.DWORD), ('dwReserved', wintypes.DWORD)]
    class WLAN_AVAILABLE_NETWORK_LIST(ctypes.Structure): _fields_ = [('dwNumberOfItems', wintypes.DWORD), ('dwIndex', wintypes.DWORD), ('Network', WLAN_AVAILABLE_NETWORK * 1)]
 
    WlanOpenHandle = wlanapi.WlanOpenHandle
    WlanOpenHandle.argtypes = [wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_void_p)]
    WlanOpenHandle.restype = wintypes.DWORD
    WlanCloseHandle = wlanapi.WlanCloseHandle
    WlanCloseHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    WlanCloseHandle.restype = wintypes.DWORD
    WlanEnumInterfaces = wlanapi.WlanEnumInterfaces
    WlanEnumInterfaces.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    WlanEnumInterfaces.restype = wintypes.DWORD
    WlanFreeMemory = wlanapi.WlanFreeMemory
    WlanFreeMemory.argtypes = [ctypes.c_void_p]
    WlanFreeMemory.restype = None
    WlanScan = wlanapi.WlanScan
    WlanScan.argtypes = [ctypes.c_void_p, ctypes.POINTER(GUID), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    WlanScan.restype = wintypes.DWORD
    WlanGetAvailableNetworkList = wlanapi.WlanGetAvailableNetworkList
    WlanGetAvailableNetworkList.argtypes = [ctypes.c_void_p, ctypes.POINTER(GUID), wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    WlanGetAvailableNetworkList.restype = wintypes.DWORD
except: wlanapi = None
 
def aggressive_scan_native(timeout_sec: float = 5.0) -> List[Dict]:
    if wlanapi is None: raise RuntimeError("Native WLAN API not available")
    negotiated, client_handle = wintypes.DWORD(0), ctypes.c_void_p()
    ret = WlanOpenHandle(WLAN_CLIENT_VERSION_LONGHORN, None, ctypes.byref(negotiated), ctypes.byref(client_handle))
    if ret != ERROR_SUCCESS: raise RuntimeError(f"WlanOpenHandle failed: {ret}")
    iface_list_ptr = ctypes.c_void_p()
    try:
        ret = WlanEnumInterfaces(client_handle, None, ctypes.byref(iface_list_ptr))
        if ret != ERROR_SUCCESS: raise RuntimeError(f"WlanEnumInterfaces failed: {ret}")
        iface_list = ctypes.cast(iface_list_ptr, ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)).contents
        if iface_list.dwNumberOfItems == 0: return []
        first_iface = ctypes.cast(ctypes.addressof(iface_list.InterfaceInfo), ctypes.POINTER(WLAN_INTERFACE_INFO)).contents
        WlanScan(client_handle, ctypes.byref(first_iface.InterfaceGuid), None, None, None)
        time.sleep(timeout_sec)
        avail_ptr = ctypes.c_void_p()
        ret = WlanGetAvailableNetworkList(client_handle, ctypes.byref(first_iface.InterfaceGuid), 0, None, ctypes.byref(avail_ptr))
        if ret != ERROR_SUCCESS: raise RuntimeError(f"WlanGetAvailableNetworkList failed: {ret}")
        try:
            avail = ctypes.cast(avail_ptr, ctypes.POINTER(WLAN_AVAILABLE_NETWORK_LIST)).contents
            base = ctypes.addressof(avail.Network)
            stride = ctypes.sizeof(WLAN_AVAILABLE_NETWORK)
            best = {}
            for i in range(avail.dwNumberOfItems):
                item = ctypes.cast(base + i * stride, ctypes.POINTER(WLAN_AVAILABLE_NETWORK)).contents
                ssid = bytes(item.dot11Ssid.ucSSID[:item.dot11Ssid.uSSIDLength]).decode('utf-8', errors='ignore').strip()
                if not ssid: continue
                signal = int(item.wlanSignalQuality)
                auth = "Secure" if bool(item.bSecurityEnabled) else "Open"
                if ssid not in best or signal > best[ssid]["signal"]:
                    best[ssid] = {"ssid": ssid, "signal": signal, "auth": auth, "type": "wifi"}
            netsh_auth = auth_map_from_netsh()
            for ssid, data in best.items():
                if ssid in netsh_auth: data["auth"] = netsh_auth[ssid]
            nets = list(best.values())
            nets.sort(key=lambda x: x["signal"], reverse=True)
            return nets
        finally: WlanFreeMemory(avail_ptr)
    finally:
        WlanFreeMemory(iface_list_ptr)
        WlanCloseHandle(client_handle, None)
 
def scan_burst(max_tries: int = 4, pause_sec: float = 2.5) -> List[Dict]:
    combined, last_err = {}, None
    for i in range(max_tries):
        try:
            code, out, _ = run_cmd('netsh wlan show networks mode=bssid')
            if code == 0:
                for n in parse_scan_output(out):
                    if n["ssid"] not in combined or n["signal"] > combined[n["ssid"]]["signal"]: combined[n["ssid"]] = n
            else: last_err = "Netsh error"
        except Exception as e: last_err = str(e)
        if len(combined) >= 2 and i > 0: break
        time.sleep(pause_sec)
    nets = list(combined.values())
    nets.sort(key=lambda x: x["signal"], reverse=True)
    return nets
 
def auth_map_from_netsh() -> dict:
    code, out, _ = run_cmd('netsh wlan show networks mode=bssid')
    if code != 0: return {}
    return {n["ssid"]: n.get("auth", "Unknown") for n in parse_scan_output(out) if n.get("ssid")}
 
def auto_reconnect_strongest_known() -> Optional[str]:
    try: nets = aggressive_scan_native(5.0)
    except: nets = scan_burst(4, 2.5)
    profiles = set(list_saved_profiles())
    known = [n for n in nets if n["ssid"] in profiles]
    if not known: return None
    target = max(known, key=lambda x: x["signal"])
    return target["ssid"] if connect_with_existing_profile(target["ssid"]) else None
 
# ---------------------------
# IMPROVED Network Discovery engine (Topology)
# ---------------------------
 
def _get_default_iface_gateway():
    try:
        out = subprocess.check_output(['ipconfig', '/all'], text=True, errors='ignore',
                                       creationflags=_NO_WINDOW_FLAGS)
        adapters = re.split(r'\r?\n\r?\n', out)
        for a in adapters:
            if 'Default Gateway' in a and ('IPv4 Address' in a or 'IPv4' in a):
                m_gw = re.search(r'Default Gateway[^\r\n:]*:\s*([0-9.]+)', a)
                m_ip = re.search(r'IPv4 Address[^\r\n:]*:\s*([0-9.]+)', a)
                m_mask = re.search(r'Subnet Mask[^\r\n:]*:\s*([0-9.]+)', a)
                if m_ip and m_mask and m_gw:
                    ip, mask, gw = m_ip.group(1).strip(), m_mask.group(1).strip(), m_gw.group(1).strip()
                    net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                    name_line = a.splitlines()[0].strip()
                    return str(net), ip, gw, name_line
    except Exception: pass
    return None, None, None, None
 
def _ping_details(ip):
    """Returns (is_alive, ttl)."""
    cmd = ['ping', '-n', '1', '-w', '200', str(ip)]
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        proc = subprocess.run(cmd, capture_output=True, text=True, startupinfo=startupinfo)
        if proc.returncode == 0:
            m = re.search(r'TTL=(\d+)', proc.stdout, re.IGNORECASE)
            ttl = int(m.group(1)) if m else None
            return True, ttl
        return False, None
    except Exception: return False, None
 
def _arp_table():
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        out = subprocess.check_output(['arp', '-a'], text=True, errors='ignore', startupinfo=startupinfo)
    except: return {}
    res = {}
    for line in out.splitlines():
        m = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{11,})', line)
        if m:
            ip = m.group(1)
            mac = m.group(2).replace('-', ':').upper()
            res[ip] = mac
    return res
 
def _reverse_dns(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except: return None
 
class TopoEngine(threading.Thread):
    def __init__(self, cidr, gateway, baseline=None, interval=30, out_q=None):
        super().__init__(daemon=True)
        self.cidr, self.gateway = cidr, gateway
        self.baseline = baseline or {}
        self.interval = max(10, int(interval))
        self.out_q = out_q or queue.Queue()
        self._stop_evt = threading.Event()
        self._kick = threading.Event()   # allows an immediate rescan on demand
 
    def update_baseline(self, new_baseline): self.baseline = new_baseline
    def stop(self): self._stop_evt.set()
    def refresh_now(self): self._kick.set()
 
    def run(self):
        try:
            net = ipaddress.ip_network(self.cidr, strict=False)
            if net.num_addresses > 4096:
                return
            ips = [str(ip) for ip in net.hosts()]
        except ValueError: return
 
        # OPTIMIZATION: Dynamic Thread Pool
        # Scales based on network size (fast for /24, robust for /22)
        max_workers = 25
        if len(ips) > 500: max_workers = 50
        if len(ips) > 4000: max_workers = 100
 
        while not self._stop_evt.is_set():
            self._kick.clear()
            alive_results = {}
            lock = threading.Lock()
            
            # The task for a single IP
            def scan_host(ip):
                if self._stop_evt.is_set(): return
                is_alive, ttl = _ping_details(ip)
                if is_alive:
                    with lock: alive_results[ip] = ttl
 
            # Use ThreadPoolExecutor to manage threads efficiently
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                list(executor.map(scan_host, ips))
 
            arp = _arp_table()
            nodes = []
            for ip in sorted(alive_results.keys()):
                mac = arp.get(ip, "Unknown")
                ttl = alive_results[ip]
                vendor = get_vendor(mac)
                os_guess = get_os_from_ttl(ttl)
                status = "Unreviewed"
                if self.baseline:
                    status = "Known"
                    if ip not in self.baseline: status = "Newly observed"
                    elif self.baseline[ip] != mac and mac != "Unknown": status = "Address changed"
                nodes.append({'ip': ip, 'mac': mac, 'vendor': vendor, 'os': os_guess, 'status': status, 'name': _reverse_dns(ip)})
            
            if self.baseline:
                active_ips = set(alive_results.keys())
                for b_ip, b_mac in self.baseline.items():
                    if b_ip not in active_ips:
                        nodes.append({'ip': b_ip, 'mac': b_mac, 'vendor': get_vendor(b_mac), 'os': 'Offline', 'status': 'Missing', 'name': 'OFFLINE'})
 
            payload = {'nodes': nodes, 'gateway': self.gateway}
            try: self.out_q.put_nowait(payload)
            except queue.Full: pass
            
            for _ in range(self.interval):
                if self._stop_evt.is_set(): break
                if self._kick.wait(timeout=1):
                    break
 
 
# ---------------------------
# Nmap Vulnerability Assessment
# ---------------------------
 
def find_nmap_binary() -> Optional[str]:
    path_in_env = which('nmap')
    if path_in_env: return path_in_env
    common_paths = [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe", os.path.expandvars(r"%LOCALAPPDATA%\Programs\Nmap\nmap.exe")]
    for p in common_paths:
        if os.path.exists(p): return p
    try:
        registry_paths = [(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Nmap"), (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Nmap")]
        for hkey, subkey in registry_paths:
            try:
                with winreg.OpenKey(hkey, subkey) as key:
                    install_dir, _ = winreg.QueryValueEx(key, "InstallDir")
                    nmap_exe = os.path.join(install_dir, "nmap.exe")
                    if os.path.exists(nmap_exe): return nmap_exe
            except: continue
    except: pass
    return None
 
def nmap_installed() -> bool: return find_nmap_binary() is not None
 
NMAP_PRESETS = {"Fast Scan (-T4)": "-T4 --max-retries 1 --min-rate 1000 -F", "Service Version (-sV)": "-sV", "OS Detection (-O)": "-O", "Aggressive (-A)": "-A", "Full TCP (-p-)": "-p-", "Custom": ""}
HIGH_RISK_PORTS = {21,23,137,138,139,445,3389}
MEDIUM_RISK_PORTS = {80,1433,3306,1521,5900}
LOW_RISK_PORTS = {53,443,123}

# ---------------------------
# Port Risk Assessment (Security Verdict)
# ---------------------------
# Uses HIGH/MEDIUM/LOW_RISK_PORTS above (previously defined but never
# consumed) to turn raw Nmap output into a readable, prioritized risk
# report: which open ports matter, why, and an overall verdict per host.

PORT_RISK_INFO: Dict[int, Tuple[str, str]] = {
    21:   ("HIGH",   "FTP - unencrypted credentials & file transfer."),
    23:   ("HIGH",   "Telnet - unencrypted remote administration."),
    137:  ("HIGH",   "NetBIOS Name Service - legacy Windows discovery, info leakage."),
    138:  ("HIGH",   "NetBIOS Datagram Service - legacy Windows discovery."),
    139:  ("HIGH",   "NetBIOS Session Service - SMB over NetBIOS, common attack surface."),
    445:  ("HIGH",   "SMB - historically exploited (EternalBlue/WannaCry, NotPetya)."),
    3389: ("HIGH",   "RDP - frequent brute-force/ransomware entry point (also BlueKeep)."),
    80:   ("MEDIUM", "HTTP - unencrypted web traffic; verify it doesn't handle sensitive data."),
    1433: ("MEDIUM", "MSSQL - database listener exposed; restrict to trusted hosts."),
    3306: ("MEDIUM", "MySQL - database listener exposed; restrict to trusted hosts."),
    1521: ("MEDIUM", "Oracle DB - database listener exposed; restrict to trusted hosts."),
    5900: ("MEDIUM", "VNC - remote desktop, often weakly authenticated."),
    53:   ("LOW",    "DNS - normal if this host is a resolver; watch for open recursion."),
    443:  ("LOW",    "HTTPS - encrypted web traffic, generally lower risk."),
    123:  ("LOW",    "NTP - time sync; can be abused for DDoS amplification if misconfigured."),
}
_RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

def classify_port_risk(port: int) -> Tuple[str, str]:
    """Returns (risk_level, description) for a given open port number."""
    if port in PORT_RISK_INFO:
        return PORT_RISK_INFO[port]
    if port in HIGH_RISK_PORTS:
        return ("HIGH", "Commonly targeted service.")
    if port in MEDIUM_RISK_PORTS:
        return ("MEDIUM", "Service warrants review/restriction.")
    if port in LOW_RISK_PORTS:
        return ("LOW", "Generally lower-risk service.")
    return ("INFO", "Open service - confirm it's intended to be reachable.")

def extract_hosts_and_ports(nmap_text: str) -> Dict[str, List[Tuple[int, str, str]]]:
    """Parses raw Nmap text into {ip: [(port, proto, service), ...]} for open ports only."""
    hosts: Dict[str, List[Tuple[int, str, str]]] = {}
    current_ip = None
    for line in nmap_text.splitlines():
        m_ip = re.search(r"Nmap scan report for .*?(\d{1,3}(?:\.\d{1,3}){3})", line)
        if m_ip:
            current_ip = m_ip.group(1)
            hosts.setdefault(current_ip, [])
            continue
        m_port = re.match(r"\s*(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
        if m_port and current_ip:
            hosts[current_ip].append((int(m_port.group(1)), m_port.group(2), m_port.group(3)))
    return hosts

def summarize_port_risk(hosts: Dict[str, List[Tuple[int, str, str]]]) -> str:
    """Builds a human-readable, per-host security verdict from parsed port data."""
    if not hosts or not any(hosts.values()):
        return ("No open ports were reported for the scanned target(s). (This can also mean "
                "the scan type used - e.g. -sn / host-discovery only - doesn't enumerate ports.)")

    lines: List[str] = []
    totals = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for ip, ports in hosts.items():
        if not ports:
            continue
        lines.append(f"\nHost: {ip}")
        scored = []
        for port, proto, service in ports:
            level, desc = classify_port_risk(port)
            totals[level] += 1
            scored.append((level, port, proto, service, desc))
        scored.sort(key=lambda x: _RISK_ORDER.get(x[0], 9))
        for level, port, proto, service, desc in scored:
            lines.append(f"  [{level:<6}] {port:<5}/{proto:<3} {service:<14} - {desc}")

    if totals["HIGH"] > 0: verdict = "HIGH"
    elif totals["MEDIUM"] > 0: verdict = "MEDIUM"
    elif totals["LOW"] > 0: verdict = "LOW"
    else: verdict = "INFORMATIONAL ONLY"

    header = (f"Service review priority: {verdict}\n"
              f"  High-risk: {totals['HIGH']}   Medium-risk: {totals['MEDIUM']}   "
              f"Low-risk: {totals['LOW']}   Informational: {totals['INFO']}")
    return header + "\n" + "\n".join(lines)

def format_security_verdict(hosts: Dict[str, List[Tuple[int, str, str]]]) -> str:
    """Wraps summarize_port_risk() with the standard report banner."""
    body = summarize_port_risk(hosts)
    rule = "=" * 60
    return f"\n{rule}\n=== SERVICE EXPOSURE REVIEW (NOT VERIFIED VULNERABILITIES) ===\n{rule}\n{body}\n{rule}\n"

def build_security_verdict_report(raw_output: str) -> str:
    """Entry point called after a completed scan: parses raw Nmap output and
    returns a formatted security risk assessment block."""
    hosts = extract_hosts_and_ports(raw_output)
    return format_security_verdict(hosts)

 
class HelpWindow(tk.Toplevel):
    def __init__(self, parent, title="Nmap Flags Reference", text=""):
        super().__init__(parent)
        self.title(title)
        self.geometry("760x520")
        frm = ttk.Frame(self, padding=8)
        frm.pack(fill='both', expand=True)
        lbl = ttk.Label(frm, text=title, font=("Segoe UI", 11, "bold"))
        lbl.pack(anchor='w')
        txt = scrolledtext.ScrolledText(frm, wrap='word', bg='#1e2632', fg='#e8eef7', font=('Consolas', 10))
        txt.pack(fill='both', expand=True, pady=(6,0))
        txt.insert('1.0', text)
        txt.config(state='disabled')
        ttk.Button(frm, text="Close", command=self.destroy).pack(pady=(8,4))
 
NMAP_FLAGS_HELP = """SCAN TECHNIQUES:
  -sS : TCP SYN Scan (Stealthy, requires Admin)
  -sT : Connect Scan (Default without Admin)
  -sU : UDP Scan (Slow, for DNS/DHCP/etc)
  -sn : Ping Scan (Host Discovery only, no ports)
  -PR : ARP Ping (Faster for local network)

TIMING & PERFORMANCE:
  -T0 to -T5 : Speed template (0=Paranoid, 4=Aggressive, 5=Insane)
  -F : Fast mode (Scans fewer ports)
  -p- : Scan all 65535 ports (Very slow)
  --top-ports <n> : Scan <n> most common ports

SERVICE & OS DETECTION:
  -sV : Probe open ports to determine service/version
  -O  : Enable OS detection (Requires Admin)
  -A  : Aggressive scan (OS detection, version detection, script scanning, traceroute)

NSE SCRIPTS (Nmap Scripting Engine):
  --script <name>          : Run one specific script (e.g. --script http-title)
  --script <category>      : Run every script in a category (see below)
  --script <s1>,<s2>       : Run multiple scripts/categories, comma-separated
  --script-args <key=val>  : Pass arguments to scripts that support them
  --script-updatedb        : Refresh Nmap's local script database
  --script-help <name>     : Show what a script checks and how to use it

  Most scripts need the port to already be identified, so pair --script
  with -sV (or -p to target a specific port) rather than running it alone.

COMMON SCRIPT CATEGORIES:
  vuln       : Actively checks for known vulnerabilities (can be slow)
  safe       : Scripts considered unlikely to crash/disrupt the target
  intrusive  : May disrupt or crash the target service - use with care
  default    : The baseline scripts run automatically by -sC / -A
  discovery  : Gathers extra info (hostnames, extra services, share names)
  auth       : Tests for authentication bypass or default credentials
  brute      : Brute-force credential guessing (noisy - only with permission)

A FEW USEFUL SCRIPTS TO KNOW:
  http-title            : Grabs the title/heading of a web page
  http-enum             : Enumerates common web directories & files
  ssl-enum-ciphers       : Lists supported TLS/SSL ciphers, flags weak ones
  smb-vuln-ms17-010      : Checks SMB for EternalBlue (MS17-010)
  ftp-anon               : Checks whether anonymous FTP login is allowed
  dns-zone-transfer      : Attempts a DNS zone transfer against a nameserver

EXAMPLES:
  1. Quick Scan:      nmap -T4 -F 192.168.1.1
  2. Full OS Detect:  nmap -A -T4 192.168.1.1
  3. Specific Ports:  nmap -p 80,443 192.168.1.1

SCRIPT EXAMPLES (type these into "Extra Flags" with Scan Type = Custom):
  4. Safe Vuln Check:     -sV --script vuln,safe
  5. Full Vuln Sweep:     -sV --script vuln
  6. Default NSE + Ver.:  -sC -sV
  7. Script with Args:    --script http-enum --script-args http-enum.basepath=/app
  8. Targeted CVE Check:  -p445 --script smb-vuln-ms17-010

NOTE: Scripts tagged 'intrusive' (and some 'vuln' scripts) can disrupt or
      crash the target service. Only run them against systems you own or
      have explicit permission to test."""
 
# ---------------------------
# HTTP Server Thread
# ---------------------------
 
class CustomLoggingHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        msg = "%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), format % args)
        if hasattr(self.server, 'log_callback'): self.server.log_callback(msg)
 
 
# ---------------------------
# Adapter settings dialog
# ---------------------------
 
 
# ---------------------------
# Network Monitor Engine
# ---------------------------
 
MONITOR_HISTORY_LEN = 60   # rolling window length (samples)
MONITOR_LOSS_WINDOW = 20   # packet-loss rolling window
MONITOR_JITTER_WIN  = 10   # jitter (stdev) rolling window
 
# ---------------------------------------------------------------------------
# Safe throughput helper — PowerShell Get-NetAdapterStatistics.
# Runs in a pooled thread so it never blocks the 1-second tick.
# ---------------------------------------------------------------------------
 
 
class MonitorEngine(threading.Thread):
    """
    High-performance network monitor daemon (R5.2 — crash-safe).
 
    Architecture:
    ─────────────────────────────────────────────────────────────────────
    • Ping and throughput run IN PARALLEL in a 2-thread pool so each
      1-second tick stays on schedule regardless of subprocess latency.
    • Throughput uses PowerShell (safe, no ctypes struct manipulation).
    • Gateway and alias are cached and refreshed every 10 ticks.
    • Precision timing via time.perf_counter() deadline loop with
      overrun-skip protection.
    • All data pushed to a queue; GUI drains it on the main thread.
    ─────────────────────────────────────────────────────────────────────
    """
 
    def __init__(self, interval: float = 1.0, out_q=None):
        super().__init__(daemon=True, name="MonitorEngine")
        self.interval    = max(1.0, float(interval))
        self.out_q       = out_q or queue.Queue(maxsize=3)
        self._stop_evt   = threading.Event()
 
        self._lat_hist  : List[int]               = []
        self._ping_hist : List[bool]              = []
        self._dl_hist   : List[Tuple[float, int]] = []
        self._ul_hist   : List[Tuple[float, int]] = []
 
        # 2-worker pool: one for ping, one for throughput
        self._pool = ThreadPoolExecutor(max_workers=2,
                                        thread_name_prefix="MonWorker")
 
        self._gw_cache   : Optional[str] = None
        self._alias_cache: Optional[str] = None
        self._cache_ttl  : int = 0
 
    def stop(self):
        self._stop_evt.set()
        # Pool is closed by run() after in-flight work finishes.
 
    # ---- workers ----
 
    def _ping_worker(self, target: str) -> Optional[int]:
        """ICMP ping, 800 ms Windows timeout + 1.2 s Python timeout."""
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            proc = subprocess.run(
                ['ping', '-n', '1', '-w', '800', str(target)],
                capture_output=True, text=True,
                startupinfo=si, timeout=1.2
            )
            if proc.returncode == 0:
                if re.search(r'time<1ms', proc.stdout, re.IGNORECASE):
                    return 1
                m = re.search(r'time[=<](\d+)ms', proc.stdout, re.IGNORECASE)
                if m: return int(m.group(1))
        except Exception:
            pass
        return None
 
    @staticmethod
    def _bytes_to_mbps(hist: List[Tuple[float, int]],
                       now: float, new_bytes: int) -> float:
        hist.append((now, new_bytes))
        if len(hist) > 4: hist.pop(0)
        if len(hist) < 2: return None
        dt = hist[-1][0] - hist[-2][0]
        db = hist[-1][1] - hist[-2][1]
        if dt <= 0 or db < 0: return 0.0
        return round((db * 8) / (dt * 1_000_000), 4)
 
    # ---- main loop ----
 
    def run(self):
        deadline = time.perf_counter()
 
        while not self._stop_evt.is_set():
            tick_wall = time.time()
 
            # 1. Refresh cache every 10 ticks
            self._cache_ttl -= 1
            if self._cache_ttl <= 0:
                try:
                    alias = get_active_interface_alias()
                    gw = get_adapter_info(alias).get('Gateway')
                    if (alias, gw) != (self._alias_cache, self._gw_cache):
                        self._lat_hist.clear(); self._ping_hist.clear()
                        self._dl_hist.clear(); self._ul_hist.clear()
                except Exception:
                    gw, alias = None, None
                self._gw_cache    = gw
                self._alias_cache = alias
                self._cache_ttl   = 10
 
            gw    = self._gw_cache
            alias = self._alias_cache
 
            # 2. Dispatch ping + throughput IN PARALLEL
            fut_ping = self._pool.submit(self._ping_worker, gw) \
                       if gw else None
            fut_tp   = self._pool.submit(_get_adapter_bytes_ps, alias) \
                       if alias else None
 
            # 3. Collect results (ping waits up to 1.1 s, tp up to 3 s but
            #    in practice finishes long before ping on a warm PS session)
            rtt    : Optional[int] = None
            recv_b : Optional[int] = None
            sent_b : Optional[int] = None
 
            if fut_ping is not None:
                try: rtt = fut_ping.result(timeout=1.3)
                except Exception: rtt = None
 
            if fut_tp is not None:
                try: recv_b, sent_b = fut_tp.result(timeout=3.5)
                except Exception: recv_b = sent_b = None
 
            # 4. Update rolling histories
            self._ping_hist.append(rtt is not None)
            if len(self._ping_hist) > MONITOR_LOSS_WINDOW:
                self._ping_hist.pop(0)
            if rtt is not None:
                self._lat_hist.append(rtt)
                if len(self._lat_hist) > MONITOR_HISTORY_LEN:
                    self._lat_hist.pop(0)
 
            # 5. Derived metrics
            loss_pct = 0.0
            if self._ping_hist:
                loss_pct = round(
                    100.0 * self._ping_hist.count(False) / len(self._ping_hist), 1)
 
            jitter = None
            window = self._lat_hist[-MONITOR_JITTER_WIN:]
            if len(window) >= 2:
                jitter = round(statistics.stdev(window), 2)
 
            # 6. Throughput
            now = time.time()
            dl_mbps = ul_mbps = None
            if recv_b is not None:
                dl_mbps = self._bytes_to_mbps(self._dl_hist, now, recv_b)
            if sent_b is not None:
                ul_mbps = self._bytes_to_mbps(self._ul_hist, now, sent_b)
 
            # 7. Push payload
            payload = {
                'latency'  : rtt,
                'jitter'   : jitter,
                'loss_pct' : loss_pct if gw else None,
                'dl_mbps'  : dl_mbps,
                'ul_mbps'  : ul_mbps,
                'gateway'  : gw    or '-',
                'alias'    : alias or '-',
                'timestamp': tick_wall,
                'lat_hist' : list(self._lat_hist),
            }
            try:
                if self.out_q.full():
                    try: self.out_q.get_nowait()
                    except queue.Empty: pass
                self.out_q.put_nowait(payload)
            except queue.Full:
                pass
 
            # 8. Precision sleep to next deadline
            deadline += self.interval
            now_pc = time.perf_counter()
            sleep_for = deadline - now_pc
            if sleep_for <= 0:
                deadline = now_pc + self.interval
                sleep_for = self.interval
            self._stop_evt.wait(timeout=sleep_for)
        self._pool.shutdown(wait=False, cancel_futures=True)
 
 
# ---------------------------
# Ping Tool Window
# ---------------------------
 
class PingWindow(tk.Toplevel):
    """
    Continuous ping window — behaves like `ping -t <target>` in CMD.
 
    - User enters an IP address or hostname.
    - Pings run one per second in a background daemon thread.
    - Live output streams into a ScrolledText widget.
    - Running statistics (sent, recv, loss%, min/avg/max RTT) shown in a
      status bar at the bottom, updated after every reply.
    - Stop / Clear buttons.  Window close auto-stops the ping loop.
    """
 
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Ping Tool")
        self.geometry("660x500")
        self.minsize(500, 350)
        self.configure(bg="#1e1e1e")
        self.protocol("WM_DELETE_WINDOW", self._on_close)
 
        self._stop_evt  = threading.Event()
        self._thread    : Optional[threading.Thread] = None
        self._seq       = 0          # packets sent
        self._recv      = 0          # packets received
        self._rtt_list  : List[int] = []
        self._out_q     : queue.Queue = queue.Queue()
 
        self._build_ui()
        self._poll_output()
 
    # ------------------------------------------------------------------ #
    # UI                                                                   #
    # ------------------------------------------------------------------ #
    def _build_ui(self):
        # ── Top bar ──────────────────────────────────────────────────────
        top = tk.Frame(self, bg="#1e1e1e", pady=8, padx=10)
        top.pack(fill="x")
 
        tk.Label(top, text="Target (IP or hostname):",
                 bg="#1e1e1e", fg="#cccccc",
                 font=("Segoe UI", 9)).pack(side="left")
 
        self._target_var = tk.StringVar()
        ent = tk.Entry(top, textvariable=self._target_var,
                       width=28, bg="#2d2d2d", fg="#ffffff",
                       insertbackground="white",
                       relief="flat", font=("Consolas", 10))
        ent.pack(side="left", padx=(6, 10))
        ent.bind("<Return>", lambda e: self._start_ping())
 
        self._btn_start = tk.Button(top, text="Start",
                                    bg="#4caf50", fg="#ffffff",
                                    activebackground="#388E3C",
                                    relief="flat", padx=10,
                                    font=("Segoe UI", 9, "bold"),
                                    command=self._start_ping)
        self._btn_start.pack(side="left", padx=(0, 4))
 
        self._btn_stop = tk.Button(top, text="Stop",
                                   bg="#FF5722", fg="#ffffff",
                                   activebackground="#BF360C",
                                   relief="flat", padx=10,
                                   font=("Segoe UI", 9, "bold"),
                                   state="disabled",
                                   command=self._stop_ping)
        self._btn_stop.pack(side="left", padx=(0, 4))
 
        tk.Button(top, text="Clear",
                  bg="#555555", fg="#ffffff",
                  activebackground="#333333",
                  relief="flat", padx=10,
                  font=("Segoe UI", 9),
                  command=self._clear_output).pack(side="left")
 
        # ── Output area ──────────────────────────────────────────────────
        out_frame = tk.Frame(self, bg="#1e1e1e", padx=10)
        out_frame.pack(fill="both", expand=True)
 
        self._txt = scrolledtext.ScrolledText(
            out_frame,
            bg="#0d0d0d", fg="#d4d4d4",
            font=("Consolas", 9),
            wrap="none",
            state="disabled"
        )
        self._txt.pack(fill="both", expand=True)
 
        # Colour tags
        self._txt.tag_config("ok",      foreground="#4caf50")
        self._txt.tag_config("timeout", foreground="#FF5722")
        self._txt.tag_config("info",    foreground="#888888")
        self._txt.tag_config("header",  foreground="#2196F3")
 
        # ── Stats bar ────────────────────────────────────────────────────
        self._stats_var = tk.StringVar(value="Sent: 0 | Recv: 0 | Loss: -% | RTT min/avg/max: -/-/- ms")
        stats_bar = tk.Label(self, textvariable=self._stats_var,
                             bg="#2d2d2d", fg="#cccccc",
                             font=("Consolas", 9), anchor="w",
                             padx=10, pady=4)
        stats_bar.pack(fill="x", side="bottom")
 
    # ------------------------------------------------------------------ #
    # Ping control                                                         #
    # ------------------------------------------------------------------ #
    def _start_ping(self):
        target = self._target_var.get().strip()
        if not target:
            messagebox.showwarning("No Target", "Please enter an IP address or hostname.", parent=self)
            return
        if self._thread and self._thread.is_alive():
            self._stop_ping()   # stop current before restarting
 
        # reset counters
        self._stop_evt.clear()
        self._seq      = 0
        self._recv     = 0
        self._rtt_list = []
 
        self._btn_start.config(state="disabled")
        self._btn_stop.config(state="normal")
 
        self._append(f"Pinging {target} continuously — press Stop to end.\n", "header")
 
        self._thread = threading.Thread(
            target=self._ping_loop,
            args=(target,),
            daemon=True,
            name="PingLoop"
        )
        self._thread.start()
 
    def _stop_ping(self):
        self._stop_evt.set()
        self._btn_start.config(state="normal")
        self._btn_stop.config(state="disabled")
        # Summary will be printed when the loop exits naturally
 
    def _on_close(self):
        self._stop_evt.set()
        self.destroy()
 
    # ------------------------------------------------------------------ #
    # Background ping loop                                                 #
    # ------------------------------------------------------------------ #
    def _ping_loop(self, target: str):
        while not self._stop_evt.is_set():
            tick = time.perf_counter()
            self._seq += 1
            seq = self._seq
 
            rtt, reply_str, tag = self._do_ping(target, seq)
 
            if rtt is not None:
                self._recv += 1
                self._rtt_list.append(rtt)
 
            self._out_q.put(("line", reply_str, tag))
            self._out_q.put(("stats", None, None))
 
            # Precise 1-second interval
            elapsed = time.perf_counter() - tick
            wait = max(0.0, 1.0 - elapsed)
            self._stop_evt.wait(timeout=wait)
 
        # ── Summary ──────────────────────────────────────────────────────
        sent = self._seq
        recv = self._recv
        lost = sent - recv
        loss_pct = round(100.0 * lost / sent, 1) if sent else 0.0
        summary_lines = [
            f"\n─── Ping Statistics ───────────────────────────────",
            f"  Packets:  Sent = {sent}  Received = {recv}  Lost = {lost}  ({loss_pct}% loss)",
        ]
        if self._rtt_list:
            summary_lines.append(
                f"  RTT (ms): Min = {min(self._rtt_list)}  "
                f"Avg = {round(sum(self._rtt_list)/len(self._rtt_list), 1)}  "
                f"Max = {max(self._rtt_list)}"
            )
        summary_lines.append("─────────────────────────────────────────────────\n")
        self._out_q.put(("line", "\n".join(summary_lines), "info"))
        self._out_q.put(("done", None, None))
 
    def _do_ping(self, target: str, seq: int):
        """
        Runs one ICMP ping. Returns (rtt_ms_or_None, display_string, tag).
        Uses a 900 ms Windows timeout so we still return within 1 s.
        """
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            proc = subprocess.run(
                ['ping', '-n', '1', '-w', '900', str(target)],
                capture_output=True, text=True,
                startupinfo=si, timeout=1.1
            )
            ts = datetime.now().strftime("%H:%M:%S")
 
            if proc.returncode == 0:
                # Parse RTT
                m = re.search(r'time[=<](\d+)ms', proc.stdout, re.IGNORECASE)
                if re.search(r'time<1ms', proc.stdout, re.IGNORECASE):
                    rtt = 1
                elif m:
                    rtt = int(m.group(1))
                else:
                    rtt = None
 
                # Parse reply-from IP
                m_from = re.search(r'Reply from ([\d\.]+)', proc.stdout, re.IGNORECASE)
                from_ip = m_from.group(1) if m_from else target
 
                # Parse TTL
                m_ttl = re.search(r'TTL=(\d+)', proc.stdout, re.IGNORECASE)
                ttl_str = f"  TTL={m_ttl.group(1)}" if m_ttl else ""
 
                if rtt is not None:
                    line = f"[{ts}]  Reply from {from_ip}:  bytes=32  time={rtt}ms{ttl_str}"
                    return rtt, line, "ok"
                else:
                    line = f"[{ts}]  Reply from {from_ip}  (RTT parse failed)"
                    return None, line, "info"
            else:
                line = f"[{ts}]  Request timed out."
                return None, line, "timeout"
 
        except subprocess.TimeoutExpired:
            ts = datetime.now().strftime("%H:%M:%S")
            return None, f"[{ts}]  Request timed out (process timeout).", "timeout"
        except Exception as exc:
            ts = datetime.now().strftime("%H:%M:%S")
            return None, f"[{ts}]  Error: {exc}", "timeout"
 
    # ------------------------------------------------------------------ #
    # Output queue consumer (runs on main thread via after())             #
    # ------------------------------------------------------------------ #
    def _poll_output(self):
        try:
            while True:
                kind, text, tag = self._out_q.get_nowait()
                if kind == "line":
                    self._append(text + "\n", tag)
                elif kind == "stats":
                    self._update_stats()
                elif kind == "done":
                    self._btn_start.config(state="normal")
                    self._btn_stop.config(state="disabled")
        except queue.Empty:
            pass
        self.after(80, self._poll_output)
 
    def _append(self, text: str, tag: str = ""):
        self._txt.config(state="normal")
        if tag:
            self._txt.insert(tk.END, text, tag)
        else:
            self._txt.insert(tk.END, text)
        self._txt.see(tk.END)
        self._txt.config(state="disabled")
 
    def _clear_output(self):
        self._txt.config(state="normal")
        self._txt.delete("1.0", tk.END)
        self._txt.config(state="disabled")
 
    def _update_stats(self):
        sent = self._seq
        recv = self._recv
        lost = sent - recv
        loss_pct = round(100.0 * lost / sent, 1) if sent else 0.0
        if self._rtt_list:
            rtt_min = min(self._rtt_list)
            rtt_avg = round(sum(self._rtt_list) / len(self._rtt_list), 1)
            rtt_max = max(self._rtt_list)
            rtt_str = f"{rtt_min}/{rtt_avg}/{rtt_max} ms"
        else:
            rtt_str = "-/-/- ms"
        self._stats_var.set(
            f"Sent: {sent} | Recv: {recv} | Loss: {loss_pct}% | RTT min/avg/max: {rtt_str}"
        )
 
 
# ---------------------------
# Main GUI
# ---------------------------
 


# ---------------------------------------------------------------------------
# Netversity workspace UI and coordinated task lifecycle
# ---------------------------------------------------------------------------
import math
import shlex
import webbrowser
import xml.etree.ElementTree as ET
from pathlib import Path

APP_VERSION = '6.0'
DATA_DIR = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'Netversity'
BG, PANEL, FIELD = '#151a22', '#1e2632', '#263140'
TEXT, MUTED, LINE = '#e8eef7', '#aab8cb', '#364557'
ACCENT, GOOD, WARN, BAD = '#94bfff', '#92d9b0', '#efc77b', '#ffa3a3'


def process_args(args, timeout=25):
    result = subprocess.run(args, capture_output=True, text=True, errors='replace',
                            creationflags=_NO_WINDOW_FLAGS, timeout=timeout)
    return result.returncode, result.stdout, result.stderr


def get_active_interface_alias():
    script = ("$r=Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
              "Where-Object {$_.State -ne 'Dead'} | Sort-Object @{Expression={$_.RouteMetric + "
              "(Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).InterfaceMetric}} | "
              "Select-Object -First 1; if($r){$r.InterfaceAlias}")
    try:
        code, out, _ = process_args(['powershell', '-NoProfile', '-Command', script])
        return out.strip() if code == 0 and out.strip() else None
    except (OSError, subprocess.SubprocessError):
        return None


def _get_adapter_bytes_ps(alias):
    if not alias: return None, None
    quoted = str(alias).replace("'", "''")
    script = f"$s=Get-NetAdapterStatistics -Name '{quoted}' -ErrorAction Stop; [pscustomobject]@{{received=$s.ReceivedBytes;sent=$s.SentBytes}} | ConvertTo-Json -Compress"
    try:
        code, out, _ = process_args(['powershell', '-NoProfile', '-Command', script], timeout=3)
        if code == 0:
            data = json.loads(out); return int(data['received']), int(data['sent'])
    except (OSError, ValueError, KeyError, subprocess.SubprocessError): pass
    return None, None


def get_adapter_info(alias):
    info = dict.fromkeys(('IPv4', 'PrefixLength', 'Mask', 'Gateway', 'DNS1', 'DNS2', 'MAC', 'DHCP'))
    if not alias:
        return info
    quoted = str(alias).replace("'", "''")
    script = (f"$a='{quoted}'; $c=Get-NetIPConfiguration -InterfaceAlias $a -ErrorAction Stop; "
              "$ip=$c.IPv4Address | Select-Object -First 1; "
              "$d=(Get-DnsClientServerAddress -InterfaceAlias $a -AddressFamily IPv4).ServerAddresses; "
              "[pscustomobject]@{IPv4=$ip.IPAddress; PrefixLength=$ip.PrefixLength; "
              "Gateway=($c.IPv4DefaultGateway | Select-Object -First 1).NextHop; "
              "DNS=@($d); MAC=(Get-NetAdapter -Name $a).MacAddress; "
              "DHCP=([string]$ip.PrefixOrigin -eq 'Dhcp')} | ConvertTo-Json -Compress")
    try:
        code, out, _ = process_args(['powershell', '-NoProfile', '-Command', script])
        if code == 0 and out.strip():
            data = json.loads(out)
            info.update({k: data.get(k) for k in info if k in data})
            if data.get('PrefixLength') is not None:
                info['Mask'] = str(ipaddress.IPv4Network(f"0.0.0.0/{data['PrefixLength']}").netmask)
            dns = data.get('DNS') or []
            if isinstance(dns, str): dns = [dns]
            info['DNS1'] = dns[0] if dns else None
            info['DNS2'] = dns[1] if len(dns) > 1 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return info


def set_interface_state(interface_name, enable):
    return process_args(['netsh', 'interface', 'set', 'interface',
                         f'name={interface_name}', 'admin=enable' if enable else 'admin=disable'])[0] == 0


def connect_with_existing_profile(ssid):
    return process_args(['netsh', 'wlan', 'connect', f'name={ssid}', f'ssid={ssid}'])[0] == 0


def disconnect():
    return process_args(['netsh', 'wlan', 'disconnect'])[0] == 0


def set_static_config(adapter_name, ip, mask, gateway, dns1, dns2=''):
    try:
        ipaddress.IPv4Address(ip)
        ipaddress.IPv4Network(f'{ip}/{mask}', strict=False)
        for value in (gateway, dns1, dns2):
            if value: ipaddress.IPv4Address(value)
    except ValueError as exc:
        return False, f'Invalid IPv4 configuration: {exc}'
    commands = [['netsh', 'interface', 'ipv4', 'set', 'address', f'name={adapter_name}',
                 'source=static', f'address={ip}', f'mask={mask}', f'gateway={gateway or "none"}']]
    if dns1:
        commands.append(['netsh', 'interface', 'ipv4', 'set', 'dnsservers', f'name={adapter_name}',
                         'source=static', f'address={dns1}', 'validate=no'])
    else:
        commands.append(['netsh', 'interface', 'ipv4', 'set', 'dnsservers', f'name={adapter_name}', 'source=dhcp'])
    if dns2:
        commands.append(['netsh', 'interface', 'ipv4', 'add', 'dnsservers', f'name={adapter_name}',
                         f'address={dns2}', 'index=2', 'validate=no'])
    for command in commands:
        code, out, err = process_args(command)
        if code: return False, 'Configuration was not fully applied.\n' + (err or out)
    return True, 'Configuration applied.'


def set_dhcp_config(adapter_name):
    errors = []
    for field in ('address', 'dnsservers'):
        code, out, err = process_args(['netsh', 'interface', 'ipv4', 'set', field,
                                      f'name={adapter_name}', 'source=dhcp'])
        if code: errors.append(err or out)
    return not errors, '\n'.join(errors) if errors else 'Automatic addressing applied.'


class AdapterSettingsDialog(tk.Toplevel):
    def __init__(self, master, target_adapter=None):
        super().__init__(master)
        self.alias = target_adapter or 'Wi-Fi'
        self.title(f'Adapter settings — {self.alias}')
        self.configure(bg=BG)
        self.transient(master)
        self.geometry('510x440')
        self.minsize(460, 420)
        self.mode = tk.StringVar(value='dhcp')
        self.values = {k: tk.StringVar() for k in ('IPv4', 'Mask', 'Gateway', 'DNS1', 'DNS2')}
        self.result = tk.StringVar(value='Loading adapter settings…')
        frame = ttk.Frame(self, padding=22)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text=self.alias, style='Heading.TLabel').grid(row=0, column=0, columnspan=2, sticky='w', pady=(0, 16))
        for col, (text, value) in enumerate((('Automatic (DHCP)', 'dhcp'), ('Manual', 'static'))):
            ttk.Radiobutton(frame, text=text, variable=self.mode, value=value, command=self._mode_changed).grid(row=1, column=col, sticky='w', pady=8)
        self.entries = []
        for row, (key, label) in enumerate(zip(self.values, ('IPv4 address', 'Subnet mask', 'Gateway', 'Primary DNS', 'Secondary DNS')), 2):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky='w', pady=7)
            entry = ttk.Entry(frame, textvariable=self.values[key])
            entry.grid(row=row, column=1, sticky='ew', padx=(15, 0))
            self.entries.append(entry)
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, textvariable=self.result, wraplength=430, style='Muted.TLabel').grid(row=7, column=0, columnspan=2, sticky='w', pady=15)
        self.apply_btn = ttk.Button(frame, text='Apply configuration', command=self._apply, style='Accent.TButton', state='disabled')
        self.apply_btn.grid(row=8, column=0, sticky='w')
        ttk.Button(frame, text='Close', command=self.destroy).grid(row=8, column=1, sticky='e')
        self._mode_changed()
        master._job(lambda: get_adapter_info(self.alias), self._loaded)

    def _loaded(self, info):
        if not self.winfo_exists(): return
        for key, var in self.values.items(): var.set(info.get(key) or '')
        self.mode.set('dhcp' if info.get('DHCP') else 'static')
        self.result.set(('MAC: ' + (info.get('MAC') or 'Unavailable') + '\n') + ('Choose addressing mode. Changes affect this adapter.' if info.get('IPv4') else 'No IPv4 address reported. You can configure this adapter.'))
        self.apply_btn.config(state='normal')
        self._mode_changed()

    def _mode_changed(self):
        for entry in self.entries: entry.config(state='normal' if self.mode.get() == 'static' else 'disabled')

    def _apply(self):
        if not is_admin():
            self.result.set('Administrator rights are required. Restart Netversity as administrator to apply changes.')
            return
        mode, values = self.mode.get(), [v.get().strip() for v in self.values.values()]
        if mode == 'static':
            try:
                ipaddress.IPv4Address(values[0]); ipaddress.IPv4Network(f'{values[0]}/{values[1]}', strict=False)
                for item in values[2:]:
                    if item: ipaddress.IPv4Address(item)
                if values[4] and not values[3]: raise ValueError('Enter primary DNS before secondary DNS.')
            except ValueError as exc:
                self.result.set(str(exc)); return
        self.apply_btn.config(state='disabled')
        self.result.set('Applying configuration…')
        def done(result):
            if not self.winfo_exists(): return
            self.apply_btn.config(state='normal')
            self.result.set(result[1])
            if result[0]: self.master._job(lambda: get_adapter_info(self.alias), self._loaded)
        def apply():
            try: return set_dhcp_config(self.alias) if mode == 'dhcp' else set_static_config(self.alias, *values)
            except Exception as exc: return False, str(exc)
        self.master._job(apply, done)


class SharingServer(threading.Thread):
    def __init__(self, port, directory, callback, log):
        super().__init__(daemon=True)
        self.port, self.directory, self.callback, self.log = port, directory, callback, log
        self.httpd = None
        self.cancel = threading.Event()

    def run(self):
        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = os.name != 'nt'

            def server_bind(self):
                if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                super().server_bind()
        try:
            handler = partial(CustomLoggingHandler, directory=self.directory)
            with Server(('', self.port), handler) as server:
                self.httpd = server
                server.log_callback = self.log
                server.timeout = .25
                if not self.cancel.is_set(): self.callback('Running', '')
                while not self.cancel.is_set(): server.handle_request()
            self.callback('Stopped', '')
        except Exception as exc:
            self.callback('Failed', str(exc))
        finally:
            self.httpd = None

    def stop(self):
        self.cancel.set()


def parse_nmap_xml(text):
    """Preserve exact port state and structured Nmap evidence."""
    root = ET.fromstring(text)
    rows, hosts = [], []
    for host in root.findall('host'):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None: addr = host.find('address')
        ip = addr.get('addr', 'Unknown') if addr is not None else 'Unknown'
        status = host.find('status')
        hosts.append((ip, status.get('state', 'unknown') if status is not None else 'unknown'))
        for port in host.findall('ports/port'):
            state, svc = port.find('state'), port.find('service')
            status_text = state.get('state', 'unknown') if state is not None else 'unknown'
            number = int(port.get('portid', 0))
            service = svc.get('name', '') if svc is not None else ''
            version = ' '.join(svc.get(k, '') for k in ('product', 'version', 'extrainfo')).strip() if svc is not None else ''
            evidence = '\n'.join(script.get('id', '') + ': ' + script.get('output', '') for script in port.findall('script'))
            priority = classify_port_risk(number)[0] if status_text == 'open' else 'Unconfirmed'
            rows.append((ip, f"{number}/{port.get('protocol', '')}", status_text, service, priority, version, evidence))
    return rows, hosts


class ScanSession(threading.Thread):
    def __init__(self, targets, plans, callback):
        super().__init__(daemon=True)
        self.targets, self.plans, self.callback = targets, plans, callback
        self.cancel = threading.Event()
        self.proc = None
        self.lock = threading.Lock()

    def stop(self):
        self.cancel.set()
        with self.lock:
            if self.proc and self.proc.poll() is None:
                try: self.proc.terminate()
                except OSError: pass

    def run(self):
        records, hosts, failures = [], [], []
        try:
            exe = find_nmap_binary()
            if not exe: raise RuntimeError('Nmap is not installed. Install Nmap, then restart the scan.')
            for label, args in self.plans:
                if self.cancel.is_set(): break
                with tempfile.TemporaryDirectory(prefix='netversity-') as temp:
                    xmlpath = os.path.join(temp, 'result.xml')
                    cmd = [exe, *args, '-oX', xmlpath, *self.targets]
                    self.callback('line', f'\n[{label}] {subprocess.list2cmdline(cmd)}\n')
                    with self.lock:
                        if self.cancel.is_set(): break
                        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors='replace', creationflags=_NO_WINDOW_FLAGS)
                    for line in self.proc.stdout:
                        self.callback('line', line)
                    code = self.proc.wait()
                    if code and not self.cancel.is_set(): failures.append(f'{label}: exit code {code}')
                    try:
                        with open(xmlpath, encoding='utf-8') as f: parsed, discovered = parse_nmap_xml(f.read())
                        records.extend(parsed); hosts.extend((label, ip, state) for ip, state in discovered)
                    except (OSError, ET.ParseError) as exc:
                        if not self.cancel.is_set(): failures.append(f'{label}: no complete XML results ({exc})')
        except Exception as exc:
            failures.append(str(exc))
        finally:
            state = 'Cancelled' if self.cancel.is_set() else 'Failed' if failures else 'Completed'
            self.callback('done', (state, records, hosts, failures))


class TraceroutePane(ttk.Frame):
    """
    Continuous traceroute window — runs 'tracert <target>' (Windows) in a background thread.
    Streams output to a ScrolledText widget.
    """
    def __init__(self, parent):
        super().__init__(parent, padding=14)
        self._stop_evt, self._out_q = threading.Event(), queue.Queue()
        self._thread = None
        self._target_var = tk.StringVar(value='')
        self._stats_var = tk.StringVar(value='No traceroute session started')

        row = ttk.Frame(self); row.pack(fill='x', pady=(0, 12))
        ttk.Label(row, text='Target').pack(side='left')
        self.target_entry = ttk.Entry(row, textvariable=self._target_var, width=30)
        self.target_entry.pack(side='left', padx=10)
        self.target_entry.bind('<Return>', lambda e: self._start_tracert())
        self._btn_start = ttk.Button(row, text='Start traceroute', command=self._start_tracert, style='Accent.TButton')
        self._btn_start.pack(side='left')
        self._btn_stop = ttk.Button(row, text='Stop', command=self._stop_tracert, state='disabled')
        self._btn_stop.pack(side='left', padx=8)
        ttk.Button(row, text='Clear', command=self._clear_output).pack(side='left')

        self._txt = scrolledtext.ScrolledText(self, bg=PANEL, fg=TEXT, insertbackground=TEXT,
                                           font=('Consolas', 10), wrap='word', state='disabled', relief='flat')
        self._txt.pack(fill='both', expand=True)
        for tag, color in (('ok', GOOD), ('timeout', WARN), ('info', MUTED), ('header', ACCENT)):
            self._txt.tag_config(tag, foreground=color)
        ttk.Label(self, textvariable=self._stats_var).pack(fill='x', pady=(12, 0))
        self.after(100, self._poll_output)

    def _start_tracert(self):
        target = self._target_var.get().strip()
        if not target or target.startswith('-') or any(c.isspace() for c in target):
            self._stats_var.set('Enter one IP address or hostname.'); return
        if self._thread and self._thread.is_alive(): return
        self._stop_evt.clear()
        self._btn_start.config(state='disabled'); self._btn_stop.config(state='normal')
        self.target_entry.config(state='disabled')
        self._stats_var.set('Traceroute running...')
        self._clear_output()
        self._thread = threading.Thread(target=self._tracert_loop, args=(target,), daemon=True)
        self._thread.start()

    def _stop_tracert(self):
        self._stop_evt.set(); self._btn_stop.config(state='disabled')
        self._stats_var.set('Stopping traceroute…')

    def _tracert_loop(self, target: str):
        cmd = ['tracert', '-d', str(target)]
        self._out_q.put(('line', f"Tracing route to {target} over a maximum of 30 hops:\n", 'header'))
        try:
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, errors='replace', startupinfo=si)
            while True:
                if self._stop_evt.is_set():
                    proc.terminate()
                    break
                line = proc.stdout.readline()
                if not line:
                    break
                self._out_q.put(('line', line, 'ok' if 'ms' in line else 'info'))
            proc.wait()
        except Exception as exc:
            self._out_q.put(('line', f"Error: {exc}\n", 'timeout'))
        finally:
            self._out_q.put(('done', None, None))

    def _poll_output(self):
        for _ in range(200):
            try: kind, text, tag = self._out_q.get_nowait()
            except queue.Empty: break
            if kind == 'line': self._append(text, tag)
            elif kind == 'done':
                self._btn_start.config(state='normal'); self._btn_stop.config(state='disabled')
                self.target_entry.config(state='normal')
                if self._stop_evt.is_set():
                    self._stats_var.set('Traceroute stopped.')
                else:
                    self._stats_var.set('Traceroute completed.')
        if int(self._txt.index('end-1c').split('.')[0]) > 3000:
            self._txt.config(state='normal'); self._txt.delete('1.0', '1000.0'); self._txt.config(state='disabled')
        self.after(100, self._poll_output)

    def _append(self, text: str, tag: str = ""):
        self._txt.config(state="normal")
        if tag:
            self._txt.insert(tk.END, text, tag)
        else:
            self._txt.insert(tk.END, text)
        self._txt.see(tk.END)
        self._txt.config(state="disabled")

    def _clear_output(self):
        self._txt.config(state="normal")
        self._txt.delete("1.0", tk.END)
        self._txt.config(state="disabled")


class PingPane(ttk.Frame):
    # Reuse the original Windows ping parser and worker without a second window.
    _do_ping = PingWindow._do_ping
    _ping_loop = PingWindow._ping_loop
    _append = PingWindow._append
    _update_stats = PingWindow._update_stats
    _clear_output = PingWindow._clear_output

    def __init__(self, parent):
        super().__init__(parent, padding=14)
        self._stop_evt, self._out_q = threading.Event(), queue.Queue()
        self._thread = None
        self._seq = self._recv = 0
        self._rtt_list = []
        self._target_var = tk.StringVar(value='')
        self._stats_var = tk.StringVar(value='No ping session started')
        row = ttk.Frame(self); row.pack(fill='x', pady=(0, 12))
        ttk.Label(row, text='Target').pack(side='left')
        self.target_entry = ttk.Entry(row, textvariable=self._target_var, width=30)
        self.target_entry.pack(side='left', padx=10)
        self.target_entry.bind('<Return>', lambda e: self._start_ping())
        self._btn_start = ttk.Button(row, text='Start ping', command=self._start_ping, style='Accent.TButton')
        self._btn_start.pack(side='left')
        self._btn_stop = ttk.Button(row, text='Stop', command=self._stop_ping, state='disabled')
        self._btn_stop.pack(side='left', padx=8)
        ttk.Button(row, text='Clear', command=self._clear_output).pack(side='left')
        self._txt = scrolledtext.ScrolledText(self, bg=PANEL, fg=TEXT, insertbackground=TEXT,
                                           font=('Consolas', 10), wrap='word', state='disabled', relief='flat')
        self._txt.pack(fill='both', expand=True)
        for tag, color in (('ok', GOOD), ('timeout', WARN), ('info', MUTED), ('header', ACCENT)):
            self._txt.tag_config(tag, foreground=color)
        ttk.Label(self, textvariable=self._stats_var).pack(fill='x', pady=(12, 0))
        self.after(100, self._poll_output)

    def _start_ping(self):
        target = self._target_var.get().strip()
        if not target or target.startswith('-') or any(c.isspace() for c in target):
            self._stats_var.set('Enter one IP address or hostname.'); return
        if self._thread and self._thread.is_alive(): return
        self._stop_evt = threading.Event()
        self._seq = self._recv = 0; self._rtt_list = []
        self._btn_start.config(state='disabled'); self._btn_stop.config(state='normal')
        self.target_entry.config(state='disabled')
        self._thread = threading.Thread(target=self._ping_loop, args=(target,), daemon=True)
        self._thread.start()

    def _stop_ping(self):
        self._stop_evt.set(); self._btn_stop.config(state='disabled')
        self._stats_var.set('Stopping ping…')

    def _poll_output(self):
        for _ in range(200):
            try: kind, text, tag = self._out_q.get_nowait()
            except queue.Empty: break
            if kind == 'line': self._append(text + '\n', tag)
            elif kind == 'stats': self._update_stats()
            elif kind == 'done':
                self._btn_start.config(state='normal'); self._btn_stop.config(state='disabled')
                self.target_entry.config(state='normal')
        if int(self._txt.index('end-1c').split('.')[0]) > 3000:
            self._txt.config(state='normal'); self._txt.delete('1.0', '1000.0'); self._txt.config(state='disabled')
        self.after(100, self._poll_output)


class WiFiGUI(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self._main_thread = threading.get_ident()
        self.ui_queue = queue.Queue()
        self._shutting_down = threading.Event()
        self._after_ids = []
        self.workers = []
        self.title(f'Netversity · Network workspace {APP_VERSION}')
        self.geometry('1180x820'); self.minsize(950, 650); self.configure(bg=BG)
        self.protocol('WM_DELETE_WINDOW', self._on_app_close)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.auto_scan = tk.BooleanVar(value=False)
        self.scan_interval_ms = 15000
        self._auto_after = None
        self._network_busy = False
        self.selected_net = None
        self.networks = {}; self.saved_profiles = set(); self.wlan_snapshot = {}; self.adapter_snapshot = {}
        self.current_alias = None
        self.logging_active = False
        self.log_ui_queue, self.status_queue, self.monitor_queue = queue.Queue(), queue.Queue(), queue.Queue(maxsize=5)
        self._monitor_engine = None
        self._graph_times, self._graph_dl, self._graph_ul, self._graph_lat = [], [], [], []
        self.http_thread = None; self.server_dir = ''
        self._nmap_runner = None; self._comp_thread = None
        self._comp_stop_evt = threading.Event()
        self._scan_session = None; self._last_raw_output = ''; self._scan_rows = []
        self.v_verbosity_level = 1
        self.comp_syn, self.comp_udp, self.comp_arp = (tk.BooleanVar(value=False) for _ in range(3))
        self.device_engine = None; self.device_queue = queue.Queue(maxsize=2); self.device_nodes = []
        self.baseline = {}; self.baseline_file = None; self._alerted_ips = set()
        self._style()
        self._build_shell()
        self._build_network_ui(self.network_tab)
        self._build_vuln_ui(self.vuln_tab)
        self._build_topology_ui(self.topology_tab)
        self._build_http_ui(self.http_tab)
        self._build_monitor_ui(self.monitor_tab)
        self._show_page('Networks')
        self._monitor_queues()
        self._job(self._background_status_updater)
        self._scan_async()

    def after(self, ms, func=None, *args):
        if func is not None and hasattr(self, '_main_thread') and threading.get_ident() != self._main_thread:
            if not self._shutting_down.is_set(): self.ui_queue.put(lambda: tk.Tk.after(self, ms, func, *args))
            return None
        return tk.Tk.after(self, ms, func, *args)

    def _post(self, callback, *args, **kwargs):
        if not self._shutting_down.is_set(): self.ui_queue.put(lambda: callback(*args, **kwargs))

    def _job(self, work, done=None):
        def run():
            try:
                result = work()
                if done: self._post(done, result)
            except Exception as exc:
                self._post(self._set_status, f'Operation failed: {exc}')
        thread = threading.Thread(target=run, daemon=True)
        self.workers = [t for t in self.workers if t.is_alive()]
        self.workers.append(thread); thread.start()
        return thread

    def _style(self):
        self.option_add('*Font', ('Segoe UI', 10))
        style = ttk.Style(self); style.theme_use('clam')
        style.configure('.', background=BG, foreground=TEXT, bordercolor=LINE, troughcolor=BG,
                        fieldbackground=FIELD, lightcolor=LINE, darkcolor=LINE, focuscolor=ACCENT)
        style.configure('TFrame', background=BG)
        style.configure('Panel.TFrame', background=PANEL)
        style.configure('TLabel', background=BG, foreground=TEXT)
        style.configure('Muted.TLabel', foreground=MUTED)
        style.configure('Title.TLabel', font=('Segoe UI', 22, 'bold'))
        style.configure('Heading.TLabel', font=('Segoe UI', 12, 'bold'))
        style.configure('TButton', background=FIELD, foreground=TEXT, padding=(12, 8), borderwidth=1)
        style.map('TButton', background=[('active', '#34475f'), ('disabled', '#222b37')], foreground=[('disabled', '#778698')])
        style.configure('Accent.TButton', background='#365f93', foreground='#ffffff')
        style.map('Accent.TButton', background=[('active', '#487cb5'), ('disabled', '#27354a')])
        style.configure('Nav.TButton', anchor='w', padding=(16, 12), background=BG, borderwidth=0)
        style.configure('Selected.Nav.TButton', background='#263c58', foreground=ACCENT)
        style.configure('TEntry', padding=7, insertcolor=TEXT)
        style.configure('TCombobox', padding=6, arrowsize=15)
        style.map('TCombobox', fieldbackground=[('readonly', FIELD)], foreground=[('readonly', TEXT)])
        style.configure('TNotebook', background=BG, borderwidth=0)
        style.configure('TNotebook.Tab', padding=(16, 9), background=PANEL)
        style.map('TNotebook.Tab', background=[('selected', FIELD)], foreground=[('selected', ACCENT)])
        style.configure('Treeview', background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=43, borderwidth=0)
        style.configure('Treeview.Heading', background=FIELD, foreground=MUTED, padding=(8, 10), font=('Segoe UI', 10, 'bold'))
        style.map('Treeview', background=[('selected', '#2b4565')], foreground=[('selected', '#ffffff')])
        style.configure('TLabelframe', padding=12, bordercolor=LINE)
        style.configure('TLabelframe.Label', foreground=MUTED)

    def _build_shell(self):
        top = ttk.Frame(self, padding=(22, 12)); top.pack(fill='x')
        ttk.Label(top, text='NETVERSITY', font=('Segoe UI', 12, 'bold')).pack(side='left')
        ttk.Label(top, text='Network workspace', style='Muted.TLabel').pack(side='left', padx=16)
        ttk.Label(top, text='Administrator' if is_admin() else 'Standard access', style='Muted.TLabel').pack(side='right')
        ttk.Separator(self).pack(fill='x')
        body = ttk.Frame(self); body.pack(fill='both', expand=True)
        nav = ttk.Frame(body, width=175, padding=(8, 18)); nav.pack(side='left', fill='y'); nav.pack_propagate(False)
        self.pages, self.nav_buttons = {}, {}
        content = ttk.Frame(body); content.pack(side='left', fill='both', expand=True)
        self.context = tk.StringVar(value='Detecting active connection…')
        ttk.Label(content, textvariable=self.context, padding=(22, 12), foreground=GOOD,
                  wraplength=800).pack(fill='x')
        ttk.Separator(content).pack(fill='x')
        holder = ttk.Frame(content); holder.pack(fill='both', expand=True)
        holder.rowconfigure(0, weight=1); holder.columnconfigure(0, weight=1)
        mapping = [('Networks', 'network_tab'), ('Devices', 'topology_tab'), ('Security scans', 'vuln_tab'), ('Diagnostics', 'monitor_tab'), ('File sharing', 'http_tab')]
        for name, attr in mapping:
            page = ttk.Frame(holder, padding=(22, 16)); page.grid(row=0, column=0, sticky='nsew')
            setattr(self, attr, page); self.pages[name] = page
            button = ttk.Button(nav, text=name, style='Nav.TButton', command=lambda n=name: self._show_page(n))
            button.pack(fill='x', pady=3); self.nav_buttons[name] = button
        ttk.Button(nav, text='Open logs folder', command=lambda: os.startfile(str(DATA_DIR))).pack(side='bottom', fill='x', pady=8)
        ttk.Label(nav, text=f'Version {APP_VERSION}', style='Muted.TLabel').pack(side='bottom', pady=10)
        self.statusbar = ttk.Label(self, text='Ready', padding=(20, 9), foreground=MUTED)
        self.statusbar.pack(side='bottom', fill='x')

    def _show_page(self, name):
        self.pages[name].tkraise()
        for key, button in self.nav_buttons.items(): button.config(style='Selected.Nav.TButton' if key == name else 'Nav.TButton')

    def _set_status(self, text):
        self.statusbar.config(text=text)

    def _send_magic_packet(self, mac_address: str):
        """Sends a Wake-on-LAN magic packet to the given MAC address."""
        if not mac_address or mac_address.lower() == 'unknown':
            raise ValueError("Invalid MAC address")
        mac_bytes = bytes.fromhex(mac_address.replace(':', '').replace('-', ''))
        if len(mac_bytes) != 6:
            raise ValueError("Invalid MAC address length")
        magic_packet = b'\xff' * 6 + mac_bytes * 16
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(magic_packet, ('255.255.255.255', 9))

    def _open_nmap_help(self):
        HelpWindow(self, title='Nmap flags reference', text=NMAP_FLAGS_HELP)

    def _select_http_folder(self):
        folder = filedialog.askdirectory(parent=self, title='Choose the folder to share')
        if folder:
            self.server_dir = folder; self.http_path_var.set(folder)

    def _save_nmap_output(self):
        if not self._last_raw_output.strip(): return
        path = filedialog.asksaveasfilename(parent=self, defaultextension='.txt',
            initialfile=f'netversity_scan_{time.strftime("%Y%m%d_%H%M%S")}.txt', filetypes=[('Text file', '*.txt')])
        if path:
            try:
                Path(path).write_text(self._last_raw_output, encoding='utf-8')
                self._set_status('Scan output exported.')
            except OSError as exc: self._set_status(str(exc))

    def _heading(self, parent, title, description):
        frame = ttk.Frame(parent); frame.pack(fill='x', pady=(0, 18))
        ttk.Label(frame, text=title, style='Title.TLabel').pack(anchor='w')
        ttk.Label(frame, text=description, style='Muted.TLabel', wraplength=760).pack(anchor='w', pady=(3, 0))
        return frame

    def _tree(self, parent, columns, widths):
        frame = ttk.Frame(parent); frame.pack(fill='both', expand=True)
        tree = ttk.Treeview(frame, columns=columns, show='headings', selectmode='browse')
        for name, width in zip(columns, widths):
            tree.heading(name, text=name, command=lambda c=name: self._sort_tree(tree, c))
            tree.column(name, width=width, minwidth=65, stretch=True)
        sy = ttk.Scrollbar(frame, command=tree.yview)
        sx = ttk.Scrollbar(frame, orient='horizontal', command=tree.xview)
        tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        tree.grid(row=0, column=0, sticky='nsew'); sy.grid(row=0, column=1, sticky='ns'); sx.grid(row=1, column=0, sticky='ew')
        frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
        return tree

    def _sort_tree(self, tree, column):
        values = [(tree.set(i, column), i) for i in tree.get_children()]
        def key(item):
            try: return (0, float(item[0].rstrip('%')))
            except ValueError: return (1, item[0].lower())
        for index, (_, item) in enumerate(sorted(values, key=key)): tree.move(item, '', index)

    def _build_network_ui(self, parent):
        self._heading(parent, 'Networks', 'Your adapters and nearby Wi-Fi networks')
        controls = ttk.Frame(parent); controls.pack(fill='x', pady=(0, 14))
        self.btn_scan = ttk.Button(controls, text='Refresh', command=self._scan_async); self.btn_scan.pack(side='left')
        ttk.Checkbutton(controls, text='Refresh every 15 seconds', variable=self.auto_scan, command=self._toggle_auto_scan).pack(side='left', padx=16)
        self.btn_auto = ttk.Button(controls, text='Connect strongest saved', command=self._auto_reconnect_async); self.btn_auto.pack(side='right')
        split = ttk.Panedwindow(parent, orient='horizontal'); split.pack(fill='both', expand=True)
        left, right = ttk.Frame(split), ttk.Frame(split, padding=(18, 0, 0))
        split.add(left, weight=3); split.add(right, weight=2)
        self.net_tree = self._tree(left, ('Network', 'Type', 'Signal', 'Status'), (180, 70, 70, 115))
        self.net_tree.bind('<<TreeviewSelect>>', self._select_network)
        self.detail_title = ttk.Label(right, text='Select a network', style='Heading.TLabel', wraplength=280); self.detail_title.pack(anchor='w', pady=(3, 12))
        self.detail_text = tk.StringVar(value='Connection details and actions will appear here.')
        ttk.Label(right, textvariable=self.detail_text, justify='left', wraplength=270).pack(anchor='w', fill='x', pady=(0, 16))
        self.btn_connect = ttk.Button(right, text='Connect', command=self._connect_async, style='Accent.TButton', state='disabled'); self.btn_connect.pack(fill='x', pady=4)
        self.btn_disconnect = ttk.Button(right, text='Disconnect', command=self._disconnect_async, state='disabled'); self.btn_disconnect.pack(fill='x', pady=4)
        ttk.Button(right, text='Adapter settings', command=self._open_adapter_settings).pack(fill='x', pady=4)
        ttk.Button(right, text='Copy details', command=lambda: self._copy(self.detail_title.cget('text') + '\n' + self.detail_text.get())).pack(fill='x', pady=4)
        self.network_summary = ttk.Label(parent, text='Scanning…', style='Muted.TLabel'); self.network_summary.pack(fill='x', pady=(12, 0))

    def _network_key(self, net): return net.get('type', 'wifi') + ':' + net['ssid']

    def _populate_cards(self, nets):
        selected = self._network_key(self.selected_net) if self.selected_net else None
        self.networks = {self._network_key(n): n for n in nets}
        pos = self.net_tree.yview()[0]
        self.net_tree.delete(*self.net_tree.get_children())
        for key, n in self.networks.items():
            wired = n.get('type') == 'wired'
            connected = n.get('state') == 'Connected' if wired else n['ssid'] == self.wlan_snapshot.get('SSID')
            state = 'Connected' if connected else 'Disabled' if wired and n.get('admin_state') == 'Disabled' else 'Disconnected' if wired else 'Saved' if n['ssid'] in self.saved_profiles else 'Available'
            self.net_tree.insert('', 'end', iid=key, values=(n['ssid'], 'Ethernet' if wired else 'Wi-Fi', '—' if wired else f"{n.get('signal', 0)}%", state))
        if selected in self.networks:
            self.net_tree.selection_set(selected); self.selected_net = self.networks[selected]
        else:
            self.selected_net = None
            if nets:
                key = next((k for k, n in self.networks.items() if n['ssid'] == self.wlan_snapshot.get('SSID')), next(iter(self.networks)))
                self.net_tree.selection_set(key); self.selected_net = self.networks[key]
        self.net_tree.yview_moveto(pos)
        self._update_details()
        self.network_summary.config(text=f'{len(nets)} adapters / networks · Updated {time.strftime("%H:%M:%S")}' if nets else 'No networks found. Check that an adapter is enabled, then refresh.')

    def _select_network(self, event=None):
        selection = self.net_tree.selection()
        self.selected_net = self.networks.get(selection[0]) if selection else None
        self._update_details()

    def _update_details(self):
        n = self.selected_net
        if not n:
            self.detail_title.config(text='Select a network'); self.detail_text.set('No network selected.')
            self.btn_connect.config(state='disabled'); self.btn_disconnect.config(state='disabled'); return
        wired = n.get('type') == 'wired'
        connected = n.get('state') == 'Connected' if wired else n['ssid'] == self.wlan_snapshot.get('SSID')
        self.detail_title.config(text=n['ssid'])
        parts = [('Type', 'Ethernet adapter' if wired else 'Wi-Fi network'), ('Status', n.get('state', 'Unknown') if wired else 'Connected' if connected else 'Available')]
        if not wired: parts.extend([('Signal', f"{n.get('signal', 0)}%"), ('Security', n.get('auth', 'Unknown')), ('Profile', 'Saved' if n['ssid'] in self.saved_profiles else 'Not saved')])
        if (wired and n['ssid'] == self.current_alias) or (not wired and connected and self.current_alias == self.adapter_snapshot.get('wifi_alias')):
            info = self.adapter_snapshot
            parts.extend([('IPv4', info.get('IPv4') or 'Unavailable'), ('Gateway', info.get('Gateway') or 'Unavailable'), ('DNS', info.get('DNS1') or 'Unavailable'), ('Addressing', 'DHCP' if info.get('DHCP') else 'Manual')])
        self.detail_text.set('\n\n'.join(f'{key}  ·  {value}' for key, value in parts))
        self.btn_connect.config(text='Enable adapter' if wired else 'Connect', state='disabled' if self._network_busy or (wired and n.get('admin_state') == 'Enabled') or (not wired and connected) else 'normal')
        self.btn_disconnect.config(text='Disable adapter' if wired else 'Disconnect', state='normal' if not self._network_busy and (wired and n.get('admin_state') != 'Disabled' or not wired and connected) else 'disabled')

    def _copy(self, text):
        self.clipboard_clear(); self.clipboard_append(text); self._set_status('Copied to clipboard.')

    def _set_busy(self, busy):
        self._network_busy = busy
        for button in (self.btn_scan, self.btn_auto): button.config(state='disabled' if busy else 'normal')
        self._update_details()

    def _scan_async(self):
        if self._network_busy or self._shutting_down.is_set(): return
        self._set_busy(True); self._set_status('Refreshing networks…')
        def work():
            try:
                wired = get_wired_interfaces()
                try: wifi = aggressive_scan_native(3.0)
                except Exception: wifi = scan_burst(2, 1.0)
                return wired + wifi, set(list_saved_profiles()), current_status(), None
            except Exception as exc: return [], set(), {}, str(exc)
        def done(result):
            nets, self.saved_profiles, self.wlan_snapshot, error = result
            self._populate_cards(nets); self._set_busy(False)
            self._set_status('Scan failed: ' + error if error else 'Network list updated.')
        self._job(work, done)

    def _toggle_auto_scan(self):
        if self._auto_after:
            self.after_cancel(self._auto_after); self._auto_after = None
        if self.auto_scan.get(): self._auto_after = self.after(self.scan_interval_ms, self._auto_scan_tick)

    def _auto_scan_tick(self):
        self._auto_after = None
        if self.auto_scan.get() and not self._shutting_down.is_set():
            self._scan_async(); self._auto_after = self.after(self.scan_interval_ms, self._auto_scan_tick)

    def _connect_async(self):
        if not self.selected_net or self._network_busy: return
        n = dict(self.selected_net); wired = n.get('type') == 'wired'; password = None
        if wired and not is_admin():
            messagebox.showinfo('Administrator required', 'Restart Netversity as administrator to enable this adapter.', parent=self); return
        if not wired and n['ssid'] not in self.saved_profiles:
            if is_open_auth(n.get('auth', '')):
                if not messagebox.askyesno('Open Wi-Fi', f"Connect to {n['ssid']} without wireless encryption?", parent=self): return
            else:
                password = simpledialog.askstring('Connect to Wi-Fi', f"Password for {n['ssid']}:", show='*', parent=self)
                if password is None: return
        self._set_busy(True); self._set_status('Enabling adapter…' if wired else f"Connecting to {n['ssid']}…")
        def work():
            try:
                if wired: return set_interface_state(n['ssid'], True), 'Adapter enabled.'
                ok = self._connect_wifi(n, password)
                if not ok: return False, 'Connection request failed. Check the profile or password.'
                for _ in range(15):
                    if self._shutting_down.wait(1): return False, 'Cancelled.'
                    status = current_status()
                    if status.get('SSID') == n['ssid'] and status.get('State', '').lower() == 'connected':
                        return True, f"Connected to {n['ssid']}."
                return False, 'Connection was requested, but association was not confirmed. Refresh or check Windows Wi-Fi settings.'
            except Exception as exc: return False, str(exc)
        self._job(work, self._connection_done)

    def _connect_wifi(self, n, password):
        ssid = n['ssid']
        if ssid in self.saved_profiles: return connect_with_existing_profile(ssid)
        auth = n.get('auth', '').lower()
        if not is_open_auth(auth) and ('enterprise' in auth or '802.1x' in auth or 'wpa3' in auth):
            raise ValueError('Create this enterprise/WPA3 profile in Windows Wi-Fi settings first, then connect using the saved profile.')
        security = '<authEncryption><authentication>open</authentication><encryption>none</encryption><useOneX>false</useOneX></authEncryption>' if is_open_auth(auth) else '<authEncryption><authentication>WPA2PSK</authentication><encryption>AES</encryption><useOneX>false</useOneX></authEncryption><sharedKey><keyType>passPhrase</keyType><protected>false</protected><keyMaterial>' + xml_escape(password or '') + '</keyMaterial></sharedKey>'
        xml = '<?xml version="1.0"?><WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1"><name>' + xml_escape(ssid) + '</name><SSIDConfig><SSID><name>' + xml_escape(ssid) + '</name></SSID></SSIDConfig><connectionType>ESS</connectionType><connectionMode>manual</connectionMode><MSM><security>' + security + '</security></MSM></WLANProfile>'
        with tempfile.TemporaryDirectory(prefix='netversity-wifi-') as temp:
            path = Path(temp) / 'profile.xml'; path.write_text(xml, encoding='utf-8')
            code, out, err = process_args(['netsh', 'wlan', 'add', 'profile', f'filename={path}', 'user=current'])
            if code: raise ValueError(err or out or 'Windows rejected this Wi-Fi profile.')
        return connect_with_existing_profile(ssid)

    def _connection_done(self, result):
        self._set_busy(False); self._set_status(result[1] if result[0] else 'Connection operation failed: ' + result[1])
        self.after(2500, self._scan_async)

    def _disconnect_async(self):
        if not self.selected_net or self._network_busy: return
        n = dict(self.selected_net); wired = n.get('type') == 'wired'
        if wired and not is_admin():
            messagebox.showinfo('Administrator required', 'Restart Netversity as administrator to disable this adapter.', parent=self); return
        self._set_busy(True)
        def work():
            try:
                ok = set_interface_state(n['ssid'], False) if wired else disconnect()
                return ok, ('Adapter disabled.' if wired else 'Disconnect request accepted.') if ok else 'Windows rejected the request.'
            except Exception as exc: return False, str(exc)
        self._job(work, self._connection_done)

    def _auto_reconnect_async(self):
        choices = [n for n in self.networks.values() if n.get('type') == 'wifi' and n['ssid'] in self.saved_profiles]
        if not choices: self._set_status('No saved Wi-Fi network is currently available. Refresh and try again.'); return
        self.net_tree.selection_set(self._network_key(max(choices, key=lambda n: n.get('signal', 0))))
        self._select_network(); self._connect_async()

    def _open_adapter_settings(self):
        n = self.selected_net
        alias = n['ssid'] if n and n.get('type') == 'wired' else self.adapter_snapshot.get('wifi_alias') if n else self.current_alias
        if not alias: self._set_status('No matching adapter is available yet. Wait for connection details or refresh.'); return
        AdapterSettingsDialog(self, alias)

    def _background_status_updater(self):
        while not self._shutting_down.is_set():
            try:
                alias = get_active_interface_alias(); info = get_adapter_info(alias); wlan = current_status()
                info['wifi_alias'] = wifi_interface_alias()
                self.status_queue.put((alias, info, wlan))
            except Exception: pass
            self._shutting_down.wait(4)

    def _monitor_queues(self):
        if self._shutting_down.is_set(): return
        for _ in range(300):
            try: callback = self.ui_queue.get_nowait()
            except queue.Empty: break
            try: callback()
            except tk.TclError: pass  # Closed dialogs may have queued completion callbacks.
            except Exception as exc: self._set_status(f'UI update failed: {exc}')
        while not self.status_queue.empty():
            alias, info, wlan = self.status_queue.get_nowait()
            self.current_alias, self.adapter_snapshot, self.wlan_snapshot = alias, info, wlan
            if not getattr(self, '_targets_initialized', False) and info.get('IPv4') and info.get('Mask'):
                subnet = str(ipaddress.IPv4Network(f"{info['IPv4']}/{info['Mask']}", strict=False))
                if not self.device_target.get(): self.device_target.insert(0, subnet)
                if not self.v_target.get(): self.v_target.insert(0, subnet)
                if not self.ping_pane._target_var.get(): self.ping_pane._target_var.set(info.get('Gateway') or '')
                self._targets_initialized = True
            name = wlan.get('SSID') if alias == info.get('wifi_alias') else alias
            self.context.set(f"{name or 'No active connection'}   ·   {info.get('IPv4') or 'No IPv4 address'}   ·   {alias or 'No default route'}   ·   Updated {time.strftime('%H:%M:%S')}")
            self._update_details()
        while not self.monitor_queue.empty(): self._apply_monitor_payload(self.monitor_queue.get_nowait())
        while not self.device_queue.empty(): self._apply_devices(self.device_queue.get_nowait())
        self.after(100, self._monitor_queues)

    def _build_vuln_ui(self, parent):
        self._heading(parent, 'Security scans', 'Inspect services, compare scan methods, and review the evidence')
        config = ttk.Frame(parent); config.pack(fill='x')
        config.columnconfigure(0, weight=2); config.columnconfigure(1, weight=1)
        ttk.Label(config, text='Targets · IP, hostname or subnet').grid(row=0, column=0, sticky='w')
        ttk.Label(config, text='Scan preset').grid(row=0, column=1, sticky='w', padx=(12, 0))
        self.v_target = ttk.Entry(config); self.v_target.grid(row=1, column=0, sticky='ew', pady=6)
        self.v_preset = tk.StringVar(value='Fast Scan (-T4)')
        preset = ttk.Combobox(config, textvariable=self.v_preset, values=list(NMAP_PRESETS), state='readonly')
        preset.grid(row=1, column=1, sticky='ew', padx=(12, 0)); preset.bind('<<ComboboxSelected>>', lambda e: self._on_preset_change())
        advanced = ttk.Frame(parent); advanced.pack(fill='x', pady=6)
        ttk.Label(advanced, text='Extra flags').pack(side='left')
        self.v_extra = ttk.Entry(advanced); self.v_extra.pack(side='left', fill='x', expand=True, padx=10)
        ttk.Button(advanced, text='Flags reference', command=self._open_nmap_help).pack(side='right')
        compare = ttk.Frame(parent); compare.pack(fill='x', pady=6)
        self.scan_mode = tk.StringVar(value='Single scan')
        ttk.Combobox(compare, textvariable=self.scan_mode, values=['Single scan', 'Compare methods'], state='readonly', width=18).pack(side='left')
        for title, var in [('SYN', self.comp_syn), ('UDP', self.comp_udp), ('ARP discovery', self.comp_arp)]:
            ttk.Checkbutton(compare, text=title, variable=var).pack(side='left', padx=10)
        buttons = ttk.Frame(parent); buttons.pack(fill='x', pady=(8, 12))
        self.v_start_btn = ttk.Button(buttons, text='Start scan', command=self._start_nmap_scan, style='Accent.TButton'); self.v_start_btn.pack(side='left')
        self.v_stop_btn = ttk.Button(buttons, text='Stop', command=self._stop_nmap_scan, state='disabled'); self.v_stop_btn.pack(side='left', padx=8)
        self.v_save_btn = ttk.Button(buttons, text='Export TXT', command=self._save_nmap_output, state='disabled'); self.v_save_btn.pack(side='left')
        ttk.Button(buttons, text='Export CSV', command=self._export_scan_csv).pack(side='left', padx=8)
        self.scan_state = ttk.Label(buttons, text='Ready' if nmap_installed() else 'Nmap not installed', style='Muted.TLabel'); self.scan_state.pack(side='right')
        self.scan_notebook = ttk.Notebook(parent); self.scan_notebook.pack(fill='both', expand=True)
        result, raw, runs = (ttk.Frame(self.scan_notebook, padding=8) for _ in range(3))
        for frame, name in ((result, 'Results'), (raw, 'Raw output'), (runs, 'Comparison / run details')): self.scan_notebook.add(frame, text=name)
        self.result_tree = self._tree(result, ('Host', 'Port', 'State', 'Service', 'Review'), (130, 85, 110, 130, 90))
        self.result_tree.bind('<<TreeviewSelect>>', self._scan_detail)
        self.scan_detail = tk.StringVar(value='Service review priorities are heuristics, not verified vulnerabilities.')
        ttk.Label(result, textvariable=self.scan_detail, wraplength=730, style='Muted.TLabel').pack(fill='x', pady=8)
        self.v_output = scrolledtext.ScrolledText(raw, bg=PANEL, fg=TEXT, font=('Consolas', 10), wrap='word', state='disabled', relief='flat'); self.v_output.pack(fill='both', expand=True)
        self.run_output = scrolledtext.ScrolledText(runs, bg=PANEL, fg=TEXT, font=('Consolas', 10), wrap='word', state='disabled', relief='flat'); self.run_output.pack(fill='both', expand=True)

    def _on_preset_change(self):
        if self.v_preset.get() == 'Custom': self.v_extra.focus_set()

    def _append_vout(self, text):
        self._last_raw_output += text
        self.v_output.config(state='normal'); self.v_output.insert('end', text); self.v_output.see('end')
        if int(self.v_output.index('end-1c').split('.')[0]) > 6000: self.v_output.delete('1.0', '1000.0')
        self.v_output.config(state='disabled')

    def _start_nmap_scan(self):
        if self._scan_session and self._scan_session.is_alive(): return
        try:
            targets = shlex.split(self.v_target.get().strip())
            if not targets or any(t.startswith('-') for t in targets): raise ValueError('Enter valid target addresses or hostnames, without command flags.')
            extra = shlex.split(self.v_extra.get().strip())
            if any(a.startswith(('-oX', '-oA', '--resume')) for a in extra): raise ValueError('XML output and resume options are managed by Netversity. Use the export buttons.')
            if self.scan_mode.get() == 'Compare methods':
                plans = [(label, flags) for label, flags, enabled in [('SYN', ['-sS', '-T4'], self.comp_syn.get()), ('UDP', ['-sU', '-T4'], self.comp_udp.get()), ('ARP', ['-sn', '-PR'], self.comp_arp.get())] if enabled]
                if not plans: raise ValueError('Select at least one comparison method.')
                if not is_admin(): raise ValueError('Comparison methods require administrator rights.')
            else: plans = [('Single scan', shlex.split(NMAP_PRESETS.get(self.v_preset.get(), '')) + extra)]
        except ValueError as exc:
            self._set_status(str(exc)); return
        if not nmap_installed(): self._set_status('Install Nmap to use Security scans. Other tools remain available.'); return
        self._last_raw_output = ''; self._scan_rows = []
        self.result_tree.delete(*self.result_tree.get_children())
        for text in (self.v_output, self.run_output): text.config(state='normal'); text.delete('1.0', 'end'); text.config(state='disabled')
        self.v_start_btn.config(state='disabled'); self.v_stop_btn.config(state='normal'); self.v_save_btn.config(state='disabled')
        self.scan_state.config(text='Running…')
        session = ScanSession(targets, plans, lambda kind, data: self._post(self._scan_event, session, kind, data))
        self._scan_session = session; session.start()

    def _scan_event(self, session, kind, data):
        if session is not self._scan_session: return
        if kind == 'line': self._append_vout(data); return
        state, rows, hosts, failures = data
        self._scan_rows = rows
        for index, row in enumerate(rows): self.result_tree.insert('', 'end', iid=str(index), values=row[:5])
        summary = f'{state}\n{len(set(ip for _, ip, status in hosts if status == "up"))} hosts up; {len(rows)} port observations.\n\n'
        summary += '\n'.join(f'{label}: {ip} — {status}' for label, ip, status in hosts)
        summary += '\n\n' + '\n'.join(failures)
        self.run_output.config(state='normal'); self.run_output.insert('end', summary); self.run_output.config(state='disabled')
        self._append_vout('\n' + summary + '\n')
        self.scan_state.config(text=state); self.v_start_btn.config(state='normal'); self.v_stop_btn.config(state='disabled'); self.v_save_btn.config(state='normal')
        self._set_status(f'Scan {state.lower()}. Partial results are retained where available.')

    def _scan_detail(self, event=None):
        ids = self.result_tree.selection()
        if ids:
            row = self._scan_rows[int(ids[0])]
            text = row[5] or 'No version reported.'
            if row[6]: text += '\n' + row[6]
            self.scan_detail.set(text[:700] + '\nReview priority describes exposure, not a confirmed vulnerability.')

    def _stop_nmap_scan(self):
        if self._scan_session:
            self.scan_state.config(text='Stopping…'); self.v_stop_btn.config(state='disabled'); self._scan_session.stop()

    def _export_scan_csv(self):
        if not self._scan_rows: self._set_status('There are no structured results to export.'); return
        path = filedialog.asksaveasfilename(parent=self, defaultextension='.csv', initialfile='netversity_scan.csv', filetypes=[('CSV', '*.csv')])
        if path:
            try:
                with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                    writer = csv.writer(f); writer.writerow(['Host', 'Port', 'State', 'Service', 'Review priority', 'Version', 'Evidence']); writer.writerows(self._scan_rows)
                self._set_status('Scan results exported.')
            except OSError as exc: self._set_status(str(exc))

    def _build_topology_ui(self, parent):
        self._heading(parent, 'Devices', 'Discover hosts and review changes against a saved network baseline')
        row = ttk.Frame(parent); row.pack(fill='x', pady=(0, 12))
        self.device_target = ttk.Entry(row, width=22); self.device_target.pack(side='left')
        self.device_start = ttk.Button(row, text='Start discovery', command=self._start_devices, style='Accent.TButton'); self.device_start.pack(side='left', padx=8)
        ttk.Button(row, text='Stop', command=self._stop_devices).pack(side='left')
        ttk.Button(row, text='Save baseline', command=self._save_device_baseline).pack(side='left', padx=8)
        ttk.Button(row, text='Alert log', command=self._device_alert_log).pack(side='left')

        self.continuous_monitoring = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text='Continuous Monitoring', variable=self.continuous_monitoring, command=self._toggle_continuous).pack(side='left', padx=16)

        self.device_state = ttk.Label(parent, text='Choose a local subnet, then start discovery. Maximum 4,096 addresses.', style='Muted.TLabel'); self.device_state.pack(fill='x', pady=(0, 12))

        # Add warning banner for ARP Spoofing / Address changes
        self.device_alert_banner = tk.Label(parent, text='', bg=BAD, fg='#000000', font=('Segoe UI', 10, 'bold'), padx=10, pady=5)
        notebook = ttk.Notebook(parent); notebook.pack(fill='both', expand=True)
        table, graph = ttk.Frame(notebook, padding=8), ttk.Frame(notebook, padding=8)
        notebook.add(table, text='Device list'); notebook.add(graph, text='Network map')
        self.device_tree = self._tree(table, ('Address', 'Name', 'MAC', 'Vendor estimate', 'OS estimate', 'Review'), (115, 145, 150, 120, 115, 125))
        actions = ttk.Frame(table); actions.pack(fill='x', pady=(12, 0))
        ttk.Button(actions, text='Ping selected', command=self._ping_device).pack(side='left')
        ttk.Button(actions, text='Scan selected', command=self._scan_device).pack(side='left', padx=8)
        ttk.Button(actions, text='Copy selected', command=self._copy_device).pack(side='left')
        ttk.Button(actions, text='Wake selected', command=self._wake_device).pack(side='left', padx=8)
        ttk.Label(graph, text='Inferred gateway relationships · Not a physical wiring map', style='Muted.TLabel').pack(anchor='w', pady=(0, 8))
        self.device_fig = self.device_canvas = None
        if mpl_figure and FigureCanvasTkAgg and nx:
            self.device_fig = mpl_figure.Figure(facecolor=PANEL)
            self.device_ax = self.device_fig.add_subplot(111); self.device_ax.set_facecolor(PANEL); self.device_ax.axis('off')
            self.device_canvas = FigureCanvasTkAgg(self.device_fig, graph); self.device_canvas.get_tk_widget().pack(fill='both', expand=True)
        else: ttk.Label(graph, text='Install matplotlib and networkx to enable the optional map.').pack(pady=20)

    def _start_devices(self):
        if self.device_engine and self.device_engine.is_alive():
            if self.device_engine._stop_evt.is_set(): self._set_status('Discovery is still stopping.'); return
            self.device_engine.refresh_now(); self.device_state.config(text='Refresh requested…'); return
        try:
            network = ipaddress.IPv4Network(self.device_target.get().strip(), strict=False)
            if network.num_addresses > 4096: raise ValueError('Use a subnet containing at most 4,096 addresses.')
        except ValueError as exc: self._set_status(str(exc)); return
        self.baseline_file = DATA_DIR / ('baseline_' + str(network).replace('/', '_') + '.json')
        try: self.baseline = json.loads(self.baseline_file.read_text()) if self.baseline_file.exists() else {}
        except (OSError, ValueError): self.baseline = {}
        self._alerted_ips.clear()
        while not self.device_queue.empty(): self.device_queue.get_nowait()
        gateway = self.adapter_snapshot.get('Gateway')
        interval = 300 if getattr(self, 'continuous_monitoring', None) and self.continuous_monitoring.get() else 30
        self.device_engine = TopoEngine(str(network), gateway, self.baseline, interval=interval, out_q=self.device_queue)
        self.device_engine.start(); self.device_start.config(text='Refresh now'); self.device_target.config(state='disabled')
        if interval == 300:
            self.device_state.config(text=f'Monitoring {network} continuously… Updates every 5 minutes.')
        else:
            self.device_state.config(text=f'Discovering {network}… Updates every 30 seconds after each sweep.')

    def _stop_devices(self):
        if self.device_engine:
            self.device_engine.stop(); self.device_state.config(text='Stopping discovery…'); self.after(200, self._devices_stopped)

    def _devices_stopped(self):
        if self.device_engine and self.device_engine.is_alive(): self.after(200, self._devices_stopped); return
        self.device_engine = None; self.device_start.config(text='Start discovery'); self.device_target.config(state='normal')
        self.device_state.config(text='Discovery stopped. Last results retained.')

    def _toggle_continuous(self):
        if self.continuous_monitoring.get():
            if self.device_engine:
                self.device_engine.interval = 300 # 5 minutes interval for continuous scan loop.
                self.device_state.config(text=self.device_state.cget('text').replace('30 seconds', '5 minutes').replace('Discovering', 'Monitoring').replace('after each sweep.', 'continuously…'))
            else:
                self._start_devices()
        else:
            if self.device_engine:
                self.device_engine.interval = 30 # Revert to default behavior
                self.device_state.config(text=self.device_state.cget('text').replace('5 minutes', '30 seconds').replace('Monitoring', 'Discovering').replace('continuously…', 'after each sweep.'))

    def _apply_devices(self, payload):
        self.device_nodes = payload.get('nodes', [])
        selected = self.device_tree.selection()
        self.device_tree.delete(*self.device_tree.get_children())
        spoof_warnings = []
        for n in self.device_nodes:
            self.device_tree.insert('', 'end', iid=n['ip'], values=(n['ip'], n.get('name') or 'Unnamed', n.get('mac'), n.get('vendor'), n.get('os') or 'Unknown', n.get('status')))
            if n['status'] in ('Newly observed', 'Address changed') and n['ip'] not in self._alerted_ips:
                with (DATA_DIR / 'security_alerts.log').open('a', encoding='utf-8') as f: f.write(f"{datetime.now().isoformat()} {n['ip']} {n['status']} {n.get('mac')}\n")
            if n['status'] == 'Address changed':
                spoof_warnings.append(n['ip'])

        if spoof_warnings:
            self.device_alert_banner.config(text=f"WARNING: MAC Address changed for IP(s): {', '.join(spoof_warnings)}. Possible ARP Spoofing detected!")
            self.device_alert_banner.pack(fill='x', pady=(0, 10), before=self.device_state)
        else:
            self.device_alert_banner.pack_forget()

        self._alerted_ips = {n['ip'] for n in self.device_nodes if n['status'] in ('Newly observed', 'Address changed')}
        if selected and self.device_tree.exists(selected[0]): self.device_tree.selection_set(selected[0])
        self.device_state.config(text=f"{len(self.device_nodes)} observations · {len(self._alerted_ips)} changes to review · Updated {time.strftime('%H:%M:%S')}")
        if self.device_canvas:
            graph = nx.Graph(); gateway = payload.get('gateway')
            if gateway: graph.add_node(gateway)
            for n in self.device_nodes:
                graph.add_node(n['ip'])
                if gateway and gateway != n['ip']: graph.add_edge(gateway, n['ip'])
            self.device_ax.clear(); self.device_ax.axis('off')
            if len(graph) <= 100 and len(graph):
                positions = nx.spring_layout(graph, seed=42)
                nx.draw_networkx(graph, positions, ax=self.device_ax, node_color='#365f93', edge_color=LINE,
                                 font_color=TEXT, font_size=9, node_size=650, labels={ip:ip for ip in graph})
            elif len(graph) > 100: self.device_ax.text(.5, .5, 'Use the device list for networks with more than 100 hosts.', ha='center', color=TEXT)
            self.device_fig.tight_layout(); self.device_canvas.draw_idle()

    def _save_device_baseline(self):
        if not self.device_nodes or not self.baseline_file: self._set_status('Run discovery before saving a baseline.'); return
        if not messagebox.askyesno('Replace baseline', 'Use the currently responding devices as the baseline for this subnet?', parent=self): return
        self.baseline = {n['ip']: n.get('mac', 'Unknown') for n in self.device_nodes if n['status'] != 'Missing'}
        try:
            self.baseline_file.write_text(json.dumps(self.baseline, indent=2))
            if self.device_engine: self.device_engine.update_baseline(self.baseline); self.device_engine.refresh_now()
            self._set_status('Baseline saved for this subnet.')
        except OSError as exc: self._set_status(str(exc))

    def _device_alert_log(self):
        path = DATA_DIR / 'security_alerts.log'
        HelpWindow(self, title='Device observation log', text=path.read_text(encoding='utf-8') if path.exists() else 'No changes logged yet.')

    def _selected_device(self):
        ids = self.device_tree.selection()
        if not ids: self._set_status('Select a device first.'); return None
        return ids[0]

    def _ping_device(self):
        ip = self._selected_device()
        if ip:
            if self.ping_pane._thread and self.ping_pane._thread.is_alive(): self._set_status('Stop the current ping session before choosing a new target.'); return
            self.ping_pane._target_var.set(ip); self._show_page('Diagnostics'); self.diag_notebook.select(self.ping_pane)

    def _scan_device(self):
        ip = self._selected_device()
        if ip: self.v_target.delete(0, 'end'); self.v_target.insert(0, ip); self._show_page('Security scans')

    def _copy_device(self):
        ip = self._selected_device()
        if ip: self._copy(' | '.join(map(str, self.device_tree.item(ip, 'values'))))

    def _wake_device(self):
        ip = self._selected_device()
        if not ip: return
        values = self.device_tree.item(ip, 'values')
        mac = values[2] if len(values) > 2 else None
        if not mac or mac == 'Unknown':
            self._set_status('Cannot wake device: Unknown MAC address.')
            return
        try:
            self._send_magic_packet(mac)
            self._set_status(f'Wake-on-LAN magic packet sent to {mac}.')
        except Exception as exc:
            self._set_status(f'Failed to send Wake-on-LAN packet: {exc}')

    def _build_http_ui(self, parent):
        self._heading(parent, 'File sharing', 'Share a selected folder over HTTP')
        config = ttk.Frame(parent); config.pack(fill='x')
        ttk.Label(config, text='Shared folder').pack(anchor='w')
        folder = ttk.Frame(config); folder.pack(fill='x', pady=(6, 12))
        self.http_path_var = tk.StringVar(value='Choose a folder to share')
        ttk.Entry(folder, textvariable=self.http_path_var, state='readonly').pack(side='left', fill='x', expand=True)
        self.folder_button = ttk.Button(folder, text='Choose folder', command=self._select_http_folder); self.folder_button.pack(side='left', padx=(10, 0))
        row = ttk.Frame(config); row.pack(fill='x')
        ttk.Label(row, text='Port').pack(side='left')
        self.http_port_var = tk.StringVar(value='8000')
        self.port_entry = ttk.Entry(row, textvariable=self.http_port_var, width=8); self.port_entry.pack(side='left', padx=10)
        self.btn_http_start = ttk.Button(row, text='Start sharing', command=self._start_http_server, style='Accent.TButton'); self.btn_http_start.pack(side='left', padx=8)
        self.btn_http_stop = ttk.Button(row, text='Stop', command=self._stop_http_server, state='disabled'); self.btn_http_stop.pack(side='left')
        self.http_state = ttk.Label(row, text='Stopped', foreground=MUTED); self.http_state.pack(side='right')
        ttk.Label(config, text='Access: all local interfaces · No sign-in · Unencrypted HTTP', style='Muted.TLabel').pack(anchor='w', pady=12)
        self.http_url = tk.StringVar(value='Address appears after the server starts')
        link = ttk.Frame(parent); link.pack(fill='x', pady=(0, 12))
        ttk.Entry(link, textvariable=self.http_url, state='readonly').pack(side='left', fill='x', expand=True)
        ttk.Button(link, text='Copy address', command=lambda: self._copy(self.http_url.get()) if self.http_state.cget('text') == 'Running' else self._set_status('Start sharing to obtain an address.')).pack(side='left', padx=(10, 0))
        self.http_log_area = scrolledtext.ScrolledText(parent, bg=PANEL, fg=TEXT, font=('Consolas', 10), state='disabled', relief='flat', wrap='word')
        self.http_log_area.pack(fill='both', expand=True)

    def _log_http_msg(self, message):
        def append():
            self.http_log_area.config(state='normal'); self.http_log_area.insert('end', message); self.http_log_area.see('end')
            if int(self.http_log_area.index('end-1c').split('.')[0]) > 3000: self.http_log_area.delete('1.0', '1000.0')
            self.http_log_area.config(state='disabled')
        self._post(append)

    def _start_http_server(self):
        if self.http_thread and self.http_thread.is_alive(): return
        try:
            port = int(self.http_port_var.get())
            if not 1 <= port <= 65535: raise ValueError('Port must be between 1 and 65535.')
            if not self.server_dir or not os.path.isdir(self.server_dir): raise ValueError('Choose an existing folder first.')
        except ValueError as exc: self._set_status(str(exc)); return
        self.http_state.config(text='Starting…'); self.btn_http_start.config(state='disabled'); self.folder_button.config(state='disabled'); self.port_entry.config(state='disabled')
        server = SharingServer(port, self.server_dir, lambda state, error: self._post(self._server_event, server, state, error), self._log_http_msg)
        self.http_thread = server; server.start()

    def _server_event(self, server, state, error):
        if server is not self.http_thread: return
        self.http_state.config(text=state, foreground=GOOD if state == 'Running' else BAD if state == 'Failed' else MUTED)
        active = state == 'Running'
        self.btn_http_start.config(state='disabled' if active else 'normal'); self.btn_http_stop.config(state='normal' if active else 'disabled')
        self.folder_button.config(state='disabled' if active else 'normal'); self.port_entry.config(state='disabled' if active else 'normal')
        if active:
            ip = self.adapter_snapshot.get('IPv4') or '127.0.0.1'; self.http_url.set(f'http://{ip}:{server.port}')
        else: self.http_url.set('Server is not running')
        self._log_http_msg(f'{time.strftime("%H:%M:%S")} {state}: {error or server.directory}\n')
        if error: self._set_status('Sharing failed: ' + error)

    def _stop_http_server(self):
        if self.http_thread:
            self.http_thread.stop(); self.http_state.config(text='Stopping…'); self.btn_http_stop.config(state='disabled')

    def _build_monitor_ui(self, parent):
        self._heading(parent, 'Diagnostics', 'Measure gateway reachability, interface traffic and individual targets')
        self.diag_notebook = ttk.Notebook(parent); self.diag_notebook.pack(fill='both', expand=True)
        monitor = ttk.Frame(self.diag_notebook, padding=12)
        self.ping_pane = PingPane(self.diag_notebook)
        self.traceroute_pane = TraceroutePane(self.diag_notebook)
        logs = ttk.Frame(self.diag_notebook, padding=18)
        self.diag_notebook.add(monitor, text='Live monitor'); self.diag_notebook.add(self.ping_pane, text='Ping'); self.diag_notebook.add(self.traceroute_pane, text='Traceroute'); self.diag_notebook.add(logs, text='Logging')
        ctrl = ttk.Frame(monitor); ctrl.pack(fill='x', pady=(0, 14))
        self.btn_mon_start = ttk.Button(ctrl, text='Start monitor', command=self._start_monitor, style='Accent.TButton'); self.btn_mon_start.pack(side='left')
        self.btn_mon_stop = ttk.Button(ctrl, text='Stop', command=self._stop_monitor, state='disabled'); self.btn_mon_stop.pack(side='left', padx=8)
        ttk.Label(ctrl, text='Interval (s)').pack(side='left', padx=(10, 0))
        self.mon_interval_var = tk.StringVar(value='1')
        self.interval_entry = ttk.Entry(ctrl, textvariable=self.mon_interval_var, width=5); self.interval_entry.pack(side='left', padx=8)
        self.mon_status_lbl = ttk.Label(ctrl, text='Idle', style='Muted.TLabel'); self.mon_status_lbl.pack(side='right')
        metrics = ttk.Frame(monitor); metrics.pack(fill='x', pady=(0, 12))
        for index, (name, attr) in enumerate([('Gateway latency', '_mon_lbl_lat'), ('Variation (last 10 replies)', '_mon_lbl_jit'), ('Loss (last 20 probes)', '_mon_lbl_loss')]):
            tile = ttk.Frame(metrics, padding=12, style='Panel.TFrame'); tile.grid(row=0, column=index, sticky='nsew', padx=(0, 8))
            metrics.columnconfigure(index, weight=1)
            tk.Label(tile, text=name, bg=PANEL, fg=MUTED, anchor='w', font=('Segoe UI', 9)).pack(fill='x')
            label = tk.Label(tile, text='—', bg=PANEL, fg=TEXT, anchor='w', font=('Segoe UI', 20, 'bold')); label.pack(fill='x', pady=(5, 0)); setattr(self, attr, label)
        self.mon_context = tk.StringVar(value='No measurements yet. Throughput is adapter traffic, not an Internet speed test.')
        ttk.Label(monitor, textvariable=self.mon_context, style='Muted.TLabel', wraplength=720).pack(fill='x', pady=(0, 8))
        self._mon_fig = self._mon_canvas = self._mon_axes = None
        if mpl_figure and FigureCanvasTkAgg:
            self._mon_fig = mpl_figure.Figure(facecolor=BG, figsize=(7, 4))
            ax_tp, ax_lat = self._mon_fig.subplots(2, 1)
            for ax, ylabel in ((ax_tp, 'Mbps'), (ax_lat, 'ms')):
                ax.set_facecolor(PANEL); ax.tick_params(colors=MUTED, labelsize=9)
                ax.set_ylabel(ylabel, color=MUTED); ax.grid(color=LINE, alpha=.5)
                for spine in ax.spines.values(): spine.set_color(LINE)
            self._mon_line_dl, = ax_tp.plot([], [], color=ACCENT, label='Received')
            self._mon_line_ul, = ax_tp.plot([], [], color=WARN, label='Sent')
            ax_tp.legend(facecolor=PANEL, labelcolor=TEXT, edgecolor=LINE, loc='upper right', fontsize=9)
            self._mon_line_lat, = ax_lat.plot([], [], color=GOOD)
            ax_lat.set_xlabel('Seconds from first visible sample', color=MUTED)
            self._mon_axes = [ax_tp, ax_lat]
            self._mon_fig.tight_layout(pad=1.3)
            self._mon_canvas = FigureCanvasTkAgg(self._mon_fig, monitor); self._mon_canvas.get_tk_widget().pack(fill='both', expand=True)
        else: ttk.Label(monitor, text='Install matplotlib to enable charts. Numeric measurements remain available.').pack(pady=20)
        ttk.Label(logs, text='Signal and gateway latency', style='Heading.TLabel').pack(anchor='w')
        ttk.Label(logs, text=f'CSV files are saved in:\n{DATA_DIR}\n\nRecords include timestamp, interface, SSID, signal percentage and gateway latency.', wraplength=650, style='Muted.TLabel').pack(anchor='w', pady=16)
        self.btn_log = ttk.Button(logs, text='Start logging', command=self._toggle_logging, style='Accent.TButton'); self.btn_log.pack(anchor='w')
        self.lbl_latency = ttk.Label(logs, text='Not recording'); self.lbl_latency.pack(anchor='w', pady=16)
        ttk.Button(logs, text='Open logs folder', command=lambda: os.startfile(str(DATA_DIR))).pack(anchor='w')

    def _start_monitor(self):
        if self._monitor_engine and self._monitor_engine.is_alive(): return
        try:
            interval = int(self.mon_interval_var.get())
            if not 1 <= interval <= 60: raise ValueError()
        except ValueError: self._set_status('Enter a monitor interval from 1 to 60 seconds.'); return
        for values in (self._graph_times, self._graph_dl, self._graph_ul, self._graph_lat): values.clear()
        self._monitor_identity = None
        while not self.monitor_queue.empty(): self.monitor_queue.get_nowait()
        self._monitor_engine = MonitorEngine(interval, self.monitor_queue); self._monitor_engine.start()
        self.btn_mon_start.config(state='disabled'); self.btn_mon_stop.config(state='normal'); self.interval_entry.config(state='disabled'); self.mon_status_lbl.config(text='Running')

    def _stop_monitor(self):
        if self._monitor_engine:
            self._monitor_engine.stop(); self.btn_mon_stop.config(state='disabled'); self.mon_status_lbl.config(text='Stopping…'); self.after(100, self._monitor_stopped)

    def _monitor_stopped(self):
        if self._monitor_engine and self._monitor_engine.is_alive(): self.after(100, self._monitor_stopped); return
        self._monitor_engine = None; self.btn_mon_start.config(state='normal'); self.interval_entry.config(state='normal'); self.mon_status_lbl.config(text='Stopped')

    def _apply_monitor_payload(self, payload):
        lat, jitter, loss = payload.get('latency'), payload.get('jitter'), payload.get('loss_pct')
        dl, ul = payload.get('dl_mbps'), payload.get('ul_mbps')
        self._mon_lbl_lat.config(text=f'{lat} ms' if lat is not None else 'No reply', fg=TEXT if lat is not None else WARN)
        self._mon_lbl_jit.config(text=f'{jitter:.1f} ms' if jitter is not None else '—')
        self._mon_lbl_loss.config(text=f'{loss:.1f}%' if loss is not None else '—', fg=WARN if loss else TEXT)
        rate = lambda x: 'Unavailable' if x is None else f'{x:.2f} Mbps'
        self.mon_context.set(f"{payload.get('alias', '—')} · Gateway {payload.get('gateway', '—')} · ↓ {rate(dl)}  ↑ {rate(ul)} · {time.strftime('%H:%M:%S')}")
        identity = (payload.get('alias'), payload.get('gateway'))
        if getattr(self, '_monitor_identity', None) != identity:
            for values in (self._graph_times, self._graph_dl, self._graph_ul, self._graph_lat): values.clear()
            self._monitor_identity = identity
        for values, value in ((self._graph_times, payload.get('timestamp', time.time())), (self._graph_dl, dl), (self._graph_ul, ul), (self._graph_lat, lat)):
            values.append(value if value is not None else float('nan'))
            del values[:-MONITOR_HISTORY_LEN]
        if self._mon_canvas:
            times = [t - self._graph_times[0] for t in self._graph_times]
            for line, values in ((self._mon_line_dl, self._graph_dl), (self._mon_line_ul, self._graph_ul), (self._mon_line_lat, self._graph_lat)): line.set_data(times, values)
            for ax in self._mon_axes:
                ax.relim(); ax.autoscale_view(); ax.set_xlim(0, max(10, times[-1])); ax.set_ylim(0, max(5, ax.get_ylim()[1]))
            self._mon_canvas.draw_idle()

    def _open_ping_window(self):
        self._show_page('Diagnostics'); self.diag_notebook.select(self.ping_pane)

    def _toggle_logging(self):
        if self.logging_active:
            self.logging_active = False; self.btn_log.config(text='Stopping…', state='disabled'); return
        self.logging_active = True; self.btn_log.config(text='Stop logging')
        filename = DATA_DIR / f'network_log_{datetime.now():%Y%m%d_%H%M%S}.csv'
        def work():
            try:
                with filename.open('w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f); writer.writerow(['Timestamp', 'Interface', 'SSID', 'Signal (%)', 'Latency (ms)'])
                    while self.logging_active and not self._shutting_down.is_set():
                        alias = get_active_interface_alias(); info = get_adapter_info(alias)
                        wlan = current_status() if alias == wifi_interface_alias() else {}
                        signal = re.search(r'\d+', wlan.get('Signal', ''))
                        latency = measure_latency(info['Gateway']) if info.get('Gateway') else None
                        writer.writerow([datetime.now().isoformat(), alias, wlan.get('SSID', ''), signal.group() if signal else '', latency if latency is not None else 'Unavailable']); f.flush()
                        self._post(self.lbl_latency.config, text=f'Last gateway latency: {latency if latency is not None else "Unavailable"} · {filename.name}')
                        self._shutting_down.wait(2)
            finally:
                self.logging_active = False; self._post(self.btn_log.config, text='Start logging', state='normal')
        self._job(work)

    def _on_app_close(self):
        if self._shutting_down.is_set(): return
        self._shutting_down.set(); self.auto_scan.set(False); self.logging_active = False
        self.ping_pane._stop_evt.set()
        for engine in (self._monitor_engine, self.device_engine, self.http_thread, self._scan_session):
            if engine:
                try: engine.stop()
                except Exception: pass
        self._set_status('Closing background tools…')
        self.after(300, self.destroy)


if __name__ == '__main__':
    if sys.platform != 'win32':
        raise SystemExit('Netversity requires Windows.')
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    app = WiFiGUI()
    app.mainloop()
