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
 
def set_static_config(adapter_name: str, ip: str, mask: str, gateway: str, dns1: str, dns2: str = "") -> Tuple[bool, str]:
    """Sets a static IP configuration using netsh with robust input handling."""
    adapter_name = adapter_name.strip().replace('"', '') 
    if gateway and gateway.strip():
        cmd_ip = f'netsh interface ip set address name="{adapter_name}" static {ip} {mask} {gateway} 1'
    else:
        cmd_ip = f'netsh interface ip set address name="{adapter_name}" static {ip} {mask}'
    code, out, _ = run_cmd(cmd_ip)
    if code != 0: return False, f"Failed to set IP Address.\nCommand: {cmd_ip}\nOutput: {out}"
    
    if dns1 and dns1.strip():
        cmd_dns1 = f'netsh interface ip set dns name="{adapter_name}" static {dns1}'
        code, out, _ = run_cmd(cmd_dns1)
        if code != 0: return False, f"Failed to set Primary DNS.\nOutput: {out}"
    if dns2 and dns2.strip():
        cmd_dns2 = f'netsh interface ip add dns name="{adapter_name}" {dns2} index=2'
        run_cmd(cmd_dns2)
    return True, "Static configuration applied successfully."
 
def set_dhcp_config(adapter_name: str) -> Tuple[bool, str]:
    """Resets the adapter to DHCP."""
    adapter_name = adapter_name.strip().replace('"', '')
    cmd_ip = f'netsh interface ip set address name="{adapter_name}" source=dhcp'
    code_ip, out_ip, _ = run_cmd(cmd_ip)
    cmd_dns = f'netsh interface ip set dns name="{adapter_name}" source=dhcp'
    code_dns, out_dns, _ = run_cmd(cmd_dns)
    if code_ip == 0 and code_dns == 0: return True, "Reverted to DHCP successfully."
    else: return False, f"Errors occurred:\nIP: {out_ip}\nDNS: {out_dns}"
 
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
 
def set_interface_state(interface_name: str, enable: bool) -> bool:
    action = "enable" if enable else "disable"
    cmd = f'netsh interface set interface "{interface_name}" admin={action}'
    code, out, err = run_cmd(cmd)
    return code == 0
 
def get_active_interface_alias() -> Optional[str]:
    cmd = 'powershell -NoProfile -Command "Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | Select-Object -ExpandProperty InterfaceAlias -ErrorAction SilentlyContinue"'
    code, out, err = run_cmd(cmd)
    if code == 0 and out.strip(): return out.strip().splitlines()[0].strip()
    return None
 
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
 
def get_adapter_info(alias: str) -> Dict[str, Optional[str]]:
    info = {"IPv4": None, "PrefixLength": None, "Mask": None, "Gateway": None, "DNS1": None, "DNS2": None, "MAC": None, "DHCP": None}
    cmd_base = f'powershell -NoProfile -Command'
    code, out, _ = run_cmd(f'{cmd_base} "(Get-NetIPConfiguration -InterfaceAlias \'{alias}\').IPv4Address | Select -First 1 | ForEach-Object {{ $_.IPAddress, $_.PrefixLength -join \',\' }}"')
    if code == 0 and out.strip():
        parts = out.strip().split(',')
        if len(parts) >= 2:
            info["IPv4"] = parts[0].strip()
            info["PrefixLength"] = parts[1].strip()
            try:
                pre = int(info["PrefixLength"])
                m = ((1 << pre) - 1) << (32 - pre)
                info["Mask"] = '.'.join(str((m >> (8 * i)) & 0xFF) for i in [3,2,1,0])
            except: pass
    code, out, _ = run_cmd(f'{cmd_base} "(Get-NetIPConfiguration -InterfaceAlias \'{alias}\').IPv4DefaultGateway | Select -ExpandProperty NextHop"')
    if code == 0: info["Gateway"] = out.strip().splitlines()[0].strip() if out.strip() else None
    code, out, _ = run_cmd(f'{cmd_base} "(Get-DnsClientServerAddress -InterfaceAlias \'{alias}\' -AddressFamily IPv4).ServerAddresses -join \',\'"')
    if code == 0 and out.strip():
        dns = [x.strip() for x in out.strip().split(',') if x.strip()]
        if dns: info["DNS1"] = dns[0]
        if len(dns) > 1: info["DNS2"] = dns[1]
    code, out, _ = run_cmd(f'{cmd_base} "(Get-NetAdapter -InterfaceAlias \'{alias}\').MacAddress"')
    if code == 0: info["MAC"] = out.strip().splitlines()[0].strip() if out.strip() else None
    code, out, _ = run_cmd(f'{cmd_base} "(Get-NetIPConfiguration -InterfaceAlias \'{alias}\').IPv4Address | Select -First 1 | Select -ExpandProperty PrefixOrigin"')
    if code == 0: info["DHCP"] = "Dhcp" in out
    return info
 
def connect_with_existing_profile(ssid: str) -> bool:
    code, _, _ = run_cmd(f'netsh wlan connect name="{ssid}" ssid="{ssid}"')
    return code == 0
 
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
 
def disconnect() -> bool:
    code, _, _ = run_cmd('netsh wlan disconnect')
    return code == 0
 
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
        self._stop = threading.Event()
        self._kick = threading.Event()   # allows an immediate rescan on demand
 
    def update_baseline(self, new_baseline): self.baseline = new_baseline
    def stop(self): self._stop.set()
    def refresh_now(self): self._kick.set()
 
    def run(self):
        try:
            net = ipaddress.ip_network(self.cidr, strict=False)
            ips = [str(ip) for ip in net.hosts()]
        except ValueError: return
 
        # OPTIMIZATION: Dynamic Thread Pool
        # Scales based on network size (fast for /24, robust for /22)
        max_workers = 25
        if len(ips) > 500: max_workers = 50
        if len(ips) > 4000: max_workers = 100
 
        while not self._stop.is_set():
            self._kick.clear()
            alive_results = {}
            lock = threading.Lock()
            
            # The task for a single IP
            def scan_host(ip):
                if self._stop.is_set(): return
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
                status = "Known"
                if self.baseline:
                    if ip not in self.baseline: status = "New/Rogue"
                    elif self.baseline[ip] != mac and mac != "Unknown": status = "Spoofed?"
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
                if self._stop.is_set(): break
                if self._kick.wait(timeout=1):
                    break
 
class TopoWindow(tk.Toplevel):
    def __init__(self, parent, scan_interval=30):
        super().__init__(parent)
        self.parent = parent
        self.title("Network Discovery (Intelligent)")
        self.geometry("1100x750")
        self.protocol('WM_DELETE_WINDOW', self._on_close)
        
        self.baseline_file = "topology_baseline.json"
        self.baseline = self._load_baseline()
        self.engine: Optional["TopoEngine"] = None

        # Security alerting state: tracks which IPs currently have an
        # active New/Rogue or Spoofed? flag so we only alert once per
        # occurrence (not every 30s refresh) and can re-alert if a
        # device drops off the flagged list and later reappears.
        self.alert_log_file = "security_alerts.log"
        self._alerted_ips = set()
        
        self._setup_ui()
        cidr, _, gw, iface = _get_default_iface_gateway()
        if not cidr:
            messagebox.showerror("Error", "Could not detect local network.")
            self.destroy()
            return
            
        self.status_lbl.config(text=f'Net: {cidr} | Gateway: {gw} | Interface: {iface}')
        
        if nx is None or plt is None or FigureCanvasTkAgg is None:
            messagebox.showerror("Error", "Missing networkx/matplotlib. Install with:\n  pip install networkx matplotlib")
            self.destroy()
            return
            
        self.q = queue.Queue(maxsize=2)
        self.engine = TopoEngine(cidr, gw, baseline=self.baseline, interval=scan_interval, out_q=self.q)
        self.engine.start()
        self.after(500, self._poll_queue)
 
    def _setup_ui(self):
        topf = ttk.Frame(self)
        topf.pack(fill='x', padx=6, pady=6)
        ttk.Button(topf, text='Manual Refresh', command=self._manual_refresh).pack(side='left', padx=4)
        ttk.Button(topf, text='Save as Baseline', command=self._save_baseline).pack(side='left', padx=4)
        ttk.Button(topf, text='Stop Engine', command=self._stop_engine).pack(side='left', padx=4)
        ttk.Button(topf, text='Alert Log', command=self._view_alert_log).pack(side='left', padx=4)
        
        leg_frame = ttk.Frame(topf)
        leg_frame.pack(side='right', padx=10)
        for color, text in [("#90EE90", "Known"), ("#FF9999", "New/Rogue"), ("#D3D3D3", "Missing")]:
            lbl = tk.Label(leg_frame, text=f"  {text}  ", bg=color, relief="solid", borderwidth=1)
            lbl.pack(side='left', padx=2)

        # Security alert banner — hidden until a rogue/spoofed device is detected
        self._alert_banner = tk.Frame(self, bg="#8B0000")
        self._alert_lbl = tk.Label(self._alert_banner, text="", bg="#8B0000", fg="white",
                                    font=("Segoe UI", 9, "bold"), anchor="w", padx=10, pady=6,
                                    wraplength=950, justify="left")
        self._alert_lbl.pack(side="left", fill="x", expand=True)
        tk.Button(self._alert_banner, text="Dismiss", command=self._dismiss_alert_banner,
                  bg="#5a0000", fg="white", activebackground="#3a0000", relief="flat",
                  padx=10).pack(side="right", padx=8, pady=4)
        # Not packed yet — shown on first alert via _show_alert_banner()
 
        self.status_lbl = ttk.Label(self, text='Initializing...', font=('Consolas', 10))
        self.status_lbl.pack(fill='x', padx=6, pady=(0,6))
        
        self.fig, self.ax = plt.subplots(figsize=(10,6))
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)
        self.current_nodes_data = []
 
    def _load_baseline(self):
        if os.path.exists(self.baseline_file):
            try:
                with open(self.baseline_file, 'r') as f: return json.load(f)
            except: pass
        return {}
 
    def _save_baseline(self):
        if not self.current_nodes_data: return
        new_baseline = {}
        for n in self.current_nodes_data:
            if n['status'] != 'Missing': new_baseline[n['ip']] = n.get('mac', 'Unknown')
        try:
            with open(self.baseline_file, 'w') as f: json.dump(new_baseline, f)
            self.baseline = new_baseline
            if self.engine: self.engine.update_baseline(new_baseline)
            messagebox.showinfo("Success", f"Baseline saved with {len(new_baseline)} hosts.")
            self._manual_refresh()
        except Exception as e: messagebox.showerror("Error", str(e))
 
    def _manual_refresh(self):
        if self.engine and self.engine.is_alive():
            self.engine.refresh_now()
            self.status_lbl.config(text="Manual scan triggered...")
        else:
            self.status_lbl.config(text="Engine not running.")
    def _stop_engine(self):
        if self.engine: self.engine.stop()
        self.status_lbl.config(text="Engine stopped.")
    def _on_close(self):
        if self.engine: self.engine.stop()
        self.destroy()

    # ---- Security alerting: rogue devices / spoofed MACs ----

    def _log_security_alert(self, node: Dict):
        """Append a flagged device to the on-disk security alert log (CSV)."""
        try:
            is_new_file = not os.path.exists(self.alert_log_file)
            with open(self.alert_log_file, 'a', newline='') as f:
                w = csv.writer(f)
                if is_new_file:
                    w.writerow(["Timestamp", "IP", "MAC", "Vendor", "Status", "OS Guess"])
                w.writerow([
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    node.get('ip', '?'), node.get('mac', 'Unknown'),
                    node.get('vendor', 'Unknown'), node.get('status', '?'),
                    node.get('os', 'Unknown'),
                ])
        except Exception:
            pass  # logging must never crash the discovery loop

    def _view_alert_log(self):
        if not os.path.exists(self.alert_log_file):
            messagebox.showinfo("Alert Log", "No security alerts have been logged yet.")
            return
        try:
            with open(self.alert_log_file, 'r') as f:
                content = f.read()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return
        HelpWindow(self, title="Security Alert Log", text=content or "(empty)")

    def _dismiss_alert_banner(self):
        self._alert_banner.pack_forget()

    def _flash_alert_banner(self, remaining=6):
        if not self._alert_banner.winfo_ismapped():
            return
        cur = self._alert_banner.cget("bg")
        nxt = "#FF3B30" if cur != "#FF3B30" else "#8B0000"
        self._alert_banner.configure(bg=nxt)
        self._alert_lbl.configure(bg=nxt)
        if remaining > 0:
            self.after(300, lambda: self._flash_alert_banner(remaining - 1))
        else:
            self._alert_banner.configure(bg="#8B0000")
            self._alert_lbl.configure(bg="#8B0000")

    def _show_alert_banner(self, flagged_nodes: List[Dict]):
        parts = [f"{n['status']}: {n['ip']} ({n.get('vendor', 'Unknown')})" for n in flagged_nodes]
        self._alert_lbl.config(text="⚠ SECURITY ALERT — " + "   |   ".join(parts))
        if not self._alert_banner.winfo_ismapped():
            self._alert_banner.pack(fill='x', padx=6, pady=(0, 4), before=self.status_lbl)
        try:
            self.bell()
        except Exception:
            pass
        self._flash_alert_banner()
 
    def _poll_queue(self):
        try:
            payload = self.q.get_nowait()
            self._draw_payload(payload)
        except queue.Empty: pass
        self.after(500, self._poll_queue)
 
    def _draw_payload(self, payload):
        nodes = payload.get('nodes', [])
        gw = payload.get('gateway')
        self.current_nodes_data = nodes

        # Fire an alert only for devices that just became flagged this cycle,
        # not every refresh while they remain flagged. If a device's status
        # later clears, it's removed from the tracked set so a *future*
        # reappearance can alert again.
        current_flagged_ips = {n['ip'] for n in nodes if n['status'] in ('New/Rogue', 'Spoofed?')}
        newly_flagged_ips = current_flagged_ips - self._alerted_ips
        newly_flagged = [n for n in nodes if n['ip'] in newly_flagged_ips]
        for n in newly_flagged:
            self._log_security_alert(n)
        self._alerted_ips = current_flagged_ips
        if newly_flagged:
            self._show_alert_banner(newly_flagged)

        G = nx.Graph()
        if gw: G.add_node(gw, label=f"Gateway\n{gw}", type='gateway', status='Known')
        
        for n in nodes:
            ip = n['ip']
            lines = [ip]
            if n.get('name'): lines.append(n['name'][:15])
            if n.get('vendor'): lines.append(n['vendor'])
            if n.get('os'): lines.append(n['os'])
            G.add_node(ip, label="\n".join(lines), type='host', status=n['status'])
            if gw: G.add_edge(gw, ip)
 
        self.ax.clear()
        if not G.nodes:
            self.canvas.draw()
            return
 
        pos = nx.spring_layout(G, seed=42, k=0.6)
        color_map = []
        size_map = []
        for node in G.nodes:
            attrs = G.nodes[node]
            status = attrs.get('status', 'Known')
            if attrs.get('type') == 'gateway':
                color_map.append('#FFD700')
                size_map.append(1200)
            elif status == 'Missing':
                color_map.append('#D3D3D3')
                size_map.append(400)
            elif status in ['New/Rogue', 'Spoofed?']:
                color_map.append('#FF9999')
                size_map.append(600)
            else:
                color_map.append('#90EE90')
                size_map.append(600)
 
        nx.draw_networkx_nodes(G, pos, node_color=color_map, node_size=size_map, ax=self.ax, edgecolors='black')
        nx.draw_networkx_edges(G, pos, ax=self.ax, alpha=0.5)
        nx.draw_networkx_labels(G, pos, nx.get_node_attributes(G, 'label'), font_size=7, ax=self.ax)
        self.ax.set_axis_off()
        self.fig.tight_layout()
        self.canvas.draw()
        count_alive = sum(1 for n in nodes if n['status'] != 'Missing')
        self.status_lbl.config(text=f"Active Hosts: {count_alive} | Total: {len(nodes)} | Baseline: {'Loaded' if self.baseline else 'Empty'}")
 
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

    if totals["HIGH"] > 0: verdict = "HIGH RISK"
    elif totals["MEDIUM"] > 0: verdict = "MEDIUM RISK"
    elif totals["LOW"] > 0: verdict = "LOW RISK"
    else: verdict = "INFORMATIONAL ONLY"

    header = (f"Overall Verdict: {verdict}\n"
              f"  High-risk: {totals['HIGH']}   Medium-risk: {totals['MEDIUM']}   "
              f"Low-risk: {totals['LOW']}   Informational: {totals['INFO']}")
    return header + "\n" + "\n".join(lines)

def format_security_verdict(hosts: Dict[str, List[Tuple[int, str, str]]]) -> str:
    """Wraps summarize_port_risk() with the standard report banner."""
    body = summarize_port_risk(hosts)
    rule = "=" * 60
    return f"\n{rule}\n=== SECURITY RISK ASSESSMENT ===\n{rule}\n{body}\n{rule}\n"

def build_security_verdict_report(raw_output: str) -> str:
    """Entry point called after a completed scan: parses raw Nmap output and
    returns a formatted security risk assessment block."""
    hosts = extract_hosts_and_ports(raw_output)
    return format_security_verdict(hosts)

class NmapRunner:
    def __init__(self, target, flags, update_cb, finished_cb):
        self.target, self.flags, self.update_cb, self.finished_cb = target, flags, update_cb, finished_cb
        self._proc = None
        self._stop_evt = threading.Event()
    
    def start(self): threading.Thread(target=self._run, daemon=True).start()
    
    def stop(self):
        self._stop_evt.set()
        if self._proc:
            try:
                self._proc.terminate()
                # /T kills the whole process tree, not just this PID. Since the
                # process was launched with shell=True, self._proc.pid is
                # actually cmd.exe's PID — nmap.exe is its CHILD. Without /T,
                # taskkill only killed the (already-dying) cmd.exe wrapper and
                # left nmap.exe itself running in the background.
                subprocess.run(f'taskkill /F /T /PID {self._proc.pid}', shell=True, stdout=subprocess.DEVNULL,
                                creationflags=_NO_WINDOW_FLAGS)
            except: pass
 
    def _run(self):
        nmap_exe = find_nmap_binary()
        if not nmap_exe: 
            self.update_cb("Nmap not found.\n"); self.finished_cb(False, ""); return
        cmd = f'"{nmap_exe}" {self.flags} {self.target}'
        try:
            self._proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                           creationflags=_NO_WINDOW_FLAGS)
            for line in self._proc.stdout:
                if self._stop_evt.is_set(): break
                self.update_cb(line.rstrip("\n"))
            self._proc.wait()
            self.finished_cb(self._proc.returncode==0, "")
        except Exception as e:
            self.update_cb(str(e)); self.finished_cb(False, "")
 
class HelpWindow(tk.Toplevel):
    def __init__(self, parent, title="Nmap Flags Reference", text=""):
        super().__init__(parent)
        self.title(title)
        self.geometry("760x520")
        frm = ttk.Frame(self, padding=8)
        frm.pack(fill='both', expand=True)
        lbl = ttk.Label(frm, text=title, font=("Segoe UI", 11, "bold"))
        lbl.pack(anchor='w')
        txt = scrolledtext.ScrolledText(frm, wrap='word')
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
 
class HttpServerThread(threading.Thread):
    def __init__(self, port, directory, log_callback):
        super().__init__(daemon=True)
        self.port, self.directory, self.log_callback = port, directory, log_callback
        self.httpd = None
        
    def run(self):
        try:
            handler = partial(CustomLoggingHandler, directory=self.directory)
            self.httpd = socketserver.TCPServer(("", self.port), handler)
            self.httpd.log_callback = self.log_callback
            self.log_callback(f"Server started at port {self.port}\nServing: {self.directory}\n")
            self.httpd.serve_forever()
        except Exception as e: self.log_callback(f"Server error: {e}\n")
 
    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.log_callback("Server stopped.\n")
 
# ---------------------------
# Adapter settings dialog
# ---------------------------
 
class AdapterSettingsDialog(tk.Toplevel):
    def __init__(self, master, target_adapter=None):
        super().__init__(master)
        self.title("Adapter Settings")
        self.resizable(False, False)
        self.alias = target_adapter or "Wi-Fi"
        self.mode = tk.StringVar(value="dhcp")
        self._setup_ui()
        self.load_current()
 
    def _setup_ui(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)
        row = 0
        ttk.Label(frm, text=f"Adapter: {self.alias}").grid(row=row, column=0, columnspan=2, sticky="w", pady=(0,6))
        row += 1
        self.lbl_mac = ttk.Label(frm, text="MAC: -"); self.lbl_mac.grid(row=row, column=0, columnspan=2, sticky="w")
        row += 1
        ttk.Separator(frm, orient="horizontal").grid(row=row, column=0, columnspan=2, sticky="ew", pady=8); row += 1
        ttk.Radiobutton(frm, text="DHCP (automatic)", variable=self.mode, value="dhcp").grid(row=row, column=0, sticky="w")
        ttk.Radiobutton(frm, text="Static (manual)",  variable=self.mode, value="static").grid(row=row, column=1, sticky="w")
        row += 1
        ttk.Label(frm, text="IPv4 Address").grid(row=row, column=0, sticky="w")
        self.ent_ip = ttk.Entry(frm, width=22); self.ent_ip.grid(row=row, column=1, sticky="w"); row += 1
        ttk.Label(frm, text="Subnet Mask").grid(row=row, column=0, sticky="w")
        self.ent_mask = ttk.Entry(frm, width=22); self.ent_mask.grid(row=row, column=1, sticky="w"); row += 1
        ttk.Label(frm, text="Gateway").grid(row=row, column=0, sticky="w")
        self.ent_gw = ttk.Entry(frm, width=22); self.ent_gw.grid(row=row, column=1, sticky="w"); row += 1
        ttk.Label(frm, text="Primary DNS").grid(row=row, column=0, sticky="w")
        self.ent_dns1 = ttk.Entry(frm, width=22); self.ent_dns1.grid(row=row, column=1, sticky="w"); row += 1
        ttk.Label(frm, text="Secondary DNS").grid(row=row, column=0, sticky="w")
        self.ent_dns2 = ttk.Entry(frm, width=22); self.ent_dns2.grid(row=row, column=1, sticky="w"); row += 1
        btns = ttk.Frame(frm); btns.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(8,0))
        ttk.Button(btns, text="Load", command=self.load_current).pack(side="left")
        ttk.Button(btns, text="Apply Static", command=self.apply_static).pack(side="left", padx=6)
        ttk.Button(btns, text="Reset DHCP", command=self.reset_dhcp).pack(side="left")
        ttk.Button(btns, text="Close", command=self.destroy).pack(side="right")
 
    def load_current(self):
        info = get_adapter_info(self.alias)
        self.lbl_mac.config(text=f"MAC: {info.get('MAC') or '-'}")
        if info.get("DHCP") is True: self.mode.set("dhcp")
        elif info.get("IPv4"): self.mode.set("static")
        self.ent_ip.delete(0, tk.END);   self.ent_ip.insert(0, info.get("IPv4") or "")
        self.ent_mask.delete(0, tk.END); self.ent_mask.insert(0, info.get("Mask") or "")
        self.ent_gw.delete(0, tk.END);   self.ent_gw.insert(0, info.get("Gateway") or "")
        self.ent_dns1.delete(0, tk.END); self.ent_dns1.insert(0, info.get("DNS1") or "")
        self.ent_dns2.delete(0, tk.END); self.ent_dns2.insert(0, info.get("DNS2") or "")
 
    def apply_static(self):
        if not is_admin(): messagebox.showerror("Error", "Admin required."); return
        ok, msg = set_static_config(self.alias, self.ent_ip.get(), self.ent_mask.get(), self.ent_gw.get(), self.ent_dns1.get(), self.ent_dns2.get())
        if ok: messagebox.showinfo("Success", "Settings applied."); self.load_current()
        else: messagebox.showerror("Error", msg)
 
    def reset_dhcp(self):
        if not is_admin(): messagebox.showerror("Error", "Admin required."); return
        ok, msg = set_dhcp_config(self.alias)
        if ok: messagebox.showinfo("Success", "Reset to DHCP."); self.load_current()
        else: messagebox.showerror("Error", msg)
 
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
def _get_adapter_bytes_ps(alias: str) -> Tuple[Optional[int], Optional[int]]:
    """
    Returns (bytes_recv, bytes_sent) using PowerShell.
    Safe: no ctypes struct manipulation.  Runs in ~100-250 ms on warm PS.
    Called from a pool thread so latency is absorbed in parallel.
    """
    if not alias:
        return None, None
    try:
        cmd = (
            'powershell -NoProfile -Command '
            f'"$s=Get-NetAdapterStatistics -Name \'{alias}\' -EA Stop;'
            f'$s.ReceivedBytes,$s.SentBytes -join \',\'"'
        )
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              startupinfo=si, shell=True, timeout=3)
        if proc.returncode == 0 and proc.stdout.strip():
            parts = proc.stdout.strip().split(',')
            if len(parts) >= 2:
                return int(parts[0].strip()), int(parts[1].strip())
    except Exception:
        pass
    return None, None
 
 
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
        self._pool.shutdown(wait=False)
 
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
        if len(hist) < 2: return 0.0
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
                    _, _, gw, _ = _get_default_iface_gateway()
                    alias = get_active_interface_alias()
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
 
            jitter = 0.0
            window = self._lat_hist[-MONITOR_JITTER_WIN:]
            if len(window) >= 2:
                jitter = round(statistics.stdev(window), 2)
 
            # 6. Throughput
            now = time.time()
            dl_mbps = ul_mbps = 0.0
            if recv_b is not None:
                dl_mbps = self._bytes_to_mbps(self._dl_hist, now, recv_b)
            if sent_b is not None:
                ul_mbps = self._bytes_to_mbps(self._ul_hist, now, sent_b)
 
            # 7. Push payload
            payload = {
                'latency'  : rtt,
                'jitter'   : jitter,
                'loss_pct' : loss_pct,
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
 
class WiFiGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Network Manager (R4 Final)")
        self.geometry("1100x800")
        self.minsize(950, 650)
        self.configure(bg='#1e1e1e')
        self.protocol('WM_DELETE_WINDOW', self._on_app_close)
        
        self.wifi_icon = None
        self.eth_icon = None
        self._load_icons()
 
        self.auto_scan = tk.BooleanVar(value=False)
        self.scan_interval_ms = 15000
        self.v_verbosity_level = 1
        
        self.selected_net: Optional[Dict] = None
        self.cards = {} 
 
        # Comparison State
        self.comp_syn = tk.BooleanVar(value=False)
        self.comp_udp = tk.BooleanVar(value=False)
        self.comp_arp = tk.BooleanVar(value=False)
        self._comp_thread = None
        self._comp_stop_evt = threading.Event()
 
        # Logging State
        self.logging_active = False
 
        # HTTP Server State
        self.http_thread = None
        self.server_dir = os.getcwd()
 
        # Network Monitor State
        self._monitor_engine: Optional[MonitorEngine] = None
        self.monitor_queue: queue.Queue = queue.Queue(maxsize=5)
        # graph data series kept on GUI side for rendering
        self._graph_times: List[float] = []
        self._graph_dl:    List[float] = []
        self._graph_ul:    List[float] = []
        self._graph_lat:   List[float] = []
 
        # Thread-safe queues for UI updates
        self.log_ui_queue = queue.Queue()
        self.status_queue = queue.Queue() # NEW: Status update queue

        # App-wide shutdown flag + tracked .after() ids, so every polling
        # loop (background daemon threads AND self.after() reschedulers)
        # can be told to stop cleanly on close instead of running forever
        # against a root window that's being torn down.
        self._shutting_down = threading.Event()
        self._after_ids: List[str] = []

        # Start background workers
        self._monitor_queues()
        threading.Thread(target=self._background_status_updater, daemon=True).start()
 
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background="#1e1e1e", borderwidth=0)
        style.configure("TNotebook.Tab", background="#333333", foreground="#ffffff", padding=[10, 5])
        style.map("TNotebook.Tab", background=[("selected", "#4caf50")])
        style.configure("TFrame", background="#1e1e1e")
        style.configure("TLabel", background="#1e1e1e", foreground="#ffffff")
        style.configure("TButton", background="#333333", foreground="#ffffff", borderwidth=1)
        style.map("TButton", background=[('active', '#4caf50')])
        style.configure("TLabelframe", background="#1e1e1e", foreground="#ffffff")
        style.configure("TLabelframe.Label", background="#1e1e1e", foreground="#4caf50")
        style.configure("TCheckbutton", background="#1e1e1e", foreground="#ffffff")
 
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)
        self.network_tab = ttk.Frame(self.notebook)
        self.vuln_tab = ttk.Frame(self.notebook)
        self.topology_tab = ttk.Frame(self.notebook)
        self.http_tab = ttk.Frame(self.notebook)
        self.monitor_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.network_tab, text="Networks")
        self.notebook.add(self.vuln_tab, text="Vulnerability Assessment")
        self.notebook.add(self.topology_tab, text="Network Discovery")
        self.notebook.add(self.http_tab, text="File Server (HTTP)")
        self.notebook.add(self.monitor_tab, text="Network Monitor")
        
        self._build_network_ui(self.network_tab)
        self._build_vuln_ui(self.vuln_tab)
        self._build_topology_ui(self.topology_tab)
        self._build_http_ui(self.http_tab)
        self._build_monitor_ui(self.monitor_tab)
        
        self._scan_async()
 
    def _monitor_queues(self):
        """Unified monitor for all background thread updates."""
        # 1. Latency Updates (from performance logging loop)
        try:
            while True:
                latency = self.log_ui_queue.get_nowait()
                self.lbl_latency.config(text=f"Latency: {latency} ms")
        except queue.Empty: pass
        
        # 2. Status Panel Updates
        try:
            while not self.status_queue.empty():
                data = self.status_queue.get_nowait()
                self.lbl_type.config(text=f"Active Interface: {data['alias']}")
                self.lbl_ssid.config(text=f"Name/SSID: {data['ssid']}")
                self.lbl_ip.config(text=f"IPv4: {data['ip']}")
                self.lbl_dns1.config(text=f"DNS 1: {data['dns1']}")
                self.lbl_dns2.config(text=f"DNS 2: {data['dns2']}")
                self.lbl_sig.config(text=f"Signal: {data['signal']}")
                self.lbl_auth.config(text=f"Auth: {data['auth']}")
        except queue.Empty: pass
 
        # 3. Network Monitor Updates
        try:
            while not self.monitor_queue.empty():
                payload = self.monitor_queue.get_nowait()
                self._apply_monitor_payload(payload)
        except queue.Empty: pass
        
        # Only reschedule while the app isn't tearing down. Without this
        # check, this self.after() chain runs forever - even after
        # destroy() - since nothing ever broke the reschedule loop.
        if not self._shutting_down.is_set():
            self.after(100, self._monitor_queues)
 
    def _background_status_updater(self):
        """
        Runs in background. Fetches heavy PowerShell data. Never blocks UI.

        Originally `while True:` with no exit condition - a daemon thread,
        so it shouldn't by itself prevent process exit, but each loop runs
        several blocking subprocess.run() calls (via run_cmd) that take a
        real amount of time to return. If shutdown happens mid-call, the
        exe can sit around until that in-flight call finishes rather than
        exiting immediately. Checking _shutting_down lets it exit between
        iterations instead of always waiting for the next process kill.
        """
        while not self._shutting_down.is_set():
            try:
                # 1. Get Active Interface (Slow)
                alias = get_active_interface_alias()
                
                # 2. Get Details (Very Slow)
                info = get_adapter_info(alias) if alias else {}
                wlan = current_status()
                
                # Pack data
                payload = {
                    'alias': alias or "None",
                    'ip': info.get('IPv4', '-'),
                    'dns1': info.get('DNS1', '-'),
                    'dns2': info.get('DNS2', '-'), # ADDED THIS BACK
                    'ssid': wlan.get('SSID', '-'),
                    'signal': wlan.get('Signal', '-'),
                    'auth': wlan.get('Authentication', '-')
                }
                
                # Send to UI
                self.status_queue.put(payload)
                
            except Exception: pass
            
            # Interruptible sleep: Event.wait() returns immediately once
            # _shutting_down is set, instead of a flat time.sleep(2) that
            # would make close() wait up to 2s for this loop to notice.
            self._shutting_down.wait(timeout=2)
 
    def _load_icons(self):
        icon_size = (50, 40)
        wifi_path = resource_path("wifi_icon.png")
        eth_path = resource_path("ethernet_icon.png")
        if os.path.exists(wifi_path):
            try:
                if HAS_PIL:
                    self.wifi_icon = ImageTk.PhotoImage(Image.open(wifi_path).resize(icon_size, Image.Resampling.LANCZOS))
                else: 
                    self.wifi_icon = tk.PhotoImage(file=wifi_path).subsample(4, 4)
            except: pass
        if os.path.exists(eth_path):
            try:
                if HAS_PIL:
                    self.eth_icon = ImageTk.PhotoImage(Image.open(eth_path).resize(icon_size, Image.Resampling.LANCZOS))
                else: 
                    self.eth_icon = tk.PhotoImage(file=eth_path).subsample(4, 4)
            except: pass
 
    # ---------- Network Monitoring Logic ----------
    def _toggle_logging(self):
        if self.logging_active:
            self.logging_active = False
            self.btn_log.config(text="Start Logging (RSSI/Latency)")
            self._set_status("Logging stopped.")
        else:
            self.logging_active = True
            self.btn_log.config(text="Stop Logging")
            self._set_status("Logging enabled. Writing to wifi_log.csv...")
            threading.Thread(target=self._logging_loop, daemon=True).start()
 
    def _logging_loop(self):
        filename = "wifi_log.csv"
        if not os.path.exists(filename):
            with open(filename, 'w', newline='') as f:
                csv.writer(f).writerow(["Timestamp", "Interface", "SSID", "Signal (%)", "Latency (ms)"])
 
        while self.logging_active:
            try:
                active_alias = get_active_interface_alias()
                wlan_status = current_status()
                
                ssid = wlan_status.get('SSID', 'Unknown')
                sig_str = wlan_status.get('Signal', '0%')
                signal = int(re.search(r'\d+', sig_str).group()) if re.search(r'\d+', sig_str) else 0
                
                # Measure Latency
                gateway = get_adapter_info(active_alias or "Wi-Fi").get("Gateway")
                latency = "Timeout"
                if gateway:
                    lat_val = measure_latency(gateway)
                    if lat_val is not None: latency = lat_val
                
                self.log_ui_queue.put(latency)
 
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(filename, 'a', newline='') as f:
                    csv.writer(f).writerow([timestamp, active_alias, ssid, signal, latency])
            except Exception as e: print(f"Log error: {e}")
            # Interruptible: lets shutdown proceed without waiting out a
            # full flat sleep once logging_active flips to False.
            self._shutting_down.wait(timeout=2)
 
    # ---------- HTTP Server UI ----------
    def _build_http_ui(self, parent):
        top_frame = ttk.Frame(parent, padding=15)
        top_frame.pack(fill="x")
        cfg_frame = ttk.LabelFrame(top_frame, text="Server Configuration", padding=10)
        cfg_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(cfg_frame, text="Root Directory:").grid(row=0, column=0, sticky="w", padx=5)
        self.http_path_var = tk.StringVar(value=os.getcwd())
        ttk.Entry(cfg_frame, textvariable=self.http_path_var, width=50, state="readonly").grid(row=0, column=1, padx=5, sticky="ew")
        ttk.Button(cfg_frame, text="Select Folder...", command=self._select_http_folder).grid(row=0, column=2, padx=5)
        
        ttk.Label(cfg_frame, text="Port:").grid(row=1, column=0, sticky="w", padx=5, pady=10)
        self.http_port_var = tk.StringVar(value="8000")
        ttk.Entry(cfg_frame, textvariable=self.http_port_var, width=10).grid(row=1, column=1, sticky="w", padx=5)
        
        btn_frame = ttk.Frame(top_frame)
        btn_frame.pack(fill="x", pady=5)
        self.btn_http_start = ttk.Button(btn_frame, text="Start Server", command=self._start_http_server)
        self.btn_http_start.pack(side="left", padx=5)
        self.btn_http_stop = ttk.Button(btn_frame, text="Stop Server", command=self._stop_http_server, state="disabled")
        self.btn_http_stop.pack(side="left", padx=5)
        
        log_frame = ttk.LabelFrame(parent, text="Server Logs", padding=10)
        log_frame.pack(fill="both", expand=True, padx=15, pady=10)
        self.http_log_area = scrolledtext.ScrolledText(log_frame, height=15, bg="#2d2d2d", fg="#ffffff", state="disabled")
        self.http_log_area.pack(fill="both", expand=True)
 
    def _select_http_folder(self):
        folder = filedialog.askdirectory()
        if folder: self.server_dir = folder; self.http_path_var.set(folder)
 
    def _log_http_msg(self, message):
        def _append():
            self.http_log_area.config(state="normal")
            self.http_log_area.insert(tk.END, message)
            self.http_log_area.see(tk.END)
            self.http_log_area.config(state="disabled")
        self.after(0, _append)
 
    def _start_http_server(self):
        try: port = int(self.http_port_var.get())
        except: messagebox.showerror("Error", "Port must be int"); return
        if self.http_thread and self.http_thread.is_alive(): return
        self.http_thread = HttpServerThread(port, self.server_dir, self._log_http_msg)
        self.http_thread.start()
        self.btn_http_start.config(state="disabled"); self.btn_http_stop.config(state="normal")
        self._log_http_msg(f"--- Started on Port {port} ---\n")
 
    def _stop_http_server(self):
        # httpd.shutdown() blocks until serve_forever()'s loop notices the
        # shutdown flag (polled periodically), which can stall briefly.
        # Calling it directly on the Tk main thread froze the whole GUI —
        # no redraws, no queue draining — especially while other engines
        # (Discovery, Monitor, Nmap) were already busy. Run it on a
        # disposable background thread instead so the main loop never blocks.
        if self.http_thread:
            t = self.http_thread
            self.http_thread = None
            threading.Thread(target=t.stop, daemon=True).start()
        self.btn_http_start.config(state="normal"); self.btn_http_stop.config(state="disabled")
 
    # ---------- network UI ----------
    def _build_network_ui(self, parent):
        top = ttk.Frame(parent, padding=15)
        top.pack(fill="x")
        self.btn_scan = ttk.Button(top, text="Refresh Scan", command=self._scan_async)
        self.btn_scan.pack(side="left", padx=(0,10))
        self.btn_connect = ttk.Button(top, text="Connect / Enable", command=self._connect_async)
        self.btn_connect.pack(side="left", padx=10)
        self.btn_disconnect = ttk.Button(top, text="Disconnect / Disable", command=self._disconnect_async)
        self.btn_disconnect.pack(side="left", padx=10)
        self.btn_auto = ttk.Button(top, text="Auto-Connect (WiFi)", command=self._auto_reconnect_async)
        self.btn_auto.pack(side="left", padx=10)
 
        # LOGGING BUTTON (NEW)
        self.btn_log = ttk.Button(top, text="Start Logging (RSSI/Latency)", command=self._toggle_logging)
        self.btn_log.pack(side="left", padx=20)
 
        # PING BUTTON
        self.btn_ping = ttk.Button(top, text="Ping", command=self._open_ping_window)
        self.btn_ping.pack(side="left", padx=(0, 10))
 
        extra_opts = ttk.Frame(top)
        extra_opts.pack(side="right")
        ttk.Button(extra_opts, text="Settings", command=self._open_adapter_settings).pack(side="left", padx=5)
        chk = ttk.Checkbutton(extra_opts, text="Auto-Scan (15s)", variable=self.auto_scan, command=self._toggle_auto_scan)
        chk.pack(side="left", padx=5)
 
        canvas_frame = tk.Frame(parent, bg='#1e1e1e')
        canvas_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.canvas = tk.Canvas(canvas_frame, bg='#1e1e1e', highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.canvas.yview)
        self.cards_frame = tk.Frame(self.canvas, bg='#1e1e1e')
        self.cards_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.cards_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
 
        status_frame = ttk.LabelFrame(parent, text="Current Network Status", padding=10)
        status_frame.pack(fill="x", padx=10, pady=10)
        self.lbl_type = ttk.Label(status_frame, text="Active Interface: -", font=("Segoe UI", 9, "bold"))
        self.lbl_ssid = ttk.Label(status_frame, text="Name/SSID: -")
        self.lbl_auth = ttk.Label(status_frame, text="Auth: -")
        self.lbl_sig  = ttk.Label(status_frame, text="Signal: -")
        self.lbl_ip   = ttk.Label(status_frame, text="IPv4: -")
        self.lbl_dns1 = ttk.Label(status_frame, text="DNS 1: -")
        self.lbl_dns2 = ttk.Label(status_frame, text="DNS 2: -")
        
        # Latency Label (NEW)
        self.lbl_latency = ttk.Label(status_frame, text="Latency: - ms", font=("Segoe UI", 9, "bold"), foreground="#4caf50")
        
        self.lbl_type.grid(row=0, column=0, sticky="w", padx=10, pady=2)
        self.lbl_ssid.grid(row=0, column=1, sticky="w", padx=10, pady=2)
        self.lbl_auth.grid(row=0, column=2, sticky="w", padx=10, pady=2)
        self.lbl_sig.grid(row=0, column=3, sticky="w", padx=10, pady=2)
        self.lbl_ip.grid(row=1, column=0, sticky="w", padx=10, pady=2)
        self.lbl_dns1.grid(row=1, column=1, sticky="w", padx=10, pady=2)
        self.lbl_dns2.grid(row=1, column=2, sticky="w", padx=10, pady=2)
        self.lbl_latency.grid(row=1, column=3, sticky="w", padx=10, pady=2)
        
        self.statusbar = ttk.Label(parent, text="Ready", anchor="w", padding=5, background="#333333")
        self.statusbar.pack(fill="x", side="bottom")
 
    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
 
    def _populate_cards(self, nets: List[Dict]):
        for widget in self.cards_frame.winfo_children(): widget.destroy()
        self.cards = {}
        current_wlan = current_status().get('SSID', '')
        saved_profiles = list_saved_profiles()
        row, col, MAX_COLS = 0, 0, 2
        for net in nets:
            ssid = net['ssid']
            auth = net.get('auth', 'Unknown')
            net_type = net.get('type', 'wifi')
            state = net.get('state', '')
            signal_val = net.get('signal', 0)
            is_connected = (ssid == current_wlan) if net_type == 'wifi' else (state == 'Connected')
            is_saved = (ssid in saved_profiles) if net_type == 'wifi' else True
            
            card_bg = '#2d2d2d'
            card = tk.Frame(self.cards_frame, bg=card_bg, padx=15, pady=15, highlightthickness=1, highlightbackground="#444444")
            card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
            
            icon_img = self.eth_icon if net_type == 'wired' else self.wifi_icon
            if icon_img:
                icon_lbl = tk.Label(card, image=icon_img, bg=card_bg)
                icon_lbl.grid(row=0, column=0, rowspan=5, padx=(0,15))
                icon_lbl.bind("<Button-1>", lambda e, n=net: self._on_card_click(n))
            else:
                txt = "[ETH]" if net_type == 'wired' else "[WIFI]"
                tk.Label(card, text=txt, bg=card_bg, fg="#666").grid(row=0, column=0, rowspan=5, padx=(0,15))
 
            title_fg = "#ffffff"
            if is_connected: status_text, status_color = "Connected", "#4caf50"
            elif is_saved: status_text, status_color = "Saved" if net_type == 'wifi' else "Disconnected", "#4caf50" if net_type == 'wifi' else "#aaaaaa"
            else: status_text, status_color = "Available", "#aaaaaa"
 
            name_lbl = tk.Label(card, text=ssid, font=("Segoe UI", 12, "bold"), bg=card_bg, fg=title_fg, anchor="w")
            name_lbl.grid(row=0, column=1, sticky="w")
            stat_lbl = tk.Label(card, text=status_text, font=("Segoe UI", 9, "bold"), bg=card_bg, fg=status_color, anchor="w")
            stat_lbl.grid(row=1, column=1, sticky="w")
            
            if net_type == 'wifi':
                sig_str = f"{signal_to_bars(signal_val)} {signal_val}%"
                sig_lbl = tk.Label(card, text=sig_str, font=("Segoe UI", 9), bg=card_bg, fg="#cccccc", anchor="w")
                sig_lbl.grid(row=2, column=1, sticky="w")
                next_row = 3
            else: next_row = 2
 
            sec_lbl = tk.Label(card, text=f"Security: {auth}" if net_type == 'wifi' else "Wired Interface", font=("Segoe UI", 9), bg=card_bg, fg="#aaaaaa", anchor="w")
            sec_lbl.grid(row=next_row, column=1, sticky="w")
            
            conn_txt = "Auto-Connect" if (net_type=='wifi' and is_saved) else "Manual Connection" if net_type=='wifi' else "Physical Adapter"
            conn_lbl = tk.Label(card, text=conn_txt, font=("Segoe UI", 9), bg=card_bg, fg="#aaaaaa", anchor="w")
            conn_lbl.grid(row=next_row+1, column=1, sticky="w")
 
            widgets_to_bind = [card, name_lbl, stat_lbl, sec_lbl, conn_lbl]
            if net_type == 'wifi': widgets_to_bind.append(sig_lbl)
            for w in widgets_to_bind: w.bind("<Button-1>", lambda e, n=net: self._on_card_click(n))
 
            self.cards[ssid] = card
            col += 1
            if col >= MAX_COLS: col = 0; row += 1
        for i in range(MAX_COLS): self.cards_frame.grid_columnconfigure(i, weight=1)
 
    def _on_card_click(self, net_data: Dict):
        ssid = net_data['ssid']
        if self.selected_net:
            old_ssid = self.selected_net['ssid']
            if old_ssid in self.cards:
                self.cards[old_ssid].configure(bg='#2d2d2d', highlightbackground="#444444")
                for child in self.cards[old_ssid].winfo_children(): child.configure(bg='#2d2d2d')
        
        self.selected_net = net_data
        if ssid in self.cards:
            sel_bg = '#404040'
            self.cards[ssid].configure(bg=sel_bg, highlightbackground="#4caf50")
            for child in self.cards[ssid].winfo_children(): child.configure(bg=sel_bg)
        
        type_lbl = "Wired" if net_data.get('type') == 'wired' else "WiFi"
        self._set_status(f"Selected: {ssid} ({type_lbl})")
 
    # ---------- vulnerability tab UI
    def _build_vuln_ui(self, parent):
        ctrl = ttk.Frame(parent, padding=8); ctrl.pack(fill="x")
        ttk.Label(ctrl, text="Target(s):").pack(side="left")
        self.v_target = ttk.Entry(ctrl, width=40); self.v_target.pack(side="left", padx=(6,10)); self.v_target.insert(0, "192.168.1.0/24")
        ttk.Label(ctrl, text="Scan Type:").pack(side="left")
        self.v_preset = tk.StringVar(value="Custom")
        preset_cb = ttk.Combobox(ctrl, textvariable=self.v_preset, values=list(NMAP_PRESETS.keys()), width=22, state="readonly")
        preset_cb.pack(side="left", padx=(6,6))
        preset_cb.bind("<<ComboboxSelected>>", lambda e: self._on_preset_change())
        help_btn = ttk.Button(ctrl, text="(?)", width=3, command=self._open_nmap_help)
        help_btn.pack(side="left", padx=(4,2))
        ttk.Label(ctrl, text="Extra Flags:").pack(side="left", padx=(8,0))
        self.v_extra = ttk.Entry(ctrl, width=28); self.v_extra.pack(side="left", padx=(6,6))
        self.v_verb_label = ttk.Label(ctrl, text=f"Verbosity: {self.v_verbosity_level}", width=14)
        self.v_verb_label.pack(side="left", padx=(10,2))
        self.v_verb_btn = ttk.Button(ctrl, text="V", width=3, command=self._cycle_verbosity)
        self.v_verb_btn.pack(side="left")
 
        # NEW: Comparison Mode UI
        comp_frame = ttk.LabelFrame(parent, text="Comparison Mode (Compare Scan Results)", padding=5)
        comp_frame.pack(fill="x", padx=8, pady=4)
        ttk.Checkbutton(comp_frame, text="SYN (-sS)", variable=self.comp_syn).pack(side="left", padx=10)
        ttk.Checkbutton(comp_frame, text="UDP (-sU)", variable=self.comp_udp).pack(side="left", padx=10)
        ttk.Checkbutton(comp_frame, text="ARP Ping (-sn -PR)", variable=self.comp_arp).pack(side="left", padx=10)
        ttk.Label(comp_frame, text="(Admin required for comparison)", font=("Segoe UI", 8)).pack(side="right", padx=5)
 
        btns = ttk.Frame(parent, padding=(8,0)); btns.pack(fill="x")
        self.v_start_btn = ttk.Button(btns, text="Start Scan", command=self._start_nmap_scan); self.v_start_btn.pack(side="left", padx=6)
        self.v_stop_btn = ttk.Button(btns, text="Stop Scan", command=self._stop_nmap_scan, state="disabled"); self.v_stop_btn.pack(side="left")
        self.v_save_btn = ttk.Button(btns, text="Save Output (TXT)", command=self._save_nmap_output, state="disabled"); self.v_save_btn.pack(side="left", padx=6)
        self.v_clear_btn = ttk.Button(btns, text="Clear Output", command=self._clear_vuln_output); self.v_clear_btn.pack(side="right", padx=6)
 
        txt_frame = ttk.LabelFrame(parent, text="Live Nmap Output / Comparison Report", padding=6); txt_frame.pack(fill="both", expand=True, padx=8, pady=8)
        self.v_output = scrolledtext.ScrolledText(txt_frame, wrap='word', height=20, bg="#2d2d2d", fg="#ffffff", insertbackground="white")
        self.v_output.pack(fill="both", expand=True)
        self.v_output.config(state='disabled')
 
        self._nmap_runner: Optional[NmapRunner] = None
        self._last_raw_output: str = ""
 
        if not nmap_installed():
            self._append_vout("[!] Nmap not found on this system. Please install from https://nmap.org/download.html\n")
            self._append_vout("Scans will not run until 'nmap' is available in your PATH.\n")
 
    def _open_nmap_help(self):
        try: HelpWindow(self, title="Nmap Flags Reference", text=NMAP_FLAGS_HELP)
        except Exception as e: messagebox.showerror("Help window error", str(e))
 
    def _on_preset_change(self):
        sel = self.v_preset.get()
        if sel == "Custom": self.v_extra.focus_set()
        else:
            flags = NMAP_PRESETS.get(sel, "")
            self.v_extra.delete(0, tk.END)
            self.v_extra.insert(0, flags)
 
    def _append_vout(self, text: str):
        def _update_ui():
            try:
                self.v_output.config(state='normal')
                self.v_output.insert(tk.END, text)
                if not text.endswith("\n"): self.v_output.insert(tk.END, "\n")
                self.v_output.see(tk.END)
                self.v_output.config(state='disabled')
                self._last_raw_output += text + ("\n" if not text.endswith("\n") else "")
            except Exception: pass
        
        # Safely push the update to the main Tkinter thread
        self.after(0, _update_ui)
 
    def _clear_vuln_output(self):
        try:
            self.v_output.config(state='normal')
            self.v_output.delete('1.0', tk.END)
            self.v_output.config(state='disabled')
            self._last_raw_output = ""
            self.v_save_btn.config(state='disabled')
        except Exception: pass
 
    def _cycle_verbosity(self):
        old = self.v_verbosity_level
        new = old + 1
        if new > 3: new = 1
        self.v_verbosity_level = new
        self.v_verb_label.config(text=f"Verbosity: {self.v_verbosity_level}")
        verbosity_flag = "-" + "v" * self.v_verbosity_level
        cur_extra = self.v_extra.get().strip()
        cur_extra_clean = re.sub(r'\s*-v{1,3}\b', '', cur_extra)
        self.v_extra.delete(0, tk.END)
        if cur_extra_clean: self.v_extra.insert(0, f"{verbosity_flag} {cur_extra_clean}".strip())
        else: self.v_extra.insert(0, verbosity_flag)
        self._append_vout(f"[Verbosity set to {self.v_verbosity_level}]\n")
 
    def _start_nmap_scan(self):
        nmap_exe = find_nmap_binary()
        if not nmap_exe:
            messagebox.showerror("Nmap not found", "Nmap is not installed.")
            return
        
        target = self.v_target.get().strip()
        if not target: messagebox.showerror("Invalid target", "Please enter a target."); return
 
        # CHECK COMPARISON MODE
        do_syn = self.comp_syn.get()
        do_udp = self.comp_udp.get()
        do_arp = self.comp_arp.get()
        
        if do_syn or do_udp or do_arp:
            if not is_admin():
                messagebox.showerror("Permission Error", "Comparison Mode (SYN/UDP/ARP) requires Administrator privileges.\nPlease restart the app as Admin.")
                return
            
            self._clear_vuln_output()
            self.v_start_btn.config(state="disabled")
            self.v_stop_btn.config(state="normal")
            self._comp_stop_evt.clear()
            self._comp_thread = threading.Thread(target=self._run_comparison_scan, args=(target, do_syn, do_udp, do_arp, nmap_exe), daemon=True)
            self._comp_thread.start()
            return
        
        # STANDARD SCAN LOGIC
        preset = self.v_preset.get()
        extra = self.v_extra.get().strip()
        flags = ""
        if preset and preset in NMAP_PRESETS and preset != "Custom": flags = NMAP_PRESETS[preset]
        verbosity_flag = "-" + "v" * self.v_verbosity_level
        extra_clean = re.sub(r'\s*-v{1,3}\b', '', extra)
        if extra_clean: flags = (flags + " " + verbosity_flag + " " + extra_clean).strip()
        else: flags = (flags + " " + verbosity_flag).strip()
 
        if "-sS" in flags or "-O" in flags or "-A" in flags:
            if not is_admin():
                if not messagebox.askyesno("Privileged flags", "Privileged flags detected. Continue?"): return
 
        self._clear_vuln_output()
        self.v_output.config(state='normal'); self.v_output.insert(tk.END, f"Command: {nmap_exe} {flags} {target}\n"); self.v_output.config(state='disabled')
        self._last_raw_output += f"Command: {nmap_exe} {flags} {target}\n"
 
        self.v_start_btn.config(state="disabled")
        self.v_stop_btn.config(state="normal")
        self.v_save_btn.config(state="disabled")
 
        def update_cb(line): self._append_vout(line)
        def finished_cb(success, _):
            # finished_cb runs on NmapRunner's background thread — widget
            # updates must be deferred to the main thread via .after().
            self.after(0, lambda: self.v_start_btn.config(state="normal"))
            self.after(0, lambda: self.v_stop_btn.config(state="disabled"))
            if self._last_raw_output.strip():
                self.after(0, lambda: self.v_save_btn.config(state="normal"))
            if success:
                self._append_vout("[Scan completed]")
                self._append_vout(build_security_verdict_report(self._last_raw_output))
            else:
                self._append_vout("[Scan ended with errors or was stopped]")
        self._nmap_runner = NmapRunner(target, flags, update_cb, finished_cb)
        self._nmap_runner.start()
 
    def _run_comparison_scan(self, target, do_syn, do_udp, do_arp, nmap_exe):
        self._append_vout("=== STARTING COMPARISON ENGINE ===\n")
        results = {}
        
        # Helper to run sequential scans without blocking the thread's ability to stop
        def run_one(name, flags):
            if self._comp_stop_evt.is_set(): return None
            self._append_vout(f"\n[+] Running {name} Scan on {target}...\nFlags: {flags}\n")
            cmd = f'"{nmap_exe}" {flags} {target}'
            try:
                # Use Popen instead of run() so we can read output line-by-line and allow cancellation
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                         creationflags=_NO_WINDOW_FLAGS)
                
                output_lines = []
                # Read line by line to check for the stop event continuously
                for line in iter(proc.stdout.readline, ''):
                    if self._comp_stop_evt.is_set():
                        proc.terminate()
                        # See note in NmapRunner.stop(): /T is required to kill
                        # nmap.exe itself, since shell=True makes proc.pid the
                        # cmd.exe wrapper's PID, not nmap's.
                        subprocess.run(f'taskkill /F /T /PID {proc.pid}', shell=True, stdout=subprocess.DEVNULL,
                                        creationflags=_NO_WINDOW_FLAGS)
                        return None
                    output_lines.append(line)
                    
                proc.wait()
                return "".join(output_lines)
            except Exception as e:
                self._append_vout(f"[!] Error: {e}\n")
                return None
 
        # 1. SYN Scan
        if do_syn:
            out = run_one("SYN (TCP)", "-sS -T4") 
            if out: results['SYN'] = out
        
        # 2. UDP Scan
        if do_udp:
            out = run_one("UDP", "-sU -T4") 
            if out: results['UDP'] = out
            
        # 3. ARP Scan
        if do_arp:
            out = run_one("ARP (Host Discovery)", "-sn -PR")
            if out: results['ARP'] = out
 
        if self._comp_stop_evt.is_set():
            self._append_vout("\n[Comparison Aborted by User]\n")
        else:
            self._append_vout("\n=== GENERATING COMPARISON REPORT ===\n")
            self._generate_comparison_report(results)
 
        self.after(0, lambda: self.v_start_btn.config(state="normal"))
        self.after(0, lambda: self.v_stop_btn.config(state="disabled"))
        if self._last_raw_output.strip(): 
            self.after(0, lambda: self.v_save_btn.config(state="normal"))
 
    def _generate_comparison_report(self, results):
        report = []
        
        # Simple Parsers
        def extract_hosts(text):
            return set(re.findall(r"Nmap scan report for .*?([\d\.]+)", text))
        
        def extract_ports(text):
            # Returns dict {ip: [port/proto]}
            mapping = {}
            curr_ip = None
            for line in text.splitlines():
                m_ip = re.search(r"Nmap scan report for .*?([\d\.]+)", line)
                if m_ip: 
                    curr_ip = m_ip.group(1)
                    mapping[curr_ip] = []
                m_port = re.search(r"(\d+)/(tcp|udp)\s+open", line)
                if m_port and curr_ip:
                    mapping[curr_ip].append(f"{m_port.group(1)}/{m_port.group(2)}")
            return mapping
 
        # Compare Hosts (ARP vs others)
        arp_hosts = extract_hosts(results.get('ARP', ''))
        syn_hosts = extract_hosts(results.get('SYN', ''))
        udp_hosts = extract_hosts(results.get('UDP', ''))
        
        all_hosts = arp_hosts | syn_hosts | udp_hosts
        report.append(f"Total Unique Hosts Discovered: {len(all_hosts)}")
        
        if 'ARP' in results:
            report.append(f"ARP Scan found: {len(arp_hosts)} hosts.")
            missed = all_hosts - arp_hosts
            if missed: report.append(f"  - Missed by ARP (blocked?): {', '.join(missed)}")
        
        # Compare Ports (SYN vs UDP)
        syn_ports = extract_ports(results.get('SYN', ''))
        udp_ports = extract_ports(results.get('UDP', ''))
        
        for ip in sorted(all_hosts):
            report.append(f"\nTarget: {ip}")
            s_p = syn_ports.get(ip, [])
            u_p = udp_ports.get(ip, [])
            
            if 'SYN' in results: report.append(f"  - TCP Open Ports (SYN): {len(s_p)} -> {', '.join(s_p) if s_p else 'None'}")
            if 'UDP' in results: report.append(f"  - UDP Open Ports:       {len(u_p)} -> {', '.join(u_p) if u_p else 'None'}")
            
            if s_p and u_p:
                report.append("  - Services found on both TCP and UDP (Rare):")
                # Check for matching port numbers
                s_nums = {p.split('/')[0] for p in s_p}
                u_nums = {p.split('/')[0] for p in u_p}
                common = s_nums & u_nums
                if common: report.append(f"    Ports: {', '.join(common)}")
                else: report.append("    None")

        # --- Security Risk Assessment: reuse the same risk engine the
        # standard scan uses, merging whatever SYN/UDP results we have ---
        merged_hosts: Dict[str, List[Tuple[int, str, str]]] = {}
        for key in ('SYN', 'UDP'):
            if key in results:
                for ip, ports in extract_hosts_and_ports(results[key]).items():
                    merged_hosts.setdefault(ip, []).extend(ports)
        if merged_hosts:
            report.append(format_security_verdict(merged_hosts))

        self._append_vout("\n".join(report))
        self._append_vout("\n[End of Report]")
 
    def _stop_nmap_scan(self):
        # Handle stopping comparison thread
        if self._comp_thread and self._comp_thread.is_alive():
            self._comp_stop_evt.set()
            self._append_vout("\n[Stopping Comparison...]\n")
            return
 
        if self._nmap_runner:
            self._append_vout("[Stopping scan...]\n")
            try: self._nmap_runner.stop()
            except Exception: pass
            self._nmap_runner = None
            self.v_start_btn.config(state="normal")
            self.v_stop_btn.config(state="disabled")
            self._append_vout("[Scan stopped by user]")
 
    def _save_nmap_output(self):
        if not self._last_raw_output.strip(): return
        timestr = time.strftime("%Y-%m-%d_%H-%M-%S")
        default = f"nmap_scan_{timestr}.txt"
        fld = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=default, filetypes=[("Text Files","*.txt"),("All files","*.*")])
        if not fld: return
        try:
            with open(fld, "w", encoding="utf-8") as f: f.write(self._last_raw_output)
            messagebox.showinfo("Saved", f"Scan output saved to:\n{fld}")
        except Exception as e: messagebox.showerror("Save error", str(e))
 
    # ---------- topology tab
    def _build_topology_ui(self, parent):
        lbl = ttk.Label(parent, text="Network Discovery Map", font=("Segoe UI", 12, "bold")); lbl.pack(anchor="w", padx=10, pady=(10, 4))
        ttk.Label(parent, text="Open the dynamic network discovery visualizer (separate window).").pack(anchor="w", padx=10)
        ttk.Button(parent, text="Open Discovery Map", command=self._open_topology_window).pack(anchor="w", padx=10, pady=10)
        if nx is None or plt is None:
            ttk.Label(parent, text="Visualizer requires 'networkx' and 'matplotlib'.", foreground="red").pack(anchor="w", padx=10, pady=(6,0))
 
    def _open_topology_window(self):
        try: TopoWindow(self, scan_interval=30)
        except NameError: messagebox.showerror("Error", "Topology modules missing.")
 
    # ================================================================
    # Network Monitor Tab
    # ================================================================
 
    def _build_monitor_ui(self, parent):
        """
        Minimalist two-column layout:
          Left  column : metric tiles (stacked vertically, compact)
          Right column : graph panel (two stacked sub-plots, narrower)
 
        Crash fix: Figure is created with mpl_figure.Figure() — never
        touches the shared plt state machine, so it cannot race with
        TopoWindow's draw calls.
        """
        # ── Top control bar ──────────────────────────────────────────────
        ctrl = ttk.Frame(parent, padding=(10, 6))
        ctrl.pack(fill="x")
 
        self.btn_mon_start = ttk.Button(ctrl, text="▶  Start",
                                        command=self._start_monitor)
        self.btn_mon_start.pack(side="left", padx=(0, 4))
 
        self.btn_mon_stop = ttk.Button(ctrl, text="■  Stop",
                                       command=self._stop_monitor,
                                       state="disabled")
        self.btn_mon_stop.pack(side="left", padx=(0, 16))
 
        ttk.Label(ctrl, text="Interval (s):").pack(side="left")
        self.mon_interval_var = tk.StringVar(value="1")
        ttk.Entry(ctrl, textvariable=self.mon_interval_var,
                  width=4).pack(side="left", padx=(4, 16))
 
        self.mon_status_lbl = ttk.Label(ctrl, text="● Idle",
                                        font=("Segoe UI", 9),
                                        foreground="#888888")
        self.mon_status_lbl.pack(side="left")
 
        # ── Body: left tiles + right graph ───────────────────────────────
        body = tk.Frame(parent, bg="#1e1e1e")
        body.pack(fill="both", expand=True, padx=10, pady=(4, 8))
 
        # ── LEFT: metric tiles (fixed width, full height) ─────────────────
        left = tk.Frame(body, bg="#1e1e1e", width=220)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)
 
        tile_defs = [
            ("LATENCY",      "—  ms",    "#4caf50", "_mon_lbl_lat"),
            ("JITTER",       "—  ms",    "#2196F3", "_mon_lbl_jit"),
            ("PACKET LOSS",  "—  %",     "#FF5722", "_mon_lbl_loss"),
            ("DOWNLOAD ↓",   "—  Mbps",  "#00BCD4", "_mon_lbl_dl"),
            ("UPLOAD ↑",     "—  Mbps",  "#FF9800", "_mon_lbl_ul"),
            ("GATEWAY",      "—",        "#aaaaaa", "_mon_lbl_gw"),
            ("INTERFACE",    "—",        "#aaaaaa", "_mon_lbl_iface"),
        ]
 
        for title, init_val, color, attr in tile_defs:
            tile = tk.Frame(left, bg="#252525",
                            highlightthickness=1,
                            highlightbackground="#383838")
            tile.pack(fill="x", pady=3)
 
            tk.Label(tile, text=title,
                     font=("Segoe UI", 7, "bold"),
                     bg="#252525", fg="#555555",
                     anchor="w", padx=10, pady=4).pack(fill="x")
 
            val_lbl = tk.Label(tile, text=init_val,
                               font=("Consolas", 13, "bold"),
                               bg="#252525", fg=color,
                               anchor="w", padx=10, pady=4)
            val_lbl.pack(fill="x")
            setattr(self, attr, val_lbl)
 
        # ── RIGHT: graph panel — expands to fill remaining window space ──
        right = tk.Frame(body, bg="#1e1e1e")
        right.pack(side="left", fill="both", expand=True, padx=(0, 0))
 
        graph_lbl = tk.Label(right, text="LIVE ACTIVITY",
                             font=("Segoe UI", 7, "bold"),
                             bg="#1e1e1e", fg="#555555", anchor="w")
        graph_lbl.pack(anchor="w", pady=(2, 4))
 
        graph_container = tk.Frame(right, bg="#1e1e1e")
        graph_container.pack(fill="both", expand=True)
 
        if mpl_figure is not None and FigureCanvasTkAgg is not None:
            # ISOLATED Figure — no plt.subplots(), never touches shared state
            self._mon_fig = mpl_figure.Figure(facecolor="#1a1a1a")
            self._mon_fig.subplots_adjust(
                hspace=0.60, left=0.14, right=0.96, top=0.92, bottom=0.09)
 
            # ── Throughput subplot (fixed 0–100 Mbps, 20 Mbps steps) ──────
            ax_tp = self._mon_fig.add_subplot(2, 1, 1)
            ax_tp.set_facecolor("#222222")
            ax_tp.set_title("Throughput (Mbps)", color="#888888",
                            fontsize=8, pad=3, loc="left")
            ax_tp.tick_params(colors="#555555", labelsize=7)
            for sp in ax_tp.spines.values(): sp.set_edgecolor("#333333")
 
            # Fixed Y axis: 0 to 100 Mbps, gridlines every 20 Mbps
            ax_tp.set_ylim(0, 100)
            ax_tp.set_yticks([0, 20, 40, 60, 80, 100])
            ax_tp.yaxis.set_tick_params(labelsize=7, colors="#555555")
            ax_tp.set_autoscaley_on(False)
            ax_tp.grid(axis="y", color="#2e2e2e", linewidth=0.6, linestyle="--")
 
            self._mon_line_dl, = ax_tp.plot(
                [], [], color="#00BCD4", linewidth=1.2, label="DL ↓")
            self._mon_line_ul, = ax_tp.plot(
                [], [], color="#FF9800", linewidth=1.2, label="UL ↑")
            ax_tp.legend(loc="upper right", fontsize=7,
                         facecolor="#222222", labelcolor="#aaaaaa",
                         edgecolor="#333333", framealpha=0.7)
            ax_tp.set_ylabel("Mbps", color="#555555", fontsize=7)
            ax_tp.yaxis.set_label_coords(-0.10, 0.5)
 
            # ── Latency subplot (autoscaling, min 5 ms ceiling) ───────────
            ax_lat = self._mon_fig.add_subplot(2, 1, 2)
            ax_lat.set_facecolor("#222222")
            ax_lat.set_title("Latency (ms)", color="#888888",
                             fontsize=8, pad=3, loc="left")
            ax_lat.tick_params(colors="#555555", labelsize=7)
            for sp in ax_lat.spines.values(): sp.set_edgecolor("#333333")
            ax_lat.grid(axis="y", color="#2e2e2e", linewidth=0.6, linestyle="--")
            self._mon_line_lat, = ax_lat.plot(
                [], [], color="#4caf50", linewidth=1.2, label="RTT")
            ax_lat.legend(loc="upper right", fontsize=7,
                          facecolor="#222222", labelcolor="#aaaaaa",
                          edgecolor="#333333", framealpha=0.7)
            ax_lat.set_ylabel("ms", color="#555555", fontsize=7)
            ax_lat.yaxis.set_label_coords(-0.10, 0.5)
 
            # Store axes refs for _apply_monitor_payload
            self._mon_axes = [ax_tp, ax_lat]
 
            self._mon_canvas = FigureCanvasTkAgg(
                self._mon_fig, master=graph_container)
            self._mon_canvas.get_tk_widget().pack(fill="both", expand=True)
        else:
            ttk.Label(graph_container,
                      text="Graph requires matplotlib.\npip install matplotlib",
                      foreground="#FF5722").pack(padx=10, pady=20)
            self._mon_fig    = None
            self._mon_canvas = None
            self._mon_axes   = None
 
    # ---- Monitor engine start / stop ----
 
    def _start_monitor(self):
        if self._monitor_engine and self._monitor_engine.is_alive():
            return
        try:
            interval = max(1, int(self.mon_interval_var.get()))
        except ValueError:
            interval = 1
            self.mon_interval_var.set("1")
 
        self._graph_times.clear()
        self._graph_dl.clear()
        self._graph_ul.clear()
        self._graph_lat.clear()
 
        while not self.monitor_queue.empty():
            try: self.monitor_queue.get_nowait()
            except queue.Empty: break
 
        self._monitor_engine = MonitorEngine(interval=interval,
                                             out_q=self.monitor_queue)
        self._monitor_engine.start()
 
        self.btn_mon_start.config(state="disabled")
        self.btn_mon_stop.config(state="normal")
        self.mon_status_lbl.config(text="● Running", foreground="#4caf50")
 
    def _stop_monitor(self):
        if self._monitor_engine:
            self._monitor_engine.stop()
            self._monitor_engine = None
        self.btn_mon_start.config(state="normal")
        self.btn_mon_stop.config(state="disabled")
        self.mon_status_lbl.config(text="● Stopped", foreground="#FF5722")
 
    # ---- Payload application (main thread only) ----
 
    def _apply_monitor_payload(self, payload):
        """
        Update tiles and graph. Called exclusively on the Tkinter main
        thread via _monitor_queues → self.after(). Never called from a
        background thread, so no matplotlib thread-safety issues.
        """
        # ── Tiles ──────────────────────────────────────────────────────
        lat = payload.get('latency')
        lat_str   = f"{lat} ms" if lat is not None else "Timeout"
        lat_color = ("#4caf50" if lat is not None and lat < 80
                     else "#FF9800" if lat is not None and lat < 200
                     else "#FF5722")
        self._mon_lbl_lat.config(text=lat_str, fg=lat_color)
 
        jitter    = payload.get('jitter', 0.0)
        jit_color = ("#4caf50" if jitter < 10
                     else "#FF9800" if jitter < 30 else "#FF5722")
        self._mon_lbl_jit.config(text=f"{jitter:.1f} ms", fg=jit_color)
 
        loss      = payload.get('loss_pct', 0.0)
        loss_color = ("#4caf50" if loss == 0
                      else "#FF9800" if loss < 10 else "#FF5722")
        self._mon_lbl_loss.config(text=f"{loss:.1f} %", fg=loss_color)
 
        dl = payload.get('dl_mbps', 0.0)
        ul = payload.get('ul_mbps', 0.0)
        self._mon_lbl_dl.config(text=f"{dl:.3f} Mbps")
        self._mon_lbl_ul.config(text=f"{ul:.3f} Mbps")
        self._mon_lbl_gw.config(text=payload.get('gateway', '—'))
        self._mon_lbl_iface.config(text=payload.get('alias', '—'))
 
        # ── Graph ──────────────────────────────────────────────────────
        if self._mon_fig is None or self._mon_canvas is None:
            return
 
        now = payload.get('timestamp', time.time())
        self._graph_times.append(now)
        self._graph_dl.append(dl)
        self._graph_ul.append(ul)
        # keep latency series aligned (carry last known value on timeout)
        self._graph_lat.append(
            lat if lat is not None
            else (self._graph_lat[-1] if self._graph_lat else 0)
        )
 
        # trim to window
        if len(self._graph_times) > MONITOR_HISTORY_LEN:
            self._graph_times = self._graph_times[-MONITOR_HISTORY_LEN:]
            self._graph_dl    = self._graph_dl[-MONITOR_HISTORY_LEN:]
            self._graph_ul    = self._graph_ul[-MONITOR_HISTORY_LEN:]
            self._graph_lat   = self._graph_lat[-MONITOR_HISTORY_LEN:]
 
        if not self._graph_times:
            return
 
        t0 = self._graph_times[0]
        xs = [t - t0 for t in self._graph_times]
 
        ax_tp, ax_lat = self._mon_axes[0], self._mon_axes[1]
 
        # Throughput — Y axis is fixed 0–100 Mbps, never autoscaled
        self._mon_line_dl.set_data(xs, self._graph_dl)
        self._mon_line_ul.set_data(xs, self._graph_ul)
        ax_tp.set_xlim(0, max(xs[-1], 10))
 
        # Latency — autoscales, minimum 5 ms ceiling
        self._mon_line_lat.set_data(xs, self._graph_lat)
        ax_lat.relim(); ax_lat.autoscale_view()
        if ax_lat.get_ylim()[1] < 5: ax_lat.set_ylim(0, 5)
        ax_lat.set_xlim(0, max(xs[-1], 10))
 
        try:
            self._mon_canvas.draw_idle()
        except Exception:
            pass
 
    # ---- Network tab helpers (unchanged boundary) ----
 
    def _set_busy(self, busy: bool):
        for b in (getattr(self, 'btn_scan', None), getattr(self, 'btn_connect', None), getattr(self, 'btn_disconnect', None), getattr(self, 'btn_auto', None)):
            if b: b.configure(state=("disabled" if busy else "normal"))
        self.config(cursor="watch" if busy else "")
        self.update_idletasks()
 
    def _set_status(self, text: str):
        self.statusbar.config(text=text)
 
    def _refresh_status_panel(self):
        # NOTE: This method is now effectively replaced by _monitor_queues, 
        # but kept empty or minimal if called elsewhere.
        pass
 
    def _scan_async(self):
        def worker():
            try:
                wired_nets = get_wired_interfaces()
                try: wifi_nets = aggressive_scan_native(timeout_sec=5.0)
                except Exception: wifi_nets = scan_burst(max_tries=4, pause_sec=2.0)
                all_nets = wired_nets + wifi_nets
                self.after(0, lambda: self._populate_cards(all_nets))
                self.after(0, lambda: self._set_status(f"Scan complete. {len(all_nets)} network(s) found."))
            except Exception as e:
                # Capture the message now: 'e' is unbound the instant this except
                # block ends, but the lambda below only runs later via .after().
                err_msg = str(e)
                self.after(0, lambda msg=err_msg: messagebox.showerror("Scan Error", msg))
                self.after(0, lambda: self._set_status("Scan failed."))
            finally:
                self.after(0, lambda: self._set_busy(False))
                # Status panel update is now handled by background thread automatically
        self._set_busy(True); self._set_status("Scanning…")
        threading.Thread(target=worker, daemon=True).start()
 
    def _connect_async(self):
        if not self.selected_net: messagebox.showinfo("Select", "Please select a network."); return
        ssid = self.selected_net['ssid']
        net_type = self.selected_net.get('type', 'wifi')
        
        if net_type == 'wired':
            if not is_admin(): messagebox.showerror("Admin Required", "Admin privileges required."); return
            def wired_worker():
                ok = set_interface_state(ssid, enable=True)
                self.after(0, lambda: self._set_status(f"Enabled '{ssid}'." if ok else "Failed."))
                self.after(1000, self._scan_async)
            self._set_busy(True); self._set_status(f"Enabling {ssid}...")
            threading.Thread(target=wired_worker, daemon=True).start()
            return
            
        auth = self.selected_net.get('auth', '')
        if is_open_auth(str(auth)):
            if not messagebox.askyesno("Insecure", "Connect to OPEN network?"): return
            pw = None
        else:
            pw = simpledialog.askstring("Connect", f"Password for '{ssid}':", show="*")
            if pw is None: return 
            if pw == "": pw = None
 
        def worker():
            ok = False
            try:
                ok = connect(ssid, pw)
            except Exception as e:
                err_msg = str(e)
                self.after(0, lambda msg=err_msg: messagebox.showerror("Error", msg))
            finally:
                self.after(0, lambda: self._set_status("Connected." if ok else "Failed."))
                self.after(0, lambda: self._set_busy(False))
                self.after(1000, self._scan_async)
        self._set_busy(True); self._set_status(f"Connecting to '{ssid}'…")
        threading.Thread(target=worker, daemon=True).start()
 
    def _disconnect_async(self):
        if self.selected_net and self.selected_net.get('type') == 'wired':
            if not is_admin(): messagebox.showerror("Admin Required", "Admin privileges required."); return
            ssid = self.selected_net['ssid']
            def wired_worker():
                ok = set_interface_state(ssid, enable=False)
                self.after(0, lambda: self._set_status(f"Disabled '{ssid}'." if ok else "Failed."))
                self.after(1000, self._scan_async)
            self._set_busy(True); self._set_status(f"Disabling {ssid}...")
            threading.Thread(target=wired_worker, daemon=True).start()
        else:
            def worker():
                ok = disconnect()
                self.after(0, lambda: self._set_status("Disconnected." if ok else "Failed."))
                self.after(0, lambda: self._set_busy(False))
                self.after(1000, self._scan_async)
            self._set_busy(True); self._set_status("Disconnecting…")
            threading.Thread(target=worker, daemon=True).start()
 
    def _auto_reconnect_async(self):
        def worker():
            ssid = auto_reconnect_strongest_known()
            if ssid: self.after(0, lambda: self._set_status(f"Connected to: {ssid}"))
            else: self.after(0, lambda: self._set_status("No known networks found."))
            self.after(0, lambda: self._set_busy(False))
            self.after(1200, self._scan_async)
        self._set_busy(True); self._set_status("Auto-reconnecting…")
        threading.Thread(target=worker, daemon=True).start()
 
    def _open_adapter_settings(self):
        # Determine the correct physical interface name (Alias)
        target_adapter = "Wi-Fi" # Default fallback
        
        if self.selected_net:
            net_type = self.selected_net.get('type', 'wifi')
            if net_type == 'wired':
                # For wired, the 'ssid' field holds the interface name (e.g., "Ethernet")
                target_adapter = self.selected_net.get('ssid')
            else:
                # For WiFi, we need the interface name (e.g., "Wi-Fi"), NOT the SSID
                # We use the helper function wifi_interface_alias() defined earlier
                wa = wifi_interface_alias()
                if wa:
                    target_adapter = wa
        
        # If no network selected, try to detect the active one
        elif get_active_interface_alias():
            target_adapter = get_active_interface_alias()
 
        AdapterSettingsDialog(self, target_adapter=target_adapter)
 
    def _open_ping_window(self):
        PingWindow(self)
 
    def _toggle_auto_scan(self):
        if self.auto_scan.get():
            self._set_status("Auto-Scan enabled.")
            self.after(self.scan_interval_ms, self._auto_scan_tick)
        else: self._set_status("Auto-Scan disabled.")
 
    def _auto_scan_tick(self):
        if not self.auto_scan.get(): return
        self._scan_async()
        self.after(self.scan_interval_ms, self._auto_scan_tick)

    def _on_app_close(self):
        """
        Runs when the user clicks the window's X button (WM_DELETE_WINDOW).

        Without this handler, Tkinter's default close behavior just
        destroys the window and lets mainloop() return — it never touches
        any background thread or subprocess. Several of those loops
        (_background_status_updater, the logging loop, the monitor engine)
        had NO exit condition at all (`while True:`), or an exit condition
        but a flat, non-interruptible time.sleep() — so even after
        destroy() they kept issuing fresh subprocess.run() calls
        (netsh/PowerShell/nmap) in the background. Being daemon threads
        means Python *can* exit without waiting for them, but a call that's
        already mid-flight when destroy() happens can still delay real
        process exit, and any spawned subprocess (nmap.exe, taskkill,
        powershell.exe) is a fully independent OS process that keeps
        running regardless of what Python's threads do.

        Sequence: signal every loop to stop -> explicitly stop each
        engine/subprocess -> give threads a brief moment to notice ->
        destroy the window -> hard-exit the interpreter so nothing lingers
        even if a stray thread is still unwinding.
        """
        # Signal every while-loop keyed off this flag to stop on its next
        # check, and make their sleeps return immediately instead of
        # waiting out a flat 2s each.
        self._shutting_down.set()
        self.auto_scan.set(False)
        self.logging_active = False

        # Nmap: single scan or comparison-mode scan, whichever is active.
        if self._comp_thread and self._comp_thread.is_alive():
            self._comp_stop_evt.set()
        if self._nmap_runner:
            try: self._nmap_runner.stop()
            except Exception: pass
            self._nmap_runner = None

        # Network Monitor (ping + throughput polling loop).
        if self._monitor_engine:
            try: self._monitor_engine.stop()
            except Exception: pass
            self._monitor_engine = None

        # HTTP file server — shutdown() can block briefly, so run it on a
        # disposable thread rather than stalling window teardown.
        if self.http_thread:
            t = self.http_thread
            self.http_thread = None
            threading.Thread(target=t.stop, daemon=True).start()

        # Give background threads a brief window to notice the stop
        # signals above and exit their loops cleanly before we tear down
        # the Tk root they may still be about to touch via .after()/queues.
        self.after(150, self._finish_app_close)

    def _finish_app_close(self):
        try:
            self.destroy()
        except Exception:
            pass
        # Belt-and-suspenders: force the interpreter to exit immediately
        # rather than trusting that every daemon thread and self.after()
        # chain has actually unwound by now. This is what guarantees
        # Netversity.exe itself disappears from Task Manager the moment
        # the window closes, instead of possibly lingering while a
        # background thread finishes an in-flight subprocess call.
        os._exit(0)

if __name__ == "__main__":
    app = WiFiGUI()
    app.mainloop()