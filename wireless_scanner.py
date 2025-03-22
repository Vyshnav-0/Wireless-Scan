import os
import sys
import subprocess
import venv
from pathlib import Path
from datetime import datetime
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn
import urllib.request
import json
from typing import Dict, Optional
import signal
import atexit
import time
import threading

# Initialize console for rich output
console = Console()
discovered_devices = {}

# Add to global variables section
OUI_DATABASE_URL = "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf"
MAC_TO_COMPANY: Dict[str, str] = {}

# Enhanced projector detection keywords
PROJECTOR_IDENTIFIERS = {
    'brands': [
        'epson', 'benq', 'viewsonic', 'optoma', 'sony', 'panasonic', 'nec', 
        'hitachi', 'acer', 'dell', 'infocus', 'casio', 'vivitek', 'christie'
    ],
    'keywords': [
        'projector', 'proj-', 'beamer', 'pj-', 'vga', 'hdmi', 'display',
        'screen', 'presentation'
    ],
    'models': [
        'eb-', 'emp-', 'powerlite', 'brightlink', 'w1', 'h1', 'x1', 'p1',
        'mw-', 'mx-', 'mp-', 'ls-'
    ]
}

# Add more detailed device signatures
DEVICE_SIGNATURES = {
    'mobile': {
        'brands': ['iphone', 'samsung', 'xiaomi', 'huawei', 'oneplus', 'pixel', 'redmi', 'oppo', 'vivo', 'realme'],
        'keywords': ['phone', 'mobile', 'smartphone', 'android', 'iphone'],
        'oui': {
            'apple': ['00:23:32', '00:0A:95', 'A8:5C:2C'],
            'samsung': ['00:07:AB', '00:21:19', '94:35:0A'],
            'xiaomi': ['00:9E:C8', '58:44:98'],
            'huawei': ['00:E0:FC', '00:18:82']
        }
    },
    'laptop': {
        'brands': ['macbook', 'thinkpad', 'dell', 'hp', 'asus', 'acer', 'lenovo', 'msi'],
        'keywords': ['laptop', 'notebook', 'computer', 'pc', 'macbook'],
        'oui': {
            'apple': ['00:03:93', '00:0A:27'],
            'dell': ['00:06:5B', '00:14:22'],
            'lenovo': ['00:09:2D', '00:24:7E']
        }
    },
    'tablet': {
        'brands': ['ipad', 'galaxy tab', 'surface', 'kindle'],
        'keywords': ['tablet', 'pad', 'reader'],
        'oui': {
            'apple': ['00:1C:B3', '00:26:08'],
            'samsung': ['00:15:99', '00:13:77']
        }
    },
    'smartwatch': {
        'brands': ['apple watch', 'galaxy watch', 'fitbit', 'garmin'],
        'keywords': ['watch', 'band', 'fitness'],
        'oui': {
            'apple': ['00:22:41', '00:25:00'],
            'fitbit': ['00:1C:B1']
        }
    }
}

# Add this to the global variables section
MAC_PREFIXES = {
    # Apple Devices
    'apple_mobile': ['04:15:52', '04:1E:64', '04:26:65', '04:4B:ED', '04:52:F3', '04:54:53', '04:DB:56', '08:66:98', '08:70:45', '08:74:02', 'A8:5C:2C', 'A8:88:B2', 'AC:29:3A', 'B4:F7:A1', 'B8:09:8A', 'B8:17:C2', 'B8:41:A4', 'B8:53:AC', 'B8:8D:12', 'B8:C7:5D', 'B8:E8:56', 'B8:F6:B1', 'B8:FF:61', 'BC:3B:AF', 'BC:4C:C4', 'BC:52:B7', 'BC:67:78', 'BC:6C:21', 'BC:92:6B', 'BC:A9:20', 'BC:E1:43', 'C0:63:94', 'C0:84:7A', 'C0:A5:3E', 'C0:CC:F8', 'C0:CE:CD', 'C4:2C:03', 'C4:B3:01', 'C8:1E:E7', 'C8:2A:14', 'C8:33:4B', 'C8:3C:85', 'C8:69:CD', 'C8:85:50', 'C8:B5:B7', 'C8:E0:EB', 'C8:F6:50', 'CC:08:E0', 'CC:20:E8', 'CC:25:EF', 'CC:29:F5', 'CC:44:63', 'CC:78:5F', 'CC:7E:E7', 'CC:C7:60', 'D0:03:4B', 'D0:23:DB', 'D0:25:98', 'D0:33:11', 'D0:4F:7E', 'D0:A6:37', 'D0:C5:F3', 'D0:D2:B0', 'D0:E1:40', 'D4:61:9D', 'D4:90:9C', 'D4:A3:3D', 'D4:DC:CD', 'D8:00:4D', 'D8:1D:72', 'D8:30:62', 'D8:96:95', 'D8:9E:3F', 'D8:A2:5E', 'D8:BB:2C', 'D8:CF:9C', 'DC:0C:5C', 'DC:2B:2A', 'DC:2B:61', 'DC:37:14', 'DC:41:5F', 'DC:86:D8', 'DC:9B:9C', 'DC:A4:CA', 'DC:A9:04', 'E0:5F:45', 'E0:66:78', 'E0:B9:BA', 'E0:C7:67', 'E0:F8:47', 'E4:25:E7', 'E4:2B:34', 'E4:98:D6', 'E4:C6:3D', 'E4:CE:8F', 'E4:E0:A6', 'E4:E4:AB', 'E8:04:0B', 'E8:06:88', 'E8:80:2E', 'E8:8D:28', 'EC:35:86', 'EC:85:2F', 'EC:AD:B8', 'F0:18:98', 'F0:79:60', 'F0:98:9D', 'F0:99:BF', 'F0:B0:E7', 'F0:B4:79', 'F0:C1:F1', 'F0:CB:A1', 'F0:D1:A9', 'F0:DB:E2', 'F0:DB:F8', 'F0:DC:E2', 'F0:F6:1C', 'F4:0F:24', 'F4:1B:A1', 'F4:31:C3', 'F4:37:B7', 'F4:5C:89', 'F4:63:1F', 'F4:F1:5A', 'F4:F9:51', 'F8:03:77', 'F8:27:93', 'F8:62:14', 'F8:95:EA', 'FC:D8:48', 'FC:E9:D8', 'FC:FC:48'],
    
    # Samsung Devices
    'samsung_mobile': ['00:07:AB', '00:12:47', '00:15:99', '00:17:C9', '00:1C:43', '00:21:19', '00:24:54', '00:26:37', '00:E0:64', '04:18:0F', '08:08:C2', '08:37:3D', '08:D4:2B', '0C:14:20', '0C:71:5D', '0C:89:10', '10:1D:C0', '10:3B:59', '10:77:B1', '14:49:E0', '14:56:8E', '14:F4:2A', '18:1E:B0', '18:3F:47', '18:46:17', '18:83:31', '18:89:5B', '1C:5A:3E', '1C:62:B8', '1C:66:AA', '1C:AF:05', '20:13:E0', '20:55:31', '20:6E:9C', '20:D3:90', '24:4B:03', '24:C6:96', '24:DB:ED', '28:27:BF', '28:83:35', '28:BA:B5', '2C:AE:2B', '30:19:66', '30:96:FB', '34:14:5F', '34:23:BA', '34:31:11', '34:AA:8B', '34:BE:00', '34:C3:AC', '38:0A:94', '38:16:D1', '38:2D:D1', '38:94:96', '38:AA:3C', '3C:5A:37', '3C:62:00', '3C:8B:FE', '40:0E:85', '40:16:3B', '40:D3:AE', '44:4E:1A', '44:6D:6C', '44:78:3E', '44:F4:59', '48:13:7E', '48:27:EA', '48:44:F7', '4C:3C:16', '4C:BC:A5', '50:01:BB', '50:32:75', '50:85:69', '50:92:B9', '50:A4:C8', '50:B7:C3', '50:C8:E5', '50:F0:D3', '54:40:AD', '54:88:0E', '54:92:BE', '54:F2:01', '58:C3:8B', '5C:2E:59', '5C:3C:27', '5C:49:7D', '5C:A3:9D', '5C:E8:EB', '5C:F6:DC', '60:6B:BD', '60:77:E2', '60:A1:0A', '60:D0:A9', '64:1C:AE', '64:6C:B2', '64:77:91', '64:B3:10', '68:27:37', '68:48:98', '68:E7:C2', '6C:2F:2C', '6C:83:36', '6C:B7:49', '70:28:8B', '70:F9:27', '74:45:8A', '74:5F:00', '78:1F:DB', '78:25:AD', '78:40:E4', '78:47:1D', '78:52:1A', '78:59:5E', '78:9E:D0', '78:A8:73', '78:BD:BC', '78:C3:E9', '7C:0B:C6', '7C:1C:68', '7C:64:56', '7C:78:7E', '7C:91:22', '7C:F8:54', '80:18:A7', '80:4E:81', '80:57:19', '80:65:6D', '84:11:9E', '84:25:DB', '84:38:38', '84:51:81', '84:55:A5', '84:98:66', '88:32:9B', '88:75:98', '88:83:22', '88:9B:39', '8C:71:F8', '8C:77:12', '8C:BF:A6', '90:00:DB', '90:18:7C', '94:01:C2', '94:35:0A', '94:51:03', '94:63:D1', '94:76:B7', '94:87:E0', '94:B1:0A', '98:1D:FA', '98:39:8E', '9C:02:98', '9C:3A:AF', '9C:65:B0', 'A0:07:98', 'A0:21:95', 'A0:60:90', 'A0:75:91', 'A0:82:1F', 'A0:B4:A5', 'A0:CB:FD', 'A4:07:B6', 'A4:84:31', 'A8:06:00', 'A8:16:D0', 'AC:36:13', 'AC:5A:14', 'B0:C4:E7', 'B0:D0:9C', 'B0:EC:71', 'B4:3A:28', 'B4:62:93', 'B4:79:A7', 'B8:57:D8', 'B8:5A:73', 'B8:5E:7B', 'B8:6C:E8', 'B8:BB:AF', 'B8:C6:8E', 'BC:14:85', 'BC:20:A4', 'BC:44:86', 'BC:47:60', 'BC:72:B1', 'BC:79:AD', 'BC:85:1F', 'BC:B1:F3', 'C0:11:73', 'C0:65:99', 'C0:89:97', 'C0:BD:D1', 'C4:42:02', 'C4:50:06', 'C4:57:6E', 'C4:62:EA', 'C4:73:1E', 'C4:88:E5', 'C8:14:79', 'C8:19:F7', 'C8:38:70', 'C8:7E:75', 'C8:A8:23', 'CC:07:AB', 'CC:3A:61', 'CC:6E:A4', 'CC:F9:E8', 'CC:FE:3C', 'D0:17:6A', 'D0:22:BE', 'D0:59:E4', 'D0:66:7B', 'D0:87:E2', 'D0:B1:28', 'D0:C1:B1', 'D0:DF:C7', 'D4:87:D8', 'D4:88:90', 'D4:E8:DB', 'D8:08:31', 'D8:57:EF', 'D8:90:E8', 'D8:C4:E9', 'DC:44:B6', 'DC:66:72', 'DC:CF:96', 'E4:12:1D', 'E4:32:CB', 'E4:40:E2', 'E4:58:B8', 'E4:7C:F9', 'E4:92:FB', 'E4:B0:21', 'E4:E0:C5', 'E8:03:9A', 'E8:11:32', 'E8:3A:12', 'E8:4E:84', 'E8:93:09', 'E8:B4:C8', 'EC:10:7B', 'EC:1F:72', 'EC:9B:F3', 'F0:08:F1', 'F0:5A:09', 'F0:5B:7B', 'F0:72:8C', 'F0:E7:7E', 'F4:09:D8', 'F4:42:8F', 'F4:7B:5E', 'F4:9F:54', 'F4:D9:FB', 'F8:04:2E', 'F8:3F:51', 'F8:77:B8', 'F8:84:F2', 'FC:00:12', 'FC:1F:19', 'FC:42:03', 'FC:8F:90', 'FC:A1:3E', 'FC:C7:34'],
    
    # Add more device-specific MAC prefixes here
}

def console_print(message, color):
    """Print colored messages before rich library is available"""
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "blue": "\033[94m",
        "yellow": "\033[93m",
        "end": "\033[0m"
    }
    print(f"{colors[color]}{message}{colors['end']}")

def setup_environment():
    """Setup virtual environment and install required packages"""
    console_print("[+] Setting up environment...", "blue")
    
    venv_path = Path("./venv")
    if not venv_path.exists():
        console_print("[+] Creating virtual environment...", "blue")
        venv.create(venv_path, with_pip=True)
        
        # Get the correct pip path
        if os.name == "nt":  # Windows
            pip_path = venv_path / "Scripts" / "pip"
        else:  # Unix/Linux
            pip_path = venv_path / "bin" / "pip"
            
        # Install required packages
        console_print("[+] Installing required packages...", "blue")
        subprocess.run([str(pip_path), "install", "scapy"])
        subprocess.run([str(pip_path), "install", "rich"])
        
        console_print("[+] Setup complete!", "green")

def verify_monitor_mode(interface):
    """Verify interface is in monitor mode"""
    try:
        result = subprocess.run(["iwconfig", interface], 
                              capture_output=True, 
                              text=True)
        if "Mode:Monitor" not in result.stdout:
            console_print("[-] Monitor mode not enabled correctly!", "red")
            return False
        return True
    except:
        return False

def enable_monitor_mode():
    """Enable monitor mode on wireless interface"""
    if os.name != "nt":  # Only for Linux
        console_print("[+] Enabling monitor mode...", "blue")
        
        try:
            result = subprocess.run(["iwconfig"], capture_output=True, text=True)
            interfaces = [line.split()[0] for line in result.stdout.split('\n') if 'IEEE 802.11' in line]
            
            if not interfaces:
                console_print("[-] No wireless interfaces found!", "red")
                sys.exit(1)
                
            if len(interfaces) > 1:
                console_print("[+] Multiple wireless interfaces found:", "blue")
                for i, iface in enumerate(interfaces):
                    console_print(f"    {i+1}. {iface}", "yellow")
                choice = input("\nSelect interface number: ")
                interface = interfaces[int(choice)-1]
            else:
                interface = interfaces[0]
                
            console_print(f"[+] Using interface: {interface}", "blue")
            
            subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL)
            subprocess.run(["airmon-ng", "start", interface], stdout=subprocess.DEVNULL)
            
            result = subprocess.run(["iwconfig"], capture_output=True, text=True)
            mon_interface = next((line.split()[0] for line in result.stdout.split('\n') 
                               if 'Mode:Monitor' in line), None)
            
            if not mon_interface:
                console_print("[-] Failed to enable monitor mode!", "red")
                sys.exit(1)
                
            # Add verification
            if not verify_monitor_mode(mon_interface):
                console_print("[-] Trying alternative method...", "yellow")
                try:
                    subprocess.run(["ip", "link", "set", mon_interface, "down"], stdout=subprocess.DEVNULL)
                    subprocess.run(["iw", mon_interface, "set", "monitor", "none"], stdout=subprocess.DEVNULL)
                    subprocess.run(["ip", "link", "set", mon_interface, "up"], stdout=subprocess.DEVNULL)
                    if not verify_monitor_mode(mon_interface):
                        console_print("[-] Failed to enable monitor mode!", "red")
                        sys.exit(1)
                except:
                    console_print("[-] Failed to enable monitor mode!", "red")
                    sys.exit(1)
            
            return mon_interface
            
        except FileNotFoundError:
            console_print("[-] Required tools not found! Installing...", "yellow")
            subprocess.run(["apt-get", "update"])
            subprocess.run(["apt-get", "install", "-y", "wireless-tools", "aircrack-ng"])
            console_print("[+] Tools installed, please run the script again", "green")
            sys.exit(1)
    
    return "wlan0mon"

def check_root():
    """Check if script is running with root privileges"""
    if os.name != "nt" and os.geteuid() != 0:
        console_print("[-] This script requires root privileges!", "red")
        console_print("[*] Please run with sudo", "yellow")
        sys.exit(1)

def is_likely_projector(ssid, mac_addr):
    """Enhanced projector detection logic"""
    ssid_lower = ssid.lower() if ssid else ""
    
    # Check against known projector identifiers
    for category in PROJECTOR_IDENTIFIERS.values():
        if any(identifier in ssid_lower for identifier in category):
            return True
            
    # Check common projector MAC prefixes (OUIs)
    projector_ouis = {
        'epson': ['00:26:ab', '00:1b:a9'],
        'benq': ['00:6b:8e'],
        'nec': ['00:16:41'],
        'panasonic': ['00:13:43'],
    }
    
    mac_prefix = mac_addr[:8].lower()
    for brand, ouis in projector_ouis.items():
        if any(oui.lower() in mac_prefix for oui in ouis):
            return True
    
    return False

def load_oui_database():
    """Load MAC address to company mapping"""
    console_print("[+] Loading MAC address database...", "blue")
    try:
        # Try to download the database
        response = urllib.request.urlopen(OUI_DATABASE_URL, timeout=5)
        data = response.read().decode('utf-8')
        
        for line in data.split('\n'):
            if line and not line.startswith('#'):
                parts = line.split('\t')
                if len(parts) >= 2:
                    mac_prefix = parts[0].strip().lower()
                    company = parts[1].strip()
                    MAC_TO_COMPANY[mac_prefix] = company
                    
        console_print(f"[+] Loaded {len(MAC_TO_COMPANY)} company entries", "green")
    except Exception as e:
        # If download fails, use a basic built-in database
        console_print("[-] Using built-in MAC database", "yellow")
        MAC_TO_COMPANY.update({
            "00:00:0c": "Cisco",
            "00:05:69": "VMware",
            "00:17:88": "Philips",
            "00:20:00": "Apple",
            "00:26:ab": "Seiko Epson",
            "00:1b:a9": "Brother",
            # Add more common manufacturers
        })

def get_device_info_from_mac(mac_addr: str) -> tuple:
    """Get detailed device info from MAC address"""
    if not mac_addr:
        return "Unknown", "Unknown"

    try:
        mac_prefix = mac_addr[:8].lower()
        
        # Check device-specific MAC prefixes
        for device_type, prefixes in MAC_PREFIXES.items():
            if any(mac_addr.lower().startswith(prefix.lower().replace(':', '')) for prefix in prefixes):
                if 'apple' in device_type:
                    return "Apple", device_type.replace('apple_', '').title()
                elif 'samsung' in device_type:
                    return "Samsung", device_type.replace('samsung_', '').title()
                else:
                    return "Unknown", device_type.title()

        # Check general manufacturer
        company = MAC_TO_COMPANY.get(mac_prefix, "Unknown")
        
        # Try to determine device type from company name
        device_type = "Unknown"
        company_lower = company.lower()
        
        if any(brand in company_lower for brand in ['apple', 'iphone', 'ipad']):
            device_type = "Mobile" if 'iphone' in company_lower else "Apple Device"
        elif any(brand in company_lower for brand in ['samsung', 'huawei', 'xiaomi', 'oppo', 'vivo']):
            device_type = "Mobile"
        elif any(brand in company_lower for brand in ['intel', 'realtek', 'broadcom']):
            device_type = "Computer"
        elif any(brand in company_lower for brand in PROJECTOR_IDENTIFIERS['brands']):
            device_type = "Projector"
            
        return company, device_type

    except Exception:
        return "Unknown", "Unknown"

def get_device_type(mac_addr: str, ssid: Optional[str] = None, company: str = "Unknown") -> str:
    """Enhanced device type detection"""
    if not mac_addr:
        return "Unknown"

    try:
        mac_prefix = mac_addr[:8].lower()
        
        # First check OUI-based device type
        for device_type, info in DEVICE_SIGNATURES.items():
            if 'oui' in info:
                for brand, ouis in info['oui'].items():
                    if any(mac_addr.lower().startswith(oui.lower().replace(':', '')) for oui in ouis):
                        return device_type.title()

        # Then check SSID-based detection
        if ssid:
            ssid_lower = ssid.lower()
            for device_type, info in DEVICE_SIGNATURES.items():
                if any(brand in ssid_lower for brand in info['brands']) or \
                   any(keyword in ssid_lower for keyword in info['keywords']):
                    return device_type.title()

        # Finally check company name
        company_lower = company.lower()
        for device_type, info in DEVICE_SIGNATURES.items():
            if any(brand in company_lower for brand in info['brands']):
                return device_type.title()

    except Exception:
        pass

    return "Unknown"

def create_device_table():
    """Create and update the device table"""
    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.ROUNDED,
        title="[bold blue]Active Wireless Devices[/bold blue]",
        caption="[italic]Press Ctrl+C to stop scanning[/italic]"
    )
    
    table.add_column("MAC Address", style="cyan", width=17)
    table.add_column("Company", style="magenta", width=20)
    table.add_column("Device Type", style="red", width=15)
    table.add_column("Name/SSID", style="green", width=25)
    table.add_column("Signal", style="yellow", width=8)
    table.add_column("Last Seen", style="blue", width=8)

    try:
        # Get active devices (seen in last 30 seconds)
        active_devices = [
            (mac, info) for mac, info in discovered_devices.items()
            if (datetime.now() - info['last_seen']).total_seconds() <= 30
        ]

        # Sort by signal strength
        sorted_devices = sorted(
            active_devices,
            key=lambda x: x[1]['signal_strength'],
            reverse=True
        )

        for mac, info in sorted_devices:
            signal = f"{info['signal_strength']} dBm"
            device_type = info['device_type']
            name = info['ssid'] if info['ssid'] else 'N/A'
            last_seen = info['last_seen'].strftime("%H:%M:%S")

            # Style based on device type
            style = None
            if info['is_ap']:
                style = "bold blue"
            elif device_type == "Mobile":
                style = "bold green"
            elif device_type == "Laptop":
                style = "bold yellow"
            elif device_type == "Tablet":
                style = "bold magenta"
            elif device_type == "Smartwatch":
                style = "bold cyan"
            elif device_type == "Projector":
                style = "bold red"

            table.add_row(
                mac,
                info['company'],
                device_type,
                name,
                signal,
                last_seen,
                style=style
            )

    except Exception as e:
        console.print(f"[red]Error creating table: {str(e)}[/red]")

    return table

def packet_handler(pkt):
    """Enhanced packet handler with better device detection"""
    try:
        if not pkt.haslayer(Dot11):
            return

        # Get valid MAC addresses
        addresses = set()
        for field in ['addr1', 'addr2', 'addr3']:
            if hasattr(pkt, field):
                addr = getattr(pkt, field)
                if addr and isinstance(addr, str):
                    if not addr.startswith(('ff:ff:ff', '00:00:00', '33:33:', '01:00:5e')):
                        addresses.add(addr)

        if not addresses:
            return

        for mac_address in addresses:
            # Get signal strength
            signal_strength = -100
            try:
                if hasattr(pkt, 'dBm_AntSignal'):
                    signal_strength = pkt.dBm_AntSignal
                elif hasattr(pkt, 'notdecoded') and len(pkt.notdecoded) >= 4:
                    signal_strength = -(256-ord(pkt.notdecoded[-4:-3]))
            except:
                pass

            # Process new device
            if mac_address not in discovered_devices:
                company, device_type = get_device_info_from_mac(mac_address)
                
                discovered_devices[mac_address] = {
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'signal_strength': signal_strength,
                    'ssid': None,
                    'device_type': device_type,
                    'company': company,
                    'connection_type': None,
                    'probe_requests': set(),
                    'is_ap': False
                }

                # Print new device with more details
                console.print(Panel.fit(
                    f"[bold green]New Device Found![/bold green]\n"
                    f"MAC: [cyan]{mac_address}[/cyan]\n"
                    f"Type: [red]{device_type}[/red]\n"
                    f"Company: [magenta]{company}[/magenta]\n"
                    f"Signal: [yellow]{signal_strength} dBm[/yellow]",
                    border_style="green"
                ))

            device_info = discovered_devices[mac_address]
            device_info['last_seen'] = datetime.now()
            
            if signal_strength > device_info['signal_strength']:
                device_info['signal_strength'] = signal_strength

            # Process SSID and update device type
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                try:
                    if hasattr(pkt, 'info') and pkt.info:
                        ssid = pkt.info.decode().strip()
                        if ssid:
                            device_info['ssid'] = ssid
                            if mac_address == pkt.addr3:
                                device_info['is_ap'] = True
                                device_info['device_type'] = 'Access Point'
                            else:
                                # Update device type based on SSID
                                new_type = get_device_type(mac_address, ssid, device_info['company'])
                                if new_type != "Unknown":
                                    device_info['device_type'] = new_type
                except:
                    pass

            # Update device type for data frames
            if pkt.type == 2 and device_info['device_type'] == "Unknown":
                device_info['device_type'] = get_device_type(mac_address, company=device_info['company'])

    except Exception as e:
        pass

def disable_monitor_mode(interface):
    """Disable monitor mode and restore normal interface operation"""
    try:
        console_print("\n[+] Restoring wireless interface...", "blue")
        
        # Stop monitoring
        subprocess.run(["airmon-ng", "stop", interface], stdout=subprocess.DEVNULL)
        
        # Restart NetworkManager
        subprocess.run(["systemctl", "start", "NetworkManager"], stdout=subprocess.DEVNULL)
        
        console_print("[+] Wireless interface restored", "green")
    except Exception as e:
        console_print(f"[-] Error restoring interface: {str(e)}", "red")

def cleanup(interface):
    """Cleanup function to be called on exit"""
    try:
        # Kill any remaining processes
        subprocess.run(["pkill", "airodump-ng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "iwconfig"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Disable monitor mode
        disable_monitor_mode(interface)
        
        # Force exit after cleanup
        os._exit(0)
    except:
        os._exit(1)

def signal_handler(sig, frame):
    """Handle Ctrl+C and other signals"""
    console.print("\n[bold yellow]Stopping scan and cleaning up...[/bold yellow]")
    # Let the main thread handle cleanup
    raise KeyboardInterrupt

def channel_hopper(interface, stop_event):
    """Hop between WiFi channels"""
    while not stop_event.is_set():
        for channel in range(1, 14):  # Channels 1-13
            if stop_event.is_set():
                break
            try:
                os.system(f"iwconfig {interface} channel {channel} 2>/dev/null")
                time.sleep(0.3)
            except:
                pass

def start_scan(interface):
    """Start the scanning process"""
    console.clear()
    console.print(Panel.fit(
        "[bold blue]Wireless Device Scanner[/bold blue]\n"
        "[yellow]Scanning for all wireless devices...[/yellow]\n"
        "[green]Press Ctrl+C to stop scanning[/green]",
        border_style="blue"
    ))

    # Configure Scapy
    conf.iface = interface
    conf.sniff_promisc = True

    # Create stop event for clean exit
    stop_event = threading.Event()

    # Start channel hopper
    hopper = threading.Thread(target=channel_hopper, args=(interface, stop_event))
    hopper.daemon = True
    hopper.start()

    try:
        with Live(create_device_table(), refresh_per_second=1, screen=True) as live:
            def update_callback(pkt):
                if stop_event.is_set():
                    return True  # Stop sniffing
                packet_handler(pkt)
                try:
                    live.update(create_device_table())
                except Exception:
                    pass

            # Start capture
            sniff(iface=interface,
                 prn=update_callback,
                 store=0,
                 stop_filter=lambda _: stop_event.is_set())

    except KeyboardInterrupt:
        stop_event.set()  # Signal threads to stop
        console.print("\n[bold green]Scan Complete![/bold green]")
        console.print("\n[bold blue]Final Results:[/bold blue]")
        console.print(create_device_table())
    finally:
        stop_event.set()  # Ensure threads stop
        cleanup(interface)

def main():
    """Main function to handle the workflow"""
    try:
        print("\n=== Wireless Device Scanner ===\n")
        
        # Check if running as root
        check_root()
        
        # Setup virtual environment
        setup_environment()
        
        # Load MAC address database
        load_oui_database()
        
        # Enable monitor mode and get interface name
        mon_interface = enable_monitor_mode()
        
        # Register cleanup functions
        atexit.register(cleanup, mon_interface)
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start scanning
        start_scan(mon_interface)
        
    except KeyboardInterrupt:
        cleanup(mon_interface)
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
        cleanup(mon_interface)

if __name__ == "__main__":
    main() 