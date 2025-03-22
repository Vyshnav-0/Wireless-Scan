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

# Add more device signatures
DEVICE_SIGNATURES = {
    'phones': {
        'brands': ['iphone', 'samsung', 'xiaomi', 'huawei', 'oneplus', 'pixel', 'redmi', 'oppo', 'vivo'],
        'keywords': ['phone', 'mobile', 'smartphone', 'android']
    },
    'laptops': {
        'brands': ['macbook', 'thinkpad', 'dell', 'hp', 'asus', 'acer', 'lenovo', 'msi'],
        'keywords': ['laptop', 'notebook', 'computer', 'pc']
    },
    'iot': {
        'brands': ['nest', 'ring', 'alexa', 'echo', 'philips', 'xiaomi', 'smart'],
        'keywords': ['cam', 'thermostat', 'smart', 'iot', 'hub', 'switch', 'bulb']
    },
    'tablets': {
        'brands': ['ipad', 'galaxy tab', 'surface', 'kindle'],
        'keywords': ['tablet', 'pad', 'reader']
    },
    'media': {
        'brands': ['roku', 'firestick', 'chromecast', 'apple tv', 'nvidia shield'],
        'keywords': ['tv', 'streaming', 'media', 'cast']
    },
    'wearables': {
        'brands': ['fitbit', 'garmin', 'apple watch', 'galaxy watch'],
        'keywords': ['watch', 'band', 'fitness']
    }
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

def get_device_info(mac_addr: str, ssid: Optional[str] = None) -> tuple:
    """Get device manufacturer and type based on MAC and SSID"""
    mac_prefix = mac_addr[:8].lower()
    company = "Unknown"
    device_type = "Unknown"
    
    # Try to get company name from local database first
    try:
        # Try exact match first
        company = MAC_TO_COMPANY.get(mac_prefix, None)
        if not company:
            # Try partial match
            for prefix, comp in MAC_TO_COMPANY.items():
                if mac_prefix.startswith(prefix.lower()):
                    company = comp
                    break
    except Exception:
        pass
    
    # Try to determine device type
    if ssid:
        ssid_lower = ssid.lower()
        
        # Check all device signatures
        for dev_type, signatures in DEVICE_SIGNATURES.items():
            if any(brand in ssid_lower for brand in signatures['brands']) or \
               any(keyword in ssid_lower for keyword in signatures['keywords']):
                device_type = dev_type.title()
                break
        
        # Check projector signatures separately
        if is_likely_projector(ssid, mac_addr):
            device_type = "Projector"
            
    # If still unknown, try to guess from company name
    if device_type == "Unknown" and company != "Unknown":
        company_lower = company.lower()
        for dev_type, signatures in DEVICE_SIGNATURES.items():
            if any(brand.lower() in company_lower for brand in signatures['brands']):
                device_type = dev_type.title()
                break
    
    return company, device_type

def create_device_table():
    """Create and update the device table"""
    table = Table(box=box.ROUNDED)
    table.add_column("MAC Address", style="cyan", width=17)
    table.add_column("Company", style="magenta", width=20)
    table.add_column("Type", style="red", width=15)
    table.add_column("Name/SSID", style="green", width=20)
    table.add_column("Signal", style="yellow", width=8)
    table.add_column("Last Seen", style="blue", width=8)

    # Sort devices by signal strength
    sorted_devices = sorted(
        discovered_devices.items(),
        key=lambda x: x[1]['signal_strength'],
        reverse=True
    )

    for mac, info in sorted_devices:
        # Skip devices not seen in last 60 seconds
        if (datetime.now() - info['last_seen']).total_seconds() > 60:
            continue

        signal = f"{info['signal_strength']} dBm"
        device_type = info['device_type']
        name = info['ssid'] if info['ssid'] else 'N/A'
        last_seen = info['last_seen'].strftime("%H:%M:%S")

        # Determine row style
        style = None
        if info['is_ap']:
            style = "bold blue"
        elif device_type == "Projector":
            style = "bold red"
        elif device_type != "Unknown":
            style = "bold white"

        table.add_row(
            mac,
            info['company'],
            device_type,
            name,
            signal,
            last_seen,
            style=style
        )

    return table

def packet_handler(pkt):
    """Handle captured packets"""
    try:
        if not pkt.haslayer(Dot11):
            return

        # Get all possible MAC addresses from the packet
        addresses = set()
        
        # Check all possible address fields
        if hasattr(pkt, 'addr1') and pkt.addr1:
            addresses.add(pkt.addr1)
        if hasattr(pkt, 'addr2') and pkt.addr2:
            addresses.add(pkt.addr2)
        if hasattr(pkt, 'addr3') and pkt.addr3:
            addresses.add(pkt.addr3)

        # Filter out broadcast and multicast addresses
        addresses = {addr for addr in addresses if addr and 
                    not addr.startswith(('ff:ff:ff', '00:00:00', '33:33:', '01:00:5e'))}

        if not addresses:
            return

        # Debug print (temporary)
        console.print(f"[cyan]Found MAC: {addresses}[/cyan]", end="\r")

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
                company, device_type = get_device_info(mac_address)
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
                # Print new device discovery
                console.print(f"\n[bold green]New Device Found:[/bold green]")
                console.print(f"MAC: [cyan]{mac_address}[/cyan]")
                console.print(f"Company: [magenta]{company}[/magenta]")
                console.print(f"Type: [red]{device_type}[/red]")

            device_info = discovered_devices[mac_address]
            device_info['last_seen'] = datetime.now()
            
            if signal_strength > device_info['signal_strength']:
                device_info['signal_strength'] = signal_strength

            # Process SSID information
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                if hasattr(pkt, 'info') and pkt.info:
                    try:
                        ssid = pkt.info.decode()
                        device_info['ssid'] = ssid
                        if mac_address == pkt.addr3:  # This is an AP
                            device_info['is_ap'] = True
                            device_info['device_type'] = 'Access Point'
                    except:
                        pass

            # Mark data-sending devices as active
            if pkt.type == 2:  # Data frames
                if device_info['device_type'] == 'Unknown':
                    device_info['device_type'] = 'Active Device'

    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]", end="\r")

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
        # Kill any remaining airodump-ng processes
        subprocess.run(["pkill", "airodump-ng"], stdout=subprocess.DEVNULL)
        
        # Disable monitor mode
        disable_monitor_mode(interface)
    except:
        pass

def signal_handler(sig, frame):
    """Handle Ctrl+C and other signals"""
    console_print("\n[+] Stopping scan and cleaning up...", "yellow")
    sys.exit(0)

def channel_hopper(interface):
    """Hop between WiFi channels"""
    while True:
        for channel in range(1, 14):  # Channels 1-13
            try:
                os.system(f"iwconfig {interface} channel {channel}")
                # Print channel change (temporary for debugging)
                console.print(f"[yellow]Scanning channel {channel}[/yellow]", end="\r")
                time.sleep(0.5)  # Stay longer on each channel
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

    # Configure Scapy for better packet capture
    conf.iface = interface
    conf.sniff_promisc = True
    
    # Don't use pcap as it might cause issues
    conf.use_pcap = False
    
    # Add monitor mode configuration
    os.system(f"iwconfig {interface} mode monitor")
    os.system(f"ifconfig {interface} up")

    try:
        with Live(create_device_table(), refresh_per_second=1) as live:
            def update_callback(pkt):
                packet_handler(pkt)
                try:
                    live.update(create_device_table())
                except Exception as e:
                    pass

            # Start packet capture with specific filter for all 802.11 packets
            sniff(iface=interface,
                 prn=update_callback,
                 store=0,
                 lfilter=lambda x: x.haslayer(Dot11))

    except KeyboardInterrupt:
        console.print("\n[bold green]Scan Complete![/bold green]")
        console.print("\n[bold blue]Final Results:[/bold blue]")
        console.print(create_device_table())
    finally:
        cleanup(interface)

def main():
    """Main function to handle the workflow"""
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
    
    try:
        # Start scanning
        start_scan(mon_interface)
    finally:
        # Ensure cleanup happens even on error
        cleanup(mon_interface)

if __name__ == "__main__":
    main() 