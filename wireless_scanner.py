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
    if not mac_addr:  # Add check for None
        return "Unknown", "Unknown"
        
    try:
        mac_prefix = mac_addr[:8].lower()
    except (AttributeError, TypeError):
        return "Unknown", "Unknown"
        
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
    
    # Try to determine device type from SSID
    if ssid:
        try:
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
        except (AttributeError, TypeError):
            pass
            
    return company, device_type

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
                company, _ = get_device_info(mac_address)
                device_type = get_device_type(mac_address, company=company)
                
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