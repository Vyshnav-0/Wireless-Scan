# Wireless Device Scanner

A Python tool for scanning and detecting wireless devices in your surroundings, with special focus on finding projectors and display devices.

## Setup Instructions

1. Make sure you have Python 3.7+ installed
2. Run the setup script to create virtual environment and install dependencies:
   ```bash
   python setup.py
   ```

3. Activate the virtual environment:
   - On Windows:
     ```bash
     venv\Scripts\activate
     ```
   - On Linux/Mac:
     ```bash
     source venv/bin/activate
     ```

4. Put your wireless interface in monitor mode (Linux only):
   ```bash
   sudo airmon-ng check kill
   sudo airmon-ng start wlan0
   ```

5. Run the scanner:
   ```bash
   sudo python scanner.py
   ```

## Requirements

- Python 3.7+
- Linux operating system (recommended)
- Wireless adapter that supports monitor mode
- Root/sudo privileges

## Installed Packages

- scapy: For packet capture and analysis
- rich: For beautiful terminal interface

## Notes

- The tool requires root privileges to capture packets
- Make sure your wireless adapter supports monitor mode
- Use responsibly and only on networks you own or have permission to scan 