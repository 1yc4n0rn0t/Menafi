import time
import subprocess
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11WEP
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

# ASCII Art Header (Inspired by Wifite)
ascii_logo = """
▗▖  ▗▖▗▄▄▄▖▗▖  ▗▖ ▗▄▖ ▗▄▄▄▖▗▄▄▄▖
▐▛▚▞▜▌▐▌   ▐▛▚▖▐▌▐▌ ▐▌▐▌     █  
▐▌  ▐▌▐▛▀▀▘▐▌ ▝▜▌▐▛▀▜▌▐▛▀▀▘  █  
▐▌  ▐▌▐▙▄▄▖▐▌  ▐▌▐▌ ▐▌▐▌   ▗▄█▄▖

"for the average wardriver"
"""

# Store seen SSIDs to avoid duplication
seen_networks = set()

# Open the log file in append mode
log_file = open("log.txt", "a")

def set_monitor_mode(interface):
    """Ensure the interface is in monitor mode."""
    try:
        print(f"{Fore.GREEN}Setting {interface} to monitor mode...")
        subprocess.check_call(["sudo", "ip", "link", "set", interface, "down"])
        subprocess.check_call(["sudo", "iw", "dev", interface, "set", "type", "monitor"])
        subprocess.check_call(["sudo", "ip", "link", "set", interface, "up"])
        print(f"{Fore.GREEN}{interface} is now in monitor mode.")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error setting {interface} to monitor mode: {e}")
        exit(1)

def packet_handler(pkt):
    """Process each captured packet to extract information."""
    if pkt.haslayer(Dot11Beacon):  # We're interested in Beacon frames (APs announcing themselves)
        ssid = pkt[Dot11Elt].info.decode() if pkt[Dot11Elt].info else "<Hidden SSID>"
        mac_address = pkt[Dot11].addr2
        signal_strength = pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else "N/A"
        encryption = "Open"  # Default to Open (no encryption)

        # Detect encryption type
        if pkt.haslayer(Dot11WEP):
            encryption = "WEP"
        # You can add more heuristics for WPA detection, but Scapy doesn't directly support this in your version.
        
        # Skip duplicate networks
        if ssid not in seen_networks:
            seen_networks.add(ssid)
            # Print packet info with colors for better readability
            print(f"{Fore.CYAN}SSID: {ssid}, {Fore.YELLOW}MAC: {mac_address}, {Fore.MAGENTA}Signal: {signal_strength}, {Fore.BLUE}Encryption: {encryption}")

            # Log the SSID to the log file
            log_file.write(f"SSID: {ssid}, MAC: {mac_address}, Signal: {signal_strength}, Encryption: {encryption}\n")
            log_file.flush()  # Ensure the data is written to the file immediately
        else:
            # Optionally, you can print the same SSID in a different color or skip it.
            pass

def start_sniffing(interface):
    """Start sniffing for networks using Scapy."""
    print(f"{Fore.GREEN}Starting WiFi scan on {interface}...")
    sniff(iface=interface, prn=packet_handler, store=0, timeout=60)  # Sniff for 60 seconds

def main():
    # Print ASCII logo explicitly without color
    print(ascii_logo)
    
    interface = "wlxe84e06b6076c"  # Your new USB Wi-Fi interface
    set_monitor_mode(interface)  # Set the interface to monitor mode
    while True:
        start_sniffing(interface)    # Start sniffing for Wi-Fi networks
        print(f"{Fore.YELLOW}\nWaiting 10 seconds before next scan...\n")
        time.sleep(10)  # Throttle output and wait before the next scan

if __name__ == "__main__":
    try:
        main()
    finally:
        # Ensure the log file is closed when the script exits
        log_file.close()
