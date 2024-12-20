# Menafi

<p align="center">
  <img src="https://github.com/1yc4n0rn0t/Menafi/blob/main/elf.png" alt="Image" style="height: 350px; vertical-align: middle; margin-left: 10px;" />
</p>

______________________________________

# Menafi - WiFi Scanner for Wardriving

## About the Project

**Menafi** is a Python-based WiFi scanner designed for **wardriving** and wireless network analysis. It allows users to scan for nearby WiFi networks, capture key details about each network (such as SSID, MAC address, signal strength, and encryption type), and log them for later analysis. Unlike WiFi cracking tools, Menafi focuses solely on scanning and logging WiFi networks, making it a great tool for network mapping and wireless environment assessments.

**"For the average wardriver"**

## What It Does

- **Scans for WiFi networks**: Detects all available WiFi networks in the vicinity.
- **Logs network information**: Records SSID, MAC address, signal strength, and encryption type in a log file.
- **Color-coded output**: Displays network details in the terminal with color-coding for readability.
- **Supports USB Wi-Fi adapters**: Use an external USB Wi-Fi adapter in monitor mode for scanning.

## How to Use

### Install the Dependencies

Follow these steps to set up your environment and install Menafi:

1. **Installation**  
   Ensure that Python 3.6 or higher is installed. You can check by running:
   ```bash
   python3 --version
   sudo apt install python3-pip
   sudo apt install iw
   python3 -m venv menafi-env
   source menafi-env/bin/activate
   pip install -r requirements.txt
   ```

     Setup the Network interface
      ```bash
     sudo ip link set <interface> down
     sudo iw dev <interface> set type monitor
     sudo ip link set <interface> up
      ```

     Update the script to match you interface
     ```bash
    line 73
      interface = "your-interface"  # Your new USB Wi-Fi interface
     ```

     Finally
      ```bash
      python3 menafi.py
      ```

3. **Usage**
   When the scanner runs there are two things to keep in mind
   - A log.txt file will be created to keep track of all your SSIDs
   - There is a 10 sec wait, this is so you can stop and pull over to get a good scan of the area , then move on
   
