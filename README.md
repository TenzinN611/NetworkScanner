# NetworkScanner
This project involves developing a network scanning and vulnerability assessment tool using Python and the `nmap` library. The tool performs three main functions: ARP scanning, port scanning, and vulnerability scanning. It is designed to help network administrators and security professionals discover devices on a network, identify open ports, and assess potential vulnerabilities in a targeted device.

 Features

1. ARP Scan
   - Function: `arp_scan(ip, subnet_mask)`
   - Description: Scans the network using ARP to discover all devices within a specified IP range. It retrieves and displays the IP and MAC addresses of these devices.
   - Usage: Useful for identifying all active devices on a local network.

2. Port Scan
   - Function: `port_scan(ip)`
   - 

- Description: Scans a specified IP address to identify open TCP ports. It uses a fast scan method to quickly determine which ports are accessible.
   - Usage: Helps in identifying open ports which could be potential entry points for attackers or services that need to be monitored.

3. Vulnerability Scan
   - Function: `vulnerability_scan(ip)`
   - Description: Conducts a comprehensive scan to identify vulnerabilities on a specified IP address. It uses techniques like SYN scanning, service version detection, OS detection, and runs vulnerability scripts to find and display security weaknesses.
   - Usage: Essential for assessing the security posture of devices and identifying vulnerabilities that need to be addressed to protect against potential threats.

 Workflow

1. User Input for Network Range: 
   - The user inputs the IP address and subnet mask to define the network range to be scanned.
   
2. ARP Scanning:
   - The tool performs an ARP scan over the specified network range to discover active devices and their IP/MAC addresses.
   
3. Display Devices:
   - Lists all discovered devices with their IP and MAC addresses for the user.

4. User Selection for Further Scanning:
   - The user selects a specific device (by IP address) for deeper scanning.
   
5. Port Scanning:
   - The tool scans the selected device for open ports and displays the results.

6. Vulnerability Scanning:
   - Finally, the tool performs a vulnerability scan on the selected device, identifying potential security issues and displaying detailed information about each vulnerability.

 Intended Use

This tool is designed for use by network administrators, security professionals, and students in a controlled environment or with proper authorization. It aids in understanding network structure, identifying open ports, and assessing vulnerabilities to improve overall network security. It is crucial to obtain permission before using this tool on any network to comply with legal and ethical standards.
