import nmap


def arp_scan(ip, subnet_mask):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=f"{ip}/{subnet_mask}", arguments='-PR -sn ')
        devices = []

        for host in nm.all_hosts():
            if 'mac' in nm[host]['addresses']:
                devices.append({'ip': host, 'mac': nm[host]['addresses']['mac']})

        return devices
    except Exception as e:
        print(f"Nmap ARP scan failed: {e}")
        return []


def port_scan(ip):
    try:
        scan_options = '-T4 -F'
        nm = nmap.PortScanner()
        nm.scan(ip, arguments=scan_options)
        result = nm[ip].all_tcp()

        return result
    except Exception as e:
        print(f"Port scan failed: {e}")


def vulnerability_scan(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-sS -sV -O -A --script vulners')
        result = nm[ip].get('tcp', {})

        # Print vulnerability scan results
        print("Vulnerabilities:")
        for port, info in result.items():
            print(f"Port: {port}")
            for key, value in info.items():
                print(f"{key}: {value}")
            print()  # Add empty line between vulnerability info
    except Exception as e:
        print(f"Vulnerability scan failed: {e}")


if __name__ == "__main__":
    try:
        ip_to_scan = input("Enter IP to scan: ")
        subnet_mask = input("Enter subnet mask (e.g., 24): ")

        print("==============================================================================================\n\n")

        devices = arp_scan(ip_to_scan, subnet_mask)
        if not devices:
            print("No devices found on the network.")
            exit()

        print("Devices on network:")
        for device in devices:
            print("IP:", device['ip'], " MAC:", device['mac'])

        print("==============================================================================================\n\n")

        ipp = input("Enter the ip of the device you want to scan: ")
        print("Scanning ports f1or:", ipp)
        open_ports = port_scan(ipp)
        print("Open ports:", open_ports)
        print("==============================================================================================\n\n\n")

        print("Scanning vulnerabilities for:", ipp)
        vulnerability_scan(ipp)
        print("==============================================================================================\n\n\n")

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
