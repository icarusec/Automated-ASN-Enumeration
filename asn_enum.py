import argparse
import subprocess
import os
import json
from collections import defaultdict
from termcolor import colored

# Directory for storing temporary files
temp_dir = "temp_files"
os.makedirs(temp_dir, exist_ok=True)

# Output files
nmap_output_file = "nmap_scan_results.txt"
webservers_file = "webservers.txt"
final_file = "final_results.txt"

# Colors
GREEN = 'green'
RED = 'red'

def run_command_live(command):
    """
    Execute a shell command and display output in real-time.
    """
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    for line in process.stdout:
        print(line, end='')  # Show output line by line
    process.stdout.close()
    process.wait()  # Ensure the process finishes

def scan_asn(asn_list):
    all_ips = []
    
    # Step 1: For each ASN, run asnmap and naabu
    for asn in asn_list:
        print(colored(f"Processing ASN: {asn}", 'cyan'))
        temp_asn_file = os.path.join(temp_dir, "naabu_temp.json")
        
        # Run asnmap and naabu
        asnmap_command = f"echo {asn} | asnmap -silent | naabu -json -o {temp_asn_file}"
        run_command_live(asnmap_command)

        # Parse the JSON output from Naabu
        if os.path.exists(temp_asn_file):
            with open(temp_asn_file, "r") as file:
                for line in file:
                    try:
                        entry = json.loads(line)
                        ip = entry['ip']
                        all_ips.append(ip)
                    except json.JSONDecodeError:
                        pass

    return list(set(all_ips))  # Return unique IPs

def collect_ports_for_ips():
    """
    Parses the naabu JSON output and collects the open ports for each IP.
    Returns a dictionary with IPs as keys and list of open ports as values.
    """
    ip_ports_map = defaultdict(list)
    
    temp_naabu_file = os.path.join(temp_dir, "naabu_temp.json")
    with open(temp_naabu_file, "r") as naabu_file:
        for line in naabu_file:
            try:
                entry = json.loads(line)
                ip = entry["ip"]
                port = entry["port"]
                ip_ports_map[ip].append(port)
            except json.JSONDecodeError:
                pass

    return ip_ports_map

def run_nmap_scan(ip_ports_map):
    """
    Runs Nmap scan for each IP with the ports found by Naabu.
    """
    print(colored("Running Nmap scan on collected IPs with open ports...", 'yellow'))
    
    for ip, ports in ip_ports_map.items():
        # Convert list of ports to comma-separated string
        port_str = ','.join(map(str, ports))
        
        # Construct the Nmap command for this IP with the ports
        nmap_command = f"nmap -sV -p {port_str} {ip} -oN {nmap_output_file}"
        print(colored(f"Running Nmap on {ip} with open ports: {port_str}", 'yellow'))
        run_command_live(nmap_command)

def identify_webservers(ip_ports_map):
    web_ips = set()
    
    print(colored("Identifying web servers...", 'yellow'))
    
    # Check if the IP has web server ports (80, 443, 8080) open
    for ip, ports in ip_ports_map.items():
        if any(port in [80, 443, 8080] for port in ports):
            web_ips.add(ip)

    # Save web servers to the webservers file
    with open(webservers_file, "w") as web_file:
        for ip in web_ips:
            web_file.write(f"{ip}\n")

    return list(web_ips)

def create_urls(web_ips):
    urls = []
    
    print(colored("Generating URLs from IPs...", 'yellow'))
    for ip in web_ips:
        urls.append(f"http://{ip}/")
    
    # Write URLs to a file
    urls_file = os.path.join(temp_dir, "urls.txt")
    with open(urls_file, "w") as file:
        for url in urls:
            file.write(f"{url}\n")
    
    return urls_file

def check_live_websites(urls_file):
    print(colored("Checking live websites with httpx...", 'yellow'))
    
    httpx_command = f"httpx -l {urls_file} -status-code -mc 200,301,302 -o {final_file}"
    run_command_live(httpx_command)

def main(asn_numbers):
    asn_list = asn_numbers.split(',')
    
    # Step 1: Collect IPs from ASN numbers
    ips = scan_asn(asn_list)

    # Step 2: Collect open ports for each IP from Naabu output
    ip_ports_map = collect_ports_for_ips()

    # Step 3: Run Nmap Service Scan with open ports for each IP
    run_nmap_scan(ip_ports_map)

    # Step 4: Identify IPs hosting web servers
    web_ips = identify_webservers(ip_ports_map)

    # Step 5: Create URLs from web server IPs
    urls_file = create_urls(web_ips)

    # Step 6: Run httpx to check live web servers
    check_live_websites(urls_file)

    # Display live web servers
    print(colored("\nLive Web Servers:", GREEN))
    with open(final_file, "r") as file:
        for line in file:
            print(colored(line.strip(), GREEN))

    # Cleanup temporary files
    for temp_file in os.listdir(temp_dir):
        os.remove(os.path.join(temp_dir, temp_file))
    os.rmdir(temp_dir)
    print(colored("\nTemporary files deleted.", RED))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='ASN Enumeration Script')
    parser.add_argument('-a', '--asn', type=str, required=True, help='Comma-separated ASN numbers')

    args = parser.parse_args()
    asn_numbers = args.asn
    main(asn_numbers)

