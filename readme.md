# ASN Enumeration and Web Server Detection Script

This script automates the process of enumerating ASN (Autonomous System Number) IP addresses, scanning for open ports, identifying web servers, and performing service scans. The results are displayed in real-time and written to output files for further analysis.

## Features

- **ASN Enumeration**: Uses `asnmap` to enumerate IP addresses for the given ASN numbers.
- **Port Scanning**: Utilizes `naabu` to scan for open ports on the enumerated IP addresses and parse the results in JSON format.
- **Nmap Service Scanning**: Dynamically runs Nmap to perform service scans on the open ports found by `naabu` for each IP address.
- **Web Server Identification**: Identifies IP addresses hosting web servers by checking if ports 80, 443, or 8080 are open.
- **Live Website Detection**: Generates URLs from IP addresses and uses `httpx` to check if the websites are live, filtering responses with status codes 200, 301, or 302.
- **Real-Time Output**: Displays the output of all commands (asnmap, naabu, nmap, httpx) in real-time for better visibility into the scanning process.
- **Color-Coded Results**: Uses color coding to highlight important information, such as live web servers.
- **Automatic Cleanup**: Deletes all temporary files created during the process, retaining only the Nmap scan results and a list of live web servers.

## Requirements

- Python 3.x
- Tools used in the script:
  - `asnmap`
  - `naabu`
  - `nmap`
  - `httpx`
- Python packages:
  - `argparse`
  - `subprocess`
  - `json`
  - `termcolor`

## Usage 
`python asn_enum.py -a <ASN NUM>(comma separated)`
