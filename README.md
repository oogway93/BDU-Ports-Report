# BDU Ports Report

# Port Scanner with Vulnerability Intelligence

A Go-based port scanner that incorporates CVE information, MITRE ATT&CK mappings, and FSTEC BDU data into its reports. The tool generates PDF reports and provides a web interface for viewing scan results.

## Features

- Parallel port scanning
- Service identification
- CVE vulnerability lookup
- MITRE ATT&CK framework mapping
- FSTEC BDU vulnerability database integration
- PDF report generation
- Custom port ranges
- Penetration testing recommendations for detected services

## Installation

1. Ensure you have Go 1.21 or newer installed
2. Clone this repository
3. Install dependencies:
```bash
go mod download
```

## Usage
Run the scanner using the following command:
```bash
go run main.go -ips=192.168.1.1 -ports=1-1024 -output=scan_report.pdf
```

## Command-line arguments
- -ips: Comma-separated list of IP addresses to scan (required)
- -ports: Port range to scan (default: 1-1024)
- -output: Output PDF file path (default: scan_report.pdf)

## Results
### The tool generates the result as PDF Report, contains detailed scan:

- IP addresses

- Open ports

- Identified services

- Associated CVEs

- MITRE ATT&CK mappings

- FSTEC BDU information

# Security Notice
This tool is intended for authorized security testing only. Always ensure you have permission to scan target systems.
