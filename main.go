package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
)

type Rep struct {
	IP        string
	StartPort int
	EndPort   int
	StartTime string
	Status    string
	Results   []ScanResult
}

func main() {
	// Command-line flag parsing
	var (
		ips    = flag.String("ips", "", "IP address(es) to scan (comma-separated)")
		ports  = flag.String("ports", "", "Port range (e.g., 80-1000)")
		output = flag.String("output", "scan_report.pdf", "Path to save the PDF report")
	)
	flag.Parse()

	if *ips == "" || *ports == ""  {
		fmt.Println("Using: go run . -ips=192.168.1.1 -ports=80-1000 -output=report.pdf")
		flag.PrintDefaults()
		return
	}

	// Creating and starting the scanner
	scanner := NewScanner()
	ipList := strings.Split(*ips, ",")
	fmt.Printf("Starting scan of %d IPs and %d ports...\n", len(ipList), scanner.EndPort-scanner.StartPort+1)
	results := scanner.Scan(*ips, *ports)

	// Generating PDF report
	fmt.Printf("Generating PDF report: %s\n", *output)
	if err := generatePDFReport(results, *output); err != nil {
		log.Printf("Error in creating PDF file: %v", err)
	}
}
