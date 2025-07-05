package main

// ScanResult represents the result of a port scan
type ScanResult struct {
	IP              string
	Port            int
	State           string
	Service         string
	CVEs            []CVEInfo
	MITRE           []MITREInfo
	FSTEC           []FSTECInfo
	PenTestCommands []string
} 