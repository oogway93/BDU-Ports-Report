package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Scanner struct {
	IPs       []string
	Ports     []int
	StartPort int
	EndPort   int
}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Scan(ipsStr, portsStr string) []ScanResult {
	// Парсинг IP-адресов
	s.IPs = strings.Split(ipsStr, ",")

	// Парсинг диапазона портов
	parts := strings.Split(portsStr, "-")
	if len(parts) != 2 {
		log.Fatal("Неверный формат диапазона портов. Используйте формат: начало-конец")
	}

	var err error
	s.StartPort, err = strconv.Atoi(parts[0])
	if err != nil {
		log.Fatal("Неверный начальный порт:", err)
	}

	s.EndPort, err = strconv.Atoi(parts[1])
	if err != nil {
		log.Fatal("Неверный конечный порт:", err)
	}

	for port := s.StartPort; port <= s.EndPort; port++ {
		s.Ports = append(s.Ports, port)
	}

	var results []ScanResult
	var mutex sync.Mutex
	var wg sync.WaitGroup

	for _, ip := range s.IPs {
		for _, port := range s.Ports {
			wg.Add(1)
			go func(ip string, port int) {
				defer wg.Done()
				result := s.scanPort(ip, port)
				if result.State == "open" {
					mutex.Lock()
					results = append(results, result)
					mutex.Unlock()
				}
			}(ip, port)
		}
	}

	wg.Wait()
	return results
}

func (s *Scanner) scanPort(ip string, port int) ScanResult {
	result := ScanResult{
		IP:   ip,
		Port: port,
	}

	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)

	if err != nil {
		result.State = "closed"
		return result
	}

	defer conn.Close()
	result.State = "open"
	result.Service = s.detectService(port)

	// Получение информации об уязвимостях
	vulnInfo := getVulnerabilityInfo(port, result.Service)
	result.CVEs = vulnInfo.CVEs
	result.MITRE = vulnInfo.MITRE
	result.FSTEC = vulnInfo.FSTEC
	
	// Добавляем пентест-команды
	result.PenTestCommands = getPenTestCommands(port, result.Service, ip)

	return result
}

func (s *Scanner) detectService(port int) string {
	services := map[int]string{
		20:   "FTP-DATA",
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		3306: "MySQL",
		5432: "PostgreSQL",
		8080: "HTTP-Proxy",
		9929: "Nping-echo",
	}

	if service, ok := services[port]; ok {
		return service
	}
	return "unknown"
}

func identifyService(conn net.Conn, port int) string {
	// Comprehensive service identification based on common ports
	switch port {
	// Well-known ports (0-1023)
	case 20, 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 67, 68:
		return "DHCP"
	case 69:
		return "TFTP"
	case 80:
		return "HTTP"
	case 110:
		return "POP3"
	case 123:
		return "NTP"
	case 135:
		return "RPC"
	case 139, 445:
		return "SMB"
	case 143:
		return "IMAP"
	case 161, 162:
		return "SNMP"
	case 389:
		return "LDAP"
	case 443:
		return "HTTPS"
	case 465:
		return "SMTPS"
	case 500:
		return "ISAKMP"
	case 514:
		return "Syslog"
	case 587:
		return "SMTP (Submission)"
	case 636:
		return "LDAPS"
	case 993:
		return "IMAPS"
	case 995:
		return "POP3S"
	case 1080:
		return "SOCKS"
	case 1194:
		return "OpenVPN"
	case 1433, 1434:
		return "MSSQL"
	case 1521:
		return "Oracle"
	case 1723:
		return "PPTP"
	case 2049:
		return "NFS"
	case 2181:
		return "ZooKeeper"
	case 3128:
		return "Squid"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5432:
		return "PostgreSQL"
	case 5900:
		return "VNC"
	case 5938:
		return "TeamViewer"
	case 5984:
		return "CouchDB"
	case 6379:
		return "Redis"
	case 8080:
		return "HTTP Proxy"
	case 8443:
		return "HTTPS Alt"
	case 8888:
		return "HTTP Alt"
	case 9000:
		return "Jenkins"
	case 9090:
		return "HTTP Alt"
	case 9200, 9300:
		return "Elasticsearch"
	case 9929:
		return "Nping-echo"
	case 11211:
		return "Memcached"
	case 27017, 27018, 27019:
		return "MongoDB"
	case 50070, 50075:
		return "Hadoop"
	default:
		// Try to identify service by banner grabbing
		banner := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(time.Second * 2))
		n, err := conn.Read(banner)
		if err == nil && n > 0 {
			return fmt.Sprintf("Unknown (Banner: %s)", string(banner[:n]))
		}
		return "Unknown"
	}
} 