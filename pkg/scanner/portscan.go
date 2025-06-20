
package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/sirupsen/logrus"
)

type PortResult struct {
	Port     int    `json:"port"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Banner   string `json:"banner"`
	Version  string `json:"version"`
	Response time.Duration `json:"response_time"`
}

type ScanResult struct {
	Target      string       `json:"target"`
	Ports       []PortResult `json:"ports"`
	OpenPorts   int          `json:"open_ports"`
	ScanTime    time.Duration `json:"scan_time"`
	Stealth     bool         `json:"stealth_mode"`
	Honeypot    bool         `json:"honeypot_detected"`
	Fingerprint string       `json:"os_fingerprint"`
}

type Scanner struct {
	Target       string
	Ports        []int
	Threads      int
	Timeout      time.Duration
	Stealth      bool
	Silent       bool
	BannerGrab   bool
	ServiceScan  bool
	logger       *logrus.Logger
}

func NewScanner(target string, ports []int, options ...func(*Scanner)) *Scanner {
	s := &Scanner{
		Target:      target,
		Ports:       ports,
		Threads:     100,
		Timeout:     time.Second * 3,
		Stealth:     false,
		Silent:      false,
		BannerGrab:  true,
		ServiceScan: true,
		logger:      logrus.New(),
	}

	for _, option := range options {
		option(s)
	}

	if s.Silent {
		s.logger.SetLevel(logrus.WarnLevel)
	}

	return s
}

func WithStealth() func(*Scanner) {
	return func(s *Scanner) {
		s.Stealth = true
	}
}

func WithSilent() func(*Scanner) {
	return func(s *Scanner) {
		s.Silent = true
	}
}

func WithThreads(threads int) func(*Scanner) {
	return func(s *Scanner) {
		s.Threads = threads
	}
}

func WithTimeout(timeout time.Duration) func(*Scanner) {
	return func(s *Scanner) {
		s.Timeout = timeout
	}
}

func (s *Scanner) Scan(ctx context.Context) (*ScanResult, error) {
	startTime := time.Now()
	
	if !s.Silent {
		color.Cyan("🔍 Starting port scan on %s", s.Target)
		color.Yellow("Ports: %d | Threads: %d | Timeout: %v", len(s.Ports), s.Threads, s.Timeout)
		if s.Stealth {
			color.Green("🥷 Stealth mode enabled")
		}
	}

	if err := s.validateTarget(); err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	honeypotDetected := s.detectHoneypot(ctx)
	if honeypotDetected && !s.Silent {
		color.Red("⚠️  Possible honeypot detected! Proceeding with extra caution...")
	}

	ports := make([]int, len(s.Ports))
	copy(ports, s.Ports)
	if s.Stealth {
		s.randomizePorts(ports)
	}

	semaphore := make(chan struct{}, s.Threads)
	results := make(chan PortResult, len(ports))
	var wg sync.WaitGroup

	var bar *progressbar.ProgressBar
	if !s.Silent {
		bar = progressbar.NewOptions(len(ports),
			progressbar.OptionSetDescription("Scanning ports"),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "█",
				SaucerHead:    "█",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
		)
	}

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if s.Stealth {
				time.Sleep(s.getJitterDelay())
			}

			result := s.scanPort(ctx, p)
			results <- result

			if !s.Silent && bar != nil {
				bar.Add(1)
			}
		}(port)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var portResults []PortResult
	for result := range results {
		portResults = append(portResults, result)
	}

	sort.Slice(portResults, func(i, j int) bool {
		return portResults[i].Port < portResults[j].Port
	})

	openPorts := 0
	for _, result := range portResults {
		if result.State == "open" {
			openPorts++
		}
	}

	scanResult := &ScanResult{
		Target:      s.Target,
		Ports:       portResults,
		OpenPorts:   openPorts,
		ScanTime:    time.Since(startTime),
		Stealth:     s.Stealth,
		Honeypot:    honeypotDetected,
		Fingerprint: s.generateFingerprint(portResults),
	}

	if !s.Silent {
		s.printResults(scanResult)
	}

	return scanResult, nil
}

func (s *Scanner) scanPort(ctx context.Context, port int) PortResult {
	result := PortResult{
		Port:  port,
		State: "closed",
	}

	start := time.Now()
	address := net.JoinHostPort(s.Target, strconv.Itoa(port))
	
	scanCtx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(scanCtx, "tcp", address)
	
	result.Response = time.Since(start)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.State = "filtered"
		} else {
			result.State = "closed"
		}
		return result
	}

	defer conn.Close()
	result.State = "open"

	if s.ServiceScan {
		result.Service = s.detectService(port)
	}

	if s.BannerGrab {
		banner, version := s.grabBanner(conn, port)
		result.Banner = banner
		result.Version = version
	}

	return result
}

func (s *Scanner) detectService(port int) string {
	commonPorts := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		139:  "netbios",
		143:  "imap",
		443:  "https",
		993:  "imaps",
		995:  "pop3s",
		1433: "mssql",
		3306: "mysql",
		3389: "rdp",
		5432: "postgresql",
		6379: "redis",
		27017: "mongodb",
	}

	if service, exists := commonPorts[port]; exists {
		return service
	}
	return "unknown"
}

func (s *Scanner) grabBanner(conn net.Conn, port int) (string, string) {
	conn.SetReadDeadline(time.Now().Add(time.Second * 2))
	
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		if port == 80 || port == 443 || port == 8080 {
			return s.grabHTTPBanner(conn)
		}
		return "", ""
	}

	banner := strings.TrimSpace(string(buffer[:n]))
	version := s.extractVersion(banner)
	
	return banner, version
}

func (s *Scanner) grabHTTPBanner(conn net.Conn) (string, string) {
	request := "HEAD / HTTP/1.1\r\nHost: " + s.Target + "\r\n\r\n"
	conn.Write([]byte(request))
	
	conn.SetReadDeadline(time.Now().Add(time.Second * 2))
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", ""
	}

	response := string(buffer[:n])
	lines := strings.Split(response, "\r\n")
	
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			server := strings.TrimSpace(line[7:])
			version := s.extractVersion(server)
			return server, version
		}
	}

	return response, ""
}

func (s *Scanner) extractVersion(banner string) string {
	for _, _ = range []string{`(\d+\.\d+\.\d+)`, `(\d+\.\d+)`, `v(\d+\.\d+)`} {
		if strings.Contains(banner, ".") {
			words := strings.Fields(banner)
			for _, word := range words {
				if strings.Contains(word, ".") && len(word) < 20 {
					return word
				}
			}
		}
	}

	return ""
}

func (s *Scanner) validateTarget() error {
	_, err := net.LookupHost(s.Target)
	return err
}

func (s *Scanner) detectHoneypot(ctx context.Context) bool {
	testPorts := []int{21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 1723, 3389, 5900}
	openCount := 0
	
	for _, port := range testPorts {
		if openCount > 10 {
			break
		}
		
		address := net.JoinHostPort(s.Target, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", address, time.Millisecond*500)
		if err == nil {
			conn.Close()
			openCount++
		}
	}

	return float64(openCount)/float64(len(testPorts)) > 0.8
}

func (s *Scanner) randomizePorts(ports []int) {
	for i := len(ports) - 1; i > 0; i-- {
		j := int(time.Now().UnixNano()) % (i + 1)
		ports[i], ports[j] = ports[j], ports[i]
	}
}

func (s *Scanner) getJitterDelay() time.Duration {
	base := 50 * time.Millisecond
	jitter := time.Duration(time.Now().UnixNano()%int64(100*time.Millisecond))
	return base + jitter
}

func (s *Scanner) generateFingerprint(results []PortResult) string {
	var signature []string

	for _, result := range results {
		if result.State == "open" {
			signature = append(signature, fmt.Sprintf("%d/%s", result.Port, result.Service))
		}
	}

	hasSSH := false
	hasRDP := false

	for _, result := range results {
		switch result.Service {
		case "ssh":
			hasSSH = true
		case "rdp":
			hasRDP = true
		}
	}

	os := "unknown"
	if hasSSH && !hasRDP {
		os = "linux"
	} else if hasRDP {
		os = "windows"
	}

	return fmt.Sprintf("OS:%s Ports:%s", os, strings.Join(signature, ","))
}

func (s *Scanner) printResults(result *ScanResult) {
	fmt.Println()
	color.Green("📊 Scan Results for %s", result.Target)
	color.White("=" + strings.Repeat("=", 50))
	
	if result.Honeypot {
		color.Red("⚠️  HONEYPOT DETECTED!")
	}

	color.Cyan("Open Ports: %d/%d", result.OpenPorts, len(result.Ports))
	color.Cyan("Scan Time: %v", result.ScanTime)
	color.Cyan("Fingerprint: %s", result.Fingerprint)

	fmt.Println()
	fmt.Printf("%-6s %-10s %-12s %-30s %s\n", "PORT", "STATE", "SERVICE", "VERSION", "BANNER")
	fmt.Println(strings.Repeat("-", 80))

	for _, port := range result.Ports {
		if port.State == "open" {
			stateColor := color.GreenString(port.State)
			banner := port.Banner
			if len(banner) > 30 {
				banner = banner[:27] + "..."
			}
			fmt.Printf("%-6d %-10s %-12s %-30s %s\n", 
				port.Port, stateColor, port.Service, port.Version, banner)
		}
	}
}

func ParsePortRange(portRange string) ([]int, error) {
	var ports []int

	ranges := strings.Split(portRange, ",")
	for _, r := range ranges {
		if strings.Contains(r, "-") {
			parts := strings.Split(r, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", r)
			}

			start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", parts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", parts[1])
			}

			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			port, err := strconv.Atoi(strings.TrimSpace(r))
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", r)
			}
			ports = append(ports, port)
		}
	}

	return ports, nil
}

func CommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
		1723, 3306, 3389, 5900, 8080, 8443, 8888,
	}
}

func TopPorts() []int {
	return []int{
		1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000,
	}
}