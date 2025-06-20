package services

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type ServiceProfile struct {
	Host           string            `json:"host"`
	Port           int               `json:"port"`
	Protocol       string            `json:"protocol"`
	Service        string            `json:"service"`
	Product        string            `json:"product"`
	Version        string            `json:"version"`
	ExtraInfo      string            `json:"extra_info"`
	OS             string            `json:"os"`
	DeviceType     string            `json:"device_type"`
	Banner         string            `json:"banner"`
	Headers        map[string]string `json:"headers"`
	Fingerprint    string            `json:"fingerprint"`
	Confidence     float64           `json:"confidence"`
	CVEs           []CVE             `json:"cves"`
	Exploitable    bool              `json:"exploitable"`
	RiskScore      int               `json:"risk_score"`
	LastSeen       time.Time         `json:"last_seen"`
	ResponseTime   time.Duration     `json:"response_time"`
	TLSInfo        *TLSInfo          `json:"tls_info,omitempty"`
	HTTPInfo       *HTTPInfo         `json:"http_info,omitempty"`
	SMBInfo        *SMBInfo          `json:"smb_info,omitempty"`
	SSHInfo        *SSHInfo          `json:"ssh_info,omitempty"`
	FTPInfo        *FTPInfo          `json:"ftp_info,omitempty"`
}

type CVE struct {
	ID          string    `json:"id"`
	Severity    string    `json:"severity"`
	Score       float64   `json:"score"`
	Description string    `json:"description"`
	Exploitable bool      `json:"exploitable"`
	Published   time.Time `json:"published"`
	ExploitURL  string    `json:"exploit_url,omitempty"`
}

type TLSInfo struct {
	Version      string    `json:"version"`
	CipherSuite  string    `json:"cipher_suite"`
	Certificate  *CertInfo `json:"certificate"`
	Vulnerable   bool      `json:"vulnerable"`
	WeakCiphers  []string  `json:"weak_ciphers"`
	Protocols    []string  `json:"protocols"`
}

type CertInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	Serial       string    `json:"serial"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	SelfSigned   bool      `json:"self_signed"`
	Expired      bool      `json:"expired"`
	KeyAlgorithm string    `json:"key_algorithm"`
	Signature    string    `json:"signature"`
}

type HTTPInfo struct {
	StatusCode    int               `json:"status_code"`
	Server        string            `json:"server"`
	PoweredBy     string            `json:"powered_by"`
	ContentType   string            `json:"content_type"`
	ContentLength int64             `json:"content_length"`
	Headers       map[string]string `json:"headers"`
	Title         string            `json:"title"`
	Technologies  []string          `json:"technologies"`
	Cookies       []string          `json:"cookies"`
	Redirects     []string          `json:"redirects"`
	Forms         []FormInfo        `json:"forms"`
	AuthRequired  bool              `json:"auth_required"`
	HTTPS         bool              `json:"https"`
}

type FormInfo struct {
	Action string            `json:"action"`
	Method string            `json:"method"`
	Inputs map[string]string `json:"inputs"`
}

type SMBInfo struct {
	OS           string   `json:"os"`
	Domain       string   `json:"domain"`
	Workgroup    string   `json:"workgroup"`
	ComputerName string   `json:"computer_name"`
	Shares       []string `json:"shares"`
	Signing      bool     `json:"signing"`
	NullSession  bool     `json:"null_session"`
	Dialect      string   `json:"dialect"`
	Version      string   `json:"version"`
}

type SSHInfo struct {
	Protocol       string   `json:"protocol"`
	Software       string   `json:"software"`
	KexAlgorithms  []string `json:"kex_algorithms"`
	HostKeyTypes   []string `json:"host_key_types"`
	Encryption     []string `json:"encryption"`
	MAC            []string `json:"mac"`
	Compression    []string `json:"compression"`
	AuthMethods    []string `json:"auth_methods"`
	WeakAlgorithms []string `json:"weak_algorithms"`
}

type FTPInfo struct {
	Banner         string `json:"banner"`
	Software       string `json:"software"`
	Anonymous      bool   `json:"anonymous"`
	Directory      string `json:"directory"`
	Writable       bool   `json:"writable"`
	TLS            bool   `json:"tls"`
	PassiveMode    bool   `json:"passive_mode"`
	Features       []string `json:"features"`
}

type VersionScanner struct {
	timeout    time.Duration
	threads    int
	aggressive bool
	logger     *logrus.Logger
	mutex      sync.RWMutex
	profiles   []*ServiceProfile
	patterns   map[string][]*Pattern
	cveDB      map[string][]CVE
}

type Pattern struct {
	Service     string
	Product     string
	VersionRegex *regexp.Regexp
	BannerRegex  *regexp.Regexp
	Confidence   float64
	Fingerprint  string
}

func NewVersionScanner() *VersionScanner {
	vs := &VersionScanner{
		timeout:  time.Second * 10,
		threads:  20,
		logger:   logrus.New(),
		profiles: make([]*ServiceProfile, 0),
		patterns: make(map[string][]*Pattern),
		cveDB:    make(map[string][]CVE),
	}

	vs.initializePatterns()
	vs.loadCVEDatabase()

	return vs
}

func (vs *VersionScanner) initializePatterns() {
	vs.patterns["http"] = []*Pattern{
		{
			Service:      "http",
			Product:      "Apache",
			VersionRegex: regexp.MustCompile(`Apache[/\s]([\d\.]+)`),
			BannerRegex:  regexp.MustCompile(`(?i)server:\s*apache`),
			Confidence:   0.9,
			Fingerprint:  "apache_httpd",
		},
		{
			Service:      "http",
			Product:      "nginx",
			VersionRegex: regexp.MustCompile(`nginx[/\s]([\d\.]+)`),
			BannerRegex:  regexp.MustCompile(`(?i)server:\s*nginx`),
			Confidence:   0.9,
			Fingerprint:  "nginx",
		},
		{
			Service:      "http",
			Product:      "IIS",
			VersionRegex: regexp.MustCompile(`Microsoft-IIS[/\s]([\d\.]+)`),
			BannerRegex:  regexp.MustCompile(`(?i)server:\s*microsoft-iis`),
			Confidence:   0.9,
			Fingerprint:  "microsoft_iis",
		},
	}

	vs.patterns["ssh"] = []*Pattern{
		{
			Service:      "ssh",
			Product:      "OpenSSH",
			VersionRegex: regexp.MustCompile(`OpenSSH[_\s]([\d\.]+[\w]*)`),
			BannerRegex:  regexp.MustCompile(`SSH-[\d\.]+-OpenSSH`),
			Confidence:   0.95,
			Fingerprint:  "openssh",
		},
		{
			Service:      "ssh",
			Product:      "Dropbear",
			VersionRegex: regexp.MustCompile(`dropbear[_\s]([\d\.]+)`),
			BannerRegex:  regexp.MustCompile(`SSH-[\d\.]+-dropbear`),
			Confidence:   0.9,
			Fingerprint:  "dropbear_ssh",
		},
	}

	vs.patterns["ftp"] = []*Pattern{
		{
			Service:      "ftp",
			Product:      "vsftpd",
			VersionRegex: regexp.MustCompile(`vsftpd\s([\d\.]+)`),
			BannerRegex:  regexp.MustCompile(`220.*vsftpd`),
			Confidence:   0.9,
			Fingerprint:  "vsftpd",
		},
		{
			Service:      "ftp",
			Product:      "ProFTPD",
			VersionRegex: regexp.MustCompile(`ProFTPD\s([\d\.]+)`),
			BannerRegex:  regexp.MustCompile(`220.*ProFTPD`),
			Confidence:   0.9,
			Fingerprint:  "proftpd",
		},
	}

	vs.patterns["smtp"] = []*Pattern{
		{
			Service:      "smtp",
			Product:      "Postfix",
			VersionRegex: regexp.MustCompile(`Postfix\s([\d\.]+)`),
			BannerRegex:  regexp.MustCompile(`220.*Postfix`),
			Confidence:   0.9,
			Fingerprint:  "postfix",
		},
		{
			Service:      "smtp",
			Product:      "Sendmail",
			VersionRegex: regexp.MustCompile(`Sendmail\s([\d\.]+)`),
			BannerRegex:  regexp.MustCompile(`220.*Sendmail`),
			Confidence:   0.9,
			Fingerprint:  "sendmail",
		},
	}

	vs.patterns["mysql"] = []*Pattern{
		{
			Service:      "mysql",
			Product:      "MySQL",
			VersionRegex: regexp.MustCompile(`([\d\.]+)-`),
			BannerRegex:  regexp.MustCompile(`mysql_native_password`),
			Confidence:   0.8,
			Fingerprint:  "mysql",
		},
	}
}

func (vs *VersionScanner) loadCVEDatabase() {
	vs.cveDB["apache_httpd"] = []CVE{
		{
			ID:          "CVE-2021-44228",
			Severity:    "CRITICAL",
			Score:       10.0,
			Description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
			Exploitable: true,
			Published:   time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC),
			ExploitURL:  "https://github.com/kozmer/log4j-shell-poc",
		},
		{
			ID:          "CVE-2021-42013",
			Severity:    "CRITICAL",
			Score:       9.8,
			Description: "Apache HTTP Server 2.4.49 and 2.4.50 Path Traversal",
			Exploitable: true,
			Published:   time.Date(2021, 10, 7, 0, 0, 0, 0, time.UTC),
		},
	}

	vs.cveDB["openssh"] = []CVE{
		{
			ID:          "CVE-2020-14145",
			Severity:    "MEDIUM",
			Score:       5.9,
			Description: "OpenSSH 7.9 Information Disclosure",
			Exploitable: false,
			Published:   time.Date(2020, 6, 29, 0, 0, 0, 0, time.UTC),
		},
	}

	vs.cveDB["nginx"] = []CVE{
		{
			ID:          "CVE-2021-23017",
			Severity:    "HIGH",
			Score:       7.7,
			Description: "nginx DNS resolver off-by-one heap write",
			Exploitable: true,
			Published:   time.Date(2021, 5, 25, 0, 0, 0, 0, time.UTC),
		},
	}
}

func (vs *VersionScanner) ScanService(host string, port int, protocol string) *ServiceProfile {
	profile := &ServiceProfile{
		Host:         host,
		Port:         port,
		Protocol:     protocol,
		Headers:      make(map[string]string),
		LastSeen:     time.Now(),
		CVEs:         make([]CVE, 0),
	}

	start := time.Now()

	switch strings.ToLower(protocol) {
	case "tcp":
		vs.scanTCPService(profile)
	case "http", "https":
		vs.scanHTTPService(profile)
	case "ssh":
		vs.scanSSHService(profile)
	case "ftp":
		vs.scanFTPService(profile)
	case "smtp":
		vs.scanSMTPService(profile)
	case "mysql":
		vs.scanMySQLService(profile)
	case "smb":
		vs.scanSMBService(profile)
	default:
		vs.scanGenericService(profile)
	}

	profile.ResponseTime = time.Since(start)
	vs.identifyService(profile)
	vs.findVulnerabilities(profile)
	vs.calculateRiskScore(profile)

	return profile
}

func (vs *VersionScanner) scanTCPService(profile *ServiceProfile) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", profile.Host, profile.Port), vs.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	banner := vs.grabBanner(conn)
	profile.Banner = banner
	profile.Service = vs.detectServiceFromBanner(banner, profile.Port)
}

func (vs *VersionScanner) scanHTTPService(profile *ServiceProfile) {
	scheme := "http"
	if profile.Port == 443 || profile.Port == 8443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, profile.Host, profile.Port)
	client := &http.Client{
		Timeout: vs.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	profile.Service = "http"
	httpInfo := &HTTPInfo{
		StatusCode:  resp.StatusCode,
		Headers:     make(map[string]string),
		HTTPS:       scheme == "https",
		AuthRequired: resp.StatusCode == 401,
	}

	for k, v := range resp.Header {
		if len(v) > 0 {
			httpInfo.Headers[k] = v[0]
			profile.Headers[k] = v[0]
		}
	}

	if server := resp.Header.Get("Server"); server != "" {
		httpInfo.Server = server
		profile.Banner = server
	}

	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		httpInfo.PoweredBy = powered
	}

	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		httpInfo.ContentType = contentType
	}

	httpInfo.ContentLength = resp.ContentLength
	profile.HTTPInfo = httpInfo

	if scheme == "https" {
		vs.scanTLSInfo(profile)
	}
}

func (vs *VersionScanner) scanSSHService(profile *ServiceProfile) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", profile.Host, profile.Port), vs.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	banner := vs.grabBanner(conn)
	profile.Banner = banner
	profile.Service = "ssh"

	sshInfo := &SSHInfo{
		Protocol: "SSH-2.0",
	}

	if strings.Contains(banner, "OpenSSH") {
		sshInfo.Software = "OpenSSH"
		if matches := regexp.MustCompile(`OpenSSH[_\s]([\d\.]+[\w]*)`).FindStringSubmatch(banner); len(matches) > 1 {
			profile.Version = matches[1]
			profile.Product = "OpenSSH"
		}
	}

	profile.SSHInfo = sshInfo
}

func (vs *VersionScanner) scanFTPService(profile *ServiceProfile) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", profile.Host, profile.Port), vs.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	banner := vs.grabBanner(conn)
	profile.Banner = banner
	profile.Service = "ftp"

	ftpInfo := &FTPInfo{
		Banner: banner,
	}

	if strings.Contains(banner, "vsftpd") {
		ftpInfo.Software = "vsftpd"
		if matches := regexp.MustCompile(`vsftpd\s([\d\.]+)`).FindStringSubmatch(banner); len(matches) > 1 {
			profile.Version = matches[1]
			profile.Product = "vsftpd"
		}
	}

	ftpInfo.Anonymous = vs.testFTPAnonymous(profile.Host, profile.Port)
	profile.FTPInfo = ftpInfo
}

func (vs *VersionScanner) scanSMTPService(profile *ServiceProfile) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", profile.Host, profile.Port), vs.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	banner := vs.grabBanner(conn)
	profile.Banner = banner
	profile.Service = "smtp"

	if strings.Contains(banner, "Postfix") {
		profile.Product = "Postfix"
		if matches := regexp.MustCompile(`Postfix\s([\d\.]+)`).FindStringSubmatch(banner); len(matches) > 1 {
			profile.Version = matches[1]
		}
	}
}

func (vs *VersionScanner) scanMySQLService(profile *ServiceProfile) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", profile.Host, profile.Port), vs.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	n, err := conn.Read(buffer)
	if err != nil {
		return
	}

	data := string(buffer[:n])
	profile.Banner = data
	profile.Service = "mysql"
	profile.Product = "MySQL"

	if len(data) > 10 {
		version := vs.extractMySQLVersion(data)
		if version != "" {
			profile.Version = version
		}
	}
}

func (vs *VersionScanner) scanSMBService(profile *ServiceProfile) {
	profile.Service = "smb"
	profile.Product = "Microsoft SMB"

	smbInfo := &SMBInfo{
		OS:      "Windows",
		Dialect: "SMB",
	}

	profile.SMBInfo = smbInfo
}

func (vs *VersionScanner) scanTLSInfo(profile *ServiceProfile) {
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", profile.Host, profile.Port), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	tlsInfo := &TLSInfo{
		Version:     vs.getTLSVersion(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		Protocols:   make([]string, 0),
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		tlsInfo.Certificate = &CertInfo{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			Serial:       cert.SerialNumber.String(),
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			SelfSigned:   cert.Subject.String() == cert.Issuer.String(),
			Expired:      time.Now().After(cert.NotAfter),
			KeyAlgorithm: cert.PublicKeyAlgorithm.String(),
			Signature:    cert.SignatureAlgorithm.String(),
		}
	}

	profile.TLSInfo = tlsInfo
}

func (vs *VersionScanner) scanGenericService(profile *ServiceProfile) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", profile.Host, profile.Port), vs.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	banner := vs.grabBanner(conn)
	profile.Banner = banner
	profile.Service = vs.detectServiceFromPort(profile.Port)
}

func (vs *VersionScanner) grabBanner(conn net.Conn) string {
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(buffer[:n]))
}

func (vs *VersionScanner) detectServiceFromBanner(banner string, port int) string {
	banner = strings.ToLower(banner)

	servicePatterns := map[string][]string{
		"ssh":   {"ssh-", "openssh", "dropbear"},
		"http":  {"http/", "server:", "apache", "nginx", "iis"},
		"ftp":   {"220", "ftp", "vsftpd", "proftpd"},
		"smtp":  {"220", "esmtp", "postfix", "sendmail"},
		"pop3":  {"+ok", "pop3"},
		"imap":  {"* ok", "imap"},
		"mysql": {"mysql_native_password", "\x00\x00\x00"},
		"smb":   {"smb", "cifs"},
	}

	for service, patterns := range servicePatterns {
		for _, pattern := range patterns {
			if strings.Contains(banner, pattern) {
				return service
			}
		}
	}

	return vs.detectServiceFromPort(port)
}

func (vs *VersionScanner) detectServiceFromPort(port int) string {
	portMap := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		143:  "imap",
		443:  "https",
		993:  "imaps",
		995:  "pop3s",
		3306: "mysql",
		5432: "postgresql",
		6379: "redis",
		8080: "http",
		8443: "https",
	}

	if service, exists := portMap[port]; exists {
		return service
	}

	return "unknown"
}

func (vs *VersionScanner) identifyService(profile *ServiceProfile) {
	if patterns, exists := vs.patterns[profile.Service]; exists {
		for _, pattern := range patterns {
			if pattern.BannerRegex.MatchString(profile.Banner) {
				profile.Product = pattern.Product
				profile.Fingerprint = pattern.Fingerprint
				profile.Confidence = pattern.Confidence

				if matches := pattern.VersionRegex.FindStringSubmatch(profile.Banner); len(matches) > 1 {
					profile.Version = matches[1]
				}
				break
			}
		}
	}
}

func (vs *VersionScanner) findVulnerabilities(profile *ServiceProfile) {
	if cves, exists := vs.cveDB[profile.Fingerprint]; exists {
		for _, cve := range cves {
			if vs.isVersionVulnerable(profile.Version, cve) {
				profile.CVEs = append(profile.CVEs, cve)
				if cve.Exploitable {
					profile.Exploitable = true
				}
			}
		}
	}
}

func (vs *VersionScanner) isVersionVulnerable(version string, cve CVE) bool {
	return true
}

func (vs *VersionScanner) calculateRiskScore(profile *ServiceProfile) {
	score := 0

	for _, cve := range profile.CVEs {
		switch cve.Severity {
		case "CRITICAL":
			score += 10
		case "HIGH":
			score += 7
		case "MEDIUM":
			score += 4
		case "LOW":
			score += 1
		}
	}

	if profile.Exploitable {
		score += 15
	}

	if profile.Service == "ssh" && profile.Port == 22 {
		score += 2
	}

	if profile.HTTPInfo != nil && profile.HTTPInfo.AuthRequired {
		score -= 3
	}

	profile.RiskScore = score
}

func (vs *VersionScanner) testFTPAnonymous(host string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), time.Second*5)
	if err != nil {
		return false
	}
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return false
	}

	fmt.Fprintf(conn, "USER anonymous\r\n")
	if !scanner.Scan() {
		return false
	}

	response := scanner.Text()
	return strings.HasPrefix(response, "331") || strings.HasPrefix(response, "230")
}

func (vs *VersionScanner) extractMySQLVersion(data string) string {
	if len(data) < 10 {
		return ""
	}

	version := ""
	for i := 5; i < len(data) && i < 15; i++ {
		if data[i] == 0 {
			break
		}
		version += string(data[i])
	}

	return version
}

func (vs *VersionScanner) getTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

func (vs *VersionScanner) GetProfiles() []*ServiceProfile {
	vs.mutex.RLock()
	defer vs.mutex.RUnlock()
	return vs.profiles
}

func (vs *VersionScanner) AddProfile(profile *ServiceProfile) {
	vs.mutex.Lock()
	defer vs.mutex.Unlock()
	vs.profiles = append(vs.profiles, profile)
}