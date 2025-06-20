package mobile

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type DeviceType string

const (
	TypeMobile    DeviceType = "mobile"
	TypeIoT       DeviceType = "iot"
	TypeEmbedded  DeviceType = "embedded"
	TypeIndustrial DeviceType = "industrial"
	TypeSmartHome DeviceType = "smarthome"
	TypeWearable  DeviceType = "wearable"
)

type MobileDevice struct {
	IP           string            `json:"ip"`
	Port         int               `json:"port"`
	Service      string            `json:"service"`
	DeviceType   DeviceType        `json:"device_type"`
	Vendor       string            `json:"vendor"`
	Model        string            `json:"model"`
	Version      string            `json:"version"`
	OS           string            `json:"os"`
	Protocol     string            `json:"protocol"`
	Banner       string            `json:"banner"`
	Headers      map[string]string `json:"headers"`
	Authentication string          `json:"authentication"`
	Encryption   string            `json:"encryption"`
	Vulnerable   bool              `json:"vulnerable"`
	Exploitable  []string          `json:"exploitable"`
	Risk         string            `json:"risk"`
	Discovered   time.Time         `json:"discovered"`
}

type MobileScanner struct {
	target         string
	portRange      string
	timeout        time.Duration
	threads        int
	aggressive     bool
	client         *http.Client
	logger         *logrus.Logger
	mutex          sync.RWMutex
	devices        []*MobileDevice
	serviceProbes  map[string][]string
	deviceSignatures map[string]DeviceSignature
	vulnChecks     map[string]VulnCheck
}

type DeviceSignature struct {
	Type    DeviceType
	Vendor  string
	Model   string
	Patterns []string
}

type VulnCheck struct {
	Name        string
	Payload     string
	Expected    string
	Risk        string
	Exploitable []string
}

func NewMobileScanner(target string, options ...func(*MobileScanner)) *MobileScanner {
	ms := &MobileScanner{
		target:    target,
		portRange: "1-65535",
		timeout:   time.Second * 5,
		threads:   50,
		aggressive: false,
		logger:    logrus.New(),
		devices:   make([]*MobileDevice, 0),
	}

	ms.client = &http.Client{
		Timeout: ms.timeout,
	}

	for _, option := range options {
		option(ms)
	}

	ms.initializeServiceProbes()
	ms.initializeDeviceSignatures()
	ms.initializeVulnChecks()

	return ms
}

func WithPortRange(portRange string) func(*MobileScanner) {
	return func(ms *MobileScanner) {
		ms.portRange = portRange
	}
}

func WithThreads(threads int) func(*MobileScanner) {
	return func(ms *MobileScanner) {
		ms.threads = threads
	}
}

func WithAggressive() func(*MobileScanner) {
	return func(ms *MobileScanner) {
		ms.aggressive = true
	}
}

func (ms *MobileScanner) initializeServiceProbes() {
	ms.serviceProbes = map[string][]string{
		"http": {
			"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
			"GET /admin HTTP/1.1\r\nHost: %s\r\n\r\n",
			"GET /config HTTP/1.1\r\nHost: %s\r\n\r\n",
		},
		"telnet": {
			"\xFF\xFD\x18\xFF\xFD\x20\xFF\xFD\x23\xFF\xFD\x27",
		},
		"ssh": {
			"SSH-2.0-OpenSSH_7.4\r\n",
		},
		"ftp": {
			"USER anonymous\r\n",
			"PASS guest\r\n",
		},
		"snmp": {
			"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04",
		},
		"mqtt": {
			"\x10\x0e\x00\x04MQTT\x04\x02\x00\x3c\x00\x00",
		},
		"coap": {
			"\x40\x01\x00\x00", // CoAP GET request
		},
		"modbus": {
			"\x00\x00\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01",
		},
	}
}

func (ms *MobileScanner) initializeDeviceSignatures() {
	ms.deviceSignatures = map[string]DeviceSignature{
		"android": {
			Type:   TypeMobile,
			Vendor: "Google",
			Model:  "Android",
			Patterns: []string{"Android", "Dalvik", "okhttp"},
		},
		"ios": {
			Type:   TypeMobile,
			Vendor: "Apple",
			Model:  "iOS",
			Patterns: []string{"iPhone", "iPad", "iOS", "CFNetwork"},
		},
		"router": {
			Type:   TypeIoT,
			Vendor: "Generic",
			Model:  "Router",
			Patterns: []string{"router", "gateway", "DD-WRT", "OpenWrt"},
		},
		"camera": {
			Type:   TypeIoT,
			Vendor: "Generic",
			Model:  "IP Camera",
			Patterns: []string{"camera", "webcam", "ipcam", "surveillance"},
		},
		"printer": {
			Type:   TypeIoT,
			Vendor: "Generic",
			Model:  "Network Printer",
			Patterns: []string{"printer", "print", "cups", "ipp"},
		},
		"smarttv": {
			Type:   TypeSmartHome,
			Vendor: "Generic",
			Model:  "Smart TV",
			Patterns: []string{"SmartTV", "webOS", "Tizen", "AndroidTV"},
		},
		"alexa": {
			Type:   TypeSmartHome,
			Vendor: "Amazon",
			Model:  "Echo",
			Patterns: []string{"echo", "alexa", "amazon"},
		},
		"nest": {
			Type:   TypeSmartHome,
			Vendor: "Google",
			Model:  "Nest",
			Patterns: []string{"nest", "thermostat"},
		},
		"arduino": {
			Type:   TypeEmbedded,
			Vendor: "Arduino",
			Model:  "Board",
			Patterns: []string{"arduino", "esp8266", "esp32"},
		},
		"raspberry": {
			Type:   TypeEmbedded,
			Vendor: "Raspberry Pi",
			Model:  "Pi",
			Patterns: []string{"raspberry", "raspbian"},
		},
		"plc": {
			Type:   TypeIndustrial,
			Vendor: "Generic",
			Model:  "PLC",
			Patterns: []string{"plc", "scada", "modbus", "siemens"},
		},
	}
}

func (ms *MobileScanner) initializeVulnChecks() {
	ms.vulnChecks = map[string]VulnCheck{
		"default_creds": {
			Name:        "Default Credentials",
			Payload:     "admin:admin",
			Expected:    "200",
			Risk:        "HIGH",
			Exploitable: []string{"Unauthorized access", "Device takeover"},
		},
		"no_auth": {
			Name:        "No Authentication",
			Payload:     "GET /config",
			Expected:    "200",
			Risk:        "CRITICAL",
			Exploitable: []string{"Configuration access", "Sensitive data exposure"},
		},
		"weak_ssl": {
			Name:        "Weak SSL/TLS",
			Payload:     "SSLv3",
			Expected:    "accept",
			Risk:        "MEDIUM",
			Exploitable: []string{"Man-in-the-middle", "Data interception"},
		},
		"open_telnet": {
			Name:        "Open Telnet",
			Payload:     "telnet",
			Expected:    "prompt",
			Risk:        "HIGH",
			Exploitable: []string{"Remote access", "Command execution"},
		},
		"mqtt_open": {
			Name:        "Open MQTT",
			Payload:     "mqtt_connect",
			Expected:    "connack",
			Risk:        "MEDIUM",
			Exploitable: []string{"Message interception", "Device manipulation"},
		},
	}
}

func (ms *MobileScanner) Scan(ctx context.Context) ([]*MobileDevice, error) {
	ms.logger.Infof("📱 Starting mobile/IoT device scan of %s", ms.target)

	// Phase 1: Port scanning and service detection
	ms.scanPorts(ctx)

	// Phase 2: Service fingerprinting
	ms.fingerprintServices(ctx)

	// Phase 3: Device classification
	ms.classifyDevices()

	// Phase 4: Vulnerability checks
	ms.checkVulnerabilities(ctx)

	// Phase 5: Deep inspection (if aggressive)
	if ms.aggressive {
		ms.deepInspection(ctx)
	}

	ms.logger.Infof("📱 Mobile/IoT scan complete: discovered %d devices", len(ms.devices))
	return ms.devices, nil
}

func (ms *MobileScanner) scanPorts(ctx context.Context) {
	ms.logger.Info("🔍 Scanning for mobile and IoT services")

	// Common mobile/IoT ports
	commonPorts := []int{
		22, 23, 53, 80, 443, 554, 1883, 5683, 8080, 8443,
		161, 162, 502, 1025, 2323, 4567, 5000, 5001, 9000,
		8000, 8888, 9999, 7547, 37777, 49152, 51235,
	}

	for _, port := range commonPorts {
		go ms.scanPort(ctx, port)
	}
}

func (ms *MobileScanner) scanPort(ctx context.Context, port int) {
	address := fmt.Sprintf("%s:%d", ms.target, port)
	
	conn, err := net.DialTimeout("tcp", address, ms.timeout)
	if err != nil {
		return
	}
	defer conn.Close()

	// Service detection
	banner := ms.grabBanner(conn)
	service := ms.detectService(port, banner)

	device := &MobileDevice{
		IP:         ms.target,
		Port:       port,
		Service:    service,
		Banner:     banner,
		Headers:    make(map[string]string),
		Discovered: time.Now(),
	}

	// HTTP-specific checks
	if port == 80 || port == 443 || port == 8080 || port == 8443 {
		ms.httpDetection(device)
	}

	ms.mutex.Lock()
	ms.devices = append(ms.devices, device)
	ms.mutex.Unlock()
}

func (ms *MobileScanner) grabBanner(conn net.Conn) string {
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Second * 3))
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	return string(buffer[:n])
}

func (ms *MobileScanner) detectService(port int, banner string) string {
	serviceMap := map[int]string{
		22:    "SSH",
		23:    "Telnet",
		53:    "DNS",
		80:    "HTTP",
		443:   "HTTPS",
		554:   "RTSP",
		1883:  "MQTT",
		5683:  "CoAP",
		161:   "SNMP",
		502:   "Modbus",
		2323:  "Telnet Alt",
		7547:  "TR-069",
		37777: "DVR",
	}

	if service, exists := serviceMap[port]; exists {
		return service
	}

	// Banner-based detection
	banner = strings.ToLower(banner)
	if strings.Contains(banner, "ssh") {
		return "SSH"
	}
	if strings.Contains(banner, "http") {
		return "HTTP"
	}
	if strings.Contains(banner, "ftp") {
		return "FTP"
	}

	return "Unknown"
}

func (ms *MobileScanner) httpDetection(device *MobileDevice) {
	protocol := "http"
	if device.Port == 443 || device.Port == 8443 {
		protocol = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", protocol, device.IP, device.Port)
	resp, err := ms.client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Extract headers
	for k, v := range resp.Header {
		if len(v) > 0 {
			device.Headers[k] = v[0]
		}
	}

	// Server detection
	if server := resp.Header.Get("Server"); server != "" {
		device.Version = server
	}
}

func (ms *MobileScanner) fingerprintServices(ctx context.Context) {
	ms.logger.Info("🔍 Fingerprinting services")

	for _, device := range ms.devices {
		ms.fingerprintDevice(ctx, device)
	}
}

func (ms *MobileScanner) fingerprintDevice(ctx context.Context, device *MobileDevice) {
	// HTTP fingerprinting
	if device.Service == "HTTP" || device.Service == "HTTPS" {
		ms.httpFingerprint(device)
	}

	// Banner analysis
	if device.Banner != "" {
		ms.analyzeBanner(device)
	}
}

func (ms *MobileScanner) httpFingerprint(device *MobileDevice) {
	protocol := "http"
	if device.Port == 443 || device.Port == 8443 {
		protocol = "https"
	}

	paths := []string{"/", "/admin", "/config", "/status", "/info", "/device"}
	
	for _, path := range paths {
		url := fmt.Sprintf("%s://%s:%d%s", protocol, device.IP, device.Port, path)
		resp, err := ms.client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check for device-specific indicators
		contentType := resp.Header.Get("Content-Type")
		if strings.Contains(contentType, "json") {
			device.Protocol = "REST API"
		}
	}
}

func (ms *MobileScanner) analyzeBanner(device *MobileDevice) {
	banner := strings.ToLower(device.Banner)

	// Extract version information
	versionRegex := regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)
	if matches := versionRegex.FindStringSubmatch(banner); len(matches) > 1 {
		device.Version = matches[1]
	}

	// OS detection
	if strings.Contains(banner, "linux") {
		device.OS = "Linux"
	} else if strings.Contains(banner, "windows") {
		device.OS = "Windows"
	} else if strings.Contains(banner, "freebsd") {
		device.OS = "FreeBSD"
	}
}

func (ms *MobileScanner) classifyDevices() {
	ms.logger.Info("📱 Classifying devices")

	for _, device := range ms.devices {
		ms.classifyDevice(device)
	}
}

func (ms *MobileScanner) classifyDevice(device *MobileDevice) {
	combinedText := strings.ToLower(device.Banner + " " + device.Version + " " + strings.Join(mapValues(device.Headers), " "))

	for _, signature := range ms.deviceSignatures {
		for _, pattern := range signature.Patterns {
			if strings.Contains(combinedText, strings.ToLower(pattern)) {
				device.DeviceType = signature.Type
				device.Vendor = signature.Vendor
				device.Model = signature.Model
				return
			}
		}
	}

	// Fallback classification based on ports
	ms.classifyByPort(device)
}

func (ms *MobileScanner) classifyByPort(device *MobileDevice) {
	switch device.Port {
	case 554:
		device.DeviceType = TypeIoT
		device.Model = "IP Camera"
	case 1883, 5683:
		device.DeviceType = TypeIoT
		device.Model = "IoT Device"
	case 502:
		device.DeviceType = TypeIndustrial
		device.Model = "Industrial Controller"
	case 7547:
		device.DeviceType = TypeIoT
		device.Model = "Router/Modem"
	case 37777:
		device.DeviceType = TypeIoT
		device.Model = "DVR/NVR"
	default:
		device.DeviceType = TypeEmbedded
	}
}

func (ms *MobileScanner) checkVulnerabilities(ctx context.Context) {
	ms.logger.Info("🔍 Checking for vulnerabilities")

	for _, device := range ms.devices {
		ms.checkDeviceVulnerabilities(ctx, device)
	}
}

func (ms *MobileScanner) checkDeviceVulnerabilities(ctx context.Context, device *MobileDevice) {
	// Check for default credentials
	if device.Service == "HTTP" || device.Service == "HTTPS" {
		ms.checkDefaultCredentials(device)
	}

	// Check for open services
	ms.checkOpenServices(device)

	// Calculate overall risk
	device.Risk = ms.calculateRisk(device)
}

func (ms *MobileScanner) checkDefaultCredentials(device *MobileDevice) {
	defaultCreds := []struct {
		username string
		password string
	}{
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", ""},
		{"root", "root"},
		{"user", "user"},
		{"guest", "guest"},
		{"admin", "12345"},
		{"admin", "123456"},
	}

	for _, cred := range defaultCreds {
		if ms.testCredentials(device, cred.username, cred.password) {
			device.Vulnerable = true
			device.Exploitable = append(device.Exploitable, "Device takeover", "Unauthorized access")
			device.Authentication = "Weak (default credentials)"
			return
		}
	}
}

func (ms *MobileScanner) testCredentials(device *MobileDevice, username, password string) bool {
	// Simple HTTP basic auth test
	protocol := "http"
	if device.Port == 443 || device.Port == 8443 {
		protocol = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/admin", protocol, device.IP, device.Port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	req.SetBasicAuth(username, password)
	resp, err := ms.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

func (ms *MobileScanner) checkOpenServices(device *MobileDevice) {
	openServices := []string{"Telnet", "FTP", "SNMP", "MQTT", "CoAP"}
	
	for _, service := range openServices {
		if device.Service == service {
			device.Vulnerable = true
			device.Exploitable = append(device.Exploitable, "Unsecured service access")
			device.Authentication = "None"
		}
	}
}

func (ms *MobileScanner) calculateRisk(device *MobileDevice) string {
	if device.Vulnerable {
		if device.DeviceType == TypeIndustrial || len(device.Exploitable) > 2 {
			return "CRITICAL"
		}
		return "HIGH"
	}

	if device.Authentication == "None" || device.DeviceType == TypeIoT {
		return "MEDIUM"
	}

	return "LOW"
}

func (ms *MobileScanner) deepInspection(ctx context.Context) {
	ms.logger.Info("🕵️ Performing deep inspection")

	for _, device := range ms.devices {
		if device.Vulnerable {
			ms.deepInspectDevice(ctx, device)
		}
	}
}

func (ms *MobileScanner) deepInspectDevice(ctx context.Context, device *MobileDevice) {
	// Attempt to gather more information from vulnerable devices
	if device.Service == "HTTP" || device.Service == "HTTPS" {
		ms.deepHTTPInspection(device)
	}
}

func (ms *MobileScanner) deepHTTPInspection(device *MobileDevice) {
	protocol := "http"
	if device.Port == 443 || device.Port == 8443 {
		protocol = "https"
	}

	// Try to access sensitive endpoints
	sensitivePaths := []string{
		"/config.json", "/status.xml", "/device.json",
		"/system/config", "/api/v1/info", "/cgi-bin/info",
	}

	for _, path := range sensitivePaths {
		url := fmt.Sprintf("%s://%s:%d%s", protocol, device.IP, device.Port, path)
		resp, err := ms.client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			device.Exploitable = append(device.Exploitable, fmt.Sprintf("Information disclosure: %s", path))
		}
	}
}

func (ms *MobileScanner) GetStats() map[string]interface{} {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_devices": len(ms.devices),
	}

	// Count by type
	typeCounts := make(map[DeviceType]int)
	riskCounts := make(map[string]int)
	vulnerableCount := 0

	for _, device := range ms.devices {
		typeCounts[device.DeviceType]++
		riskCounts[device.Risk]++
		if device.Vulnerable {
			vulnerableCount++
		}
	}

	stats["device_types"] = typeCounts
	stats["risk_counts"] = riskCounts
	stats["vulnerable_devices"] = vulnerableCount

	return stats
}

// Helper function to get map values
func mapValues(m map[string]string) []string {
	values := make([]string, 0, len(m))
	for _, v := range m {
		values = append(values, v)
	}
	return values
}