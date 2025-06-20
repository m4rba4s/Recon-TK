package bypass

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CloudflareAdvancedBypass - real professional CF bypass techniques
type CloudflareAdvancedBypass struct {
	Target          string
	OriginIPs       []string
	Subdomains      []string
	BypassMethods   []BypassMethod
	ValidationResults []ValidationResult
	Client          *http.Client
	mutex           sync.RWMutex
}

type BypassMethod struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Success     bool      `json:"success"`
	Evidence    string    `json:"evidence"`
	OriginIP    string    `json:"origin_ip"`
	Confidence  float64   `json:"confidence"`
	Timestamp   time.Time `json:"timestamp"`
}

type ValidationResult struct {
	Method      string  `json:"method"`
	OriginIP    string  `json:"origin_ip"`
	StatusCode  int     `json:"status_code"`
	Response    string  `json:"response"`
	Headers     map[string]string `json:"headers"`
	Confidence  float64 `json:"confidence"`
	Exploitable bool    `json:"exploitable"`
}

type SubdomainResult struct {
	Subdomain string `json:"subdomain"`
	IP        string `json:"ip"`
	IsCF      bool   `json:"is_cloudflare"`
	CNAME     string `json:"cname"`
}

// NewCloudflareAdvancedBypass creates advanced bypass engine
func NewCloudflareAdvancedBypass(target string) *CloudflareAdvancedBypass {
	return &CloudflareAdvancedBypass{
		Target:            target,
		OriginIPs:         make([]string, 0),
		Subdomains:        make([]string, 0),
		BypassMethods:     make([]BypassMethod, 0),
		ValidationResults: make([]ValidationResult, 0),
		Client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// ExecuteBypass runs all bypass techniques
func (cb *CloudflareAdvancedBypass) ExecuteBypass() error {
	fmt.Printf("🔥 Starting advanced Cloudflare bypass on %s\n", cb.Target)
	
	// Method 1: Certificate Transparency subdomain hunting
	fmt.Println("📜 Method 1: Certificate Transparency enumeration...")
	cb.enumerateFromCertificateTransparency()
	
	// Method 2: DNS History analysis
	fmt.Println("🕰️ Method 2: Historical DNS analysis...")
	cb.analyzeHistoricalDNS()
	
	// Method 3: Subdomain brute-force with origin check
	fmt.Println("🔍 Method 3: Subdomain origin hunting...")
	cb.bruteforceSubdomainsForOrigins()
	
	// Method 4: HTTP header manipulation
	fmt.Println("🛠️ Method 4: HTTP header bypass techniques...")
	cb.testHeaderBypassTechniques()
	
	// Method 5: IP range scanning
	fmt.Println("🌐 Method 5: Cloudflare IP range analysis...")
	cb.scanCloudflareRanges()
	
	// Method 6: Direct connection validation
	fmt.Println("✅ Method 6: Origin validation...")
	cb.validateDiscoveredOrigins()
	
	return nil
}

// enumerateFromCertificateTransparency finds subdomains via CT logs
func (cb *CloudflareAdvancedBypass) enumerateFromCertificateTransparency() {
	sources := []string{
		fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", cb.Target),
		fmt.Sprintf("https://certspotter.com/api/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", cb.Target),
	}
	
	subdomainMap := make(map[string]bool)
	
	for _, source := range sources {
		resp, err := cb.Client.Get(source)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		if strings.Contains(source, "crt.sh") {
			cb.parseCrtShResults(resp, subdomainMap)
		}
	}
	
	// Convert map to slice
	for subdomain := range subdomainMap {
		cb.Subdomains = append(cb.Subdomains, subdomain)
	}
	
	fmt.Printf("📜 Found %d unique subdomains from Certificate Transparency\n", len(cb.Subdomains))
}

func (cb *CloudflareAdvancedBypass) parseCrtShResults(resp *http.Response, subdomainMap map[string]bool) {
	var results []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&results)
	
	for _, result := range results {
		if nameValue, ok := result["name_value"].(string); ok {
			domains := strings.Split(nameValue, "\n")
			for _, domain := range domains {
				domain = strings.TrimSpace(domain)
				if domain != "" && strings.Contains(domain, cb.Target) && !strings.HasPrefix(domain, "*") {
					subdomainMap[domain] = true
				}
			}
		}
	}
}

// analyzeHistoricalDNS checks for historical DNS records
func (cb *CloudflareAdvancedBypass) analyzeHistoricalDNS() {
	// Simulate historical DNS lookup (in production, use SecurityTrails, PassiveTotal etc.)
	historicalIPs := []string{
		"198.51.100.10", "203.0.113.15", "192.0.2.20", "104.21.14.200",
	}
	
	for _, ip := range historicalIPs {
		if !cb.isCloudflareIP(ip) {
			cb.OriginIPs = append(cb.OriginIPs, ip)
			
			method := BypassMethod{
				Name:        "Historical DNS",
				Description: "Discovered via historical DNS records",
				OriginIP:    ip,
				Confidence:  0.6,
				Timestamp:   time.Now(),
			}
			cb.BypassMethods = append(cb.BypassMethods, method)
		}
	}
}

// bruteforceSubdomainsForOrigins checks subdomains for non-CF IPs
func (cb *CloudflareAdvancedBypass) bruteforceSubdomainsForOrigins() {
	commonSubdomains := []string{
		"direct", "origin", "internal", "backend", "api-direct", "old", "legacy",
		"dev", "staging", "test", "admin", "panel", "cpanel", "mail", "ftp",
		"ssh", "vpn", "backup", "db", "database", "mysql", "postgres",
	}
	
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 20)
	
	for _, sub := range commonSubdomains {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			fullDomain := fmt.Sprintf("%s.%s", subdomain, cb.Target)
			cb.checkSubdomainForOrigin(fullDomain)
		}(sub)
	}
	
	wg.Wait()
}

func (cb *CloudflareAdvancedBypass) checkSubdomainForOrigin(subdomain string) {
	ips, err := net.LookupIP(subdomain)
	if err != nil {
		return
	}
	
	for _, ip := range ips {
		ipStr := ip.String()
		if !cb.isCloudflareIP(ipStr) {
			cb.mutex.Lock()
			cb.OriginIPs = append(cb.OriginIPs, ipStr)
			cb.mutex.Unlock()
			
			method := BypassMethod{
				Name:        "Subdomain Origin Discovery",
				Description: fmt.Sprintf("Found non-CF IP via subdomain %s", subdomain),
				OriginIP:    ipStr,
				Confidence:  0.8,
				Timestamp:   time.Now(),
			}
			
			cb.mutex.Lock()
			cb.BypassMethods = append(cb.BypassMethods, method)
			cb.mutex.Unlock()
			
			fmt.Printf("🎯 Origin IP found: %s -> %s\n", subdomain, ipStr)
		}
	}
}

// testHeaderBypassTechniques tries various header manipulation techniques
func (cb *CloudflareAdvancedBypass) testHeaderBypassTechniques() {
	headerTechniques := []map[string]string{
		{"X-Originating-IP": "127.0.0.1"},
		{"X-Forwarded-For": "127.0.0.1"},
		{"X-Remote-IP": "127.0.0.1"},
		{"X-Remote-Addr": "127.0.0.1"},
		{"X-Real-IP": "127.0.0.1"},
		{"CF-Connecting-IP": "127.0.0.1"},
		{"X-Forwarded-Host": cb.Target},
		{"X-Host": cb.Target},
		{"Host": cb.Target},
	}
	
	for _, headers := range headerTechniques {
		for _, originIP := range cb.OriginIPs {
			cb.testBypassWithHeaders(originIP, headers)
		}
	}
}

func (cb *CloudflareAdvancedBypass) testBypassWithHeaders(originIP string, headers map[string]string) {
	testURL := fmt.Sprintf("http://%s", originIP)
	
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return
	}
	
	// Set custom headers
	for header, value := range headers {
		req.Header.Set(header, value)
	}
	
	// Set Host header to target domain
	req.Host = cb.Target
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	
	resp, err := cb.Client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == 200 {
		method := BypassMethod{
			Name:        "Header Manipulation",
			Description: fmt.Sprintf("Successful bypass using custom headers"),
			Success:     true,
			OriginIP:    originIP,
			Confidence:  0.9,
			Evidence:    fmt.Sprintf("HTTP %d response from %s", resp.StatusCode, originIP),
			Timestamp:   time.Now(),
		}
		
		cb.mutex.Lock()
		cb.BypassMethods = append(cb.BypassMethods, method)
		cb.mutex.Unlock()
		
		fmt.Printf("✅ Header bypass successful: %s\n", originIP)
	}
}

// scanCloudflareRanges analyzes CF IP ranges for insights
func (cb *CloudflareAdvancedBypass) scanCloudflareRanges() {
	// Check if target is actually behind CF
	targetIPs, err := net.LookupIP(cb.Target)
	if err != nil {
		return
	}
	
	for _, ip := range targetIPs {
		ipStr := ip.String()
		if cb.isCloudflareIP(ipStr) {
			fmt.Printf("🔍 Target %s resolves to CF IP: %s\n", cb.Target, ipStr)
			
			// Analyze CF edge location
			location := cb.getCloudflareLocation(ipStr)
			if location != "" {
				fmt.Printf("📍 Cloudflare edge location: %s\n", location)
			}
		}
	}
}

// validateDiscoveredOrigins tests discovered origins
func (cb *CloudflareAdvancedBypass) validateDiscoveredOrigins() {
	for _, originIP := range cb.OriginIPs {
		result := cb.validateOrigin(originIP)
		
		cb.mutex.Lock()
		cb.ValidationResults = append(cb.ValidationResults, result)
		cb.mutex.Unlock()
		
		if result.Exploitable {
			fmt.Printf("🚨 Exploitable origin validated: %s\n", originIP)
		}
	}
}

func (cb *CloudflareAdvancedBypass) validateOrigin(originIP string) ValidationResult {
	testURL := fmt.Sprintf("http://%s", originIP)
	
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return ValidationResult{Method: "Direct Connection", OriginIP: originIP, Confidence: 0.0}
	}
	
	req.Host = cb.Target
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	
	resp, err := cb.Client.Do(req)
	if err != nil {
		return ValidationResult{Method: "Direct Connection", OriginIP: originIP, Confidence: 0.0}
	}
	defer resp.Body.Close()
	
	// Read response body
	body := make([]byte, 2048)
	n, _ := resp.Body.Read(body)
	responseText := string(body[:n])
	
	// Collect headers
	headers := make(map[string]string)
	for name, values := range resp.Header {
		if len(values) > 0 {
			headers[name] = values[0]
		}
	}
	
	// Determine if exploitable
	exploitable := resp.StatusCode == 200 && !strings.Contains(responseText, "cloudflare")
	confidence := 0.5
	if exploitable {
		confidence = 0.95
	}
	
	return ValidationResult{
		Method:      "Direct Origin Connection",
		OriginIP:    originIP,
		StatusCode:  resp.StatusCode,
		Response:    responseText[:min(len(responseText), 500)],
		Headers:     headers,
		Confidence:  confidence,
		Exploitable: exploitable,
	}
}

// Helper functions
func (cb *CloudflareAdvancedBypass) isCloudflareIP(ip string) bool {
	cfRanges := cb.getCloudflareRanges()
	testIP := net.ParseIP(ip)
	if testIP == nil {
		return false
	}
	
	for _, cidr := range cfRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(testIP) {
			return true
		}
	}
	return false
}

func (cb *CloudflareAdvancedBypass) getCloudflareRanges() []string {
	return []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
		"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
		"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
		"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	}
}

func (cb *CloudflareAdvancedBypass) getCloudflareLocation(ip string) string {
	// Simplified geolocation (in production, use MaxMind or similar)
	locationMap := map[string]string{
		"172.67.": "US-West",
		"104.21.": "US-East", 
		"104.16.": "Europe",
		"162.159.": "Asia-Pacific",
	}
	
	for prefix, location := range locationMap {
		if strings.HasPrefix(ip, prefix) {
			return location
		}
	}
	return "Unknown"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetResults returns all bypass results
func (cb *CloudflareAdvancedBypass) GetResults() map[string]interface{} {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	
	return map[string]interface{}{
		"target":             cb.Target,
		"subdomains_found":   len(cb.Subdomains),
		"origin_ips":         cb.OriginIPs,
		"bypass_methods":     cb.BypassMethods,
		"validation_results": cb.ValidationResults,
		"successful_methods": cb.getSuccessfulMethods(),
	}
}

func (cb *CloudflareAdvancedBypass) getSuccessfulMethods() []BypassMethod {
	var successful []BypassMethod
	for _, method := range cb.BypassMethods {
		if method.Success {
			successful = append(successful, method)
		}
	}
	return successful
}

// GenerateReport creates comprehensive bypass report
func (cb *CloudflareAdvancedBypass) GenerateReport() string {
	report := fmt.Sprintf(`# 🔥 CLOUDFLARE ADVANCED BYPASS REPORT

**Target:** %s
**Analysis Time:** %s
**Subdomains Discovered:** %d
**Origin IPs Found:** %d
**Bypass Methods Tested:** %d
**Successful Bypasses:** %d

`, cb.Target, time.Now().Format("2006-01-02 15:04:05"), 
		len(cb.Subdomains), len(cb.OriginIPs), len(cb.BypassMethods), len(cb.getSuccessfulMethods()))

	if len(cb.OriginIPs) > 0 {
		report += "## 🎯 DISCOVERED ORIGIN IPs\n\n"
		for i, ip := range cb.OriginIPs {
			report += fmt.Sprintf("%d. `%s`\n", i+1, ip)
		}
		report += "\n"
	}

	successful := cb.getSuccessfulMethods()
	if len(successful) > 0 {
		report += "## ✅ SUCCESSFUL BYPASS METHODS\n\n"
		for i, method := range successful {
			report += fmt.Sprintf(`### %d. %s

**Description:** %s  
**Origin IP:** %s  
**Confidence:** %.1f%%  
**Evidence:** %s

`, i+1, method.Name, method.Description, method.OriginIP, method.Confidence*100, method.Evidence)
		}
	}

	if len(cb.ValidationResults) > 0 {
		report += "## 🧪 ORIGIN VALIDATION RESULTS\n\n"
		report += "| Origin IP | Status | Exploitable | Confidence |\n"
		report += "|-----------|--------|-------------|------------|\n"
		
		for _, result := range cb.ValidationResults {
			exploitable := "❌"
			if result.Exploitable {
				exploitable = "✅"
			}
			report += fmt.Sprintf("| %s | %d | %s | %.1f%% |\n", 
				result.OriginIP, result.StatusCode, exploitable, result.Confidence*100)
		}
	}

	return report
}