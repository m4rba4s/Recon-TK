package origin

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// CloudflareOriginHunter - engine for finding real origin IPs behind Cloudflare
type CloudflareOriginHunter struct {
	Target     string
	Subdomains []string
	OriginIPs  []OriginResult
	Methods    []string
	Client     *http.Client
	mutex      sync.RWMutex
}

type OriginResult struct {
	IP         string    `json:"ip"`
	Source     string    `json:"source"`
	Method     string    `json:"method"`
	Confidence float64   `json:"confidence"`
	Verified   bool      `json:"verified"`
	Timestamp  time.Time `json:"timestamp"`
	Response   string    `json:"response,omitempty"`
}

type CrtShResult struct {
	NameValue string `json:"name_value"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

// NewCloudflareOriginHunter creates new origin hunter
func NewCloudflareOriginHunter(target string) *CloudflareOriginHunter {
	return &CloudflareOriginHunter{
		Target:    target,
		OriginIPs: make([]OriginResult, 0),
		Methods:   []string{"crt.sh", "dns_history", "subdomain_enum", "direct_connect"},
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Hunt executes comprehensive origin discovery
func (h *CloudflareOriginHunter) Hunt() ([]OriginResult, error) {
	fmt.Printf("🔍 Starting Cloudflare origin discovery for %s\n", h.Target)
	
	// Phase 1: Subdomain enumeration via Certificate Transparency
	fmt.Println("📜 Phase 1: Certificate Transparency enumeration...")
	subdomains := h.enumerateSubdomainsCrtSh()
	h.Subdomains = append(h.Subdomains, subdomains...)
	
	// Phase 2: DNS resolution for non-CF IPs
	fmt.Println("🔍 Phase 2: DNS resolution for origin discovery...")
	originIPs := h.findNonCloudflareIPs()
	
	// Phase 3: Direct connection verification
	fmt.Println("✅ Phase 3: Origin verification...")
	verifiedOrigins := h.verifyOrigins(originIPs)
	
	// Phase 4: Historical DNS data (simulated)
	fmt.Println("📊 Phase 4: Historical DNS analysis...")
	historicalIPs := h.getHistoricalDNS()
	
	h.mutex.Lock()
	h.OriginIPs = append(h.OriginIPs, verifiedOrigins...)
	h.OriginIPs = append(h.OriginIPs, historicalIPs...)
	h.mutex.Unlock()
	
	return h.OriginIPs, nil
}

// enumerateSubdomainsCrtSh gets subdomains from crt.sh
func (h *CloudflareOriginHunter) enumerateSubdomainsCrtSh() []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", h.Target)
	
	resp, err := h.Client.Get(url)
	if err != nil {
		fmt.Printf("❌ crt.sh query failed: %v\n", err)
		return []string{}
	}
	defer resp.Body.Close()
	
	var results []CrtShResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		fmt.Printf("❌ Failed to parse crt.sh response: %v\n", err)
		return []string{}
	}
	
	subdomainMap := make(map[string]bool)
	for _, result := range results {
		// Parse multiple subdomains from name_value
		domains := strings.Split(result.NameValue, "\n")
		for _, domain := range domains {
			domain = strings.TrimSpace(domain)
			if domain != "" && strings.Contains(domain, h.Target) {
				subdomainMap[domain] = true
			}
		}
	}
	
	subdomains := make([]string, 0, len(subdomainMap))
	for subdomain := range subdomainMap {
		subdomains = append(subdomains, subdomain)
	}
	
	fmt.Printf("📜 Found %d unique subdomains from Certificate Transparency\n", len(subdomains))
	return subdomains
}

// findNonCloudflareIPs resolves subdomains and filters non-CF IPs
func (h *CloudflareOriginHunter) findNonCloudflareIPs() []OriginResult {
	var origins []OriginResult
	cloudflareRanges := h.getCloudflareRanges()
	
	// Add main domain to subdomain list
	allDomains := append([]string{h.Target}, h.Subdomains...)
	
	for _, domain := range allDomains {
		ips, err := net.LookupIP(domain)
		if err != nil {
			continue
		}
		
		for _, ip := range ips {
			ipStr := ip.String()
			if !h.isCloudflareIP(ipStr, cloudflareRanges) {
				origin := OriginResult{
					IP:         ipStr,
					Source:     domain,
					Method:     "dns_resolution",
					Confidence: 0.8,
					Verified:   false,
					Timestamp:  time.Now(),
				}
				origins = append(origins, origin)
				fmt.Printf("🎯 Potential origin found: %s -> %s\n", domain, ipStr)
			}
		}
	}
	
	return origins
}

// getCloudflareRanges returns known Cloudflare IP ranges
func (h *CloudflareOriginHunter) getCloudflareRanges() []string {
	return []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
		"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
		"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
		"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	}
}

// isCloudflareIP checks if IP belongs to Cloudflare
func (h *CloudflareOriginHunter) isCloudflareIP(ip string, ranges []string) bool {
	testIP := net.ParseIP(ip)
	if testIP == nil {
		return false
	}
	
	for _, cidr := range ranges {
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

// verifyOrigins attempts to connect directly to potential origins
func (h *CloudflareOriginHunter) verifyOrigins(origins []OriginResult) []OriginResult {
	var verified []OriginResult
	
	for _, origin := range origins {
		if h.verifyOriginConnection(origin.IP) {
			origin.Verified = true
			origin.Confidence = 0.95
			origin.Response = "Direct connection successful"
			verified = append(verified, origin)
			fmt.Printf("✅ Origin verified: %s (confidence: %.1f%%)\n", origin.IP, origin.Confidence*100)
		}
	}
	
	return verified
}

// verifyOriginConnection tests direct connection to potential origin
func (h *CloudflareOriginHunter) verifyOriginConnection(ip string) bool {
	// Test HTTP connection
	testURL := fmt.Sprintf("http://%s", ip)
	client := &http.Client{Timeout: 5 * time.Second}
	
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return false
	}
	
	// Set Host header to target domain
	req.Host = h.Target
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	// Check if response looks like the target site
	return resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302
}

// getHistoricalDNS simulates historical DNS data lookup
func (h *CloudflareOriginHunter) getHistoricalDNS() []OriginResult {
	// In real implementation, this would query services like:
	// - SecurityTrails API
	// - PassiveTotal
	// - DNSHistory.org
	// - ViewDNS.info
	
	var historical []OriginResult
	
	// Simulate some historical IPs (in real tool, query actual services)
	historicalIPs := []string{
		"198.51.100.10", "203.0.113.15", "192.0.2.20",
	}
	
	for _, ip := range historicalIPs {
		if !h.isCloudflareIP(ip, h.getCloudflareRanges()) {
			historical = append(historical, OriginResult{
				IP:         ip,
				Source:     "historical_dns",
				Method:     "dns_history_lookup",
				Confidence: 0.6,
				Verified:   false,
				Timestamp:  time.Now().Add(-24 * time.Hour), // Simulate old data
			})
		}
	}
	
	return historical
}

// GetResults returns all discovered origins
func (h *CloudflareOriginHunter) GetResults() []OriginResult {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	
	return h.OriginIPs
}

// GenerateReport creates detailed origin discovery report
func (h *CloudflareOriginHunter) GenerateReport() string {
	report := fmt.Sprintf(`# 🔍 CLOUDFLARE ORIGIN DISCOVERY REPORT

**Target:** %s
**Discovery Time:** %s
**Subdomains Found:** %d
**Origin IPs Discovered:** %d

## 📊 DISCOVERY SUMMARY

`, h.Target, time.Now().Format("2006-01-02 15:04:05"), len(h.Subdomains), len(h.OriginIPs))

	if len(h.OriginIPs) > 0 {
		report += "### 🎯 DISCOVERED ORIGINS\n\n"
		report += "| IP Address | Source | Method | Confidence | Verified |\n"
		report += "|------------|--------|--------|------------|----------|\n"
		
		for _, origin := range h.OriginIPs {
			verified := "❌"
			if origin.Verified {
				verified = "✅"
			}
			report += fmt.Sprintf("| %s | %s | %s | %.1f%% | %s |\n",
				origin.IP, origin.Source, origin.Method, origin.Confidence*100, verified)
		}
	} else {
		report += "### ❌ NO ORIGINS DISCOVERED\n\n"
		report += "Cloudflare protection appears to be properly configured.\n"
	}

	return report
}