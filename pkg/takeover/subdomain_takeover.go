package takeover

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SubdomainTakeoverDetector detects vulnerable subdomains
type SubdomainTakeoverDetector struct {
	Target       string
	Subdomains   []string
	Vulnerable   []VulnerableSubdomain
	Fingerprints map[string]ServiceFingerprint
	Client       *http.Client
	mutex        sync.RWMutex
}

type VulnerableSubdomain struct {
	Subdomain    string    `json:"subdomain"`
	Service      string    `json:"service"`
	CNAME        string    `json:"cname"`
	Confidence   float64   `json:"confidence"`
	Evidence     string    `json:"evidence"`
	Exploitation string    `json:"exploitation"`
	Timestamp    time.Time `json:"timestamp"`
}

type ServiceFingerprint struct {
	Service     string
	Patterns    []string
	CNAMEKeywords []string
	Confidence  float64
	Description string
}

// NewSubdomainTakeoverDetector creates new takeover detector
func NewSubdomainTakeoverDetector(target string, subdomains []string) *SubdomainTakeoverDetector {
	detector := &SubdomainTakeoverDetector{
		Target:     target,
		Subdomains: subdomains,
		Vulnerable: make([]VulnerableSubdomain, 0),
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
	
	detector.initializeFingerprints()
	return detector
}

// initializeFingerprints sets up service detection patterns
func (d *SubdomainTakeoverDetector) initializeFingerprints() {
	d.Fingerprints = map[string]ServiceFingerprint{
		"github": {
			Service:       "GitHub Pages",
			Patterns:      []string{"There isn't a GitHub Pages site here", "404 - File not found"},
			CNAMEKeywords: []string{"github.io", "github.com"},
			Confidence:    0.95,
			Description:   "GitHub Pages subdomain takeover via unclaimed repository",
		},
		"heroku": {
			Service:       "Heroku",
			Patterns:      []string{"No such app", "herokucdn.com"},
			CNAMEKeywords: []string{"herokuapp.com", "herokussl.com"},
			Confidence:    0.90,
			Description:   "Heroku app subdomain takeover via unclaimed app name",
		},
		"aws_s3": {
			Service:       "AWS S3",
			Patterns:      []string{"NoSuchBucket", "The specified bucket does not exist"},
			CNAMEKeywords: []string{"amazonaws.com", "s3.amazonaws.com"},
			Confidence:    0.85,
			Description:   "AWS S3 bucket subdomain takeover via unclaimed bucket",
		},
		"azure": {
			Service:       "Azure",
			Patterns:      []string{"404 Web Site not found", "azurewebsites.net"},
			CNAMEKeywords: []string{"azurewebsites.net", "cloudapp.net"},
			Confidence:    0.88,
			Description:   "Microsoft Azure subdomain takeover via unclaimed service",
		},
		"digitalocean": {
			Service:       "DigitalOcean",
			Patterns:      []string{"Domain uses DigitalOcean DNS", "page not found"},
			CNAMEKeywords: []string{"digitaloceanspaces.com"},
			Confidence:    0.80,
			Description:   "DigitalOcean Spaces subdomain takeover",
		},
		"vercel": {
			Service:       "Vercel",
			Patterns:      []string{"The deployment could not be found", "vercel.app"},
			CNAMEKeywords: []string{"vercel.app", "now.sh"},
			Confidence:    0.85,
			Description:   "Vercel deployment subdomain takeover",
		},
		"netlify": {
			Service:       "Netlify",
			Patterns:      []string{"Not Found - Request ID", "netlify.app"},
			CNAMEKeywords: []string{"netlify.app", "netlify.com"},
			Confidence:    0.87,
			Description:   "Netlify site subdomain takeover",
		},
		"fastly": {
			Service:       "Fastly",
			Patterns:      []string{"Fastly error: unknown domain", "Request ID:"},
			CNAMEKeywords: []string{"fastly.com", "fastlylb.net"},
			Confidence:    0.82,
			Description:   "Fastly CDN subdomain takeover",
		},
	}
}

// ScanForTakeoverVulns scans all subdomains for takeover vulnerabilities
func (d *SubdomainTakeoverDetector) ScanForTakeoverVulns() error {
	fmt.Printf("🎯 Scanning %d subdomains for takeover vulnerabilities\n", len(d.Subdomains))
	
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 20) // Limit concurrent requests
	
	for _, subdomain := range d.Subdomains {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			d.checkSubdomainTakeover(sub)
		}(subdomain)
	}
	
	wg.Wait()
	return nil
}

// checkSubdomainTakeover checks individual subdomain for takeover
func (d *SubdomainTakeoverDetector) checkSubdomainTakeover(subdomain string) {
	// Step 1: Get CNAME record
	cname := d.getCNAME(subdomain)
	if cname == "" {
		return // No CNAME, likely not vulnerable
	}
	
	// Step 2: Check if CNAME points to vulnerable service
	service := d.identifyVulnerableService(cname)
	if service == "" {
		return // Not pointing to known vulnerable service
	}
	
	// Step 3: Attempt HTTP request to verify
	evidence, confidence := d.verifyTakeoverVulnerability(subdomain, service)
	if confidence > 0.5 {
		vulnerable := VulnerableSubdomain{
			Subdomain:    subdomain,
			Service:      service,
			CNAME:        cname,
			Confidence:   confidence,
			Evidence:     evidence,
			Exploitation: d.generateExploitationSteps(service),
			Timestamp:    time.Now(),
		}
		
		d.mutex.Lock()
		d.Vulnerable = append(d.Vulnerable, vulnerable)
		d.mutex.Unlock()
		
		fmt.Printf("🚨 TAKEOVER VULNERABILITY: %s -> %s (%.1f%% confidence)\n", 
			subdomain, service, confidence*100)
	}
}

// getCNAME retrieves CNAME record for subdomain
func (d *SubdomainTakeoverDetector) getCNAME(subdomain string) string {
	cname, err := net.LookupCNAME(subdomain)
	if err != nil {
		return ""
	}
	
	// Remove trailing dot
	if strings.HasSuffix(cname, ".") {
		cname = cname[:len(cname)-1]
	}
	
	return cname
}

// identifyVulnerableService checks if CNAME points to vulnerable service
func (d *SubdomainTakeoverDetector) identifyVulnerableService(cname string) string {
	cnameUpper := strings.ToUpper(cname)
	
	for serviceKey, fingerprint := range d.Fingerprints {
		for _, keyword := range fingerprint.CNAMEKeywords {
			if strings.Contains(cnameUpper, strings.ToUpper(keyword)) {
				return serviceKey
			}
		}
	}
	
	return ""
}

// verifyTakeoverVulnerability attempts HTTP request to verify vulnerability
func (d *SubdomainTakeoverDetector) verifyTakeoverVulnerability(subdomain, service string) (string, float64) {
	fingerprint, exists := d.Fingerprints[service]
	if !exists {
		return "", 0.0
	}
	
	// Attempt HTTP request
	testURL := fmt.Sprintf("http://%s", subdomain)
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return "", 0.0
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	
	resp, err := d.Client.Do(req)
	if err != nil {
		// Try HTTPS
		testURL = fmt.Sprintf("https://%s", subdomain)
		req, err = http.NewRequest("GET", testURL, nil)
		if err != nil {
			return "", 0.0
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
		resp, err = d.Client.Do(req)
		if err != nil {
			return "", 0.0
		}
	}
	defer resp.Body.Close()
	
	// Read response body
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	responseText := string(body[:n])
	
	// Check for vulnerability patterns
	for _, pattern := range fingerprint.Patterns {
		if strings.Contains(responseText, pattern) {
			return fmt.Sprintf("Found pattern: '%s' in response", pattern), fingerprint.Confidence
		}
	}
	
	// Check status codes that might indicate vulnerability
	if resp.StatusCode == 404 && strings.Contains(responseText, "not found") {
		return fmt.Sprintf("404 status with 'not found' message for %s service", fingerprint.Service), 0.7
	}
	
	return "", 0.0
}

// generateExploitationSteps provides exploitation guidance
func (d *SubdomainTakeoverDetector) generateExploitationSteps(service string) string {
	exploitSteps := map[string]string{
		"github": `1. Create GitHub account
2. Create repository named after the subdomain
3. Enable GitHub Pages in repository settings
4. Upload index.html with your content
5. Subdomain will now serve your content`,
		
		"heroku": `1. Create Heroku account
2. Create new app with the exact name from CNAME
3. Deploy your application
4. Subdomain will now point to your app`,
		
		"aws_s3": `1. Create AWS S3 bucket with exact name from CNAME
2. Enable static website hosting
3. Upload your index.html
4. Configure bucket policy for public access`,
		
		"azure": `1. Create Azure account
2. Create Web App with matching name
3. Deploy your application
4. Configure custom domain if needed`,
		
		"vercel": `1. Create Vercel account
2. Create project with matching name
3. Deploy your application
4. Subdomain will serve your content`,
		
		"netlify": `1. Create Netlify account
2. Create site with matching name
3. Deploy your static site
4. Configure custom domain`,
	}
	
	if steps, exists := exploitSteps[service]; exists {
		return steps
	}
	
	return "Generic takeover: Create account on the identified service and claim the subdomain/resource"
}

// GetVulnerableSubdomains returns all found vulnerable subdomains
func (d *SubdomainTakeoverDetector) GetVulnerableSubdomains() []VulnerableSubdomain {
	d.mutex.RLock()
	defer d.mutex.RUnlock()
	
	return d.Vulnerable
}

// GenerateReport creates detailed takeover vulnerability report
func (d *SubdomainTakeoverDetector) GenerateReport() string {
	report := fmt.Sprintf(`# 🎯 SUBDOMAIN TAKEOVER VULNERABILITY REPORT

**Target Domain:** %s
**Scan Time:** %s
**Subdomains Tested:** %d
**Vulnerable Subdomains:** %d

`, d.Target, time.Now().Format("2006-01-02 15:04:05"), len(d.Subdomains), len(d.Vulnerable))

	if len(d.Vulnerable) > 0 {
		report += "## 🚨 CRITICAL VULNERABILITIES FOUND\n\n"
		
		for i, vuln := range d.Vulnerable {
			report += fmt.Sprintf(`### %d. %s

**Service:** %s  
**CNAME:** %s  
**Confidence:** %.1f%%  
**Evidence:** %s  

**Exploitation Steps:**
%s

---

`, i+1, vuln.Subdomain, vuln.Service, vuln.CNAME, vuln.Confidence*100, vuln.Evidence, vuln.Exploitation)
		}
		
		report += "\n## ⚠️ BUSINESS IMPACT\n\n"
		report += "Subdomain takeover vulnerabilities allow attackers to:\n"
		report += "- Host malicious content on your domain\n"
		report += "- Steal sensitive cookies and session tokens\n"
		report += "- Perform phishing attacks against your users\n"
		report += "- Damage your organization's reputation\n"
		report += "- Bypass Content Security Policy (CSP) restrictions\n\n"
		
		report += "## 🛡️ REMEDIATION\n\n"
		report += "1. **Immediate:** Remove DNS records for unclaimed subdomains\n"
		report += "2. **Monitor:** Implement continuous subdomain monitoring\n"
		report += "3. **Inventory:** Maintain accurate inventory of all subdomains\n"
		report += "4. **Process:** Establish procedures for subdomain lifecycle management\n"
		
	} else {
		report += "## ✅ NO VULNERABILITIES FOUND\n\n"
		report += "No subdomain takeover vulnerabilities were detected.\n"
		report += "This suggests proper subdomain management practices.\n"
	}

	return report
}

// GetStatistics returns vulnerability statistics
func (d *SubdomainTakeoverDetector) GetStatistics() map[string]int {
	stats := make(map[string]int)
	stats["total_subdomains"] = len(d.Subdomains)
	stats["vulnerable_subdomains"] = len(d.Vulnerable)
	
	// Count by service type
	serviceCounts := make(map[string]int)
	for _, vuln := range d.Vulnerable {
		serviceCounts[vuln.Service]++
	}
	
	for service, count := range serviceCounts {
		stats[fmt.Sprintf("vulnerable_%s", service)] = count
	}
	
	return stats
}