package origin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type OriginVerifier struct {
	Client *http.Client
}

type OriginVerificationResult struct {
	IP               string  `json:"ip"`
	IsCloudflareEdge bool    `json:"is_cloudflare_edge"`
	ASN              int     `json:"asn"`
	ASNOrg           string  `json:"asn_org"`
	IsOrigin         bool    `json:"is_origin"`
	Confidence       float64 `json:"confidence"`
	Evidence         string  `json:"evidence"`
	Timestamp        int64   `json:"timestamp"`
}

type ASNInfo struct {
	ASN    int    `json:"asn"`
	Org    string `json:"org"`
	Source string `json:"source"`
}

func NewOriginVerifier() *OriginVerifier {
	return &OriginVerifier{
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (ov *OriginVerifier) VerifyOrigins(ctx context.Context, ips []string) ([]OriginVerificationResult, error) {
	results := make([]OriginVerificationResult, 0, len(ips))
	
	for _, ip := range ips {
		result := ov.verifyIP(ctx, ip)
		results = append(results, result)
	}
	
	return results, nil
}

func (ov *OriginVerifier) verifyIP(ctx context.Context, ip string) OriginVerificationResult {
	result := OriginVerificationResult{
		IP:        ip,
		Timestamp: time.Now().Unix(),
	}
	
	// Step 1: Check if IP is in Cloudflare ranges
	if ov.isCloudflareRange(ip) {
		result.IsCloudflareEdge = true
		result.IsOrigin = false
		result.Confidence = 1.0
		result.Evidence = "IP is in Cloudflare CIDR ranges"
		return result
	}
	
	// Step 2: ASN lookup
	asnInfo, err := ov.lookupASN(ctx, ip)
	if err == nil {
		result.ASN = asnInfo.ASN
		result.ASNOrg = asnInfo.Org
		
		// Check if ASN is Cloudflare (13335)
		if asnInfo.ASN == 13335 {
			result.IsCloudflareEdge = true
			result.IsOrigin = false
			result.Confidence = 1.0
			result.Evidence = fmt.Sprintf("ASN %d belongs to Cloudflare", asnInfo.ASN)
			return result
		}
		
		// Check other CDN ASNs
		if ov.isCDNASN(asnInfo.ASN) {
			result.IsCloudflareEdge = false
			result.IsOrigin = false
			result.Confidence = 0.9
			result.Evidence = fmt.Sprintf("ASN %d (%s) is a CDN provider", asnInfo.ASN, asnInfo.Org)
			return result
		}
	}
	
	// Step 3: TLS certificate analysis
	certEvidence := ov.analyzeTLSCertificate(ctx, ip)
	if strings.Contains(certEvidence, "cloudflare") {
		result.IsCloudflareEdge = true
		result.IsOrigin = false
		result.Confidence = 0.95
		result.Evidence = certEvidence
		return result
	}
	
	// Step 4: HTTP response analysis
	httpEvidence := ov.analyzeHTTPResponse(ctx, ip)
	if strings.Contains(httpEvidence, "cloudflare") {
		result.IsCloudflareEdge = true
		result.IsOrigin = false
		result.Confidence = 0.8
		result.Evidence = httpEvidence
		return result
	}
	
	// If all checks pass, likely a real origin
	result.IsOrigin = true
	result.Confidence = 0.7
	if asnInfo != nil {
		result.Evidence = fmt.Sprintf("Non-CDN ASN %d (%s), no Cloudflare indicators", asnInfo.ASN, asnInfo.Org)
	} else {
		result.Evidence = "No CDN indicators found, likely origin"
	}
	
	return result
}

func (ov *OriginVerifier) isCloudflareRange(ip string) bool {
	cfRanges := []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
		"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
		"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
		"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
		"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
		"2c0f:f248::/32",
	}
	
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

func (ov *OriginVerifier) lookupASN(ctx context.Context, ip string) (*ASNInfo, error) {
	// Try ip-api.com first (free, reliable)
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=as", ip)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	resp, err := ov.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var result struct {
		AS string `json:"as"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	if result.AS == "" {
		return nil, fmt.Errorf("no ASN data")
	}
	
	// Parse "AS13335 Cloudflare, Inc." format
	parts := strings.Fields(result.AS)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid ASN format")
	}
	
	asnStr := strings.TrimPrefix(parts[0], "AS")
	asn, err := strconv.Atoi(asnStr)
	if err != nil {
		return nil, err
	}
	
	org := strings.Join(parts[1:], " ")
	
	return &ASNInfo{
		ASN:    asn,
		Org:    org,
		Source: "ip-api.com",
	}, nil
}

func (ov *OriginVerifier) isCDNASN(asn int) bool {
	cdnASNs := map[int]string{
		13335: "Cloudflare",
		16509: "Amazon CloudFront",
		15169: "Google",
		8075:  "Microsoft",
		20940: "Akamai",
		16625: "Akamai",
		23286: "Akamai",
		32787: "Facebook",
		36183: "MaxCDN",
		394750: "Fastly",
		54113: "Fastly",
		15133: "EdgeCast",
		33070: "RackSpace",
		29789: "VoxCDN",
	}
	
	_, exists := cdnASNs[asn]
	return exists
}

func (ov *OriginVerifier) analyzeTLSCertificate(ctx context.Context, ip string) string {
	// Quick TLS handshake to check certificate
	conn, err := net.DialTimeout("tcp", ip+":443", 5*time.Second)
	if err != nil {
		return "No TLS on :443"
	}
	defer conn.Close()
	
	// TODO: Proper TLS certificate analysis
	// For now, basic connection test
	return "TLS available, certificate analysis needed"
}

func (ov *OriginVerifier) analyzeHTTPResponse(ctx context.Context, ip string) string {
	urls := []string{
		fmt.Sprintf("http://%s", ip),
		fmt.Sprintf("https://%s", ip),
	}
	
	for _, url := range urls {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		
		req.Header.Set("User-Agent", "RTK-Elite-Origin-Verifier/2.1")
		
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		
		// Check for Cloudflare headers
		cfHeaders := []string{
			"CF-RAY", "CF-Cache-Status", "CF-Request-ID",
			"Server", "cf-ray", "cf-cache-status",
		}
		
		for _, header := range cfHeaders {
			value := resp.Header.Get(header)
			if value != "" {
				if header == "Server" && strings.Contains(strings.ToLower(value), "cloudflare") {
					return fmt.Sprintf("Cloudflare Server header: %s", value)
				}
				if strings.HasPrefix(strings.ToLower(header), "cf-") {
					return fmt.Sprintf("Cloudflare header %s: %s", header, value)
				}
			}
		}
	}
	
	return "No Cloudflare indicators in HTTP response"
}

// FilterOrigins returns only verified real origins (not edge nodes)
func (ov *OriginVerifier) FilterOrigins(results []OriginVerificationResult) []string {
	var realOrigins []string
	
	for _, result := range results {
		if result.IsOrigin && !result.IsCloudflareEdge && result.Confidence >= 0.5 {
			realOrigins = append(realOrigins, result.IP)
		}
	}
	
	return realOrigins
}

// GetEdgeOnlyStatus returns true if all IPs are edge nodes
func (ov *OriginVerifier) GetEdgeOnlyStatus(results []OriginVerificationResult) bool {
	if len(results) == 0 {
		return false
	}
	
	for _, result := range results {
		if !result.IsCloudflareEdge {
			return false
		}
	}
	
	return true
}

// GenerateReport creates detailed verification report
func (ov *OriginVerifier) GenerateReport(results []OriginVerificationResult) string {
	report := "# Origin Verification Report\n\n"
	
	realOrigins := 0
	edgeNodes := 0
	
	for _, result := range results {
		if result.IsOrigin {
			realOrigins++
		}
		if result.IsCloudflareEdge {
			edgeNodes++
		}
	}
	
	report += fmt.Sprintf("**Total IPs analyzed:** %d  \n", len(results))
	report += fmt.Sprintf("**Real origins:** %d  \n", realOrigins)
	report += fmt.Sprintf("**Edge nodes:** %d  \n", edgeNodes)
	report += fmt.Sprintf("**Analysis time:** %s  \n\n", time.Now().Format("2006-01-02 15:04:05"))
	
	if len(results) > 0 {
		report += "## Detailed Results\n\n"
		report += "| IP | Type | ASN | Organization | Confidence | Evidence |\n"
		report += "|----|----|-----|--------------|------------|----------|\n"
		
		for _, result := range results {
			ipType := "❓ Unknown"
			if result.IsOrigin {
				ipType = "✅ Origin"
			} else if result.IsCloudflareEdge {
				ipType = "🌐 Edge"
			}
			
			report += fmt.Sprintf("| %s | %s | %d | %s | %.1f%% | %s |\n",
				result.IP, ipType, result.ASN, result.ASNOrg,
				result.Confidence*100, result.Evidence)
		}
	}
	
	return report
}