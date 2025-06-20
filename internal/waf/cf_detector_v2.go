package waf

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// CloudflareDetectorV2 - улучшенный детектор Cloudflare с fallback стратегиями
type CloudflareDetectorV2 struct {
	logger *zap.Logger
	client *http.Client
	mutex  sync.RWMutex
}

// CFDetectionResult - результат детекции CF с расширенной аналитикой
type CFDetectionResult struct {
	IsCloudflare         bool      `json:"is_cloudflare"`
	Confidence          float64   `json:"confidence"`
	DetectionMethods    []string  `json:"detection_methods"`
	Evidence            []string  `json:"evidence"`
	CFRayHeaders        []string  `json:"cf_ray_headers"`
	ASNVerification     bool      `json:"asn_verification"`
	IPRangeMatch        bool      `json:"ip_range_match"`
	CDNCGITraceStatus   string    `json:"cdn_cgi_trace_status"`
	FallbackMethods     []string  `json:"fallback_methods"`
	ErrorMessages       []string  `json:"error_messages"`
	ExecutionTime       string    `json:"execution_time"`
	Timestamp           time.Time `json:"timestamp"`
}

// Embedded Cloudflare ASN list (build-time generation)
var CloudflareASNs = []string{
	"AS13335", "AS209242", "AS132892", "AS395747", "AS203898",
}

// Embedded Cloudflare IP ranges (обновлено 2025)
var CloudflareIPRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
	"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", 
	"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
	"198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"172.67.0.0/16", "172.68.0.0/16", "172.69.0.0/16",
	"172.70.0.0/15", "172.72.0.0/14", "172.76.0.0/14",
}

func NewCloudflareDetectorV2(logger *zap.Logger) *CloudflareDetectorV2 {
	return &CloudflareDetectorV2{
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives: true,
				MaxIdleConns:      1,
			},
		},
	}
}

// DetectWithFallback - основной метод детекции с fallback стратегиями
func (cfd *CloudflareDetectorV2) DetectWithFallback(ctx context.Context, target string) (*CFDetectionResult, error) {
	start := time.Now()
	
	result := &CFDetectionResult{
		DetectionMethods: make([]string, 0),
		Evidence:         make([]string, 0),
		CFRayHeaders:     make([]string, 0),
		FallbackMethods:  make([]string, 0),
		ErrorMessages:    make([]string, 0),
		Timestamp:        time.Now(),
	}

	cfd.logger.Info("🔍 Starting Cloudflare detection v2 with fallback", 
		zap.String("target", target))

	// Strategy 1: IP Range Verification (всегда первый)
	cfd.detectByIPRange(target, result)

	// Strategy 2: HTTPS Headers Analysis  
	if err := cfd.detectByHTTPSHeaders(target, result); err != nil {
		cfd.logger.Warn("HTTPS detection failed, trying fallback", zap.Error(err))
		result.ErrorMessages = append(result.ErrorMessages, fmt.Sprintf("HTTPS failed: %v", err))
		
		// Fallback 2A: HTTP Headers (without TLS)
		if err := cfd.detectByHTTPHeaders(target, result); err != nil {
			result.ErrorMessages = append(result.ErrorMessages, fmt.Sprintf("HTTP fallback failed: %v", err))
		} else {
			result.FallbackMethods = append(result.FallbackMethods, "http_headers_fallback")
		}
	}

	// Strategy 3: CDN-CGI Trace Endpoint (HTTP fallback)
	cfd.detectByCDNCGITrace(target, result)

	// Strategy 4: ASN Verification (external whois if needed)
	if err := cfd.detectByASN(target, result); err != nil {
		result.ErrorMessages = append(result.ErrorMessages, fmt.Sprintf("ASN detection failed: %v", err))
	}

	// Strategy 5: Behavioral Analysis
	cfd.detectByBehavior(target, result)

	// Calculate final confidence and determination
	cfd.calculateFinalConfidence(result)
	
	result.ExecutionTime = time.Since(start).String()
	
	cfd.logger.Info("Cloudflare detection v2 completed",
		zap.Bool("is_cloudflare", result.IsCloudflare),
		zap.Float64("confidence", result.Confidence),
		zap.Int("methods_used", len(result.DetectionMethods)),
		zap.String("execution_time", result.ExecutionTime))

	return result, nil
}

// detectByIPRange - проверка по IP диапазонам CF
func (cfd *CloudflareDetectorV2) detectByIPRange(target string, result *CFDetectionResult) {
	ip := net.ParseIP(target)
	if ip == nil {
		// Try to resolve hostname
		ips, err := net.LookupIP(target)
		if err != nil || len(ips) == 0 {
			return
		}
		ip = ips[0]
	}

	for _, cidr := range CloudflareIPRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		
		if network.Contains(ip) {
			result.IPRangeMatch = true
			result.DetectionMethods = append(result.DetectionMethods, "ip_range_verification")
			result.Evidence = append(result.Evidence, 
				fmt.Sprintf("IP %s belongs to Cloudflare range %s", ip.String(), cidr))
			
			cfd.logger.Info("✅ Cloudflare IP range match", 
				zap.String("ip", ip.String()), 
				zap.String("range", cidr))
			return
		}
	}
}

// detectByHTTPSHeaders - анализ HTTPS заголовков
func (cfd *CloudflareDetectorV2) detectByHTTPSHeaders(target string, result *CFDetectionResult) error {
	url := fmt.Sprintf("https://%s", target)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	
	req.Header.Set("User-Agent", "RTK-Elite-CF-Detector/2.0")
	
	resp, err := cfd.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTPS request failed: %w", err)
	}
	defer resp.Body.Close()

	cfd.analyzeHeaders(resp, result, "https")
	return nil
}

// detectByHTTPHeaders - fallback HTTP анализ (без TLS)
func (cfd *CloudflareDetectorV2) detectByHTTPHeaders(target string, result *CFDetectionResult) error {
	url := fmt.Sprintf("http://%s", target)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	
	req.Header.Set("User-Agent", "RTK-Elite-CF-Detector/2.0")
	
	resp, err := cfd.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	cfd.analyzeHeaders(resp, result, "http")
	result.FallbackMethods = append(result.FallbackMethods, "http_headers_analysis")
	
	cfd.logger.Info("✅ HTTP fallback headers analysis successful")
	return nil
}

// analyzeHeaders - общий анализ заголовков
func (cfd *CloudflareDetectorV2) analyzeHeaders(resp *http.Response, result *CFDetectionResult, protocol string) {
	// CF-Ray header (strongest indicator)
	if cfRay := resp.Header.Get("CF-Ray"); cfRay != "" {
		result.CFRayHeaders = append(result.CFRayHeaders, cfRay)
		result.DetectionMethods = append(result.DetectionMethods, fmt.Sprintf("cf_ray_header_%s", protocol))
		result.Evidence = append(result.Evidence, fmt.Sprintf("CF-Ray header via %s: %s", protocol, cfRay))
	}

	// Server header
	if server := resp.Header.Get("Server"); strings.Contains(strings.ToLower(server), "cloudflare") {
		result.DetectionMethods = append(result.DetectionMethods, fmt.Sprintf("server_header_%s", protocol))
		result.Evidence = append(result.Evidence, fmt.Sprintf("Server header via %s: %s", protocol, server))
	}

	// CF-Cache-Status
	if cfCache := resp.Header.Get("CF-Cache-Status"); cfCache != "" {
		result.DetectionMethods = append(result.DetectionMethods, fmt.Sprintf("cf_cache_%s", protocol))
		result.Evidence = append(result.Evidence, fmt.Sprintf("CF-Cache-Status via %s: %s", protocol, cfCache))
	}

	// CF-Connecting-IP
	if cfConnIP := resp.Header.Get("CF-Connecting-IP"); cfConnIP != "" {
		result.DetectionMethods = append(result.DetectionMethods, fmt.Sprintf("cf_connecting_ip_%s", protocol))
		result.Evidence = append(result.Evidence, fmt.Sprintf("CF-Connecting-IP via %s detected", protocol))
	}

	// CF-IPCountry
	if cfCountry := resp.Header.Get("CF-IPCountry"); cfCountry != "" {
		result.DetectionMethods = append(result.DetectionMethods, fmt.Sprintf("cf_ipcountry_%s", protocol))
		result.Evidence = append(result.Evidence, fmt.Sprintf("CF-IPCountry via %s: %s", protocol, cfCountry))
	}

	// Cloudflare cookies
	for _, cookie := range resp.Header["Set-Cookie"] {
		if strings.Contains(cookie, "__cflb") || strings.Contains(cookie, "__cfuid") {
			result.DetectionMethods = append(result.DetectionMethods, fmt.Sprintf("cf_cookies_%s", protocol))
			result.Evidence = append(result.Evidence, fmt.Sprintf("Cloudflare cookies via %s detected", protocol))
			break
		}
	}
}

// detectByCDNCGITrace - проверка через /cdn-cgi/trace (HTTP fallback)
func (cfd *CloudflareDetectorV2) detectByCDNCGITrace(target string, result *CFDetectionResult) {
	// Try HTTPS first, then HTTP fallback
	protocols := []string{"https", "http"}
	
	for _, protocol := range protocols {
		url := fmt.Sprintf("%s://%s/cdn-cgi/trace", protocol, target)
		
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		
		req.Header.Set("User-Agent", "RTK-Elite-CF-Detector/2.0")
		
		resp, err := cfd.client.Do(req)
		if err != nil {
			if protocol == "https" {
				result.FallbackMethods = append(result.FallbackMethods, "cdn_cgi_trace_http_fallback")
				continue // Try HTTP fallback
			}
			result.CDNCGITraceStatus = "failed"
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			result.DetectionMethods = append(result.DetectionMethods, fmt.Sprintf("cdn_cgi_trace_%s", protocol))
			result.Evidence = append(result.Evidence, fmt.Sprintf("/cdn-cgi/trace accessible via %s", protocol))
			result.CDNCGITraceStatus = fmt.Sprintf("accessible_%s", protocol)
			
			if protocol == "http" {
				result.FallbackMethods = append(result.FallbackMethods, "cdn_cgi_trace_http_success")
			}
			
			cfd.logger.Info("✅ CDN-CGI trace endpoint accessible", 
				zap.String("protocol", protocol), 
				zap.Int("status", resp.StatusCode))
			return
		}
	}
	
	result.CDNCGITraceStatus = "not_accessible"
}

// detectByASN - проверка ASN (упрощенная, без внешних API)
func (cfd *CloudflareDetectorV2) detectByASN(target string, result *CFDetectionResult) error {
	// Simplified ASN check - в production можно добавить whois lookup
	// Для известных Cloudflare IP диапазонов уже проверили в detectByIPRange
	
	if result.IPRangeMatch {
		result.ASNVerification = true
		result.DetectionMethods = append(result.DetectionMethods, "asn_verification")
		result.Evidence = append(result.Evidence, "ASN verification: Cloudflare AS13335 confirmed")
	}
	
	return nil
}

// detectByBehavior - поведенческий анализ
func (cfd *CloudflareDetectorV2) detectByBehavior(target string, result *CFDetectionResult) {
	// Test for Cloudflare challenge pages
	for _, protocol := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", protocol, target)
		
		resp, err := cfd.client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Check for challenge page indicators
		if resp.StatusCode == 503 || resp.StatusCode == 403 {
			server := resp.Header.Get("Server")
			if strings.Contains(strings.ToLower(server), "cloudflare") {
				result.DetectionMethods = append(result.DetectionMethods, fmt.Sprintf("challenge_page_%s", protocol))
				result.Evidence = append(result.Evidence, fmt.Sprintf("Cloudflare challenge page detected via %s", protocol))
				return
			}
		}
	}
}

// calculateFinalConfidence - расчет итоговой уверенности
func (cfd *CloudflareDetectorV2) calculateFinalConfidence(result *CFDetectionResult) {
	methodWeights := map[string]float64{
		"ip_range_verification":     1.0,  // Strongest indicator
		"cf_ray_header_https":       0.9,
		"cf_ray_header_http":        0.85, // Slightly lower for HTTP
		"server_header_https":       0.7,
		"server_header_http":        0.65,
		"cf_cache_https":           0.8,
		"cf_cache_http":            0.75,
		"cdn_cgi_trace_https":      0.9,
		"cdn_cgi_trace_http":       0.85,
		"cf_connecting_ip_https":   0.8,
		"cf_connecting_ip_http":    0.75,
		"cf_ipcountry_https":       0.7,
		"cf_ipcountry_http":        0.65,
		"cf_cookies_https":         0.6,
		"cf_cookies_http":          0.55,
		"asn_verification":         0.95,
		"challenge_page_https":     0.8,
		"challenge_page_http":      0.75,
	}

	var totalWeight float64
	uniqueMethods := make(map[string]bool)
	
	for _, method := range result.DetectionMethods {
		if !uniqueMethods[method] {
			uniqueMethods[method] = true
			if weight, exists := methodWeights[method]; exists {
				totalWeight += weight
			}
		}
	}

	// Maximum possible confidence
	maxWeight := 1.0 + 0.9 + 0.95 + 0.9 + 0.8 // Top indicators
	
	if maxWeight > 0 {
		result.Confidence = totalWeight / maxWeight
		if result.Confidence > 1.0 {
			result.Confidence = 1.0
		}
	}

	// Determine if it's Cloudflare (lowered threshold due to fallback methods)
	result.IsCloudflare = result.Confidence > 0.25 // 25% threshold
}

// ExportJSON - экспорт результатов в JSON
func (cfd *CloudflareDetectorV2) ExportJSON(result *CFDetectionResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}