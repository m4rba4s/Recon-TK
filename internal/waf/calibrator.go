package waf

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

type WAFCalibrator struct {
	logger     *zap.Logger
	client     *http.Client
	calibData  map[string]*CalibrationData
	configDir  string
}

type CalibrationData struct {
	Target              string                    `json:"target"`
	Timestamp           time.Time                 `json:"timestamp"`
	BaselineResponses   map[string]*ResponseSig   `json:"baseline_responses"`
	WAFSignatures       []WAFSignature            `json:"waf_signatures"`
	FilterRules         []FilterRule              `json:"filter_rules"`
	CalibrationPayloads []CalibrationPayload      `json:"calibration_payloads"`
	NoiseProfile        *NoiseProfile             `json:"noise_profile"`
}

type ResponseSig struct {
	StatusCode    int               `json:"status_code"`
	ContentLength int               `json:"content_length"`
	ResponseTime  time.Duration     `json:"response_time"`
	Headers       map[string]string `json:"headers"`
	BodyHash      string            `json:"body_hash"`
	ContentType   string            `json:"content_type"`
	Fingerprint   string            `json:"fingerprint"`
}

type WAFSignature struct {
	PayloadType    string `json:"payload_type"`
	TriggerPattern string `json:"trigger_pattern"`
	BlockedStatus  int    `json:"blocked_status"`
	BlockedLength  int    `json:"blocked_length"`
	BlockedHash    string `json:"blocked_hash"`
	DetectionRate  float64 `json:"detection_rate"`
}

type FilterRule struct {
	RuleType    string `json:"rule_type"`
	Pattern     string `json:"pattern"`
	Confidence  float64 `json:"confidence"`
	Description string `json:"description"`
}

type CalibrationPayload struct {
	Name        string `json:"name"`
	Payload     string `json:"payload"`
	PayloadType string `json:"payload_type"`
	Benign      bool   `json:"benign"`
	Expected    string `json:"expected"`
}

type NoiseProfile struct {
	CommonStatusCodes map[int]float64     `json:"common_status_codes"`
	TypicalSizes      []int              `json:"typical_sizes"`
	ResponsePatterns  map[string]float64 `json:"response_patterns"`
	HeaderVariations  map[string][]string `json:"header_variations"`
}

var calibrationPayloads = []CalibrationPayload{
	// Benign requests
	{"normal_get", "GET /index.html HTTP/1.1", "http", true, "normal"},
	{"normal_post", "test=value", "form", true, "normal"},
	{"normal_json", `{"test": "value"}`, "json", true, "normal"},
	
	// SQL Injection tests
	{"sqli_union", "' UNION SELECT 1,2,3--", "sqli", false, "blocked"},
	{"sqli_error", "' AND 1=1--", "sqli", false, "blocked"},
	{"sqli_blind", "' OR SLEEP(5)--", "sqli", false, "blocked"},
	
	// XSS tests
	{"xss_script", "<script>alert('test')</script>", "xss", false, "blocked"},
	{"xss_img", "<img src=x onerror=alert(1)>", "xss", false, "blocked"},
	{"xss_encoded", "%3Cscript%3Ealert%281%29%3C%2Fscript%3E", "xss", false, "blocked"},
	
	// Path traversal
	{"lfi_basic", "../../../../etc/passwd", "lfi", false, "blocked"},
	{"lfi_encoded", "..%2F..%2F..%2F..%2Fetc%2Fpasswd", "lfi", false, "blocked"},
	
	// Command injection
	{"cmd_pipe", "; cat /etc/passwd", "cmd", false, "blocked"},
	{"cmd_backtick", "`whoami`", "cmd", false, "blocked"},
	
	// LDAP injection
	{"ldap_basic", ")(cn=*))(|(cn=*", "ldap", false, "blocked"},
}

func NewWAFCalibrator(logger *zap.Logger, configDir string) *WAFCalibrator {
	return &WAFCalibrator{
		logger:    logger,
		client:    &http.Client{Timeout: 30 * time.Second},
		calibData: make(map[string]*CalibrationData),
		configDir: configDir,
	}
}

func (wc *WAFCalibrator) CalibrateTarget(ctx context.Context, target string) (*CalibrationData, error) {
	wc.logger.Info("Starting WAF calibration",
		zap.String("target", target),
		zap.Int("test_payloads", len(calibrationPayloads)))

	calib := &CalibrationData{
		Target:              target,
		Timestamp:           time.Now(),
		BaselineResponses:   make(map[string]*ResponseSig),
		WAFSignatures:       make([]WAFSignature, 0),
		FilterRules:         make([]FilterRule, 0),
		CalibrationPayloads: calibrationPayloads,
		NoiseProfile:        &NoiseProfile{
			CommonStatusCodes: make(map[int]float64),
			TypicalSizes:      make([]int, 0),
			ResponsePatterns:  make(map[string]float64),
			HeaderVariations:  make(map[string][]string),
		},
	}

	// Step 1: Establish baseline with benign requests
	if err := wc.establishBaseline(ctx, target, calib); err != nil {
		return nil, fmt.Errorf("baseline establishment failed: %w", err)
	}

	// Step 2: Test attack payloads
	if err := wc.testAttackPayloads(ctx, target, calib); err != nil {
		return nil, fmt.Errorf("attack payload testing failed: %w", err)
	}

	// Step 3: Generate filter rules
	wc.generateFilterRules(calib)

	// Step 4: Build noise profile
	wc.buildNoiseProfile(calib)

	// Step 5: Save calibration data
	if err := wc.saveCalibration(target, calib); err != nil {
		wc.logger.Warn("Failed to save calibration data", zap.Error(err))
	}

	wc.calibData[target] = calib

	wc.logger.Info("WAF calibration completed",
		zap.String("target", target),
		zap.Int("waf_signatures", len(calib.WAFSignatures)),
		zap.Int("filter_rules", len(calib.FilterRules)))

	return calib, nil
}

func (wc *WAFCalibrator) establishBaseline(ctx context.Context, target string, calib *CalibrationData) error {
	wc.logger.Info("Establishing baseline responses")

	baselineTests := []struct {
		name string
		url  string
		method string
		body string
	}{
		{"root", fmt.Sprintf("http://%s/", target), "GET", ""},
		{"index", fmt.Sprintf("http://%s/index.html", target), "GET", ""},
		{"404", fmt.Sprintf("http://%s/nonexistent.html", target), "GET", ""},
		{"post_form", fmt.Sprintf("http://%s/", target), "POST", "test=value"},
	}

	for _, test := range baselineTests {
		sig, err := wc.getResponseSignature(ctx, test.url, test.method, test.body)
		if err != nil {
			wc.logger.Warn("Failed to get baseline response",
				zap.String("test", test.name),
				zap.Error(err))
			continue
		}
		calib.BaselineResponses[test.name] = sig
	}

	return nil
}

func (wc *WAFCalibrator) testAttackPayloads(ctx context.Context, target string, calib *CalibrationData) error {
	wc.logger.Info("Testing attack payloads for WAF detection")

	baseURL := fmt.Sprintf("http://%s/", target)

	for _, payload := range calibrationPayloads {
		if payload.Benign {
			continue // Skip benign payloads
		}

		// Test payload in different contexts
		testURLs := []string{
			fmt.Sprintf("%s?test=%s", baseURL, payload.Payload),
			baseURL, // POST body
		}

		var detectionCount int
		var totalTests int

		for _, url := range testURLs {
			totalTests++
			var sig *ResponseSig
			var err error

			if strings.Contains(url, "?") {
				sig, err = wc.getResponseSignature(ctx, url, "GET", "")
			} else {
				sig, err = wc.getResponseSignature(ctx, url, "POST", payload.Payload)
			}

			if err != nil {
				continue
			}

			// Check if response indicates blocking
			if wc.isBlockedResponse(sig, calib.BaselineResponses) {
				detectionCount++
			}
		}

		if detectionCount > 0 {
			signature := WAFSignature{
				PayloadType:   payload.PayloadType,
				TriggerPattern: payload.Payload,
				DetectionRate: float64(detectionCount) / float64(totalTests),
			}
			calib.WAFSignatures = append(calib.WAFSignatures, signature)
		}
	}

	return nil
}

func (wc *WAFCalibrator) getResponseSignature(ctx context.Context, url, method, body string) (*ResponseSig, error) {
	var req *http.Request
	var err error

	if body != "" {
		req, err = http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
		if method == "POST" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}

	if err != nil {
		return nil, err
	}

	start := time.Now()
	resp, err := wc.client.Do(req)
	responseTime := time.Since(start)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	sig := &ResponseSig{
		StatusCode:    resp.StatusCode,
		ContentLength: len(bodyBytes),
		ResponseTime:  responseTime,
		Headers:       make(map[string]string),
		BodyHash:      fmt.Sprintf("%x", md5.Sum(bodyBytes)),
		ContentType:   resp.Header.Get("Content-Type"),
	}

	// Capture important headers
	importantHeaders := []string{"Server", "X-Powered-By", "Set-Cookie", "Location", "CF-Ray"}
	for _, header := range importantHeaders {
		if value := resp.Header.Get(header); value != "" {
			sig.Headers[header] = value
		}
	}

	// Generate fingerprint
	sig.Fingerprint = wc.generateFingerprint(sig)

	return sig, nil
}

func (wc *WAFCalibrator) isBlockedResponse(sig *ResponseSig, baseline map[string]*ResponseSig) bool {
	// Common WAF blocking indicators
	blockingIndicators := []func(*ResponseSig) bool{
		func(s *ResponseSig) bool { return s.StatusCode == 403 || s.StatusCode == 406 || s.StatusCode == 503 },
		func(s *ResponseSig) bool { return s.ContentLength < 100 && strings.Contains(s.ContentType, "text/html") },
		func(s *ResponseSig) bool { return s.ResponseTime < 10*time.Millisecond }, // Too fast = cached block page
	}

	for _, indicator := range blockingIndicators {
		if indicator(sig) {
			return true
		}
	}

	// Compare with baseline
	if baseline != nil {
		for _, baseSig := range baseline {
			if sig.StatusCode != baseSig.StatusCode || 
			   abs(sig.ContentLength-baseSig.ContentLength) > 100 {
				return true
			}
		}
	}

	return false
}

func (wc *WAFCalibrator) generateFilterRules(calib *CalibrationData) {
	wc.logger.Info("Generating filter rules from calibration data")

	// Generate rules based on detected signatures
	for _, sig := range calib.WAFSignatures {
		if sig.DetectionRate > 0.5 {
			rule := FilterRule{
				RuleType:    "payload_signature",
				Pattern:     sig.TriggerPattern,
				Confidence:  sig.DetectionRate,
				Description: fmt.Sprintf("WAF blocks %s payloads with %.1f%% detection rate", 
					sig.PayloadType, sig.DetectionRate*100),
			}
			calib.FilterRules = append(calib.FilterRules, rule)
		}
	}

	// Add status code rules
	if baseline, exists := calib.BaselineResponses["root"]; exists {
		rule := FilterRule{
			RuleType:    "status_filter",
			Pattern:     fmt.Sprintf("ignore_status_%d", baseline.StatusCode),
			Confidence:  0.9,
			Description: fmt.Sprintf("Normal responses use status %d", baseline.StatusCode),
		}
		calib.FilterRules = append(calib.FilterRules, rule)
	}
}

func (wc *WAFCalibrator) buildNoiseProfile(calib *CalibrationData) {
	// Analyze baseline responses to build noise profile
	for _, sig := range calib.BaselineResponses {
		calib.NoiseProfile.CommonStatusCodes[sig.StatusCode]++
		calib.NoiseProfile.TypicalSizes = append(calib.NoiseProfile.TypicalSizes, sig.ContentLength)
		
		if sig.ContentType != "" {
			calib.NoiseProfile.ResponsePatterns[sig.ContentType]++
		}
	}

	// Normalize frequencies
	total := float64(len(calib.BaselineResponses))
	for code := range calib.NoiseProfile.CommonStatusCodes {
		calib.NoiseProfile.CommonStatusCodes[code] /= total
	}
	
	for pattern := range calib.NoiseProfile.ResponsePatterns {
		calib.NoiseProfile.ResponsePatterns[pattern] /= total
	}
}

func (wc *WAFCalibrator) generateFingerprint(sig *ResponseSig) string {
	fingerprint := fmt.Sprintf("%d_%d_%s", 
		sig.StatusCode, 
		sig.ContentLength/100*100, // Round to nearest 100
		sig.ContentType)
	return fmt.Sprintf("%x", md5.Sum([]byte(fingerprint)))[:8]
}

func (wc *WAFCalibrator) saveCalibration(target string, calib *CalibrationData) error {
	if wc.configDir == "" {
		return nil
	}

	filename := fmt.Sprintf("waf_calib_%s.json", strings.ReplaceAll(target, ":", "_"))
	filepath := filepath.Join(wc.configDir, filename)

	data, err := json.MarshalIndent(calib, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath, data, 0644)
}

func (wc *WAFCalibrator) LoadCalibration(target string) (*CalibrationData, error) {
	filename := fmt.Sprintf("waf_calib_%s.json", strings.ReplaceAll(target, ":", "_"))
	filepath := filepath.Join(wc.configDir, filename)

	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var calib CalibrationData
	if err := json.Unmarshal(data, &calib); err != nil {
		return nil, err
	}

	wc.calibData[target] = &calib
	return &calib, nil
}

func (wc *WAFCalibrator) ShouldIgnoreResponse(target string, sig *ResponseSig) bool {
	calib, exists := wc.calibData[target]
	if !exists {
		return false
	}

	// Apply filter rules
	for _, rule := range calib.FilterRules {
		if rule.Confidence > 0.8 && wc.matchesRule(rule, sig) {
			return true
		}
	}

	return false
}

func (wc *WAFCalibrator) matchesRule(rule FilterRule, sig *ResponseSig) bool {
	switch rule.RuleType {
	case "status_filter":
		pattern := strings.TrimPrefix(rule.Pattern, "ignore_status_")
		if status := parseInt(pattern); status == sig.StatusCode {
			return true
		}
	case "payload_signature":
		// This would be used when scanning with specific payloads
		return false
	}
	return false
}

func parseInt(s string) int {
	if len(s) == 0 {
		return 0
	}
	var result int
	fmt.Sscanf(s, "%d", &result)
	return result
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}