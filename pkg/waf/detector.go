
package waf

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
)

type WAFSignature struct {
	Name    string
	Headers map[string]string
	Body    []string
	Status  []int
}

type WAFResult struct {
	Target      string        `json:"target"`
	WAFDetected bool          `json:"waf_detected"`
	WAFType     string        `json:"waf_type"`
	Confidence  float64       `json:"confidence"`
	Signatures  []string      `json:"signatures_matched"`
	Response    ResponseInfo  `json:"response_info"`
	Bypasses    []BypassTest  `json:"bypass_tests"`
	ScanTime    time.Duration `json:"scan_time"`
}

type ResponseInfo struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body_snippet"`
	Size       int                 `json:"content_length"`
}

type BypassTest struct {
	Technique string `json:"technique"`
	Payload   string `json:"payload"`
	Success   bool   `json:"success"`
	Response  int    `json:"response_code"`
}

type Detector struct {
	Target     string
	Timeout    time.Duration
	UserAgent  string
	Silent     bool
	TestBypass bool
	client     *http.Client
	logger     *logrus.Logger
}

func NewDetector(target string, options ...func(*Detector)) *Detector {
	d := &Detector{
		Target:     target,
		Timeout:    time.Second * 10,
		UserAgent:  "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",
		Silent:     false,
		TestBypass: false,
		logger:     logrus.New(),
	}

	for _, option := range options {
		option(d)
	}

	d.client = &http.Client{
		Timeout: d.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if d.Silent {
		d.logger.SetLevel(logrus.WarnLevel)
	}

	return d
}

func WithSilent() func(*Detector) {
	return func(d *Detector) {
		d.Silent = true
	}
}

func WithBypassTesting() func(*Detector) {
	return func(d *Detector) {
		d.TestBypass = true
	}
}

func WithTimeout(timeout time.Duration) func(*Detector) {
	return func(d *Detector) {
		d.Timeout = timeout
	}
}

func (d *Detector) Detect(ctx context.Context) (*WAFResult, error) {
	startTime := time.Now()

	if !d.Silent {
		color.Cyan("🛡️  Starting WAF detection for %s", d.Target)
	}

	result := &WAFResult{
		Target:      d.Target,
		WAFDetected: false,
		Confidence:  0.0,
		Signatures:  []string{},
		Bypasses:    []BypassTest{},
	}

	baseline, err := d.makeRequest(ctx, "GET", "/", "", nil)
	if err != nil {
		return nil, fmt.Errorf("baseline request failed: %w", err)
	}

	result.Response = baseline

	signatures := d.getWAFSignatures()
	var matches []WAFSignature

	for _, sig := range signatures {
		if d.matchSignature(baseline, sig) {
			matches = append(matches, sig)
			result.Signatures = append(result.Signatures, sig.Name)
		}
	}

	if len(matches) > 0 {
		result.WAFDetected = true
		result.WAFType = d.determineWAFType(matches)
		result.Confidence = d.calculateConfidence(matches, baseline)

		if !d.Silent {
			color.Red("🚨 WAF Detected: %s (Confidence: %.2f)", result.WAFType, result.Confidence)
		}
	} else {
		detected, wafType := d.testDetectionPayloads(ctx)
		if detected {
			result.WAFDetected = true
			result.WAFType = wafType
			result.Confidence = 0.7
		}
	}

	if d.TestBypass && result.WAFDetected {
		if !d.Silent {
			color.Yellow("🔓 Testing WAF bypass techniques...")
		}
		result.Bypasses = d.testBypassTechniques(ctx)
	}

	result.ScanTime = time.Since(startTime)

	if !d.Silent {
		d.printResults(result)
	}

	return result, nil
}

func (d *Detector) makeRequest(ctx context.Context, method, path, payload string, headers map[string]string) (ResponseInfo, error) {
	var body io.Reader
	if payload != "" {
		body = strings.NewReader(payload)
	}

	url := d.Target + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return ResponseInfo{}, err
	}

	req.Header.Set("User-Agent", d.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return ResponseInfo{}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return ResponseInfo{}, err
	}

	bodyStr := string(bodyBytes)
	if len(bodyStr) > 1000 {
		bodyStr = bodyStr[:1000] + "..."
	}

	return ResponseInfo{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       bodyStr,
		Size:       len(bodyBytes),
	}, nil
}

func (d *Detector) getWAFSignatures() []WAFSignature {
	return []WAFSignature{
		{
			Name: "CloudFlare",
			Headers: map[string]string{
				"server":     "cloudflare",
				"cf-ray":     "",
				"cf-cache-status": "",
			},
		},
		{
			Name: "AWS WAF",
			Headers: map[string]string{
				"server": "awselb",
			},
			Body: []string{"The request could not be satisfied"},
		},
		{
			Name: "Akamai",
			Headers: map[string]string{
				"server": "AkamaiGHost",
			},
			Body: []string{"Access Denied", "Reference #"},
		},
		{
			Name: "Incapsula",
			Headers: map[string]string{
				"x-iinfo": "",
			},
			Body: []string{"Request unsuccessful", "Incapsula"},
		},
		{
			Name: "ModSecurity",
			Body: []string{
				"Not Acceptable!",
				"You don't have permission to access",
				"mod_security",
			},
			Status: []int{406, 403},
		},
		{
			Name: "Sucuri",
			Headers: map[string]string{
				"server": "Sucuri/Cloudproxy",
			},
			Body: []string{"Access Denied", "Sucuri Website Firewall"},
		},
		{
			Name: "StackPath",
			Headers: map[string]string{
				"server": "StackPath",
			},
		},
		{
			Name: "F5 BIG-IP",
			Headers: map[string]string{
				"server": "BIG-IP",
			},
			Body: []string{"The requested URL was rejected"},
		},
		{
			Name: "Barracuda",
			Body: []string{
				"You have been blocked",
				"Barracuda",
				"BWAF",
			},
		},
		{
			Name: "Cloudfront",
			Headers: map[string]string{
				"server": "CloudFront",
			},
		},
	}
}

func (d *Detector) matchSignature(response ResponseInfo, sig WAFSignature) bool {
	score := 0
	total := 0

	for headerKey, expectedValue := range sig.Headers {
		total++
		for key, values := range response.Headers {
			if strings.ToLower(key) == strings.ToLower(headerKey) {
				if expectedValue == "" || strings.Contains(strings.ToLower(strings.Join(values, " ")), strings.ToLower(expectedValue)) {
					score++
					break
				}
			}
		}
	}

	for _, bodyPattern := range sig.Body {
		total++
		if strings.Contains(strings.ToLower(response.Body), strings.ToLower(bodyPattern)) {
			score++
		}
	}

	for _, statusCode := range sig.Status {
		total++
		if response.StatusCode == statusCode {
			score++
		}
	}

	return total > 0 && float64(score)/float64(total) >= 0.5
}

func (d *Detector) determineWAFType(matches []WAFSignature) string {
	if len(matches) == 0 {
		return "Unknown WAF"
	}

	return matches[0].Name
}

func (d *Detector) calculateConfidence(matches []WAFSignature, response ResponseInfo) float64 {
	if len(matches) == 0 {
		return 0.0
	}

	baseConfidence := 0.5
	
	if len(matches) > 1 {
		baseConfidence += 0.2
	}

	for key := range response.Headers {
		key = strings.ToLower(key)
		if strings.Contains(key, "cloudflare") || strings.Contains(key, "cf-") {
			baseConfidence += 0.3
		}
		if strings.Contains(key, "akamai") || strings.Contains(key, "incap") {
			baseConfidence += 0.3
		}
	}

	if baseConfidence > 1.0 {
		baseConfidence = 1.0
	}

	return baseConfidence
}

func (d *Detector) testDetectionPayloads(ctx context.Context) (bool, string) {
	payloads := []string{
		"/?test=<script>alert(1)</script>",
		"/?test=' OR '1'='1",
		"/?test=../../../etc/passwd",
		"/?test=<img src=x onerror=alert(1)>",
		"/?test=1' UNION SELECT NULL--",
	}

	suspiciousResponses := 0
	
	for _, payload := range payloads {
		resp, err := d.makeRequest(ctx, "GET", payload, "", nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 444 {
			suspiciousResponses++
		}

		if strings.Contains(strings.ToLower(resp.Body), "blocked") ||
		   strings.Contains(strings.ToLower(resp.Body), "forbidden") ||
		   strings.Contains(strings.ToLower(resp.Body), "security") {
			suspiciousResponses++
		}
	}

	if float64(suspiciousResponses)/float64(len(payloads)) > 0.6 {
		return true, "Generic WAF"
	}

	return false, ""
}

func (d *Detector) testBypassTechniques(ctx context.Context) []BypassTest {
	var results []BypassTest

	techniques := []struct {
		name    string
		payload string
		headers map[string]string
	}{
		{
			name:    "Case Variation",
			payload: "/?test=<ScRiPt>alert(1)</ScRiPt>",
		},
		{
			name:    "Double Encoding",
			payload: "/?test=%253Cscript%253Ealert(1)%253C/script%253E",
		},
		{
			name:    "Unicode Encoding",
			payload: "/?test=\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
		},
		{
			name:    "HTTP Parameter Pollution",
			payload: "/?test=<script>&test=alert(1)</script>",
		},
		{
			name:    "X-Forwarded-For",
			payload: "/?test=<script>alert(1)</script>",
			headers: map[string]string{"X-Forwarded-For": "127.0.0.1"},
		},
		{
			name:    "X-Real-IP",
			payload: "/?test=<script>alert(1)</script>",
			headers: map[string]string{"X-Real-IP": "127.0.0.1"},
		},
		{
			name:    "Content-Type Manipulation",
			payload: "/?test=<script>alert(1)</script>",
			headers: map[string]string{"Content-Type": "application/json"},
		},
	}

	for _, tech := range techniques {
		resp, err := d.makeRequest(ctx, "GET", tech.payload, "", tech.headers)
		if err != nil {
			continue
		}

		success := resp.StatusCode != 403 && resp.StatusCode != 406 && resp.StatusCode != 444

		results = append(results, BypassTest{
			Technique: tech.name,
			Payload:   tech.payload,
			Success:   success,
			Response:  resp.StatusCode,
		})
	}

	return results
}

func (d *Detector) printResults(result *WAFResult) {
	fmt.Println()
	color.Green("🛡️  WAF Detection Results for %s", result.Target)
	color.White("=" + strings.Repeat("=", 50))

	if result.WAFDetected {
		color.Red("WAF Detected: %s", result.WAFType)
		color.Yellow("Confidence: %.2f", result.Confidence)
		
		if len(result.Signatures) > 0 {
			color.Cyan("Signatures matched: %s", strings.Join(result.Signatures, ", "))
		}

		if len(result.Bypasses) > 0 {
			fmt.Println()
			color.Cyan("Bypass test results:")
			for _, bypass := range result.Bypasses {
				status := color.RedString("FAILED")
				if bypass.Success {
					status = color.GreenString("SUCCESS")
				}
				fmt.Printf("  %s: %s (HTTP %d)\n", bypass.Technique, status, bypass.Response)
			}
		}
	} else {
		color.Green("No WAF detected")
	}

	color.Cyan("Scan time: %v", result.ScanTime)
}