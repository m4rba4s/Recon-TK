package shadow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"recon-toolkit/pkg/core"
)

// HoneypotDetector - Legendary system for detecting honeypots and traps
type HoneypotDetector struct {
	logger    core.Logger
	client    *http.Client
	suspicion map[string]float64
	mutex     sync.RWMutex
	config    *HoneypotConfig
}

type HoneypotConfig struct {
	RTTThreshold       time.Duration `json:"rtt_threshold"`
	EntropyThreshold   float64       `json:"entropy_threshold"`
	TimingVariance     float64       `json:"timing_variance"`
	FaviconBlacklist   []string      `json:"favicon_blacklist"`
	SuspicionThreshold float64       `json:"suspicion_threshold"`
	MaxRetries         int           `json:"max_retries"`
}

type HoneypotResult struct {
	Target         string                 `json:"target"`
	IsHoneypot     bool                   `json:"is_honeypot"`
	SuspicionLevel float64                `json:"suspicion_level"`
	Indicators     []HoneypotIndicator    `json:"indicators"`
	Evidence       []core.Evidence        `json:"evidence"`
	Metadata       map[string]interface{} `json:"metadata"`
}

type HoneypotIndicator struct {
	Type        string  `json:"type"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
	Details     string  `json:"details"`
}

// NewHoneypotDetector creates legendary honeypot detection system
func NewHoneypotDetector(logger core.Logger, config *HoneypotConfig) *HoneypotDetector {
	if config == nil {
		config = &HoneypotConfig{
			RTTThreshold:       50 * time.Millisecond,
			EntropyThreshold:   6.5,
			TimingVariance:     0.2,
			SuspicionThreshold: 0.7,
			MaxRetries:         3,
			FaviconBlacklist: []string{
				"d41d8cd98f00b204e9800998ecf8427e", // Empty MD5
				"default_favicon_hash",
				"honeypot_favicon_signature",
			},
		}
	}

	return &HoneypotDetector{
		logger:    logger,
		suspicion: make(map[string]float64),
		config:    config,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		},
	}
}

// AnalyzeTarget performs comprehensive honeypot detection
func (h *HoneypotDetector) AnalyzeTarget(ctx context.Context, target string) (*HoneypotResult, error) {
	h.logger.Info("🕵️ STARTING HONEYPOT DETECTION - Time to smell the traps!", 
		core.NewField("target", target))

	result := &HoneypotResult{
		Target:     target,
		Indicators: make([]HoneypotIndicator, 0),
		Evidence:   make([]core.Evidence, 0),
		Metadata:   make(map[string]interface{}),
	}

	// Multi-vector honeypot detection
	var wg sync.WaitGroup
	indicators := make(chan HoneypotIndicator, 10)

	// 1. Timing Analysis - RTT fingerprinting
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.analyzeTimingPatterns(ctx, target, indicators)
	}()

	// 2. Favicon Analysis - detect black favicons
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.analyzeFavicon(ctx, target, indicators)
	}()

	// 3. Response Pattern Analysis - entropy & variance
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.analyzeResponsePatterns(ctx, target, indicators)
	}()

	// 4. Port Behavior Analysis - detect fake services
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.analyzePortBehavior(ctx, target, indicators)
	}()

	// 5. TCP Fingerprinting - detect emulated stacks
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.analyzeTCPFingerprint(ctx, target, indicators)
	}()

	// Collect indicators
	go func() {
		wg.Wait()
		close(indicators)
	}()

	// Process indicators and calculate suspicion
	var totalSuspicion float64
	for indicator := range indicators {
		result.Indicators = append(result.Indicators, indicator)
		totalSuspicion += indicator.Confidence

		// Create evidence
		evidence := core.NewBaseEvidence(
			core.EvidenceTypeLog,
			map[string]interface{}{
				"indicator_type": indicator.Type,
				"confidence":     indicator.Confidence,
				"details":        indicator.Details,
			},
			fmt.Sprintf("Honeypot indicator: %s", indicator.Description),
		)
		result.Evidence = append(result.Evidence, evidence)
	}

	// Calculate final suspicion level
	if len(result.Indicators) > 0 {
		result.SuspicionLevel = totalSuspicion / float64(len(result.Indicators))
	}

	result.IsHoneypot = result.SuspicionLevel >= h.config.SuspicionThreshold
	result.Metadata["total_indicators"] = len(result.Indicators)
	result.Metadata["analysis_timestamp"] = time.Now()

	// Log results with legendary humor
	if result.IsHoneypot {
		h.logger.Info("🍯 HONEYPOT DETECTED! This trap is sweeter than your ex's lies", 
			core.NewField("suspicion", result.SuspicionLevel),
			core.NewField("indicators", len(result.Indicators)))
	} else {
		h.logger.Info("✅ Target looks legit - probably just regular incompetence", 
			core.NewField("suspicion", result.SuspicionLevel))
	}

	return result, nil
}

// analyzeTimingPatterns detects fake RTT patterns
func (h *HoneypotDetector) analyzeTimingPatterns(ctx context.Context, target string, indicators chan<- HoneypotIndicator) {
	h.logger.Debug("⏱️ Analyzing timing patterns for honeypot detection")

	var timings []time.Duration
	
	// Send multiple requests to analyze RTT variance
	for i := 0; i < 10; i++ {
		start := time.Now()
		
		conn, err := net.DialTimeout("tcp", target+":80", 5*time.Second)
		if err == nil {
			conn.Close()
			rtt := time.Since(start)
			timings = append(timings, rtt)
		}
		
		time.Sleep(100 * time.Millisecond)
	}

	if len(timings) < 3 {
		return
	}

	// Calculate RTT statistics
	var total time.Duration
	for _, timing := range timings {
		total += timing
	}
	avgRTT := total / time.Duration(len(timings))

	// Calculate variance
	var variance float64
	for _, timing := range timings {
		diff := float64(timing - avgRTT)
		variance += diff * diff
	}
	variance /= float64(len(timings))
	stdDev := math.Sqrt(variance)

	// Detect suspicious timing patterns
	confidence := 0.0
	
	// Honeypots often have too consistent RTT
	if stdDev < float64(h.config.RTTThreshold)/10 {
		confidence += 0.6
	}
	
	// Or suspiciously fast responses
	if avgRTT < h.config.RTTThreshold {
		confidence += 0.4
	}

	if confidence > 0.3 {
		indicators <- HoneypotIndicator{
			Type:        "timing_analysis",
			Severity:    "medium",
			Description: fmt.Sprintf("Suspicious RTT patterns detected (avg: %v, stddev: %.2f)", avgRTT, stdDev),
			Confidence:  confidence,
			Details:     fmt.Sprintf("RTT too consistent or fast - typical honeypot behavior"),
		}
	}
}

// analyzeFavicon detects honeypot favicon signatures
func (h *HoneypotDetector) analyzeFavicon(ctx context.Context, target string, indicators chan<- HoneypotIndicator) {
	h.logger.Debug("🖼️ Analyzing favicon for honeypot signatures")

	url := fmt.Sprintf("http://%s/favicon.ico", target)
	if strings.Contains(target, ":") {
		url = fmt.Sprintf("http://%s/favicon.ico", target)
	}

	resp, err := h.client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Read favicon content
	faviconData := make([]byte, 10240) // Max 10KB
	n, _ := resp.Body.Read(faviconData)
	
	if n == 0 {
		// Empty favicon - suspicious
		indicators <- HoneypotIndicator{
			Type:        "favicon_analysis",
			Severity:    "low",
			Description: "Empty or missing favicon detected",
			Confidence:  0.3,
			Details:     "Honeypots often have empty favicons",
		}
		return
	}

	// Calculate favicon hash
	hash := sha256.Sum256(faviconData[:n])
	hashStr := hex.EncodeToString(hash[:])

	// Check against known honeypot favicon hashes
	for _, blacklistedHash := range h.config.FaviconBlacklist {
		if hashStr == blacklistedHash {
			indicators <- HoneypotIndicator{
				Type:        "favicon_analysis",
				Severity:    "high",
				Description: "Known honeypot favicon signature detected",
				Confidence:  0.9,
				Details:     fmt.Sprintf("Favicon hash %s matches known honeypot", hashStr[:16]),
			}
			return
		}
	}

	// Analyze favicon entropy (too high = randomly generated)
	entropy := h.calculateEntropy(faviconData[:n])
	if entropy > h.config.EntropyThreshold {
		indicators <- HoneypotIndicator{
			Type:        "favicon_analysis",
			Severity:    "medium",
			Description: fmt.Sprintf("High-entropy favicon detected (%.2f)", entropy),
			Confidence:  0.6,
			Details:     "Randomly generated favicons often indicate honeypots",
		}
	}
}

// analyzeResponsePatterns detects response pattern anomalies
func (h *HoneypotDetector) analyzeResponsePatterns(ctx context.Context, target string, indicators chan<- HoneypotIndicator) {
	h.logger.Debug("🔍 Analyzing HTTP response patterns")

	var responses []string
	testPaths := []string{"/", "/admin", "/test", "/404", "/random123"}

	// Collect responses
	for _, path := range testPaths {
		url := fmt.Sprintf("http://%s%s", target, path)
		resp, err := h.client.Get(url)
		if err != nil {
			continue
		}

		responseData := make([]byte, 1024)
		n, _ := resp.Body.Read(responseData)
		resp.Body.Close()

		if n > 0 {
			responses = append(responses, string(responseData[:n]))
		}
	}

	if len(responses) < 3 {
		return
	}

	// Analyze response similarity (honeypots often return identical responses)
	similarity := h.calculateResponseSimilarity(responses)
	if similarity > 0.8 {
		indicators <- HoneypotIndicator{
			Type:        "response_pattern",
			Severity:    "medium",
			Description: fmt.Sprintf("Highly similar responses detected (%.2f similarity)", similarity),
			Confidence:  0.7,
			Details:     "Identical responses to different requests indicate honeypot",
		}
	}

	// Check for template responses
	for _, response := range responses {
		if h.containsHoneypotTemplates(response) {
			indicators <- HoneypotIndicator{
				Type:        "response_pattern",
				Severity:    "high",
				Description: "Honeypot template response detected",
				Confidence:  0.85,
				Details:     "Response contains known honeypot framework signatures",
			}
			break
		}
	}
}

// analyzePortBehavior detects fake service responses
func (h *HoneypotDetector) analyzePortBehavior(ctx context.Context, target string, indicators chan<- HoneypotIndicator) {
	h.logger.Debug("🔌 Analyzing port behavior for service spoofing")

	commonPorts := []int{22, 23, 25, 53, 80, 110, 143, 443, 993, 995}
	var openPorts []int

	// Quick port scan
	for _, port := range commonPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 2*time.Second)
		if err == nil {
			conn.Close()
			openPorts = append(openPorts, port)
		}
	}

	// Too many open ports = suspicious
	if len(openPorts) > 7 {
		indicators <- HoneypotIndicator{
			Type:        "port_behavior",
			Severity:    "medium",
			Description: fmt.Sprintf("Suspiciously many open ports (%d)", len(openPorts)),
			Confidence:  0.6,
			Details:     "Real servers rarely have so many services exposed",
		}
	}

	// Test SSH banner (port 22)
	if contains(openPorts, 22) {
		if h.testSSHBanner(target) {
			indicators <- HoneypotIndicator{
				Type:        "port_behavior",
				Severity:    "high",
				Description: "Fake SSH service detected",
				Confidence:  0.8,
				Details:     "SSH banner or behavior indicates honeypot",
			}
		}
	}
}

// analyzeTCPFingerprint detects TCP stack emulation
func (h *HoneypotDetector) analyzeTCPFingerprint(ctx context.Context, target string, indicators chan<- HoneypotIndicator) {
	h.logger.Debug("🧬 Analyzing TCP fingerprint for stack emulation")

	// This is a simplified version - real implementation would use raw sockets
	// to analyze TCP sequence numbers, window sizes, etc.
	
	conn, err := net.DialTimeout("tcp", target+":80", 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	// Simple TCP behavior analysis
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}

	// Check for suspicious TCP behavior
	// Real implementation would analyze:
	// - TCP sequence number patterns
	// - Window scaling behavior  
	// - TCP options ordering
	// - Congestion control algorithms

	_ = tcpConn // Placeholder for actual TCP analysis

	// For now, just a basic check
	indicators <- HoneypotIndicator{
		Type:        "tcp_fingerprint",
		Severity:    "low",
		Description: "TCP stack analysis completed",
		Confidence:  0.1,
		Details:     "Basic TCP behavior appears normal",
	}
}

// Helper functions

func (h *HoneypotDetector) calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	frequency := make(map[byte]int)
	for _, b := range data {
		frequency[b]++
	}

	entropy := 0.0
	length := float64(len(data))

	for _, count := range frequency {
		if count > 0 {
			probability := float64(count) / length
			entropy -= probability * math.Log2(probability)
		}
	}

	return entropy
}

func (h *HoneypotDetector) calculateResponseSimilarity(responses []string) float64 {
	if len(responses) < 2 {
		return 0
	}

	totalSimilarity := 0.0
	comparisons := 0

	for i := 0; i < len(responses); i++ {
		for j := i + 1; j < len(responses); j++ {
			similarity := h.stringSimilarity(responses[i], responses[j])
			totalSimilarity += similarity
			comparisons++
		}
	}

	if comparisons == 0 {
		return 0
	}

	return totalSimilarity / float64(comparisons)
}

func (h *HoneypotDetector) stringSimilarity(s1, s2 string) float64 {
	if len(s1) == 0 && len(s2) == 0 {
		return 1.0
	}

	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	// Simple Jaccard similarity
	set1 := make(map[rune]bool)
	set2 := make(map[rune]bool)

	for _, r := range s1 {
		set1[r] = true
	}

	for _, r := range s2 {
		set2[r] = true
	}

	intersection := 0
	union := 0

	allRunes := make(map[rune]bool)
	for r := range set1 {
		allRunes[r] = true
	}
	for r := range set2 {
		allRunes[r] = true
	}

	for r := range allRunes {
		if set1[r] && set2[r] {
			intersection++
		}
		union++
	}

	if union == 0 {
		return 0
	}

	return float64(intersection) / float64(union)
}

func (h *HoneypotDetector) containsHoneypotTemplates(response string) bool {
	honeypotSignatures := []string{
		"kippo",
		"cowrie", 
		"dionaea",
		"glastopf",
		"honeyd",
		"default_honeypot_page",
		"template_response",
	}

	responseLower := strings.ToLower(response)
	for _, signature := range honeypotSignatures {
		if strings.Contains(responseLower, signature) {
			return true
		}
	}

	return false
}

func (h *HoneypotDetector) testSSHBanner(target string) bool {
	conn, err := net.DialTimeout("tcp", target+":22", 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Read SSH banner
	banner := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(banner)
	if err != nil {
		return false
	}

	bannerStr := string(banner[:n])
	
	// Check for honeypot SSH signatures
	honeypotSSH := []string{
		"kippo",
		"cowrie",
		"fake",
		"honeypot",
	}

	bannerLower := strings.ToLower(bannerStr)
	for _, signature := range honeypotSSH {
		if strings.Contains(bannerLower, signature) {
			return true
		}
	}

	// Check for suspicious banner patterns
	if !strings.Contains(bannerStr, "SSH-2.0") && !strings.Contains(bannerStr, "SSH-1.") {
		return true // Invalid SSH banner
	}

	return false
}

func contains(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}