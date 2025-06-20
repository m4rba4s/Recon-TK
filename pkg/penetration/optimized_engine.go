package penetration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"recon-toolkit/pkg/core"
)

// OptimizedPenetrationEngine - Lightweight, high-performance penetration engine
type OptimizedPenetrationEngine struct {
	logger     core.Logger
	target     string
	httpClient *http.Client
	results    []VulnResult
	mutex      sync.RWMutex
}

type VulnResult struct {
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Payload     string    `json:"payload"`
	StatusCode  int       `json:"status_code"`
	Confidence  float64   `json:"confidence"`
	PoC         string    `json:"poc"`
	Timestamp   time.Time `json:"timestamp"`
}

type OptimizedConfig struct {
	Target       string
	MaxThreads   int
	Timeout      time.Duration
	StealthMode  bool
}

// NewOptimizedEngine creates high-performance penetration engine
func NewOptimizedEngine(logger core.Logger, config *OptimizedConfig) *OptimizedPenetrationEngine {
	return &OptimizedPenetrationEngine{
		logger: logger,
		target: config.Target,
		results: make([]VulnResult, 0),
		httpClient: &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        config.MaxThreads,
				MaxIdleConnsPerHost: config.MaxThreads,
				DisableKeepAlives:   !config.StealthMode,
			},
		},
	}
}

// FastPenetrate performs optimized penetration testing
func (o *OptimizedPenetrationEngine) FastPenetrate(ctx context.Context) ([]VulnResult, error) {
	o.logger.Info("🚀 OPTIMIZED PENETRATION ENGINE - Maximum speed, maximum chaos!")

	start := time.Now()

	// High-value attack vectors only
	vectors := []struct {
		name    string
		payload string
		check   func(int, string) (float64, bool)
	}{
		{
			"Host Header Injection",
			"Host: evil.com",
			func(code int, body string) (float64, bool) {
				return 0.8, code == 409 || code >= 500
			},
		},
		{
			"HTTP Smuggling", 
			"Transfer-Encoding: chunked",
			func(code int, body string) (float64, bool) {
				return 0.9, code == 409 || code >= 500
			},
		},
		{
			"X-Forwarded-Host Bypass",
			"X-Forwarded-Host: localhost",
			func(code int, body string) (float64, bool) {
				return 0.6, code != 403 && code != 444
			},
		},
		{
			"Method Override",
			"X-HTTP-Method-Override: TRACE",
			func(code int, body string) (float64, bool) {
				return 0.7, code == 200 || code == 405
			},
		},
	}

	// Parallel execution for maximum speed
	var wg sync.WaitGroup
	for _, vector := range vectors {
		wg.Add(1)
		go func(v struct {
			name    string
			payload string
			check   func(int, string) (float64, bool)
		}) {
			defer wg.Done()
			o.testVector(v.name, v.payload, v.check)
		}(vector)
	}

	wg.Wait()

	duration := time.Since(start)
	o.logger.Info("⚡ Optimized penetration complete", 
		core.NewField("duration", duration),
		core.NewField("findings", len(o.results)))

	return o.results, nil
}

// testVector tests individual attack vector
func (o *OptimizedPenetrationEngine) testVector(name, payload string, check func(int, string) (float64, bool)) {
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s", o.target), nil)
	if err != nil {
		return
	}

	// Apply payload
	parts := strings.SplitN(payload, ":", 2)
	if len(parts) == 2 {
		req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)

	confidence, isVuln := check(resp.StatusCode, string(body[:n]))
	
	if isVuln {
		result := VulnResult{
			Type:       name,
			Severity:   o.getSeverity(confidence),
			Payload:    payload,
			StatusCode: resp.StatusCode,
			Confidence: confidence,
			PoC:        fmt.Sprintf(`curl -H "%s" http://%s`, payload, o.target),
			Timestamp:  time.Now(),
		}

		o.mutex.Lock()
		o.results = append(o.results, result)
		o.mutex.Unlock()

		o.logger.Info("🎯 VULNERABILITY FOUND!", 
			core.NewField("type", name),
			core.NewField("confidence", confidence))
	}
}

// getSeverity determines severity based on confidence
func (o *OptimizedPenetrationEngine) getSeverity(confidence float64) string {
	switch {
	case confidence >= 0.9:
		return "CRITICAL"
	case confidence >= 0.7:
		return "HIGH"
	case confidence >= 0.5:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// QuickScan performs ultra-fast vulnerability scan
func QuickScan(target string, logger core.Logger) ([]VulnResult, error) {
	config := &OptimizedConfig{
		Target:      target,
		MaxThreads:  20,
		Timeout:     5 * time.Second,
		StealthMode: true,
	}

	engine := NewOptimizedEngine(logger, config)
	return engine.FastPenetrate(context.Background())
}