
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type LLMProvider string

const (
	ProviderOpenAI    LLMProvider = "openai"
	ProviderLocal     LLMProvider = "local"
	ProviderOllama    LLMProvider = "ollama"
)

type PayloadRequest struct {
	Target       string            `json:"target"`
	WAFType      string            `json:"waf_type"`
	PreviousTries []string         `json:"previous_tries"`
	Context      map[string]string `json:"context"`
	AttackType   string            `json:"attack_type"`
}

type PayloadResponse struct {
	Payloads    []GeneratedPayload `json:"payloads"`
	Strategy    string             `json:"strategy"`
	Explanation string             `json:"explanation"`
	Confidence  float64           `json:"confidence"`
}

type GeneratedPayload struct {
	Payload     string            `json:"payload"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Description string            `json:"description"`
	Technique   string            `json:"technique"`
	Confidence  float64          `json:"confidence"`
}

type AnalysisRequest struct {
	Logs        []string          `json:"logs"`
	Responses   []ResponseData    `json:"responses"`
	Target      string            `json:"target"`
	Objective   string            `json:"objective"`
}

type ResponseData struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
	Timing     time.Duration     `json:"timing"`
}

type LLMEngine struct {
	Provider    LLMProvider
	APIKey      string
	BaseURL     string
	Model       string
	Temperature float64
	MaxTokens   int
	client      *http.Client
	logger      *logrus.Logger
	
	successfulPayloads []GeneratedPayload
	failedPayloads     []GeneratedPayload
	wafFingerprints    map[string][]string
}

func NewLLMEngine(provider LLMProvider, apiKey, baseURL, model string) *LLMEngine {
	return &LLMEngine{
		Provider:           provider,
		APIKey:            apiKey,
		BaseURL:           baseURL,
		Model:             model,
		Temperature:       0.7,
		MaxTokens:         2000,
		client:            &http.Client{Timeout: 30 * time.Second},
		logger:            logrus.New(),
		successfulPayloads: make([]GeneratedPayload, 0),
		failedPayloads:     make([]GeneratedPayload, 0),
		wafFingerprints:    make(map[string][]string),
	}
}

func (engine *LLMEngine) GenerateWAFBypass(ctx context.Context, req PayloadRequest) (*PayloadResponse, error) {
	prompt := engine.buildWAFBypassPrompt(req)
	
	response, err := engine.callLLM(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("LLM call failed: %w", err)
	}

	payloadResp, err := engine.parsePayloadResponse(response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	return payloadResp, nil
}

func (engine *LLMEngine) AnalyzeLogs(ctx context.Context, req AnalysisRequest) (string, error) {
	prompt := engine.buildAnalysisPrompt(req)
	
	response, err := engine.callLLM(ctx, prompt)
	if err != nil {
		return "", fmt.Errorf("LLM analysis failed: %w", err)
	}

	return response, nil
}

func (engine *LLMEngine) LearnFromResult(payload GeneratedPayload, success bool, response ResponseData) {
	if success {
		engine.successfulPayloads = append(engine.successfulPayloads, payload)
		engine.logger.Infof("Learned successful technique: %s", payload.Technique)
	} else {
		engine.failedPayloads = append(engine.failedPayloads, payload)
	}
	
	if response.StatusCode == 403 || response.StatusCode == 406 {
		engine.analyzeWAFFingerprint(response)
	}
}

func (engine *LLMEngine) buildWAFBypassPrompt(req PayloadRequest) string {
	var prompt strings.Builder
	
	prompt.WriteString("You are an expert penetration tester specializing in WAF bypass techniques. ")
	prompt.WriteString("Generate creative and effective payload variations to bypass web application firewalls.\n\n")
	
	prompt.WriteString(fmt.Sprintf("TARGET: %s\n", req.Target))
	prompt.WriteString(fmt.Sprintf("WAF TYPE: %s\n", req.WAFType))
	prompt.WriteString(fmt.Sprintf("ATTACK TYPE: %s\n", req.AttackType))
	
	if len(req.PreviousTries) > 0 {
		prompt.WriteString("\nPREVIOUS FAILED ATTEMPTS:\n")
		for _, attempt := range req.PreviousTries {
			prompt.WriteString(fmt.Sprintf("- %s\n", attempt))
		}
	}
	
	if len(engine.successfulPayloads) > 0 {
		prompt.WriteString("\nSUCCESSFUL TECHNIQUES FROM PREVIOUS TESTS:\n")
		for _, payload := range engine.successfulPayloads[max(0, len(engine.successfulPayloads)-5):] {
			prompt.WriteString(fmt.Sprintf("- %s: %s\n", payload.Technique, payload.Payload))
		}
	}
	
	prompt.WriteString(`
GENERATE 5-10 INNOVATIVE BYPASS PAYLOADS INCLUDING:

1. ENCODING VARIATIONS:
   - Double/Triple URL encoding
   - Unicode normalization attacks
   - HTML entity encoding
   - Base64 variations
   - Hex encoding combinations

2. STRUCTURAL BYPASSES:
   - Comment injection techniques
   - Case variation attacks
   - Whitespace manipulation
   - Character substitution
   - Polyglot payloads

3. PROTOCOL-LEVEL BYPASSES:
   - HTTP Parameter Pollution
   - Content-Type manipulation
   - Custom headers (X-Originating-IP, etc.)
   - HTTP method variations
   - Chunked transfer encoding

4. ADVANCED TECHNIQUES:
   - WAF signature fragmentation
   - Time-based blind bypasses
   - Error-based information disclosure
   - Cache poisoning attempts
   - JSONP callback manipulation

Return ONLY valid JSON in this format:
{
  "payloads": [
    {
      "payload": "actual_payload_here",
      "method": "GET/POST",
      "headers": {"Header-Name": "Header-Value"},
      "description": "Brief explanation",
      "technique": "encoding/structural/protocol/advanced",
      "confidence": 0.8
    }
  ],
  "strategy": "Overall bypass strategy explanation",
  "explanation": "Why these techniques should work",
  "confidence": 0.75
}`)

	return prompt.String()
}

func (engine *LLMEngine) buildAnalysisPrompt(req AnalysisRequest) string {
	var prompt strings.Builder
	
	prompt.WriteString("You are a cybersecurity expert analyzing server responses and logs. ")
	prompt.WriteString("Identify patterns, vulnerabilities, and optimization strategies.\n\n")
	
	prompt.WriteString(fmt.Sprintf("TARGET: %s\n", req.Target))
	prompt.WriteString(fmt.Sprintf("OBJECTIVE: %s\n\n", req.Objective))
	
	prompt.WriteString("SERVER RESPONSES:\n")
	for i, resp := range req.Responses {
		prompt.WriteString(fmt.Sprintf("Response %d:\n", i+1))
		prompt.WriteString(fmt.Sprintf("  Status: %d\n", resp.StatusCode))
		prompt.WriteString(fmt.Sprintf("  Timing: %v\n", resp.Timing))
		for k, v := range resp.Headers {
			prompt.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
		}
		if len(resp.Body) > 200 {
			prompt.WriteString(fmt.Sprintf("  Body: %s...\n", resp.Body[:200]))
		} else {
			prompt.WriteString(fmt.Sprintf("  Body: %s\n", resp.Body))
		}
		prompt.WriteString("\n")
	}
	
	prompt.WriteString(`
ANALYZE AND PROVIDE:
1. WAF/Security system identification
2. Potential bypass techniques
3. Vulnerability indicators
4. Rate limiting patterns
5. Recommended next steps
6. Risk assessment
`)

	return prompt.String()
}

func (engine *LLMEngine) callLLM(ctx context.Context, prompt string) (string, error) {
	switch engine.Provider {
	case ProviderOpenAI:
		return engine.callOpenAI(ctx, prompt)
	case ProviderOllama:
		return engine.callOllama(ctx, prompt)
	case ProviderLocal:
		return engine.callLocal(ctx, prompt)
	default:
		return "", fmt.Errorf("unsupported LLM provider: %s", engine.Provider)
	}
}

func (engine *LLMEngine) callOpenAI(ctx context.Context, prompt string) (string, error) {
	reqBody := map[string]interface{}{
		"model": engine.Model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"temperature": engine.Temperature,
		"max_tokens":  engine.MaxTokens,
	}
	
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+engine.APIKey)
	
	resp, err := engine.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	
	choices, ok := result["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}
	
	choice := choices[0].(map[string]interface{})
	message := choice["message"].(map[string]interface{})
	content := message["content"].(string)
	
	return content, nil
}

func (engine *LLMEngine) callOllama(ctx context.Context, prompt string) (string, error) {
	reqBody := map[string]interface{}{
		"model":  engine.Model,
		"prompt": prompt,
		"stream": false,
	}
	
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	
	url := engine.BaseURL
	if url == "" {
		url = "http://localhost:11434"
	}
	
	req, err := http.NewRequestWithContext(ctx, "POST", url+"/api/generate", bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := engine.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	
	response, ok := result["response"].(string)
	if !ok {
		return "", fmt.Errorf("no response in result")
	}
	
	return response, nil
}

func (engine *LLMEngine) callLocal(ctx context.Context, prompt string) (string, error) {
	return "Local model not implemented yet", fmt.Errorf("local model not implemented")
}

func (engine *LLMEngine) parsePayloadResponse(response string) (*PayloadResponse, error) {
	start := strings.Index(response, "{")
	end := strings.LastIndex(response, "}") + 1
	
	if start == -1 || end <= start {
		return nil, fmt.Errorf("no valid JSON found in response")
	}
	
	jsonStr := response[start:end]
	
	var payloadResp PayloadResponse
	if err := json.Unmarshal([]byte(jsonStr), &payloadResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	
	return &payloadResp, nil
}

func (engine *LLMEngine) analyzeWAFFingerprint(response ResponseData) {
	fingerprints := []string{}
	
	for header, value := range response.Headers {
		headerLower := strings.ToLower(header)
		valueLower := strings.ToLower(value)
		
		if strings.Contains(headerLower, "cloudflare") || strings.Contains(valueLower, "cloudflare") {
			fingerprints = append(fingerprints, "CloudFlare")
		}
		if strings.Contains(headerLower, "incap") || strings.Contains(valueLower, "incapsula") {
			fingerprints = append(fingerprints, "Incapsula")
		}
		if strings.Contains(headerLower, "sucuri") || strings.Contains(valueLower, "sucuri") {
			fingerprints = append(fingerprints, "Sucuri")
		}
	}
	
	bodyLower := strings.ToLower(response.Body)
	if strings.Contains(bodyLower, "access denied") {
		fingerprints = append(fingerprints, "Generic-AccessDenied")
	}
	if strings.Contains(bodyLower, "blocked") {
		fingerprints = append(fingerprints, "Generic-Blocked")
	}
	
	if len(fingerprints) > 0 {
		key := fmt.Sprintf("status_%d", response.StatusCode)
		engine.wafFingerprints[key] = append(engine.wafFingerprints[key], fingerprints...)
	}
}

func (engine *LLMEngine) GetLearningStats() map[string]interface{} {
	return map[string]interface{}{
		"successful_payloads": len(engine.successfulPayloads),
		"failed_payloads":     len(engine.failedPayloads),
		"waf_fingerprints":    len(engine.wafFingerprints),
		"success_rate":        float64(len(engine.successfulPayloads)) / float64(len(engine.successfulPayloads)+len(engine.failedPayloads)),
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}