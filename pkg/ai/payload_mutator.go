package ai

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"recon-toolkit/pkg/core"
)

// PayloadMutator - Self-evolving AI-powered payload generation engine
type PayloadMutator struct {
	logger       core.Logger
	llmClient    *LLMClient
	mutations    *MutationDatabase
	stats        *PayloadStats
	config       *MutatorConfig
	mutex        sync.RWMutex
}

type MutatorConfig struct {
	LLMProvider    string  `json:"llm_provider"`
	APIKey         string  `json:"api_key"`
	Model          string  `json:"model"`
	MaxMutations   int     `json:"max_mutations"`
	SuccessRate    float64 `json:"success_rate_threshold"`
	LearningRate   float64 `json:"learning_rate"`
	EnableChaos    bool    `json:"enable_chaos_mode"`
	AggressiveMode bool    `json:"aggressive_mode"`
}

type LLMClient struct {
	provider string
	apiKey   string
	model    string
	client   *http.Client
}

type MutationDatabase struct {
	mutations map[string]*MutationRecord
	mutex     sync.RWMutex
}

type MutationRecord struct {
	PayloadType    string             `json:"payload_type"`
	Technique      string             `json:"technique"`
	SuccessRate    float64            `json:"success_rate"`
	Attempts       int                `json:"attempts"`
	Successes      int                `json:"successes"`
	LastSuccess    time.Time          `json:"last_success"`
	Variants       []PayloadVariant   `json:"variants"`
	TargetProfiles []string           `json:"target_profiles"`
	Metadata       map[string]interface{} `json:"metadata"`
}

type PayloadVariant struct {
	Payload     string    `json:"payload"`
	Success     bool      `json:"success"`
	Timestamp   time.Time `json:"timestamp"`
	Encoding    string    `json:"encoding"`
	Obfuscation string    `json:"obfuscation"`
	BypassTech  string    `json:"bypass_technique"`
}

type PayloadStats struct {
	TotalAttempts    int64             `json:"total_attempts"`
	TotalSuccesses   int64             `json:"total_successes"`
	SuccessRate      float64           `json:"success_rate"`
	BestTechniques   []string          `json:"best_techniques"`
	WorstTechniques  []string          `json:"worst_techniques"`
	TargetFingerprints map[string]int  `json:"target_fingerprints"`
}

type MutationRequest struct {
	OriginalPayload string            `json:"original_payload"`
	TargetResponse  string            `json:"target_response"`
	PayloadType     string            `json:"payload_type"`
	FailureReason   string            `json:"failure_reason"`
	TargetContext   map[string]interface{} `json:"target_context"`
	PreviousAttempts []PayloadVariant  `json:"previous_attempts"`
}

type MutationResult struct {
	MutatedPayloads []PayloadVariant  `json:"mutated_payloads"`
	Confidence      float64           `json:"confidence"`
	Reasoning       string            `json:"reasoning"`
	NextStrategy    string            `json:"next_strategy"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// NewPayloadMutator creates legendary self-evolving payload engine
func NewPayloadMutator(logger core.Logger, config *MutatorConfig) *PayloadMutator {
	if config == nil {
		config = &MutatorConfig{
			LLMProvider:    "openai",
			Model:          "gpt-4",
			MaxMutations:   50,
			SuccessRate:    0.1,
			LearningRate:   0.05,
			EnableChaos:    true,
			AggressiveMode: false,
		}
	}

	return &PayloadMutator{
		logger: logger,
		llmClient: &LLMClient{
			provider: config.LLMProvider,
			apiKey:   config.APIKey,
			model:    config.Model,
			client: &http.Client{
				Timeout: 30 * time.Second,
			},
		},
		mutations: &MutationDatabase{
			mutations: make(map[string]*MutationRecord),
		},
		stats: &PayloadStats{
			TargetFingerprints: make(map[string]int),
		},
		config: config,
	}
}

// EvolvePayload - The legendary payload evolution engine
func (p *PayloadMutator) EvolvePayload(ctx context.Context, request *MutationRequest) (*MutationResult, error) {
	p.logger.Info("🧬 PAYLOAD EVOLUTION INITIATED - Darwin would be proud!", 
		core.NewField("payload_type", request.PayloadType),
		core.NewField("attempts", len(request.PreviousAttempts)))

	// Update statistics
	p.updateStats(request)

	// Analyze failure patterns
	failureAnalysis := p.analyzeFailurePatterns(request)
	
	// Generate mutations using multiple strategies
	mutations := p.generateMutations(ctx, request, failureAnalysis)

	// Apply AI-powered improvements
	aiMutations, err := p.generateAIMutations(ctx, request, failureAnalysis)
	if err != nil {
		p.logger.Warn("AI mutation failed, using traditional methods", 
			core.NewField("error", err.Error()))
	} else {
		mutations = append(mutations, aiMutations...)
	}

	// Apply chaos mutations if enabled
	if p.config.EnableChaos {
		chaosMutations := p.generateChaosMutations(request)
		mutations = append(mutations, chaosMutations...)
	}

	// Rank mutations by predicted success
	rankedMutations := p.rankMutations(mutations, request)

	result := &MutationResult{
		MutatedPayloads: rankedMutations[:min(len(rankedMutations), p.config.MaxMutations)],
		Confidence:      p.calculateConfidence(rankedMutations),
		Reasoning:       p.generateReasoning(failureAnalysis),
		NextStrategy:    p.suggestNextStrategy(request),
		Metadata: map[string]interface{}{
			"failure_analysis": failureAnalysis,
			"mutation_count":   len(rankedMutations),
			"chaos_mode":       p.config.EnableChaos,
		},
	}

	p.logger.Info("🚀 Evolved payloads generated - time to make WAFs cry!", 
		core.NewField("mutations", len(result.MutatedPayloads)),
		core.NewField("confidence", result.Confidence))

	return result, nil
}

// generateMutations creates traditional payload mutations
func (p *PayloadMutator) generateMutations(ctx context.Context, request *MutationRequest, analysis map[string]interface{}) []PayloadVariant {
	var mutations []PayloadVariant
	payload := request.OriginalPayload

	// 1. Encoding mutations
	mutations = append(mutations, p.generateEncodingMutations(payload)...)

	// 2. Obfuscation mutations  
	mutations = append(mutations, p.generateObfuscationMutations(payload)...)

	// 3. Case manipulation
	mutations = append(mutations, p.generateCaseMutations(payload)...)

	// 4. Character substitution
	mutations = append(mutations, p.generateCharSubstitutions(payload)...)

	// 5. Structure mutations
	mutations = append(mutations, p.generateStructureMutations(payload)...)

	// 6. WAF bypass specific
	mutations = append(mutations, p.generateWAFBypassMutations(payload)...)

	return mutations
}

// generateEncodingMutations creates various encoding variants
func (p *PayloadMutator) generateEncodingMutations(payload string) []PayloadVariant {
	var mutations []PayloadVariant

	encodings := []struct {
		name     string
		encoder  func(string) string
	}{
		{"url_encode", p.urlEncode},
		{"double_url_encode", func(s string) string { return p.urlEncode(p.urlEncode(s)) }},
		{"html_encode", p.htmlEncode},
		{"unicode_encode", p.unicodeEncode},
		{"base64_encode", p.base64Encode},
		{"hex_encode", p.hexEncode},
		{"mixed_encoding", p.mixedEncode},
	}

	for _, encoding := range encodings {
		encoded := encoding.encoder(payload)
		mutations = append(mutations, PayloadVariant{
			Payload:     encoded,
			Timestamp:   time.Now(),
			Encoding:    encoding.name,
			Obfuscation: "encoding",
			BypassTech:  "character_encoding",
		})
	}

	return mutations
}

// generateObfuscationMutations creates obfuscated variants
func (p *PayloadMutator) generateObfuscationMutations(payload string) []PayloadVariant {
	var mutations []PayloadVariant

	// Comment injection
	if strings.Contains(payload, "script") {
		commented := strings.ReplaceAll(payload, "<script>", "<scri/**/pt>")
		mutations = append(mutations, PayloadVariant{
			Payload:     commented,
			Timestamp:   time.Now(),
			Obfuscation: "comment_injection",
			BypassTech:  "html_comment_bypass",
		})
	}

	// Whitespace variations
	spaced := p.insertRandomWhitespace(payload)
	mutations = append(mutations, PayloadVariant{
		Payload:     spaced,
		Timestamp:   time.Now(),
		Obfuscation: "whitespace_variation",
		BypassTech:  "whitespace_bypass",
	})

	// String concatenation
	if strings.Contains(payload, "'") || strings.Contains(payload, "\"") {
		concatenated := p.stringConcatenation(payload)
		mutations = append(mutations, PayloadVariant{
			Payload:     concatenated,
			Timestamp:   time.Now(),
			Obfuscation: "string_concatenation",
			BypassTech:  "js_concatenation",
		})
	}

	return mutations
}

// generateCaseMutations creates case variation mutations
func (p *PayloadMutator) generateCaseMutations(payload string) []PayloadVariant {
	var mutations []PayloadVariant

	// Random case
	randomCase := p.randomizeCase(payload)
	mutations = append(mutations, PayloadVariant{
		Payload:     randomCase,
		Timestamp:   time.Now(),
		Obfuscation: "random_case",
		BypassTech:  "case_variation",
	})

	// Alternating case
	alternating := p.alternatingCase(payload)
	mutations = append(mutations, PayloadVariant{
		Payload:     alternating,
		Timestamp:   time.Now(),
		Obfuscation: "alternating_case",
		BypassTech:  "case_variation",
	})

	return mutations
}

// generateAIMutations uses LLM for intelligent mutations
func (p *PayloadMutator) generateAIMutations(ctx context.Context, request *MutationRequest, analysis map[string]interface{}) ([]PayloadVariant, error) {
	prompt := p.buildAIPrompt(request, analysis)
	
	response, err := p.llmClient.generate(ctx, prompt)
	if err != nil {
		return nil, err
	}

	return p.parseAIResponse(response)
}

// buildAIPrompt creates intelligent prompt for LLM
func (p *PayloadMutator) buildAIPrompt(request *MutationRequest, analysis map[string]interface{}) string {
	prompt := fmt.Sprintf(`You are an elite penetration testing AI specializing in WAF bypass and payload obfuscation.

CONTEXT:
- Original Payload: %s
- Payload Type: %s
- Failure Reason: %s
- Target Response: %s
- Previous Attempts: %d

TASK: Generate 10 highly effective payload mutations that will bypass security controls.

MUTATION STRATEGIES TO CONSIDER:
1. Advanced encoding combinations (double/triple encoding)
2. HTML entity obfuscation
3. JavaScript obfuscation techniques
4. SQL injection comment variations
5. Protocol-specific bypasses
6. Character substitution with unicode
7. Polyglot payload creation
8. Context-aware bypasses

RESPONSE FORMAT:
Generate a JSON array with objects containing:
{
  "payload": "mutated_payload_here",
  "technique": "bypass_technique_name", 
  "reasoning": "why_this_will_work",
  "confidence": 0.85
}

Be creative and aggressive. Think like a legendary hacker.`, 
		request.OriginalPayload, 
		request.PayloadType,
		request.FailureReason,
		request.TargetResponse[:min(len(request.TargetResponse), 200)],
		len(request.PreviousAttempts))

	return prompt
}

// generateChaosMutations creates completely random mutations
func (p *PayloadMutator) generateChaosMutations(request *MutationRequest) []PayloadVariant {
	var mutations []PayloadVariant
	payload := request.OriginalPayload

	// Random character insertion
	chaotic1 := p.insertRandomChars(payload)
	mutations = append(mutations, PayloadVariant{
		Payload:     chaotic1,
		Timestamp:   time.Now(),
		Obfuscation: "chaos_insertion",
		BypassTech:  "random_chaos",
	})

	// Random encoding combination
	chaotic2 := p.randomEncodingCombination(payload)
	mutations = append(mutations, PayloadVariant{
		Payload:     chaotic2,
		Timestamp:   time.Now(),
		Obfuscation: "chaos_encoding",
		BypassTech:  "random_chaos",
	})

	// Payload fragmentation
	chaotic3 := p.fragmentPayload(payload)
	mutations = append(mutations, PayloadVariant{
		Payload:     chaotic3,
		Timestamp:   time.Now(),
		Obfuscation: "chaos_fragmentation", 
		BypassTech:  "random_chaos",
	})

	return mutations
}

// updateStats updates success/failure statistics
func (p *PayloadMutator) updateStats(request *MutationRequest) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.stats.TotalAttempts++

	// Check if any previous attempts succeeded
	for _, attempt := range request.PreviousAttempts {
		if attempt.Success {
			p.stats.TotalSuccesses++
			
			// Update mutation database
			key := fmt.Sprintf("%s_%s", request.PayloadType, attempt.BypassTech)
			if record, exists := p.mutations.mutations[key]; exists {
				record.Successes++
				record.Attempts++
				record.LastSuccess = attempt.Timestamp
				record.SuccessRate = float64(record.Successes) / float64(record.Attempts)
			} else {
				p.mutations.mutations[key] = &MutationRecord{
					PayloadType: request.PayloadType,
					Technique:   attempt.BypassTech,
					Successes:   1,
					Attempts:    1,
					SuccessRate: 1.0,
					LastSuccess: attempt.Timestamp,
					Variants:    []PayloadVariant{attempt},
				}
			}
		}
	}

	if p.stats.TotalAttempts > 0 {
		p.stats.SuccessRate = float64(p.stats.TotalSuccesses) / float64(p.stats.TotalAttempts)
	}
}

// Encoding helper functions
func (p *PayloadMutator) urlEncode(s string) string {
	result := ""
	for _, char := range s {
		result += fmt.Sprintf("%%%02X", char)
	}
	return result
}

func (p *PayloadMutator) htmlEncode(s string) string {
	replacer := strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
		"&", "&amp;",
	)
	return replacer.Replace(s)
}

func (p *PayloadMutator) unicodeEncode(s string) string {
	result := ""
	for _, char := range s {
		result += fmt.Sprintf("\\u%04x", char)
	}
	return result
}

func (p *PayloadMutator) base64Encode(s string) string {
	// Simple base64-like encoding for demo
	return fmt.Sprintf("atob('%s')", s) // JavaScript base64 decode
}

func (p *PayloadMutator) hexEncode(s string) string {
	result := ""
	for _, char := range s {
		result += fmt.Sprintf("\\x%02x", char)
	}
	return result
}

func (p *PayloadMutator) mixedEncode(s string) string {
	result := ""
	for i, char := range s {
		switch i % 3 {
		case 0:
			result += fmt.Sprintf("%%%02X", char)
		case 1:
			result += fmt.Sprintf("&#%d;", char)
		case 2:
			result += string(char)
		}
	}
	return result
}

// LLM Client implementation
func (llm *LLMClient) generate(ctx context.Context, prompt string) (string, error) {
	requestBody := map[string]interface{}{
		"model": llm.model,
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"max_tokens":   2000,
		"temperature": 0.8,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+llm.apiKey)

	resp, err := llm.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}

	choices, ok := response["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		return "", fmt.Errorf("no response from LLM")
	}

	choice := choices[0].(map[string]interface{})
	message := choice["message"].(map[string]interface{})
	content := message["content"].(string)

	return content, nil
}

// Additional helper methods
func (p *PayloadMutator) insertRandomWhitespace(payload string) string {
	chars := []rune(payload)
	result := ""
	
	for i, char := range chars {
		result += string(char)
		if i < len(chars)-1 && p.randomBool() {
			whitespaces := []string{" ", "\t", "\n", "\r", "\f", "\v"}
			result += whitespaces[p.randomInt(len(whitespaces))]
		}
	}
	
	return result
}

func (p *PayloadMutator) randomBool() bool {
	b := make([]byte, 1)
	rand.Read(b)
	return b[0]%2 == 0
}

func (p *PayloadMutator) randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	b := make([]byte, 1)
	rand.Read(b)
	return int(b[0]) % max
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Placeholder implementations for remaining methods
func (p *PayloadMutator) generateCharSubstitutions(payload string) []PayloadVariant { return []PayloadVariant{} }
func (p *PayloadMutator) generateStructureMutations(payload string) []PayloadVariant { return []PayloadVariant{} }
func (p *PayloadMutator) generateWAFBypassMutations(payload string) []PayloadVariant { return []PayloadVariant{} }
func (p *PayloadMutator) randomizeCase(payload string) string { return payload }
func (p *PayloadMutator) alternatingCase(payload string) string { return payload }
func (p *PayloadMutator) stringConcatenation(payload string) string { return payload }
func (p *PayloadMutator) insertRandomChars(payload string) string { return payload }
func (p *PayloadMutator) randomEncodingCombination(payload string) string { return payload }
func (p *PayloadMutator) fragmentPayload(payload string) string { return payload }
func (p *PayloadMutator) analyzeFailurePatterns(request *MutationRequest) map[string]interface{} { return make(map[string]interface{}) }
func (p *PayloadMutator) rankMutations(mutations []PayloadVariant, request *MutationRequest) []PayloadVariant { return mutations }
func (p *PayloadMutator) calculateConfidence(mutations []PayloadVariant) float64 { return 0.8 }
func (p *PayloadMutator) generateReasoning(analysis map[string]interface{}) string { return "AI-powered evolution complete" }
func (p *PayloadMutator) suggestNextStrategy(request *MutationRequest) string { return "Continue evolution" }
func (p *PayloadMutator) parseAIResponse(response string) ([]PayloadVariant, error) { return []PayloadVariant{}, nil }