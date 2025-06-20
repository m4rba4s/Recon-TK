
package knowledge

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type TechniqueType string

const (
	TechniqueWAFBypass    TechniqueType = "waf_bypass"
	TechniquePortScan     TechniqueType = "port_scan"
	TechniqueDNSEnum      TechniqueType = "dns_enum"
	TechniqueRateLimitBypass TechniqueType = "rate_limit_bypass"
	TechniqueStealthScan  TechniqueType = "stealth_scan"
	TechniqueEvasion      TechniqueType = "evasion"
)

type Technique struct {
	ID          string            `json:"id"`
	Type        TechniqueType     `json:"type"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Payload     string            `json:"payload"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Parameters  map[string]string `json:"parameters"`
	
	SuccessCount int     `json:"success_count"`
	FailureCount int     `json:"failure_count"`
	SuccessRate  float64 `json:"success_rate"`
	
	TargetWAF     string            `json:"target_waf"`
	TargetOS      string            `json:"target_os"`
	TargetService string            `json:"target_service"`
	Tags          []string          `json:"tags"`
	
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used"`
	LastSuccess time.Time `json:"last_success"`
	Source      string    `json:"source"`
	
	Context     map[string]interface{} `json:"context"`
	Variations  []string              `json:"variations"`
	Confidence  float64               `json:"confidence"`
}

type TechniqueResult struct {
	TechniqueID string            `json:"technique_id"`
	Target      string            `json:"target"`
	Success     bool              `json:"success"`
	StatusCode  int               `json:"status_code"`
	ResponseTime time.Duration    `json:"response_time"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	Error       string            `json:"error"`
	Timestamp   time.Time         `json:"timestamp"`
	Context     map[string]interface{} `json:"context"`
}

type WAFProfile struct {
	Name        string             `json:"name"`
	Signatures  []string           `json:"signatures"`
	Headers     []string           `json:"headers"`
	BodyPatterns []string          `json:"body_patterns"`
	StatusCodes []int              `json:"status_codes"`
	
	EffectiveTechniques   []string  `json:"effective_techniques"`
	IneffectiveTechniques []string  `json:"ineffective_techniques"`
	
	// Statistics
	EncounterCount    int       `json:"encounter_count"`
	LastEncountered   time.Time `json:"last_encountered"`
	SuccessRate       float64   `json:"success_rate"`
	PreferredMethods  []string  `json:"preferred_methods"`
}

type KnowledgeDB struct {
	dbPath     string
	techniques map[string]*Technique
	results    []TechniqueResult
	wafProfiles map[string]*WAFProfile
	logger     *logrus.Logger
	
	// Statistics
	stats KnowledgeStats
}

type KnowledgeStats struct {
	TotalTechniques     int                    `json:"total_techniques"`
	TechniquesByType    map[TechniqueType]int  `json:"techniques_by_type"`
	TotalResults        int                    `json:"total_results"`
	OverallSuccessRate  float64                `json:"overall_success_rate"`
	TopTechniques       []string               `json:"top_techniques"`
	WAFsEncountered     int                    `json:"wafs_encountered"`
	LastUpdate          time.Time              `json:"last_update"`
}

func NewKnowledgeDB(dbPath string) (*KnowledgeDB, error) {
	db := &KnowledgeDB{
		dbPath:      dbPath,
		techniques:  make(map[string]*Technique),
		results:     make([]TechniqueResult, 0),
		wafProfiles: make(map[string]*WAFProfile),
		logger:      logrus.New(),
		stats:       KnowledgeStats{TechniquesByType: make(map[TechniqueType]int)},
	}
	
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}
	
	if err := db.Load(); err != nil {
		db.logger.Warnf("Failed to load existing database: %v", err)
	}
	
	if len(db.techniques) == 0 {
		db.initializeDefaultTechniques()
	}
	
	return db, nil
}

func (db *KnowledgeDB) AddTechnique(technique Technique) string {
	if technique.ID == "" {
		technique.ID = db.generateID(technique.Name + technique.Payload)
	}
	
	technique.CreatedAt = time.Now()
	technique.SuccessRate = 0.0
	
	db.techniques[technique.ID] = &technique
	db.updateStats()
	
	db.logger.Infof("Added new technique: %s (%s)", technique.Name, technique.ID)
	return technique.ID
}

func (db *KnowledgeDB) RecordResult(result TechniqueResult) {
	result.Timestamp = time.Now()
	db.results = append(db.results, result)
	
	if technique, exists := db.techniques[result.TechniqueID]; exists {
		technique.LastUsed = result.Timestamp
		
		if result.Success {
			technique.SuccessCount++
			technique.LastSuccess = result.Timestamp
		} else {
			technique.FailureCount++
		}
		
		total := technique.SuccessCount + technique.FailureCount
		if total > 0 {
			technique.SuccessRate = float64(technique.SuccessCount) / float64(total)
		}
		
		db.logger.Infof("Updated technique %s: %d/%d success rate: %.2f", 
			technique.Name, technique.SuccessCount, total, technique.SuccessRate)
	}
	
	db.updateStats()
}

func (db *KnowledgeDB) GetEffectiveTechniques(techniqueType TechniqueType, limit int) []*Technique {
	var filtered []*Technique
	
	for _, technique := range db.techniques {
		if technique.Type == techniqueType {
			filtered = append(filtered, technique)
		}
	}
	
	// Sort by success rate and usage
	sort.Slice(filtered, func(i, j int) bool {
		// Prioritize techniques with higher success rate and more usage
		scoreI := filtered[i].SuccessRate * float64(filtered[i].SuccessCount+filtered[i].FailureCount)
		scoreJ := filtered[j].SuccessRate * float64(filtered[j].SuccessCount+filtered[j].FailureCount)
		return scoreI > scoreJ
	})
	
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[:limit]
	}
	
	return filtered
}

func (db *KnowledgeDB) GetTechniquesForWAF(wafType string, limit int) []*Technique {
	var effective []*Technique
	
	for _, technique := range db.techniques {
		if technique.TargetWAF == wafType || technique.TargetWAF == "" {
			if technique.SuccessRate > 0.3 {
				effective = append(effective, technique)
			}
		}
	}
	
	// Sort by success rate
	sort.Slice(effective, func(i, j int) bool {
		return effective[i].SuccessRate > effective[j].SuccessRate
	})
	
	if limit > 0 && len(effective) > limit {
		effective = effective[:limit]
	}
	
	return effective
}

func (db *KnowledgeDB) AnalyzeWAF(name string, headers map[string]string, body string, statusCode int) {
	profile, exists := db.wafProfiles[name]
	if !exists {
		profile = &WAFProfile{
			Name:                  name,
			Signatures:           make([]string, 0),
			Headers:              make([]string, 0),
			BodyPatterns:         make([]string, 0),
			StatusCodes:          make([]int, 0),
			EffectiveTechniques:   make([]string, 0),
			IneffectiveTechniques: make([]string, 0),
			PreferredMethods:     make([]string, 0),
		}
		db.wafProfiles[name] = profile
	}
	
	profile.EncounterCount++
	profile.LastEncountered = time.Now()
	
	// Analyze headers
	for header, value := range headers {
		headerSig := fmt.Sprintf("%s:%s", strings.ToLower(header), strings.ToLower(value))
		if !contains(profile.Headers, headerSig) {
			profile.Headers = append(profile.Headers, headerSig)
		}
	}
	
	// Analyze body patterns
	if body != "" {
		bodyLower := strings.ToLower(body)
		patterns := []string{"access denied", "blocked", "forbidden", "security", "firewall"}
		for _, pattern := range patterns {
			if strings.Contains(bodyLower, pattern) && !contains(profile.BodyPatterns, pattern) {
				profile.BodyPatterns = append(profile.BodyPatterns, pattern)
			}
		}
	}
	
	// Track status codes
	if !containsInt(profile.StatusCodes, statusCode) {
		profile.StatusCodes = append(profile.StatusCodes, statusCode)
	}
	
	db.logger.Infof("Updated WAF profile for %s: %d encounters", name, profile.EncounterCount)
}

func (db *KnowledgeDB) GetRecommendations(target, wafType string, previousFailures []string) []string {
	recommendations := make([]string, 0)
	
	// Get effective techniques for this WAF type
	techniques := db.GetTechniquesForWAF(wafType, 10)
	
	for _, technique := range techniques {
		// Skip if this technique was already tried and failed
		skip := false
		for _, failure := range previousFailures {
			if strings.Contains(failure, technique.Payload) {
				skip = true
				break
			}
		}
		
		if !skip {
			recommendation := fmt.Sprintf("Try %s: %s (Success rate: %.2f)", 
				technique.Name, technique.Description, technique.SuccessRate)
			recommendations = append(recommendations, recommendation)
		}
	}
	
	// Add general recommendations
	if len(recommendations) < 3 {
		general := []string{
			"Try encoding variations: URL, HTML entity, Unicode normalization",
			"Attempt parameter pollution with duplicate parameters",
			"Use case variation and whitespace manipulation",
			"Test with different HTTP methods (POST, PUT, OPTIONS)",
			"Try fragmenting payloads across multiple parameters",
		}
		recommendations = append(recommendations, general...)
	}
	
	return recommendations
}

func (db *KnowledgeDB) Save() error {
	data := map[string]interface{}{
		"techniques":   db.techniques,
		"results":      db.results,
		"waf_profiles": db.wafProfiles,
		"stats":        db.stats,
		"last_save":    time.Now(),
	}
	
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}
	
	return os.WriteFile(db.dbPath, jsonData, 0644)
}

func (db *KnowledgeDB) Load() error {
	data, err := os.ReadFile(db.dbPath)
	if err != nil {
		return fmt.Errorf("failed to read database file: %w", err)
	}
	
	var loadData map[string]interface{}
	if err := json.Unmarshal(data, &loadData); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}
	
	// Load techniques
	if techniqueData, ok := loadData["techniques"].(map[string]interface{}); ok {
		for id, techData := range techniqueData {
			techJSON, _ := json.Marshal(techData)
			var technique Technique
			json.Unmarshal(techJSON, &technique)
			db.techniques[id] = &technique
		}
	}
	
	// Load results
	if resultData, ok := loadData["results"].([]interface{}); ok {
		for _, resData := range resultData {
			resJSON, _ := json.Marshal(resData)
			var result TechniqueResult
			json.Unmarshal(resJSON, &result)
			db.results = append(db.results, result)
		}
	}
	
	// Load WAF profiles
	if wafData, ok := loadData["waf_profiles"].(map[string]interface{}); ok {
		for name, profileData := range wafData {
			profileJSON, _ := json.Marshal(profileData)
			var profile WAFProfile
			json.Unmarshal(profileJSON, &profile)
			db.wafProfiles[name] = &profile
		}
	}
	
	db.updateStats()
	db.logger.Infof("Loaded knowledge database: %d techniques, %d results", 
		len(db.techniques), len(db.results))
	
	return nil
}

func (db *KnowledgeDB) updateStats() {
	db.stats.TotalTechniques = len(db.techniques)
	db.stats.TotalResults = len(db.results)
	db.stats.WAFsEncountered = len(db.wafProfiles)
	db.stats.LastUpdate = time.Now()
	
	// Reset type counters
	db.stats.TechniquesByType = make(map[TechniqueType]int)
	
	successTotal := 0
	totalAttempts := 0
	topTechniques := make([]*Technique, 0)
	
	for _, technique := range db.techniques {
		db.stats.TechniquesByType[technique.Type]++
		successTotal += technique.SuccessCount
		totalAttempts += technique.SuccessCount + technique.FailureCount
		topTechniques = append(topTechniques, technique)
	}
	
	if totalAttempts > 0 {
		db.stats.OverallSuccessRate = float64(successTotal) / float64(totalAttempts)
	}
	
	// Sort top techniques
	sort.Slice(topTechniques, func(i, j int) bool {
		return topTechniques[i].SuccessRate > topTechniques[j].SuccessRate
	})
	
	db.stats.TopTechniques = make([]string, 0)
	for i, technique := range topTechniques {
		if i >= 10 { // Top 10
			break
		}
		db.stats.TopTechniques = append(db.stats.TopTechniques, technique.Name)
	}
}

func (db *KnowledgeDB) initializeDefaultTechniques() {
	defaultTechniques := []Technique{
		{
			Name:        "Double URL Encoding",
			Type:        TechniqueWAFBypass,
			Description: "Double URL encode special characters",
			Payload:     "%253Cscript%253Ealert(1)%253C/script%253E",
			Method:      "GET",
			Tags:        []string{"encoding", "xss"},
			Source:      "manual",
		},
		{
			Name:        "Unicode Normalization",
			Type:        TechniqueWAFBypass,
			Description: "Use Unicode normalization to bypass filters",
			Payload:     "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
			Method:      "GET",
			Tags:        []string{"unicode", "encoding", "xss"},
			Source:      "manual",
		},
		{
			Name:        "Case Variation",
			Type:        TechniqueWAFBypass,
			Description: "Vary case of payload characters",
			Payload:     "<ScRiPt>alert(1)</ScRiPt>",
			Method:      "GET",
			Tags:        []string{"case", "xss"},
			Source:      "manual",
		},
		{
			Name:        "HTTP Parameter Pollution",
			Type:        TechniqueWAFBypass,
			Description: "Split payload across multiple parameters",
			Payload:     "test=<script&test=alert(1)</script>",
			Method:      "GET",
			Tags:        []string{"hpp", "pollution"},
			Source:      "manual",
		},
		{
			Name:        "X-Forwarded-For Bypass",
			Type:        TechniqueWAFBypass,
			Description: "Use X-Forwarded-For header to bypass IP restrictions",
			Headers:     map[string]string{"X-Forwarded-For": "127.0.0.1"},
			Method:      "GET",
			Tags:        []string{"header", "ip-bypass"},
			Source:      "manual",
		},
		{
			Name:        "Slow Stealth Scan",
			Type:        TechniqueStealthScan,
			Description: "Very slow scanning with large delays",
			Parameters:  map[string]string{"delay": "5000", "threads": "1"},
			Tags:        []string{"stealth", "slow"},
			Source:      "manual",
		},
	}
	
	for _, technique := range defaultTechniques {
		db.AddTechnique(technique)
	}
	
	db.logger.Info("Initialized database with default techniques")
}

func (db *KnowledgeDB) generateID(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input + time.Now().String()))
	return fmt.Sprintf("%x", hasher.Sum(nil))[:16]
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsInt(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (db *KnowledgeDB) GetStats() KnowledgeStats {
	return db.stats
}