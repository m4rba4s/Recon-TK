package forensics

import (
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type YaraEngine struct {
	rules       []*YaraRule
	rulesets    map[string][]*YaraRule // categorized rulesets
	logger      *logrus.Logger
	config      *YaraConfig
	cache       map[string]*ScanResult
	mutex       sync.RWMutex
}

type YaraConfig struct {
	RulesPath     string        `json:"rules_path"`
	Timeout       time.Duration `json:"timeout"`
	MaxFileSize   int64         `json:"max_file_size"`
	MaxConcurrent int           `json:"max_concurrent"`
	EnableCache   bool          `json:"enable_cache"`
}

type YaraRule struct {
	Name        string            `json:"name"`
	Category    string            `json:"category"`
	Description string            `json:"description"`
	Author      string            `json:"author"`
	Severity    string            `json:"severity"`
	Tags        []string          `json:"tags"`
	Strings     map[string]string `json:"strings"`
	Condition   string            `json:"condition"`
	Content     string            `json:"content"`
	FilePath    string            `json:"file_path"`
}

type ScanResult struct {
	FilePath    string            `json:"file_path"`
	FileSize    int64             `json:"file_size"`
	FileHash    string            `json:"file_hash"`
	Matches     []*RuleMatch      `json:"matches"`
	ScanTime    time.Duration     `json:"scan_time"`
	Timestamp   time.Time         `json:"timestamp"`
	Metadata    map[string]string `json:"metadata"`
}

type RuleMatch struct {
	RuleName    string            `json:"rule_name"`
	Category    string            `json:"category"`
	Severity    string            `json:"severity"`
	Description string            `json:"description"`
	Tags        []string          `json:"tags"`
	Matches     []*StringMatch    `json:"matches"`
	Confidence  int               `json:"confidence"`
}

type StringMatch struct {
	Name     string `json:"name"`
	Content  string `json:"content"`
	Offset   int64  `json:"offset"`
	Length   int    `json:"length"`
	Context  string `json:"context"`
}

type ThreatIntelligence struct {
	IOCs        []*IOC            `json:"iocs"`
	Signatures  []*ThreatSig      `json:"signatures"`
	LastUpdated time.Time         `json:"last_updated"`
}

type IOC struct {
	Type        string    `json:"type"` // hash, ip, domain, url, email
	Value       string    `json:"value"`
	Threat      string    `json:"threat"`
	Confidence  int       `json:"confidence"`
	Source      string    `json:"source"`
	FirstSeen   time.Time `json:"first_seen"`
}

type ThreatSig struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Family      string   `json:"family"`
	Platform    string   `json:"platform"`
	Techniques  []string `json:"techniques"`
	Severity    string   `json:"severity"`
	Pattern     string   `json:"pattern"`
}

// NewYaraEngine creates a new YARA scanning engine
func NewYaraEngine(logger *logrus.Logger, config *YaraConfig) *YaraEngine {
	if config == nil {
		config = &YaraConfig{
			RulesPath:     "./rules",
			Timeout:       30 * time.Second,
			MaxFileSize:   100 * 1024 * 1024, // 100MB
			MaxConcurrent: 5,
			EnableCache:   true,
		}
	}

	engine := &YaraEngine{
		logger:   logger,
		config:   config,
		rulesets: make(map[string][]*YaraRule),
		cache:    make(map[string]*ScanResult),
	}

	// Load built-in rules
	engine.loadBuiltinRules()

	return engine
}

// loadBuiltinRules loads predefined threat detection rules
func (y *YaraEngine) loadBuiltinRules() {
	builtinRules := []*YaraRule{
		{
			Name:        "malware_executable",
			Category:    "malware",
			Description: "Detects potentially malicious executable files",
			Author:      "recon-toolkit",
			Severity:    "HIGH",
			Tags:        []string{"malware", "executable", "suspicious"},
			Strings: map[string]string{
				"$mz":      "4D5A",           // MZ header
				"$pe":      "50450000",       // PE header
				"$upx":     "555058",         // UPX packer
				"$vmware":  "VMware",         // VMware detection
				"$debug":   "IsDebuggerPresent", // Anti-debug
			},
			Condition: "$mz at 0 and $pe and ($upx or $vmware or $debug)",
		},
		{
			Name:        "web_shell",
			Category:    "webshell",
			Description: "Detects common web shell patterns",
			Author:      "recon-toolkit",
			Severity:    "CRITICAL",
			Tags:        []string{"webshell", "backdoor", "php"},
			Strings: map[string]string{
				"$eval":    "eval(",
				"$base64":  "base64_decode",
				"$system":  "system(",
				"$exec":    "exec(",
				"$shell":   "shell_exec",
				"$pass":    "password",
			},
			Condition: "($eval or $base64) and ($system or $exec or $shell) and $pass",
		},
		{
			Name:        "crypto_miner",
			Category:    "cryptominer",
			Description: "Detects cryptocurrency mining malware",
			Author:      "recon-toolkit",
			Severity:    "MEDIUM",
			Tags:        []string{"cryptominer", "malware", "mining"},
			Strings: map[string]string{
				"$xmrig":    "xmrig",
				"$stratum":  "stratum+tcp",
				"$monero":   "monero",
				"$bitcoin":  "bitcoin",
				"$mining":   "mining",
				"$hashrate": "hashrate",
			},
			Condition: "2 of them",
		},
		{
			Name:        "ransomware",
			Category:    "ransomware",
			Description: "Detects ransomware patterns",
			Author:      "recon-toolkit",
			Severity:    "CRITICAL",
			Tags:        []string{"ransomware", "encryption", "malware"},
			Strings: map[string]string{
				"$encrypt":  "encrypt",
				"$ransom":   "ransom",
				"$bitcoin":  "bitcoin",
				"$payment":  "payment",
				"$decrypt":  "decrypt",
				"$victim":   "victim",
			},
			Condition: "$encrypt and $ransom and ($bitcoin or $payment)",
		},
		{
			Name:        "suspicious_powershell",
			Category:    "powershell",
			Description: "Detects suspicious PowerShell activity",
			Author:      "recon-toolkit",
			Severity:    "HIGH",
			Tags:        []string{"powershell", "suspicious", "encoded"},
			Strings: map[string]string{
				"$encoded":     "EncodedCommand",
				"$bypass":      "ExecutionPolicy Bypass",
				"$download":    "DownloadString",
				"$invoke":      "Invoke-Expression",
				"$shellcode":   "shellcode",
				"$base64":      "Base64",
			},
			Condition: "2 of them",
		},
	}

	y.rules = builtinRules
	
	// Categorize rules
	for _, rule := range builtinRules {
		y.rulesets[rule.Category] = append(y.rulesets[rule.Category], rule)
	}

	y.logger.Infof("Loaded %d built-in YARA rules across %d categories", len(builtinRules), len(y.rulesets))
}

// LoadRulesFromDirectory loads YARA rules from a directory
func (y *YaraEngine) LoadRulesFromDirectory(rulesPath string) error {
	y.logger.Infof("Loading YARA rules from: %s", rulesPath)
	
	return filepath.Walk(rulesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && (strings.HasSuffix(path, ".yar") || strings.HasSuffix(path, ".yara")) {
			rule, err := y.parseRuleFile(path)
			if err != nil {
				y.logger.WithError(err).Warnf("Failed to parse rule file: %s", path)
				return nil
			}

			y.rules = append(y.rules, rule)
			y.rulesets[rule.Category] = append(y.rulesets[rule.Category], rule)
		}

		return nil
	})
}

// parseRuleFile parses a YARA rule file
func (y *YaraEngine) parseRuleFile(filepath string) (*YaraRule, error) {
	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	// Basic YARA rule parsing (simplified)
	rule := &YaraRule{
		FilePath: filepath,
		Content:  string(content),
		Strings:  make(map[string]string),
	}

	lines := strings.Split(string(content), "\n")
	inStrings := false
	inCondition := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.HasPrefix(line, "rule ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				rule.Name = strings.TrimSuffix(parts[1], "{")
			}
		} else if strings.Contains(line, "author =") {
			rule.Author = y.extractQuotedValue(line)
		} else if strings.Contains(line, "description =") {
			rule.Description = y.extractQuotedValue(line)
		} else if line == "strings:" {
			inStrings = true
		} else if line == "condition:" {
			inStrings = false
			inCondition = true
		} else if inStrings && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.Trim(strings.TrimSpace(parts[1]), "\"")
				rule.Strings[key] = value
			}
		} else if inCondition && !strings.HasPrefix(line, "}") {
			rule.Condition += line + " "
		}
	}

	// Set default category if not specified
	if rule.Category == "" {
		rule.Category = "generic"
	}

	return rule, nil
}

// extractQuotedValue extracts a quoted value from a line
func (y *YaraEngine) extractQuotedValue(line string) string {
	start := strings.Index(line, "\"")
	if start == -1 {
		return ""
	}
	end := strings.LastIndex(line, "\"")
	if end <= start {
		return ""
	}
	return line[start+1 : end]
}

// ScanFile scans a single file with YARA rules
func (y *YaraEngine) ScanFile(ctx context.Context, filePath string) (*ScanResult, error) {
	// Check cache first
	if y.config.EnableCache {
		y.mutex.RLock()
		if cached, exists := y.cache[filePath]; exists {
			y.mutex.RUnlock()
			return cached, nil
		}
		y.mutex.RUnlock()
	}

	startTime := time.Now()

	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	// Check file size
	if fileInfo.Size() > y.config.MaxFileSize {
		return nil, fmt.Errorf("file too large: %d bytes", fileInfo.Size())
	}

	// Calculate file hash
	hash, err := y.calculateFileHash(filePath)
	if err != nil {
		return nil, err
	}

	result := &ScanResult{
		FilePath:  filePath,
		FileSize:  fileInfo.Size(),
		FileHash:  hash,
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
	}

	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Scan with all rules
	for _, rule := range y.rules {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		match := y.scanContentWithRule(content, rule)
		if match != nil {
			result.Matches = append(result.Matches, match)
		}
	}

	result.ScanTime = time.Since(startTime)

	// Cache result
	if y.config.EnableCache {
		y.mutex.Lock()
		y.cache[filePath] = result
		y.mutex.Unlock()
	}

	return result, nil
}

// ScanDirectory recursively scans a directory
func (y *YaraEngine) ScanDirectory(ctx context.Context, dirPath string) ([]*ScanResult, error) {
	y.logger.Infof("Starting YARA scan of directory: %s", dirPath)
	
	var results []*ScanResult
	var mutex sync.Mutex
	sem := make(chan struct{}, y.config.MaxConcurrent)
	var wg sync.WaitGroup

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			wg.Add(1)
			go func(filePath string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				result, err := y.ScanFile(ctx, filePath)
				if err != nil {
					y.logger.WithError(err).Warnf("Failed to scan file: %s", filePath)
					return
				}

				if len(result.Matches) > 0 {
					mutex.Lock()
					results = append(results, result)
					mutex.Unlock()
				}
			}(path)
		}

		return nil
	})

	wg.Wait()

	if err != nil {
		return nil, err
	}

	y.logger.Infof("YARA scan completed. Found %d files with matches", len(results))
	return results, nil
}

// scanContentWithRule scans content with a specific rule
func (y *YaraEngine) scanContentWithRule(content []byte, rule *YaraRule) *RuleMatch {
	contentStr := string(content)
	var stringMatches []*StringMatch
	matchCount := 0

	// Check each string pattern
	for name, pattern := range rule.Strings {
		matches := y.findStringMatches(contentStr, pattern, name)
		if len(matches) > 0 {
			stringMatches = append(stringMatches, matches...)
			matchCount++
		}
	}

	// Evaluate condition (simplified)
	if y.evaluateCondition(rule.Condition, matchCount, len(rule.Strings)) {
		confidence := y.calculateConfidence(matchCount, len(rule.Strings))
		
		return &RuleMatch{
			RuleName:    rule.Name,
			Category:    rule.Category,
			Severity:    rule.Severity,
			Description: rule.Description,
			Tags:        rule.Tags,
			Matches:     stringMatches,
			Confidence:  confidence,
		}
	}

	return nil
}

// findStringMatches finds all matches of a pattern in content
func (y *YaraEngine) findStringMatches(content, pattern, name string) []*StringMatch {
	var matches []*StringMatch
	
	// Simple string search (in real implementation, support regex and hex)
	offset := 0
	for {
		index := strings.Index(content[offset:], pattern)
		if index == -1 {
			break
		}
		
		actualOffset := int64(offset + index)
		context := y.extractContext(content, offset+index, len(pattern))
		
		match := &StringMatch{
			Name:    name,
			Content: pattern,
			Offset:  actualOffset,
			Length:  len(pattern),
			Context: context,
		}
		
		matches = append(matches, match)
		offset = offset + index + len(pattern)
	}
	
	return matches
}

// extractContext extracts surrounding context for a match
func (y *YaraEngine) extractContext(content string, offset, length int) string {
	start := offset - 50
	if start < 0 {
		start = 0
	}
	
	end := offset + length + 50
	if end > len(content) {
		end = len(content)
	}
	
	return content[start:end]
}

// evaluateCondition evaluates a YARA rule condition (simplified)
func (y *YaraEngine) evaluateCondition(condition string, matchCount, totalStrings int) bool {
	condition = strings.TrimSpace(condition)
	
	// Simple condition evaluation
	if condition == "all of them" {
		return matchCount == totalStrings
	} else if condition == "any of them" {
		return matchCount > 0
	} else if strings.Contains(condition, "of them") {
		// Parse numeric conditions like "2 of them"
		parts := strings.Fields(condition)
		if len(parts) >= 1 {
			if requiredCount := y.parseNumber(parts[0]); requiredCount > 0 {
				return matchCount >= requiredCount
			}
		}
	}
	
	// Default: require at least one match
	return matchCount > 0
}

// parseNumber parses a number from string
func (y *YaraEngine) parseNumber(s string) int {
	switch s {
	case "1", "one":
		return 1
	case "2", "two":
		return 2
	case "3", "three":
		return 3
	case "4", "four":
		return 4
	case "5", "five":
		return 5
	default:
		return 0
	}
}

// calculateConfidence calculates match confidence
func (y *YaraEngine) calculateConfidence(matchCount, totalStrings int) int {
	if totalStrings == 0 {
		return 0
	}
	
	percentage := (matchCount * 100) / totalStrings
	
	// Adjust confidence based on match ratio
	switch {
	case percentage >= 80:
		return 95
	case percentage >= 60:
		return 80
	case percentage >= 40:
		return 65
	case percentage >= 20:
		return 50
	default:
		return 30
	}
}

// calculateFileHash calculates MD5 hash of a file
func (y *YaraEngine) calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// GetRulesByCategory returns rules filtered by category
func (y *YaraEngine) GetRulesByCategory(category string) []*YaraRule {
	return y.rulesets[category]
}

// GetCategories returns all available rule categories
func (y *YaraEngine) GetCategories() []string {
	var categories []string
	for category := range y.rulesets {
		categories = append(categories, category)
	}
	return categories
}

// AddCustomRule adds a custom YARA rule
func (y *YaraEngine) AddCustomRule(rule *YaraRule) {
	y.rules = append(y.rules, rule)
	y.rulesets[rule.Category] = append(y.rulesets[rule.Category], rule)
	y.logger.Infof("Added custom rule: %s", rule.Name)
}

// ScanProcessMemory scans running process memory (simplified)
func (y *YaraEngine) ScanProcessMemory(ctx context.Context, pid int) (*ScanResult, error) {
	y.logger.Infof("Scanning process memory: PID %d", pid)
	
	// In a real implementation, this would read process memory
	// For demo, scan /proc/[pid]/cmdline and /proc/[pid]/environ
	
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	content, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return nil, err
	}
	
	result := &ScanResult{
		FilePath:  cmdlinePath,
		FileSize:  int64(len(content)),
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"type": "process_memory",
			"pid":  fmt.Sprintf("%d", pid),
		},
	}
	
	// Scan with malware detection rules
	for _, rule := range y.GetRulesByCategory("malware") {
		match := y.scanContentWithRule(content, rule)
		if match != nil {
			result.Matches = append(result.Matches, match)
		}
	}
	
	return result, nil
}

// QuarantineFile moves a suspicious file to quarantine
func (y *YaraEngine) QuarantineFile(filePath, quarantineDir string) error {
	if err := os.MkdirAll(quarantineDir, 0755); err != nil {
		return err
	}
	
	fileName := filepath.Base(filePath)
	timestamp := time.Now().Format("20060102_150405")
	quarantinePath := filepath.Join(quarantineDir, fmt.Sprintf("%s_%s", timestamp, fileName))
	
	// Move file to quarantine
	if err := os.Rename(filePath, quarantinePath); err != nil {
		return err
	}
	
	y.logger.Warnf("File quarantined: %s -> %s", filePath, quarantinePath)
	return nil
}