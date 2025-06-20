package firmware

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"recon-toolkit/pkg/core"
)

type BinaryEngine struct {
	config      *FirmwareConfig
	logger      core.Logger
	analyzers   map[string]BinaryAnalyzer
	extractors  map[string]FirmwareExtractor
	exploits    []BinaryExploit
	yararules   []YaraRule
	mutex       sync.RWMutex
}

type FirmwareConfig struct {
	AnalysisTypes    []string      `json:"analysis_types"`
	ExtractionMethods []string     `json:"extraction_methods"`
	DeepAnalysis     bool          `json:"deep_analysis"`
	StringAnalysis   bool          `json:"string_analysis"`
	CryptoAnalysis   bool          `json:"crypto_analysis"`
	MemoryAnalysis   bool          `json:"memory_analysis"`
	ExploitGeneration bool         `json:"exploit_generation"`
	YaraScanning     bool          `json:"yara_scanning"`
	Timeout          time.Duration `json:"timeout"`
	MaxFileSize      int64         `json:"max_file_size"`
	TempDir          string        `json:"temp_dir"`
}

type BinaryAnalyzer interface {
	Analyze(ctx context.Context, binary *BinaryFile) (*AnalysisResult, error)
	GetCapabilities() []string
	GetName() string
}

type FirmwareExtractor interface {
	Extract(ctx context.Context, firmware *FirmwareFile) (*ExtractionResult, error)
	GetSupportedFormats() []string
	GetName() string
}

type BinaryFile struct {
	Path         string            `json:"path"`
	Name         string            `json:"name"`
	Size         int64             `json:"size"`
	Type         BinaryType        `json:"type"`
	Architecture string            `json:"architecture"`
	Format       string            `json:"format"`
	Checksums    map[string]string `json:"checksums"`
	Metadata     map[string]interface{} `json:"metadata"`
	Content      []byte            `json:"-"`
}

type FirmwareFile struct {
	Path         string            `json:"path"`
	Name         string            `json:"name"`
	Size         int64             `json:"size"`
	Type         FirmwareType      `json:"type"`
	Vendor       string            `json:"vendor"`
	Version      string            `json:"version"`
	Format       string            `json:"format"`
	Checksums    map[string]string `json:"checksums"`
	Metadata     map[string]interface{} `json:"metadata"`
	Content      []byte            `json:"-"`
}

type AnalysisResult struct {
	Binary          *BinaryFile        `json:"binary"`
	Vulnerabilities []BinaryVuln       `json:"vulnerabilities"`
	Strings         []ExtractedString  `json:"strings"`
	Functions       []Function         `json:"functions"`
	Imports         []Import           `json:"imports"`
	Exports         []Export           `json:"exports"`
	Sections        []Section          `json:"sections"`
	CryptoElements  []CryptoElement    `json:"crypto_elements"`
	SuspiciousCode  []SuspiciousCode   `json:"suspicious_code"`
	Exploits        []BinaryExploit    `json:"exploits"`
	RiskScore       float64            `json:"risk_score"`
	Metadata        map[string]interface{} `json:"metadata"`
}

type ExtractionResult struct {
	Firmware        *FirmwareFile      `json:"firmware"`
	ExtractedFiles  []ExtractedFile    `json:"extracted_files"`
	Filesystem      *FilesystemInfo    `json:"filesystem"`
	BootLoader      *BootLoaderInfo    `json:"bootloader"`
	Kernel          *KernelInfo        `json:"kernel"`
	Services        []ServiceInfo      `json:"services"`
	Configurations  []ConfigFile       `json:"configurations"`
	Certificates    []Certificate      `json:"certificates"`
	Keys            []CryptoKey        `json:"keys"`
	Vulnerabilities []FirmwareVuln     `json:"vulnerabilities"`
	RiskScore       float64            `json:"risk_score"`
	Metadata        map[string]interface{} `json:"metadata"`
}

type BinaryExploit struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Type         ExploitType    `json:"type"`
	Severity     core.Severity  `json:"severity"`
	Description  string         `json:"description"`
	CVE          string         `json:"cve,omitempty"`
	CVSS         float64        `json:"cvss"`
	PoC          string         `json:"poc"`
	Payload      []byte         `json:"payload"`
	Requirements []string       `json:"requirements"`
	Evidence     []core.Evidence `json:"evidence"`
	Automated    bool           `json:"automated"`
}

type YaraRule struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Pattern     string   `json:"pattern"`
	Tags        []string `json:"tags"`
	Severity    core.Severity `json:"severity"`
}

// Enums
type BinaryType int
type FirmwareType int
type ExploitType int

const (
	// Binary Types
	BinaryTypeELF BinaryType = iota
	BinaryTypePE
	BinaryTypeMachO
	BinaryTypeShellcode
	BinaryTypeFirmware
	BinaryTypeDriver
	BinaryTypeLibrary
	BinaryTypeUnknown
)

const (
	// Firmware Types
	FirmwareTypeRouter FirmwareType = iota
	FirmwareTypeIoT
	FirmwareTypeMobile
	FirmwareTypeEmbedded
	FirmwareTypeBIOS
	FirmwareTypeUEFI
	FirmwareTypeBootloader
	FirmwareTypeUnknown
)

const (
	// Exploit Types
	ExploitTypeBufferOverflow ExploitType = iota
	ExploitTypeStackOverflow
	ExploitTypeHeapOverflow
	ExploitTypeFormatString
	ExploitTypeIntegerOverflow
	ExploitTypeUseAfterFree
	ExploitTypeRaceCondition
	ExploitTypePrivilegeEscalation
	ExploitTypeCodeInjection
	ExploitTypeMemoryCorruption
)

// NewBinaryEngine creates firmware/binary analysis engine
func NewBinaryEngine(logger core.Logger, config *FirmwareConfig) *BinaryEngine {
	if config == nil {
		config = &FirmwareConfig{
			AnalysisTypes:     []string{"static", "strings", "crypto", "exploits"},
			ExtractionMethods: []string{"binwalk", "unpack", "filesystem"},
			DeepAnalysis:      true,
			StringAnalysis:    true,
			CryptoAnalysis:    true,
			MemoryAnalysis:    false,
			ExploitGeneration: true,
			YaraScanning:      true,
			Timeout:           300 * time.Second,
			MaxFileSize:       100 * 1024 * 1024, // 100MB
			TempDir:           "/tmp/firmware-analysis",
		}
	}

	engine := &BinaryEngine{
		config:     config,
		logger:     logger,
		analyzers:  make(map[string]BinaryAnalyzer),
		extractors: make(map[string]FirmwareExtractor),
		exploits:   make([]BinaryExploit, 0),
		yararules:  make([]YaraRule, 0),
	}

	// Initialize analyzers and extractors
	engine.initializeAnalyzers()
	engine.initializeExtractors()
	engine.loadExploitDatabase()
	engine.loadYaraRules()

	return engine
}

// AnalyzeBinary performs comprehensive binary analysis
func (e *BinaryEngine) AnalyzeBinary(ctx context.Context, filePath string) (*AnalysisResult, error) {
	e.logger.Info("🔬 INITIATING BINARY ANALYSIS", core.NewField("file", filePath))

	// Load and prepare binary
	binary, err := e.loadBinaryFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load binary: %w", err)
	}

	result := &AnalysisResult{
		Binary:          binary,
		Vulnerabilities: make([]BinaryVuln, 0),
		Strings:         make([]ExtractedString, 0),
		Functions:       make([]Function, 0),
		Imports:         make([]Import, 0),
		Exports:         make([]Export, 0),
		Sections:        make([]Section, 0),
		CryptoElements:  make([]CryptoElement, 0),
		SuspiciousCode:  make([]SuspiciousCode, 0),
		Exploits:        make([]BinaryExploit, 0),
		Metadata:        make(map[string]interface{}),
	}

	// Run analyzers
	for analysisType, analyzer := range e.analyzers {
		if contains(e.config.AnalysisTypes, analysisType) {
			e.logger.Debug("Running analyzer", core.NewField("type", analysisType))
			
			analysisResult, err := analyzer.Analyze(ctx, binary)
			if err != nil {
				e.logger.Warn("Analyzer failed", 
					core.NewField("type", analysisType),
					core.NewField("error", err.Error()))
				continue
			}

			// Merge results
			e.mergeAnalysisResults(result, analysisResult)
		}
	}

	// YARA scanning
	if e.config.YaraScanning {
		yaraMatches := e.performYaraScanning(binary)
		result.Metadata["yara_matches"] = yaraMatches
	}

	// Exploit generation
	if e.config.ExploitGeneration {
		exploits := e.generateExploits(result)
		result.Exploits = exploits
	}

	// Calculate risk score
	result.RiskScore = e.calculateRiskScore(result)

	e.logger.Info("🔬 Binary analysis completed", 
		core.NewField("vulnerabilities", len(result.Vulnerabilities)),
		core.NewField("exploits", len(result.Exploits)),
		core.NewField("risk_score", result.RiskScore))

	return result, nil
}

// ExtractFirmware performs firmware extraction and analysis
func (e *BinaryEngine) ExtractFirmware(ctx context.Context, filePath string) (*ExtractionResult, error) {
	e.logger.Info("📦 INITIATING FIRMWARE EXTRACTION", core.NewField("file", filePath))

	// Load firmware file
	firmware, err := e.loadFirmwareFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load firmware: %w", err)
	}

	result := &ExtractionResult{
		Firmware:        firmware,
		ExtractedFiles:  make([]ExtractedFile, 0),
		Vulnerabilities: make([]FirmwareVuln, 0),
		Metadata:        make(map[string]interface{}),
	}

	// Run extractors
	for method, extractor := range e.extractors {
		if contains(e.config.ExtractionMethods, method) {
			e.logger.Debug("Running extractor", core.NewField("method", method))
			
			extractionResult, err := extractor.Extract(ctx, firmware)
			if err != nil {
				e.logger.Warn("Extractor failed", 
					core.NewField("method", method),
					core.NewField("error", err.Error()))
				continue
			}

			// Merge results
			e.mergeExtractionResults(result, extractionResult)
		}
	}

	// Analyze extracted files
	for _, file := range result.ExtractedFiles {
		if file.Type == "binary" || file.Type == "executable" {
			binaryResult, err := e.AnalyzeBinary(ctx, file.Path)
			if err == nil {
				// Convert binary vulns to firmware vulns
				for _, vuln := range binaryResult.Vulnerabilities {
					firmwareVuln := FirmwareVuln{
						ID:          vuln.ID,
						Type:        "binary_vulnerability",
						Description: vuln.Description,
						Severity:    vuln.Severity,
						File:        file.Path,
						CVE:         vuln.CVE,
					}
					result.Vulnerabilities = append(result.Vulnerabilities, firmwareVuln)
				}
			}
		}
	}

	// Calculate risk score
	result.RiskScore = e.calculateFirmwareRiskScore(result)

	e.logger.Info("📦 Firmware extraction completed", 
		core.NewField("extracted_files", len(result.ExtractedFiles)),
		core.NewField("vulnerabilities", len(result.Vulnerabilities)),
		core.NewField("risk_score", result.RiskScore))

	return result, nil
}

// Helper methods
func (e *BinaryEngine) loadBinaryFile(filePath string) (*BinaryFile, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if stat.Size() > e.config.MaxFileSize {
		return nil, fmt.Errorf("file too large: %d bytes", stat.Size())
	}

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	binary := &BinaryFile{
		Path:         filePath,
		Name:         filepath.Base(filePath),
		Size:         stat.Size(),
		Type:         e.detectBinaryType(content),
		Architecture: e.detectArchitecture(content),
		Format:       e.detectFormat(content),
		Checksums:    e.calculateChecksums(content),
		Metadata:     make(map[string]interface{}),
		Content:      content,
	}

	return binary, nil
}

func (e *BinaryEngine) loadFirmwareFile(filePath string) (*FirmwareFile, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	firmware := &FirmwareFile{
		Path:      filePath,
		Name:      filepath.Base(filePath),
		Size:      stat.Size(),
		Type:      e.detectFirmwareType(content),
		Vendor:    e.detectVendor(content),
		Version:   e.detectVersion(content),
		Format:    e.detectFormat(content),
		Checksums: e.calculateChecksums(content),
		Metadata:  make(map[string]interface{}),
		Content:   content,
	}

	return firmware, nil
}

func (e *BinaryEngine) detectBinaryType(content []byte) BinaryType {
	if len(content) < 4 {
		return BinaryTypeUnknown
	}

	// ELF magic
	if bytes.Equal(content[:4], []byte{0x7f, 0x45, 0x4c, 0x46}) {
		return BinaryTypeELF
	}

	// PE magic
	if bytes.Equal(content[:2], []byte{0x4d, 0x5a}) {
		return BinaryTypePE
	}

	// Mach-O magic
	if bytes.Equal(content[:4], []byte{0xfe, 0xed, 0xfa, 0xce}) ||
		bytes.Equal(content[:4], []byte{0xfe, 0xed, 0xfa, 0xcf}) ||
		bytes.Equal(content[:4], []byte{0xce, 0xfa, 0xed, 0xfe}) ||
		bytes.Equal(content[:4], []byte{0xcf, 0xfa, 0xed, 0xfe}) {
		return BinaryTypeMachO
	}

	return BinaryTypeUnknown
}

func (e *BinaryEngine) detectFirmwareType(content []byte) FirmwareType {
	// Simple heuristics for firmware type detection
	contentStr := string(content)
	
	if strings.Contains(contentStr, "router") || strings.Contains(contentStr, "openwrt") {
		return FirmwareTypeRouter
	}
	if strings.Contains(contentStr, "android") || strings.Contains(contentStr, "bootloader") {
		return FirmwareTypeMobile
	}
	if strings.Contains(contentStr, "BIOS") {
		return FirmwareTypeBIOS
	}
	if strings.Contains(contentStr, "UEFI") {
		return FirmwareTypeUEFI
	}

	return FirmwareTypeUnknown
}

func (e *BinaryEngine) detectArchitecture(content []byte) string {
	if len(content) < 20 {
		return "unknown"
	}

	// ELF architecture detection
	if bytes.Equal(content[:4], []byte{0x7f, 0x45, 0x4c, 0x46}) {
		switch content[18] {
		case 0x3e:
			return "x86_64"
		case 0x03:
			return "x86"
		case 0x28:
			return "arm"
		case 0xb7:
			return "aarch64"
		case 0x08:
			return "mips"
		}
	}

	return "unknown"
}

func (e *BinaryEngine) detectFormat(content []byte) string {
	if len(content) < 4 {
		return "unknown"
	}

	// Common firmware formats
	if bytes.Equal(content[:4], []byte{0x7f, 0x45, 0x4c, 0x46}) {
		return "ELF"
	}
	if bytes.Equal(content[:2], []byte{0x4d, 0x5a}) {
		return "PE"
	}
	if bytes.HasPrefix(content, []byte("ANDROID!")) {
		return "Android Boot Image"
	}
	if bytes.HasPrefix(content, []byte("uImage")) {
		return "U-Boot Image"
	}

	return "unknown"
}

func (e *BinaryEngine) detectVendor(content []byte) string {
	contentStr := strings.ToLower(string(content))
	
	vendors := map[string]string{
		"cisco":     "Cisco",
		"netgear":   "Netgear",
		"linksys":   "Linksys",
		"dlink":     "D-Link",
		"tplink":    "TP-Link",
		"asus":      "ASUS",
		"android":   "Google",
		"qualcomm":  "Qualcomm",
		"broadcom":  "Broadcom",
	}

	for pattern, vendor := range vendors {
		if strings.Contains(contentStr, pattern) {
			return vendor
		}
	}

	return "Unknown"
}

func (e *BinaryEngine) detectVersion(content []byte) string {
	// Simple version detection using regex
	versionRegex := regexp.MustCompile(`[vV]?(\d+\.\d+(?:\.\d+)?)`)
	matches := versionRegex.FindStringSubmatch(string(content))
	if len(matches) > 1 {
		return matches[1]
	}
	return "Unknown"
}

func (e *BinaryEngine) calculateChecksums(content []byte) map[string]string {
	checksums := make(map[string]string)

	// MD5
	md5Sum := md5.Sum(content)
	checksums["md5"] = hex.EncodeToString(md5Sum[:])

	// SHA1
	sha1Sum := sha1.Sum(content)
	checksums["sha1"] = hex.EncodeToString(sha1Sum[:])

	// SHA256
	sha256Sum := sha256.Sum256(content)
	checksums["sha256"] = hex.EncodeToString(sha256Sum[:])

	return checksums
}

func (e *BinaryEngine) performYaraScanning(binary *BinaryFile) []string {
	matches := make([]string, 0)

	for _, rule := range e.yararules {
		if e.matchYaraRule(binary.Content, rule) {
			matches = append(matches, rule.Name)
		}
	}

	return matches
}

func (e *BinaryEngine) matchYaraRule(content []byte, rule YaraRule) bool {
	// Simple pattern matching
	return strings.Contains(string(content), rule.Pattern)
}

func (e *BinaryEngine) generateExploits(result *AnalysisResult) []BinaryExploit {
	exploits := make([]BinaryExploit, 0)

	// Generate exploits based on vulnerabilities
	for _, vuln := range result.Vulnerabilities {
		if vuln.Exploitable {
			exploit := BinaryExploit{
				ID:          fmt.Sprintf("EXPLOIT-%s", vuln.ID),
				Name:        fmt.Sprintf("Auto-generated exploit for %s", vuln.Description),
				Type:        ExploitTypeBufferOverflow, // Default
				Severity:    vuln.Severity,
				Description: fmt.Sprintf("Automated exploit for %s vulnerability", vuln.Description),
				CVE:         vuln.CVE,
				Automated:   true,
			}

			// Generate simple PoC
			exploit.PoC = e.generatePoC(vuln)

			exploits = append(exploits, exploit)
		}
	}

	return exploits
}

func (e *BinaryEngine) generatePoC(vuln BinaryVuln) string {
	switch vuln.Type {
	case "buffer_overflow":
		return fmt.Sprintf("# Buffer overflow PoC for %s\n# Send %d 'A' characters to trigger overflow\nprint('A' * %d)", vuln.Description, vuln.BufferSize+100, vuln.BufferSize+100)
	case "format_string":
		return "# Format string PoC\n# Use format specifiers to read/write memory\nprintf('%08x.%08x.%08x.%08x')"
	default:
		return "# Generic PoC\n# Manual analysis required"
	}
}

func (e *BinaryEngine) calculateRiskScore(result *AnalysisResult) float64 {
	score := 0.0

	// Vulnerability scoring
	for _, vuln := range result.Vulnerabilities {
		switch vuln.Severity {
		case core.SeverityCritical:
			score += 20.0
		case core.SeverityHigh:
			score += 15.0
		case core.SeverityMedium:
			score += 10.0
		case core.SeverityLow:
			score += 5.0
		}

		if vuln.Exploitable {
			score += 10.0
		}
	}

	// Suspicious code
	score += float64(len(result.SuspiciousCode)) * 2.0

	// Crypto weaknesses
	for _, crypto := range result.CryptoElements {
		if crypto.Weak {
			score += 5.0
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (e *BinaryEngine) calculateFirmwareRiskScore(result *ExtractionResult) float64 {
	score := 0.0

	// Vulnerability scoring
	for _, vuln := range result.Vulnerabilities {
		switch vuln.Severity {
		case core.SeverityCritical:
			score += 25.0
		case core.SeverityHigh:
			score += 18.0
		case core.SeverityMedium:
			score += 12.0
		case core.SeverityLow:
			score += 6.0
		}
	}

	// Configuration issues
	for _, config := range result.Configurations {
		if config.HasSecrets {
			score += 15.0
		}
		if config.WeakPermissions {
			score += 8.0
		}
	}

	// Weak crypto
	for _, key := range result.Keys {
		if key.Weak {
			score += 10.0
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (e *BinaryEngine) mergeAnalysisResults(target, source *AnalysisResult) {
	target.Vulnerabilities = append(target.Vulnerabilities, source.Vulnerabilities...)
	target.Strings = append(target.Strings, source.Strings...)
	target.Functions = append(target.Functions, source.Functions...)
	target.Imports = append(target.Imports, source.Imports...)
	target.Exports = append(target.Exports, source.Exports...)
	target.Sections = append(target.Sections, source.Sections...)
	target.CryptoElements = append(target.CryptoElements, source.CryptoElements...)
	target.SuspiciousCode = append(target.SuspiciousCode, source.SuspiciousCode...)
}

func (e *BinaryEngine) mergeExtractionResults(target, source *ExtractionResult) {
	target.ExtractedFiles = append(target.ExtractedFiles, source.ExtractedFiles...)
	target.Services = append(target.Services, source.Services...)
	target.Configurations = append(target.Configurations, source.Configurations...)
	target.Certificates = append(target.Certificates, source.Certificates...)
	target.Keys = append(target.Keys, source.Keys...)
	target.Vulnerabilities = append(target.Vulnerabilities, source.Vulnerabilities...)
}

// Initialize analyzers and extractors
func (e *BinaryEngine) initializeAnalyzers() {
	e.analyzers["static"] = &StaticAnalyzer{logger: e.logger}
	e.analyzers["strings"] = &StringAnalyzer{logger: e.logger}
	e.analyzers["crypto"] = &CryptoAnalyzer{logger: e.logger}
	e.analyzers["disasm"] = &DisassemblyAnalyzer{logger: e.logger}
}

func (e *BinaryEngine) initializeExtractors() {
	e.extractors["binwalk"] = &BinwalkExtractor{logger: e.logger}
	e.extractors["unpack"] = &UnpackExtractor{logger: e.logger}
	e.extractors["filesystem"] = &FilesystemExtractor{logger: e.logger}
}

func (e *BinaryEngine) loadExploitDatabase() {
	// Load common binary exploits
	e.exploits = []BinaryExploit{
		{
			ID:          "BIN-001",
			Name:        "Stack Buffer Overflow",
			Type:        ExploitTypeStackOverflow,
			Severity:    core.SeverityHigh,
			Description: "Classic stack-based buffer overflow",
		},
		{
			ID:          "BIN-002",
			Name:        "Format String Vulnerability",
			Type:        ExploitTypeFormatString,
			Severity:    core.SeverityMedium,
			Description: "Format string attack vector",
		},
	}
}

func (e *BinaryEngine) loadYaraRules() {
	e.yararules = []YaraRule{
		{
			Name:        "Embedded_Credentials",
			Description: "Detects embedded credentials",
			Pattern:     "password",
			Tags:        []string{"credentials", "security"},
			Severity:    core.SeverityMedium,
		},
		{
			Name:        "Backdoor_Pattern",
			Description: "Detects potential backdoor patterns",
			Pattern:     "backdoor",
			Tags:        []string{"backdoor", "malware"},
			Severity:    core.SeverityHigh,
		},
	}
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Result types and data structures
type BinaryVuln struct {
	ID          string        `json:"id"`
	Type        string        `json:"type"`
	Description string        `json:"description"`
	Severity    core.Severity `json:"severity"`
	CVE         string        `json:"cve,omitempty"`
	Exploitable bool          `json:"exploitable"`
	BufferSize  int           `json:"buffer_size,omitempty"`
	Offset      int64         `json:"offset,omitempty"`
}

type FirmwareVuln struct {
	ID          string        `json:"id"`
	Type        string        `json:"type"`
	Description string        `json:"description"`
	Severity    core.Severity `json:"severity"`
	File        string        `json:"file"`
	CVE         string        `json:"cve,omitempty"`
}

type ExtractedString struct {
	Value   string `json:"value"`
	Offset  int64  `json:"offset"`
	Type    string `json:"type"`
	Entropy float64 `json:"entropy"`
}

type Function struct {
	Name    string `json:"name"`
	Address int64  `json:"address"`
	Size    int    `json:"size"`
	Type    string `json:"type"`
}

type Import struct {
	Name     string `json:"name"`
	Library  string `json:"library"`
	Address  int64  `json:"address"`
	Ordinal  int    `json:"ordinal,omitempty"`
}

type Export struct {
	Name    string `json:"name"`
	Address int64  `json:"address"`
	Ordinal int    `json:"ordinal,omitempty"`
}

type Section struct {
	Name         string `json:"name"`
	Address      int64  `json:"address"`
	Size         int64  `json:"size"`
	Permissions  string `json:"permissions"`
	Entropy      float64 `json:"entropy"`
	Suspicious   bool   `json:"suspicious"`
}

type CryptoElement struct {
	Type        string `json:"type"`
	Algorithm   string `json:"algorithm"`
	KeySize     int    `json:"key_size"`
	Location    int64  `json:"location"`
	Weak        bool   `json:"weak"`
	Description string `json:"description"`
}

type SuspiciousCode struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Location    int64  `json:"location"`
	Severity    core.Severity `json:"severity"`
}

type ExtractedFile struct {
	Path        string            `json:"path"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Size        int64             `json:"size"`
	Permissions string            `json:"permissions"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type FilesystemInfo struct {
	Type        string   `json:"type"`
	MountPoints []string `json:"mount_points"`
	FileCount   int      `json:"file_count"`
	TotalSize   int64    `json:"total_size"`
}

type BootLoaderInfo struct {
	Type    string `json:"type"`
	Version string `json:"version"`
	Address int64  `json:"address"`
	Size    int64  `json:"size"`
}

type KernelInfo struct {
	Version      string   `json:"version"`
	Architecture string   `json:"architecture"`
	Modules      []string `json:"modules"`
	Address      int64    `json:"address"`
}

type ServiceInfo struct {
	Name        string   `json:"name"`
	Binary      string   `json:"binary"`
	Config      string   `json:"config"`
	Ports       []int    `json:"ports"`
	StartupType string   `json:"startup_type"`
	User        string   `json:"user"`
}

type ConfigFile struct {
	Path            string            `json:"path"`
	Type            string            `json:"type"`
	HasSecrets      bool              `json:"has_secrets"`
	WeakPermissions bool              `json:"weak_permissions"`
	Settings        map[string]string `json:"settings"`
}

type Certificate struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Algorithm string    `json:"algorithm"`
	KeySize   int       `json:"key_size"`
	SelfSigned bool     `json:"self_signed"`
}

type CryptoKey struct {
	Type      string `json:"type"`
	Algorithm string `json:"algorithm"`
	Size      int    `json:"size"`
	Weak      bool   `json:"weak"`
	Location  string `json:"location"`
}