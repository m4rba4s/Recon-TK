package firmware

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"

	"recon-toolkit/pkg/core"
)

// StaticAnalyzer performs static analysis of binaries
type StaticAnalyzer struct {
	logger core.Logger
}

func (a *StaticAnalyzer) Analyze(ctx context.Context, binary *BinaryFile) (*AnalysisResult, error) {
	a.logger.Debug("Performing static analysis", core.NewField("binary", binary.Name))

	result := &AnalysisResult{
		Binary:          binary,
		Vulnerabilities: make([]BinaryVuln, 0),
		Functions:       make([]Function, 0),
		Imports:         make([]Import, 0),
		Exports:         make([]Export, 0),
		Sections:        make([]Section, 0),
		SuspiciousCode:  make([]SuspiciousCode, 0),
		Metadata:        make(map[string]interface{}),
	}

	// Analyze binary structure
	switch binary.Type {
	case BinaryTypeELF:
		a.analyzeELF(binary, result)
	case BinaryTypePE:
		a.analyzePE(binary, result)
	case BinaryTypeMachO:
		a.analyzeMachO(binary, result)
	default:
		a.analyzeGeneric(binary, result)
	}

	// Detect suspicious patterns
	a.detectSuspiciousPatterns(binary, result)

	return result, nil
}

func (a *StaticAnalyzer) GetCapabilities() []string {
	return []string{"elf_analysis", "pe_analysis", "macho_analysis", "pattern_detection"}
}

func (a *StaticAnalyzer) GetName() string {
	return "StaticAnalyzer"
}

func (a *StaticAnalyzer) analyzeELF(binary *BinaryFile, result *AnalysisResult) {
	content := binary.Content
	
	// Mock ELF analysis
	if len(content) > 52 {
		// ELF header analysis
		entryPoint := int64(content[24]) | int64(content[25])<<8 | int64(content[26])<<16 | int64(content[27])<<24
		
		result.Metadata["entry_point"] = entryPoint
		result.Metadata["elf_type"] = content[16]
		result.Metadata["machine"] = content[18]

		// Mock sections
		sections := []Section{
			{
				Name:        ".text",
				Address:     0x1000,
				Size:        int64(len(content) / 3),
				Permissions: "rx",
				Entropy:     7.2,
				Suspicious:  false,
			},
			{
				Name:        ".data",
				Address:     0x2000,
				Size:        int64(len(content) / 4),
				Permissions: "rw",
				Entropy:     5.8,
				Suspicious:  false,
			},
		}
		result.Sections = sections

		// Mock imports
		imports := []Import{
			{Name: "printf", Library: "libc.so.6", Address: 0x1040},
			{Name: "malloc", Library: "libc.so.6", Address: 0x1050},
			{Name: "strcpy", Library: "libc.so.6", Address: 0x1060},
		}
		result.Imports = imports

		// Check for dangerous functions
		for _, imp := range imports {
			if a.isDangerousFunction(imp.Name) {
				vuln := BinaryVuln{
					ID:          fmt.Sprintf("STATIC-%s", imp.Name),
					Type:        "dangerous_function",
					Description: fmt.Sprintf("Use of dangerous function: %s", imp.Name),
					Severity:    core.SeverityMedium,
					Exploitable: true,
				}
				result.Vulnerabilities = append(result.Vulnerabilities, vuln)
			}
		}
	}
}

func (a *StaticAnalyzer) analyzePE(binary *BinaryFile, result *AnalysisResult) {
	content := binary.Content
	
	// Mock PE analysis
	if len(content) > 64 {
		result.Metadata["pe_type"] = "executable"
		result.Metadata["subsystem"] = "console"

		// Mock sections
		sections := []Section{
			{
				Name:        ".text",
				Address:     0x401000,
				Size:        int64(len(content) / 2),
				Permissions: "rx",
				Entropy:     6.8,
				Suspicious:  false,
			},
			{
				Name:        ".rdata",
				Address:     0x402000,
				Size:        int64(len(content) / 4),
				Permissions: "r",
				Entropy:     5.2,
				Suspicious:  false,
			},
		}
		result.Sections = sections

		// Check for packed binary
		for _, section := range sections {
			if section.Entropy > 7.5 {
				suspiciousCode := SuspiciousCode{
					Type:        "high_entropy_section",
					Description: fmt.Sprintf("Section %s has high entropy (%.2f), possibly packed", section.Name, section.Entropy),
					Location:    section.Address,
					Severity:    core.SeverityMedium,
				}
				result.SuspiciousCode = append(result.SuspiciousCode, suspiciousCode)
			}
		}
	}
}

func (a *StaticAnalyzer) analyzeMachO(binary *BinaryFile, result *AnalysisResult) {
	// Mock Mach-O analysis
	result.Metadata["macho_type"] = "executable"
	result.Metadata["platform"] = "macos"

	// Basic structure analysis
	sections := []Section{
		{
			Name:        "__TEXT",
			Address:     0x100000000,
			Size:        int64(len(binary.Content) / 2),
			Permissions: "rx",
			Entropy:     6.5,
			Suspicious:  false,
		},
	}
	result.Sections = sections
}

func (a *StaticAnalyzer) analyzeGeneric(binary *BinaryFile, result *AnalysisResult) {
	// Generic analysis for unknown binary types
	content := binary.Content
	
	// Calculate entropy
	entropy := a.calculateEntropy(content)
	result.Metadata["entropy"] = entropy

	if entropy > 7.5 {
		suspiciousCode := SuspiciousCode{
			Type:        "high_entropy",
			Description: fmt.Sprintf("High entropy (%.2f) suggests encryption or packing", entropy),
			Location:    0,
			Severity:    core.SeverityMedium,
		}
		result.SuspiciousCode = append(result.SuspiciousCode, suspiciousCode)
	}
}

func (a *StaticAnalyzer) detectSuspiciousPatterns(binary *BinaryFile, result *AnalysisResult) {
	content := binary.Content
	contentStr := string(content)

	// Suspicious strings patterns
	suspiciousPatterns := map[string]core.Severity{
		"backdoor":     core.SeverityHigh,
		"rootkit":      core.SeverityHigh,
		"keylogger":    core.SeverityHigh,
		"password":     core.SeverityMedium,
		"admin123":     core.SeverityMedium,
		"telnet":       core.SeverityLow,
		"shell":        core.SeverityLow,
		"exec":         core.SeverityLow,
	}

	for pattern, severity := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(contentStr), pattern) {
			suspiciousCode := SuspiciousCode{
				Type:        "suspicious_string",
				Description: fmt.Sprintf("Found suspicious string: %s", pattern),
				Location:    int64(strings.Index(strings.ToLower(contentStr), pattern)),
				Severity:    severity,
			}
			result.SuspiciousCode = append(result.SuspiciousCode, suspiciousCode)
		}
	}
}

func (a *StaticAnalyzer) isDangerousFunction(funcName string) bool {
	dangerousFunctions := []string{
		"strcpy", "strcat", "sprintf", "gets", "scanf",
		"system", "exec", "popen", "malloc", "free",
	}

	for _, dangerous := range dangerousFunctions {
		if funcName == dangerous {
			return true
		}
	}
	return false
}

func (a *StaticAnalyzer) calculateEntropy(data []byte) float64 {
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

// StringAnalyzer extracts and analyzes strings from binaries
type StringAnalyzer struct {
	logger core.Logger
}

func (a *StringAnalyzer) Analyze(ctx context.Context, binary *BinaryFile) (*AnalysisResult, error) {
	a.logger.Debug("Performing string analysis", core.NewField("binary", binary.Name))

	result := &AnalysisResult{
		Binary:          binary,
		Strings:         make([]ExtractedString, 0),
		Vulnerabilities: make([]BinaryVuln, 0),
		SuspiciousCode:  make([]SuspiciousCode, 0),
		Metadata:        make(map[string]interface{}),
	}

	// Extract strings
	strings := a.extractStrings(binary.Content)
	result.Strings = strings

	// Analyze strings for secrets and vulnerabilities
	a.analyzeStringsForSecrets(strings, result)

	result.Metadata["string_count"] = len(strings)

	return result, nil
}

func (a *StringAnalyzer) GetCapabilities() []string {
	return []string{"string_extraction", "secret_detection", "url_extraction"}
}

func (a *StringAnalyzer) GetName() string {
	return "StringAnalyzer"
}

func (a *StringAnalyzer) extractStrings(content []byte) []ExtractedString {
	strings := make([]ExtractedString, 0)
	
	// Extract ASCII strings (min length 4)
	var current []byte
	var offset int64

	for i, b := range content {
		if b >= 32 && b <= 126 { // Printable ASCII
			if len(current) == 0 {
				offset = int64(i)
			}
			current = append(current, b)
		} else {
			if len(current) >= 4 {
				str := ExtractedString{
					Value:   string(current),
					Offset:  offset,
					Type:    a.classifyString(string(current)),
					Entropy: a.calculateStringEntropy(current),
				}
				strings = append(strings, str)
			}
			current = nil
		}
	}

	// Handle final string
	if len(current) >= 4 {
		str := ExtractedString{
			Value:   string(current),
			Offset:  offset,
			Type:    a.classifyString(string(current)),
			Entropy: a.calculateStringEntropy(current),
		}
		strings = append(strings, str)
	}

	return strings
}

func (a *StringAnalyzer) classifyString(s string) string {
	s = strings.ToLower(s)

	// URL pattern
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "ftp://") {
		return "url"
	}

	// Email pattern
	if matched, _ := regexp.MatchString(`\w+@\w+\.\w+`, s); matched {
		return "email"
	}

	// IP address pattern
	if matched, _ := regexp.MatchString(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, s); matched {
		return "ip_address"
	}

	// File path
	if strings.Contains(s, "/") && (strings.Contains(s, ".") || strings.HasPrefix(s, "/")) {
		return "file_path"
	}

	// Registry key (Windows)
	if strings.HasPrefix(s, "hkey_") || strings.Contains(s, "\\software\\") {
		return "registry_key"
	}

	// High entropy (possible encoded/encrypted)
	if a.calculateStringEntropy([]byte(s)) > 6.0 {
		return "high_entropy"
	}

	return "generic"
}

func (a *StringAnalyzer) calculateStringEntropy(data []byte) float64 {
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

func (a *StringAnalyzer) analyzeStringsForSecrets(extractedStrings []ExtractedString, result *AnalysisResult) {
	secretPatterns := map[string]core.Severity{
		"password":    core.SeverityMedium,
		"passwd":      core.SeverityMedium,
		"secret":      core.SeverityMedium,
		"api_key":     core.SeverityHigh,
		"private_key": core.SeverityHigh,
		"admin":       core.SeverityLow,
		"root":        core.SeverityLow,
		"token":       core.SeverityMedium,
		"ssh_key":     core.SeverityHigh,
	}

	for _, str := range extractedStrings {
		strLower := strings.ToLower(str.Value)
		
		for pattern, severity := range secretPatterns {
			if strings.Contains(strLower, pattern) {
				vuln := BinaryVuln{
					ID:          fmt.Sprintf("STRING-SECRET-%d", str.Offset),
					Type:        "embedded_secret",
					Description: fmt.Sprintf("Potential secret found: %s", pattern),
					Severity:    severity,
					Offset:      str.Offset,
					Exploitable: false,
				}
				result.Vulnerabilities = append(result.Vulnerabilities, vuln)
			}
		}

		// Check for high-entropy strings (possible keys)
		if str.Entropy > 6.5 && len(str.Value) > 20 {
			suspiciousCode := SuspiciousCode{
				Type:        "high_entropy_string",
				Description: fmt.Sprintf("High entropy string (%.2f): %s", str.Entropy, str.Value[:50]),
				Location:    str.Offset,
				Severity:    core.SeverityLow,
			}
			result.SuspiciousCode = append(result.SuspiciousCode, suspiciousCode)
		}
	}
}

// CryptoAnalyzer detects cryptographic elements and weaknesses
type CryptoAnalyzer struct {
	logger core.Logger
}

func (a *CryptoAnalyzer) Analyze(ctx context.Context, binary *BinaryFile) (*AnalysisResult, error) {
	a.logger.Debug("Performing crypto analysis", core.NewField("binary", binary.Name))

	result := &AnalysisResult{
		Binary:          binary,
		CryptoElements:  make([]CryptoElement, 0),
		Vulnerabilities: make([]BinaryVuln, 0),
		Metadata:        make(map[string]interface{}),
	}

	// Detect crypto constants and patterns
	a.detectCryptoConstants(binary.Content, result)
	a.detectCryptoPatterns(binary.Content, result)

	return result, nil
}

func (a *CryptoAnalyzer) GetCapabilities() []string {
	return []string{"crypto_detection", "key_analysis", "algorithm_identification"}
}

func (a *CryptoAnalyzer) GetName() string {
	return "CryptoAnalyzer"
}

func (a *CryptoAnalyzer) detectCryptoConstants(content []byte, result *AnalysisResult) {
	// Common crypto constants
	cryptoConstants := map[string]string{
		"\x67\x45\x23\x01": "MD5 initial vector",
		"\x01\x23\x45\x67": "MD5 initial vector (swapped)",
		"\xAB\xCD\xEF\x01": "SHA-1 constant",
		"\x6A\x09\xE6\x67": "SHA-256 constant",
	}

	for constant, description := range cryptoConstants {
		if bytes.Contains(content, []byte(constant)) {
			offset := int64(bytes.Index(content, []byte(constant)))
			crypto := CryptoElement{
				Type:        "constant",
				Algorithm:   description,
				Location:    offset,
				Weak:        false,
				Description: fmt.Sprintf("Found crypto constant: %s", description),
			}
			result.CryptoElements = append(result.CryptoElements, crypto)
		}
	}
}

func (a *CryptoAnalyzer) detectCryptoPatterns(content []byte, result *AnalysisResult) {
	contentStr := string(content)

	// Crypto algorithm strings
	cryptoAlgorithms := map[string]bool{
		"AES":    false,
		"DES":    true,  // Weak
		"3DES":   true,  // Weak
		"MD5":    true,  // Weak
		"SHA1":   true,  // Weak
		"SHA256": false,
		"SHA512": false,
		"RSA":    false,
		"RC4":    true,  // Weak
	}

	for algorithm, weak := range cryptoAlgorithms {
		if strings.Contains(strings.ToUpper(contentStr), algorithm) {
			offset := int64(strings.Index(strings.ToUpper(contentStr), algorithm))
			crypto := CryptoElement{
				Type:        "algorithm",
				Algorithm:   algorithm,
				Location:    offset,
				Weak:        weak,
				Description: fmt.Sprintf("Found crypto algorithm: %s", algorithm),
			}
			result.CryptoElements = append(result.CryptoElements, crypto)

			if weak {
				vuln := BinaryVuln{
					ID:          fmt.Sprintf("CRYPTO-WEAK-%s", algorithm),
					Type:        "weak_crypto",
					Description: fmt.Sprintf("Use of weak cryptographic algorithm: %s", algorithm),
					Severity:    core.SeverityMedium,
					Offset:      offset,
					Exploitable: false,
				}
				result.Vulnerabilities = append(result.Vulnerabilities, vuln)
			}
		}
	}
}

// DisassemblyAnalyzer performs basic disassembly and code analysis
type DisassemblyAnalyzer struct {
	logger core.Logger
}

func (a *DisassemblyAnalyzer) Analyze(ctx context.Context, binary *BinaryFile) (*AnalysisResult, error) {
	a.logger.Debug("Performing disassembly analysis", core.NewField("binary", binary.Name))

	result := &AnalysisResult{
		Binary:          binary,
		Functions:       make([]Function, 0),
		Vulnerabilities: make([]BinaryVuln, 0),
		SuspiciousCode:  make([]SuspiciousCode, 0),
		Metadata:        make(map[string]interface{}),
	}

	// Mock disassembly analysis
	a.mockDisassemblyAnalysis(binary, result)

	return result, nil
}

func (a *DisassemblyAnalyzer) GetCapabilities() []string {
	return []string{"disassembly", "control_flow", "vulnerability_detection"}
}

func (a *DisassemblyAnalyzer) GetName() string {
	return "DisassemblyAnalyzer"
}

func (a *DisassemblyAnalyzer) mockDisassemblyAnalysis(binary *BinaryFile, result *AnalysisResult) {
	// Mock function detection
	functions := []Function{
		{Name: "main", Address: 0x1040, Size: 256, Type: "function"},
		{Name: "vulnerable_function", Address: 0x1140, Size: 128, Type: "function"},
		{Name: "auth_check", Address: 0x1200, Size: 64, Type: "function"},
	}
	result.Functions = functions

	// Mock vulnerability detection in functions
	for _, fn := range functions {
		if strings.Contains(fn.Name, "vulnerable") {
			vuln := BinaryVuln{
				ID:          fmt.Sprintf("FUNC-%s", fn.Name),
				Type:        "buffer_overflow",
				Description: fmt.Sprintf("Potential buffer overflow in function %s", fn.Name),
				Severity:    core.SeverityHigh,
				Offset:      fn.Address,
				Exploitable: true,
				BufferSize:  256,
			}
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}
	}

	// Mock suspicious code patterns
	suspicious := []SuspiciousCode{
		{
			Type:        "ret2libc",
			Description: "Potential return-to-libc gadget",
			Location:    0x1080,
			Severity:    core.SeverityMedium,
		},
		{
			Type:        "rop_gadget",
			Description: "Potential ROP gadget sequence",
			Location:    0x1120,
			Severity:    core.SeverityLow,
		},
	}
	result.SuspiciousCode = suspicious
}