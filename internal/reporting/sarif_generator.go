package reporting

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"
)

type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool       SARIFTool       `json:"tool"`
	Results    []SARIFResult   `json:"results"`
	Invocation SARIFInvocation `json:"invocation"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	InformationURI  string          `json:"informationUri"`
	Rules           []SARIFRule     `json:"rules"`
	SupportedTaxonomies []SARIFTaxonomy `json:"supportedTaxonomies"`
}

type SARIFRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription SARIFText           `json:"shortDescription"`
	FullDescription  SARIFText           `json:"fullDescription"`
	Help             SARIFText           `json:"help"`
	Properties       SARIFRuleProperties `json:"properties"`
	DefaultConfiguration SARIFConfiguration `json:"defaultConfiguration"`
}

type SARIFRuleProperties struct {
	Tags           []string `json:"tags"`
	SecuritySeverity string `json:"security-severity"`
	Precision      string   `json:"precision"`
	ProblemSeverity string  `json:"problem.severity"`
}

type SARIFConfiguration struct {
	Level string `json:"level"`
}

type SARIFTaxonomy struct {
	Name string `json:"name"`
	Index int   `json:"index"`
	GUID  string `json:"guid"`
}

type SARIFResult struct {
	RuleID          string             `json:"ruleId"`
	RuleIndex       int                `json:"ruleIndex"`
	Level           string             `json:"level"`
	Message         SARIFText          `json:"message"`
	Locations       []SARIFLocation    `json:"locations"`
	PartialFingerprints SARIFFingerprints `json:"partialFingerprints"`
	Properties      SARIFResultProperties `json:"properties"`
	CodeFlows       []SARIFCodeFlow    `json:"codeFlows,omitempty"`
	RelatedLocations []SARIFLocation   `json:"relatedLocations,omitempty"`
}

type SARIFText struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion          `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI   string `json:"uri"`
	Index int    `json:"index,omitempty"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

type SARIFLogicalLocation struct {
	Name             string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind             string `json:"kind,omitempty"`
}

type SARIFFingerprints struct {
	PrimaryLocationLineHash string `json:"primaryLocationLineHash,omitempty"`
	StableId               string `json:"stableId,omitempty"`
}

type SARIFResultProperties struct {
	SecuritySeverity string            `json:"security-severity"`
	Tags             []string          `json:"tags"`
	CVSS             map[string]string `json:"cvss,omitempty"`
	CWE              []string          `json:"cwe,omitempty"`
	Precision        string            `json:"precision"`
}

type SARIFCodeFlow struct {
	ThreadFlows []SARIFThreadFlow `json:"threadFlows"`
}

type SARIFThreadFlow struct {
	Locations []SARIFThreadFlowLocation `json:"locations"`
}

type SARIFThreadFlowLocation struct {
	Location SARIFLocation `json:"location"`
	State    map[string]string `json:"state,omitempty"`
}

type SARIFInvocation struct {
	ExecutionSuccessful bool      `json:"executionSuccessful"`
	StartTimeUTC        time.Time `json:"startTimeUtc"`
	EndTimeUTC          time.Time `json:"endTimeUtc"`
	CommandLine         string    `json:"commandLine"`
	Arguments           []string  `json:"arguments,omitempty"`
	WorkingDirectory    SARIFArtifactLocation `json:"workingDirectory"`
}

type SARIFGenerator struct {
	toolName    string
	toolVersion string
	baseURI     string
}

func NewSARIFGenerator(toolName, toolVersion, baseURI string) *SARIFGenerator {
	return &SARIFGenerator{
		toolName:    toolName,
		toolVersion: toolVersion,
		baseURI:     baseURI,
	}
}

func (sg *SARIFGenerator) GenerateSARIF(findings []Finding, target string, startTime, endTime time.Time) (*SARIFReport, error) {
	rules := sg.generateRules(findings)
	results := sg.convertFindingsToResults(findings, rules)
	
	report := &SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           sg.toolName,
						Version:        sg.toolVersion,
						InformationURI: "https://github.com/funcybot/rtk-elite",
						Rules:          rules,
						SupportedTaxonomies: []SARIFTaxonomy{
							{
								Name:  "CWE",
								Index: 0,
								GUID:  "25f72d7e-8637-4c0a-8bb5-3d3d7d3b5f3e",
							},
							{
								Name:  "OWASP",
								Index: 1,
								GUID:  "a2e8b4c5-7f3d-4e9a-8c6b-1f4d7e8a9b2c",
							},
						},
					},
				},
				Results: results,
				Invocation: SARIFInvocation{
					ExecutionSuccessful: true,
					StartTimeUTC:        startTime,
					EndTimeUTC:          endTime,
					CommandLine:         fmt.Sprintf("rtk scan --target %s", target),
					Arguments:           []string{"scan", "--target", target},
					WorkingDirectory: SARIFArtifactLocation{
						URI: sg.baseURI,
					},
				},
			},
		},
	}
	
	return report, nil
}

func (sg *SARIFGenerator) generateRules(findings []Finding) []SARIFRule {
	ruleMap := make(map[string]SARIFRule)
	
	for _, finding := range findings {
		ruleID := sg.generateRuleID(finding)
		if _, exists := ruleMap[ruleID]; !exists {
			rule := sg.createRule(finding)
			ruleMap[ruleID] = rule
		}
	}
	
	rules := make([]SARIFRule, 0, len(ruleMap))
	for _, rule := range ruleMap {
		rules = append(rules, rule)
	}
	
	return rules
}

func (sg *SARIFGenerator) createRule(finding Finding) SARIFRule {
	ruleID := sg.generateRuleID(finding)
	
	descriptions := map[string]struct {
		short, full, help string
		tags              []string
		cwe               []string
		severity          string
		cweID             string
	}{
		"sql_injection": {
			short:    "SQL Injection vulnerability detected",
			full:     "A SQL injection vulnerability allows attackers to interfere with the queries that an application makes to its database.",
			help:     "To fix SQL injection vulnerabilities, use parameterized queries (prepared statements) or stored procedures. Never construct SQL queries using string concatenation with user input.",
			tags:     []string{"security", "sql", "injection", "database"},
			cwe:      []string{"CWE-89"},
			cweID:    "CWE-89",
			severity: "high",
		},
		"xss": {
			short:    "Cross-Site Scripting (XSS) vulnerability detected",
			full:     "Cross-site scripting vulnerabilities allow attackers to inject malicious scripts into web pages viewed by other users.",
			help:     "To prevent XSS, encode all user input before displaying it in HTML. Use content security policy (CSP) headers and validate input on both client and server side.",
			tags:     []string{"security", "xss", "injection", "web"},
			cwe:      []string{"CWE-79"},
			cweID:    "CWE-79",
			severity: "medium",
		},
		"rce": {
			short:    "Remote Code Execution vulnerability detected",
			full:     "Remote code execution vulnerabilities allow attackers to execute arbitrary code on the target system.",
			help:     "To prevent RCE, avoid executing user input as code. Use input validation, sandboxing, and principle of least privilege.",
			tags:     []string{"security", "rce", "execution", "critical"},
			cwe:      []string{"CWE-94", "CWE-78"},
			cweID:    "CWE-94",
			severity: "critical",
		},
		"lfi": {
			short:    "Local File Inclusion vulnerability detected",
			full:     "Local file inclusion vulnerabilities allow attackers to include files from the local filesystem.",
			help:     "To prevent LFI, validate and sanitize file paths. Use whitelisting for allowed files and avoid user input in file operations.",
			tags:     []string{"security", "lfi", "inclusion", "file"},
			cwe:      []string{"CWE-98"},
			cweID:    "CWE-98",
			severity: "high",
		},
		"host_bypass": {
			short:    "Host Header Bypass vulnerability detected",
			full:     "Host header injection allows attackers to manipulate server-side behavior through malicious Host headers.",
			help:     "Validate Host headers against a whitelist of allowed domains. Implement proper request routing validation.",
			tags:     []string{"security", "injection", "bypass", "web"},
			cwe:      []string{"CWE-20"},
			cweID:    "CWE-20",
			severity: "medium",
		},
		"origin_discovery": {
			short:    "Origin Server Discovery",
			full:     "The real origin server has been discovered behind CDN/proxy protection.",
			help:     "Ensure origin servers are not directly accessible from the internet. Use proper firewall rules.",
			tags:     []string{"information", "discovery", "infrastructure"},
			cwe:      []string{"CWE-200"},
			cweID:    "CWE-200",
			severity: "low",
		},
		"default": {
			short:    "Security vulnerability detected",
			full:     "A security vulnerability has been detected that may allow unauthorized access or actions.",
			help:     "Review the finding details and implement appropriate security controls.",
			tags:     []string{"security", "vulnerability"},
			cwe:      []string{"CWE-200"},
			cweID:    "CWE-200",
			severity: "medium",
		},
	}
	
	desc, exists := descriptions[finding.Type]
	if !exists {
		desc = descriptions["default"]
	}
	
	return SARIFRule{
		ID:   fmt.Sprintf("%s/%s", desc.cweID, ruleID),
		Name: fmt.Sprintf("RTK/%s", ruleID),
		ShortDescription: SARIFText{
			Text: desc.short,
		},
		FullDescription: SARIFText{
			Text: fmt.Sprintf("%s (CWE ID: %s)", desc.full, desc.cweID),
		},
		Help: SARIFText{
			Text:     desc.help,
			Markdown: fmt.Sprintf("## %s\n\n%s\n\n**CWE Classification:** %s\n\n### Remediation\n\n%s", desc.short, desc.full, desc.cweID, desc.help),
		},
		Properties: SARIFRuleProperties{
			Tags:             append(desc.tags, desc.cweID),
			SecuritySeverity: sg.getSeverityScore(desc.severity),
			Precision:        "high",
			ProblemSeverity:  desc.severity,
		},
		DefaultConfiguration: SARIFConfiguration{
			Level: sg.mapSeverityToLevel(desc.severity),
		},
	}
}

func (sg *SARIFGenerator) convertFindingsToResults(findings []Finding, rules []SARIFRule) []SARIFResult {
	ruleIndexMap := make(map[string]int)
	for i, rule := range rules {
		ruleIndexMap[rule.ID] = i
	}
	
	results := make([]SARIFResult, 0, len(findings))
	
	for _, finding := range findings {
		ruleID := sg.generateRuleID(finding)
		ruleIndex := ruleIndexMap[ruleID]
		
		result := SARIFResult{
			RuleID:    ruleID,
			RuleIndex: ruleIndex,
			Level:     sg.mapSeverityToLevel(finding.Severity),
			Message: SARIFText{
				Text: sg.generateMessage(finding),
			},
			Locations: sg.generateLocations(finding),
			PartialFingerprints: SARIFFingerprints{
				StableId: sg.generateStableID(finding),
			},
			Properties: SARIFResultProperties{
				SecuritySeverity: sg.getSeverityScore(finding.Severity),
				Tags:             sg.generateTags(finding),
				CWE:              sg.getCWE(finding.Type),
				Precision:        "high",
			},
		}
		
		// Add code flows for complex vulnerabilities
		if finding.Type == "sql_injection" || finding.Type == "rce" {
			result.CodeFlows = sg.generateCodeFlows(finding)
		}
		
		results = append(results, result)
	}
	
	return results
}

func (sg *SARIFGenerator) generateRuleID(finding Finding) string {
	return fmt.Sprintf("RTK%03d_%s", sg.getTypeID(finding.Type), finding.Type)
}

func (sg *SARIFGenerator) getTypeID(findingType string) int {
	typeIDs := map[string]int{
		"sql_injection":    89,
		"xss":             79,
		"rce":             94,
		"lfi":             98,
		"csrf":            352,
		"xxe":             611,
		"idor":            639,
		"host_bypass":     200,
		"origin_discovery": 200,
	}
	
	if id, exists := typeIDs[findingType]; exists {
		return id
	}
	return 999
}

func (sg *SARIFGenerator) generateMessage(finding Finding) string {
	messages := map[string]string{
		"sql_injection": "SQL injection vulnerability allows database access",
		"xss":          "Cross-site scripting vulnerability allows script injection",
		"rce":          "Remote code execution vulnerability allows arbitrary code execution",
		"lfi":          "Local file inclusion vulnerability allows file system access",
	}
	
	if msg, exists := messages[finding.Type]; exists {
		return fmt.Sprintf("%s in %s", msg, sg.getLocationFromEvidence(finding))
	}
	
	return fmt.Sprintf("%s vulnerability detected in %s", finding.Type, sg.getLocationFromEvidence(finding))
}

func (sg *SARIFGenerator) generateLocations(finding Finding) []SARIFLocation {
	location := SARIFLocation{
		PhysicalLocation: SARIFPhysicalLocation{
			ArtifactLocation: SARIFArtifactLocation{
				URI: sg.getURIFromEvidence(finding),
			},
		},
	}
	
	// Add logical location for web vulnerabilities
	if target := sg.getLocationFromEvidence(finding); target != "" {
		location.LogicalLocations = []SARIFLogicalLocation{
			{
				Name:               target,
				FullyQualifiedName: fmt.Sprintf("web://%s", target),
				Kind:               "resource",
			},
		}
	}
	
	return []SARIFLocation{location}
}

func (sg *SARIFGenerator) generateCodeFlows(finding Finding) []SARIFCodeFlow {
	// For web vulnerabilities, create a simple flow
	location := SARIFLocation{
		PhysicalLocation: SARIFPhysicalLocation{
			ArtifactLocation: SARIFArtifactLocation{
				URI: sg.getURIFromEvidence(finding),
			},
		},
	}
	
	return []SARIFCodeFlow{
		{
			ThreadFlows: []SARIFThreadFlow{
				{
					Locations: []SARIFThreadFlowLocation{
						{
							Location: location,
							State: map[string]string{
								"payload": sg.getPayloadFromEvidence(finding),
							},
						},
					},
				},
			},
		},
	}
}

func (sg *SARIFGenerator) generateStableID(finding Finding) string {
	// Generate a stable ID based on finding characteristics
	target := sg.getLocationFromEvidence(finding)
	return fmt.Sprintf("%s_%s_%s", finding.Type, target, finding.ID[:8])
}

func (sg *SARIFGenerator) generateTags(finding Finding) []string {
	baseTags := []string{"security", finding.Type}
	
	// Add severity-based tags
	switch finding.Severity {
	case "Critical":
		baseTags = append(baseTags, "critical", "high-impact")
	case "High":
		baseTags = append(baseTags, "high", "severe")
	case "Medium":
		baseTags = append(baseTags, "medium", "moderate")
	case "Low":
		baseTags = append(baseTags, "low", "minor")
	}
	
	// Add type-specific tags
	typeTagsMap := map[string][]string{
		"sql_injection": {"database", "injection", "data-access"},
		"xss":          {"web", "injection", "client-side"},
		"rce":          {"execution", "system", "remote"},
		"lfi":          {"file-system", "disclosure", "traversal"},
	}
	
	if typeTags, exists := typeTagsMap[finding.Type]; exists {
		baseTags = append(baseTags, typeTags...)
	}
	
	return baseTags
}

func (sg *SARIFGenerator) getCWE(findingType string) []string {
	cweMap := map[string][]string{
		"sql_injection": {"CWE-89"},
		"xss":          {"CWE-79"},
		"rce":          {"CWE-94", "CWE-78"},
		"lfi":          {"CWE-98"},
		"csrf":         {"CWE-352"},
		"xxe":          {"CWE-611"},
		"idor":         {"CWE-639"},
	}
	
	if cwe, exists := cweMap[findingType]; exists {
		return cwe
	}
	
	return []string{"CWE-200"}
}

func (sg *SARIFGenerator) mapSeverityToLevel(severity string) string {
	switch severity {
	case "Critical":
		return "error"
	case "High":
		return "error"
	case "Medium":
		return "warning"
	case "Low":
		return "note"
	default:
		return "info"
	}
}

func (sg *SARIFGenerator) getSeverityScore(severity string) string {
	scores := map[string]string{
		"critical": "9.0",
		"high":     "7.0",
		"medium":   "5.0",
		"low":      "3.0",
	}
	
	if score, exists := scores[severity]; exists {
		return score
	}
	return "5.0"
}

func (sg *SARIFGenerator) getLocationFromEvidence(finding Finding) string {
	if target, ok := finding.Evidence["target"].(string); ok {
		return target
	}
	if url, ok := finding.Evidence["url"].(string); ok {
		return url
	}
	return "unknown"
}

func (sg *SARIFGenerator) getURIFromEvidence(finding Finding) string {
	target := sg.getLocationFromEvidence(finding)
	if target == "unknown" {
		return "/"
	}
	
	// Convert target to URI format
	if filepath.IsAbs(target) {
		return target
	}
	
	return fmt.Sprintf("https://%s/", target)
}

func (sg *SARIFGenerator) getPayloadFromEvidence(finding Finding) string {
	if payload, ok := finding.Evidence["payload"].(string); ok {
		return payload
	}
	if param, ok := finding.Evidence["parameter"].(string); ok {
		return param
	}
	return ""
}

func (sg *SARIFGenerator) ExportSARIF(report *SARIFReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}