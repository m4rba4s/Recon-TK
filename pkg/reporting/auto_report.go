/*
Automated Report Generator with PoC
===================================

Автоматический генератор профессиональных pentest отчётов с интеграцией AI.
Features:
- Автоматическая генерация executive summary
- Техническая документация уязвимостей
- Генерация PoC эксплойтов
- Risk assessment и CVSS scoring
- Compliance mapping (OWASP, NIST, etc.)
- Multiple output formats (PDF, HTML, JSON, Word)
- AI-powered vulnerability analysis
- Automated remediation recommendations
*/

package reporting

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"recon-toolkit/pkg/ai"
	"recon-toolkit/pkg/knowledge"
	"recon-toolkit/pkg/multiprotocol"
	"recon-toolkit/pkg/scanner"
	"recon-toolkit/pkg/waf"
)

// ReportType represents different report types
type ReportType string

const (
	ReportExecutive    ReportType = "executive"
	ReportTechnical    ReportType = "technical"
	ReportCompliance   ReportType = "compliance"
	ReportPenetration  ReportType = "penetration"
	ReportVulnerability ReportType = "vulnerability"
)

// VulnerabilityRating represents vulnerability severity
type VulnerabilityRating string

const (
	RatingCritical VulnerabilityRating = "Critical"
	RatingHigh     VulnerabilityRating = "High"
	RatingMedium   VulnerabilityRating = "Medium"
	RatingLow      VulnerabilityRating = "Low"
	RatingInfo     VulnerabilityRating = "Informational"
)

// Finding represents a security finding
type Finding struct {
	ID            string              `json:"id"`
	Title         string              `json:"title"`
	Severity      VulnerabilityRating `json:"severity"`
	CVSSScore     float64            `json:"cvss_score"`
	CVSSVector    string             `json:"cvss_vector"`
	Description   string             `json:"description"`
	Impact        string             `json:"impact"`
	Evidence      []Evidence         `json:"evidence"`
	Remediation   string             `json:"remediation"`
	References    []string           `json:"references"`
	CWE           string             `json:"cwe"`
	CVE           []string           `json:"cve"`
	
	// Technical details
	AffectedHosts []string           `json:"affected_hosts"`
	Ports         []int              `json:"ports"`
	Services      []string           `json:"services"`
	ProofOfConcept string            `json:"proof_of_concept"`
	ExploitCode   string             `json:"exploit_code"`
	
	// Compliance mapping
	OWASP         []string           `json:"owasp"`
	NIST          []string           `json:"nist"`
	ISO27001      []string           `json:"iso27001"`
	
	// Metadata
	FirstSeen     time.Time          `json:"first_seen"`
	LastSeen      time.Time          `json:"last_seen"`
	Verified      bool               `json:"verified"`
	FalsePositive bool               `json:"false_positive"`
}

// Evidence represents evidence for a finding
type Evidence struct {
	Type        string            `json:"type"` // screenshot, log, network_capture, code
	Description string            `json:"description"`
	Data        string            `json:"data"`
	Timestamp   time.Time         `json:"timestamp"`
	Metadata    map[string]string `json:"metadata"`
}

// ReportMetadata represents report metadata
type ReportMetadata struct {
	Title           string            `json:"title"`
	Client          string            `json:"client"`
	Consultant      string            `json:"consultant"`
	Company         string            `json:"company"`
	Version         string            `json:"version"`
	Classification  string            `json:"classification"`
	GeneratedAt     time.Time         `json:"generated_at"`
	ScanPeriod      string            `json:"scan_period"`
	Scope           []string          `json:"scope"`
	Methodology     []string          `json:"methodology"`
	Tools           []string          `json:"tools"`
	Disclaimer      string            `json:"disclaimer"`
	ExecutiveSummary string           `json:"executive_summary"`
}

// RiskMetrics represents risk calculations
type RiskMetrics struct {
	TotalFindings    int                            `json:"total_findings"`
	FindingsBySeverity map[VulnerabilityRating]int  `json:"findings_by_severity"`
	AverageCVSS     float64                        `json:"average_cvss"`
	RiskScore       float64                        `json:"risk_score"`
	ComplianceScore float64                        `json:"compliance_score"`
	TopRisks        []string                       `json:"top_risks"`
	
	// Host-based metrics
	HostsAffected   int                            `json:"hosts_affected"`
	ServicesAffected int                           `json:"services_affected"`
	PortsAffected   int                            `json:"ports_affected"`
}

// Report represents a complete security assessment report
type Report struct {
	Metadata    ReportMetadata         `json:"metadata"`
	Findings    []Finding              `json:"findings"`
	Metrics     RiskMetrics            `json:"metrics"`
	Appendices  map[string]interface{} `json:"appendices"`
	
	// AI-generated content
	AIAnalysis  string                 `json:"ai_analysis"`
	Recommendations []string           `json:"recommendations"`
	ThreatModel string                 `json:"threat_model"`
}

// ReportGenerator represents the main report generator
type ReportGenerator struct {
	aiEngine    *ai.LLMEngine
	knowledgeDB *knowledge.KnowledgeDB
	logger      *logrus.Logger
	templates   map[string]*template.Template
	config      ReportConfig
}

// ReportConfig represents report generation configuration
type ReportConfig struct {
	Company         string
	Consultant      string
	OutputDir       string
	EnableAI        bool
	AIModel         string
	AIAPIKey        string
	IncludePoC      bool
	IncludeExploits bool
	ComplianceFrameworks []string
	CustomTemplates map[string]string
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(config ReportConfig) (*ReportGenerator, error) {
	generator := &ReportGenerator{
		logger:    logrus.New(),
		templates: make(map[string]*template.Template),
		config:    config,
	}

	// Initialize AI engine if enabled
	if config.EnableAI && config.AIAPIKey != "" {
		generator.aiEngine = ai.NewLLMEngine(
			ai.ProviderOpenAI,
			config.AIAPIKey,
			"",
			config.AIModel,
		)
	}

	// Initialize knowledge database
	dbPath := filepath.Join(config.OutputDir, "knowledge.json")
	var err error
	generator.knowledgeDB, err = knowledge.NewKnowledgeDB(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize knowledge DB: %w", err)
	}

	// Load templates
	if err := generator.loadTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}

	return generator, nil
}

// GenerateReport generates a comprehensive security report
func (rg *ReportGenerator) GenerateReport(ctx context.Context, scanResults interface{}, reportType ReportType) (*Report, error) {
	rg.logger.Info("Starting report generation")

	report := &Report{
		Metadata: ReportMetadata{
			Title:       "Security Assessment Report",
			Company:     rg.config.Company,
			Consultant:  rg.config.Consultant,
			Version:     "1.0",
			GeneratedAt: time.Now(),
			Tools:       []string{"recon-toolkit"},
			Methodology: []string{"OWASP", "NIST", "PTES"},
		},
		Findings:    make([]Finding, 0),
		Appendices:  make(map[string]interface{}),
		Recommendations: make([]string, 0),
	}

	// Process different types of scan results
	switch results := scanResults.(type) {
	case *scanner.ScanResult:
		rg.processPortScanResults(results, report)
	case *waf.WAFResult:
		rg.processWAFResults(results, report)
	case *multiprotocol.ScanResult:
		rg.processMultiProtocolResults(results, report)
	case map[string]interface{}:
		rg.processMultipleResults(results, report)
	default:
		return nil, fmt.Errorf("unsupported scan result type: %T", scanResults)
	}

	// Calculate risk metrics
	rg.calculateRiskMetrics(report)

	// Generate AI analysis if enabled
	if rg.aiEngine != nil {
		if err := rg.generateAIAnalysis(ctx, report); err != nil {
			rg.logger.Warnf("AI analysis failed: %v", err)
		}
	}

	// Generate executive summary
	rg.generateExecutiveSummary(report)

	// Generate recommendations
	rg.generateRecommendations(report)

	rg.logger.Info("Report generation completed")
	return report, nil
}

// processPortScanResults processes port scan results
func (rg *ReportGenerator) processPortScanResults(scanResult *scanner.ScanResult, report *Report) {
	if scanResult.OpenPorts == 0 {
		return
	}

	// Create findings for open ports
	for _, portResult := range scanResult.Ports {
		if portResult.State == "open" {
			finding := Finding{
				ID:       fmt.Sprintf("PORT-%d", portResult.Port),
				Title:    fmt.Sprintf("Open Port %d (%s)", portResult.Port, portResult.Service),
				Severity: rg.assessPortSeverity(portResult.Port, portResult.Service),
				Description: fmt.Sprintf("Port %d is open and running %s service", 
					portResult.Port, portResult.Service),
				AffectedHosts: []string{scanResult.Target},
				Ports:         []int{portResult.Port},
				Services:      []string{portResult.Service},
				FirstSeen:     time.Now(),
				LastSeen:      time.Now(),
				Verified:      true,
			}

			// Add evidence
			if portResult.Banner != "" {
				evidence := Evidence{
					Type:        "network_response",
					Description: "Service banner",
					Data:        portResult.Banner,
					Timestamp:   time.Now(),
				}
				finding.Evidence = append(finding.Evidence, evidence)
			}

			// Generate PoC if enabled
			if rg.config.IncludePoC {
				finding.ProofOfConcept = rg.generatePortPoC(portResult.Port, portResult.Service)
			}

			// Set CVSS score and remediation
			finding.CVSSScore = rg.calculateCVSS(finding)
			finding.Remediation = rg.generateRemediation(finding)

			report.Findings = append(report.Findings, finding)
		}
	}

	// Add honeypot detection finding
	if scanResult.Honeypot {
		finding := Finding{
			ID:          "HONEYPOT-DETECTED",
			Title:       "Honeypot Environment Detected",
			Severity:    RatingHigh,
			CVSSScore:   7.5,
			Description: "The target appears to be a honeypot or decoy system",
			Impact:      "This may indicate that the assessment is being monitored or logged",
			AffectedHosts: []string{scanResult.Target},
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			Verified:    true,
			Remediation: "Verify the legitimacy of the target system and proceed with caution",
		}
		report.Findings = append(report.Findings, finding)
	}
}

// processWAFResults processes WAF detection results
func (rg *ReportGenerator) processWAFResults(wafResult *waf.WAFResult, report *Report) {
	if wafResult == nil {
		return
	}
	
	if !wafResult.WAFDetected {
		// No WAF detected - this might be a finding
		finding := Finding{
			ID:          "NO-WAF-DETECTED",
			Title:       "Web Application Firewall Not Detected",
			Severity:    RatingMedium,
			CVSSScore:   5.3,
			Description: "No Web Application Firewall was detected protecting the web application",
			Impact:      "Application may be vulnerable to web-based attacks",
			AffectedHosts: []string{wafResult.Target},
			Remediation: "Consider implementing a Web Application Firewall (WAF) solution",
			OWASP:      []string{"A06:2021 - Vulnerable and Outdated Components"},
		}
		report.Findings = append(report.Findings, finding)
		return
	}

	// WAF detected
	finding := Finding{
		ID:       "WAF-DETECTED",
		Title:    fmt.Sprintf("Web Application Firewall Detected: %s", wafResult.WAFType),
		Severity: RatingInfo,
		Description: fmt.Sprintf("A %s Web Application Firewall was detected with %.2f confidence", 
			wafResult.WAFType, wafResult.Confidence),
		AffectedHosts: []string{wafResult.Target},
		FirstSeen:     time.Now(),
		LastSeen:      time.Now(),
		Verified:      true,
	}

	// Check bypass attempts
	successfulBypasses := 0
	for _, bypass := range wafResult.Bypasses {
		if bypass.Success {
			successfulBypasses++
		}
	}

	if successfulBypasses > 0 {
		finding.Title = fmt.Sprintf("WAF Bypass Possible: %s", wafResult.WAFType)
		finding.Severity = RatingHigh
		finding.CVSSScore = 8.1
		finding.Description += fmt.Sprintf(". %d bypass techniques were successful", successfulBypasses)
		finding.Impact = "WAF protection may be insufficient against determined attackers"
		
		// Add bypass evidence
		for _, bypass := range wafResult.Bypasses {
			if bypass.Success {
				evidence := Evidence{
					Type:        "bypass_technique",
					Description: fmt.Sprintf("Successful bypass: %s", bypass.Technique),
					Data:        bypass.Payload,
					Timestamp:   time.Now(),
				}
				finding.Evidence = append(finding.Evidence, evidence)
			}
		}

		// Generate PoC
		if rg.config.IncludePoC {
			finding.ProofOfConcept = rg.generateWAFBypassPoC(wafResult.Bypasses)
		}
	}

	report.Findings = append(report.Findings, finding)
}

// processMultiProtocolResults processes multiprotocol scan results
func (rg *ReportGenerator) processMultiProtocolResults(scanResult *multiprotocol.ScanResult, report *Report) {
	for _, protocolResult := range scanResult.Protocols {
		if protocolResult.State != "open" {
			continue
		}

		finding := Finding{
			ID:       fmt.Sprintf("PROTOCOL-%s-%d", protocolResult.Protocol, protocolResult.Port),
			Title:    fmt.Sprintf("%s Service on Port %d", strings.ToUpper(string(protocolResult.Protocol)), protocolResult.Port),
			Severity: rg.assessProtocolSeverity(protocolResult.Protocol),
			Description: fmt.Sprintf("%s service detected on port %d", protocolResult.Service, protocolResult.Port),
			AffectedHosts: []string{scanResult.Target},
			Ports:         []int{protocolResult.Port},
			Services:      []string{protocolResult.Service},
			FirstSeen:     time.Now(),
			LastSeen:      time.Now(),
			Verified:      true,
		}

		// Add protocol-specific details
		if protocolResult.Version != "" {
			finding.Description += fmt.Sprintf(" (Version: %s)", protocolResult.Version)
		}

		// Add vulnerabilities found during protocol scan
		for _, vuln := range protocolResult.Vulnerabilities {
			vulnFinding := Finding{
				ID:          fmt.Sprintf("VULN-%s", vuln.ID),
				Title:       vuln.Name,
				Severity:    VulnerabilityRating(vuln.Severity),
				Description: vuln.Description,
				CVE:         []string{vuln.CVE},
				AffectedHosts: []string{scanResult.Target},
				Ports:         []int{protocolResult.Port},
				Services:      []string{protocolResult.Service},
				FirstSeen:     time.Now(),
				LastSeen:      time.Now(),
				Verified:      true,
			}

			if vuln.Proof != "" {
				evidence := Evidence{
					Type:        "vulnerability_proof",
					Description: "Vulnerability evidence",
					Data:        vuln.Proof,
					Timestamp:   time.Now(),
				}
				vulnFinding.Evidence = append(vulnFinding.Evidence, evidence)
			}

			vulnFinding.CVSSScore = rg.calculateCVSS(vulnFinding)
			vulnFinding.Remediation = rg.generateRemediation(vulnFinding)

			report.Findings = append(report.Findings, vulnFinding)
		}

		// Generate PoC for protocol
		if rg.config.IncludePoC {
			finding.ProofOfConcept = rg.generateProtocolPoC(protocolResult)
		}

		finding.CVSSScore = rg.calculateCVSS(finding)
		finding.Remediation = rg.generateRemediation(finding)

		report.Findings = append(report.Findings, finding)
	}
}

// Assessment and scoring methods

func (rg *ReportGenerator) assessPortSeverity(port int, service string) VulnerabilityRating {
	// High-risk ports
	highRiskPorts := map[int]bool{
		21: true, 22: true, 23: true, 135: true, 139: true, 445: true,
		1433: true, 3306: true, 3389: true, 5432: true, 6379: true,
	}

	// Medium-risk ports
	mediumRiskPorts := map[int]bool{
		25: true, 53: true, 110: true, 143: true, 993: true, 995: true,
		587: true, 465: true,
	}

	if highRiskPorts[port] {
		return RatingHigh
	} else if mediumRiskPorts[port] {
		return RatingMedium
	} else if port == 80 || port == 443 {
		return RatingLow
	}

	return RatingInfo
}

func (rg *ReportGenerator) assessProtocolSeverity(protocol multiprotocol.ProtocolType) VulnerabilityRating {
	switch protocol {
	case multiprotocol.ProtocolSMB, multiprotocol.ProtocolRDP, multiprotocol.ProtocolSSH:
		return RatingHigh
	case multiprotocol.ProtocolMySQL, multiprotocol.ProtocolPostgreSQL, multiprotocol.ProtocolMongoDB, multiprotocol.ProtocolRedis:
		return RatingHigh
	case multiprotocol.ProtocolFTP, multiprotocol.ProtocolTelnet:
		return RatingMedium
	case multiprotocol.ProtocolHTTP, multiprotocol.ProtocolHTTPS:
		return RatingLow
	default:
		return RatingInfo
	}
}

func (rg *ReportGenerator) calculateCVSS(finding Finding) float64 {
	// Simplified CVSS calculation
	baseScore := 0.0

	switch finding.Severity {
	case RatingCritical:
		baseScore = 9.0
	case RatingHigh:
		baseScore = 7.0
	case RatingMedium:
		baseScore = 5.0
	case RatingLow:
		baseScore = 3.0
	case RatingInfo:
		baseScore = 0.0
	}

	// Adjust based on evidence and verification
	if finding.Verified {
		baseScore += 0.5
	}
	if len(finding.Evidence) > 0 {
		baseScore += 0.3
	}

	if baseScore > 10.0 {
		baseScore = 10.0
	}

	return baseScore
}

// PoC generation methods

func (rg *ReportGenerator) generatePortPoC(port int, service string) string {
	poc := fmt.Sprintf("# Proof of Concept for %s on port %d\n\n", service, port)
	poc += fmt.Sprintf("# Basic connection test:\n")
	poc += fmt.Sprintf("nc -nv <target> %d\n\n", port)

	switch service {
	case "ssh":
		poc += "# SSH version enumeration:\n"
		poc += fmt.Sprintf("ssh -o ConnectTimeout=5 user@<target> -p %d\n", port)
	case "ftp":
		poc += "# FTP anonymous login test:\n"
		poc += fmt.Sprintf("ftp <target> %d\n", port)
		poc += "# Username: anonymous\n# Password: anonymous@domain.com\n"
	case "http", "https":
		scheme := "http"
		if port == 443 {
			scheme = "https"
		}
		poc += fmt.Sprintf("# Web service enumeration:\n")
		poc += fmt.Sprintf("curl -I %s://<target>:%d/\n", scheme, port)
	case "mysql":
		poc += "# MySQL connection test:\n"
		poc += fmt.Sprintf("mysql -h <target> -P %d -u root -p\n", port)
	}

	return poc
}

func (rg *ReportGenerator) generateWAFBypassPoC(bypasses []waf.BypassTest) string {
	poc := "# WAF Bypass Proof of Concept\n\n"

	for _, bypass := range bypasses {
		if bypass.Success {
			poc += fmt.Sprintf("# Successful bypass technique: %s\n", bypass.Technique)
			poc += fmt.Sprintf("curl -X GET '%s' \\\n", bypass.Payload)
			poc += "  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'\n\n"
		}
	}

	return poc
}

func (rg *ReportGenerator) generateProtocolPoC(protocolResult multiprotocol.ProtocolResult) string {
	poc := fmt.Sprintf("# %s Protocol PoC for port %d\n\n", 
		strings.ToUpper(string(protocolResult.Protocol)), protocolResult.Port)

	switch protocolResult.Protocol {
	case multiprotocol.ProtocolRedis:
		poc += "# Redis unauthenticated access:\n"
		poc += fmt.Sprintf("redis-cli -h <target> -p %d\n", protocolResult.Port)
		poc += "INFO\nCONFIG GET \"*\"\n"
	case multiprotocol.ProtocolMongoDB:
		poc += "# MongoDB unauthenticated access:\n"
		poc += fmt.Sprintf("mongo <target>:%d\n", protocolResult.Port)
		poc += "show dbs\n"
	case multiprotocol.ProtocolSMB:
		poc += "# SMB enumeration:\n"
		poc += fmt.Sprintf("smbclient -L //<target> -p %d\n", protocolResult.Port)
		poc += "enum4linux <target>\n"
	}

	return poc
}

// Report generation methods

func (rg *ReportGenerator) calculateRiskMetrics(report *Report) {
	metrics := RiskMetrics{
		TotalFindings:    len(report.Findings),
		FindingsBySeverity: make(map[VulnerabilityRating]int),
		TopRisks:         make([]string, 0),
	}

	cvssSum := 0.0
	hostsSet := make(map[string]bool)
	servicesSet := make(map[string]bool)
	portsSet := make(map[int]bool)

	for _, finding := range report.Findings {
		// Count by severity
		metrics.FindingsBySeverity[finding.Severity]++

		// Sum CVSS scores
		cvssSum += finding.CVSSScore

		// Track affected assets
		for _, host := range finding.AffectedHosts {
			hostsSet[host] = true
		}
		for _, service := range finding.Services {
			servicesSet[service] = true
		}
		for _, port := range finding.Ports {
			portsSet[port] = true
		}

		// Collect high-severity findings for top risks
		if finding.Severity == RatingCritical || finding.Severity == RatingHigh {
			metrics.TopRisks = append(metrics.TopRisks, finding.Title)
		}
	}

	// Calculate averages
	if len(report.Findings) > 0 {
		metrics.AverageCVSS = cvssSum / float64(len(report.Findings))
	}

	// Calculate risk score (0-100)
	criticalWeight := float64(metrics.FindingsBySeverity[RatingCritical]) * 10
	highWeight := float64(metrics.FindingsBySeverity[RatingHigh]) * 7
	mediumWeight := float64(metrics.FindingsBySeverity[RatingMedium]) * 4
	lowWeight := float64(metrics.FindingsBySeverity[RatingLow]) * 1

	totalWeight := criticalWeight + highWeight + mediumWeight + lowWeight
	if totalWeight > 100 {
		totalWeight = 100
	}
	metrics.RiskScore = totalWeight

	// Set asset counts
	metrics.HostsAffected = len(hostsSet)
	metrics.ServicesAffected = len(servicesSet)
	metrics.PortsAffected = len(portsSet)

	// Limit top risks to 10
	if len(metrics.TopRisks) > 10 {
		metrics.TopRisks = metrics.TopRisks[:10]
	}

	report.Metrics = metrics
}

func (rg *ReportGenerator) generateAIAnalysis(ctx context.Context, report *Report) error {
	if rg.aiEngine == nil {
		return fmt.Errorf("AI engine not initialized")
	}

	// Prepare analysis request
	prompt := rg.buildAnalysisPrompt(report)
	
	analysis, err := rg.aiEngine.AnalyzeLogs(ctx, ai.AnalysisRequest{
		Target:    "Security Assessment",
		Objective: "Generate comprehensive security analysis",
		Logs:      []string{prompt},
	})
	if err != nil {
		return err
	}

	report.AIAnalysis = analysis
	return nil
}

func (rg *ReportGenerator) buildAnalysisPrompt(report *Report) string {
	var prompt strings.Builder
	
	prompt.WriteString("Analyze this security assessment and provide expert insights:\n\n")
	prompt.WriteString(fmt.Sprintf("Total Findings: %d\n", report.Metrics.TotalFindings))
	prompt.WriteString(fmt.Sprintf("Risk Score: %.1f/100\n", report.Metrics.RiskScore))
	prompt.WriteString(fmt.Sprintf("Average CVSS: %.1f\n", report.Metrics.AverageCVSS))
	
	prompt.WriteString("\nFindings by Severity:\n")
	for severity, count := range report.Metrics.FindingsBySeverity {
		prompt.WriteString(fmt.Sprintf("- %s: %d\n", severity, count))
	}

	prompt.WriteString("\nKey Findings:\n")
	for _, finding := range report.Findings {
		if finding.Severity == RatingCritical || finding.Severity == RatingHigh {
			prompt.WriteString(fmt.Sprintf("- %s (%s): %s\n", 
				finding.Title, finding.Severity, finding.Description))
		}
	}

	prompt.WriteString("\nProvide analysis on:\n")
	prompt.WriteString("1. Overall security posture\n")
	prompt.WriteString("2. Attack vectors and threat scenarios\n")
	prompt.WriteString("3. Business impact assessment\n")
	prompt.WriteString("4. Compliance implications\n")
	prompt.WriteString("5. Strategic recommendations\n")

	return prompt.String()
}

func (rg *ReportGenerator) generateExecutiveSummary(report *Report) {
	var summary strings.Builder
	
	summary.WriteString("This security assessment identified ")
	summary.WriteString(fmt.Sprintf("%d security findings ", report.Metrics.TotalFindings))
	summary.WriteString("across the target environment. ")

	if report.Metrics.RiskScore > 70 {
		summary.WriteString("The overall risk level is HIGH, ")
	} else if report.Metrics.RiskScore > 40 {
		summary.WriteString("The overall risk level is MEDIUM, ")
	} else {
		summary.WriteString("The overall risk level is LOW, ")
	}

	summary.WriteString(fmt.Sprintf("with a risk score of %.1f out of 100. ", report.Metrics.RiskScore))

	// Critical findings
	critical := report.Metrics.FindingsBySeverity[RatingCritical]
	high := report.Metrics.FindingsBySeverity[RatingHigh]
	
	if critical > 0 {
		summary.WriteString(fmt.Sprintf("There are %d critical vulnerabilities ", critical))
		summary.WriteString("that require immediate attention. ")
	}
	
	if high > 0 {
		summary.WriteString(fmt.Sprintf("Additionally, %d high-severity issues ", high))
		summary.WriteString("were identified that should be addressed promptly. ")
	}

	summary.WriteString("Detailed findings and remediation guidance are provided in the technical sections of this report.")

	report.Metadata.ExecutiveSummary = summary.String()
}

func (rg *ReportGenerator) generateRecommendations(report *Report) {
	recommendations := []string{
		"Implement a vulnerability management program with regular assessments",
		"Deploy endpoint detection and response (EDR) solutions",
		"Establish network segmentation and access controls",
		"Implement multi-factor authentication for all user accounts",
		"Develop and test incident response procedures",
		"Provide security awareness training for all personnel",
		"Establish regular security monitoring and logging",
		"Implement patch management processes for all systems",
	}

	// Add specific recommendations based on findings
	for _, finding := range report.Findings {
		if finding.Severity == RatingCritical || finding.Severity == RatingHigh {
			if strings.Contains(strings.ToLower(finding.Title), "waf") {
				recommendations = append(recommendations, "Review and strengthen Web Application Firewall rules")
			}
			if strings.Contains(strings.ToLower(finding.Title), "ssh") {
				recommendations = append(recommendations, "Implement SSH key-based authentication and disable password login")
			}
			if strings.Contains(strings.ToLower(finding.Title), "database") {
				recommendations = append(recommendations, "Secure database configurations and implement access controls")
			}
		}
	}

	report.Recommendations = recommendations
}

func (rg *ReportGenerator) generateRemediation(finding Finding) string {
	// Generate specific remediation based on finding type
	remediation := "Review and secure the identified service configuration. "

	if strings.Contains(strings.ToLower(finding.Title), "port") {
		remediation += "Consider closing unnecessary ports or implementing access controls. "
	}

	if strings.Contains(strings.ToLower(finding.Title), "waf") {
		remediation += "Review WAF configuration and update security rules. "
	}

	if len(finding.Services) > 0 {
		service := strings.ToLower(finding.Services[0])
		switch service {
		case "ssh":
			remediation += "Implement key-based authentication, disable root login, and use non-standard ports. "
		case "ftp":
			remediation += "Disable anonymous access, use SFTP/FTPS, or consider alternative file transfer methods. "
		case "mysql", "postgresql":
			remediation += "Restrict database access, use strong authentication, and encrypt connections. "
		case "redis":
			remediation += "Enable authentication, bind to localhost only, and disable dangerous commands. "
		}
	}

	remediation += "Apply security patches and follow vendor security guidelines."

	return remediation
}

// Template and output methods

func (rg *ReportGenerator) loadTemplates() error {
	// Load default HTML template
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>{{.Metadata.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; margin-bottom: 30px; }
        .finding { border-left: 4px solid #e74c3c; padding: 15px; margin: 20px 0; background: #f8f9fa; }
        .finding.high { border-color: #e74c3c; }
        .finding.medium { border-color: #f39c12; }
        .finding.low { border-color: #27ae60; }
        .metrics { background: #ecf0f1; padding: 20px; margin: 20px 0; }
        .poc { background: #2c3e50; color: white; padding: 15px; font-family: monospace; white-space: pre-wrap; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{.Metadata.Title}}</h1>
        <p>Generated: {{.Metadata.GeneratedAt.Format "2006-01-02 15:04:05"}}</p>
        <p>Risk Score: {{printf "%.1f" .Metrics.RiskScore}}/100</p>
    </div>

    <h2>Executive Summary</h2>
    <p>{{.Metadata.ExecutiveSummary}}</p>

    <div class="metrics">
        <h2>Risk Metrics</h2>
        <p><strong>Total Findings:</strong> {{.Metrics.TotalFindings}}</p>
        <p><strong>Critical:</strong> {{getSeverityCount .Metrics.FindingsBySeverity "Critical"}}</p>
        <p><strong>High:</strong> {{getSeverityCount .Metrics.FindingsBySeverity "High"}}</p>
        <p><strong>Medium:</strong> {{getSeverityCount .Metrics.FindingsBySeverity "Medium"}}</p>
        <p><strong>Low:</strong> {{getSeverityCount .Metrics.FindingsBySeverity "Low"}}</p>
        <p><strong>Average CVSS:</strong> {{printf "%.1f" .Metrics.AverageCVSS}}</p>
    </div>

    <h2>Findings</h2>
    {{range .Findings}}
    <div class="finding {{severityToString .Severity | lower}}">
        <h3>{{.Title}} ({{.Severity}})</h3>
        <p><strong>CVSS Score:</strong> {{printf "%.1f" .CVSSScore}}</p>
        <p><strong>Description:</strong> {{.Description}}</p>
        <p><strong>Affected Hosts:</strong> {{range .AffectedHosts}}{{.}} {{end}}</p>
        {{if .ProofOfConcept}}
        <h4>Proof of Concept:</h4>
        <div class="poc">{{.ProofOfConcept}}</div>
        {{end}}
        <p><strong>Remediation:</strong> {{.Remediation}}</p>
    </div>
    {{end}}

    {{if .AIAnalysis}}
    <h2>AI Security Analysis</h2>
    <div style="background: #e8f6f3; padding: 20px; margin: 20px 0;">
        <pre>{{.AIAnalysis}}</pre>
    </div>
    {{end}}

    <h2>Recommendations</h2>
    <ul>
    {{range .Recommendations}}
        <li>{{.}}</li>
    {{end}}
    </ul>
</body>
</html>
`

	tmpl, err := template.New("html_report").Funcs(template.FuncMap{
		"lower": strings.ToLower,
		"getSeverityCount": func(findings map[VulnerabilityRating]int, severity string) int {
			switch severity {
			case "Critical":
				return findings[RatingCritical]
			case "High":
				return findings[RatingHigh]
			case "Medium":
				return findings[RatingMedium]
			case "Low":
				return findings[RatingLow]
			default:
				return 0
			}
		},
		"severityToString": func(severity VulnerabilityRating) string {
			return string(severity)
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	rg.templates["html"] = tmpl
	return nil
}

// SaveReport saves the report in the specified format
func (rg *ReportGenerator) SaveReport(report *Report, format string, filename string) error {
	switch strings.ToLower(format) {
	case "json":
		return rg.saveJSONReport(report, filename)
	case "html":
		return rg.saveHTMLReport(report, filename)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func (rg *ReportGenerator) saveJSONReport(report *Report, filename string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func (rg *ReportGenerator) saveHTMLReport(report *Report, filename string) error {
	tmpl, exists := rg.templates["html"]
	if !exists {
		return fmt.Errorf("HTML template not loaded")
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return tmpl.Execute(file, report)
}

// Utility methods
func (rg *ReportGenerator) processMultipleResults(results map[string]interface{}, report *Report) {
	// Process multiple result types
	for resultType, data := range results {
		switch resultType {
		case "port_scan":
			if scanResult, ok := data.(*scanner.ScanResult); ok {
				rg.processPortScanResults(scanResult, report)
			}
		case "waf_scan":
			if wafResult, ok := data.(*waf.WAFResult); ok {
				rg.processWAFResults(wafResult, report)
			}
		case "multiprotocol_scan":
			if mpResult, ok := data.(*multiprotocol.ScanResult); ok {
				rg.processMultiProtocolResults(mpResult, report)
			}
		}
	}
}