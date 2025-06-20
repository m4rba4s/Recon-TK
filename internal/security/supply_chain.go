package security

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

type SupplyChainValidator struct {
	logger        *zap.Logger
	trustedKeys   map[string]*x509.Certificate
	checksumCache map[string]string
	configDir     string
}

type VulnerabilityDB struct {
	LastUpdated   time.Time                    `json:"last_updated"`
	Vulnerabilities map[string][]Vulnerability `json:"vulnerabilities"`
	Source        string                       `json:"source"`
	Version       string                       `json:"version"`
}

type Vulnerability struct {
	ID          string    `json:"id"`
	Package     string    `json:"package"`
	Version     string    `json:"version"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	CVSS        float64   `json:"cvss"`
	PublishedAt time.Time `json:"published_at"`
	FixedIn     string    `json:"fixed_in,omitempty"`
	References  []string  `json:"references,omitempty"`
}

type SecurityReport struct {
	Timestamp         time.Time       `json:"timestamp"`
	Target            string          `json:"target"`
	TotalComponents   int             `json:"total_components"`
	VulnerableComponents int          `json:"vulnerable_components"`
	HighRiskVulns     int             `json:"high_risk_vulnerabilities"`
	CriticalVulns     int             `json:"critical_vulnerabilities"`
	Vulnerabilities   []Vulnerability `json:"vulnerabilities"`
	SupplyChainRisk   string          `json:"supply_chain_risk"`
	Recommendations   []string        `json:"recommendations"`
}

type ComponentIntegrity struct {
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	Hashes     map[string]string `json:"hashes"`
	Source     string            `json:"source"`
	Verified   bool              `json:"verified"`
	Signature  string            `json:"signature,omitempty"`
}

func NewSupplyChainValidator(logger *zap.Logger, configDir string) *SupplyChainValidator {
	return &SupplyChainValidator{
		logger:        logger,
		trustedKeys:   make(map[string]*x509.Certificate),
		checksumCache: make(map[string]string),
		configDir:     configDir,
	}
}

func (scv *SupplyChainValidator) ValidateSupplyChain(sbomPath string) (*SecurityReport, error) {
	scv.logger.Info("Starting supply chain validation", zap.String("sbom", sbomPath))

	// Load SBOM
	sbomData, err := os.ReadFile(sbomPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBOM: %w", err)
	}

	var sbom map[string]interface{}
	if err := json.Unmarshal(sbomData, &sbom); err != nil {
		return nil, fmt.Errorf("failed to parse SBOM: %w", err)
	}

	// Extract components
	components, err := scv.extractComponents(sbom)
	if err != nil {
		return nil, fmt.Errorf("failed to extract components: %w", err)
	}

	// Load vulnerability database
	vulnDB, err := scv.loadVulnerabilityDB()
	if err != nil {
		scv.logger.Warn("Failed to load vulnerability database", zap.Error(err))
		vulnDB = &VulnerabilityDB{
			LastUpdated: time.Now(),
			Vulnerabilities: make(map[string][]Vulnerability),
			Source: "local",
			Version: "1.0",
		}
	}

	// Scan for vulnerabilities
	var vulnerabilities []Vulnerability
	var vulnerableComponents int

	for _, comp := range components {
		compVulns := scv.scanComponent(comp, vulnDB)
		if len(compVulns) > 0 {
			vulnerableComponents++
			vulnerabilities = append(vulnerabilities, compVulns...)
		}
	}

	// Count severity levels
	var criticalVulns, highRiskVulns int
	for _, vuln := range vulnerabilities {
		switch strings.ToLower(vuln.Severity) {
		case "critical":
			criticalVulns++
		case "high":
			highRiskVulns++
		}
	}

	// Calculate risk level
	riskLevel := scv.calculateRiskLevel(len(components), vulnerableComponents, criticalVulns, highRiskVulns)

	// Generate recommendations
	recommendations := scv.generateRecommendations(vulnerabilities, riskLevel)

	report := &SecurityReport{
		Timestamp:            time.Now(),
		Target:               sbomPath,
		TotalComponents:      len(components),
		VulnerableComponents: vulnerableComponents,
		HighRiskVulns:       highRiskVulns,
		CriticalVulns:       criticalVulns,
		Vulnerabilities:     vulnerabilities,
		SupplyChainRisk:     riskLevel,
		Recommendations:     recommendations,
	}

	scv.logger.Info("Supply chain validation completed",
		zap.Int("total_components", len(components)),
		zap.Int("vulnerable_components", vulnerableComponents),
		zap.Int("critical_vulns", criticalVulns),
		zap.String("risk_level", riskLevel))

	return report, nil
}

func (scv *SupplyChainValidator) extractComponents(sbom map[string]interface{}) ([]ComponentIntegrity, error) {
	var components []ComponentIntegrity

	// Extract from CycloneDX format
	if compsInterface, exists := sbom["components"]; exists {
		if comps, ok := compsInterface.([]interface{}); ok {
			for _, compInterface := range comps {
				if comp, ok := compInterface.(map[string]interface{}); ok {
					component := ComponentIntegrity{
						Hashes: make(map[string]string),
					}

					if name, ok := comp["name"].(string); ok {
						component.Name = name
					}
					if version, ok := comp["version"].(string); ok {
						component.Version = version
					}

					// Extract hashes
					if hashesInterface, exists := comp["hashes"]; exists {
						if hashes, ok := hashesInterface.([]interface{}); ok {
							for _, hashInterface := range hashes {
								if hash, ok := hashInterface.(map[string]interface{}); ok {
									if alg, ok := hash["alg"].(string); ok {
										if content, ok := hash["content"].(string); ok {
											component.Hashes[alg] = content
										}
									}
								}
							}
						}
					}

					components = append(components, component)
				}
			}
		}
	}

	return components, nil
}

func (scv *SupplyChainValidator) loadVulnerabilityDB() (*VulnerabilityDB, error) {
	vulnDBPath := filepath.Join(scv.configDir, "vulnerability_db.json")

	// Check if local DB exists and is recent
	if stat, err := os.Stat(vulnDBPath); err == nil {
		if time.Since(stat.ModTime()) < 24*time.Hour {
			data, err := os.ReadFile(vulnDBPath)
			if err == nil {
				var db VulnerabilityDB
				if json.Unmarshal(data, &db) == nil {
					return &db, nil
				}
			}
		}
	}

	// Update vulnerability database
	return scv.updateVulnerabilityDB()
}

func (scv *SupplyChainValidator) updateVulnerabilityDB() (*VulnerabilityDB, error) {
	scv.logger.Info("Updating vulnerability database")

	// Create sample vulnerability database with known Go vulnerabilities
	db := &VulnerabilityDB{
		LastUpdated: time.Now(),
		Source:      "github-advisory",
		Version:     "1.0",
		Vulnerabilities: map[string][]Vulnerability{
			"github.com/golang/go": {
				{
					ID:          "GHSA-69ch-w2m2-3vjp",
					Package:     "github.com/golang/go",
					Version:     "< 1.20.6",
					Severity:    "high",
					Description: "HTTP/2 rapid reset can cause excessive work in net/http",
					CVSS:        7.5,
					PublishedAt: time.Date(2023, 10, 10, 0, 0, 0, 0, time.UTC),
					FixedIn:     "1.20.6",
					References:  []string{"https://github.com/golang/go/issues/63417"},
				},
			},
			"github.com/gin-gonic/gin": {
				{
					ID:          "GHSA-2c4m-59x9-fr2g",
					Package:     "github.com/gin-gonic/gin",
					Version:     "< 1.9.1",
					Severity:    "medium",
					Description: "Directory traversal in Gin",
					CVSS:        5.3,
					PublishedAt: time.Date(2023, 5, 10, 0, 0, 0, 0, time.UTC),
					FixedIn:     "1.9.1",
					References:  []string{"https://github.com/gin-gonic/gin/security/advisories/GHSA-2c4m-59x9-fr2g"},
				},
			},
			"github.com/gorilla/websocket": {
				{
					ID:          "GHSA-jf24-p9p9-4rjh",
					Package:     "github.com/gorilla/websocket",
					Version:     "< 1.5.0",
					Severity:    "medium",
					Description: "Denial of service in Gorilla WebSocket",
					CVSS:        5.3,
					PublishedAt: time.Date(2023, 3, 15, 0, 0, 0, 0, time.UTC),
					FixedIn:     "1.5.0",
					References:  []string{"https://github.com/gorilla/websocket/security/advisories/GHSA-jf24-p9p9-4rjh"},
				},
			},
		},
	}

	// Save to local cache
	vulnDBPath := filepath.Join(scv.configDir, "vulnerability_db.json")
	if err := os.MkdirAll(scv.configDir, 0755); err == nil {
		if data, err := json.MarshalIndent(db, "", "  "); err == nil {
			os.WriteFile(vulnDBPath, data, 0644)
		}
	}

	return db, nil
}

func (scv *SupplyChainValidator) scanComponent(comp ComponentIntegrity, vulnDB *VulnerabilityDB) []Vulnerability {
	var vulnerabilities []Vulnerability

	// Check if component has known vulnerabilities
	if vulns, exists := vulnDB.Vulnerabilities[comp.Name]; exists {
		for _, vuln := range vulns {
			if scv.isVulnerable(comp.Version, vuln.Version) {
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}

	return vulnerabilities
}

func (scv *SupplyChainValidator) isVulnerable(version, vulnVersion string) bool {
	// Simple version comparison for demonstration
	// In production, use proper semantic version comparison
	if strings.HasPrefix(vulnVersion, "< ") {
		targetVersion := strings.TrimPrefix(vulnVersion, "< ")
		return scv.compareVersions(version, targetVersion) < 0
	}
	
	if strings.HasPrefix(vulnVersion, "> ") {
		targetVersion := strings.TrimPrefix(vulnVersion, "> ")
		return scv.compareVersions(version, targetVersion) > 0
	}

	return version == vulnVersion
}

func (scv *SupplyChainValidator) compareVersions(v1, v2 string) int {
	// Simplified version comparison
	if v1 == v2 {
		return 0
	}
	if v1 < v2 {
		return -1
	}
	return 1
}

func (scv *SupplyChainValidator) calculateRiskLevel(total, vulnerable, critical, high int) string {
	if critical > 0 {
		return "CRITICAL"
	}
	if high > 3 || (high > 0 && float64(vulnerable)/float64(total) > 0.3) {
		return "HIGH"
	}
	if vulnerable > 0 {
		return "MEDIUM"
	}
	return "LOW"
}

func (scv *SupplyChainValidator) generateRecommendations(vulnerabilities []Vulnerability, riskLevel string) []string {
	var recommendations []string

	if len(vulnerabilities) == 0 {
		recommendations = append(recommendations, "✅ No known vulnerabilities detected")
		recommendations = append(recommendations, "Continue regular dependency updates")
		return recommendations
	}

	// Group by package for upgrade recommendations
	packageVulns := make(map[string][]Vulnerability)
	for _, vuln := range vulnerabilities {
		packageVulns[vuln.Package] = append(packageVulns[vuln.Package], vuln)
	}

	for pkg, vulns := range packageVulns {
		var fixVersions []string
		for _, vuln := range vulns {
			if vuln.FixedIn != "" {
				fixVersions = append(fixVersions, vuln.FixedIn)
			}
		}
		
		if len(fixVersions) > 0 {
			recommendations = append(recommendations, 
				fmt.Sprintf("🔧 Upgrade %s to version %s or later", 
					filepath.Base(pkg), fixVersions[0]))
		} else {
			recommendations = append(recommendations, 
				fmt.Sprintf("⚠️  Review %s for security patches", filepath.Base(pkg)))
		}
	}

	// Add general recommendations based on risk level
	switch riskLevel {
	case "CRITICAL":
		recommendations = append(recommendations, "🚨 URGENT: Address critical vulnerabilities immediately")
		recommendations = append(recommendations, "Consider blocking deployments until fixed")
	case "HIGH":
		recommendations = append(recommendations, "🔥 HIGH PRIORITY: Schedule immediate updates")
		recommendations = append(recommendations, "Implement additional monitoring")
	case "MEDIUM":
		recommendations = append(recommendations, "📋 Plan updates in next maintenance window")
	}

	recommendations = append(recommendations, "Enable automated dependency scanning")
	recommendations = append(recommendations, "Subscribe to security advisories for critical dependencies")

	return recommendations
}

func (scv *SupplyChainValidator) VerifyIntegrity(component ComponentIntegrity) error {
	scv.logger.Info("Verifying component integrity", 
		zap.String("component", component.Name),
		zap.String("version", component.Version))

	// Verify checksums if available
	for algorithm, expectedHash := range component.Hashes {
		if algorithm == "SHA-256" {
			// In a real implementation, you would download and verify the component
			actualHash := scv.calculateComponentHash(component)
			if actualHash != expectedHash {
				return fmt.Errorf("hash mismatch for %s: expected %s, got %s", 
					component.Name, expectedHash, actualHash)
			}
		}
	}

	return nil
}

func (scv *SupplyChainValidator) calculateComponentHash(component ComponentIntegrity) string {
	// Simplified hash calculation
	data := component.Name + component.Version
	hasher := sha256.New()
	hasher.Write([]byte(data))
	return hex.EncodeToString(hasher.Sum(nil))
}

func (scv *SupplyChainValidator) ExportSecurityReport(report *SecurityReport, outputPath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}

func (scv *SupplyChainValidator) GetTrustedPublishers() []string {
	return []string{
		"github.com/golang",
		"github.com/spf13",
		"github.com/sirupsen",
		"go.uber.org",
		"github.com/gin-gonic",
		"github.com/gorilla",
	}
}

func (scv *SupplyChainValidator) CheckPublisherTrust(packageName string) bool {
	trustedPublishers := scv.GetTrustedPublishers()
	
	for _, publisher := range trustedPublishers {
		if strings.HasPrefix(packageName, publisher) {
			return true
		}
	}
	
	return false
}