package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type OSVClient struct {
	BaseURL string
	Client  *http.Client
}

type OSVVulnerability struct {
	ID                 string                 `json:"id"`
	Summary            string                 `json:"summary"`
	Details            string                 `json:"details"`
	Published          time.Time              `json:"published"`
	Modified           time.Time              `json:"modified"`
	DatabaseSpecific   map[string]interface{} `json:"database_specific"`
	Severity           []OSVSeverity          `json:"severity"`
	Affected           []OSVAffected          `json:"affected"`
	References         []OSVReference         `json:"references"`
	SchemaVersion      string                 `json:"schema_version"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type OSVAffected struct {
	Package         OSVPackage       `json:"package"`
	Ranges          []OSVRange       `json:"ranges"`
	Versions        []string         `json:"versions"`
	EcosystemSpecific map[string]interface{} `json:"ecosystem_specific"`
}

type OSVPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl"`
}

type OSVRange struct {
	Type   string      `json:"type"`
	Events []OSVEvent  `json:"events"`
}

type OSVEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type OSVReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type OSVQueryRequest struct {
	Package  *OSVPackageQuery `json:"package,omitempty"`
	Version  string           `json:"version,omitempty"`
	Commit   string           `json:"commit,omitempty"`
}

type OSVPackageQuery struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl,omitempty"`
}

type OSVQueryResponse struct {
	Vulns []OSVVulnerability `json:"vulns"`
}

type OSVBatchRequest struct {
	Queries []OSVQueryRequest `json:"queries"`
}

type OSVBatchResponse struct {
	Results []OSVQueryResponse `json:"results"`
}

func NewOSVClient() *OSVClient {
	return &OSVClient{
		BaseURL: "https://api.osv.dev",
		Client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// QueryPackage queries OSV for vulnerabilities in a specific package
func (c *OSVClient) QueryPackage(ctx context.Context, ecosystem, packageName, version string) ([]OSVVulnerability, error) {
	request := OSVQueryRequest{
		Package: &OSVPackageQuery{
			Ecosystem: ecosystem,
			Name:      packageName,
		},
		Version: version,
	}
	
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %v", err)
	}
	
	url := fmt.Sprintf("%s/v1/query", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "RTK-Elite-CVE-Checker/2.1")
	
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}
	
	var osvResp OSVQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&osvResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}
	
	return osvResp.Vulns, nil
}

// QueryBatch performs batch vulnerability queries
func (c *OSVClient) QueryBatch(ctx context.Context, requests []OSVQueryRequest) ([]OSVQueryResponse, error) {
	batchReq := OSVBatchRequest{
		Queries: requests,
	}
	
	jsonData, err := json.Marshal(batchReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch request: %v", err)
	}
	
	url := fmt.Sprintf("%s/v1/querybatch", c.BaseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "RTK-Elite-CVE-Checker/2.1")
	
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}
	
	var batchResp OSVBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}
	
	return batchResp.Results, nil
}

// GetVulnerability retrieves a specific vulnerability by ID
func (c *OSVClient) GetVulnerability(ctx context.Context, vulnID string) (*OSVVulnerability, error) {
	url := fmt.Sprintf("%s/v1/vulns/%s", c.BaseURL, vulnID)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	req.Header.Set("User-Agent", "RTK-Elite-CVE-Checker/2.1")
	
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("vulnerability %s not found", vulnID)
	}
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}
	
	var vuln OSVVulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}
	
	return &vuln, nil
}

// IsFutureCVE checks if a CVE ID is in the future
func (c *OSVClient) IsFutureCVE(cveID string) bool {
	// Extract year from CVE ID (format: CVE-YYYY-XXXX)
	parts := strings.Split(cveID, "-")
	if len(parts) != 3 {
		return false
	}
	
	var year int
	if _, err := fmt.Sscanf(parts[1], "%d", &year); err != nil {
		return false
	}
	
	currentYear := time.Now().Year()
	return year > currentYear
}

// ValidateCVE checks if a CVE exists in OSV database
func (c *OSVClient) ValidateCVE(ctx context.Context, cveID string) (bool, error) {
	// Check if it's a future CVE first
	if c.IsFutureCVE(cveID) {
		return false, fmt.Errorf("CVE %s is from future year - likely invalid", cveID)
	}
	
	vuln, err := c.GetVulnerability(ctx, cveID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, err
	}
	
	return vuln != nil, nil
}

// GetCVSS extracts CVSS score from OSV vulnerability
func (c *OSVClient) GetCVSS(vuln *OSVVulnerability) float64 {
	for _, severity := range vuln.Severity {
		if severity.Type == "CVSS_V3" || severity.Type == "CVSS_V2" {
			var score float64
			if _, err := fmt.Sscanf(severity.Score, "%f", &score); err == nil {
				return score
			}
		}
	}
	return 0.0
}

// GetAffectedEcosystems returns list of affected ecosystems
func (c *OSVClient) GetAffectedEcosystems(vuln *OSVVulnerability) []string {
	ecosystems := make(map[string]bool)
	
	for _, affected := range vuln.Affected {
		if affected.Package.Ecosystem != "" {
			ecosystems[affected.Package.Ecosystem] = true
		}
	}
	
	result := make([]string, 0, len(ecosystems))
	for ecosystem := range ecosystems {
		result = append(result, ecosystem)
	}
	
	return result
}

// IsExploitable checks if vulnerability has known exploits
func (c *OSVClient) IsExploitable(vuln *OSVVulnerability) bool {
	exploitKeywords := []string{"exploit", "metasploit", "poc", "proof of concept", "weaponized"}
	
	searchText := strings.ToLower(vuln.Summary + " " + vuln.Details)
	
	for _, keyword := range exploitKeywords {
		if strings.Contains(searchText, keyword) {
			return true
		}
	}
	
	// Check references for exploit-related URLs
	for _, ref := range vuln.References {
		refURL := strings.ToLower(ref.URL)
		if strings.Contains(refURL, "exploit") || 
		   strings.Contains(refURL, "metasploit") ||
		   strings.Contains(refURL, "exploitdb") {
			return true
		}
	}
	
	return false
}

// ConvertToInternalCVE converts OSV vulnerability to internal CVE format
func (c *OSVClient) ConvertToInternalCVE(vuln *OSVVulnerability) *CVE {
	cvss := c.GetCVSS(vuln)
	severity := "LOW"
	
	if cvss >= 9.0 {
		severity = "CRITICAL"
	} else if cvss >= 7.0 {
		severity = "HIGH"
	} else if cvss >= 4.0 {
		severity = "MEDIUM"
	}
	
	references := make([]string, len(vuln.References))
	for i, ref := range vuln.References {
		references[i] = ref.URL
	}
	
	exploitable := c.IsExploitable(vuln)
	
	return &CVE{
		ID:           vuln.ID,
		Description:  vuln.Summary,
		CVSS:         cvss,
		Severity:     severity,
		Published:    vuln.Published,
		LastModified: vuln.Modified,
		References:   references,
		Weaponized:   exploitable,
		InTheWild:    false, // OSV doesn't provide this info directly
		Source:       "OSV",
		Verified:     true,
	}
}