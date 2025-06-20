package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type CVEEngine struct {
	client       *http.Client
	logger       *logrus.Logger
	cache        map[string]*CVEData
	mutex        sync.RWMutex
	exploitDB    *ExploitDBClient
	githubToken  string
	config       *CVEConfig
}

type CVEConfig struct {
	EnableNVD       bool          `json:"enable_nvd"`
	EnableExploitDB bool          `json:"enable_exploitdb"`
	EnableGithub    bool          `json:"enable_github"`
	CacheTimeout    time.Duration `json:"cache_timeout"`
	MaxConcurrent   int           `json:"max_concurrent"`
	Severity        string        `json:"min_severity"` // LOW, MEDIUM, HIGH, CRITICAL
}

type CVEData struct {
	ID              string             `json:"id"`
	Description     string             `json:"description"`
	CVSS            float64           `json:"cvss"`
	Severity        string            `json:"severity"`
	PublishedDate   time.Time         `json:"published_date"`
	LastModified    time.Time         `json:"last_modified"`
	References      []string          `json:"references"`
	Exploits        []*ExploitInfo    `json:"exploits"`
	AffectedProducts []ProductInfo    `json:"affected_products"`
	Patches         []*PatchInfo      `json:"patches"`
	PoCs            []*PoCInfo        `json:"pocs"`
	Weaponized      bool              `json:"weaponized"`
	InTheWild       bool              `json:"in_the_wild"`
}

type ExploitInfo struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // metasploit, exploitdb, github, manual
	Title       string    `json:"title"`
	Description string    `json:"description"`
	URL         string    `json:"url"`
	Code        string    `json:"code"`
	Verified    bool      `json:"verified"`
	Reliability string    `json:"reliability"`
	Platforms   []string  `json:"platforms"`
	Privileges  string    `json:"privileges"`
	Disclosed   time.Time `json:"disclosed"`
}

type ProductInfo struct {
	Vendor   string   `json:"vendor"`
	Product  string   `json:"product"`
	Versions []string `json:"versions"`
	CPE      string   `json:"cpe"`
}

type PatchInfo struct {
	Vendor      string    `json:"vendor"`
	Description string    `json:"description"`
	URL         string    `json:"url"`
	Released    time.Time `json:"released"`
}

type PoCInfo struct {
	URL         string    `json:"url"`
	Type        string    `json:"type"` // github, blog, paper, video
	Language    string    `json:"language"`
	Reliability string    `json:"reliability"`
	Stars       int       `json:"stars"`
	Forks       int       `json:"forks"`
	LastUpdate  time.Time `json:"last_update"`
}

type ServiceMatch struct {
	Service     string      `json:"service"`
	Version     string      `json:"version"`
	Port        int         `json:"port"`
	MatchedCVEs []*CVEData  `json:"matched_cves"`
	RiskScore   int         `json:"risk_score"`
}

type ExploitDBClient struct {
	baseURL string
	client  *http.Client
}

// NewCVEEngine creates a new CVE intelligence engine
func NewCVEEngine(logger *logrus.Logger, config *CVEConfig) *CVEEngine {
	if config == nil {
		config = &CVEConfig{
			EnableNVD:       true,
			EnableExploitDB: true,
			EnableGithub:    true,
			CacheTimeout:    6 * time.Hour,
			MaxConcurrent:   10,
			Severity:        "MEDIUM",
		}
	}

	return &CVEEngine{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger:    logger,
		cache:     make(map[string]*CVEData),
		exploitDB: NewExploitDBClient(),
		config:    config,
	}
}

// NewExploitDBClient creates a new ExploitDB client
func NewExploitDBClient() *ExploitDBClient {
	return &ExploitDBClient{
		baseURL: "https://www.exploit-db.com",
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// ScanServices scans detected services for known CVEs
func (cve *CVEEngine) ScanServices(ctx context.Context, services []ServiceMatch) ([]*ServiceMatch, error) {
	cve.logger.Info("Starting CVE scan for detected services")
	
	var wg sync.WaitGroup
	sem := make(chan struct{}, cve.config.MaxConcurrent)
	results := make([]*ServiceMatch, len(services))
	
	for i, service := range services {
		wg.Add(1)
		go func(idx int, svc ServiceMatch) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			
			cves, err := cve.searchCVEsForService(ctx, svc.Service, svc.Version)
			if err != nil {
				cve.logger.WithError(err).Warnf("Failed to search CVEs for %s %s", svc.Service, svc.Version)
				results[idx] = &svc
				return
			}
			
			// Filter and score CVEs
			filteredCVEs := cve.filterAndScoreCVEs(cves)
			svc.MatchedCVEs = filteredCVEs
			svc.RiskScore = cve.calculateRiskScore(filteredCVEs)
			results[idx] = &svc
			
		}(i, service)
	}
	
	wg.Wait()
	
	// Sort by risk score
	sort.Slice(results, func(i, j int) bool {
		return results[i].RiskScore > results[j].RiskScore
	})
	
	cve.logger.Infof("CVE scan completed. Found vulnerabilities in %d services", cve.countVulnerableServices(results))
	return results, nil
}

// searchCVEsForService searches for CVEs affecting a specific service
func (cve *CVEEngine) searchCVEsForService(ctx context.Context, service, version string) ([]*CVEData, error) {
	cacheKey := fmt.Sprintf("%s:%s", service, version)
	
	// Check cache first
	cve.mutex.RLock()
	if cached, exists := cve.cache[cacheKey]; exists {
		cve.mutex.RUnlock()
		return []*CVEData{cached}, nil
	}
	cve.mutex.RUnlock()
	
	var allCVEs []*CVEData
	
	// Search NVD
	if cve.config.EnableNVD {
		nvdCVEs, err := cve.searchNVD(ctx, service, version)
		if err != nil {
			cve.logger.WithError(err).Warn("NVD search failed")
		} else {
			allCVEs = append(allCVEs, nvdCVEs...)
		}
	}
	
	// Search ExploitDB
	if cve.config.EnableExploitDB {
		edbCVEs, err := cve.searchExploitDB(ctx, service, version)
		if err != nil {
			cve.logger.WithError(err).Warn("ExploitDB search failed")
		} else {
			allCVEs = append(allCVEs, edbCVEs...)
		}
	}
	
	// Search GitHub for PoCs
	if cve.config.EnableGithub {
		for _, cveData := range allCVEs {
			pocs, err := cve.searchGitHubPoCs(ctx, cveData.ID)
			if err != nil {
				cve.logger.WithError(err).Warnf("GitHub PoC search failed for %s", cveData.ID)
			} else {
				cveData.PoCs = append(cveData.PoCs, pocs...)
			}
		}
	}
	
	// Enrich with exploit information
	cve.enrichWithExploits(allCVEs)
	
	// Cache results
	cve.mutex.Lock()
	for _, cveData := range allCVEs {
		cve.cache[cveData.ID] = cveData
	}
	cve.mutex.Unlock()
	
	return allCVEs, nil
}

// searchNVD searches the National Vulnerability Database
func (cve *CVEEngine) searchNVD(ctx context.Context, service, version string) ([]*CVEData, error) {
	// Simulate NVD API call (real implementation would use actual NVD API)
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=100", service)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	resp, err := cve.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}
	
	// Mock CVE data for demonstration
	mockCVEs := cve.generateMockCVEs(service, version)
	return mockCVEs, nil
}

// searchExploitDB searches ExploitDB for exploits
func (cve *CVEEngine) searchExploitDB(ctx context.Context, service, version string) ([]*CVEData, error) {
	// Search ExploitDB via their search API or scraping
	url := fmt.Sprintf("%s/search?q=%s", cve.exploitDB.baseURL, service)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	resp, err := cve.exploitDB.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ExploitDB returned status %d", resp.StatusCode)
	}
	
	// Parse ExploitDB results and create CVE data
	return cve.parseExploitDBResults(resp.Body, service, version)
}

// searchGitHubPoCs searches GitHub for proof-of-concept code
func (cve *CVEEngine) searchGitHubPoCs(ctx context.Context, cveID string) ([]*PoCInfo, error) {
	if cve.githubToken == "" {
		return nil, fmt.Errorf("GitHub token not configured")
	}
	
	query := fmt.Sprintf("q=%s+poc+exploit&sort=stars&order=desc", cveID)
	url := fmt.Sprintf("https://api.github.com/search/repositories?%s", query)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", "token "+cve.githubToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	
	resp, err := cve.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	var searchResult struct {
		Items []struct {
			Name        string    `json:"name"`
			HTMLURL     string    `json:"html_url"`
			Description string    `json:"description"`
			Language    string    `json:"language"`
			Stars       int       `json:"stargazers_count"`
			Forks       int       `json:"forks_count"`
			UpdatedAt   time.Time `json:"updated_at"`
		} `json:"items"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&searchResult); err != nil {
		return nil, err
	}
	
	var pocs []*PoCInfo
	for _, item := range searchResult.Items {
		poc := &PoCInfo{
			URL:         item.HTMLURL,
			Type:        "github",
			Language:    item.Language,
			Reliability: cve.assessPoCReliability(item.Stars, item.Forks),
			Stars:       item.Stars,
			Forks:       item.Forks,
			LastUpdate:  item.UpdatedAt,
		}
		pocs = append(pocs, poc)
	}
	
	return pocs, nil
}

// parseExploitDBResults parses ExploitDB search results
func (cve *CVEEngine) parseExploitDBResults(body io.Reader, service, version string) ([]*CVEData, error) {
	// For demonstration, return mock data
	// Real implementation would parse HTML or use ExploitDB CSV data
	return cve.generateMockCVEs(service, version), nil
}

// enrichWithExploits adds exploit information to CVE data
func (cve *CVEEngine) enrichWithExploits(cves []*CVEData) {
	for _, cveData := range cves {
		// Check if exploits are available in Metasploit
		msfModules := cve.searchMetasploitModules(cveData.ID)
		for _, module := range msfModules {
			exploit := &ExploitInfo{
				ID:          module,
				Type:        "metasploit",
				Title:       fmt.Sprintf("Metasploit module: %s", module),
				Verified:    true,
				Reliability: "excellent",
				Platforms:   []string{"linux", "windows"},
			}
			cveData.Exploits = append(cveData.Exploits, exploit)
		}
		
		// Mark as weaponized if exploits exist
		cveData.Weaponized = len(cveData.Exploits) > 0
		
		// Assess if being exploited in the wild
		cveData.InTheWild = cve.assessInTheWild(cveData)
	}
}

// searchMetasploitModules searches for Metasploit modules related to a CVE
func (cve *CVEEngine) searchMetasploitModules(cveID string) []string {
	// Mock Metasploit module search
	// Real implementation would query Metasploit database or API
	mockModules := []string{
		fmt.Sprintf("exploit/linux/http/%s_rce", strings.ToLower(strings.ReplaceAll(cveID, "-", "_"))),
		fmt.Sprintf("exploit/multi/http/%s_exploit", strings.ToLower(strings.ReplaceAll(cveID, "-", "_"))),
	}
	
	return mockModules[:1] // Return first module for demo
}

// assessInTheWild determines if a CVE is being exploited in the wild
func (cve *CVEEngine) assessInTheWild(cveData *CVEData) bool {
	// Mock assessment based on CVSS score and exploit availability
	return cveData.CVSS >= 7.0 && len(cveData.Exploits) > 0
}

// assessPoCReliability assesses PoC reliability based on GitHub metrics
func (cve *CVEEngine) assessPoCReliability(stars, forks int) string {
	score := stars + (forks * 2)
	switch {
	case score >= 50:
		return "excellent"
	case score >= 20:
		return "good"
	case score >= 5:
		return "fair"
	default:
		return "poor"
	}
}

// filterAndScoreCVEs filters CVEs based on configuration and scores them
func (cve *CVEEngine) filterAndScoreCVEs(cves []*CVEData) []*CVEData {
	var filtered []*CVEData
	
	minSeverity := cve.getSeverityScore(cve.config.Severity)
	
	for _, cveData := range cves {
		if cve.getSeverityScore(cveData.Severity) >= minSeverity {
			filtered = append(filtered, cveData)
		}
	}
	
	// Sort by CVSS score
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].CVSS > filtered[j].CVSS
	})
	
	return filtered
}

// getSeverityScore converts severity string to numeric score
func (cve *CVEEngine) getSeverityScore(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// calculateRiskScore calculates overall risk score for a service
func (cve *CVEEngine) calculateRiskScore(cves []*CVEData) int {
	if len(cves) == 0 {
		return 0
	}
	
	score := 0
	for _, cveData := range cves {
		baseScore := int(cveData.CVSS * 10)
		
		// Multipliers for additional risk factors
		if cveData.Weaponized {
			baseScore = int(float64(baseScore) * 1.5)
		}
		if cveData.InTheWild {
			baseScore = int(float64(baseScore) * 2.0)
		}
		if len(cveData.PoCs) > 0 {
			baseScore = int(float64(baseScore) * 1.3)
		}
		
		score += baseScore
	}
	
	return score
}

// countVulnerableServices counts services with CVEs
func (cve *CVEEngine) countVulnerableServices(services []*ServiceMatch) int {
	count := 0
	for _, service := range services {
		if len(service.MatchedCVEs) > 0 {
			count++
		}
	}
	return count
}

// generateMockCVEs generates mock CVE data for demonstration
func (cve *CVEEngine) generateMockCVEs(service, version string) []*CVEData {
	year := time.Now().Year()
	cveID := fmt.Sprintf("CVE-%d-%d", year, 1000+len(service))
	
	return []*CVEData{
		{
			ID:            cveID,
			Description:   fmt.Sprintf("Remote code execution vulnerability in %s %s", service, version),
			CVSS:          8.5,
			Severity:      "HIGH",
			PublishedDate: time.Now().AddDate(0, -2, 0),
			LastModified:  time.Now().AddDate(0, -1, 0),
			References: []string{
				fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID),
				"https://example.com/security-advisory",
			},
			AffectedProducts: []ProductInfo{
				{
					Vendor:   "vendor",
					Product:  service,
					Versions: []string{version, "< " + version},
				},
			},
			Weaponized: false,
			InTheWild:  false,
		},
	}
}

// SetGitHubToken sets the GitHub API token for PoC searching
func (cve *CVEEngine) SetGitHubToken(token string) {
	cve.githubToken = token
}

// GetCVEDetails retrieves detailed information about a specific CVE
func (cve *CVEEngine) GetCVEDetails(ctx context.Context, cveID string) (*CVEData, error) {
	cve.mutex.RLock()
	if cached, exists := cve.cache[cveID]; exists {
		cve.mutex.RUnlock()
		return cached, nil
	}
	cve.mutex.RUnlock()
	
	// Fetch from NVD
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	
	resp, err := cve.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	// For demo, return mock data
	mockCVE := &CVEData{
		ID:          cveID,
		Description: fmt.Sprintf("Detailed information for %s", cveID),
		CVSS:        7.5,
		Severity:    "HIGH",
	}
	
	cve.mutex.Lock()
	cve.cache[cveID] = mockCVE
	cve.mutex.Unlock()
	
	return mockCVE, nil
}