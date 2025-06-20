package sploit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type SploitScanner struct {
	logger     *logrus.Logger
	mutex      sync.RWMutex
	exploits   []*ExploitInfo
	cveDB      map[string]*CVEInfo
	searchDB   *SearchDatabase
	client     *http.Client
	timeout    time.Duration
	aggressive bool
	offline    bool
	updated    time.Time
}

type ExploitInfo struct {
	ID           string            `json:"id"`
	Title        string            `json:"title"`
	Description  string            `json:"description"`
	Author       string            `json:"author"`
	Type         string            `json:"type"`
	Platform     []string          `json:"platform"`
	Date         string            `json:"date"`
	CVE          []string          `json:"cve"`
	CWE          string            `json:"cwe"`
	BID          string            `json:"bid"`
	EDB          string            `json:"edb"`
	File         string            `json:"file"`
	Path         string            `json:"path"`
	URL          string            `json:"url"`
	Verified     bool              `json:"verified"`
	Rank         int               `json:"rank"`
	Reliability  float64           `json:"reliability"`
	Difficulty   string            `json:"difficulty"`
	Privileges   string            `json:"privileges"`
	Disclosure   string            `json:"disclosure"`
	Solution     string            `json:"solution"`
	References   []string          `json:"references"`
	Tags         []string          `json:"tags"`
	Code         string            `json:"code"`
	Metadata     map[string]string `json:"metadata"`
	MatchScore   float64           `json:"match_score"`
	UsageCount   int               `json:"usage_count"`
	SuccessRate  float64           `json:"success_rate"`
}

type CVEInfo struct {
	ID               string    `json:"id"`
	Description      string    `json:"description"`
	Severity         string    `json:"severity"`
	Score            float64   `json:"score"`
	Vector           string    `json:"vector"`
	Complexity       string    `json:"complexity"`
	Authentication   string    `json:"authentication"`
	Confidentiality  string    `json:"confidentiality"`
	Integrity        string    `json:"integrity"`
	Availability     string    `json:"availability"`
	Published        time.Time `json:"published"`
	Modified         time.Time `json:"modified"`
	Vendor           string    `json:"vendor"`
	Product          string    `json:"product"`
	Versions         []string  `json:"versions"`
	Exploitable      bool      `json:"exploitable"`
	ExploitAvailable bool      `json:"exploit_available"`
	Exploits         []string  `json:"exploits"`
	Patched          bool      `json:"patched"`
	References       []string  `json:"references"`
	CWE              []string  `json:"cwe"`
	CAPEC            []string  `json:"capec"`
}

type SearchDatabase struct {
	ServiceMap    map[string][]*ExploitInfo `json:"service_map"`
	VersionMap    map[string][]*ExploitInfo `json:"version_map"`
	CVEMap        map[string][]*ExploitInfo `json:"cve_map"`
	PlatformMap   map[string][]*ExploitInfo `json:"platform_map"`
	KeywordMap    map[string][]*ExploitInfo `json:"keyword_map"`
	LastUpdated   time.Time                 `json:"last_updated"`
	TotalExploits int                       `json:"total_exploits"`
	Sources       []string                  `json:"sources"`
}

type SearchResult struct {
	Query       string         `json:"query"`
	Exploits    []*ExploitInfo `json:"exploits"`
	Total       int            `json:"total"`
	Relevant    int            `json:"relevant"`
	Confidence  float64        `json:"confidence"`
	Suggestions []string       `json:"suggestions"`
	Filters     map[string]int `json:"filters"`
	Duration    time.Duration  `json:"duration"`
	Timestamp   time.Time      `json:"timestamp"`
}

type ExploitMatch struct {
	Exploit     *ExploitInfo  `json:"exploit"`
	Score       float64       `json:"score"`
	Reasons     []string      `json:"reasons"`
	Confidence  float64       `json:"confidence"`
	Applicable  bool          `json:"applicable"`
	Requires    []string      `json:"requires"`
	Limitations []string      `json:"limitations"`
	Payloads    []string      `json:"payloads"`
	Difficulty  int           `json:"difficulty"`
	Reliability float64       `json:"reliability"`
}

func NewSploitScanner() *SploitScanner {
	return &SploitScanner{
		logger:    logrus.New(),
		exploits:  make([]*ExploitInfo, 0),
		cveDB:     make(map[string]*CVEInfo),
		searchDB:  &SearchDatabase{},
		client:    &http.Client{Timeout: time.Second * 30},
		timeout:   time.Second * 10,
		aggressive: false,
		offline:   false,
		updated:   time.Now(),
	}
}

func (ss *SploitScanner) Initialize() error {
	ss.logger.Info("📊 Initializing exploit database")

	err := ss.loadLocalDatabase()
	if err != nil {
		ss.logger.Warn("Local database not found, downloading...")
		err = ss.updateDatabase()
		if err != nil {
			ss.offline = true
			ss.logger.Warn("Failed to update database, running in offline mode")
			err = ss.initializeBuiltinDatabase()
		}
	}

	ss.buildSearchIndex()
	return err
}

func (ss *SploitScanner) loadLocalDatabase() error {
	dbPath := "exploitdb.json"
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return err
	}

	data, err := os.ReadFile(dbPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &ss.exploits)
}

func (ss *SploitScanner) updateDatabase() error {
	ss.logger.Info("🔄 Updating exploit database")

	sources := []string{
		"https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
		"https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv",
	}

	for _, source := range sources {
		err := ss.downloadExploitDB(source)
		if err == nil {
			break
		}
		ss.logger.Warnf("Failed to download from %s: %v", source, err)
	}

	err := ss.downloadCVEDatabase()
	if err != nil {
		ss.logger.Warnf("Failed to download CVE database: %v", err)
	}

	return ss.saveDatabase()
}

func (ss *SploitScanner) downloadExploitDB(url string) error {
	resp, err := ss.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "id,") {
			continue
		}

		exploit := ss.parseExploitDBLine(line)
		if exploit != nil {
			ss.exploits = append(ss.exploits, exploit)
		}
	}

	return scanner.Err()
}

func (ss *SploitScanner) parseExploitDBLine(line string) *ExploitInfo {
	fields := ss.parseCSVLine(line)
	if len(fields) < 7 {
		return nil
	}

	exploit := &ExploitInfo{
		ID:          fields[0],
		File:        fields[1],
		Description: fields[2],
		Date:        fields[3],
		Author:      fields[4],
		Type:        fields[5],
		Platform:    strings.Split(fields[6], ";"),
		Metadata:    make(map[string]string),
		References:  make([]string, 0),
		Tags:        make([]string, 0),
	}

	if len(fields) > 7 {
		exploit.Path = fields[7]
	}

	exploit.URL = fmt.Sprintf("https://www.exploit-db.com/exploits/%s", exploit.ID)
	exploit.extractCVEFromDescription()
	exploit.calculateRank()

	return exploit
}

func (ss *SploitScanner) parseCSVLine(line string) []string {
	fields := make([]string, 0)
	current := ""
	inQuotes := false

	for i, char := range line {
		switch char {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				fields = append(fields, current)
				current = ""
			} else {
				current += string(char)
			}
		default:
			current += string(char)
		}

		if i == len(line)-1 {
			fields = append(fields, current)
		}
	}

	return fields
}

func (ei *ExploitInfo) extractCVEFromDescription() {
	cveRegex := regexp.MustCompile(`CVE-\d{4}-\d+`)
	matches := cveRegex.FindAllString(ei.Description+" "+ei.Title, -1)
	ei.CVE = matches
}

func (ei *ExploitInfo) calculateRank() {
	rank := 0

	if len(ei.CVE) > 0 {
		rank += 10
	}

	if strings.Contains(strings.ToLower(ei.Type), "remote") {
		rank += 15
	}

	if strings.Contains(strings.ToLower(ei.Description), "metasploit") {
		rank += 20
	}

	if strings.Contains(strings.ToLower(ei.Description), "rce") ||
		strings.Contains(strings.ToLower(ei.Description), "remote code execution") {
		rank += 25
	}

	if strings.Contains(strings.ToLower(ei.Description), "unauthenticated") {
		rank += 15
	}

	year := ei.extractYear()
	if year >= 2020 {
		rank += 5
	} else if year >= 2015 {
		rank += 2
	} else if year < 2010 {
		rank -= 5
	}

	ei.Rank = rank
	ei.Reliability = float64(rank) / 100.0
	if ei.Reliability > 1.0 {
		ei.Reliability = 1.0
	}
}

func (ei *ExploitInfo) extractYear() int {
	yearRegex := regexp.MustCompile(`20\d{2}`)
	match := yearRegex.FindString(ei.Date)
	if match != "" {
		var year int
		fmt.Sscanf(match, "%d", &year)
		return year
	}
	return 2000
}

func (ss *SploitScanner) downloadCVEDatabase() error {
	cveURL := "https://cve.circl.lu/api/last/100"
	resp, err := ss.client.Get(cveURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var cveList []map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&cveList)
	if err != nil {
		return err
	}

	for _, cveData := range cveList {
		cve := ss.parseCVEData(cveData)
		if cve != nil {
			ss.cveDB[cve.ID] = cve
		}
	}

	return nil
}

func (ss *SploitScanner) parseCVEData(data map[string]interface{}) *CVEInfo {
	id, ok := data["id"].(string)
	if !ok {
		return nil
	}

	cve := &CVEInfo{
		ID:         id,
		References: make([]string, 0),
		CWE:        make([]string, 0),
		CAPEC:      make([]string, 0),
		Versions:   make([]string, 0),
		Exploits:   make([]string, 0),
	}

	if summary, ok := data["summary"].(string); ok {
		cve.Description = summary
	}

	if cvss, ok := data["cvss"].(float64); ok {
		cve.Score = cvss
		cve.Severity = ss.calculateSeverity(cvss)
	}

	if published, ok := data["Published"].(string); ok {
		if t, err := time.Parse("2006-01-02T15:04:05", published); err == nil {
			cve.Published = t
		}
	}

	return cve
}

func (ss *SploitScanner) calculateSeverity(score float64) string {
	if score >= 9.0 {
		return "CRITICAL"
	} else if score >= 7.0 {
		return "HIGH"
	} else if score >= 4.0 {
		return "MEDIUM"
	} else {
		return "LOW"
	}
}

func (ss *SploitScanner) initializeBuiltinDatabase() error {
	ss.logger.Info("📊 Loading built-in exploit database")

	builtinExploits := []*ExploitInfo{
		{
			ID:          "builtin_001",
			Title:       "Apache Struts 2 Remote Code Execution",
			Description: "CVE-2017-5638 - Apache Struts 2.3.5 - 2.3.31 / 2.5 - 2.5.10 RCE",
			Author:      "Built-in",
			Type:        "remote",
			Platform:    []string{"linux", "windows"},
			CVE:         []string{"CVE-2017-5638"},
			Rank:        85,
			Reliability: 0.9,
			Verified:    true,
		},
		{
			ID:          "builtin_002",
			Title:       "EternalBlue SMB Remote Code Execution",
			Description: "CVE-2017-0144 - Windows SMB Remote Code Execution (MS17-010)",
			Author:      "Built-in",
			Type:        "remote",
			Platform:    []string{"windows"},
			CVE:         []string{"CVE-2017-0144"},
			Rank:        95,
			Reliability: 0.95,
			Verified:    true,
		},
		{
			ID:          "builtin_003",
			Title:       "Apache Log4j2 Remote Code Execution",
			Description: "CVE-2021-44228 - Apache Log4j2 JNDI features RCE (Log4Shell)",
			Author:      "Built-in",
			Type:        "remote",
			Platform:    []string{"linux", "windows", "unix"},
			CVE:         []string{"CVE-2021-44228"},
			Rank:        100,
			Reliability: 0.98,
			Verified:    true,
		},
	}

	ss.exploits = append(ss.exploits, builtinExploits...)
	return nil
}

func (ss *SploitScanner) buildSearchIndex() {
	ss.logger.Info("🔍 Building search index")

	ss.searchDB = &SearchDatabase{
		ServiceMap:  make(map[string][]*ExploitInfo),
		VersionMap:  make(map[string][]*ExploitInfo),
		CVEMap:      make(map[string][]*ExploitInfo),
		PlatformMap: make(map[string][]*ExploitInfo),
		KeywordMap:  make(map[string][]*ExploitInfo),
		LastUpdated: time.Now(),
		Sources:     []string{"ExploitDB", "Built-in"},
	}

	for _, exploit := range ss.exploits {
		ss.indexExploit(exploit)
	}

	ss.searchDB.TotalExploits = len(ss.exploits)
}

func (ss *SploitScanner) indexExploit(exploit *ExploitInfo) {
	keywords := ss.extractKeywords(exploit)

	for _, keyword := range keywords {
		keyword = strings.ToLower(keyword)
		ss.searchDB.KeywordMap[keyword] = append(ss.searchDB.KeywordMap[keyword], exploit)
	}

	for _, platform := range exploit.Platform {
		platform = strings.ToLower(platform)
		ss.searchDB.PlatformMap[platform] = append(ss.searchDB.PlatformMap[platform], exploit)
	}

	for _, cve := range exploit.CVE {
		cve = strings.ToUpper(cve)
		ss.searchDB.CVEMap[cve] = append(ss.searchDB.CVEMap[cve], exploit)
	}

	services := ss.extractServices(exploit)
	for _, service := range services {
		service = strings.ToLower(service)
		ss.searchDB.ServiceMap[service] = append(ss.searchDB.ServiceMap[service], exploit)
	}
}

func (ss *SploitScanner) extractKeywords(exploit *ExploitInfo) []string {
	text := exploit.Title + " " + exploit.Description
	words := regexp.MustCompile(`\w+`).FindAllString(text, -1)

	keywords := make([]string, 0)
	for _, word := range words {
		if len(word) > 3 && !ss.isStopWord(word) {
			keywords = append(keywords, word)
		}
	}

	return keywords
}

func (ss *SploitScanner) extractServices(exploit *ExploitInfo) []string {
	services := make([]string, 0)
	text := strings.ToLower(exploit.Title + " " + exploit.Description)

	servicePatterns := map[string][]string{
		"apache":     {"apache", "httpd"},
		"nginx":      {"nginx"},
		"mysql":      {"mysql", "mariadb"},
		"postgresql": {"postgresql", "postgres"},
		"ssh":        {"ssh", "openssh"},
		"ftp":        {"ftp", "vsftpd", "proftpd"},
		"smtp":       {"smtp", "postfix", "sendmail"},
		"smb":        {"smb", "samba", "cifs"},
		"dns":        {"dns", "bind"},
		"web":        {"web", "http", "https"},
		"windows":    {"windows", "microsoft"},
		"linux":      {"linux", "unix"},
		"php":        {"php"},
		"java":       {"java", "tomcat", "struts"},
		"python":     {"python", "django", "flask"},
		"nodejs":     {"node", "nodejs", "express"},
	}

	for service, patterns := range servicePatterns {
		for _, pattern := range patterns {
			if strings.Contains(text, pattern) {
				services = append(services, service)
				break
			}
		}
	}

	return services
}

func (ss *SploitScanner) isStopWord(word string) bool {
	stopWords := []string{
		"the", "and", "for", "are", "but", "not", "you", "all", "can", "had",
		"her", "was", "one", "our", "out", "day", "get", "has", "him", "his",
		"how", "its", "may", "new", "now", "old", "see", "two", "way", "who",
		"boy", "did", "use", "let", "say", "she", "too", "any", "here", "much",
	}

	word = strings.ToLower(word)
	for _, stopWord := range stopWords {
		if word == stopWord {
			return true
		}
	}
	return false
}

func (ss *SploitScanner) SearchByService(service, version string) (*SearchResult, error) {
	start := time.Now()
	query := fmt.Sprintf("service:%s version:%s", service, version)

	result := &SearchResult{
		Query:     query,
		Exploits:  make([]*ExploitInfo, 0),
		Filters:   make(map[string]int),
		Timestamp: start,
	}

	service = strings.ToLower(service)
	version = strings.ToLower(version)

	candidates := ss.searchDB.ServiceMap[service]
	matches := make([]*ExploitMatch, 0)

	for _, exploit := range candidates {
		match := ss.calculateMatch(exploit, service, version)
		if match.Score > 0.3 {
			matches = append(matches, match)
		}
	}

	matches = ss.sortMatches(matches)

	for _, match := range matches {
		result.Exploits = append(result.Exploits, match.Exploit)
		if match.Applicable {
			result.Relevant++
		}
	}

	result.Total = len(result.Exploits)
	result.Confidence = ss.calculateConfidence(matches)
	result.Duration = time.Since(start)

	return result, nil
}

func (ss *SploitScanner) calculateMatch(exploit *ExploitInfo, service, version string) *ExploitMatch {
	match := &ExploitMatch{
		Exploit:   exploit,
		Reasons:   make([]string, 0),
		Requires:  make([]string, 0),
		Payloads:  make([]string, 0),
	}

	score := 0.0
	text := strings.ToLower(exploit.Title + " " + exploit.Description)

	if strings.Contains(text, service) {
		score += 0.4
		match.Reasons = append(match.Reasons, "Service name match")
	}

	if version != "" && strings.Contains(text, version) {
		score += 0.3
		match.Reasons = append(match.Reasons, "Version match")
	}

	if len(exploit.CVE) > 0 {
		score += 0.2
		match.Reasons = append(match.Reasons, "Has CVE")
	}

	if exploit.Verified {
		score += 0.1
		match.Reasons = append(match.Reasons, "Verified exploit")
	}

	if strings.Contains(text, "metasploit") {
		score += 0.15
		match.Reasons = append(match.Reasons, "Metasploit module")
		match.Payloads = append(match.Payloads, "metasploit")
	}

	if strings.Contains(text, "remote") {
		score += 0.1
		match.Reasons = append(match.Reasons, "Remote exploit")
	}

	if strings.Contains(text, "unauthenticated") {
		score += 0.1
		match.Reasons = append(match.Reasons, "No authentication required")
	}

	year := exploit.extractYear()
	if year >= 2020 {
		score += 0.05
	} else if year < 2010 {
		score -= 0.1
	}

	match.Score = score
	match.Confidence = score * exploit.Reliability
	match.Applicable = score > 0.5
	match.Reliability = exploit.Reliability
	match.Difficulty = ss.calculateDifficulty(exploit)

	return match
}

func (ss *SploitScanner) calculateDifficulty(exploit *ExploitInfo) int {
	difficulty := 5
	text := strings.ToLower(exploit.Description)

	if strings.Contains(text, "metasploit") {
		difficulty -= 2
	}

	if strings.Contains(text, "unauthenticated") {
		difficulty -= 1
	}

	if strings.Contains(text, "buffer overflow") {
		difficulty += 2
	}

	if strings.Contains(text, "manual") {
		difficulty += 1
	}

	if difficulty < 1 {
		difficulty = 1
	}
	if difficulty > 10 {
		difficulty = 10
	}

	return difficulty
}

func (ss *SploitScanner) sortMatches(matches []*ExploitMatch) []*ExploitMatch {
	for i := 0; i < len(matches)-1; i++ {
		for j := i + 1; j < len(matches); j++ {
			if matches[i].Score < matches[j].Score {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}
	return matches
}

func (ss *SploitScanner) calculateConfidence(matches []*ExploitMatch) float64 {
	if len(matches) == 0 {
		return 0.0
	}

	totalScore := 0.0
	for _, match := range matches {
		totalScore += match.Score
	}

	return totalScore / float64(len(matches))
}

func (ss *SploitScanner) SearchByCVE(cve string) (*SearchResult, error) {
	cve = strings.ToUpper(cve)
	exploits := ss.searchDB.CVEMap[cve]

	result := &SearchResult{
		Query:     fmt.Sprintf("cve:%s", cve),
		Exploits:  exploits,
		Total:     len(exploits),
		Relevant:  len(exploits),
		Confidence: 1.0,
		Timestamp: time.Now(),
	}

	return result, nil
}

func (ss *SploitScanner) SearchByKeyword(keyword string) (*SearchResult, error) {
	keyword = strings.ToLower(keyword)
	exploits := ss.searchDB.KeywordMap[keyword]

	result := &SearchResult{
		Query:     fmt.Sprintf("keyword:%s", keyword),
		Exploits:  exploits,
		Total:     len(exploits),
		Relevant:  len(exploits),
		Confidence: 0.8,
		Timestamp: time.Now(),
	}

	return result, nil
}

func (ss *SploitScanner) UpdateExploitDatabase() error {
	if ss.offline {
		return fmt.Errorf("running in offline mode")
	}

	return ss.updateDatabase()
}

func (ss *SploitScanner) RunSearchScript(service, version string) (*SearchResult, error) {
	if ss.offline {
		return ss.SearchByService(service, version)
	}

	cmd := exec.Command("searchsploit", "-j", service)
	output, err := cmd.Output()
	if err != nil {
		return ss.SearchByService(service, version)
	}

	var searchsploitResult map[string]interface{}
	err = json.Unmarshal(output, &searchsploitResult)
	if err != nil {
		return ss.SearchByService(service, version)
	}

	return ss.parseSearchsploitResult(searchsploitResult, service, version)
}

func (ss *SploitScanner) parseSearchsploitResult(data map[string]interface{}, service, version string) (*SearchResult, error) {
	result := &SearchResult{
		Query:     fmt.Sprintf("searchsploit:%s %s", service, version),
		Exploits:  make([]*ExploitInfo, 0),
		Timestamp: time.Now(),
	}

	if exploits, ok := data["RESULTS_EXPLOIT"].([]interface{}); ok {
		for _, exploitData := range exploits {
			if exploitMap, ok := exploitData.(map[string]interface{}); ok {
				exploit := ss.parseSearchsploitExploit(exploitMap)
				if exploit != nil {
					result.Exploits = append(result.Exploits, exploit)
				}
			}
		}
	}

	result.Total = len(result.Exploits)
	result.Relevant = result.Total
	result.Confidence = 0.9

	return result, nil
}

func (ss *SploitScanner) parseSearchsploitExploit(data map[string]interface{}) *ExploitInfo {
	exploit := &ExploitInfo{
		Metadata:   make(map[string]string),
		References: make([]string, 0),
		Tags:       make([]string, 0),
		Platform:   make([]string, 0),
		CVE:        make([]string, 0),
	}

	if title, ok := data["Title"].(string); ok {
		exploit.Title = title
		exploit.Description = title
	}

	if edbId, ok := data["EDB-ID"].(string); ok {
		exploit.ID = edbId
		exploit.EDB = edbId
		exploit.URL = fmt.Sprintf("https://www.exploit-db.com/exploits/%s", edbId)
	}

	if date, ok := data["Date"].(string); ok {
		exploit.Date = date
	}

	if author, ok := data["Author"].(string); ok {
		exploit.Author = author
	}

	if exploitType, ok := data["Type"].(string); ok {
		exploit.Type = exploitType
	}

	if platform, ok := data["Platform"].(string); ok {
		exploit.Platform = strings.Split(platform, "/")
	}

	exploit.extractCVEFromDescription()
	exploit.calculateRank()

	return exploit
}

func (ss *SploitScanner) saveDatabase() error {
	data, err := json.MarshalIndent(ss.exploits, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile("exploitdb.json", data, 0644)
}

func (ss *SploitScanner) GetExploitCount() int {
	ss.mutex.RLock()
	defer ss.mutex.RUnlock()
	return len(ss.exploits)
}

func (ss *SploitScanner) GetCVECount() int {
	ss.mutex.RLock()
	defer ss.mutex.RUnlock()
	return len(ss.cveDB)
}

func (ss *SploitScanner) GetDatabaseInfo() map[string]interface{} {
	ss.mutex.RLock()
	defer ss.mutex.RUnlock()

	return map[string]interface{}{
		"total_exploits": len(ss.exploits),
		"total_cves":     len(ss.cveDB),
		"last_updated":   ss.updated,
		"offline_mode":   ss.offline,
		"sources":        ss.searchDB.Sources,
	}
}

func (ss *SploitScanner) GetTopExploits(limit int) []*ExploitInfo {
	ss.mutex.RLock()
	defer ss.mutex.RUnlock()

	sorted := make([]*ExploitInfo, len(ss.exploits))
	copy(sorted, ss.exploits)

	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i].Rank < sorted[j].Rank {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	if limit > len(sorted) {
		limit = len(sorted)
	}

	return sorted[:limit]
}