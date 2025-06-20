package elite

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// DNSWildcardEntropyDiff - элитный анализатор entropy в wildcard DNS зонах
type DNSWildcardEntropyDiff struct {
	logger  *zap.Logger
	config  *DNSEntropyConfig
	results *DNSEntropyResults
	mutex   sync.RWMutex
}

// DNSEntropyConfig - конфигурация DNS entropy анализатора
type DNSEntropyConfig struct {
	RandomSubdomains     int      `json:"random_subdomains"`
	TestIterations      int      `json:"test_iterations"`
	Concurrency         int      `json:"concurrency"`
	TimeoutMS           int      `json:"timeout_ms"`
	EntropyThreshold    float64  `json:"entropy_threshold"`
	DNSServers          []string `json:"dns_servers"`
	UseAdvancedPayloads bool     `json:"use_advanced_payloads"`
	DetectTakeovers     bool     `json:"detect_takeovers"`
}

// DNSEntropyResults - результаты анализа entropy
type DNSEntropyResults struct {
	Domain              string                    `json:"domain"`
	TotalSubdomains     int                       `json:"total_subdomains"`
	WildcardDetected    bool                      `json:"wildcard_detected"`
	EntropyScore        float64                   `json:"entropy_score"`
	EntropyDistribution []EntropyBucket           `json:"entropy_distribution"`
	DyingWildcards      []DyingWildcardResult     `json:"dying_wildcards"`
	TakeoverCandidates  []TakeoverCandidate       `json:"takeover_candidates"`
	WildcardPatterns    []WildcardPattern         `json:"wildcard_patterns"`
	DNSAnomalies        []DNSAnomaly              `json:"dns_anomalies"`
	StatisticalData     DNSStatistics             `json:"statistical_data"`
	Timestamp           time.Time                 `json:"timestamp"`
}

// EntropyBucket - распределение entropy по размерам ответов
type EntropyBucket struct {
	ResponseSizeRange string  `json:"response_size_range"`
	Count            int     `json:"count"`
	Entropy          float64 `json:"entropy"`
	Percentage       float64 `json:"percentage"`
}

// DyingWildcardResult - "дырявая" wildcard зона
type DyingWildcardResult struct {
	Subdomain       string    `json:"subdomain"`
	ExpectedIP      string    `json:"expected_ip"`
	ActualIPs       []string  `json:"actual_ips"`
	TTLAnomaly      bool      `json:"ttl_anomaly"`
	ExpectedTTL     int       `json:"expected_ttl"`
	ActualTTL       int       `json:"actual_ttl"`
	EntropyDelta    float64   `json:"entropy_delta"`
	Confidence      float64   `json:"confidence"`
	Evidence        []string  `json:"evidence"`
}

// TakeoverCandidate - кандидат на subdomain takeover
type TakeoverCandidate struct {
	Subdomain       string    `json:"subdomain"`
	CNAME           string    `json:"cname"`
	Service         string    `json:"service"`
	Status          string    `json:"status"`
	TakeoverRisk    string    `json:"takeover_risk"`
	Confidence      float64   `json:"confidence"`
	VerificationSteps []string `json:"verification_steps"`
	Evidence        []string  `json:"evidence"`
}

// WildcardPattern - паттерн wildcard поведения
type WildcardPattern struct {
	Pattern         string  `json:"pattern"`
	ResponseType    string  `json:"response_type"`
	Frequency       int     `json:"frequency"`
	Entropy         float64 `json:"entropy"`
	Description     string  `json:"description"`
}

// DNSAnomaly - DNS аномалия
type DNSAnomaly struct {
	Type            string    `json:"type"`
	Subdomain       string    `json:"subdomain"`
	Expected        string    `json:"expected"`
	Actual          string    `json:"actual"`
	Severity        string    `json:"severity"`
	Description     string    `json:"description"`
	Evidence        []string  `json:"evidence"`
}

// DNSStatistics - статистические данные
type DNSStatistics struct {
	UniqueIPs          int     `json:"unique_ips"`
	UniqueTTLs         int     `json:"unique_ttls"`
	AvgResponseSize    float64 `json:"avg_response_size"`
	StdDevResponseSize float64 `json:"stddev_response_size"`
	SuccessRate        float64 `json:"success_rate"`
	PerformanceScore   float64 `json:"performance_score"`
}

// NewDNSWildcardEntropyDiff создает новый экземпляр DNS entropy анализатора
func NewDNSWildcardEntropyDiff(logger *zap.Logger) *DNSWildcardEntropyDiff {
	return &DNSWildcardEntropyDiff{
		logger: logger,
		config: &DNSEntropyConfig{
			RandomSubdomains:     3000,
			TestIterations:      5,
			Concurrency:         50,
			TimeoutMS:           5000,
			EntropyThreshold:    2.5,
			DNSServers:          []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"},
			UseAdvancedPayloads: true,
			DetectTakeovers:     true,
		},
		results: &DNSEntropyResults{
			EntropyDistribution: make([]EntropyBucket, 0),
			DyingWildcards:      make([]DyingWildcardResult, 0),
			TakeoverCandidates:  make([]TakeoverCandidate, 0),
			WildcardPatterns:    make([]WildcardPattern, 0),
			DNSAnomalies:        make([]DNSAnomaly, 0),
			Timestamp:           time.Now(),
		},
	}
}

// AnalyzeDomain выполняет элитный анализ DNS entropy
func (dwe *DNSWildcardEntropyDiff) AnalyzeDomain(ctx context.Context, domain string) (*DNSEntropyResults, error) {
	dwe.logger.Info("🧬 Starting elite DNS Wildcard Entropy analysis", 
		zap.String("domain", domain))

	startTime := time.Now()
	dwe.results.Domain = domain

	// Step 1: Generate random subdomains
	randomSubdomains := dwe.generateRandomSubdomains(domain)
	dwe.results.TotalSubdomains = len(randomSubdomains)

	// Step 2: Perform DNS queries with multiple iterations
	dnsResponses, err := dwe.performDNSQueries(ctx, randomSubdomains)
	if err != nil {
		return nil, fmt.Errorf("DNS queries failed: %w", err)
	}

	// Step 3: Calculate entropy metrics
	dwe.calculateEntropyMetrics(dnsResponses)

	// Step 4: Detect wildcard behavior
	dwe.detectWildcardBehavior(dnsResponses)

	// Step 5: Find dying wildcards (anomalies)
	dwe.findDyingWildcards(dnsResponses, randomSubdomains)

	// Step 6: Detect subdomain takeover candidates
	if dwe.config.DetectTakeovers {
		dwe.detectTakeoverCandidates(dnsResponses, randomSubdomains)
	}

	// Step 7: Analyze wildcard patterns
	dwe.analyzeWildcardPatterns(dnsResponses)

	// Step 8: Generate statistical data
	dwe.generateStatistics(dnsResponses, time.Since(startTime))

	dwe.logger.Info("✅ DNS Wildcard Entropy analysis completed",
		zap.Float64("entropy_score", dwe.results.EntropyScore),
		zap.Bool("wildcard_detected", dwe.results.WildcardDetected),
		zap.Int("dying_wildcards", len(dwe.results.DyingWildcards)),
		zap.Int("takeover_candidates", len(dwe.results.TakeoverCandidates)))

	return dwe.results, nil
}

// DNSResponse - ответ DNS запроса
type DNSResponse struct {
	Subdomain    string
	IPs          []string
	CNAME        string
	TTL          int
	ResponseSize int
	QueryTime    time.Duration
	Error        error
	DNSServer    string
}

// generateRandomSubdomains генерирует случайные поддомены
func (dwe *DNSWildcardEntropyDiff) generateRandomSubdomains(domain string) []string {
	subdomains := make([]string, 0, dwe.config.RandomSubdomains)

	// Набор паттернов для генерации
	patterns := []func(int) string{
		func(i int) string { return fmt.Sprintf("rnd%d.%s", i, domain) },
		func(i int) string { return fmt.Sprintf("%s.%s", dwe.randomString(8), domain) },
		func(i int) string { return fmt.Sprintf("%s-%d.%s", dwe.randomString(6), i, domain) },
		func(i int) string { return fmt.Sprintf("test-%s.%s", dwe.randomString(10), domain) },
		func(i int) string { return fmt.Sprintf("%s.api.%s", dwe.randomString(5), domain) },
	}

	// Добавляем специальные поддомены для тестирования
	specialSubdomains := []string{
		fmt.Sprintf("definitely-not-exists-12345.%s", domain),
		fmt.Sprintf("random-entropy-test.%s", domain),
		fmt.Sprintf("aaaaaaaaaaaaaaaaaaaa.%s", domain),
		fmt.Sprintf("z1z2z3z4z5z6z7z8z9.%s", domain),
	}

	subdomains = append(subdomains, specialSubdomains...)

	// Генерируем остальные случайные поддомены
	for i := len(specialSubdomains); i < dwe.config.RandomSubdomains; i++ {
		pattern := patterns[i%len(patterns)]
		subdomain := pattern(i)
		subdomains = append(subdomains, subdomain)
	}

	return subdomains
}

// randomString генерирует случайную строку
func (dwe *DNSWildcardEntropyDiff) randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	
	_, err := rand.Read(b)
	if err != nil {
		// Fallback на псевдослучайные данные
		for i := range b {
			b[i] = charset[i%len(charset)]
		}
	} else {
		for i := range b {
			b[i] = charset[int(b[i])%len(charset)]
		}
	}
	
	return string(b)
}

// performDNSQueries выполняет DNS запросы с множественными итерациями
func (dwe *DNSWildcardEntropyDiff) performDNSQueries(ctx context.Context, subdomains []string) ([]DNSResponse, error) {
	var allResponses []DNSResponse
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, dwe.config.Concurrency)

	// Выполняем несколько итераций для более точной статистики
	for iteration := 0; iteration < dwe.config.TestIterations; iteration++ {
		for serverIdx, dnsServer := range dwe.config.DNSServers {
			for i, subdomain := range subdomains {
				wg.Add(1)
				go func(iter, srvIdx, subIdx int, sub, srv string) {
					defer wg.Done()
					semaphore <- struct{}{}
					defer func() { <-semaphore }()

					response := dwe.querySubdomain(ctx, sub, srv, iter)
					
					mu.Lock()
					allResponses = append(allResponses, response)
					mu.Unlock()

				}(iteration, serverIdx, i, subdomain, dnsServer)
			}
		}
	}

	wg.Wait()
	return allResponses, nil
}

// querySubdomain выполняет DNS запрос для поддомена
func (dwe *DNSWildcardEntropyDiff) querySubdomain(ctx context.Context, subdomain, dnsServer string, iteration int) DNSResponse {
	start := time.Now()
	
	response := DNSResponse{
		Subdomain: subdomain,
		DNSServer: dnsServer,
		QueryTime: 0,
	}

	// Настраиваем резолвер с кастомным DNS сервером
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Duration(dwe.config.TimeoutMS) * time.Millisecond,
			}
			return d.DialContext(ctx, network, dnsServer)
		},
	}

	// Запрос A записей
	ips, err := resolver.LookupIPAddr(ctx, subdomain)
	if err == nil {
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				response.IPs = append(response.IPs, ip.IP.String())
			}
		}
	}

	// Запрос CNAME записи
	cname, err := resolver.LookupCNAME(ctx, subdomain)
	if err == nil && cname != subdomain+"." {
		response.CNAME = strings.TrimSuffix(cname, ".")
	}

	// Запрос TXT записей для определения TTL (упрощенно)
	txtRecords, err := resolver.LookupTXT(ctx, subdomain)
	if err == nil && len(txtRecords) > 0 {
		response.TTL = 300 // Default TTL
	}

	response.QueryTime = time.Since(start)
	response.ResponseSize = len(response.IPs)*16 + len(response.CNAME) + len(fmt.Sprintf("%v", txtRecords))

	if len(response.IPs) == 0 && response.CNAME == "" && len(txtRecords) == 0 {
		response.Error = fmt.Errorf("no DNS records found")
	}

	return response
}

// calculateEntropyMetrics рассчитывает метрики entropy
func (dwe *DNSWildcardEntropyDiff) calculateEntropyMetrics(responses []DNSResponse) {
	if len(responses) == 0 {
		return
	}

	// Группируем ответы по размерам
	sizeGroups := make(map[string][]DNSResponse)
	
	for _, resp := range responses {
		if resp.Error != nil {
			continue
		}

		sizeRange := dwe.getSizeRange(resp.ResponseSize)
		sizeGroups[sizeRange] = append(sizeGroups[sizeRange], resp)
	}

	// Рассчитываем entropy для каждой группы
	totalResponses := 0
	var totalEntropy float64

	for sizeRange, groupResponses := range sizeGroups {
		if len(groupResponses) == 0 {
			continue
		}

		groupEntropy := dwe.calculateGroupEntropy(groupResponses)
		count := len(groupResponses)
		totalResponses += count

		bucket := EntropyBucket{
			ResponseSizeRange: sizeRange,
			Count:            count,
			Entropy:          groupEntropy,
		}

		dwe.results.EntropyDistribution = append(dwe.results.EntropyDistribution, bucket)
		totalEntropy += groupEntropy * float64(count)
	}

	// Рассчитываем общий entropy score
	if totalResponses > 0 {
		dwe.results.EntropyScore = totalEntropy / float64(totalResponses)

		// Нормализуем проценты
		for i := range dwe.results.EntropyDistribution {
			dwe.results.EntropyDistribution[i].Percentage = 
				float64(dwe.results.EntropyDistribution[i].Count) / float64(totalResponses) * 100
		}
	}
}

// getSizeRange определяет диапазон размера ответа
func (dwe *DNSWildcardEntropyDiff) getSizeRange(size int) string {
	switch {
	case size <= 50:
		return "0-50"
	case size <= 100:
		return "51-100"
	case size <= 200:
		return "101-200"
	case size <= 500:
		return "201-500"
	default:
		return "500+"
	}
}

// calculateGroupEntropy рассчитывает entropy для группы ответов
func (dwe *DNSWildcardEntropyDiff) calculateGroupEntropy(responses []DNSResponse) float64 {
	if len(responses) <= 1 {
		return 0
	}

	// Считаем частоты уникальных IP адресов
	ipFrequency := make(map[string]int)
	
	for _, resp := range responses {
		for _, ip := range resp.IPs {
			ipFrequency[ip]++
		}
	}

	if len(ipFrequency) <= 1 {
		return 0
	}

	// Рассчитываем Shannon entropy
	total := float64(len(responses))
	var entropy float64

	for _, count := range ipFrequency {
		if count > 0 {
			probability := float64(count) / total
			entropy -= probability * math.Log2(probability)
		}
	}

	return entropy
}

// detectWildcardBehavior определяет wildcard поведение
func (dwe *DNSWildcardEntropyDiff) detectWildcardBehavior(responses []DNSResponse) {
	if len(responses) == 0 {
		return
	}

	// Анализируем соотношение успешных ответов
	successCount := 0
	totalCount := 0
	ipCounts := make(map[string]int)

	for _, resp := range responses {
		totalCount++
		if resp.Error == nil && len(resp.IPs) > 0 {
			successCount++
			for _, ip := range resp.IPs {
				ipCounts[ip]++
			}
		}
	}

	successRate := float64(successCount) / float64(totalCount)

	// Если более 70% запросов успешны - вероятно wildcard
	if successRate > 0.7 {
		dwe.results.WildcardDetected = true

		// Анализируем паттерны IP адресов
		dominantIP := ""
		maxCount := 0
		for ip, count := range ipCounts {
			if count > maxCount {
				maxCount = count
				dominantIP = ip
			}
		}

		// Если один IP доминирует - классический wildcard
		if float64(maxCount)/float64(successCount) > 0.8 {
			pattern := WildcardPattern{
				Pattern:      "dominant_ip",
				ResponseType: "A_record",
				Frequency:    maxCount,
				Entropy:      dwe.results.EntropyScore,
				Description:  fmt.Sprintf("Dominant IP %s in %d responses", dominantIP, maxCount),
			}
			dwe.results.WildcardPatterns = append(dwe.results.WildcardPatterns, pattern)
		}
	}
}

// findDyingWildcards находит "дырявые" wildcard зоны
func (dwe *DNSWildcardEntropyDiff) findDyingWildcards(responses []DNSResponse, subdomains []string) {
	if !dwe.results.WildcardDetected {
		return
	}

	// Группируем ответы по поддоменам
	responseMap := make(map[string][]DNSResponse)
	for _, resp := range responses {
		responseMap[resp.Subdomain] = append(responseMap[resp.Subdomain], resp)
	}

	// Определяем "нормальный" wildcard ответ
	expectedIP := dwe.findMostCommonIP(responses)
	expectedTTL := dwe.findMostCommonTTL(responses)

	for _, subdomain := range subdomains {
		subResponses := responseMap[subdomain]
		if len(subResponses) == 0 {
			continue
		}

		// Анализируем аномалии
		anomalies := dwe.analyzeResponseAnomalies(subResponses, expectedIP, expectedTTL)
		if len(anomalies) > 0 {
			dying := DyingWildcardResult{
				Subdomain:   subdomain,
				ExpectedIP:  expectedIP,
				ExpectedTTL: expectedTTL,
				Evidence:    anomalies,
			}

			// Заполняем фактические данные
			if len(subResponses) > 0 && len(subResponses[0].IPs) > 0 {
				dying.ActualIPs = subResponses[0].IPs
				if subResponses[0].TTL != expectedTTL {
					dying.TTLAnomaly = true
					dying.ActualTTL = subResponses[0].TTL
				}
			}

			// Рассчитываем confidence
			dying.Confidence = float64(len(anomalies)) / 5.0 // Максимум 5 типов аномалий
			if dying.Confidence > 1.0 {
				dying.Confidence = 1.0
			}

			// Рассчитываем entropy delta
			subEntropy := dwe.calculateGroupEntropy(subResponses)
			dying.EntropyDelta = math.Abs(subEntropy - dwe.results.EntropyScore)

			dwe.results.DyingWildcards = append(dwe.results.DyingWildcards, dying)
		}
	}
}

// findMostCommonIP находит наиболее частый IP в ответах
func (dwe *DNSWildcardEntropyDiff) findMostCommonIP(responses []DNSResponse) string {
	ipCounts := make(map[string]int)
	
	for _, resp := range responses {
		if resp.Error == nil {
			for _, ip := range resp.IPs {
				ipCounts[ip]++
			}
		}
	}

	maxCount := 0
	mostCommonIP := ""
	for ip, count := range ipCounts {
		if count > maxCount {
			maxCount = count
			mostCommonIP = ip
		}
	}

	return mostCommonIP
}

// findMostCommonTTL находит наиболее частый TTL
func (dwe *DNSWildcardEntropyDiff) findMostCommonTTL(responses []DNSResponse) int {
	ttlCounts := make(map[int]int)
	
	for _, resp := range responses {
		if resp.Error == nil && resp.TTL > 0 {
			ttlCounts[resp.TTL]++
		}
	}

	maxCount := 0
	mostCommonTTL := 300 // Default
	for ttl, count := range ttlCounts {
		if count > maxCount {
			maxCount = count
			mostCommonTTL = ttl
		}
	}

	return mostCommonTTL
}

// analyzeResponseAnomalies анализирует аномалии в ответах
func (dwe *DNSWildcardEntropyDiff) analyzeResponseAnomalies(responses []DNSResponse, expectedIP string, expectedTTL int) []string {
	var anomalies []string

	for _, resp := range responses {
		if resp.Error != nil {
			anomalies = append(anomalies, "DNS resolution failed")
			continue
		}

		// Проверяем IP аномалии
		if len(resp.IPs) > 0 && resp.IPs[0] != expectedIP {
			anomalies = append(anomalies, fmt.Sprintf("Unexpected IP: %s", resp.IPs[0]))
		}

		// Проверяем TTL аномалии
		if resp.TTL > 0 && resp.TTL != expectedTTL {
			anomalies = append(anomalies, fmt.Sprintf("TTL anomaly: %d vs expected %d", resp.TTL, expectedTTL))
		}

		// Проверяем CNAME аномалии
		if resp.CNAME != "" {
			anomalies = append(anomalies, fmt.Sprintf("Unexpected CNAME: %s", resp.CNAME))
		}

		// Проверяем время ответа
		if resp.QueryTime > 5*time.Second {
			anomalies = append(anomalies, "Slow DNS response")
		}
	}

	return anomalies
}

// detectTakeoverCandidates ищет кандидатов на subdomain takeover
func (dwe *DNSWildcardEntropyDiff) detectTakeoverCandidates(responses []DNSResponse, subdomains []string) {
	takeoverServices := map[string]string{
		"github.io":           "GitHub Pages",
		"herokuapp.com":       "Heroku",
		"amazonaws.com":       "AWS S3",
		"azure.com":           "Azure",
		"cloudfront.net":      "CloudFront",
		"fastly.com":          "Fastly",
		"netlify.com":         "Netlify",
		"vercel.app":          "Vercel",
	}

	for _, resp := range responses {
		if resp.Error == nil && resp.CNAME != "" {
			for service, provider := range takeoverServices {
				if strings.Contains(resp.CNAME, service) {
					candidate := TakeoverCandidate{
						Subdomain:    resp.Subdomain,
						CNAME:        resp.CNAME,
						Service:      provider,
						Status:       "potential",
						TakeoverRisk: "medium",
						Confidence:   0.7,
						Evidence:     []string{fmt.Sprintf("CNAME points to %s service", provider)},
						VerificationSteps: []string{
							"Verify service configuration",
							"Check for unclaimed resources",
							"Test subdomain takeover",
						},
					}

					// Дополнительная проверка на недоступность
					if len(resp.IPs) == 0 {
						candidate.TakeoverRisk = "high"
						candidate.Confidence = 0.9
						candidate.Evidence = append(candidate.Evidence, "CNAME exists but no IP resolution")
					}

					dwe.results.TakeoverCandidates = append(dwe.results.TakeoverCandidates, candidate)
				}
			}
		}
	}
}

// analyzeWildcardPatterns анализирует паттерны wildcard поведения
func (dwe *DNSWildcardEntropyDiff) analyzeWildcardPatterns(responses []DNSResponse) {
	if len(responses) == 0 {
		return
	}

	// Анализируем паттерны TTL
	ttlCounts := make(map[int]int)
	for _, resp := range responses {
		if resp.Error == nil && resp.TTL > 0 {
			ttlCounts[resp.TTL]++
		}
	}

	if len(ttlCounts) > 1 {
		pattern := WildcardPattern{
			Pattern:      "variable_ttl",
			ResponseType: "TTL_variation",
			Frequency:    len(ttlCounts),
			Entropy:      dwe.calculateTTLEntropy(ttlCounts),
			Description:  fmt.Sprintf("Variable TTL values detected: %v", ttlCounts),
		}
		dwe.results.WildcardPatterns = append(dwe.results.WildcardPatterns, pattern)
	}

	// Анализируем паттерны размеров ответов
	sizeCounts := make(map[int]int)
	for _, resp := range responses {
		if resp.Error == nil {
			sizeCounts[resp.ResponseSize]++
		}
	}

	if len(sizeCounts) > 3 {
		pattern := WildcardPattern{
			Pattern:      "variable_response_size",
			ResponseType: "Size_variation",
			Frequency:    len(sizeCounts),
			Entropy:      dwe.calculateSizeEntropy(sizeCounts),
			Description:  "Variable response sizes suggest complex wildcard logic",
		}
		dwe.results.WildcardPatterns = append(dwe.results.WildcardPatterns, pattern)
	}
}

// calculateTTLEntropy рассчитывает entropy для TTL значений
func (dwe *DNSWildcardEntropyDiff) calculateTTLEntropy(ttlCounts map[int]int) float64 {
	total := 0
	for _, count := range ttlCounts {
		total += count
	}

	var entropy float64
	for _, count := range ttlCounts {
		if count > 0 {
			probability := float64(count) / float64(total)
			entropy -= probability * math.Log2(probability)
		}
	}

	return entropy
}

// calculateSizeEntropy рассчитывает entropy для размеров ответов
func (dwe *DNSWildcardEntropyDiff) calculateSizeEntropy(sizeCounts map[int]int) float64 {
	total := 0
	for _, count := range sizeCounts {
		total += count
	}

	var entropy float64
	for _, count := range sizeCounts {
		if count > 0 {
			probability := float64(count) / float64(total)
			entropy -= probability * math.Log2(probability)
		}
	}

	return entropy
}

// generateStatistics генерирует статистические данные
func (dwe *DNSWildcardEntropyDiff) generateStatistics(responses []DNSResponse, duration time.Duration) {
	if len(responses) == 0 {
		return
	}

	uniqueIPs := make(map[string]bool)
	uniqueTTLs := make(map[int]bool)
	var responseSizes []float64
	successCount := 0

	for _, resp := range responses {
		if resp.Error == nil {
			successCount++
			responseSizes = append(responseSizes, float64(resp.ResponseSize))
			
			for _, ip := range resp.IPs {
				uniqueIPs[ip] = true
			}
			
			if resp.TTL > 0 {
				uniqueTTLs[resp.TTL] = true
			}
		}
	}

	dwe.results.StatisticalData.UniqueIPs = len(uniqueIPs)
	dwe.results.StatisticalData.UniqueTTLs = len(uniqueTTLs)
	dwe.results.StatisticalData.SuccessRate = float64(successCount) / float64(len(responses)) * 100

	// Рассчитываем среднее и стандартное отклонение для размеров ответов
	if len(responseSizes) > 0 {
		var sum float64
		for _, size := range responseSizes {
			sum += size
		}
		dwe.results.StatisticalData.AvgResponseSize = sum / float64(len(responseSizes))

		var variance float64
		for _, size := range responseSizes {
			diff := size - dwe.results.StatisticalData.AvgResponseSize
			variance += diff * diff
		}
		dwe.results.StatisticalData.StdDevResponseSize = math.Sqrt(variance / float64(len(responseSizes)))
	}

	// Рассчитываем performance score
	baseScore := dwe.results.StatisticalData.SuccessRate
	entropyBonus := math.Min(dwe.results.EntropyScore*10, 30) // Максимум 30 баллов за entropy
	dwe.results.StatisticalData.PerformanceScore = baseScore + entropyBonus
}

// GetResults возвращает результаты анализа
func (dwe *DNSWildcardEntropyDiff) GetResults() *DNSEntropyResults {
	dwe.mutex.RLock()
	defer dwe.mutex.RUnlock()
	return dwe.results
}

// ExportJSON экспортирует результаты в JSON
func (dwe *DNSWildcardEntropyDiff) ExportJSON() ([]byte, error) {
	dwe.mutex.RLock()
	defer dwe.mutex.RUnlock()
	return json.MarshalIndent(dwe.results, "", "  ")
}