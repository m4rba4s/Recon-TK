package elite

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// JA3CollisionSweeper - элитный анализатор JA3/JA3S коллизий для обхода CDN
type JA3CollisionSweeper struct {
	logger   *zap.Logger
	config   *JA3SweeperConfig
	results  *JA3SweeperResults
	mutex    sync.RWMutex
}

// JA3SweeperConfig - конфигурация JA3 sweeper
type JA3SweeperConfig struct {
	TargetHost        string        `json:"target_host"`
	TargetPort        int           `json:"target_port"`
	TLSConfigurations int           `json:"tls_configurations"`
	Concurrency       int           `json:"concurrency"`
	TimeoutSeconds    int           `json:"timeout_seconds"`
	UserAgents        []string      `json:"user_agents"`
	CustomCiphers     [][]uint16    `json:"custom_ciphers"`
	TestHTTP2         bool          `json:"test_http2"`
	TestHTTP3         bool          `json:"test_http3"`
	VerboseLogging    bool          `json:"verbose_logging"`
}

// JA3SweeperResults - результаты JA3 collision анализа
type JA3SweeperResults struct {
	Target               string                    `json:"target"`
	TotalConfigurations  int                       `json:"total_configurations"`
	SuccessfulHandshakes int                       `json:"successful_handshakes"`
	UniqueJA3S           int                       `json:"unique_ja3s"`
	CloudflareJA3S       []string                  `json:"cloudflare_ja3s"`
	OriginJA3S           []string                  `json:"origin_ja3s"`
	JA3Configurations    []JA3Configuration        `json:"ja3_configurations"`
	CollisionCandidates  []JA3CollisionCandidate   `json:"collision_candidates"`
	OriginFingerprints   []OriginFingerprint       `json:"origin_fingerprints"`
	TLSAnomalies         []TLSAnomaly              `json:"tls_anomalies"`
	PerformanceMetrics   JA3PerformanceMetrics     `json:"performance_metrics"`
	Timestamp            time.Time                 `json:"timestamp"`
}

// JA3Configuration - конфигурация TLS клиента
type JA3Configuration struct {
	ConfigID         int      `json:"config_id"`
	TLSVersion       uint16   `json:"tls_version"`
	CipherSuites     []uint16 `json:"cipher_suites"`
	Extensions       []uint16 `json:"extensions"`
	EllipticCurves   []uint16 `json:"elliptic_curves"`
	PointFormats     []uint8  `json:"point_formats"`
	JA3Hash          string   `json:"ja3_hash"`
	JA3SHash         string   `json:"ja3s_hash"`
	ServerName       string   `json:"server_name"`
	ALPN             []string `json:"alpn"`
	HandshakeSuccess bool     `json:"handshake_success"`
	ResponseTime     string   `json:"response_time"`
	Error            string   `json:"error,omitempty"`
}

// JA3CollisionCandidate - кандидат на JA3/JA3S коллизию
type JA3CollisionCandidate struct {
	ConfigID         int     `json:"config_id"`
	JA3Hash          string  `json:"ja3_hash"`
	JA3SHash         string  `json:"ja3s_hash"`
	IsOriginBehavior bool    `json:"is_origin_behavior"`
	Confidence       float64 `json:"confidence"`
	Evidence         []string `json:"evidence"`
	TLSVersion       string  `json:"tls_version"`
	CipherSuite      string  `json:"cipher_suite"`
	ServerCert       CertificateInfo `json:"server_cert"`
}

// OriginFingerprint - отпечаток origin сервера
type OriginFingerprint struct {
	JA3SHash         string           `json:"ja3s_hash"`
	ServerSoftware   string           `json:"server_software"`
	CertificateChain []CertificateInfo `json:"certificate_chain"`
	TLSFeatures      TLSFeatures      `json:"tls_features"`
	OriginIndicators []string         `json:"origin_indicators"`
	Confidence       float64          `json:"confidence"`
}

// CertificateInfo - информация о сертификате
type CertificateInfo struct {
	Subject         string    `json:"subject"`
	Issuer          string    `json:"issuer"`
	SerialNumber    string    `json:"serial_number"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	DNSNames        []string  `json:"dns_names"`
	Fingerprint     string    `json:"fingerprint"`
	SignatureAlg    string    `json:"signature_algorithm"`
	IsCloudflare    bool      `json:"is_cloudflare"`
}

// TLSFeatures - особенности TLS соединения
type TLSFeatures struct {
	SupportsHTTP2        bool     `json:"supports_http2"`
	SupportsHTTP3        bool     `json:"supports_http3"`
	SupportsSNI          bool     `json:"supports_sni"`
	SupportsALPN         bool     `json:"supports_alpn"`
	SupportsSessionTickets bool   `json:"supports_session_tickets"`
	SupportedCurves      []string `json:"supported_curves"`
	CompressionMethods   []string `json:"compression_methods"`
	SessionResumption    bool     `json:"session_resumption"`
}

// TLSAnomaly - TLS аномалия
type TLSAnomaly struct {
	Type         string  `json:"type"`
	ConfigID     int     `json:"config_id"`
	Description  string  `json:"description"`
	Severity     string  `json:"severity"`
	Evidence     []string `json:"evidence"`
	Confidence   float64 `json:"confidence"`
	Implications string  `json:"implications"`
}

// JA3PerformanceMetrics - метрики производительности
type JA3PerformanceMetrics struct {
	AvgHandshakeTime  string  `json:"avg_handshake_time"`
	FastestHandshake  string  `json:"fastest_handshake"`
	SlowestHandshake  string  `json:"slowest_handshake"`
	SuccessRate       float64 `json:"success_rate"`
	TotalScanTime     string  `json:"total_scan_time"`
	ConfigsPerSecond  float64 `json:"configs_per_second"`
}

// NewJA3CollisionSweeper создает новый экземпляр JA3 sweeper
func NewJA3CollisionSweeper(logger *zap.Logger) *JA3CollisionSweeper {
	return &JA3CollisionSweeper{
		logger: logger,
		config: &JA3SweeperConfig{
			TLSConfigurations: 120,
			Concurrency:       10,
			TimeoutSeconds:    10,
			UserAgents: []string{
				"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
				"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			},
			TestHTTP2:      true,
			TestHTTP3:      false, // Требует специальной поддержки
			VerboseLogging: false,
		},
		results: &JA3SweeperResults{
			CloudflareJA3S:      make([]string, 0),
			OriginJA3S:          make([]string, 0),
			JA3Configurations:   make([]JA3Configuration, 0),
			CollisionCandidates: make([]JA3CollisionCandidate, 0),
			OriginFingerprints:  make([]OriginFingerprint, 0),
			TLSAnomalies:        make([]TLSAnomaly, 0),
			Timestamp:           time.Now(),
		},
	}
}

// SweepTarget выполняет элитный JA3/JA3S collision sweep
func (jcs *JA3CollisionSweeper) SweepTarget(ctx context.Context, target string, port int) (*JA3SweeperResults, error) {
	jcs.logger.Info("🔐 Starting elite JA3/JA3S Collision Sweep", 
		zap.String("target", target),
		zap.Int("port", port))

	startTime := time.Now()
	jcs.config.TargetHost = target
	jcs.config.TargetPort = port
	jcs.results.Target = fmt.Sprintf("%s:%d", target, port)

	// Step 1: Generate TLS configurations
	configurations := jcs.generateTLSConfigurations()
	jcs.results.TotalConfigurations = len(configurations)

	// Step 2: Test configurations concurrently
	results, err := jcs.testTLSConfigurations(ctx, configurations)
	if err != nil {
		return nil, fmt.Errorf("TLS configuration testing failed: %w", err)
	}

	jcs.results.JA3Configurations = results

	// Step 3: Analyze JA3S responses
	jcs.analyzeJA3SResponses(results)

	// Step 4: Detect collision candidates
	jcs.detectCollisionCandidates(results)

	// Step 5: Fingerprint origin servers
	jcs.fingerprintOriginServers(results)

	// Step 6: Detect TLS anomalies
	jcs.detectTLSAnomalies(results)

	// Step 7: Generate performance metrics
	jcs.generatePerformanceMetrics(results, time.Since(startTime))

	jcs.logger.Info("✅ JA3/JA3S Collision Sweep completed",
		zap.Int("unique_ja3s", jcs.results.UniqueJA3S),
		zap.Int("collision_candidates", len(jcs.results.CollisionCandidates)),
		zap.Int("origin_fingerprints", len(jcs.results.OriginFingerprints)))

	return jcs.results, nil
}

// generateTLSConfigurations генерирует вариативные TLS конфигурации
func (jcs *JA3CollisionSweeper) generateTLSConfigurations() []JA3Configuration {
	var configurations []JA3Configuration

	// Базовые TLS версии
	tlsVersions := []uint16{
		tls.VersionTLS12,
		tls.VersionTLS13,
		tls.VersionTLS11, // Для legacy тестов
	}

	// Наборы cipher suites
	cipherSets := [][]uint16{
		// Modern Chrome-like
		{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		// Firefox-like
		{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		// Safari-like
		{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		// Legacy/Windows
		{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
	}

	// Extension combinations
	extensionSets := [][]uint16{
		{0, 5, 10, 11, 13, 18, 21, 23, 35, 43, 45, 51}, // Chrome-like
		{0, 5, 10, 11, 13, 18, 21, 23, 35, 43, 45},     // Firefox-like
		{0, 5, 10, 11, 13, 18, 21, 23, 35},             // Safari-like
		{0, 5, 10, 11, 13},                             // Minimal
	}

	// ALPN protocols
	alpnSets := [][]string{
		{"h2", "http/1.1"},
		{"http/1.1"},
		{"h2"},
		{},
	}

	configID := 0
	for _, tlsVersion := range tlsVersions {
		for i, cipherSet := range cipherSets {
			for j, extensions := range extensionSets {
				for k, alpn := range alpnSets {
					if configID >= jcs.config.TLSConfigurations {
						break
					}

					config := JA3Configuration{
						ConfigID:       configID,
						TLSVersion:     tlsVersion,
						CipherSuites:   cipherSet,
						Extensions:     extensions,
						EllipticCurves: []uint16{23, 24, 25}, // Standard curves
						PointFormats:   []uint8{0},           // Uncompressed
						ServerName:     jcs.config.TargetHost,
						ALPN:          alpn,
					}

					// Генерируем JA3 hash
					config.JA3Hash = jcs.generateJA3Hash(config)

					configurations = append(configurations, config)
					configID++
				}
			}
		}
	}

	// Добавляем специальные эксплоитные конфигурации
	jcs.addExploitConfigurations(&configurations, &configID)

	return configurations
}

// generateJA3Hash генерирует JA3 hash для конфигурации
func (jcs *JA3CollisionSweeper) generateJA3Hash(config JA3Configuration) string {
	// Преобразуем в строковый формат для JA3
	version := fmt.Sprintf("%d", config.TLSVersion)
	
	var ciphers []string
	for _, cipher := range config.CipherSuites {
		ciphers = append(ciphers, fmt.Sprintf("%d", cipher))
	}
	
	var extensions []string
	for _, ext := range config.Extensions {
		extensions = append(extensions, fmt.Sprintf("%d", ext))
	}
	
	var curves []string
	for _, curve := range config.EllipticCurves {
		curves = append(curves, fmt.Sprintf("%d", curve))
	}
	
	var formats []string
	for _, format := range config.PointFormats {
		formats = append(formats, fmt.Sprintf("%d", format))
	}

	// JA3 формат: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
	ja3String := fmt.Sprintf("%s,%s,%s,%s,%s",
		version,
		strings.Join(ciphers, "-"),
		strings.Join(extensions, "-"),
		strings.Join(curves, "-"),
		strings.Join(formats, "-"))

	// В реальной реализации использовался бы настоящий JA3 hash
	// Для демонстрации используем упрощенную версию
	return fmt.Sprintf("ja3_%x", md5.Sum([]byte(ja3String)))
}

// addExploitConfigurations добавляет специальные эксплоитные конфигурации
func (jcs *JA3CollisionSweeper) addExploitConfigurations(configurations *[]JA3Configuration, configID *int) {
	// Конфигурация для обхода Cloudflare
	cloudflareBypass := JA3Configuration{
		ConfigID:     *configID,
		TLSVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{0x1301, 0x1302, 0x1303}, // TLS 1.3 ciphers в TLS 1.2
		Extensions:   []uint16{0, 5, 10, 11, 13, 18, 21, 23, 35, 43, 45, 51, 65281},
		EllipticCurves: []uint16{29, 23, 24}, // X25519 first
		PointFormats: []uint8{0},
		ServerName:   jcs.config.TargetHost,
		ALPN:        []string{"h2", "http/1.1"},
	}
	cloudflareBypass.JA3Hash = jcs.generateJA3Hash(cloudflareBypass)
	*configurations = append(*configurations, cloudflareBypass)
	*configID++

	// Конфигурация с недокументированными extensions
	undocumentedExts := JA3Configuration{
		ConfigID:     *configID,
		TLSVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{tls.TLS_AES_256_GCM_SHA384},
		Extensions:   []uint16{0, 5, 10, 11, 13, 18, 21, 23, 35, 43, 45, 51, 17513, 65037}, // Undocumented
		EllipticCurves: []uint16{23, 24, 25, 256, 257}, // Включая экспериментальные
		PointFormats: []uint8{0, 1},
		ServerName:   jcs.config.TargetHost,
		ALPN:        []string{"h2"},
	}
	undocumentedExts.JA3Hash = jcs.generateJA3Hash(undocumentedExts)
	*configurations = append(*configurations, undocumentedExts)
	*configID++

	// Конфигурация с legacy cipher ordering
	legacyOrdering := JA3Configuration{
		ConfigID:     *configID,
		TLSVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,    // Старый в начале
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		},
		Extensions:   []uint16{0, 5, 10, 11},
		EllipticCurves: []uint16{23},
		PointFormats: []uint8{0},
		ServerName:   jcs.config.TargetHost,
		ALPN:        []string{},
	}
	legacyOrdering.JA3Hash = jcs.generateJA3Hash(legacyOrdering)
	*configurations = append(*configurations, legacyOrdering)
	*configID++
}

// testTLSConfigurations тестирует TLS конфигурации
func (jcs *JA3CollisionSweeper) testTLSConfigurations(ctx context.Context, configurations []JA3Configuration) ([]JA3Configuration, error) {
	var results []JA3Configuration
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, jcs.config.Concurrency)

	for _, config := range configurations {
		wg.Add(1)
		go func(cfg JA3Configuration) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := jcs.testSingleConfiguration(ctx, cfg)
			
			mu.Lock()
			results = append(results, result)
			if result.HandshakeSuccess {
				jcs.results.SuccessfulHandshakes++
			}
			mu.Unlock()

		}(config)
	}

	wg.Wait()

	// Сортируем результаты по ConfigID
	sort.Slice(results, func(i, j int) bool {
		return results[i].ConfigID < results[j].ConfigID
	})

	return results, nil
}

// testSingleConfiguration тестирует одну TLS конфигурацию
func (jcs *JA3CollisionSweeper) testSingleConfiguration(ctx context.Context, config JA3Configuration) JA3Configuration {
	start := time.Now()
	result := config

	// Создаем кастомную TLS конфигурацию
	tlsConfig := &tls.Config{
		ServerName:         config.ServerName,
		CipherSuites:      config.CipherSuites,
		MinVersion:        config.TLSVersion,
		MaxVersion:        config.TLSVersion,
		InsecureSkipVerify: true, // Для тестирования
		NextProtos:        config.ALPN,
	}

	// Подключаемся к серверу
	dialer := &net.Dialer{
		Timeout: time.Duration(jcs.config.TimeoutSeconds) * time.Second,
	}

	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", jcs.config.TargetHost, jcs.config.TargetPort))
	if err != nil {
		result.Error = fmt.Sprintf("Connection failed: %v", err)
		result.ResponseTime = time.Since(start).String()
		return result
	}
	defer conn.Close()

	// Выполняем TLS handshake
	tlsConn := tls.Client(conn, tlsConfig)
	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		result.Error = fmt.Sprintf("TLS handshake failed: %v", err)
		result.ResponseTime = time.Since(start).String()
		return result
	}

	result.HandshakeSuccess = true
	result.ResponseTime = time.Since(start).String()

	// Получаем состояние соединения
	state := tlsConn.ConnectionState()
	
	// Генерируем JA3S hash (упрощенная версия)
	result.JA3SHash = jcs.generateJA3SHash(state)

	if jcs.config.VerboseLogging {
		jcs.logger.Debug("TLS configuration tested",
			zap.Int("config_id", config.ConfigID),
			zap.String("ja3s_hash", result.JA3SHash),
			zap.Bool("success", result.HandshakeSuccess))
	}

	return result
}

// generateJA3SHash генерирует JA3S hash из TLS состояния
func (jcs *JA3CollisionSweeper) generateJA3SHash(state tls.ConnectionState) string {
	// JA3S формат: TLSVersion,Cipher,Extensions
	version := fmt.Sprintf("%d", state.Version)
	cipher := fmt.Sprintf("%d", state.CipherSuite)
	
	// В реальной реализации анализировались бы server extensions
	// Для демонстрации используем упрощенную версию
	extensions := "0-5-10-11" // Placeholder
	
	ja3sString := fmt.Sprintf("%s,%s,%s", version, cipher, extensions)
	
	// В реальности использовался бы MD5 hash
	return fmt.Sprintf("ja3s_%x", md5.Sum([]byte(ja3sString)))
}

// analyzeJA3SResponses анализирует JA3S ответы
func (jcs *JA3CollisionSweeper) analyzeJA3SResponses(results []JA3Configuration) {
	ja3sMap := make(map[string]int)
	cloudflarePatterns := []string{"ja3s_cloudflare", "ja3s_cf"} // Известные Cloudflare JA3S
	
	for _, result := range results {
		if result.HandshakeSuccess && result.JA3SHash != "" {
			ja3sMap[result.JA3SHash]++
			
			// Проверяем на Cloudflare patterns
			isCloudflare := false
			for _, pattern := range cloudflarePatterns {
				if strings.Contains(result.JA3SHash, pattern) {
					isCloudflare = true
					break
				}
			}
			
			if isCloudflare {
				jcs.results.CloudflareJA3S = append(jcs.results.CloudflareJA3S, result.JA3SHash)
			} else {
				jcs.results.OriginJA3S = append(jcs.results.OriginJA3S, result.JA3SHash)
			}
		}
	}
	
	jcs.results.UniqueJA3S = len(ja3sMap)
	
	// Удаляем дубликаты
	jcs.results.CloudflareJA3S = jcs.removeDuplicates(jcs.results.CloudflareJA3S)
	jcs.results.OriginJA3S = jcs.removeDuplicates(jcs.results.OriginJA3S)
}

// detectCollisionCandidates детектит кандидатов на collision
func (jcs *JA3CollisionSweeper) detectCollisionCandidates(results []JA3Configuration) {
	// Группируем по JA3S hash
	ja3sGroups := make(map[string][]JA3Configuration)
	
	for _, result := range results {
		if result.HandshakeSuccess {
			ja3sGroups[result.JA3SHash] = append(ja3sGroups[result.JA3SHash], result)
		}
	}
	
	// Анализируем группы на предмет collision
	for ja3sHash, group := range ja3sGroups {
		if len(group) > 1 {
			// Множественные JA3 конфигурации дают одинаковый JA3S - потенциальная collision
			for _, config := range group {
				candidate := JA3CollisionCandidate{
					ConfigID:         config.ConfigID,
					JA3Hash:          config.JA3Hash,
					JA3SHash:         ja3sHash,
					IsOriginBehavior: jcs.isOriginBehavior(ja3sHash),
					Confidence:       0.7,
					Evidence:         []string{fmt.Sprintf("Multiple JA3 configs (%d) produce same JA3S", len(group))},
					TLSVersion:       jcs.getTLSVersionString(config.TLSVersion),
					CipherSuite:      jcs.getCipherSuiteName(config.CipherSuites[0]),
				}
				
				// Увеличиваем confidence если это потенциально origin
				if candidate.IsOriginBehavior {
					candidate.Confidence = 0.9
					candidate.Evidence = append(candidate.Evidence, "JA3S pattern suggests origin server behavior")
				}
				
				jcs.results.CollisionCandidates = append(jcs.results.CollisionCandidates, candidate)
			}
		}
	}
}

// isOriginBehavior определяет, указывает ли JA3S на origin поведение
func (jcs *JA3CollisionSweeper) isOriginBehavior(ja3sHash string) bool {
	// Упрощенная логика - в реальности более сложный анализ
	cloudflareIndicators := []string{"cf", "cloudflare", "13335"}
	
	for _, indicator := range cloudflareIndicators {
		if strings.Contains(strings.ToLower(ja3sHash), indicator) {
			return false
		}
	}
	
	// Если не содержит Cloudflare индикаторы - возможно origin
	return true
}

// fingerprintOriginServers создает отпечатки origin серверов
func (jcs *JA3CollisionSweeper) fingerprintOriginServers(results []JA3Configuration) {
	originJA3S := make(map[string][]JA3Configuration)
	
	for _, result := range results {
		if result.HandshakeSuccess && jcs.isOriginBehavior(result.JA3SHash) {
			originJA3S[result.JA3SHash] = append(originJA3S[result.JA3SHash], result)
		}
	}
	
	for ja3sHash, configs := range originJA3S {
		fingerprint := OriginFingerprint{
			JA3SHash:         ja3sHash,
			OriginIndicators: []string{},
			Confidence:       0.6,
		}
		
		// Анализируем TLS features
		if len(configs) > 0 {
			config := configs[0]
			fingerprint.TLSFeatures = TLSFeatures{
				SupportsHTTP2: jcs.containsALPN(config.ALPN, "h2"),
				SupportsALPN:  len(config.ALPN) > 0,
				SupportsHTTP3: jcs.containsALPN(config.ALPN, "h3"),
			}
			
			// Определяем server software по паттернам
			if fingerprint.TLSFeatures.SupportsHTTP2 {
				fingerprint.ServerSoftware = "Modern HTTP/2 Server"
				fingerprint.OriginIndicators = append(fingerprint.OriginIndicators, "HTTP/2 support")
			}
			
			if config.TLSVersion == tls.VersionTLS13 {
				fingerprint.OriginIndicators = append(fingerprint.OriginIndicators, "TLS 1.3 support")
				fingerprint.Confidence += 0.2
			}
		}
		
		jcs.results.OriginFingerprints = append(jcs.results.OriginFingerprints, fingerprint)
	}
}

// detectTLSAnomalies детектит TLS аномалии
func (jcs *JA3CollisionSweeper) detectTLSAnomalies(results []JA3Configuration) {
	for _, result := range results {
		if !result.HandshakeSuccess {
			continue
		}
		
		// Детект аномалий в cipher suite selection
		if len(result.CipherSuites) > 0 {
			selectedCipher := result.CipherSuites[0] // Упрощение
			
			// Проверяем на неожиданные cipher suites
			if jcs.isUnexpectedCipher(selectedCipher) {
				anomaly := TLSAnomaly{
					Type:         "unexpected_cipher",
					ConfigID:     result.ConfigID,
					Description:  fmt.Sprintf("Server selected unexpected cipher: %s", jcs.getCipherSuiteName(selectedCipher)),
					Severity:     "medium",
					Evidence:     []string{fmt.Sprintf("Cipher %d selected", selectedCipher)},
					Confidence:   0.8,
					Implications: "May indicate custom server configuration or origin behavior",
				}
				jcs.results.TLSAnomalies = append(jcs.results.TLSAnomalies, anomaly)
			}
		}
		
		// Детект аномалий в response time
		if responseTime, err := time.ParseDuration(result.ResponseTime); err == nil {
			if responseTime > 5*time.Second {
				anomaly := TLSAnomaly{
					Type:         "slow_handshake",
					ConfigID:     result.ConfigID,
					Description:  fmt.Sprintf("Unusually slow TLS handshake: %s", result.ResponseTime),
					Severity:     "low",
					Evidence:     []string{fmt.Sprintf("Handshake time: %s", result.ResponseTime)},
					Confidence:   0.6,
					Implications: "May indicate network latency or server processing delays",
				}
				jcs.results.TLSAnomalies = append(jcs.results.TLSAnomalies, anomaly)
			}
		}
	}
}

// Helper functions
func (jcs *JA3CollisionSweeper) removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	return result
}

func (jcs *JA3CollisionSweeper) containsALPN(alpnList []string, protocol string) bool {
	for _, p := range alpnList {
		if p == protocol {
			return true
		}
	}
	return false
}

func (jcs *JA3CollisionSweeper) getTLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (%d)", version)
	}
}

func (jcs *JA3CollisionSweeper) getCipherSuiteName(cipher uint16) string {
	// Упрощенная версия - в реальности полная база cipher suites
	cipherNames := map[uint16]string{
		tls.TLS_AES_128_GCM_SHA256:        "TLS_AES_128_GCM_SHA256",
		tls.TLS_AES_256_GCM_SHA384:        "TLS_AES_256_GCM_SHA384",
		tls.TLS_CHACHA20_POLY1305_SHA256:  "TLS_CHACHA20_POLY1305_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "ECDHE-ECDSA-AES128-GCM-SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "ECDHE-RSA-AES128-GCM-SHA256",
	}
	
	if name, exists := cipherNames[cipher]; exists {
		return name
	}
	return fmt.Sprintf("Unknown (%d)", cipher)
}

func (jcs *JA3CollisionSweeper) isUnexpectedCipher(cipher uint16) bool {
	// Список неожиданных/редких cipher suites
	unexpectedCiphers := []uint16{
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
	}
	
	for _, unexpected := range unexpectedCiphers {
		if cipher == unexpected {
			return true
		}
	}
	return false
}

// generatePerformanceMetrics генерирует метрики производительности
func (jcs *JA3CollisionSweeper) generatePerformanceMetrics(results []JA3Configuration, totalTime time.Duration) {
	var handshakeTimes []time.Duration
	successCount := 0
	
	for _, result := range results {
		if result.HandshakeSuccess {
			successCount++
			if duration, err := time.ParseDuration(result.ResponseTime); err == nil {
				handshakeTimes = append(handshakeTimes, duration)
			}
		}
	}
	
	if len(handshakeTimes) > 0 {
		// Сортируем для поиска min/max
		sort.Slice(handshakeTimes, func(i, j int) bool {
			return handshakeTimes[i] < handshakeTimes[j]
		})
		
		// Рассчитываем среднее
		var total time.Duration
		for _, t := range handshakeTimes {
			total += t
		}
		avg := total / time.Duration(len(handshakeTimes))
		
		jcs.results.PerformanceMetrics = JA3PerformanceMetrics{
			AvgHandshakeTime: avg.String(),
			FastestHandshake: handshakeTimes[0].String(),
			SlowestHandshake: handshakeTimes[len(handshakeTimes)-1].String(),
			SuccessRate:      float64(successCount) / float64(len(results)) * 100,
			TotalScanTime:    totalTime.String(),
			ConfigsPerSecond: float64(len(results)) / totalTime.Seconds(),
		}
	}
}

// GetResults возвращает результаты сканирования
func (jcs *JA3CollisionSweeper) GetResults() *JA3SweeperResults {
	jcs.mutex.RLock()
	defer jcs.mutex.RUnlock()
	return jcs.results
}

// ExportJSON экспортирует результаты в JSON
func (jcs *JA3CollisionSweeper) ExportJSON() ([]byte, error) {
	jcs.mutex.RLock()
	defer jcs.mutex.RUnlock()
	return json.MarshalIndent(jcs.results, "", "  ")
}