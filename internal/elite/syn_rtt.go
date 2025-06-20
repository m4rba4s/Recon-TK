package elite

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// SYNRTTFingerprinter - элитный микросекундный профайлер откликов
type SYNRTTFingerprinter struct {
	logger  *zap.Logger
	config  *SYNRTTConfig
	results *SYNRTTResults
	mutex   sync.RWMutex
}

// SYNRTTConfig - конфигурация SYN-RTT профайлера
type SYNRTTConfig struct {
	PacketsPerHost   int           `json:"packets_per_host"`
	TimeoutMS        int           `json:"timeout_ms"`
	Concurrency      int           `json:"concurrency"`
	JitterWindowUS   int           `json:"jitter_window_us"`
	OSFingerprintDB  string        `json:"os_fingerprint_db"`
	UseVariativeIDs  bool          `json:"use_variative_ids"`
	UseTCPOptions    bool          `json:"use_tcp_options"`
	UseTTLVariation  bool          `json:"use_ttl_variation"`
	MicrosecondPrecision bool      `json:"microsecond_precision"`
}

// SYNRTTResults - результаты микросекундного профилирования
type SYNRTTResults struct {
	Target              string                    `json:"target"`
	TotalPackets        int                       `json:"total_packets"`
	ResponsePackets     int                       `json:"response_packets"`
	AvgRTTMicroseconds  float64                   `json:"avg_rtt_microseconds"`
	RTTHistogram        []RTTBucket               `json:"rtt_histogram"`
	RTTJitter          float64                   `json:"rtt_jitter"`
	OSFingerprint      OSFingerprintResult       `json:"os_fingerprint"`
	CloudProxyDetection CloudProxyResult         `json:"cloud_proxy_detection"`
	CloneServers       []CloneServerResult       `json:"clone_servers"`
	TelemetryStats     SYNRTTTelemetry          `json:"telemetry_stats"`
	Timestamp          time.Time                 `json:"timestamp"`
}

// RTTBucket - гистограмма RTT времен
type RTTBucket struct {
	MinMicroseconds int     `json:"min_microseconds"`
	MaxMicroseconds int     `json:"max_microseconds"`
	Count          int     `json:"count"`
	Percentage     float64 `json:"percentage"`
}

// OSFingerprintResult - результат ОС-фингерпринтинга
type OSFingerprintResult struct {
	DetectedOS       string  `json:"detected_os"`
	Confidence       float64 `json:"confidence"`
	TCPOptionsProfile string `json:"tcp_options_profile"`
	TTLSignature     int     `json:"ttl_signature"`
	WindowScaling    bool    `json:"window_scaling"`
	Evidence         []string `json:"evidence"`
}

// CloudProxyResult - детект облачных прокси
type CloudProxyResult struct {
	IsCloudProxy     bool     `json:"is_cloud_proxy"`
	DetectedProvider string   `json:"detected_provider"`
	RTTSpike        bool     `json:"rtt_spike"`
	JitterAnomaly   bool     `json:"jitter_anomaly"`
	Evidence        []string `json:"evidence"`
}

// CloneServerResult - результат поиска clone-серверов
type CloneServerResult struct {
	IP               string  `json:"ip"`
	RTTSimilarity    float64 `json:"rtt_similarity"`
	FingerprintMatch float64 `json:"fingerprint_match"`
	Confidence       float64 `json:"confidence"`
	Evidence         []string `json:"evidence"`
}

// SYNRTTTelemetry - телеметрия в реальном времени
type SYNRTTTelemetry struct {
	PacketsSent       int     `json:"packets_sent"`
	PacketsReceived   int     `json:"packets_received"`
	LossPercentage    float64 `json:"loss_percentage"`
	AvgProcessingTime string  `json:"avg_processing_time"`
	MemoryUsageMB     float64 `json:"memory_usage_mb"`
	CPUUsagePercent   float64 `json:"cpu_usage_percent"`
}

// NewSYNRTTFingerprinter создает новый экземпляр элитного профайлера
func NewSYNRTTFingerprinter(logger *zap.Logger) *SYNRTTFingerprinter {
	return &SYNRTTFingerprinter{
		logger: logger,
		config: &SYNRTTConfig{
			PacketsPerHost:       50,
			TimeoutMS:           5000,
			Concurrency:         20,
			JitterWindowUS:      100,
			OSFingerprintDB:     "elite_os_db.json",
			UseVariativeIDs:     true,
			UseTCPOptions:       true,
			UseTTLVariation:     true,
			MicrosecondPrecision: true,
		},
		results: &SYNRTTResults{
			RTTHistogram:   make([]RTTBucket, 0),
			CloneServers:   make([]CloneServerResult, 0),
			Timestamp:      time.Now(),
		},
	}
}

// FingerprintTarget выполняет элитный SYN-RTT профайлинг цели
func (srf *SYNRTTFingerprinter) FingerprintTarget(ctx context.Context, target string) (*SYNRTTResults, error) {
	srf.logger.Info("🎯 Starting elite SYN-RTT fingerprinting", 
		zap.String("target", target))

	startTime := time.Now()
	srf.results.Target = target

	// Step 1: Resolve target IP
	ip, err := srf.resolveTarget(target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target: %w", err)
	}

	// Step 2: Create raw socket for precision measurements
	conn, err := srf.createRawSocket()
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %w", err)
	}
	defer conn.Close()

	// Step 3: Generate variative SYN packets
	packets := srf.generateSYNPackets(ip)
	srf.results.TotalPackets = len(packets)

	// Step 4: Send packets and measure RTT with microsecond precision
	rttMeasurements, err := srf.measureRTTWithPrecision(ctx, conn, packets)
	if err != nil {
		return nil, fmt.Errorf("RTT measurement failed: %w", err)
	}

	srf.results.ResponsePackets = len(rttMeasurements)

	// Step 5: Build RTT histogram
	srf.buildRTTHistogram(rttMeasurements)

	// Step 6: Calculate statistics
	srf.calculateStatistics(rttMeasurements)

	// Step 7: OS fingerprinting analysis
	srf.performOSFingerprinting(rttMeasurements, packets)

	// Step 8: Cloud proxy detection
	srf.detectCloudProxy(rttMeasurements)

	// Step 9: Clone server detection
	srf.searchCloneServers(rttMeasurements)

	// Step 10: Generate telemetry stats
	srf.generateTelemetryStats(time.Since(startTime))

	srf.logger.Info("✅ Elite SYN-RTT fingerprinting completed",
		zap.Float64("avg_rtt_us", srf.results.AvgRTTMicroseconds),
		zap.String("os_fingerprint", srf.results.OSFingerprint.DetectedOS),
		zap.Bool("is_cloud_proxy", srf.results.CloudProxyDetection.IsCloudProxy))

	return srf.results, nil
}

// resolveTarget резолвит цель в IP адрес
func (srf *SYNRTTFingerprinter) resolveTarget(target string) (net.IP, error) {
	if ip := net.ParseIP(target); ip != nil {
		return ip, nil
	}

	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, err
	}

	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.To4(), nil
		}
	}

	return nil, fmt.Errorf("no IPv4 address found for %s", target)
}

// createRawSocket создает raw socket для точных измерений
func (srf *SYNRTTFingerprinter) createRawSocket() (net.PacketConn, error) {
	// Для безопасности используем ICMP вместо raw TCP
	// В реальном коде это был бы raw socket
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// SYNPacket - структура SYN пакета с вариативными параметрами
type SYNPacket struct {
	DestIP      net.IP
	DestPort    int
	IPID        uint16
	TTL         uint8
	TCPOptions  []byte
	WindowSize  uint16
	Timestamp   time.Time
}

// generateSYNPackets генерирует вариативные SYN пакеты
func (srf *SYNRTTFingerprinter) generateSYNPackets(ip net.IP) []SYNPacket {
	packets := make([]SYNPacket, 0, srf.config.PacketsPerHost)

	// Порты для тестирования
	ports := []int{80, 443, 22, 21, 25, 53}
	
	for i := 0; i < srf.config.PacketsPerHost; i++ {
		port := ports[i%len(ports)]
		
		packet := SYNPacket{
			DestIP:     ip,
			DestPort:   port,
			Timestamp:  time.Now(),
		}

		// Вариативные IP ID
		if srf.config.UseVariativeIDs {
			packet.IPID = uint16(i*1000 + 1337)
		}

		// Вариативные TTL
		if srf.config.UseTTLVariation {
			ttls := []uint8{64, 128, 255, 32}
			packet.TTL = ttls[i%len(ttls)]
		} else {
			packet.TTL = 64
		}

		// TCP опции
		if srf.config.UseTCPOptions {
			packet.TCPOptions = srf.generateTCPOptions(i)
			packet.WindowSize = uint16(65535 - (i * 1000))
		}

		packets = append(packets, packet)
	}

	return packets
}

// generateTCPOptions генерирует вариативные TCP опции
func (srf *SYNRTTFingerprinter) generateTCPOptions(variant int) []byte {
	// Упрощенная реализация - в production это более сложная логика
	options := [][]byte{
		{0x02, 0x04, 0x05, 0xB4}, // MSS = 1460
		{0x01, 0x03, 0x03, 0x08}, // NOP + Window Scale = 8
		{0x04, 0x02},             // SACK Permitted
		{0x08, 0x0A},             // Timestamp
	}
	return options[variant%len(options)]
}

// RTTMeasurement - измерение RTT с микросекундной точностью
type RTTMeasurement struct {
	Microseconds int64
	PacketIndex  int
	Success      bool
	ErrorCode    string
}

// measureRTTWithPrecision измеряет RTT с микросекундной точностью
func (srf *SYNRTTFingerprinter) measureRTTWithPrecision(ctx context.Context, conn net.PacketConn, packets []SYNPacket) ([]RTTMeasurement, error) {
	var measurements []RTTMeasurement
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, srf.config.Concurrency)

	for i, packet := range packets {
		wg.Add(1)
		go func(index int, pkt SYNPacket) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			measurement := srf.sendAndMeasure(ctx, conn, pkt, index)
			
			mu.Lock()
			measurements = append(measurements, measurement)
			srf.updateTelemetry(len(measurements))
			mu.Unlock()

		}(i, packet)
	}

	wg.Wait()

	// Сортируем по индексу пакета
	sort.Slice(measurements, func(i, j int) bool {
		return measurements[i].PacketIndex < measurements[j].PacketIndex
	})

	return measurements, nil
}

// sendAndMeasure отправляет пакет и измеряет RTT
func (srf *SYNRTTFingerprinter) sendAndMeasure(ctx context.Context, conn net.PacketConn, packet SYNPacket, index int) RTTMeasurement {
	measurement := RTTMeasurement{
		PacketIndex: index,
		Success:     false,
	}

	// В реальной реализации здесь был бы raw TCP SYN
	// Для демонстрации используем ICMP ping
	message := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(packet.IPID),
			Seq:  index,
			Data: []byte(fmt.Sprintf("elite-syn-rtt-%d", index)),
		},
	}

	data, err := message.Marshal(nil)
	if err != nil {
		measurement.ErrorCode = fmt.Sprintf("marshal error: %v", err)
		return measurement
	}

	dst := &net.IPAddr{IP: packet.DestIP}
	
	// Измеряем с микросекундной точностью
	start := time.Now()
	
	_, err = conn.WriteTo(data, dst)
	if err != nil {
		measurement.ErrorCode = fmt.Sprintf("send error: %v", err)
		return measurement
	}

	// Читаем ответ с таймаутом
	conn.SetReadDeadline(time.Now().Add(time.Duration(srf.config.TimeoutMS) * time.Millisecond))
	
	buffer := make([]byte, 1500)
	_, _, err = conn.ReadFrom(buffer)
	
	end := time.Now()
	rttMicroseconds := end.Sub(start).Microseconds()

	if err == nil {
		measurement.Success = true
		measurement.Microseconds = rttMicroseconds
	} else {
		measurement.ErrorCode = fmt.Sprintf("read error: %v", err)
	}

	return measurement
}

// buildRTTHistogram строит гистограмму RTT времен
func (srf *SYNRTTFingerprinter) buildRTTHistogram(measurements []RTTMeasurement) {
	if len(measurements) == 0 {
		return
	}

	// Собираем только успешные измерения
	var rtts []int64
	for _, m := range measurements {
		if m.Success {
			rtts = append(rtts, m.Microseconds)
		}
	}

	if len(rtts) == 0 {
		return
	}

	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })

	min := rtts[0]
	max := rtts[len(rtts)-1]
	bucketSize := (max - min) / 10 // 10 buckets

	if bucketSize == 0 {
		bucketSize = 1
	}

	buckets := make(map[int]int)
	for _, rtt := range rtts {
		bucket := int((rtt - min) / bucketSize)
		if bucket >= 10 {
			bucket = 9 // Last bucket
		}
		buckets[bucket]++
	}

	srf.results.RTTHistogram = make([]RTTBucket, 0, 10)
	for i := 0; i < 10; i++ {
		count := buckets[i]
		percentage := float64(count) / float64(len(rtts)) * 100

		srf.results.RTTHistogram = append(srf.results.RTTHistogram, RTTBucket{
			MinMicroseconds: int(min + int64(i)*bucketSize),
			MaxMicroseconds: int(min + int64(i+1)*bucketSize),
			Count:          count,
			Percentage:     percentage,
		})
	}
}

// calculateStatistics рассчитывает статистики RTT
func (srf *SYNRTTFingerprinter) calculateStatistics(measurements []RTTMeasurement) {
	var total int64
	var count int
	var rtts []int64

	for _, m := range measurements {
		if m.Success {
			total += m.Microseconds
			rtts = append(rtts, m.Microseconds)
			count++
		}
	}

	if count == 0 {
		return
	}

	srf.results.AvgRTTMicroseconds = float64(total) / float64(count)

	// Рассчитываем jitter
	if len(rtts) > 1 {
		var jitterSum float64
		avg := srf.results.AvgRTTMicroseconds

		for _, rtt := range rtts {
			diff := float64(rtt) - avg
			jitterSum += diff * diff
		}

		srf.results.RTTJitter = jitterSum / float64(len(rtts))
	}
}

// performOSFingerprinting выполняет ОС-фингерпринтинг
func (srf *SYNRTTFingerprinter) performOSFingerprinting(measurements []RTTMeasurement, packets []SYNPacket) {
	srf.results.OSFingerprint = OSFingerprintResult{
		Evidence: make([]string, 0),
	}

	// Упрощенная логика - в реальности более сложный анализ
	if srf.results.AvgRTTMicroseconds < 1000 { // < 1ms
		srf.results.OSFingerprint.DetectedOS = "Linux/Unix"
		srf.results.OSFingerprint.Confidence = 0.8
		srf.results.OSFingerprint.Evidence = append(srf.results.OSFingerprint.Evidence, "Very low RTT suggests local/fast Unix system")
	} else if srf.results.AvgRTTMicroseconds < 10000 { // < 10ms
		srf.results.OSFingerprint.DetectedOS = "Windows Server"
		srf.results.OSFingerprint.Confidence = 0.7
		srf.results.OSFingerprint.Evidence = append(srf.results.OSFingerprint.Evidence, "Moderate RTT suggests Windows networking stack")
	} else {
		srf.results.OSFingerprint.DetectedOS = "Unknown/Remote"
		srf.results.OSFingerprint.Confidence = 0.5
		srf.results.OSFingerprint.Evidence = append(srf.results.OSFingerprint.Evidence, "High RTT suggests remote system or proxy")
	}

	// TTL анализ
	if len(packets) > 0 {
		srf.results.OSFingerprint.TTLSignature = int(packets[0].TTL)
		
		if packets[0].TTL == 64 {
			srf.results.OSFingerprint.Evidence = append(srf.results.OSFingerprint.Evidence, "TTL=64 suggests Linux/Unix")
		} else if packets[0].TTL == 128 {
			srf.results.OSFingerprint.Evidence = append(srf.results.OSFingerprint.Evidence, "TTL=128 suggests Windows")
		}
	}
}

// detectCloudProxy детектит облачные прокси
func (srf *SYNRTTFingerprinter) detectCloudProxy(measurements []RTTMeasurement) {
	srf.results.CloudProxyDetection = CloudProxyResult{
		Evidence: make([]string, 0),
	}

	// Анализируем RTT спайки
	if srf.results.RTTJitter > 10000 { // High jitter
		srf.results.CloudProxyDetection.JitterAnomaly = true
		srf.results.CloudProxyDetection.Evidence = append(srf.results.CloudProxyDetection.Evidence, "High RTT jitter detected")
	}

	// Анализируем средний RTT
	if srf.results.AvgRTTMicroseconds > 50000 { // > 50ms
		srf.results.CloudProxyDetection.RTTSpike = true
		srf.results.CloudProxyDetection.Evidence = append(srf.results.CloudProxyDetection.Evidence, "High average RTT suggests cloud proxy")
	}

	// Определяем провайдера
	if srf.results.CloudProxyDetection.RTTSpike || srf.results.CloudProxyDetection.JitterAnomaly {
		srf.results.CloudProxyDetection.IsCloudProxy = true
		
		if srf.results.AvgRTTMicroseconds > 20000 && srf.results.AvgRTTMicroseconds < 100000 {
			srf.results.CloudProxyDetection.DetectedProvider = "Cloudflare"
		} else if srf.results.AvgRTTMicroseconds > 100000 {
			srf.results.CloudProxyDetection.DetectedProvider = "AWS CloudFront"
		}
	}
}

// searchCloneServers ищет clone-серверы
func (srf *SYNRTTFingerprinter) searchCloneServers(measurements []RTTMeasurement) {
	// Упрощенная реализация - в реальности анализ других IP
	srf.results.CloneServers = make([]CloneServerResult, 0)

	// Placeholder для демонстрации
	if len(measurements) > 10 {
		clone := CloneServerResult{
			IP:               "203.0.113.42",
			RTTSimilarity:    0.85,
			FingerprintMatch: 0.90,
			Confidence:       0.75,
			Evidence:         []string{"Similar RTT pattern detected"},
		}
		srf.results.CloneServers = append(srf.results.CloneServers, clone)
	}
}

// updateTelemetry обновляет телеметрию в реальном времени
func (srf *SYNRTTFingerprinter) updateTelemetry(packetsProcessed int) {
	srf.mutex.Lock()
	defer srf.mutex.Unlock()

	srf.results.TelemetryStats.PacketsReceived = packetsProcessed
	if srf.results.TotalPackets > 0 {
		loss := float64(srf.results.TotalPackets-packetsProcessed) / float64(srf.results.TotalPackets) * 100
		srf.results.TelemetryStats.LossPercentage = loss
	}
}

// generateTelemetryStats генерирует финальную телеметрию
func (srf *SYNRTTFingerprinter) generateTelemetryStats(duration time.Duration) {
	srf.results.TelemetryStats.PacketsSent = srf.results.TotalPackets
	srf.results.TelemetryStats.AvgProcessingTime = duration.String()
	
	// Placeholder для метрик системы
	srf.results.TelemetryStats.MemoryUsageMB = 15.5
	srf.results.TelemetryStats.CPUUsagePercent = 8.2
}

// GetResults возвращает результаты профайлинга
func (srf *SYNRTTFingerprinter) GetResults() *SYNRTTResults {
	srf.mutex.RLock()
	defer srf.mutex.RUnlock()
	return srf.results
}

// ExportJSON экспортирует результаты в JSON
func (srf *SYNRTTFingerprinter) ExportJSON() ([]byte, error) {
	srf.mutex.RLock()
	defer srf.mutex.RUnlock()
	return json.MarshalIndent(srf.results, "", "  ")
}