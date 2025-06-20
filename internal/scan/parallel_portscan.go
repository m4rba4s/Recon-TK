package scan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ParallelPortScanner - параллельный сканер портов с timeout 1s
type ParallelPortScanner struct {
	logger      *zap.Logger
	concurrency int
	timeout     time.Duration
}

// PortResult - результат сканирования порта
type PortResult struct {
	Port         int           `json:"port"`
	Protocol     string        `json:"protocol"`
	Status       string        `json:"status"`       // open, closed, filtered, error
	ResponseTime time.Duration `json:"response_time"`
	Error        string        `json:"error,omitempty"`
	Banner       string        `json:"banner,omitempty"`
}

// ScanResults - результаты сканирования всех портов
type ScanResults struct {
	Target        string        `json:"target"`
	TotalPorts    int           `json:"total_ports"`
	OpenPorts     int           `json:"open_ports"`
	ClosedPorts   int           `json:"closed_ports"`
	FilteredPorts int           `json:"filtered_ports"`
	TotalTime     time.Duration `json:"total_time"`
	Results       []PortResult  `json:"results"`
}

// NewParallelPortScanner создает новый параллельный сканер
func NewParallelPortScanner(logger *zap.Logger) *ParallelPortScanner {
	return &ParallelPortScanner{
		logger:      logger,
		concurrency: 100, // Высокая параллельность для скорости
		timeout:     1 * time.Second, // Агрессивный timeout
	}
}

// ScanCommonPorts - быстрое сканирование основных портов
func (pps *ParallelPortScanner) ScanCommonPorts(ctx context.Context, target string) (*ScanResults, error) {
	commonPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080,
	}
	
	return pps.ScanPorts(ctx, target, commonPorts)
}

// ScanBasicPorts - сканирование базовых портов для connectivity test
func (pps *ParallelPortScanner) ScanBasicPorts(ctx context.Context, target string) (*ScanResults, error) {
	basicPorts := []int{22, 53, 80, 443}
	return pps.ScanPorts(ctx, target, basicPorts)
}

// ScanPorts - основной метод сканирования портов
func (pps *ParallelPortScanner) ScanPorts(ctx context.Context, target string, ports []int) (*ScanResults, error) {
	start := time.Now()
	
	pps.logger.Info("🚀 Starting parallel port scan", 
		zap.String("target", target),
		zap.Int("ports", len(ports)),
		zap.Int("concurrency", pps.concurrency),
		zap.Duration("timeout", pps.timeout))

	results := &ScanResults{
		Target:     target,
		TotalPorts: len(ports),
		Results:    make([]PortResult, 0, len(ports)),
	}

	// Канал для ограничения параллельности
	semaphore := make(chan struct{}, pps.concurrency)
	resultsChan := make(chan PortResult, len(ports))
	
	var wg sync.WaitGroup

	// Запускаем горутины для каждого порта
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			
			// Ограничиваем параллельность
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			result := pps.scanSinglePort(ctx, target, p)
			resultsChan <- result
		}(port)
	}

	// Ждем завершения всех горутин
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Собираем результаты
	for result := range resultsChan {
		results.Results = append(results.Results, result)
		
		switch result.Status {
		case "open":
			results.OpenPorts++
		case "closed":
			results.ClosedPorts++
		case "filtered":
			results.FilteredPorts++
		}
	}

	results.TotalTime = time.Since(start)
	
	pps.logger.Info("✅ Parallel port scan completed",
		zap.Duration("total_time", results.TotalTime),
		zap.Int("open_ports", results.OpenPorts),
		zap.Int("closed_ports", results.ClosedPorts),
		zap.Int("filtered_ports", results.FilteredPorts))

	return results, nil
}

// scanSinglePort - сканирование одного порта
func (pps *ParallelPortScanner) scanSinglePort(ctx context.Context, target string, port int) PortResult {
	start := time.Now()
	
	result := PortResult{
		Port:     port,
		Protocol: "tcp",
	}

	// Создаем контекст с timeout
	scanCtx, cancel := context.WithTimeout(ctx, pps.timeout)
	defer cancel()

	// Используем DialContext для точного контроля timeout
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(scanCtx, "tcp", fmt.Sprintf("%s:%d", target, port))
	
	result.ResponseTime = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		
		// Определяем тип ошибки для точной классификации
		if isTimeoutError(err) {
			result.Status = "filtered" // timeout = filtered
			pps.logger.Debug("Port filtered (timeout)", 
				zap.String("target", target), 
				zap.Int("port", port),
				zap.Duration("response_time", result.ResponseTime))
		} else if isConnectionRefused(err) {
			result.Status = "closed" // connection refused = closed
			pps.logger.Debug("Port closed (refused)", 
				zap.String("target", target), 
				zap.Int("port", port),
				zap.Duration("response_time", result.ResponseTime))
		} else {
			result.Status = "error" // other errors
			pps.logger.Debug("Port scan error", 
				zap.String("target", target), 
				zap.Int("port", port),
				zap.Error(err))
		}
		return result
	}

	// Соединение успешно - порт открыт
	defer conn.Close()
	result.Status = "open"
	
	// Попытка получить banner (быстро)
	if banner := pps.grabBanner(conn, port); banner != "" {
		result.Banner = banner
	}

	pps.logger.Debug("Port open", 
		zap.String("target", target), 
		zap.Int("port", port),
		zap.Duration("response_time", result.ResponseTime),
		zap.String("banner", result.Banner))

	return result
}

// grabBanner - быстрое получение banner
func (pps *ParallelPortScanner) grabBanner(conn net.Conn, port int) string {
	// Устанавливаем короткий timeout для banner grabbing
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	
	// Для некоторых протоколов отправляем probe
	switch port {
	case 22:
		// SSH banner обычно приходит сразу
		buffer := make([]byte, 1024)
		n, _ := conn.Read(buffer)
		if n > 0 {
			return string(buffer[:n])
		}
	case 21:
		// FTP banner
		buffer := make([]byte, 1024)
		n, _ := conn.Read(buffer)
		if n > 0 {
			return string(buffer[:n])
		}
	case 80, 8080:
		// HTTP probe
		conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
		buffer := make([]byte, 1024)
		n, _ := conn.Read(buffer)
		if n > 0 {
			return string(buffer[:n])
		}
	case 443:
		// Для HTTPS не делаем probe из-за TLS handshake
		return "HTTPS/TLS"
	}
	
	return ""
}

// isTimeoutError - проверка на timeout ошибку
func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	// Дополнительные проверки для различных типов timeout
	errStr := err.Error()
	return strings.Contains(errStr, "timeout") || 
		   strings.Contains(errStr, "i/o timeout") ||
		   strings.Contains(errStr, "deadline exceeded")
}

// isConnectionRefused - проверка на connection refused
func isConnectionRefused(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "connection refused") ||
		   strings.Contains(errStr, "connect: connection refused")
}

// GetOpenPorts - получение списка открытых портов
func (sr *ScanResults) GetOpenPorts() []int {
	var openPorts []int
	for _, result := range sr.Results {
		if result.Status == "open" {
			openPorts = append(openPorts, result.Port)
		}
	}
	return openPorts
}

// GetClosedPorts - получение списка закрытых портов  
func (sr *ScanResults) GetClosedPorts() []int {
	var closedPorts []int
	for _, result := range sr.Results {
		if result.Status == "closed" {
			closedPorts = append(closedPorts, result.Port)
		}
	}
	return closedPorts
}

// GetFilteredPorts - получение списка фильтруемых портов
func (sr *ScanResults) GetFilteredPorts() []int {
	var filteredPorts []int
	for _, result := range sr.Results {
		if result.Status == "filtered" {
			filteredPorts = append(filteredPorts, result.Port)
		}
	}
	return filteredPorts
}

// Summary - краткое резюме сканирования
func (sr *ScanResults) Summary() string {
	return fmt.Sprintf("Target: %s | Total: %d | Open: %d | Closed: %d | Filtered: %d | Time: %v",
		sr.Target, sr.TotalPorts, sr.OpenPorts, sr.ClosedPorts, sr.FilteredPorts, sr.TotalTime)
}