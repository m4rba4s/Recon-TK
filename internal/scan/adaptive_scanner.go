package scan

import (
	"context"
	"fmt"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type AdaptiveScanner struct {
	logger           *zap.Logger
	minThreads       int
	maxThreads       int
	currentThreads   int64
	rttTracker       *RTTTracker
	packetLossTracker *PacketLossTracker
	adaptationMutex  sync.RWMutex
	semaphore        chan struct{}
	statsCollector   *ScannerStats
}

type RTTTracker struct {
	samples      []time.Duration
	ewmaRTT      time.Duration
	ewmaVariance time.Duration
	alpha        float64
	mutex        sync.RWMutex
}

type PacketLossTracker struct {
	totalAttempts int64
	lostPackets   int64
	lossRate      float64
	mutex         sync.RWMutex
}

type ScannerStats struct {
	TotalScans       int64         `json:"total_scans"`
	SuccessfulScans  int64         `json:"successful_scans"`
	AverageRTT       time.Duration `json:"average_rtt"`
	PacketLossRate   float64       `json:"packet_loss_rate"`
	ThreadAdjustments int64        `json:"thread_adjustments"`
	LastOptimization time.Time     `json:"last_optimization"`
}

type AdaptiveScanResult struct {
	Target           string              `json:"target"`
	PortResults      []AdaptivePortResult `json:"port_results"`
	FinalThreadCount int                 `json:"final_thread_count"`
	OptimizationLog  []ThreadAdjustment  `json:"optimization_log"`
	PerformanceStats *ScannerStats       `json:"performance_stats"`
	ExecutionTime    time.Duration       `json:"execution_time"`
}

type AdaptivePortResult struct {
	Port         int           `json:"port"`
	Status       string        `json:"status"`
	RTT          time.Duration `json:"rtt"`
	ThreadCount  int           `json:"thread_count_when_scanned"`
	Attempt      int           `json:"attempt_number"`
}

type ThreadAdjustment struct {
	Timestamp    time.Time     `json:"timestamp"`
	OldThreads   int           `json:"old_threads"`
	NewThreads   int           `json:"new_threads"`
	Reason       string        `json:"reason"`
	RTT          time.Duration `json:"current_rtt"`
	PacketLoss   float64       `json:"packet_loss"`
}

func NewAdaptiveScanner(logger *zap.Logger, minThreads, maxThreads int) *AdaptiveScanner {
	startThreads := (minThreads + maxThreads) / 2
	
	return &AdaptiveScanner{
		logger:           logger,
		minThreads:       minThreads,
		maxThreads:       maxThreads,
		currentThreads:   int64(startThreads),
		rttTracker:       NewRTTTracker(),
		packetLossTracker: NewPacketLossTracker(),
		semaphore:        make(chan struct{}, startThreads),
		statsCollector:   &ScannerStats{},
	}
}

func NewRTTTracker() *RTTTracker {
	return &RTTTracker{
		samples:      make([]time.Duration, 0, 100),
		ewmaRTT:      100 * time.Millisecond, // Initial estimate
		ewmaVariance: 50 * time.Millisecond,  // Initial variance
		alpha:        0.125,                   // Standard TCP alpha
	}
}

func NewPacketLossTracker() *PacketLossTracker {
	return &PacketLossTracker{
		totalAttempts: 0,
		lostPackets:   0,
		lossRate:      0.0,
	}
}

func (as *AdaptiveScanner) ScanAdaptive(ctx context.Context, target string, ports []int) (*AdaptiveScanResult, error) {
	startTime := time.Now()
	
	as.logger.Info("Starting adaptive scan with dynamic thread adjustment",
		zap.String("target", target),
		zap.Int("ports", len(ports)),
		zap.Int("initial_threads", int(atomic.LoadInt64(&as.currentThreads))))

	result := &AdaptiveScanResult{
		Target:          target,
		PortResults:     make([]AdaptivePortResult, 0, len(ports)),
		OptimizationLog: make([]ThreadAdjustment, 0),
		PerformanceStats: as.statsCollector,
	}

	// Initialize semaphore with current thread count
	as.adjustSemaphore(int(atomic.LoadInt64(&as.currentThreads)))

	var wg sync.WaitGroup
	var resultsMutex sync.Mutex
	
	// Start optimization routine
	optimizationCtx, cancelOptimization := context.WithCancel(ctx)
	defer cancelOptimization()
	
	go as.continuousOptimization(optimizationCtx, result)

	// Scan ports with adaptive threading
	for i, port := range ports {
		wg.Add(1)
		
		go func(portNum, index int) {
			defer wg.Done()
			
			// Wait for semaphore slot
			as.semaphore <- struct{}{}
			defer func() { <-as.semaphore }()
			
			portResult := as.scanPortWithMetrics(ctx, target, portNum, index)
			
			resultsMutex.Lock()
			result.PortResults = append(result.PortResults, portResult)
			resultsMutex.Unlock()
			
			// Trigger adaptation check every 10 ports
			if index%10 == 0 {
				as.considerAdaptation(result)
			}
		}(port, i)
		
		// Small delay to prevent overwhelming
		time.Sleep(time.Millisecond * 10)
	}

	wg.Wait()
	result.ExecutionTime = time.Since(startTime)
	result.FinalThreadCount = int(atomic.LoadInt64(&as.currentThreads))

	as.logger.Info("Adaptive scan completed",
		zap.Duration("execution_time", result.ExecutionTime),
		zap.Int("final_threads", result.FinalThreadCount),
		zap.Int("adjustments", len(result.OptimizationLog)))

	return result, nil
}

func (as *AdaptiveScanner) scanPortWithMetrics(ctx context.Context, target string, port, attempt int) AdaptivePortResult {
	startTime := time.Now()
	
	atomic.AddInt64(&as.statsCollector.TotalScans, 1)
	atomic.AddInt64(&as.packetLossTracker.totalAttempts, 1)
	
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 3*time.Second)
	rtt := time.Since(startTime)
	
	result := AdaptivePortResult{
		Port:        port,
		RTT:         rtt,
		ThreadCount: int(atomic.LoadInt64(&as.currentThreads)),
		Attempt:     attempt,
	}
	
	if err != nil {
		if isTimeoutError(err) {
			result.Status = "filtered"
			atomic.AddInt64(&as.packetLossTracker.lostPackets, 1)
		} else {
			result.Status = "closed"
		}
	} else {
		conn.Close()
		result.Status = "open"
		atomic.AddInt64(&as.statsCollector.SuccessfulScans, 1)
	}
	
	// Update RTT tracking
	as.rttTracker.AddSample(rtt)
	
	// Update packet loss
	as.packetLossTracker.UpdateLossRate()
	
	return result
}

func (as *AdaptiveScanner) continuousOptimization(ctx context.Context, result *AdaptiveScanResult) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			as.considerAdaptation(result)
		}
	}
}

func (as *AdaptiveScanner) considerAdaptation(result *AdaptiveScanResult) {
	as.adaptationMutex.Lock()
	defer as.adaptationMutex.Unlock()
	
	currentThreads := int(atomic.LoadInt64(&as.currentThreads))
	currentRTT := as.rttTracker.GetEWMARTT()
	packetLoss := as.packetLossTracker.GetLossRate()
	
	var newThreads int
	var reason string
	
	// Decision matrix for thread adjustment
	switch {
	case packetLoss > 0.1: // >10% packet loss
		newThreads = max(as.minThreads, int(float64(currentThreads)*0.7))
		reason = "High packet loss detected"
		
	case currentRTT > 2*time.Second:
		newThreads = max(as.minThreads, int(float64(currentThreads)*0.8))
		reason = "High RTT detected"
		
	case currentRTT < 50*time.Millisecond && packetLoss < 0.01:
		newThreads = min(as.maxThreads, int(float64(currentThreads)*1.3))
		reason = "Low latency, low loss - increasing threads"
		
	case packetLoss < 0.02 && currentRTT < 200*time.Millisecond:
		newThreads = min(as.maxThreads, currentThreads+10)
		reason = "Good performance - gradual increase"
		
	default:
		return // No adjustment needed
	}
	
	if newThreads != currentThreads {
		adjustment := ThreadAdjustment{
			Timestamp:  time.Now(),
			OldThreads: currentThreads,
			NewThreads: newThreads,
			Reason:     reason,
			RTT:        currentRTT,
			PacketLoss: packetLoss,
		}
		
		result.OptimizationLog = append(result.OptimizationLog, adjustment)
		
		atomic.StoreInt64(&as.currentThreads, int64(newThreads))
		atomic.AddInt64(&as.statsCollector.ThreadAdjustments, 1)
		as.statsCollector.LastOptimization = time.Now()
		
		as.adjustSemaphore(newThreads)
		
		// VERBOSE EWMA LOGGING: Show detailed RTT adaptation in debug mode
		direction := "→"
		if newThreads > currentThreads {
			direction = "↑"
		} else if newThreads < currentThreads {
			direction = "↓"
		}
		
		// Always log INFO level for thread changes
		as.logger.Info("EWMA Thread Adaptation",
			zap.String("change", direction),
			zap.Duration("rtt", currentRTT),
			zap.Float64("loss", packetLoss),
			zap.Int("threads_old", currentThreads),
			zap.Int("threads_new", newThreads),
			zap.String("reason", reason))
		
		// Additional detailed performance monitoring for debug mode
		as.logger.Debug("Detailed Performance Stats",
			zap.Duration("ewma_rtt", as.rttTracker.GetEWMARTT()),
			zap.Duration("rtt_variance", as.rttTracker.GetVariance()),
			zap.Float64("packet_loss_rate", as.packetLossTracker.GetLossRate()),
			zap.Int64("total_scans", atomic.LoadInt64(&as.statsCollector.TotalScans)),
			zap.Int64("successful_scans", atomic.LoadInt64(&as.statsCollector.SuccessfulScans)))
		
		// Every adjustment trigger creates a debug log entry
		as.logger.Debug("EWMA Calculation Details",
			zap.Float64("alpha", as.rttTracker.alpha),
			zap.Int("sample_count", len(as.rttTracker.samples)),
			zap.String("adaptation_trigger", getAdaptationTrigger(currentRTT, packetLoss, currentThreads)))
	}
}

func (as *AdaptiveScanner) adjustSemaphore(newSize int) {
	currentSize := cap(as.semaphore)
	
	if newSize == currentSize {
		return
	}
	
	// Create new semaphore with new size
	newSemaphore := make(chan struct{}, newSize)
	
	// Drain old semaphore
	oldSemaphore := as.semaphore
	as.semaphore = newSemaphore
	
	// Transfer existing permits
	go func() {
		transferred := 0
		for transferred < min(currentSize, newSize) {
			select {
			case <-oldSemaphore:
				transferred++
			case newSemaphore <- struct{}{}:
				// Permit transferred
			default:
				return
			}
		}
	}()
}

func (rtt *RTTTracker) AddSample(sample time.Duration) {
	rtt.mutex.Lock()
	defer rtt.mutex.Unlock()
	
	rtt.samples = append(rtt.samples, sample)
	
	// Keep only last 100 samples
	if len(rtt.samples) > 100 {
		rtt.samples = rtt.samples[1:]
	}
	
	// Update EWMA
	if rtt.ewmaRTT == 0 {
		rtt.ewmaRTT = sample
	} else {
		diff := sample - rtt.ewmaRTT
		rtt.ewmaRTT += time.Duration(float64(diff) * rtt.alpha)
		
		// Update variance
		variance := time.Duration(math.Abs(float64(diff)))
		rtt.ewmaVariance += time.Duration(float64(variance-rtt.ewmaVariance) * rtt.alpha)
	}
}

func (rtt *RTTTracker) GetEWMARTT() time.Duration {
	rtt.mutex.RLock()
	defer rtt.mutex.RUnlock()
	return rtt.ewmaRTT
}

func (rtt *RTTTracker) GetVariance() time.Duration {
	rtt.mutex.RLock()
	defer rtt.mutex.RUnlock()
	return rtt.ewmaVariance
}

func (plt *PacketLossTracker) UpdateLossRate() {
	plt.mutex.Lock()
	defer plt.mutex.Unlock()
	
	if plt.totalAttempts > 0 {
		plt.lossRate = float64(plt.lostPackets) / float64(plt.totalAttempts)
	}
}

func (plt *PacketLossTracker) GetLossRate() float64 {
	plt.mutex.RLock()
	defer plt.mutex.RUnlock()
	return plt.lossRate
}

func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func getAdaptationTrigger(rtt time.Duration, loss float64, threads int) string {
	if loss > 0.1 {
		return fmt.Sprintf("high_packet_loss_%.1f%%", loss*100)
	} else if rtt > 2*time.Second {
		return fmt.Sprintf("high_rtt_%dms", rtt.Milliseconds())
	} else if rtt < 50*time.Millisecond && loss < 0.01 {
		return fmt.Sprintf("optimal_conditions_rtt_%dms_loss_%.1f%%", rtt.Milliseconds(), loss*100)
	} else if rtt < 200*time.Millisecond && loss < 0.02 {
		return fmt.Sprintf("good_performance_gradual_increase")
	}
	return "no_adaptation_needed"
}