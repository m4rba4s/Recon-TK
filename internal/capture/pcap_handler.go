package capture

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"go.uber.org/zap"
)

type PcapHandler struct {
	logger      *zap.Logger
	outputDir   string
	handle      *pcap.Handle
	writer      *pcapgo.Writer
	file        *os.File
	enabled     bool
	sessionID   string
	packetCount int64
	bytesWritten int64
	maxFileSize int64
}

type CaptureConfig struct {
	Interface    string
	SnapLength   int32
	Promiscuous  bool
	Timeout      time.Duration
	Filter       string
	OutputDir    string
	SessionID    string
	MaxFileSize  int64  // Maximum file size in bytes
}

func NewPcapHandler(logger *zap.Logger, config *CaptureConfig) *PcapHandler {
	return &PcapHandler{
		logger:      logger,
		outputDir:   config.OutputDir,
		sessionID:   config.SessionID,
		enabled:     true,
		maxFileSize: config.MaxFileSize,
	}
}

func (ph *PcapHandler) StartCapture(ctx context.Context, config *CaptureConfig) error {
	if !ph.enabled {
		return nil
	}

	ph.logger.Info("Starting PCAP capture",
		zap.String("interface", config.Interface),
		zap.String("session_id", ph.sessionID))

	// Create output directory
	pcapDir := filepath.Join(ph.outputDir, "pcap")
	if err := os.MkdirAll(pcapDir, 0755); err != nil {
		return fmt.Errorf("failed to create pcap directory: %w", err)
	}

	// Open network interface
	handle, err := pcap.OpenLive(
		config.Interface,
		config.SnapLength,
		config.Promiscuous,
		config.Timeout,
	)
	if err != nil {
		ph.logger.Warn("Failed to open interface, trying any available interface", 
			zap.Error(err))
		
		// Try to find any available interface
		devices, err := pcap.FindAllDevs()
		if err != nil || len(devices) == 0 {
			return fmt.Errorf("no network interfaces found: %w", err)
		}
		
		// Use first available interface
		config.Interface = devices[0].Name
		handle, err = pcap.OpenLive(
			config.Interface,
			config.SnapLength,
			config.Promiscuous,
			config.Timeout,
		)
		if err != nil {
			return fmt.Errorf("failed to open any interface: %w", err)
		}
	}

	ph.handle = handle

	// Set BPF filter if provided
	if config.Filter != "" {
		if err := ph.handle.SetBPFFilter(config.Filter); err != nil {
			ph.logger.Warn("Failed to set BPF filter", zap.Error(err))
		} else {
			ph.logger.Info("BPF filter applied", zap.String("filter", config.Filter))
		}
	}

	// Create output file
	filename := fmt.Sprintf("rtk_capture_%s_%d.pcap", 
		ph.sessionID, time.Now().Unix())
	filepath := filepath.Join(pcapDir, filename)
	
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create pcap file: %w", err)
	}
	ph.file = file

	// Create pcap writer
	ph.writer = pcapgo.NewWriter(file)
	if err := ph.writer.WriteFileHeader(uint32(config.SnapLength), layers.LinkTypeEthernet); err != nil {
		return fmt.Errorf("failed to write pcap header: %w", err)
	}

	ph.logger.Info("PCAP capture started",
		zap.String("interface", config.Interface),
		zap.String("output_file", filepath))

	// Start capture goroutine
	go ph.captureLoop(ctx)

	return nil
}

func (ph *PcapHandler) captureLoop(ctx context.Context) {
	packetSource := gopacket.NewPacketSource(ph.handle, ph.handle.LinkType())
	packetChan := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			ph.logger.Info("PCAP capture stopped", 
				zap.Int64("packets_captured", ph.packetCount))
			return
		case packet := <-packetChan:
			if packet == nil {
				continue
			}
			
			if err := ph.writePacket(packet); err != nil {
				ph.logger.Error("Failed to write packet", zap.Error(err))
			}
			ph.packetCount++
		}
	}
}

func (ph *PcapHandler) writePacket(packet gopacket.Packet) error {
	// Check file size limit
	if ph.maxFileSize > 0 && ph.bytesWritten >= ph.maxFileSize {
		ph.logger.Warn("PCAP file size limit reached, stopping capture",
			zap.Int64("bytes_written", ph.bytesWritten),
			zap.Int64("max_size", ph.maxFileSize))
		return fmt.Errorf("file size limit reached")
	}
	
	err := ph.writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	if err == nil {
		ph.bytesWritten += int64(len(packet.Data()))
	}
	return err
}

func (ph *PcapHandler) StopCapture() error {
	if !ph.enabled || ph.handle == nil {
		return nil
	}

	ph.logger.Info("Stopping PCAP capture",
		zap.Int64("total_packets", ph.packetCount))

	ph.handle.Close()
	
	if ph.file != nil {
		if err := ph.file.Close(); err != nil {
			return fmt.Errorf("failed to close pcap file: %w", err)
		}
	}

	return nil
}

func (ph *PcapHandler) GetStats() (int64, error) {
	if !ph.enabled || ph.handle == nil {
		return 0, nil
	}

	stats, err := ph.handle.Stats()
	if err != nil {
		return ph.packetCount, err
	}

	ph.logger.Info("PCAP capture statistics",
		zap.Int64("packets_captured", ph.packetCount),
		zap.Int("packets_received", stats.PacketsReceived),
		zap.Int("packets_dropped", stats.PacketsDropped))

	return ph.packetCount, nil
}

func (ph *PcapHandler) SetEnabled(enabled bool) {
	ph.enabled = enabled
}

func GetDefaultInterface() (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}

	// Look for first non-loopback interface with an address
	for _, device := range devices {
		if len(device.Addresses) > 0 && device.Name != "lo" {
			return device.Name, nil
		}
	}

	// Fallback to first available interface
	if len(devices) > 0 {
		return devices[0].Name, nil
	}

	return "", fmt.Errorf("no network interfaces found")
}

func GenerateBPFFilter(target string, ports []int) string {
	if target == "" && len(ports) == 0 {
		return ""
	}

	var filters []string

	// Add host filter
	if target != "" {
		filters = append(filters, fmt.Sprintf("host %s", target))
	}

	// Add port filters
	if len(ports) > 0 {
		portFilter := "port "
		for i, port := range ports {
			if i > 0 {
				portFilter += " or port "
			}
			portFilter += fmt.Sprintf("%d", port)
		}
		filters = append(filters, fmt.Sprintf("(%s)", portFilter))
	}

	if len(filters) == 0 {
		return ""
	}

	result := filters[0]
	for i := 1; i < len(filters); i++ {
		result += " and " + filters[i]
	}

	return result
}

func (ph *PcapHandler) AnalyzeCapture(pcapFile string) (*CaptureAnalysis, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file: %w", err)
	}
	defer handle.Close()

	analysis := &CaptureAnalysis{
		Filename:       pcapFile,
		TotalPackets:   0,
		ProtocolStats:  make(map[string]int),
		PortStats:      make(map[int]int),
		TimeRange:      TimeRange{},
		SuspiciousFlow: make([]SuspiciousFlow, 0),
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	for packet := range packetSource.Packets() {
		analysis.TotalPackets++
		
		// Update time range
		timestamp := packet.Metadata().Timestamp
		if analysis.TimeRange.Start.IsZero() || timestamp.Before(analysis.TimeRange.Start) {
			analysis.TimeRange.Start = timestamp
		}
		if timestamp.After(analysis.TimeRange.End) {
			analysis.TimeRange.End = timestamp
		}

		// Analyze layers
		ph.analyzePacketLayers(packet, analysis)
	}

	analysis.Duration = analysis.TimeRange.End.Sub(analysis.TimeRange.Start)
	
	ph.logger.Info("PCAP analysis completed",
		zap.String("file", pcapFile),
		zap.Int64("packets", analysis.TotalPackets),
		zap.Duration("duration", analysis.Duration))

	return analysis, nil
}

func (ph *PcapHandler) analyzePacketLayers(packet gopacket.Packet, analysis *CaptureAnalysis) {
	// TCP layer analysis
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		analysis.ProtocolStats["TCP"]++
		analysis.PortStats[int(tcp.DstPort)]++
		analysis.PortStats[int(tcp.SrcPort)]++

		// Detect potential suspicious patterns
		if tcp.RST && tcp.ACK {
			analysis.SuspiciousFlow = append(analysis.SuspiciousFlow, SuspiciousFlow{
				Type:        "TCP_RST",
				Timestamp:   packet.Metadata().Timestamp,
				Description: fmt.Sprintf("TCP RST from %s:%d", tcp.SrcPort, tcp.DstPort),
			})
		}
	}

	// UDP layer analysis
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		analysis.ProtocolStats["UDP"]++
		analysis.PortStats[int(udp.DstPort)]++
		analysis.PortStats[int(udp.SrcPort)]++
	}

	// HTTP layer analysis
	if httpLayer := packet.Layer(layers.LayerTypeTCP); httpLayer != nil {
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload := string(appLayer.Payload())
			if isHTTPTraffic(payload) {
				analysis.ProtocolStats["HTTP"]++
				
				// Detect potential attack patterns
				if containsSuspiciousHTTP(payload) {
					analysis.SuspiciousFlow = append(analysis.SuspiciousFlow, SuspiciousFlow{
						Type:        "SUSPICIOUS_HTTP",
						Timestamp:   packet.Metadata().Timestamp,
						Description: "Potential attack pattern in HTTP traffic",
					})
				}
			}
		}
	}
}

type CaptureAnalysis struct {
	Filename       string                 `json:"filename"`
	TotalPackets   int64                  `json:"total_packets"`
	Duration       time.Duration          `json:"duration"`
	ProtocolStats  map[string]int         `json:"protocol_stats"`
	PortStats      map[int]int            `json:"port_stats"`
	TimeRange      TimeRange              `json:"time_range"`
	SuspiciousFlow []SuspiciousFlow       `json:"suspicious_flows"`
}

type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

type SuspiciousFlow struct {
	Type        string    `json:"type"`
	Timestamp   time.Time `json:"timestamp"`
	Description string    `json:"description"`
}

func isHTTPTraffic(payload string) bool {
	httpMethods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS "}
	httpResponses := []string{"HTTP/1.0 ", "HTTP/1.1 ", "HTTP/2.0 "}
	
	for _, method := range httpMethods {
		if len(payload) > len(method) && payload[:len(method)] == method {
			return true
		}
	}
	
	for _, response := range httpResponses {
		if len(payload) > len(response) && payload[:len(response)] == response {
			return true
		}
	}
	
	return false
}

func containsSuspiciousHTTP(payload string) bool {
	suspiciousPatterns := []string{
		"../", "..\\", "/etc/passwd", "/etc/shadow",
		"<script", "javascript:", "eval(",
		"union select", "1' or '1'='1",
		"cmd.exe", "/bin/sh", "whoami",
	}
	
	for _, pattern := range suspiciousPatterns {
		if len(payload) > 100 && // Only check reasonably sized payloads
		   len(payload) < 10000 &&
		   containsIgnoreCase(payload, pattern) {
			return true
		}
	}
	
	return false
}

func containsIgnoreCase(text, substr string) bool {
	return len(text) >= len(substr) && 
		   string([]rune(text)[:len([]rune(substr))]) == substr ||
		   (len(text) > len(substr) && containsIgnoreCase(text[1:], substr))
}