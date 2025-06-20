package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"recon-toolkit/internal/capture"
)

var (
	pcapOutput     string
	pcapAnalyze    string
	pcapFilter     string
	pcapSnaplen    int32
	pcapTimeout    int
	pcapDuration   int
)

var pcapCmd = &cobra.Command{
	Use:   "pcap",
	Short: "Network traffic capture and analysis",
	Long: `Capture and analyze network traffic during security assessments.

PCAP capture provides deep visibility into network communications,
allowing security professionals to:
- Monitor attack traffic in real-time
- Analyze protocol anomalies and bypasses
- Debug complex network-based exploits
- Generate forensic evidence
- Validate security controls

Features:
- Real-time packet capture with BPF filtering
- Automatic protocol analysis (TCP/UDP/HTTP)
- Suspicious traffic pattern detection
- Integration with RTK Elite scanning modules
- Offline PCAP file analysis

Examples:
  rtk pcap capture --interface eth0 --duration 60
  rtk pcap capture --filter "host 192.168.1.100 and port 80"
  rtk pcap analyze --file capture.pcap
  rtk pcap capture --output /tmp/scan_traffic.pcap`,
}

var pcapCaptureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Start live packet capture",
	Long: `Start capturing network packets on the specified interface.

Captures all network traffic matching the optional BPF filter.
Useful for monitoring attack traffic, debugging exploits, and
generating forensic evidence during security assessments.

The capture automatically detects suspicious patterns including:
- TCP RST injection attempts
- HTTP attack payloads (SQLi, XSS, etc.)
- Port scanning patterns
- Protocol anomalies

Requires root privileges or CAP_NET_RAW capability.`,
	RunE: runPcapCapture,
}

var pcapAnalyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze captured PCAP file",
	Long: `Analyze a previously captured PCAP file for security insights.

Performs comprehensive analysis including:
- Protocol distribution statistics
- Port usage patterns
- Suspicious traffic identification
- Timeline analysis
- Attack pattern detection

Generates detailed reports suitable for forensic analysis
and security assessment documentation.`,
	RunE: runPcapAnalyze,
}

func init() {
	rootCmd.AddCommand(pcapCmd)
	pcapCmd.AddCommand(pcapCaptureCmd)
	pcapCmd.AddCommand(pcapAnalyzeCmd)

	// Capture command flags
	pcapCaptureCmd.Flags().StringVarP(&pcapOutput, "output", "o", "", 
		"Output PCAP file (auto-generated if not specified)")
	pcapCaptureCmd.Flags().StringVar(&pcapFilter, "filter", "", 
		"BPF filter expression (e.g., 'host 192.168.1.1 and port 80')")
	pcapCaptureCmd.Flags().StringVar(&pcapInterface, "interface", "", 
		"Network interface to capture on (auto-detect if empty)")
	pcapCaptureCmd.Flags().Int32Var(&pcapSnaplen, "snaplen", 65536, 
		"Snapshot length for packet capture")
	pcapCaptureCmd.Flags().IntVar(&pcapTimeout, "timeout", 30, 
		"Read timeout in milliseconds")
	pcapCaptureCmd.Flags().IntVar(&pcapDuration, "duration", 0, 
		"Capture duration in seconds (0 = indefinite)")

	// Analyze command flags
	pcapAnalyzeCmd.Flags().StringVar(&pcapAnalyze, "file", "", 
		"PCAP file to analyze (required)")
	pcapAnalyzeCmd.Flags().StringVarP(&pcapOutput, "output", "o", "", 
		"Output analysis report file")

	pcapAnalyzeCmd.MarkFlagRequired("file")
}

func runPcapCapture(cmd *cobra.Command, args []string) error {
	// Dry run check
	if dryRun {
		fmt.Printf("🧪 DRY RUN: PCAP Capture Configuration\n")
		fmt.Printf("═══════════════════════════════════════════════════════════\n\n")
		
		iface := pcapInterface
		if iface == "" {
			var err error
			iface, err = capture.GetDefaultInterface()
			if err != nil {
				iface = "auto-detect-failed"
			}
		}
		
		fmt.Printf("Would capture on interface: %s\n", iface)
		if pcapFilter != "" {
			fmt.Printf("Would apply BPF filter: %s\n", pcapFilter)
		} else {
			fmt.Printf("⚠️  No BPF filter specified - would capture ALL traffic\n")
		}
		
		maxSize := parseMaxSize(pcapMaxSize)
		if maxSize > 0 {
			fmt.Printf("Would limit file size to: %s\n", formatBytes(maxSize))
		} else {
			fmt.Printf("⚠️  No file size limit - could consume all disk space\n")
		}
		
		if pcapDuration > 0 {
			fmt.Printf("Would capture for: %d seconds\n", pcapDuration)
		} else {
			fmt.Printf("Would capture indefinitely until stopped\n")
		}
		
		fmt.Printf("\n✅ Dry run complete - no traffic captured\n")
		return nil
	}
	fmt.Printf("🔍 RTK Elite Network Capture\n")
	fmt.Printf("═══════════════════════════════════════════════════════════\n\n")

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Auto-detect interface if not specified
	if pcapInterface == "" {
		var err error
		pcapInterface, err = capture.GetDefaultInterface()
		if err != nil {
			return fmt.Errorf("failed to detect network interface: %w", err)
		}
		fmt.Printf("🔗 Auto-detected interface: %s\n", pcapInterface)
	}
	
	// Warn about promiscuous capture without filter
	if pcapFilter == "" {
		fmt.Printf("⚠️  WARNING: No BPF filter specified - capturing ALL network traffic\n")
		fmt.Printf("    Consider using --filter to limit capture scope\n")
		fmt.Printf("    Example: --filter \"host 192.168.1.100 and port 80\"\n\n")
	}
	
	// Generate safe default filter for target if available
	if pcapFilter == "" && target != "" {
		pcapFilter = capture.GenerateBPFFilter(target, []int{80, 443, 8080, 8443})
		fmt.Printf("🔍 Auto-generated BPF filter: %s\n", pcapFilter)
	}

	// Generate output filename if not specified
	if pcapOutput == "" {
		timestamp := time.Now().Format("20060102_150405")
		pcapOutput = fmt.Sprintf("rtk_capture_%s.pcap", timestamp)
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(pcapOutput)
	if outputDir == "." {
		outputDir = "runs"
	}
	
	sessionID := fmt.Sprintf("rtk_%d", time.Now().Unix())
	maxSize := parseMaxSize(pcapMaxSize)
	
	fmt.Printf("📁 Output directory: %s\n", outputDir)
	fmt.Printf("🏷️  Session ID: %s\n", sessionID)
	fmt.Printf("🖧  Interface: %s\n", pcapInterface)
	fmt.Printf("📏 Snap length: %d bytes\n", pcapSnaplen)
	
	if pcapFilter != "" {
		fmt.Printf("🔍 BPF filter: %s\n", pcapFilter)
	}
	
	if maxSize > 0 {
		fmt.Printf("📦 Max file size: %s\n", formatBytes(maxSize))
	} else {
		fmt.Printf("📦 Max file size: unlimited\n")
	}
	
	if pcapDuration > 0 {
		fmt.Printf("⏱️  Duration: %d seconds\n", pcapDuration)
	} else {
		fmt.Printf("⏱️  Duration: indefinite (Ctrl+C to stop)\n")
	}
	
	fmt.Println()

	// Create PCAP handler
	config := &capture.CaptureConfig{
		Interface:   pcapInterface,
		SnapLength:  pcapSnaplen,
		Promiscuous: true,
		Timeout:     time.Duration(pcapTimeout) * time.Millisecond,
		Filter:      pcapFilter,
		OutputDir:   outputDir,
		SessionID:   sessionID,
		MaxFileSize: maxSize,
	}

	handler := capture.NewPcapHandler(logger, config)

	// Create context with timeout if specified
	ctx := context.Background()
	if pcapDuration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(pcapDuration)*time.Second)
		defer cancel()
	}

	// Start capture
	fmt.Printf("🚀 Starting packet capture...\n")
	fmt.Printf("💡 Press Ctrl+C to stop capture\n\n")

	if err := handler.StartCapture(ctx, config); err != nil {
		return fmt.Errorf("failed to start capture: %w", err)
	}

	// Wait for context completion or signal
	<-ctx.Done()

	// Stop capture and get statistics
	if err := handler.StopCapture(); err != nil {
		logger.Error("Failed to stop capture cleanly", zap.Error(err))
	}

	packets, err := handler.GetStats()
	if err != nil {
		logger.Warn("Failed to get capture statistics", zap.Error(err))
	}

	fmt.Printf("\n✅ Capture completed\n")
	fmt.Printf("📊 Packets captured: %d\n", packets)
	fmt.Printf("💾 Output files saved in: %s/pcap/\n", outputDir)

	return nil
}

func runPcapAnalyze(cmd *cobra.Command, args []string) error {
	fmt.Printf("📊 RTK Elite PCAP Analyzer\n")
	fmt.Printf("═══════════════════════════════════════════════════════════\n\n")

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Verify input file exists
	if _, err := os.Stat(pcapAnalyze); os.IsNotExist(err) {
		return fmt.Errorf("PCAP file not found: %s", pcapAnalyze)
	}

	fmt.Printf("🔍 Analyzing: %s\n\n", pcapAnalyze)

	// Create handler for analysis
	handler := capture.NewPcapHandler(logger, &capture.CaptureConfig{})

	// Perform analysis
	analysis, err := handler.AnalyzeCapture(pcapAnalyze)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Display results
	displayAnalysisResults(analysis)

	// Save report if output specified
	if pcapOutput != "" {
		if err := saveAnalysisReport(analysis, pcapOutput); err != nil {
			return fmt.Errorf("failed to save report: %w", err)
		}
		fmt.Printf("\n💾 Analysis report saved: %s\n", pcapOutput)
	}

	return nil
}

func displayAnalysisResults(analysis *capture.CaptureAnalysis) {
	fmt.Printf("📈 ANALYSIS RESULTS\n")
	fmt.Printf("═══════════════════════════════════════════════════════════\n\n")

	// Basic statistics
	fmt.Printf("📊 PACKET STATISTICS:\n")
	fmt.Printf("   Total Packets: %d\n", analysis.TotalPackets)
	fmt.Printf("   Capture Duration: %v\n", analysis.Duration)
	fmt.Printf("   Start Time: %s\n", analysis.TimeRange.Start.Format("2006-01-02 15:04:05"))
	fmt.Printf("   End Time: %s\n", analysis.TimeRange.End.Format("2006-01-02 15:04:05"))
	fmt.Println()

	// Protocol breakdown
	if len(analysis.ProtocolStats) > 0 {
		fmt.Printf("🔗 PROTOCOL DISTRIBUTION:\n")
		for protocol, count := range analysis.ProtocolStats {
			percentage := float64(count) / float64(analysis.TotalPackets) * 100
			fmt.Printf("   %s: %d packets (%.1f%%)\n", protocol, count, percentage)
		}
		fmt.Println()
	}

	// Top ports
	if len(analysis.PortStats) > 0 {
		fmt.Printf("🚪 TOP PORTS:\n")
		count := 0
		for port, packets := range analysis.PortStats {
			if count >= 10 {
				break
			}
			fmt.Printf("   Port %d: %d packets\n", port, packets)
			count++
		}
		fmt.Println()
	}

	// Suspicious flows
	if len(analysis.SuspiciousFlow) > 0 {
		fmt.Printf("⚠️  SUSPICIOUS ACTIVITY:\n")
		for _, flow := range analysis.SuspiciousFlow {
			fmt.Printf("   %s [%s]: %s\n", 
				flow.Timestamp.Format("15:04:05"), 
				flow.Type, 
				flow.Description)
		}
		fmt.Println()
	} else {
		fmt.Printf("✅ No suspicious activity detected\n\n")
	}

	// Recommendations
	fmt.Printf("💡 RECOMMENDATIONS:\n")
	if analysis.TotalPackets == 0 {
		fmt.Printf("   • No packets captured - check interface and filters\n")
	} else if len(analysis.SuspiciousFlow) > 0 {
		fmt.Printf("   • Review suspicious flows for potential security issues\n")
		fmt.Printf("   • Consider implementing additional network monitoring\n")
	} else {
		fmt.Printf("   • Traffic appears normal - no immediate concerns\n")
	}
	
	if analysis.Duration.Seconds() < 60 {
		fmt.Printf("   • Consider longer capture duration for better analysis\n")
	}
}

func saveAnalysisReport(analysis *capture.CaptureAnalysis, filename string) error {
	// For now, save as JSON
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Simple JSON serialization
	report := fmt.Sprintf(`{
  "filename": "%s",
  "total_packets": %d,
  "duration_seconds": %.1f,
  "start_time": "%s",
  "end_time": "%s",
  "protocol_stats": %v,
  "suspicious_flows": %d
}`,
		analysis.Filename,
		analysis.TotalPackets,
		analysis.Duration.Seconds(),
		analysis.TimeRange.Start.Format("2006-01-02T15:04:05Z"),
		analysis.TimeRange.End.Format("2006-01-02T15:04:05Z"),
		analysis.ProtocolStats,
		len(analysis.SuspiciousFlow))

	_, err = file.WriteString(report)
	return err
}

func parseMaxSize(sizeStr string) int64 {
	if sizeStr == "" || sizeStr == "0" {
		return 0 // Unlimited
	}
	
	sizeStr = strings.ToUpper(strings.TrimSpace(sizeStr))
	
	var multiplier int64 = 1
	var numStr string
	
	if strings.HasSuffix(sizeStr, "B") {
		numStr = strings.TrimSuffix(sizeStr, "B")
	} else if strings.HasSuffix(sizeStr, "KB") || strings.HasSuffix(sizeStr, "K") {
		multiplier = 1024
		if strings.HasSuffix(sizeStr, "KB") {
			numStr = strings.TrimSuffix(sizeStr, "KB")
		} else {
			numStr = strings.TrimSuffix(sizeStr, "K")
		}
	} else if strings.HasSuffix(sizeStr, "MB") || strings.HasSuffix(sizeStr, "M") {
		multiplier = 1024 * 1024
		if strings.HasSuffix(sizeStr, "MB") {
			numStr = strings.TrimSuffix(sizeStr, "MB")
		} else {
			numStr = strings.TrimSuffix(sizeStr, "M")
		}
	} else if strings.HasSuffix(sizeStr, "GB") || strings.HasSuffix(sizeStr, "G") {
		multiplier = 1024 * 1024 * 1024
		if strings.HasSuffix(sizeStr, "GB") {
			numStr = strings.TrimSuffix(sizeStr, "GB")
		} else {
			numStr = strings.TrimSuffix(sizeStr, "G")
		}
	} else {
		numStr = sizeStr
	}
	
	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0
	}
	
	return int64(num * float64(multiplier))
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}