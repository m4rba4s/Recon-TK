package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"recon-toolkit/pkg/core"
	"recon-toolkit/pkg/stealth"
)

var (
	ghostPhantomScan     bool
	ghostMirrorTraffic   bool
	ghostDistributedScan bool
	ghostAntiForensics   bool
	ghostProxyChains     int
	ghostDelayRange      string
	ghostOutput          string
	ghostFormat          string
	ghostVerbose         bool
)

var ghostCmd = &cobra.Command{
	Use:   "ghost",
	Short: "👻 Ghost Mode - Absolute invisibility with traffic mirroring",
	Long: `👻 GHOST MODE - Absolute Invisibility Framework

Advanced stealth reconnaissance with complete anti-detection:

🔮 PHANTOM CAPABILITIES:
  • Traffic mirroring through legitimate services
  • Distributed scanning across multiple regions/nodes
  • Proxy chain obfuscation (Tor + VPN multi-hop)
  • Legitimate API abuse (Shodan, Censys, Google)
  • Anti-forensics trace cleanup

🌐 DISTRIBUTED ARCHITECTURE:
  • Multi-node scanning coordination
  • Geographic IP distribution
  • Load balancing across regions
  • Automated failover systems

🥷 STEALTH TECHNIQUES:
  • Legitimate traffic pattern mimicry
  • Random timing and jitter
  • User agent rotation
  • Request fragmentation
  • Memory-only operation

🧹 ANTI-FORENSICS:
  • Automatic trace cleanup
  • Memory artifact wiping
  • Network log obfuscation
  • Temporary file destruction
  • Process hiding techniques

🎯 TARGET ABUSE METHODS:
  • Google dorking through search API
  • Shodan intelligence gathering
  • Censys certificate reconnaissance
  • DNS resolution via multiple resolvers
  • WHOIS data aggregation

Examples:
  recon-toolkit ghost -t example.com --phantom-scan
  recon-toolkit ghost -t target.com --mirror-traffic --distributed
  recon-toolkit ghost -t victim.com --anti-forensics --proxy-chains 5
  recon-toolkit ghost -t site.com --phantom-scan --mirror-traffic --distributed --anti-forensics`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target is required for ghost mode scanning")
		}

		if !silent {
			color.Red("👻 GHOST MODE ACTIVATED")
			color.Yellow("Target: %s", target)
			if ghostPhantomScan {
				color.Green("🔮 Phantom Scan: ENABLED")
			}
			if ghostMirrorTraffic {
				color.Green("🌐 Traffic Mirroring: ENABLED")
			}
			if ghostDistributedScan {
				color.Green("🗺️  Distributed Scan: ENABLED")
			}
			if ghostAntiForensics {
				color.Red("🧹 Anti-Forensics: ENABLED")
			}
			if ghostProxyChains > 0 {
				color.Blue("🔗 Proxy Chains: %d", ghostProxyChains)
			}
			color.Magenta("⚠️  MAXIMUM STEALTH MODE - UNDETECTABLE")
		}

		// Parse delay range
		delayRange := [2]int{1, 5} // default
		if ghostDelayRange != "" {
			_, err := fmt.Sscanf(ghostDelayRange, "%d-%d", &delayRange[0], &delayRange[1])
			if err != nil {
				return fmt.Errorf("invalid delay range format (use: min-max): %w", err)
			}
		}

		// Configure ghost engine
		config := &stealth.GhostConfig{
			MaxProxyChains:   ghostProxyChains,
			ChainLength:      3,
			DelayRange:       delayRange,
			AntiForensics:    ghostAntiForensics,
			DistributedNodes: 10,
			TrafficMimicry:   ghostMirrorTraffic,
		}

		// Setup logger
		logger := &GhostLogger{
			logger: logrus.New(),
			silent: silent,
		}
		if silent {
			logger.logger.SetLevel(logrus.ErrorLevel)
		} else if ghostVerbose {
			logger.logger.SetLevel(logrus.DebugLevel)
		}

		// Create ghost engine
		ghostEngine := stealth.NewGhostEngine(logger, config)

		// Create target
		targetObj := core.NewBaseTarget(target, core.TargetTypeHost)

		ctx := context.Background()

		if !silent {
			color.Cyan("\n👻 Initiating phantom reconnaissance...")
			color.Cyan("🔍 Target will never know what hit them")
		}

		// Execute phantom scan
		result, err := ghostEngine.PhantomScan(ctx, targetObj)
		if err != nil {
			return fmt.Errorf("phantom scan failed: %w", err)
		}

		// Display results
		err = displayGhostResults(result)
		if err != nil {
			return fmt.Errorf("failed to display results: %w", err)
		}

		// Save results if requested
		if ghostOutput != "" {
			err = saveGhostResults(result, ghostFormat, ghostOutput)
			if err != nil {
				color.Red("Failed to save results: %v", err)
			} else if !silent {
				color.Green("💾 Results saved to: %s", ghostOutput)
			}
		}

		if !silent {
			color.Green("\n✨ Ghost mode completed successfully")
			color.Yellow("🎭 Detection risk: %.1f%%", result.DetectionRisk*100)
			if result.ForensicsWiped {
				color.Red("🧹 All traces wiped - completely undetectable")
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(ghostCmd)

	ghostCmd.Flags().BoolVar(&ghostPhantomScan, "phantom-scan", true, "Enable phantom scanning mode")
	ghostCmd.Flags().BoolVar(&ghostMirrorTraffic, "mirror-traffic", true, "Mirror legitimate traffic for cover")
	ghostCmd.Flags().BoolVar(&ghostDistributedScan, "distributed", true, "Use distributed scanning nodes")
	ghostCmd.Flags().BoolVar(&ghostAntiForensics, "anti-forensics", true, "Enable anti-forensics cleanup")
	ghostCmd.Flags().IntVar(&ghostProxyChains, "proxy-chains", 3, "Number of proxy chains to use")
	ghostCmd.Flags().StringVar(&ghostDelayRange, "delay-range", "1-5", "Delay range in seconds (min-max)")
	ghostCmd.Flags().StringVar(&ghostOutput, "output", "", "Output file path")
	ghostCmd.Flags().StringVar(&ghostFormat, "format", "json", "Output format (json, text)")
	ghostCmd.Flags().BoolVar(&ghostVerbose, "verbose", false, "Verbose logging output")
}

// GhostLogger implements core.Logger interface
type GhostLogger struct {
	logger *logrus.Logger
	silent bool
}

func (l *GhostLogger) Debug(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Debug(msg)
}

func (l *GhostLogger) Info(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Info(msg)
}

func (l *GhostLogger) Warn(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Warn(msg)
}

func (l *GhostLogger) Error(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Error(msg)
}

func (l *GhostLogger) Fatal(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Fatal(msg)
}

func (l *GhostLogger) fieldsToLogrus(fields []core.Field) logrus.Fields {
	logrusFields := make(logrus.Fields)
	for _, field := range fields {
		logrusFields[field.Key()] = field.Value()
	}
	return logrusFields
}

// displayGhostResults displays ghost scan results
func displayGhostResults(result *stealth.GhostScanResult) error {
	if !silent {
		color.Cyan("\n👻 GHOST SCAN RESULTS")
		color.Cyan("=" + strings.Repeat("=", 50))

		// Summary
		findings := result.GetFindings()
		color.White("Target: %s", result.GetTarget().GetAddress())
		color.White("Findings: %d", len(findings))
		color.White("Detection Risk: %.1f%%", result.DetectionRisk*100)

		// Stealth info
		color.Blue("\n🥷 Stealth Operations:")
		if len(result.ProxyChainUsed) > 0 {
			color.Blue("  Proxy Chain: %s", strings.Join(result.ProxyChainUsed, " → "))
		}
		if result.ServiceAbused != "" {
			color.Blue("  Services Abused: %s", result.ServiceAbused)
		}
		if result.TrafficPattern != "" {
			color.Blue("  Traffic Pattern: %s", result.TrafficPattern)
		}
		if result.ForensicsWiped {
			color.Red("  Anti-Forensics: ✅ ALL TRACES WIPED")
		}

		// Display findings
		if len(findings) > 0 {
			color.Cyan("\n🔍 Intelligence Gathered:")
			color.Cyan("-" + strings.Repeat("-", 60))

			for _, finding := range findings {
				severityColor := getSeverityColor(finding.GetSeverity())
				severityColor.Printf("🎯 %s ", finding.GetTitle())
				fmt.Printf("(%s)\n", core.SeverityToString(finding.GetSeverity()))
				color.White("   %s", finding.GetDescription())

				// Show evidence
				evidence := finding.GetEvidence()
				if len(evidence) > 0 {
					color.Yellow("   Evidence:")
					for _, ev := range evidence {
						color.Yellow("     • %s", ev.GetContext())
					}
				}

				fmt.Println()
			}
		} else {
			color.Green("\n✅ Target appears clean - no intelligence gathered")
		}

		// Risk assessment
		color.Cyan("\n📊 STEALTH ASSESSMENT:")
		riskLevel := "MINIMAL"
		riskColor := color.New(color.FgGreen)
		
		if result.DetectionRisk > 0.7 {
			riskLevel = "HIGH"
			riskColor = color.New(color.FgRed)
		} else if result.DetectionRisk > 0.3 {
			riskLevel = "MODERATE"
			riskColor = color.New(color.FgYellow)
		}
		
		riskColor.Printf("Detection Risk: %s (%.1f%%)\n", riskLevel, result.DetectionRisk*100)
		
		if result.DetectionRisk < 0.1 {
			color.Green("🏆 LEGENDARY STEALTH - Completely undetectable!")
		}
	}

	return nil
}

// saveGhostResults saves ghost scan results
func saveGhostResults(result *stealth.GhostScanResult, format, filename string) error {
	switch format {
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filename, data, 0644)

	case "text":
		file, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer file.Close()

		fmt.Fprintf(file, "GHOST MODE SCAN RESULTS\n")
		fmt.Fprintf(file, "=======================\n\n")
		fmt.Fprintf(file, "Target: %s\n", result.GetTarget().GetAddress())
		fmt.Fprintf(file, "Timestamp: %s\n", result.GetTimestamp().Format("2006-01-02 15:04:05"))
		fmt.Fprintf(file, "Detection Risk: %.1f%%\n", result.DetectionRisk*100)
		fmt.Fprintf(file, "Proxy Chain: %s\n", strings.Join(result.ProxyChainUsed, " -> "))
		fmt.Fprintf(file, "Service Abused: %s\n", result.ServiceAbused)
		fmt.Fprintf(file, "Forensics Wiped: %t\n\n", result.ForensicsWiped)

		findings := result.GetFindings()
		fmt.Fprintf(file, "Findings: %d\n\n", len(findings))

		for i, finding := range findings {
			fmt.Fprintf(file, "[%d] %s\n", i+1, finding.GetTitle())
			fmt.Fprintf(file, "    Severity: %s\n", core.SeverityToString(finding.GetSeverity()))
			fmt.Fprintf(file, "    Description: %s\n", finding.GetDescription())
			
			evidence := finding.GetEvidence()
			if len(evidence) > 0 {
				fmt.Fprintf(file, "    Evidence:\n")
				for _, ev := range evidence {
					fmt.Fprintf(file, "      - %s\n", ev.GetContext())
				}
			}
			fmt.Fprintf(file, "\n")
		}

		return nil

	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// getSeverityColor returns appropriate color for severity level
func getSeverityColor(severity core.Severity) *color.Color {
	switch severity {
	case core.SeverityCritical:
		return color.New(color.FgRed, color.Bold)
	case core.SeverityHigh:
		return color.New(color.FgRed)
	case core.SeverityMedium:
		return color.New(color.FgYellow)
	case core.SeverityLow:
		return color.New(color.FgGreen)
	default:
		return color.New(color.FgBlue)
	}
}