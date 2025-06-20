package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"recon-toolkit/pkg/core"
	"recon-toolkit/pkg/shadow"
)

var (
	shadowRTTThreshold     int
	shadowEntropyThreshold float64
	shadowMaxRetries       int
	shadowVerbose          bool
	shadowOutput           string
	shadowFormat           string
)

var shadowCmd = &cobra.Command{
	Use:   "shadow",
	Short: "🕵️ Advanced honeypot detection and shadow stack analysis",
	Long: `🕵️ SHADOW STACK DETECTION SYSTEM

Advanced honeypot detection and anti-trap analysis framework:

🍯 HONEYPOT DETECTION:
  • Timing analysis - RTT fingerprinting and variance detection
  • Favicon analysis - black favicon signature detection
  • Response pattern analysis - entropy and similarity checks
  • Port behavior analysis - fake service response detection
  • TCP fingerprinting - stack emulation identification

⏱️ TIMING ANALYSIS:
  • RTT consistency detection (honeypots often have too stable timing)
  • Response time anomaly detection
  • Network latency pattern analysis
  • Service response delay correlation

🔍 ADVANCED DETECTION:
  • Template response identification
  • Honeypot framework signature detection
  • Service behavior validation
  • Traffic pattern analysis

🛡️ ANTI-TRAP TECHNIQUES:
  • Multi-vector validation
  • Behavioral analysis
  • Signature correlation
  • Confidence scoring

Examples:
  recon-toolkit shadow -t honeypot.example.com
  recon-toolkit shadow -t 192.168.1.100 --rtt-threshold 100 --verbose
  recon-toolkit shadow -t target.com --entropy-threshold 7.0 -o results.json`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target is required for shadow stack analysis")
		}

		if !silent {
			color.Red("🕵️ SHADOW STACK DETECTION SYSTEM ACTIVATED")
			color.Yellow("Target: %s", target)
			color.Green("🍯 Honeypot Detection: ENABLED")
			color.Green("⏱️ Timing Analysis: ENABLED")
			color.Green("🔍 Pattern Analysis: ENABLED")
			color.Magenta("⚠️  TRAPS WILL BE DETECTED AND AVOIDED")
		}

		// Configure shadow detection
		config := &shadow.HoneypotConfig{
			RTTThreshold:       time.Duration(shadowRTTThreshold) * time.Millisecond,
			EntropyThreshold:   shadowEntropyThreshold,
			SuspicionThreshold: 0.7,
			MaxRetries:         shadowMaxRetries,
		}

		// Setup logger
		logger := &ShadowLogger{
			logger: logrus.New(),
			silent: silent,
		}
		if silent {
			logger.logger.SetLevel(logrus.ErrorLevel)
		} else if shadowVerbose {
			logger.logger.SetLevel(logrus.DebugLevel)
		}

		// Create shadow detector
		detector := shadow.NewHoneypotDetector(logger, config)

		ctx := context.Background()

		if !silent {
			color.Cyan("\n🕵️ Initiating shadow stack analysis...")
			color.Cyan("🔍 Scanning for honeypots and traps...")
		}

		// Execute honeypot detection
		result, err := detector.AnalyzeTarget(ctx, target)
		if err != nil {
			return fmt.Errorf("shadow detection failed: %w", err)
		}

		// Display results
		err = displayShadowResults(result)
		if err != nil {
			return fmt.Errorf("failed to display results: %w", err)
		}

		// Save results if requested
		if shadowOutput != "" {
			err = saveShadowResults(result, shadowFormat, shadowOutput)
			if err != nil {
				color.Red("Failed to save results: %v", err)
			} else if !silent {
				color.Green("💾 Results saved to: %s", shadowOutput)
			}
		}

		if !silent {
			color.Green("\n✨ Shadow stack analysis completed")
			if result.IsHoneypot {
				color.Red("🚨 HONEYPOT DETECTED - Suspicion level: %.2f", result.SuspicionLevel)
				color.Red("🍯 This target is a trap! Avoid or proceed with extreme caution.")
			} else {
				color.Green("✅ Target appears legitimate - suspicion level: %.2f", result.SuspicionLevel)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(shadowCmd)

	shadowCmd.Flags().IntVar(&shadowRTTThreshold, "rtt-threshold", 50, "RTT threshold in milliseconds")
	shadowCmd.Flags().Float64Var(&shadowEntropyThreshold, "entropy-threshold", 6.5, "Entropy threshold for analysis")
	shadowCmd.Flags().IntVar(&shadowMaxRetries, "max-retries", 3, "Maximum retry attempts")
	shadowCmd.Flags().BoolVar(&shadowVerbose, "verbose", false, "Verbose output")
	shadowCmd.Flags().StringVar(&shadowOutput, "output", "", "Output file path")
	shadowCmd.Flags().StringVar(&shadowFormat, "format", "json", "Output format (json, text)")
}

// ShadowLogger implements core.Logger interface
type ShadowLogger struct {
	logger *logrus.Logger
	silent bool
}

func (l *ShadowLogger) Debug(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Debug(msg)
}

func (l *ShadowLogger) Info(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Info(msg)
}

func (l *ShadowLogger) Warn(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Warn(msg)
}

func (l *ShadowLogger) Error(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Error(msg)
}

func (l *ShadowLogger) Fatal(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Fatal(msg)
}

func (l *ShadowLogger) fieldsToLogrus(fields []core.Field) logrus.Fields {
	logrusFields := make(logrus.Fields)
	for _, field := range fields {
		logrusFields[field.Key()] = field.Value()
	}
	return logrusFields
}

// displayShadowResults displays honeypot detection results
func displayShadowResults(result *shadow.HoneypotResult) error {
	if !silent {
		color.Cyan("\n🕵️ SHADOW STACK ANALYSIS RESULTS")
		color.Cyan("=" + strings.Repeat("=", 50))

		// Summary
		color.White("Target: %s", result.Target)
		if result.IsHoneypot {
			color.Red("🚨 HONEYPOT DETECTED!")
			color.Red("Suspicion Level: %.2f", result.SuspicionLevel)
		} else {
			color.Green("✅ Target appears legitimate")
			color.Green("Suspicion Level: %.2f", result.SuspicionLevel)
		}

		// Indicators
		if len(result.Indicators) > 0 {
			color.Cyan("\n🔍 Detection Indicators:")
			color.Cyan("-" + strings.Repeat("-", 60))

			for _, indicator := range result.Indicators {
				severityColor := getSeverityColorFromString(indicator.Severity)
				severityColor.Printf("🎯 %s\n", indicator.Description)
				color.White("   Type: %s", indicator.Type)
				color.White("   Confidence: %.2f", indicator.Confidence)
				if indicator.Details != "" {
					color.Yellow("   Details: %s", indicator.Details)
				}
				fmt.Println()
			}
		}

		// Evidence
		if len(result.Evidence) > 0 {
			color.Cyan("\n📋 Evidence:")
			color.Cyan("-" + strings.Repeat("-", 60))

			for i, evidence := range result.Evidence {
				color.White("Evidence #%d: %s", i+1, evidence.GetContext())
				fmt.Println()
			}
		}

		// Recommendations
		color.Cyan("\n💡 Recommendations:")
		if result.IsHoneypot {
			color.Red("🚨 This target is likely a honeypot or trap")
			color.Red("🛑 Avoid further testing or proceed with extreme caution")
			color.Red("🔍 Consider using stealth techniques if testing is necessary")
		} else {
			color.Green("✅ Target appears to be a legitimate service")
			color.Green("🎯 Safe to proceed with normal testing procedures")
			color.Yellow("⚠️  Always maintain awareness of potential detection")
		}
	}

	return nil
}

// saveShadowResults saves honeypot detection results
func saveShadowResults(result *shadow.HoneypotResult, format, filename string) error {
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

		fmt.Fprintf(file, "SHADOW STACK ANALYSIS RESULTS\n")
		fmt.Fprintf(file, "=============================\n\n")
		fmt.Fprintf(file, "Target: %s\n", result.Target)
		fmt.Fprintf(file, "Is Honeypot: %t\n", result.IsHoneypot)
		fmt.Fprintf(file, "Suspicion Level: %.2f\n", result.SuspicionLevel)
		fmt.Fprintf(file, "Indicators: %d\n\n", len(result.Indicators))

		for i, indicator := range result.Indicators {
			fmt.Fprintf(file, "Indicator #%d:\n", i+1)
			fmt.Fprintf(file, "  Type: %s\n", indicator.Type)
			fmt.Fprintf(file, "  Description: %s\n", indicator.Description)
			fmt.Fprintf(file, "  Confidence: %.2f\n", indicator.Confidence)
			fmt.Fprintf(file, "  Details: %s\n\n", indicator.Details)
		}

		return nil

	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func getSeverityColorFromString(severity string) *color.Color {
	switch strings.ToLower(severity) {
	case "high":
		return color.New(color.FgRed)
	case "medium":
		return color.New(color.FgYellow)
	case "low":
		return color.New(color.FgBlue)
	default:
		return color.New(color.FgWhite)
	}
}