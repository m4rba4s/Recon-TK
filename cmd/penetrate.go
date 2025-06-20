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
	"recon-toolkit/pkg/penetration"
)

var (
	penetrateAggressive    bool
	penetrateStealthLevel  int
	penetrateMaxConcurrency int
	penetrateTimeout       int
	penetrateRealTimeGen   bool
	penetrateLearning      bool
	penetrateOutput        string
	penetrateFormat        string
	penetrateComplexity    string
)

var penetrateCmd = &cobra.Command{
	Use:   "penetrate",
	Short: "🔥 Adaptive penetration engine with real-time payload generation",
	Long: `🔥 ADAPTIVE PENETRATION ENGINE

Elite penetration testing with real-time payload generation and adaptive learning:

⚡ ADAPTIVE FEATURES:
  • Real-time payload generation based on target behavior
  • Intelligent attack vector selection and adaptation
  • Learning from failed attempts for improved success
  • Dynamic bypass technique selection
  • Stealth-optimized execution patterns

🧠 AI-POWERED CAPABILITIES:
  • Context-aware payload mutations
  • Behavioral pattern analysis
  • Success probability prediction
  • Adaptive timing and evasion
  • Real-time vulnerability correlation

🎯 ATTACK VECTORS:
  • Host header confusion attacks
  • HTTP method override exploitation
  • Header injection techniques
  • Origin-based bypass methods
  • Protocol smuggling attempts

🛡️ STEALTH LEVELS:
  • Level 1: Basic - Standard timing
  • Level 2: Moderate - Random delays
  • Level 3: Advanced - Traffic pattern mimicking
  • Level 4: Elite - Anti-forensics enabled
  • Level 5: Legendary - Ghost mode activation

🎭 COMPLEXITY MODES:
  • Simple: Basic payloads for quick wins
  • Adaptive: Context-aware payload selection
  • Complex: Multi-stage exploitation chains
  • Polymorphic: Self-modifying payloads

Examples:
  recon-toolkit penetrate -t 172.67.68.228 --aggressive --stealth-level 3
  recon-toolkit penetrate -t target.com --real-time-gen --learning --complexity adaptive
  recon-toolkit penetrate -t api.target.com --max-concurrency 20 --timeout 45`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target is required for adaptive penetration")
		}

		if !silent {
			color.Red("🔥 ADAPTIVE PENETRATION ENGINE ACTIVATED")
			color.Yellow("Target: %s", target)
			color.Green("🧠 Real-time Generation: %v", penetrateRealTimeGen)
			color.Green("⚡ Aggressive Mode: %v", penetrateAggressive)
			color.Green("🥷 Stealth Level: %d", penetrateStealthLevel)
			color.Green("🎓 Learning Enabled: %v", penetrateLearning)
			color.Magenta("⚠️  MAXIMUM CHAOS MODE - SYSTEMS WILL SUFFER")
		}

		// Configure penetration engine
		config := &penetration.PenetrationConfig{
			Target:             target,
			MaxConcurrency:     penetrateMaxConcurrency,
			AdaptiveTimeout:    time.Duration(penetrateTimeout) * time.Second,
			EnableRealTimeGen:  penetrateRealTimeGen,
			EnableLearning:     penetrateLearning,
			AggressiveMode:     penetrateAggressive,
			StealthLevel:       penetrateStealthLevel,
			PayloadComplexity:  penetrateComplexity,
			BypassTechniques:   []string{"header_injection", "host_confusion", "method_override", "origin_bypass"},
		}

		// Setup logger
		logger := &PenetrateLogger{
			logger: logrus.New(),
			silent: silent,
		}
		if silent {
			logger.logger.SetLevel(logrus.ErrorLevel)
		} else {
			logger.logger.SetLevel(logrus.InfoLevel)
		}

		// Create adaptive penetration engine
		engine := penetration.NewAdaptivePenetrationEngine(logger, config)

		ctx := context.Background()

		if !silent {
			color.Cyan("\\n🔥 Initiating adaptive penetration...")
			color.Cyan("🧠 AI-powered payload generation active...")
			color.Cyan("⚡ Maximum chaos level engaged...")
		}

		// Execute adaptive penetration
		result, err := engine.ExecutePenetration(ctx)
		if err != nil {
			return fmt.Errorf("adaptive penetration failed: %w", err)
		}

		// Display results
		err = displayPenetrationResults(result)
		if err != nil {
			return fmt.Errorf("failed to display results: %w", err)
		}

		// Save results if requested
		if penetrateOutput != "" {
			err = savePenetrationResults(result, penetrateFormat, penetrateOutput)
			if err != nil {
				color.Red("Failed to save results: %v", err)
			} else if !silent {
				color.Green("💾 Results saved to: %s", penetrateOutput)
			}
		}

		if !silent {
			color.Green("\\n✨ Adaptive penetration completed")
			if result.Success {
				color.Red("🎯 VULNERABILITIES FOUND - Target compromised!")
				color.Red("💥 %d security findings discovered", len(result.Findings))
			} else {
				color.Yellow("🛡️ Target appears well-defended")
			}
			color.Cyan("🎭 %s", result.CynicalAssessment)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(penetrateCmd)

	penetrateCmd.Flags().BoolVar(&penetrateAggressive, "aggressive", false, "Enable aggressive penetration mode")
	penetrateCmd.Flags().IntVar(&penetrateStealthLevel, "stealth-level", 3, "Stealth level (1-5)")
	penetrateCmd.Flags().IntVar(&penetrateMaxConcurrency, "max-concurrency", 10, "Maximum concurrent attacks")
	penetrateCmd.Flags().IntVar(&penetrateTimeout, "timeout", 30, "Request timeout in seconds")
	penetrateCmd.Flags().BoolVar(&penetrateRealTimeGen, "real-time-gen", true, "Enable real-time payload generation")
	penetrateCmd.Flags().BoolVar(&penetrateLearning, "learning", true, "Enable adaptive learning")
	penetrateCmd.Flags().StringVar(&penetrateOutput, "output", "", "Output file path")
	penetrateCmd.Flags().StringVar(&penetrateFormat, "format", "json", "Output format (json, text)")
	penetrateCmd.Flags().StringVar(&penetrateComplexity, "complexity", "adaptive", "Payload complexity (simple, adaptive, complex, polymorphic)")
}

// PenetrateLogger implements core.Logger interface
type PenetrateLogger struct {
	logger *logrus.Logger
	silent bool
}

func (l *PenetrateLogger) Debug(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Debug(msg)
}

func (l *PenetrateLogger) Info(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Info(msg)
}

func (l *PenetrateLogger) Warn(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Warn(msg)
}

func (l *PenetrateLogger) Error(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Error(msg)
}

func (l *PenetrateLogger) Fatal(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Fatal(msg)
}

func (l *PenetrateLogger) fieldsToLogrus(fields []core.Field) logrus.Fields {
	logrusFields := make(logrus.Fields)
	for _, field := range fields {
		logrusFields[field.Key()] = field.Value()
	}
	return logrusFields
}

// displayPenetrationResults shows penetration testing results
func displayPenetrationResults(result *penetration.PenetrationResult) error {
	if !silent {
		color.Cyan("\\n🔥 ADAPTIVE PENETRATION RESULTS")
		color.Cyan("=" + strings.Repeat("=", 50))

		// Summary
		color.White("Target: %s", result.Target)
		color.White("Duration: %v", result.Duration)
		color.White("Attack Vectors Tested: %d", len(result.AttackVectors))
		
		if result.Success {
			color.Red("🎯 PENETRATION SUCCESSFUL!")
			color.Red("Vulnerabilities Found: %d", len(result.Findings))
		} else {
			color.Green("🛡️ Target successfully defended")
		}

		// Findings
		if len(result.Findings) > 0 {
			color.Cyan("\\n🎯 SECURITY FINDINGS:")
			color.Cyan("-" + strings.Repeat("-", 60))

			for i, finding := range result.Findings {
				severityColor := getSeverityColorFromSeverity(finding.Severity)
				severityColor.Printf("🚨 Finding #%d: %s\\n", i+1, finding.Title)
				color.White("   Type: %s", finding.Type)
				color.White("   Severity: %s", severityToString(finding.Severity))
				color.White("   Description: %s", finding.Description)
				
				if finding.AttackVector.Payload != "" {
					color.Yellow("   Attack Vector: %s", finding.AttackVector.Name)
					color.Yellow("   Payload: %s", finding.AttackVector.Payload)
				}
				
				if finding.CynicalComment != "" {
					color.Magenta("   💀 Roast: %s", finding.CynicalComment)
				}
				fmt.Println()
			}
		}

		// Attack Vector Summary
		if len(result.AttackVectors) > 0 {
			successful := 0
			for _, vector := range result.AttackVectors {
				if vector.Success {
					successful++
				}
			}
			
			color.Cyan("\\n⚡ ATTACK VECTOR SUMMARY:")
			color.White("Total Vectors: %d", len(result.AttackVectors))
			color.White("Successful: %d", successful)
			color.White("Success Rate: %.1f%%", float64(successful)/float64(len(result.AttackVectors))*100)
		}

		// Cynical Assessment
		if result.CynicalAssessment != "" {
			color.Cyan("\\n🎭 CYNICAL ASSESSMENT:")
			color.Magenta("💀 %s", result.CynicalAssessment)
		}

		// Recommendations
		color.Cyan("\\n💡 RECOMMENDATIONS:")
		if result.Success {
			color.Red("🚨 CRITICAL: Immediate patching required")
			color.Red("🔒 Review all discovered attack vectors")
			color.Red("🛡️ Implement additional security controls")
		} else {
			color.Green("✅ Current defenses appear effective")
			color.Yellow("🔍 Continue monitoring for new attack vectors")
			color.Yellow("📈 Consider regular penetration testing")
		}
	}

	return nil
}

// savePenetrationResults saves penetration testing results
func savePenetrationResults(result *penetration.PenetrationResult, format, filename string) error {
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

		fmt.Fprintf(file, "ADAPTIVE PENETRATION RESULTS\\n")
		fmt.Fprintf(file, "============================\\n\\n")
		fmt.Fprintf(file, "Target: %s\\n", result.Target)
		fmt.Fprintf(file, "Success: %t\\n", result.Success)
		fmt.Fprintf(file, "Duration: %v\\n", result.Duration)
		fmt.Fprintf(file, "Findings: %d\\n\\n", len(result.Findings))

		for i, finding := range result.Findings {
			fmt.Fprintf(file, "Finding #%d:\\n", i+1)
			fmt.Fprintf(file, "  Type: %s\\n", finding.Type)
			fmt.Fprintf(file, "  Severity: %s\\n", severityToString(finding.Severity))
			fmt.Fprintf(file, "  Title: %s\\n", finding.Title)
			fmt.Fprintf(file, "  Description: %s\\n", finding.Description)
			if finding.CynicalComment != "" {
				fmt.Fprintf(file, "  Roast: %s\\n", finding.CynicalComment)
			}
			fmt.Fprintf(file, "\\n")
		}

		return nil

	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

func getSeverityColorFromSeverity(severity core.Severity) *color.Color {
	switch severity {
	case core.SeverityCritical:
		return color.New(color.FgRed, color.Bold)
	case core.SeverityHigh:
		return color.New(color.FgRed)
	case core.SeverityMedium:
		return color.New(color.FgYellow)
	case core.SeverityLow:
		return color.New(color.FgBlue)
	case core.SeverityInfo:
		return color.New(color.FgCyan)
	default:
		return color.New(color.FgWhite)
	}
}

func severityToString(severity core.Severity) string {
	switch severity {
	case core.SeverityCritical:
		return "CRITICAL"
	case core.SeverityHigh:
		return "HIGH"
	case core.SeverityMedium:
		return "MEDIUM"
	case core.SeverityLow:
		return "LOW"
	case core.SeverityInfo:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}