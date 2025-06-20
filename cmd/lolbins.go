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
	"recon-toolkit/pkg/lolbins"
)

var (
	lolbinsTechniques    []string
	lolbinsTargetOS      string
	lolbinsStealthMode   bool
	lolbinsChainExec     bool
	lolbinsAntiDetection bool
	lolbinsObfuscation   bool
	lolbinsOutput        string
	lolbinsFormat        string
	lolbinsVerbose       bool
	lolbinsTimeout       int
	lolbinsConcurrency   int
)

var lolbinsCmd = &cobra.Command{
	Use:   "lolbins",
	Short: "🥷 Living-off-the-Land toolkit for native binary abuse",
	Long: `🥷 LIVING-OFF-THE-LAND BINARY TOOLKIT

Advanced native binary abuse framework for stealthy post-exploitation:

🎯 TECHNIQUE CATEGORIES:
  • File Download/Upload - Data transfer using native tools
  • Command Execution - Running commands through legitimate binaries  
  • Data Exfiltration - Stealing data via trusted processes
  • Reconnaissance - Information gathering with built-in tools
  • Persistence - Maintaining access through system utilities
  • Privilege Escalation - Elevating permissions via LOLBins
  • Defense Evasion - Bypassing security controls
  • Lateral Movement - Moving through network using native tools

🔧 SUPPORTED LOLBINS:

Windows:
  • PowerShell - Advanced command execution and download
  • CertUtil - Certificate utility for file operations
  • BitsAdmin - Background transfer service abuse
  • RegSvr32 - DLL registration for code execution
  • MSBuild - Microsoft Build Engine for code compilation
  • InstallUtil - .NET installer utility abuse
  • WMIC - Windows Management Instrumentation
  • Rundll32 - DLL execution utility

Linux/macOS:
  • Bash/Zsh - Shell command execution
  • cURL - HTTP client for data transfer
  • Wget - Network downloader utility
  • SSH - Secure shell for remote access
  • Python - Scripting language abuse
  • Perl - Text processing language
  • AWK/SED - Text manipulation utilities
  • OpenSSL - Cryptographic toolkit

⛓️ ATTACK CHAINS:
  • Data Exfiltration Chain - Multi-stage data theft
  • Persistence Chain - Long-term access maintenance
  • Lateral Movement Chain - Network traversal
  • Privilege Escalation Chain - Rights elevation
  • Defense Evasion Chain - Security bypass

🥷 STEALTH FEATURES:
  • Command obfuscation and encoding
  • Anti-detection timing and patterns
  • Fileless execution techniques
  • Native process injection
  • Memory-only operations
  • Output sanitization

🔍 MITRE ATT&CK MAPPING:
  • T1105 - Ingress Tool Transfer
  • T1059 - Command and Scripting Interpreter
  • T1140 - Deobfuscate/Decode Files or Information
  • T1036 - Masquerading
  • T1218 - Signed Binary Proxy Execution
  • T1055 - Process Injection

Examples:
  recon-toolkit lolbins -t target.com --techniques file_download,reconnaissance
  recon-toolkit lolbins -t 192.168.1.100 --stealth --chain-exec --anti-detection
  recon-toolkit lolbins -t victim.local --techniques all --obfuscation
  recon-toolkit lolbins -t server.com --target-os windows --timeout 60`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target is required for Living-off-the-Land attacks")
		}

		if !silent {
			color.Red("🥷 LIVING-OFF-THE-LAND TOOLKIT ACTIVATED")
			color.Yellow("Target: %s", target)
			if len(lolbinsTechniques) > 0 {
				color.Green("🎯 Techniques: %s", strings.Join(lolbinsTechniques, ", "))
			}
			if lolbinsTargetOS != "" {
				color.Green("💻 Target OS: %s", lolbinsTargetOS)
			}
			if lolbinsStealthMode {
				color.Blue("🥷 Stealth Mode: ENABLED")
			}
			if lolbinsChainExec {
				color.Green("⛓️ Chain Execution: ENABLED")
			}
			if lolbinsAntiDetection {
				color.Blue("🛡️ Anti-Detection: ENABLED")
			}
			if lolbinsObfuscation {
				color.Blue("🔒 Output Obfuscation: ENABLED")
			}
			color.Magenta("⚠️  NATIVE BINARY ABUSE - MAXIMUM STEALTH")
		}

		// Configure LOLBins engine
		config := &lolbins.LolBinsConfig{
			TargetOS:          lolbinsTargetOS,
			TechniqueTypes:    lolbinsTechniques,
			StealthMode:       lolbinsStealthMode,
			ChainExecution:    lolbinsChainExec,
			AntiDetection:     lolbinsAntiDetection,
			OutputObfuscation: lolbinsObfuscation,
			MaxConcurrency:    lolbinsConcurrency,
		}

		// If no techniques specified, use defaults
		if len(config.TechniqueTypes) == 0 {
			config.TechniqueTypes = []string{"reconnaissance", "file_download", "command_execution"}
		}

		// Auto-detect OS if not specified
		if config.TargetOS == "" {
			config.TargetOS = "linux" // Default assumption
		}

		// Setup logger
		logger := &LOLBinsLogger{
			logger: logrus.New(),
			silent: silent,
		}
		if silent {
			logger.logger.SetLevel(logrus.ErrorLevel)
		} else if lolbinsVerbose {
			logger.logger.SetLevel(logrus.DebugLevel)
		}

		// Create LOLBins engine
		livingEngine := lolbins.NewLivingEngine(logger, config)

		// Create target
		targetObj := core.NewBaseTarget(target, core.TargetTypeHost)

		ctx := context.Background()

		if !silent {
			color.Cyan("\n🥷 Initiating Living-off-the-Land attacks...")
			color.Cyan("🔍 Discovering available native binaries...")
		}

		// Execute Living-off-the-Land attacks
		result, err := livingEngine.ExecuteLivingOffTheLand(ctx, targetObj)
		if err != nil {
			return fmt.Errorf("LOLBins execution failed: %w", err)
		}

		// Display results
		err = displayLOLBinsResults(result)
		if err != nil {
			return fmt.Errorf("failed to display results: %w", err)
		}

		// Save results if requested
		if lolbinsOutput != "" {
			err = saveLOLBinsResults(result, lolbinsFormat, lolbinsOutput)
			if err != nil {
				color.Red("Failed to save results: %v", err)
			} else if !silent {
				color.Green("💾 Results saved to: %s", lolbinsOutput)
			}
		}

		if !silent {
			color.Green("\n✨ Living-off-the-Land attacks completed")
			color.Yellow("🎯 Techniques executed: %d", len(result.ExecutedTechniques))
			color.Yellow("⛓️ Successful chains: %d", len(result.SuccessfulChains))
			color.Blue("🥷 Detection risk: %s", getDetectionLevelString(result.DetectionRisk))
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(lolbinsCmd)

	lolbinsCmd.Flags().StringSliceVar(&lolbinsTechniques, "techniques", []string{}, "Technique types (file_download,command_execution,reconnaissance,etc.)")
	lolbinsCmd.Flags().StringVar(&lolbinsTargetOS, "target-os", "", "Target operating system (windows,linux,darwin)")
	lolbinsCmd.Flags().BoolVar(&lolbinsStealthMode, "stealth", true, "Enable stealth mode")
	lolbinsCmd.Flags().BoolVar(&lolbinsChainExec, "chain-exec", true, "Enable attack chain execution")
	lolbinsCmd.Flags().BoolVar(&lolbinsAntiDetection, "anti-detection", true, "Enable anti-detection measures")
	lolbinsCmd.Flags().BoolVar(&lolbinsObfuscation, "obfuscation", true, "Enable output obfuscation")
	lolbinsCmd.Flags().StringVar(&lolbinsOutput, "output", "", "Output file path")
	lolbinsCmd.Flags().StringVar(&lolbinsFormat, "format", "json", "Output format (json, text)")
	lolbinsCmd.Flags().BoolVar(&lolbinsVerbose, "verbose", false, "Verbose logging output")
	lolbinsCmd.Flags().IntVar(&lolbinsTimeout, "timeout", 30, "Execution timeout in seconds")
	lolbinsCmd.Flags().IntVar(&lolbinsConcurrency, "concurrency", 10, "Maximum concurrent executions")
}

// LOLBinsLogger implements core.Logger interface
type LOLBinsLogger struct {
	logger *logrus.Logger
	silent bool
}

func (l *LOLBinsLogger) Debug(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Debug(msg)
}

func (l *LOLBinsLogger) Info(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Info(msg)
}

func (l *LOLBinsLogger) Warn(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Warn(msg)
}

func (l *LOLBinsLogger) Error(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Error(msg)
}

func (l *LOLBinsLogger) Fatal(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Fatal(msg)
}

func (l *LOLBinsLogger) fieldsToLogrus(fields []core.Field) logrus.Fields {
	logrusFields := make(logrus.Fields)
	for _, field := range fields {
		logrusFields[field.Key()] = field.Value()
	}
	return logrusFields
}

// displayLOLBinsResults displays LOLBins execution results
func displayLOLBinsResults(result *lolbins.LivingResult) error {
	if !silent {
		color.Cyan("\n🥷 LIVING-OFF-THE-LAND RESULTS")
		color.Cyan("=" + strings.Repeat("=", 50))

		// Summary
		color.White("Target: %s", result.GetTarget().GetAddress())
		color.White("Available Binaries: %d", len(result.AvailableBinaries))
		color.White("Executed Techniques: %d", len(result.ExecutedTechniques))
		color.White("Successful Chains: %d", len(result.SuccessfulChains))
		color.White("Detection Risk: %s", getDetectionLevelString(result.DetectionRisk))

		// Available binaries
		if len(result.AvailableBinaries) > 0 {
			color.Cyan("\n🔧 Available LOLBins:")
			color.Cyan("-" + strings.Repeat("-", 60))

			for _, binary := range result.AvailableBinaries {
				color.Blue("📦 %s", binary.Name)
				color.White("   Path: %s", binary.Path)
				color.White("   Description: %s", binary.Description)
				color.White("   Detection Risk: %s", getDetectionLevelString(binary.DetectionRisk))
				
				if len(binary.Techniques) > 0 {
					techniqueStrs := make([]string, len(binary.Techniques))
					for i, tech := range binary.Techniques {
						techniqueStrs[i] = getTechniqueTypeString(tech)
					}
					color.White("   Techniques: %s", strings.Join(techniqueStrs, ", "))
				}
				fmt.Println()
			}
		}

		// Executed techniques
		if len(result.ExecutedTechniques) > 0 {
			color.Green("\n✅ Executed Techniques:")
			color.Green("-" + strings.Repeat("-", 60))

			successCount := 0
			for _, technique := range result.ExecutedTechniques {
				statusColor := color.New(color.FgRed)
				statusSymbol := "❌"
				if technique.Success {
					statusColor = color.New(color.FgGreen)
					statusSymbol = "✅"
					successCount++
				}

				statusColor.Printf("%s %s (%s)\n", statusSymbol, technique.Name, technique.Binary.Name)
				color.White("   Type: %s", getTechniqueTypeString(technique.Type))
				color.White("   Detection Risk: %s", getDetectionLevelString(technique.DetectionRisk))
				
				if technique.Command.Template != "" {
					color.Yellow("   Command: %s", technique.Command.Template)
				}
				
				if technique.Success && technique.Output != "" {
					// Truncate long output
					output := technique.Output
					if len(output) > 200 {
						output = output[:200] + "..."
					}
					color.White("   Output: %s", strings.ReplaceAll(output, "\n", "\\n"))
				}
				
				if technique.MITRE_ID != "" {
					color.Blue("   MITRE: %s", technique.MITRE_ID)
				}
				
				fmt.Println()
			}

			// Success rate
			successRate := float64(successCount) / float64(len(result.ExecutedTechniques)) * 100
			color.Yellow("Success Rate: %.1f%% (%d/%d)", successRate, successCount, len(result.ExecutedTechniques))
		}

		// Attack chains
		if len(result.SuccessfulChains) > 0 {
			color.Magenta("\n⛓️ Successful Attack Chains:")
			color.Magenta("-" + strings.Repeat("-", 60))

			for _, chain := range result.SuccessfulChains {
				color.Magenta("🔗 %s", chain.Name)
				color.White("   Description: %s", chain.Description)
				color.White("   Techniques: %d", len(chain.Techniques))
				color.White("   Timeline: %d steps", len(chain.Timeline))
				
				if len(chain.Timeline) > 0 {
					color.Yellow("   Execution Timeline:")
					for i, step := range chain.Timeline {
						statusSymbol := "❌"
						if step.Success {
							statusSymbol = "✅"
						}
						color.Yellow("     %d. %s %s", i+1, statusSymbol, step.TechniqueID)
					}
				}
				
				fmt.Println()
			}
		}

		// Risk assessment
		color.Cyan("\n📊 DETECTION RISK ASSESSMENT:")
		detectionColor := getDetectionColor(result.DetectionRisk)
		detectionColor.Printf("Overall Detection Risk: %s\n", getDetectionLevelString(result.DetectionRisk))
		
		if result.DetectionRisk <= 1 { // DetectionLow or below
			color.Green("🏆 EXCELLENT STEALTH - Minimal detection probability!")
		} else if result.DetectionRisk <= 2 { // DetectionMedium
			color.Yellow("⚠️ MODERATE RISK - Some techniques may be detected")
		} else {
			color.Red("🚨 HIGH RISK - Consider additional evasion measures")
		}
	}

	return nil
}

// saveLOLBinsResults saves LOLBins execution results
func saveLOLBinsResults(result *lolbins.LivingResult, format, filename string) error {
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

		fmt.Fprintf(file, "LIVING-OFF-THE-LAND RESULTS\n")
		fmt.Fprintf(file, "===========================\n\n")
		fmt.Fprintf(file, "Target: %s\n", result.GetTarget().GetAddress())
		fmt.Fprintf(file, "Timestamp: %s\n", result.GetTimestamp().Format("2006-01-02 15:04:05"))
		fmt.Fprintf(file, "Available Binaries: %d\n", len(result.AvailableBinaries))
		fmt.Fprintf(file, "Executed Techniques: %d\n", len(result.ExecutedTechniques))
		fmt.Fprintf(file, "Successful Chains: %d\n", len(result.SuccessfulChains))
		fmt.Fprintf(file, "Detection Risk: %s\n\n", getDetectionLevelString(result.DetectionRisk))

		// Available binaries
		fmt.Fprintf(file, "AVAILABLE LOLBINS:\n")
		fmt.Fprintf(file, "-----------------\n")
		for i, binary := range result.AvailableBinaries {
			fmt.Fprintf(file, "[%d] %s\n", i+1, binary.Name)
			fmt.Fprintf(file, "    Path: %s\n", binary.Path)
			fmt.Fprintf(file, "    Description: %s\n", binary.Description)
			fmt.Fprintf(file, "    Detection Risk: %s\n", getDetectionLevelString(binary.DetectionRisk))
			fmt.Fprintf(file, "\n")
		}

		// Executed techniques
		fmt.Fprintf(file, "EXECUTED TECHNIQUES:\n")
		fmt.Fprintf(file, "-------------------\n")
		for i, technique := range result.ExecutedTechniques {
			status := "FAILED"
			if technique.Success {
				status = "SUCCESS"
			}
			fmt.Fprintf(file, "[%d] %s - %s\n", i+1, technique.Name, status)
			fmt.Fprintf(file, "    Type: %s\n", getTechniqueTypeString(technique.Type))
			fmt.Fprintf(file, "    Binary: %s\n", technique.Binary.Name)
			fmt.Fprintf(file, "    Detection Risk: %s\n", getDetectionLevelString(technique.DetectionRisk))
			if technique.Command.Template != "" {
				fmt.Fprintf(file, "    Command: %s\n", technique.Command.Template)
			}
			fmt.Fprintf(file, "\n")
		}

		return nil

	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// Helper functions
func getDetectionLevelString(level lolbins.DetectionLevel) string {
	switch level {
	case 0: // DetectionVeryLow
		return "VERY LOW"
	case 1: // DetectionLow
		return "LOW"
	case 2: // DetectionMedium
		return "MEDIUM"
	case 3: // DetectionHigh
		return "HIGH"
	case 4: // DetectionCritical
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func getDetectionColor(level lolbins.DetectionLevel) *color.Color {
	switch level {
	case 0, 1: // DetectionVeryLow, DetectionLow
		return color.New(color.FgGreen)
	case 2: // DetectionMedium
		return color.New(color.FgYellow)
	case 3, 4: // DetectionHigh, DetectionCritical
		return color.New(color.FgRed)
	default:
		return color.New(color.FgWhite)
	}
}

func getTechniqueTypeString(techType lolbins.TechniqueType) string {
	switch techType {
	case 0: // TechniqueFileDownload
		return "File Download"
	case 1: // TechniqueFileUpload
		return "File Upload"
	case 2: // TechniqueCommandExecution
		return "Command Execution"
	case 3: // TechniqueDataExfiltration
		return "Data Exfiltration"
	case 4: // TechniqueReconnaissance
		return "Reconnaissance"
	case 5: // TechniquePersistence
		return "Persistence"
	case 6: // TechniquePrivilegeEscalation
		return "Privilege Escalation"
	case 7: // TechniqueDefenseEvasion
		return "Defense Evasion"
	case 8: // TechniqueLateralMovement
		return "Lateral Movement"
	case 9: // TechniqueCredentialAccess
		return "Credential Access"
	case 10: // TechniqueCodeExecution
		return "Code Execution"
	case 11: // TechniqueProcessInjection
		return "Process Injection"
	default:
		return "Unknown"
	}
}