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
	"recon-toolkit/pkg/forensics"
)

var (
	yaraFile        string
	yaraDir         string
	yaraRulesPath   string
	yaraPid         int
	yaraOutput      string
	yaraFormat      string
	yaraQuarantine  string
	yaraCategory    string
	yaraMinSeverity string
	yaraAutoQuarantine bool
)

var yaraCmd = &cobra.Command{
	Use:   "yara",
	Short: "🔍 YARA malware detection and forensics engine",
	Long: `🔍 YARA FORENSICS MODULE - Advanced Malware Detection

YARA-based malware detection and forensics analysis:

🦠 MALWARE DETECTION:
  • Built-in malware signatures (ransomware, cryptominers, trojans)
  • Web shell detection for compromised servers
  • Suspicious PowerShell and script analysis
  • Memory-resident threat hunting
  • Custom rule support (.yar/.yara files)

🔬 FORENSICS CAPABILITIES:
  • File system scanning with deep analysis
  • Process memory inspection and dump analysis
  • IOC (Indicator of Compromise) matching
  • Threat intelligence correlation
  • Automated quarantine and response

🎯 DETECTION CATEGORIES:
  • Malware: Trojans, backdoors, RATs, PUPs
  • Ransomware: File encryptors and screen lockers  
  • Cryptominers: XMRig, CPU/GPU mining malware
  • Web Shells: PHP, ASP, JSP backdoors
  • PowerShell: Encoded commands, suspicious scripts
  • APT: Advanced persistent threat indicators

🤖 AUTOMATION:
  • Real-time file system monitoring
  • Automatic threat classification
  • Risk scoring and prioritization
  • Quarantine integration
  • Incident response workflows

Examples:
  recon-toolkit yara --file /path/to/suspicious.exe
  recon-toolkit yara --dir /var/www/html --category webshell
  recon-toolkit yara --pid 1234 --memory-scan
  recon-toolkit yara --dir /tmp --auto-quarantine
  recon-toolkit yara --rules-path ./custom-rules --dir /home`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if yaraFile == "" && yaraDir == "" && yaraPid == 0 {
			return fmt.Errorf("specify --file, --dir, or --pid for scanning")
		}

		if !silent {
			color.Red("🔍 YARA FORENSICS MODULE ACTIVATED")
			if yaraFile != "" {
				color.Yellow("Target File: %s", yaraFile)
			}
			if yaraDir != "" {
				color.Yellow("Target Directory: %s", yaraDir)
			}
			if yaraPid != 0 {
				color.Yellow("Target Process: PID %d", yaraPid)
			}
			if yaraCategory != "" {
				color.Yellow("Category Filter: %s", yaraCategory)
			}
			if yaraAutoQuarantine {
				color.Red("🚨 AUTO-QUARANTINE MODE ENABLED")
			}
		}

		// Initialize YARA engine
		config := &forensics.YaraConfig{
			RulesPath:     yaraRulesPath,
			MaxFileSize:   100 * 1024 * 1024, // 100MB
			MaxConcurrent: threads,
			EnableCache:   true,
		}

		logger := logrus.New()
		if silent {
			logger.SetLevel(logrus.ErrorLevel)
		}

		yaraEngine := forensics.NewYaraEngine(logger, config)

		// Load custom rules if specified
		if yaraRulesPath != "" {
			if err := yaraEngine.LoadRulesFromDirectory(yaraRulesPath); err != nil {
				color.Yellow("Warning: Could not load custom rules from %s: %v", yaraRulesPath, err)
			}
		}

		ctx := context.Background()
		var results []*forensics.ScanResult

		// Perform scanning based on target type
		if yaraFile != "" {
			// Single file scan
			if !silent {
				color.Cyan("🔍 Scanning file: %s", yaraFile)
			}

			result, err := yaraEngine.ScanFile(ctx, yaraFile)
			if err != nil {
				return fmt.Errorf("file scan failed: %w", err)
			}

			if len(result.Matches) > 0 {
				results = append(results, result)
			}

		} else if yaraDir != "" {
			// Directory scan
			if !silent {
				color.Cyan("🔍 Scanning directory: %s", yaraDir)
			}

			dirResults, err := yaraEngine.ScanDirectory(ctx, yaraDir)
			if err != nil {
				return fmt.Errorf("directory scan failed: %w", err)
			}

			results = dirResults

		} else if yaraPid != 0 {
			// Process memory scan
			if !silent {
				color.Cyan("🔍 Scanning process memory: PID %d", yaraPid)
			}

			result, err := yaraEngine.ScanProcessMemory(ctx, yaraPid)
			if err != nil {
				return fmt.Errorf("process scan failed: %w", err)
			}

			if len(result.Matches) > 0 {
				results = append(results, result)
			}
		}

		// Filter results by category and severity
		filteredResults := filterYaraResults(results, yaraCategory, yaraMinSeverity)

		// Display results
		err := displayYaraResults(filteredResults)
		if err != nil {
			return fmt.Errorf("failed to display results: %w", err)
		}

		// Auto-quarantine if enabled
		if yaraAutoQuarantine && yaraQuarantine != "" {
			quarantineCount := 0
			for _, result := range filteredResults {
				for _, match := range result.Matches {
					if match.Severity == "CRITICAL" || match.Severity == "HIGH" {
						err := yaraEngine.QuarantineFile(result.FilePath, yaraQuarantine)
						if err != nil {
							color.Red("Failed to quarantine %s: %v", result.FilePath, err)
						} else {
							quarantineCount++
							color.Red("🚨 QUARANTINED: %s", result.FilePath)
						}
						break
					}
				}
			}
			if quarantineCount > 0 && !silent {
				color.Red("🚨 %d files quarantined to: %s", quarantineCount, yaraQuarantine)
			}
		}

		// Save results if output specified
		if yaraOutput != "" {
			err = saveYaraResults(filteredResults, yaraFormat, yaraOutput)
			if err != nil {
				color.Red("Failed to save results: %v", err)
			} else if !silent {
				color.Green("💾 Results saved to: %s", yaraOutput)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(yaraCmd)

	yaraCmd.Flags().StringVar(&yaraFile, "file", "", "Single file to scan")
	yaraCmd.Flags().StringVar(&yaraDir, "dir", "", "Directory to scan recursively")
	yaraCmd.Flags().StringVar(&yaraRulesPath, "rules-path", "", "Path to custom YARA rules directory")
	yaraCmd.Flags().IntVar(&yaraPid, "pid", 0, "Process ID for memory scanning")
	yaraCmd.Flags().StringVar(&yaraOutput, "output", "", "Output file path")
	yaraCmd.Flags().StringVar(&yaraFormat, "format", "json", "Output format (json, text)")
	yaraCmd.Flags().StringVar(&yaraQuarantine, "quarantine", "/tmp/quarantine", "Quarantine directory path")
	yaraCmd.Flags().StringVar(&yaraCategory, "category", "", "Filter by rule category (malware, webshell, ransomware, etc.)")
	yaraCmd.Flags().StringVar(&yaraMinSeverity, "severity", "LOW", "Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)")
	yaraCmd.Flags().BoolVar(&yaraAutoQuarantine, "auto-quarantine", false, "Automatically quarantine detected threats")
}

// filterYaraResults filters results by category and severity
func filterYaraResults(results []*forensics.ScanResult, category, minSeverity string) []*forensics.ScanResult {
	if category == "" && minSeverity == "LOW" {
		return results
	}

	var filtered []*forensics.ScanResult
	minSevScore := getSeverityScore(minSeverity)

	for _, result := range results {
		filteredMatches := []*forensics.RuleMatch{}

		for _, match := range result.Matches {
			include := true

			// Filter by category
			if category != "" && !strings.EqualFold(match.Category, category) {
				include = false
			}

			// Filter by severity
			if getSeverityScore(match.Severity) < minSevScore {
				include = false
			}

			if include {
				filteredMatches = append(filteredMatches, match)
			}
		}

		if len(filteredMatches) > 0 {
			resultCopy := *result
			resultCopy.Matches = filteredMatches
			filtered = append(filtered, &resultCopy)
		}
	}

	return filtered
}

// getSeverityScore converts severity to numeric score
func getSeverityScore(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// displayYaraResults displays YARA scan results
func displayYaraResults(results []*forensics.ScanResult) error {
	if !silent {
		color.Cyan("\n🎯 YARA SCAN RESULTS")
		color.Cyan("=" + strings.Repeat("=", 50))

		totalMatches := 0
		criticalCount := 0
		highCount := 0
		mediumCount := 0
		lowCount := 0

		for _, result := range results {
			totalMatches += len(result.Matches)
			for _, match := range result.Matches {
				switch match.Severity {
				case "CRITICAL":
					criticalCount++
				case "HIGH":
					highCount++
				case "MEDIUM":
					mediumCount++
				case "LOW":
					lowCount++
				}
			}
		}

		color.White("Files Scanned: %d", len(results))
		color.White("Total Detections: %d", totalMatches)
		color.Red("Critical: %d", criticalCount)
		color.Red("High: %d", highCount)
		color.Yellow("Medium: %d", mediumCount)
		color.Green("Low: %d", lowCount)

		// Display detailed results
		for _, result := range results {
			if len(result.Matches) == 0 {
				continue
			}

			color.Cyan("\n📂 %s", result.FilePath)
			color.Blue("Size: %d bytes | Hash: %s | Scan Time: %v", 
				result.FileSize, result.FileHash[:16]+"...", result.ScanTime)
			color.Cyan("-" + strings.Repeat("-", 70))

			for _, match := range result.Matches {
				severityColor := color.New(color.FgYellow)
				switch match.Severity {
				case "CRITICAL":
					severityColor = color.New(color.FgRed, color.Bold)
				case "HIGH":
					severityColor = color.New(color.FgRed)
				case "MEDIUM":
					severityColor = color.New(color.FgYellow)
				case "LOW":
					severityColor = color.New(color.FgGreen)
				}

				severityColor.Printf("🚨 %s ", match.RuleName)
				fmt.Printf("(%s, %s, Confidence: %d%%)\n", match.Category, match.Severity, match.Confidence)
				color.White("   %s", match.Description)

				// Show tags
				if len(match.Tags) > 0 {
					color.Blue("   Tags: %s", strings.Join(match.Tags, ", "))
				}

				// Show string matches
				if len(match.Matches) > 0 {
					color.Yellow("   Pattern Matches:")
					for i, stringMatch := range match.Matches {
						if i >= 3 { // Limit display to first 3 matches
							color.Yellow("     ... and %d more matches", len(match.Matches)-3)
							break
						}
						color.Yellow("     • %s at offset %d: %s", 
							stringMatch.Name, stringMatch.Offset, 
							truncateString(stringMatch.Context, 60))
					}
				}

				fmt.Println()
			}
		}

		if len(results) == 0 {
			color.Green("\n✅ No threats detected - all files appear clean")
		}
	}

	return nil
}

// truncateString truncates a string to specified length
func truncateString(s string, maxLen int) string {
	// Remove newlines and tabs for display
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// saveYaraResults saves YARA results to file
func saveYaraResults(results []*forensics.ScanResult, format, filename string) error {
	switch format {
	case "json":
		data, err := json.MarshalIndent(results, "", "  ")
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

		fmt.Fprintf(file, "YARA FORENSICS SCAN RESULTS\n")
		fmt.Fprintf(file, "===========================\n\n")
		fmt.Fprintf(file, "Scan completed: %s\n", results[0].Timestamp.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(file, "Files with detections: %d\n\n", len(results))

		for _, result := range results {
			fmt.Fprintf(file, "File: %s\n", result.FilePath)
			fmt.Fprintf(file, "Size: %d bytes\n", result.FileSize)
			fmt.Fprintf(file, "MD5: %s\n", result.FileHash)
			fmt.Fprintf(file, "Scan Time: %v\n", result.ScanTime)
			fmt.Fprintf(file, "Detections: %d\n\n", len(result.Matches))

			for _, match := range result.Matches {
				fmt.Fprintf(file, "  Rule: %s\n", match.RuleName)
				fmt.Fprintf(file, "  Category: %s\n", match.Category)
				fmt.Fprintf(file, "  Severity: %s\n", match.Severity)
				fmt.Fprintf(file, "  Confidence: %d%%\n", match.Confidence)
				fmt.Fprintf(file, "  Description: %s\n", match.Description)
				
				if len(match.Tags) > 0 {
					fmt.Fprintf(file, "  Tags: %s\n", strings.Join(match.Tags, ", "))
				}

				if len(match.Matches) > 0 {
					fmt.Fprintf(file, "  Pattern Matches:\n")
					for _, stringMatch := range match.Matches {
						fmt.Fprintf(file, "    - %s at offset %d\n", stringMatch.Name, stringMatch.Offset)
					}
				}

				fmt.Fprintf(file, "\n")
			}

			fmt.Fprintf(file, "---\n\n")
		}

		return nil

	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}