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
	"recon-toolkit/pkg/intel"
	"recon-toolkit/pkg/scanner"
)

var (
	cveService     string
	cveVersion     string
	cveMinSeverity string
	cveOutput      string
	cveFormat      string
	cveExploitOnly bool
	cveInWildOnly  bool
	cveGithubToken string
	cveEnableAll   bool
)

var cveCmd = &cobra.Command{
	Use:   "cve",
	Short: "🔍 [DEPRECATED] Use 'cve-new' - Legacy CVE scanner",
	Long: `⚠️  DEPRECATED CVE SCANNER - Use 'cve-new' instead

This legacy CVE scanner has been replaced with the new OSV.dev integrated version
that provides zero false-positive vulnerability detection.

🔄 MIGRATION:
  Old: rtk cve --service nginx --version 1.18.0
  New: rtk cve-new --service nginx --version 1.18.0

✅ ADVANTAGES OF NEW SCANNER:
  • Zero false-positive rate (no future CVEs like CVE-2025-XXXX)
  • Real OSV.dev database integration
  • Professional validation methodology
  • BoltDB caching for offline use
  • SARIF output format support

⚠️  This command will be removed in v2.3.0`,

	RunE: func(cmd *cobra.Command, args []string) error {
		// Display deprecation warning
		color.Yellow("⚠️  DEPRECATED: This CVE scanner is deprecated!")
		color.Yellow("   Please use 'rtk cve-new' for zero false-positive scanning")
		color.Yellow("   Example: rtk cve-new --target %s", target)
		fmt.Println()
		
		// Still allow legacy functionality but warn user
		if target == "" && cveService == "" {
			return fmt.Errorf("target (-t) or service (--service) is required")
		}

		if !silent {
			color.Red("🔍 [LEGACY] CVE INTELLIGENCE MODULE ACTIVATED")
			color.Yellow("⚠️  WARNING: This scanner may produce false positives!")
			if target != "" {
				color.Yellow("Target: %s", target)
			}
			if cveService != "" {
				color.Yellow("Service: %s %s", cveService, cveVersion)
			}
			color.Yellow("Min Severity: %s", cveMinSeverity)
			if cveExploitOnly {
				color.Red("🚨 EXPLOIT-ONLY MODE")
			}
			if cveInWildOnly {
				color.Red("🚨 IN-THE-WILD ONLY MODE")
			}
		}

		// Configure CVE engine
		config := &intel.CVEConfig{
			EnableNVD:       true,
			EnableExploitDB: true,
			EnableGithub:    cveGithubToken != "",
			MaxConcurrent:   10,
			Severity:        cveMinSeverity,
		}

		if cveEnableAll {
			config.EnableNVD = true
			config.EnableExploitDB = true
			config.EnableGithub = true
		}

		logger := logrus.New()
		cveEngine := intel.NewCVEEngine(logger, config)
		if cveGithubToken != "" {
			cveEngine.SetGitHubToken(cveGithubToken)
		}

		ctx := context.Background()
		var services []intel.ServiceMatch

		if target != "" {
			// Scan target for services first
			if !silent {
				color.Cyan("🔍 Discovering services on target...")
			}

			services = scanTargetServices(ctx, target)
		} else {
			// Manual service specification
			service := intel.ServiceMatch{
				Service: cveService,
				Version: cveVersion,
				Port:    80, // Default port
			}
			services = []intel.ServiceMatch{service}
		}

		if len(services) == 0 {
			color.Yellow("No services detected for CVE analysis")
			return nil
		}

		if !silent {
			color.Cyan("🎯 Scanning %d services for known CVEs...", len(services))
		}

		// Scan services for CVEs
		results, err := cveEngine.ScanServices(ctx, services)
		if err != nil {
			return fmt.Errorf("CVE scan failed: %w", err)
		}

		// Filter results based on flags
		filteredResults := filterCVEResults(results, cveExploitOnly, cveInWildOnly)

		// Display results
		err = displayCVEResults(filteredResults)
		if err != nil {
			return fmt.Errorf("failed to display results: %w", err)
		}

		// Save results if output specified
		if cveOutput != "" {
			err = saveCVEResults(filteredResults, cveFormat, cveOutput)
			if err != nil {
				color.Red("Failed to save results: %v", err)
			} else if !silent {
				color.Green("💾 Results saved to: %s", cveOutput)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(cveCmd)

	cveCmd.Flags().StringVar(&cveService, "service", "", "Service name to check (e.g., 'Apache httpd', 'nginx')")
	cveCmd.Flags().StringVar(&cveVersion, "version", "", "Service version (e.g., '2.4.41')")
	cveCmd.Flags().StringVar(&cveMinSeverity, "severity", "MEDIUM", "Minimum severity (LOW, MEDIUM, HIGH, CRITICAL)")
	cveCmd.Flags().StringVar(&cveOutput, "output", "", "Output file path")
	cveCmd.Flags().StringVar(&cveFormat, "format", "json", "Output format (json, text)")
	cveCmd.Flags().BoolVar(&cveExploitOnly, "exploit-only", false, "Show only CVEs with available exploits")
	cveCmd.Flags().BoolVar(&cveInWildOnly, "in-wild-only", false, "Show only CVEs being exploited in the wild")
	cveCmd.Flags().StringVar(&cveGithubToken, "github-token", "", "GitHub API token for PoC searching")
	cveCmd.Flags().BoolVar(&cveEnableAll, "enable-all", false, "Enable all CVE sources")
}

// scanTargetServices discovers services on the target
func scanTargetServices(ctx context.Context, target string) []intel.ServiceMatch {
	// Common ports to check for services
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 6379, 27017}
	
	// Use existing scanner to discover services
	portScanner := scanner.NewScanner(target, commonPorts, scanner.WithSilent())
	
	// Scan ports
	result, err := portScanner.Scan(ctx)
	if err != nil {
		color.Yellow("Port scan failed: %v", err)
		return nil
	}

	var services []intel.ServiceMatch
	for _, portResult := range result.Ports {
		if portResult.State == "open" && portResult.Service != "" {
			service := intel.ServiceMatch{
				Service: portResult.Service,
				Version: portResult.Version,
				Port:    portResult.Port,
			}
			services = append(services, service)
		}
	}

	return services
}

// filterCVEResults filters results based on user preferences
func filterCVEResults(results []*intel.ServiceMatch, exploitOnly, inWildOnly bool) []*intel.ServiceMatch {
	var filtered []*intel.ServiceMatch

	for _, service := range results {
		if len(service.MatchedCVEs) == 0 {
			continue
		}

		// Filter CVEs within the service
		var filteredCVEs []*intel.CVEData
		for _, cve := range service.MatchedCVEs {
			include := true

			if exploitOnly && !cve.Weaponized {
				include = false
			}

			if inWildOnly && !cve.InTheWild {
				include = false
			}

			if include {
				filteredCVEs = append(filteredCVEs, cve)
			}
		}

		if len(filteredCVEs) > 0 {
			serviceCopy := *service
			serviceCopy.MatchedCVEs = filteredCVEs
			filtered = append(filtered, &serviceCopy)
		}
	}

	return filtered
}

// displayCVEResults displays CVE scan results
func displayCVEResults(results []*intel.ServiceMatch) error {
	if !silent {
		color.Cyan("\n🎯 CVE SCAN RESULTS")
		color.Cyan("=" + strings.Repeat("=", 50))

		totalCVEs := 0
		totalExploits := 0
		totalInWild := 0

		for _, service := range results {
			totalCVEs += len(service.MatchedCVEs)
			for _, cve := range service.MatchedCVEs {
				if cve.Weaponized {
					totalExploits++
				}
				if cve.InTheWild {
					totalInWild++
				}
			}
		}

		color.White("Services Analyzed: %d", len(results))
		color.White("Total CVEs Found: %d", totalCVEs)
		color.Red("Weaponized CVEs: %d", totalExploits)
		color.Red("In-the-wild CVEs: %d", totalInWild)

		// Display detailed results
		for _, service := range results {
			if len(service.MatchedCVEs) == 0 {
				continue
			}

			color.Cyan("\n🔍 %s %s (Port %d)", service.Service, service.Version, service.Port)
			color.Cyan("Risk Score: %d", service.RiskScore)
			color.Cyan("-" + strings.Repeat("-", 60))

			for _, cve := range service.MatchedCVEs {
				severityColor := color.New(color.FgYellow)
				switch cve.Severity {
				case "CRITICAL":
					severityColor = color.New(color.FgRed, color.Bold)
				case "HIGH":
					severityColor = color.New(color.FgRed)
				case "MEDIUM":
					severityColor = color.New(color.FgYellow)
				case "LOW":
					severityColor = color.New(color.FgGreen)
				}

				severityColor.Printf("📋 %s ", cve.ID)
				fmt.Printf("(CVSS: %.1f, %s)\n", cve.CVSS, cve.Severity)
				color.White("   %s", cve.Description)

				if cve.Weaponized {
					color.Red("   💀 WEAPONIZED")
				}
				if cve.InTheWild {
					color.Red("   🚨 IN THE WILD")
				}

				// Show exploits
				if len(cve.Exploits) > 0 {
					color.Red("   🔥 Available Exploits:")
					for _, exploit := range cve.Exploits {
						color.Red("     • %s (%s)", exploit.Title, exploit.Type)
						if exploit.URL != "" {
							color.Blue("       %s", exploit.URL)
						}
					}
				}

				// Show PoCs
				if len(cve.PoCs) > 0 {
					color.Yellow("   📝 Proof-of-Concepts:")
					for _, poc := range cve.PoCs {
						color.Yellow("     • %s (%s) - %s", poc.URL, poc.Language, poc.Reliability)
						if poc.Stars > 0 {
							color.Yellow("       ⭐ %d stars, %d forks", poc.Stars, poc.Forks)
						}
					}
				}

				fmt.Println()
			}
		}
	}

	return nil
}

// saveCVEResults saves CVE results to file
func saveCVEResults(results []*intel.ServiceMatch, format, filename string) error {
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

		fmt.Fprintf(file, "CVE SCAN RESULTS\n")
		fmt.Fprintf(file, "================\n\n")

		for _, service := range results {
			fmt.Fprintf(file, "Service: %s %s (Port %d)\n", service.Service, service.Version, service.Port)
			fmt.Fprintf(file, "Risk Score: %d\n", service.RiskScore)
			fmt.Fprintf(file, "CVEs Found: %d\n\n", len(service.MatchedCVEs))

			for _, cve := range service.MatchedCVEs {
				fmt.Fprintf(file, "  %s (CVSS: %.1f, %s)\n", cve.ID, cve.CVSS, cve.Severity)
				fmt.Fprintf(file, "  Description: %s\n", cve.Description)
				
				if cve.Weaponized {
					fmt.Fprintf(file, "  Status: WEAPONIZED\n")
				}
				if cve.InTheWild {
					fmt.Fprintf(file, "  Status: IN THE WILD\n")
				}

				if len(cve.Exploits) > 0 {
					fmt.Fprintf(file, "  Exploits:\n")
					for _, exploit := range cve.Exploits {
						fmt.Fprintf(file, "    - %s (%s)\n", exploit.Title, exploit.Type)
					}
				}

				fmt.Fprintf(file, "\n")
			}
		}

		return nil

	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}