package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"recon-toolkit/pkg/cloud"
)

var (
	cloudAggressive bool
	cloudThreads    int
	cloudTimeout    int
	cloudOutput     string
)

var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "☁️ Advanced cloud infrastructure scanner",
	Long: `☁️ CLOUD INFRASTRUCTURE SCANNER - Multi-Provider Asset Discovery

Advanced cloud security assessment across all major providers:

🌩️ SUPPORTED PROVIDERS:
  • Amazon Web Services (AWS)
  • Microsoft Azure
  • Google Cloud Platform (GCP)
  • DigitalOcean
  • Vultr

🔍 DISCOVERY CAPABILITIES:
  • Subdomain enumeration for cloud services
  • Service-specific endpoint discovery
  • Metadata service exposure detection
  • Credential and configuration file hunting
  • Misconfiguration identification

🚨 SECURITY CHECKS:
  • Exposed S3 buckets and storage accounts
  • Unsecured databases and APIs
  • IAM misconfigurations
  • Container service exposures
  • Serverless function discoveries

⚡ ADVANCED FEATURES:
  • Multi-threaded scanning
  • Intelligent service detection
  • Risk assessment and prioritization
  • Comprehensive reporting

Examples:
  recon-toolkit cloud -t company.com --aggressive
  recon-toolkit cloud -t https://target.com --threads 50 --timeout 20
  recon-toolkit cloud -t example.org --output cloud_assets.json`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target is required")
		}

		ctx := context.Background()

		if !silent {
			color.Red("☁️ CLOUD INFRASTRUCTURE SCANNER ACTIVATED")
			color.Yellow("Target: %s", target)
			color.Yellow("Threads: %d", cloudThreads)
			color.Yellow("Timeout: %ds", cloudTimeout)
			
			if cloudAggressive {
				color.Red("🚨 AGGRESSIVE MODE")
			}
		}

		// Configure cloud scanner
		options := []func(*cloud.CloudScanner){
			cloud.WithThreads(cloudThreads),
		}

		if cloudAggressive {
			options = append(options, cloud.WithAggressive())
		}

		// Create scanner
		cloudScanner := cloud.NewCloudScanner(target, options...)

		// Execute scan
		if !silent {
			color.Cyan("🚀 Starting cloud infrastructure discovery...")
			fmt.Println()
		}

		start := time.Now()
		assets, err := cloudScanner.Scan(ctx)
		duration := time.Since(start)

		if err != nil {
			color.Red("❌ Cloud scan failed: %v", err)
			return err
		}

		// Display results
		if !silent {
			displayCloudResults(cloudScanner, assets, duration)
		}

		// Save results
		if cloudOutput != "" {
			err = saveCloudResults(assets, cloudOutput)
			if err != nil {
				color.Red("Failed to save results: %v", err)
			} else {
				color.Green("📊 Results saved: %s", cloudOutput)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(cloudCmd)

	cloudCmd.Flags().BoolVar(&cloudAggressive, "aggressive", false, "Enable aggressive scanning")
	cloudCmd.Flags().IntVar(&cloudThreads, "threads", 20, "Number of concurrent threads")
	cloudCmd.Flags().IntVar(&cloudTimeout, "timeout", 10, "Request timeout in seconds")
	cloudCmd.Flags().StringVar(&cloudOutput, "output", "", "Output file for results")
}

func displayCloudResults(cs *cloud.CloudScanner, assets []*cloud.CloudAsset, duration time.Duration) {
	stats := cs.GetStats()
	
	color.Cyan("\n☁️ CLOUD INFRASTRUCTURE RESULTS")
	color.Cyan("=" + strings.Repeat("=", 45))
	
	color.White("Duration: %v", duration)
	color.White("Total Assets: %d", stats["total_assets"])
	color.White("Vulnerable Assets: %d", stats["vulnerable_assets"])
	color.White("Exposed Assets: %d", stats["exposed_assets"])
	
	// Provider breakdown
	if providerCounts, ok := stats["provider_counts"].(map[cloud.CloudProvider]int); ok && len(providerCounts) > 0 {
		color.Cyan("\n🌩️ PROVIDER BREAKDOWN:")
		for provider, count := range providerCounts {
			emoji := getProviderEmoji(provider)
			color.White("%s %s: %d assets", emoji, provider, count)
		}
	}
	
	// Risk assessment
	if riskCounts, ok := stats["risk_counts"].(map[string]int); ok {
		color.Cyan("\n⚠️ RISK ASSESSMENT:")
		for risk, count := range riskCounts {
			switch risk {
			case "CRITICAL":
				color.Red("💀 %s: %d", risk, count)
			case "HIGH":
				color.Red("🔥 %s: %d", risk, count)
			case "MEDIUM":
				color.Yellow("⚠️ %s: %d", risk, count)
			case "LOW":
				color.Green("ℹ️ %s: %d", risk, count)
			}
		}
	}
	
	// Critical findings
	criticalAssets := getCriticalAssets(assets)
	if len(criticalAssets) > 0 {
		color.Red("\n💀 CRITICAL FINDINGS:")
		for _, asset := range criticalAssets {
			if len(asset.Exploitable) > 0 {
				color.Red("  🔥 Direct access to cloud services found: %s", asset.Service)
				color.Red("    🎯 %s", asset.URL)
				for _, exploit := range asset.Exploitable {
					color.Red("    💥 %s", exploit)
				}
			}
		}
	}
	
	// Exposed services
	exposedAssets := getExposedAssets(assets)
	if len(exposedAssets) > 0 && len(exposedAssets) != len(criticalAssets) {
		color.Yellow("\n🔓 EXPOSED SERVICES:")
		for i, asset := range exposedAssets {
			if i >= 10 { // Show max 10
				break
			}
			if asset.Risk != "CRITICAL" {
				color.Yellow("  🌐 %s - %s (%s)", asset.Service, asset.URL, asset.Risk)
			}
		}
	}
	
	// Cynical assessment
	color.Cyan("\n🎭 CYNICAL ASSESSMENT:")
	totalAssets := len(assets)
	vulnerableCount := stats["vulnerable_assets"].(int)
	exposedCount := stats["exposed_assets"].(int)
	
	if len(criticalAssets) > 0 {
		color.Red("🖕 Holy shit! This cloud is leakier than a fucking sieve!")
		color.Red("💀 DevOps team should be fired immediately")
	} else if exposedCount > 5 {
		color.Yellow("🎪 Decent cloud exposure - someone fucked up configurations")
		color.Yellow("🤡 Security team needs cloud training ASAP")
	} else if vulnerableCount > 0 {
		color.Green("🛡️ Some cloud assets discovered, could be worse")
		color.Green("🎯 Not terrible, but room for improvement")
	} else if totalAssets > 5 {
		color.Blue("👑 Impressive cloud security posture!")
		color.Blue("🥷 Respect to the cloud architects")
	} else {
		color.Blue("🔍 Limited cloud footprint discovered")
		color.Blue("🤔 Either well-secured or hiding in the shadows...")
	}
}

func getProviderEmoji(provider cloud.CloudProvider) string {
	emojis := map[cloud.CloudProvider]string{
		"aws":          "🟠",
		"azure":        "🔵",
		"gcp":          "🟡",
		"digitalocean": "🔷",
		"vultr":        "🟣",
	}
	
	if emoji, exists := emojis[provider]; exists {
		return emoji
	}
	return "☁️"
}

func getCriticalAssets(assets []*cloud.CloudAsset) []*cloud.CloudAsset {
	var critical []*cloud.CloudAsset
	
	for _, asset := range assets {
		if asset.Risk == "CRITICAL" {
			critical = append(critical, asset)
		}
	}
	
	return critical
}

func getExposedAssets(assets []*cloud.CloudAsset) []*cloud.CloudAsset {
	var exposed []*cloud.CloudAsset
	
	for _, asset := range assets {
		if asset.Exposed {
			exposed = append(exposed, asset)
		}
	}
	
	return exposed
}

func saveCloudResults(assets []*cloud.CloudAsset, filename string) error {
	data, err := json.MarshalIndent(assets, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(filename, data, 0644)
}