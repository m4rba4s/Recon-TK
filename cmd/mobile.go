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
	"recon-toolkit/pkg/mobile"
)

var (
	mobilePlatforms      []string
	mobileContainerScan  bool
	mobileK8sScan        bool
	mobileCloudScan      bool
	mobileAppAnalysis    bool
	mobileEscapeAttempts bool
	mobileDeepScan       bool
	mobileOutput         string
	mobileFormat         string
	mobileVerbose        bool
	mobileConcurrency    int
	mobileTimeout        int
)

var mobileCmd = &cobra.Command{
	Use:   "mobile",
	Short: "📱 Advanced mobile and cloud infrastructure scanner",
	Long: `📱 MOBILE/CLOUD INFRASTRUCTURE SCANNER

Advanced mobile application and cloud infrastructure penetration framework:

🐳 CONTAINER TECHNOLOGIES:
  • Docker - Container runtime and API exploitation
  • Kubernetes - Cluster enumeration and privilege escalation
  • Containerd - Low-level container runtime analysis
  • CRI-O - OpenShift container runtime exploitation
  • Podman - Rootless container security assessment

☁️ CLOUD PLATFORMS:
  • AWS - Amazon Web Services exploitation
  • Azure - Microsoft Azure security assessment  
  • GCP - Google Cloud Platform penetration
  • DigitalOcean - Droplet and service analysis
  • Vultr - Instance and network exploitation
  • Linode - Virtual machine security testing

📱 MOBILE PLATFORMS:
  • Android - APK analysis and runtime exploitation
  • iOS - IPA security assessment and jailbreak detection
  • React Native - Cross-platform app analysis
  • Flutter - Dart-based mobile app security
  • Xamarin - .NET mobile app assessment

🏃‍♂️ CONTAINER ESCAPE TECHNIQUES:
  • /proc/self/exe symlink manipulation
  • Privileged container breakout
  • Docker socket abuse
  • Kernel exploit-based escapes
  • Capability-based privilege escalation
  • Volume mount exploitation

⚓ KUBERNETES EXPLOITATION:
  • RBAC privilege escalation
  • Pod security policy bypass
  • Service account token abuse
  • Cluster-admin role escalation
  • Node compromise via privileged pods
  • Secret and ConfigMap enumeration

☁️ CLOUD EXPLOITATION:
  • Instance metadata service abuse (AWS/Azure/GCP)
  • IAM role and managed identity compromise
  • Service enumeration and lateral movement
  • Storage bucket and database exposure
  • Serverless function exploitation
  • API gateway security assessment

📱 MOBILE APP VULNERABILITIES:
  • Insecure data storage
  • Weak cryptographic implementations
  • Insufficient transport layer protection
  • Insecure authentication mechanisms
  • Poor session management
  • Code injection vulnerabilities

🔓 ADVANCED TECHNIQUES:
  • Multi-stage container escapes
  • Cross-platform mobile exploitation
  • Cloud service chaining attacks
  • Serverless function abuse
  • Container registry poisoning
  • Supply chain attacks

Examples:
  recon-toolkit mobile -t 192.168.1.100 --platforms docker,kubernetes
  recon-toolkit mobile -t target.com --cloud-scan --k8s-scan --escape-attempts
  recon-toolkit mobile -t app.example.com --app-analysis --deep-scan
  recon-toolkit mobile -t cluster.local --platforms all --format json -o results.json`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target is required for mobile/cloud scanning")
		}

		if !silent {
			color.Red("📱 MOBILE/CLOUD INFRASTRUCTURE SCANNER ACTIVATED")
			color.Yellow("Target: %s", target)
			if len(mobilePlatforms) > 0 {
				color.Green("🏗️ Platforms: %s", strings.Join(mobilePlatforms, ", "))
			}
			if mobileContainerScan {
				color.Green("🐳 Container Scan: ENABLED")
			}
			if mobileK8sScan {
				color.Green("⚓ Kubernetes Scan: ENABLED")
			}
			if mobileCloudScan {
				color.Green("☁️ Cloud Scan: ENABLED")
			}
			if mobileAppAnalysis {
				color.Green("📱 Mobile App Analysis: ENABLED")
			}
			if mobileEscapeAttempts {
				color.Red("🏃‍♂️ Container Escape Attempts: ENABLED")
			}
			if mobileDeepScan {
				color.Blue("🔍 Deep Scan: ENABLED")
			}
			color.Magenta("⚠️  CLOUD INFRASTRUCTURE AT RISK - MAXIMUM EXPLOITATION")
		}

		// Configure mobile/cloud engine
		config := &mobile.CloudConfig{
			Platforms:         mobilePlatforms,
			ContainerRuntimes: []string{"docker", "containerd", "cri-o"},
			CloudProviders:    []string{"aws", "azure", "gcp"},
			MaxConcurrent:     mobileConcurrency,
			DeepScan:          mobileDeepScan,
			EscapeAttempts:    mobileEscapeAttempts,
			K8sExploitation:   mobileK8sScan,
			CloudRecon:        mobileCloudScan,
			MobileAnalysis:    mobileAppAnalysis,
		}

		// If no platforms specified, use defaults
		if len(config.Platforms) == 0 {
			config.Platforms = []string{"docker", "kubernetes", "aws"}
		}

		// Setup logger
		logger := &MobileLogger{
			logger: logrus.New(),
			silent: silent,
		}
		if silent {
			logger.logger.SetLevel(logrus.ErrorLevel)
		} else if mobileVerbose {
			logger.logger.SetLevel(logrus.DebugLevel)
		}

		// Create mobile/cloud engine
		cloudEngine := mobile.NewCloudEngine(logger, config)

		// Create target
		targetObj := core.NewBaseTarget(target, core.TargetTypeHost)

		ctx := context.Background()

		if !silent {
			color.Cyan("\n📱 Initiating mobile/cloud infrastructure domination...")
			color.Cyan("🔍 Scanning for containers, clusters, and cloud services...")
		}

		// Execute cloud infrastructure domination
		result, err := cloudEngine.DominateCloudInfrastructure(ctx, targetObj)
		if err != nil {
			return fmt.Errorf("cloud domination failed: %w", err)
		}

		// Display results
		err = displayMobileResults(result)
		if err != nil {
			return fmt.Errorf("failed to display results: %w", err)
		}

		// Save results if requested
		if mobileOutput != "" {
			err = saveMobileResults(result, mobileFormat, mobileOutput)
			if err != nil {
				color.Red("Failed to save results: %v", err)
			} else if !silent {
				color.Green("💾 Results saved to: %s", mobileOutput)
			}
		}

		if !silent {
			color.Green("\n✨ Mobile/Cloud domination completed successfully")
			color.Yellow("🐳 Containers discovered: %d", len(result.DiscoveredContainers))
			color.Yellow("⚓ Kubernetes clusters: %d", len(result.KubernetesClusters))
			color.Yellow("☁️ Cloud assets: %d", len(result.CloudAssets))
			color.Yellow("📱 Mobile apps: %d", len(result.MobileApps))
			color.Red("🏃‍♂️ Successful escapes: %d", len(result.SuccessfulEscapes))
			color.Red("💀 Services exploited: %d", len(result.ExploitedServices))
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(mobileCmd)

	mobileCmd.Flags().StringSliceVar(&mobilePlatforms, "platforms", []string{}, "Platforms to scan (docker,kubernetes,aws,azure,gcp,android,ios)")
	mobileCmd.Flags().BoolVar(&mobileContainerScan, "container-scan", true, "Enable container discovery and analysis")
	mobileCmd.Flags().BoolVar(&mobileK8sScan, "k8s-scan", true, "Enable Kubernetes cluster exploitation")
	mobileCmd.Flags().BoolVar(&mobileCloudScan, "cloud-scan", true, "Enable cloud service reconnaissance")
	mobileCmd.Flags().BoolVar(&mobileAppAnalysis, "app-analysis", false, "Enable mobile app analysis")
	mobileCmd.Flags().BoolVar(&mobileEscapeAttempts, "escape-attempts", false, "Enable container escape attempts")
	mobileCmd.Flags().BoolVar(&mobileDeepScan, "deep-scan", false, "Enable deep vulnerability scanning")
	mobileCmd.Flags().StringVar(&mobileOutput, "output", "", "Output file path")
	mobileCmd.Flags().StringVar(&mobileFormat, "format", "json", "Output format (json, text)")
	mobileCmd.Flags().BoolVar(&mobileVerbose, "verbose", false, "Verbose logging output")
	mobileCmd.Flags().IntVar(&mobileConcurrency, "concurrency", 20, "Maximum concurrent scans")
	mobileCmd.Flags().IntVar(&mobileTimeout, "timeout", 60, "Scan timeout in seconds")
}

// MobileLogger implements core.Logger interface
type MobileLogger struct {
	logger *logrus.Logger
	silent bool
}

func (l *MobileLogger) Debug(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Debug(msg)
}

func (l *MobileLogger) Info(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Info(msg)
}

func (l *MobileLogger) Warn(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Warn(msg)
}

func (l *MobileLogger) Error(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Error(msg)
}

func (l *MobileLogger) Fatal(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Fatal(msg)
}

func (l *MobileLogger) fieldsToLogrus(fields []core.Field) logrus.Fields {
	logrusFields := make(logrus.Fields)
	for _, field := range fields {
		logrusFields[field.Key()] = field.Value()
	}
	return logrusFields
}

// displayMobileResults displays mobile/cloud domination results
func displayMobileResults(result *mobile.CloudDominationResult) error {
	if !silent {
		color.Cyan("\n📱 MOBILE/CLOUD DOMINATION RESULTS")
		color.Cyan("=" + strings.Repeat("=", 50))

		// Summary
		color.White("Target: %s", result.GetTarget().GetAddress())
		color.White("Containers Discovered: %d", len(result.DiscoveredContainers))
		color.White("Kubernetes Clusters: %d", len(result.KubernetesClusters))
		color.White("Cloud Assets: %d", len(result.CloudAssets))
		color.White("Mobile Apps: %d", len(result.MobileApps))
		color.White("Successful Escapes: %d", len(result.SuccessfulEscapes))
		color.White("Exploited Services: %d", len(result.ExploitedServices))

		// Container discoveries
		if len(result.DiscoveredContainers) > 0 {
			color.Cyan("\n🐳 Discovered Containers:")
			color.Cyan("-" + strings.Repeat("-", 60))

			for _, container := range result.DiscoveredContainers {
				statusColor := getContainerStatusColor(container.Status)
				statusColor.Printf("📦 %s (%s)\n", container.Name, container.ID[:12])
				color.White("   Image: %s", container.Image)
				color.White("   Runtime: %s", container.Runtime)
				color.White("   Status: %s", getContainerStatusString(container.Status))
				
				if container.Privileged {
					color.Red("   ⚠️ PRIVILEGED CONTAINER!")
				}
				
				if len(container.Capabilities) > 0 {
					color.Yellow("   Capabilities: %s", strings.Join(container.Capabilities, ", "))
				}

				if len(container.Vulnerabilities) > 0 {
					color.Red("   Vulnerabilities:")
					for _, vuln := range container.Vulnerabilities {
						severityColor := getSeverityColor(vuln.Severity)
						severityColor.Printf("     • %s ", vuln.Description)
						fmt.Printf("(%s)\n", core.SeverityToString(vuln.Severity))
					}
				}

				if len(container.EscapePaths) > 0 {
					color.Magenta("   Escape Paths:")
					for _, escape := range container.EscapePaths {
						color.Magenta("     • %s (%s)", escape.Method, escape.Complexity)
					}
				}

				fmt.Println()
			}
		}

		// Kubernetes clusters
		if len(result.KubernetesClusters) > 0 {
			color.Cyan("\n⚓ Kubernetes Clusters:")
			color.Cyan("-" + strings.Repeat("-", 60))

			for _, cluster := range result.KubernetesClusters {
				color.Blue("🎡 %s (v%s)", cluster.Name, cluster.Version)
				color.White("   API Server: %s", cluster.APIServer)
				color.White("   Nodes: %d", len(cluster.Nodes))
				color.White("   Namespaces: %s", strings.Join(cluster.Namespaces, ", "))

				if len(cluster.Vulnerabilities) > 0 {
					color.Red("   Vulnerabilities:")
					for _, vuln := range cluster.Vulnerabilities {
						severityColor := getSeverityColor(vuln.Severity)
						severityColor.Printf("     • %s ", vuln.Description)
						fmt.Printf("(%s)\n", core.SeverityToString(vuln.Severity))
					}
				}

				if len(cluster.ExploitPaths) > 0 {
					color.Magenta("   Exploit Paths:")
					for _, path := range cluster.ExploitPaths {
						color.Magenta("     • %s: %s", path.Type, path.Description)
					}
				}

				fmt.Println()
			}
		}

		// Cloud assets
		if len(result.CloudAssets) > 0 {
			color.Cyan("\n☁️ Cloud Assets:")
			color.Cyan("-" + strings.Repeat("-", 60))

			for _, asset := range result.CloudAssets {
				providerColor := getProviderColor(asset.Provider)
				providerColor.Printf("☁️ %s (%s)\n", asset.Name, getProviderString(asset.Provider))
				color.White("   Type: %s", getAssetTypeString(asset.Type))
				color.White("   Region: %s", asset.Region)
				color.White("   Status: %s", getAssetStatusString(asset.Status))

				if len(asset.Vulnerabilities) > 0 {
					color.Red("   Vulnerabilities:")
					for _, vuln := range asset.Vulnerabilities {
						severityColor := getSeverityColor(vuln.Severity)
						severityColor.Printf("     • %s ", vuln.Description)
						fmt.Printf("(%s)\n", core.SeverityToString(vuln.Severity))
					}
				}

				fmt.Println()
			}
		}

		// Mobile apps
		if len(result.MobileApps) > 0 {
			color.Cyan("\n📱 Mobile Applications:")
			color.Cyan("-" + strings.Repeat("-", 60))

			for _, app := range result.MobileApps {
				platformColor := getMobilePlatformColor(app.Platform)
				platformColor.Printf("📱 %s (v%s)\n", app.Name, app.Version)
				color.White("   Package: %s", app.Package)
				color.White("   Platform: %s", getMobilePlatformString(app.Platform))
				color.White("   Permissions: %d", len(app.Permissions))

				if len(app.Vulnerabilities) > 0 {
					color.Red("   Vulnerabilities:")
					for _, vuln := range app.Vulnerabilities {
						severityColor := getSeverityColor(vuln.Severity)
						severityColor.Printf("     • %s ", vuln.Description)
						fmt.Printf("(%s)\n", core.SeverityToString(vuln.Severity))
					}
				}

				fmt.Println()
			}
		}

		// Successful escapes
		if len(result.SuccessfulEscapes) > 0 {
			color.Red("\n🏃‍♂️ Successful Container Escapes:")
			color.Red("-" + strings.Repeat("-", 60))

			for _, escape := range result.SuccessfulEscapes {
				if escape.Success {
					color.Red("💀 Container %s - ESCAPED!", escape.ContainerID[:12])
					color.White("   Method: %s", escape.Method)
					color.White("   Host Access: %t", escape.HostAccess)
					color.White("   Privileges: %s", escape.Privileges)
					color.White("   Timestamp: %s", escape.Timestamp.Format("2006-01-02 15:04:05"))
					fmt.Println()
				}
			}
		}

		// Exploited services
		if len(result.ExploitedServices) > 0 {
			color.Red("\n💀 Exploited Services:")
			color.Red("-" + strings.Repeat("-", 60))

			for _, exploit := range result.ExploitedServices {
				if exploit.Success {
					severityColor := getSeverityColor(exploit.Severity)
					severityColor.Printf("💀 %s\n", exploit.Name)
					color.White("   Platform: %s", exploit.Platform)
					color.White("   Type: %s", getExploitTypeString(exploit.Type))
					color.White("   Description: %s", exploit.Description)
					if exploit.CVSS > 0 {
						color.White("   CVSS: %.1f", exploit.CVSS)
					}
					fmt.Println()
				}
			}
		}

		// Risk assessment
		color.Cyan("\n📊 INFRASTRUCTURE RISK ASSESSMENT:")
		totalRisk := calculateTotalRisk(result)
		
		riskLevel := "LOW"
		riskColor := color.New(color.FgGreen)
		
		if totalRisk > 80 {
			riskLevel = "CRITICAL"
			riskColor = color.New(color.FgRed, color.Bold)
		} else if totalRisk > 60 {
			riskLevel = "HIGH"
			riskColor = color.New(color.FgRed)
		} else if totalRisk > 40 {
			riskLevel = "MEDIUM"
			riskColor = color.New(color.FgYellow)
		}
		
		riskColor.Printf("Infrastructure Risk: %s (%.1f)\n", riskLevel, totalRisk)
		
		if len(result.SuccessfulEscapes) > 0 {
			color.Red("🚨 CRITICAL: Container escapes successful - infrastructure compromised!")
		}
		if len(result.ExploitedServices) > 0 {
			color.Red("💀 CRITICAL: Cloud services exploited - immediate response required!")
		}
	}

	return nil
}

// saveMobileResults saves mobile/cloud domination results
func saveMobileResults(result *mobile.CloudDominationResult, format, filename string) error {
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

		fmt.Fprintf(file, "MOBILE/CLOUD DOMINATION RESULTS\n")
		fmt.Fprintf(file, "===============================\n\n")
		fmt.Fprintf(file, "Target: %s\n", result.GetTarget().GetAddress())
		fmt.Fprintf(file, "Timestamp: %s\n", result.GetTimestamp().Format("2006-01-02 15:04:05"))
		fmt.Fprintf(file, "Containers: %d\n", len(result.DiscoveredContainers))
		fmt.Fprintf(file, "K8s Clusters: %d\n", len(result.KubernetesClusters))
		fmt.Fprintf(file, "Cloud Assets: %d\n", len(result.CloudAssets))
		fmt.Fprintf(file, "Mobile Apps: %d\n", len(result.MobileApps))
		fmt.Fprintf(file, "Successful Escapes: %d\n", len(result.SuccessfulEscapes))
		fmt.Fprintf(file, "Exploited Services: %d\n\n", len(result.ExploitedServices))

		// Write detailed results...
		return nil

	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// Helper functions
func getContainerStatusColor(status mobile.ContainerStatus) *color.Color {
	switch status {
	case 0: // ContainerRunning
		return color.New(color.FgGreen)
	case 1: // ContainerStopped
		return color.New(color.FgRed)
	case 2: // ContainerPaused
		return color.New(color.FgYellow)
	case 3: // ContainerRestarting
		return color.New(color.FgBlue)
	default:
		return color.New(color.FgWhite)
	}
}

func getContainerStatusString(status mobile.ContainerStatus) string {
	switch status {
	case 0:
		return "Running"
	case 1:
		return "Stopped"
	case 2:
		return "Paused"
	case 3:
		return "Restarting"
	default:
		return "Unknown"
	}
}

func getProviderColor(provider mobile.CloudProvider) *color.Color {
	switch provider {
	case 0: // ProviderAWS
		return color.New(color.FgYellow)
	case 1: // ProviderAzure
		return color.New(color.FgBlue)
	case 2: // ProviderGCP
		return color.New(color.FgGreen)
	default:
		return color.New(color.FgWhite)
	}
}

func getProviderString(provider mobile.CloudProvider) string {
	switch provider {
	case 0:
		return "AWS"
	case 1:
		return "Azure"
	case 2:
		return "GCP"
	case 3:
		return "DigitalOcean"
	case 4:
		return "Vultr"
	case 5:
		return "Linode"
	default:
		return "Unknown"
	}
}

func getAssetTypeString(assetType mobile.AssetType) string {
	switch assetType {
	case 0:
		return "Virtual Machine"
	case 1:
		return "Container"
	case 2:
		return "Function"
	case 3:
		return "Database"
	case 4:
		return "Storage"
	case 5:
		return "Network"
	case 6:
		return "Load Balancer"
	case 7:
		return "API"
	default:
		return "Unknown"
	}
}

func getAssetStatusString(status mobile.AssetStatus) string {
	switch status {
	case 0:
		return "Running"
	case 1:
		return "Stopped"
	case 2:
		return "Terminated"
	case 3:
		return "Pending"
	default:
		return "Unknown"
	}
}

func getMobilePlatformColor(platform mobile.MobilePlatform) *color.Color {
	switch platform {
	case 0: // PlatformAndroid
		return color.New(color.FgGreen)
	case 1: // PlatformiOS
		return color.New(color.FgBlue)
	default:
		return color.New(color.FgWhite)
	}
}

func getMobilePlatformString(platform mobile.MobilePlatform) string {
	switch platform {
	case 0:
		return "Android"
	case 1:
		return "iOS"
	case 2:
		return "React Native"
	case 3:
		return "Flutter"
	case 4:
		return "Xamarin"
	default:
		return "Unknown"
	}
}

func getExploitTypeString(exploitType mobile.ExploitType) string {
	switch exploitType {
	case 0:
		return "Container Escape"
	case 1:
		return "K8s Privilege Escalation"
	case 2:
		return "Cloud Metadata"
	case 3:
		return "Serverless Function Abuse"
	case 4:
		return "Mobile App Vulnerability"
	default:
		return "Unknown"
	}
}

func calculateTotalRisk(result *mobile.CloudDominationResult) float64 {
	risk := 0.0
	
	// Container risks
	for _, container := range result.DiscoveredContainers {
		if container.Privileged {
			risk += 20
		}
		for _, vuln := range container.Vulnerabilities {
			switch vuln.Severity {
			case core.SeverityCritical:
				risk += 15
			case core.SeverityHigh:
				risk += 10
			case core.SeverityMedium:
				risk += 5
			}
		}
	}
	
	// Successful escapes add massive risk
	risk += float64(len(result.SuccessfulEscapes)) * 25
	
	// Exploited services add significant risk
	risk += float64(len(result.ExploitedServices)) * 15
	
	// Cap at 100
	if risk > 100 {
		risk = 100
	}
	
	return risk
}