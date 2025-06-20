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
	"recon-toolkit/pkg/crawler"
)

var (
	crawlMaxDepth   int
	crawlMaxPages   int
	crawlTimeout    int
	crawlAggressive bool
	crawlFuzzing    bool
	crawlOutput     string
)

var crawlerCmd = &cobra.Command{
	Use:   "crawl",
	Short: "🕷️ Advanced smart web crawler and fuzzer",
	Long: `🕷️ SMART WEB CRAWLER - AI-Powered Endpoint Discovery

Advanced web application crawler with intelligent discovery capabilities:

🧠 INTELLIGENT FEATURES:
  • Technology stack detection and adaptation
  • Context-aware endpoint classification
  • Hidden parameter discovery
  • Form analysis and classification
  • JavaScript endpoint extraction

🎯 DISCOVERY CAPABILITIES:
  • Admin panel detection
  • API endpoint enumeration
  • Upload functionality discovery
  • Configuration file hunting
  • Backup file detection
  • Debug endpoint identification

⚡ FUZZING ENGINE:
  • Parameter-based vulnerability testing
  • XSS payload injection
  • SQL injection detection
  • Command injection testing
  • Local file inclusion probes
  • Server-side template injection

🔍 SMART CLASSIFICATION:
  • Login forms and authentication
  • File upload endpoints
  • API and AJAX endpoints
  • Administrative interfaces
  • Configuration panels
  • Debug and testing pages

Examples:
  recon-toolkit crawl -t https://target.com --aggressive --fuzzing
  recon-toolkit crawl -t https://target.com --max-depth 10 --max-pages 5000
  recon-toolkit crawl -t https://target.com --output endpoints.json`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target is required")
		}

		ctx := context.Background()

		if !silent {
			color.Red("🕷️ SMART WEB CRAWLER ACTIVATED")
			color.Yellow("Target: %s", target)
			color.Yellow("Max Depth: %d", crawlMaxDepth)
			color.Yellow("Max Pages: %d", crawlMaxPages)
			color.Yellow("Timeout: %ds", crawlTimeout)
			
			if crawlAggressive {
				color.Red("🚨 AGGRESSIVE MODE")
			}
			if crawlFuzzing {
				color.Red("🎯 FUZZING ENABLED")
			}
		}

		// Configure crawler
		options := []func(*crawler.SmartCrawler){
			crawler.WithMaxDepth(crawlMaxDepth),
		}

		if crawlAggressive {
			options = append(options, crawler.WithAggressive())
		}

		if crawlFuzzing {
			options = append(options, crawler.WithFuzzing())
		}

		// Create crawler
		smartCrawler := crawler.NewSmartCrawler(target, options...)

		// Execute crawl
		if !silent {
			color.Cyan("🚀 Starting intelligent web crawl...")
			fmt.Println()
		}

		start := time.Now()
		endpoints, err := smartCrawler.Crawl(ctx)
		duration := time.Since(start)

		if err != nil {
			color.Red("❌ Crawl failed: %v", err)
			return err
		}

		// Display results
		if !silent {
			displayCrawlerResults(smartCrawler, endpoints, duration)
		}

		// Save results
		if crawlOutput != "" {
			err = saveCrawlerResults(endpoints, crawlOutput)
			if err != nil {
				color.Red("Failed to save results: %v", err)
			} else {
				color.Green("📊 Results saved: %s", crawlOutput)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(crawlerCmd)

	crawlerCmd.Flags().IntVar(&crawlMaxDepth, "max-depth", 5, "Maximum crawl depth")
	crawlerCmd.Flags().IntVar(&crawlMaxPages, "max-pages", 1000, "Maximum pages to crawl")
	crawlerCmd.Flags().IntVar(&crawlTimeout, "timeout", 10, "Request timeout in seconds")
	crawlerCmd.Flags().BoolVar(&crawlAggressive, "aggressive", false, "Enable aggressive crawling")
	crawlerCmd.Flags().BoolVar(&crawlFuzzing, "fuzzing", true, "Enable vulnerability fuzzing")
	crawlerCmd.Flags().StringVar(&crawlOutput, "output", "", "Output file for results")
}

func displayCrawlerResults(sc *crawler.SmartCrawler, endpoints []*crawler.Endpoint, duration time.Duration) {
	stats := sc.GetStats()
	
	color.Cyan("\n🕷️ SMART CRAWLER RESULTS")
	color.Cyan("=" + strings.Repeat("=", 40))
	
	color.White("Duration: %v", duration)
	color.White("Total Endpoints: %d", stats["total_endpoints"])
	color.White("Pages Visited: %d", stats["visited_pages"])
	color.White("Vulnerable Endpoints: %d", stats["vulnerable_endpoints"])
	
	// Technology detection
	if techs, ok := stats["technologies"].(map[string]bool); ok && len(techs) > 0 {
		color.Cyan("\n🔧 DETECTED TECHNOLOGIES:")
		for tech := range techs {
			color.Green("  ✅ %s", tech)
		}
	}
	
	// Endpoint classification
	if types, ok := stats["endpoint_types"].(map[crawler.EndpointType]int); ok {
		color.Cyan("\n📊 ENDPOINT BREAKDOWN:")
		for endpointType, count := range types {
			emoji := getEndpointEmoji(endpointType)
			color.White("%s %s: %d", emoji, endpointType, count)
		}
	}
	
	// Interesting findings
	color.Cyan("\n🎯 INTERESTING FINDINGS:")
	adminCount := 0
	loginCount := 0
	uploadCount := 0
	vulnerableCount := 0
	
	for _, endpoint := range endpoints {
		switch endpoint.Type {
		case crawler.TypeAdmin:
			adminCount++
		case crawler.TypeLogin:
			loginCount++
		case crawler.TypeUpload:
			uploadCount++
		}
		if endpoint.Vulnerable {
			vulnerableCount++
		}
	}
	
	if adminCount > 0 {
		color.Red("🔑 Admin panels found: %d", adminCount)
	}
	if loginCount > 0 {
		color.Yellow("🔐 Login forms found: %d", loginCount)
	}
	if uploadCount > 0 {
		color.Yellow("📤 Upload endpoints found: %d", uploadCount)
	}
	if vulnerableCount > 0 {
		color.Red("💀 Potentially vulnerable: %d", vulnerableCount)
	}
	
	// Show top vulnerable endpoints
	vulnerableEndpoints := getVulnerableEndpoints(endpoints)
	if len(vulnerableEndpoints) > 0 {
		color.Red("\n💀 VULNERABLE ENDPOINTS:")
		for i, endpoint := range vulnerableEndpoints {
			if i >= 10 { // Show max 10
				break
			}
			color.Red("  🎯 %s (%s)", endpoint.URL, endpoint.Type)
			for _, payload := range endpoint.Payloads {
				color.Red("    💥 %s", payload)
			}
		}
	}
	
	// Cynical assessment
	color.Cyan("\n🎭 CYNICAL ASSESSMENT:")
	totalEndpoints := len(endpoints)
	
	if vulnerableCount > 10 {
		color.Red("🖕 This webapp is more fucked than a pornstar in a gangbang!")
		color.Red("💀 Developer clearly learned security from YouTube tutorials")
	} else if vulnerableCount > 5 {
		color.Yellow("🎪 Decent amount of holes to exploit - not bad!")
		color.Yellow("🤡 Security team needs to step up their game")
	} else if vulnerableCount > 0 {
		color.Green("🛡️ Some vulnerabilities found, could be worse")
		color.Green("🎯 Not terrible, but room for improvement")
	} else if totalEndpoints > 50 {
		color.Blue("👑 Impressive security posture - well defended!")
		color.Blue("🥷 Respect to the development team")
	} else {
		color.Blue("🔍 Limited attack surface discovered")
		color.Blue("🤔 Either well-secured or hiding something...")
	}
}

func getEndpointEmoji(endpointType crawler.EndpointType) string {
	emojis := map[crawler.EndpointType]string{
		crawler.TypeForm:   "📝",
		crawler.TypeAPI:    "🔌",
		crawler.TypeAdmin:  "🔑",
		crawler.TypeUpload: "📤",
		crawler.TypeLogin:  "🔐",
		crawler.TypeConfig: "⚙️",
		crawler.TypeBackup: "💾",
		crawler.TypeDebug:  "🐛",
		crawler.TypeHidden: "👻",
		crawler.TypeAjax:   "⚡",
	}
	
	if emoji, exists := emojis[endpointType]; exists {
		return emoji
	}
	return "🎭"
}

func getVulnerableEndpoints(endpoints []*crawler.Endpoint) []*crawler.Endpoint {
	var vulnerable []*crawler.Endpoint
	
	for _, endpoint := range endpoints {
		if endpoint.Vulnerable {
			vulnerable = append(vulnerable, endpoint)
		}
	}
	
	return vulnerable
}

func saveCrawlerResults(endpoints []*crawler.Endpoint, filename string) error {
	data, err := json.MarshalIndent(endpoints, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(filename, data, 0644)
}