
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"recon-toolkit/pkg/bypass"
)

var (
	bypassPayload     string
	bypassTimeout     int
	bypassRetries     int
	bypassAggressive  bool
	bypassStealth     bool
	bypassLearning    bool
	bypassOutput      string
	bypassProxies     []string
)

var bypassCmd = &cobra.Command{
	Use:   "bypass",
	Short: "Adaptive protection bypass with real-time learning",
	Long: `🥷 BYPASS MODULE - Adaptive Protection Bypass

Advanced bypass engine with machine learning and real-time adaptation:

🛡️ BYPASS TECHNIQUES:
  • WAF (Web Application Firewall) evasion
  • Rate limiting circumvention
  • IP blocking bypass
  • Behavioral analysis evasion
  • Protocol-level obfuscation
  • Payload encoding/mutation
  • Request fragmentation

🧠 ADAPTIVE LEARNING:
  • Success pattern recognition
  • Failure analysis and adaptation
  • Dynamic technique selection
  • Statistical success tracking
  • Real-time strategy optimization

⚡ EVASION METHODS:
  • Multi-vector payload testing
  • Proxy rotation and IP spoofing
  • User-Agent cycling
  • Header manipulation
  • Request timing randomization
  • Session state management

🔄 REAL-TIME FEATURES:
  • Automatic recovery from blocks
  • Dynamic payload mutation
  • Success rate optimization
  • Persistent learning database
  • Confidence scoring

Examples:
  recon-toolkit bypass -t https://target.com --payload "<script>alert(1)</script>"
  recon-toolkit bypass -t https://target.com --payload "' OR 1=1--" --aggressive
  recon-toolkit bypass -t https://target.com --payload "test" --learning --stealth
  recon-toolkit bypass -t https://target.com --payload "exploit" --proxies "proxy1:8080,proxy2:3128"`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target is required")
		}
		
		if bypassPayload == "" {
			return fmt.Errorf("payload is required (use --payload)")
		}

		ctx := context.Background()
		
		if !silent {
			color.Red("🥷 BYPASS MODULE ACTIVATED")
			color.Yellow("Target: %s", target)
			color.Yellow("Payload: %s", truncatePayload(bypassPayload, 50))
			color.Yellow("Timeout: %ds | Retries: %d", bypassTimeout, bypassRetries)
			
			if bypassAggressive {
				color.Red("🚨 AGGRESSIVE MODE")
			}
			if bypassStealth {
				color.Green("🤫 STEALTH MODE")
			}
			if bypassLearning {
				color.Blue("🧠 LEARNING ENABLED")
			}
		}

		options := []func(*bypass.AdaptiveBypass){
			bypass.WithTimeout(time.Duration(bypassTimeout) * time.Second),
			bypass.WithMaxRetries(bypassRetries),
		}

		if bypassAggressive {
			options = append(options, bypass.WithAggressiveMode())
		}
		
		if bypassStealth {
			options = append(options, bypass.WithStealthMode())
		}
		
		if bypassLearning {
			options = append(options, bypass.WithAdaptiveLearning())
		}
		
		if len(bypassProxies) > 0 {
			options = append(options, bypass.WithProxies(bypassProxies))
		}

		engine := bypass.NewAdaptiveBypass(target, options...)

		if !silent {
			color.Cyan("🔄 Starting adaptive bypass attempts...")
		}

		result, err := engine.AttemptBypass(ctx, bypassPayload)
		if err != nil {
			color.Red("❌ Bypass failed: %v", err)
			
			if bypassLearning {
				stats := engine.GetStats()
				displayBypassStats(stats)
			}
			
			return err
		}

		displayBypassResult(result)
		
		if bypassLearning {
			stats := engine.GetStats()
			displayBypassStats(stats)
		}

		if bypassOutput != "" {
			err = saveBypassResult(result, bypassOutput)
			if err != nil {
				color.Red("Failed to save results: %v", err)
			} else if !silent {
				color.Green("💾 Results saved to: %s", bypassOutput)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(bypassCmd)

	bypassCmd.Flags().StringVar(&bypassPayload, "payload", "", "Payload to test for bypass (required)")
	bypassCmd.Flags().IntVar(&bypassTimeout, "timeout", 15, "Request timeout in seconds")
	bypassCmd.Flags().IntVar(&bypassRetries, "retries", 5, "Maximum retry attempts")
	bypassCmd.Flags().BoolVar(&bypassAggressive, "aggressive", false, "Enable aggressive bypass mode")
	bypassCmd.Flags().BoolVar(&bypassStealth, "stealth", true, "Enable stealth mode (default: true)")
	bypassCmd.Flags().BoolVar(&bypassLearning, "learning", true, "Enable adaptive learning (default: true)")
	bypassCmd.Flags().StringVar(&bypassOutput, "output", "", "Output file for results")
	bypassCmd.Flags().StringSliceVar(&bypassProxies, "proxies", []string{}, "Comma-separated list of proxy servers")
	
	bypassCmd.MarkFlagRequired("payload")
}

func displayBypassResult(result *bypass.BypassResult) {
	if !silent {
		color.Cyan("\n🎯 BYPASS RESULT")
		color.Cyan("=" + string(make([]byte, 40)))
		
		if result.Success {
			color.Green("✅ BYPASS SUCCESSFUL!")
			color.Green("Technique: %s", result.Technique)
		} else {
			color.Red("❌ Bypass Failed")
			color.Red("Technique: %s", result.Technique)
		}
		
		color.White("Status Code: %d", result.StatusCode)
		color.White("Response Time: %v", result.ResponseTime)
		color.White("Response Size: %d bytes", result.ResponseSize)
		color.White("Confidence: %.1f%%", result.ConfidenceScore*100)
		color.White("Method: %s", result.Method)
		color.White("Timestamp: %s", result.Timestamp.Format("15:04:05"))
		
		if result.Blocked {
			color.Red("🚫 Request was blocked")
		}
		
		if result.ErrorMessage != "" {
			color.Yellow("Error: %s", result.ErrorMessage)
		}
		
		if result.Payload != "" && result.Payload != bypassPayload {
			color.Cyan("\n🔧 Modified Payload:")
			color.White("%s", truncatePayload(result.Payload, 100))
		}
		
		if len(result.Headers) > 0 {
			color.Cyan("\n📋 Response Headers:")
			importantHeaders := []string{"Server", "X-Powered-By", "Content-Type", "Set-Cookie"}
			for _, header := range importantHeaders {
				if value, exists := result.Headers[header]; exists {
					color.White("%s: %s", header, value)
				}
			}
		}
	}
}

func displayBypassStats(stats bypass.BypassStats) {
	if !silent {
		color.Cyan("\n📊 LEARNING STATISTICS")
		color.Cyan("=" + string(make([]byte, 40)))
		
		color.White("Total Attempts: %d", stats.TotalAttempts)
		color.White("Successful Bypasses: %d", stats.SuccessfulBypass)
		color.Green("Overall Success Rate: %.1f%%", stats.SuccessRate*100)
		color.White("Last Update: %s", stats.LastUpdate.Format("15:04:05"))
		
		if len(stats.TechniqueStats) > 0 {
			color.Cyan("\n🔧 Technique Performance:")
			for technique, techStats := range stats.TechniqueStats {
				if techStats.Attempts > 0 {
					color.White("%s: %d/%d (%.1f%%) - Last used: %s", 
						technique, 
						techStats.Successes, 
						techStats.Attempts, 
						techStats.SuccessRate*100,
						techStats.LastUsed.Format("15:04:05"))
				}
			}
		}
		
		if len(stats.PatternAnalysis) > 0 {
			color.Cyan("\n🧠 Pattern Analysis:")
			count := 0
			for pattern, score := range stats.PatternAnalysis {
				if count >= 5 {
					break
				}
				if score > 0 {
					color.Green("✅ %s (Score: %.1f)", pattern, score)
				} else {
					color.Red("❌ %s (Score: %.1f)", pattern, score)
				}
				count++
			}
		}
	}
}

func saveBypassResult(result *bypass.BypassResult, filename string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func truncatePayload(payload string, maxLen int) string {
	if len(payload) <= maxLen {
		return payload
	}
	return payload[:maxLen] + "..."
}