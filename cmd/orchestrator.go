package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"recon-toolkit/pkg/orchestrator"
)

var (
	orchObjective      string
	orchAggressiveness float64
	orchMaxNodes       int
	orchestratorTimeout int
	orchAIModel        string
	orchAIAPIKey       string
	orchStealthMode    bool
	orchAdaptiveLearning bool
	orchReportOutput   string
)

var orchestratorCmd = &cobra.Command{
	Use:   "orchestrate",
	Short: "🤖 Launch AI-powered autonomous attack orchestrator",
	Long: `🚀 AI ATTACK ORCHESTRATOR - Autonomous Penetration Testing

The most advanced AI-powered penetration testing system ever created!

🧠 ARTIFICIAL INTELLIGENCE:
  • GPT-4 powered attack strategy development
  • Real-time technique optimization
  • Adaptive learning from success/failure patterns
  • Autonomous decision making

🎯 ATTACK AUTOMATION:
  • Multi-phase attack execution
  • Intelligent technique selection
  • Dynamic payload generation
  • Attack graph construction

⚡ ADVANCED FEATURES:
  • Self-learning attack patterns
  • Stealth mode with timing randomization
  • Success probability calculation
  • Comprehensive attack reporting

🔥 ATTACK PHASES:
  1. Reconnaissance & OSINT
  2. Vulnerability Discovery
  3. Exploitation Attempts
  4. Privilege Escalation
  5. Lateral Movement
  6. Data Exfiltration
  7. Cleanup & Persistence

Examples:
  recon-toolkit orchestrate -t target.com --objective="full_compromise"
  recon-toolkit orchestrate -t 192.168.1.0/24 --aggressive 0.9 --ai-model gpt-4
  recon-toolkit orchestrate -t target.com --stealth --adaptive --report attack_report.json`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target is required")
		}

		ctx := context.Background()

		if !silent {
			color.Red("🤖 AI ATTACK ORCHESTRATOR ACTIVATED")
			color.Yellow("Target: %s", target)
			color.Yellow("Objective: %s", orchObjective)
			color.Yellow("Aggressiveness: %.1f", orchAggressiveness)
			color.Yellow("AI Model: %s", orchAIModel)
			
			if orchStealthMode {
				color.Green("🥷 STEALTH MODE ENABLED")
			}
			if orchAdaptiveLearning {
				color.Blue("🧠 ADAPTIVE LEARNING ENABLED")
			}
		}

		// Configure AI orchestrator
		options := []func(*orchestrator.AIOrchestrator){
			orchestrator.WithObjective(orchObjective),
			orchestrator.WithAggressiveness(orchAggressiveness),
			orchestrator.WithStealth(orchStealthMode),
		}

		if orchAIAPIKey != "" || os.Getenv("OPENAI_API_KEY") != "" {
			apiKey := orchAIAPIKey
			if apiKey == "" {
				apiKey = os.Getenv("OPENAI_API_KEY")
			}
			options = append(options, orchestrator.WithAI(orchAIModel, apiKey))
			
			if !silent {
				color.Green("🤖 AI engine initialized with model: %s", orchAIModel)
			}
		}

		// Create orchestrator
		orch := orchestrator.NewAIOrchestrator(target, options...)

		// Execute attack plan
		if !silent {
			color.Cyan("🚀 Starting autonomous attack execution...")
			fmt.Println()
		}

		start := time.Now()
		graph, err := orch.ExecuteAttackPlan(ctx)
		duration := time.Since(start)

		if err != nil {
			color.Red("❌ Attack execution failed: %v", err)
			return err
		}

		// Display results
		if !silent {
			displayOrchestratorResults(orch, graph, duration)
		}

		// Generate and save report
		if orchReportOutput != "" {
			err = generateOrchestratorReport(orch, orchReportOutput)
			if err != nil {
				color.Red("Failed to generate report: %v", err)
			} else {
				color.Green("📊 Report saved: %s", orchReportOutput)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(orchestratorCmd)

	orchestratorCmd.Flags().StringVar(&orchObjective, "objective", "comprehensive_penetration", "Attack objective")
	orchestratorCmd.Flags().Float64Var(&orchAggressiveness, "aggressive", 0.7, "Aggressiveness level (0.1-1.0)")
	orchestratorCmd.Flags().IntVar(&orchMaxNodes, "max-nodes", 50, "Maximum attack nodes")
	orchestratorCmd.Flags().IntVar(&orchestratorTimeout, "timeout", 120, "Timeout in minutes")
	orchestratorCmd.Flags().StringVar(&orchAIModel, "ai-model", "gpt-4", "AI model to use")
	orchestratorCmd.Flags().StringVar(&orchAIAPIKey, "ai-key", "", "AI API key (or set OPENAI_API_KEY env)")
	orchestratorCmd.Flags().BoolVar(&orchStealthMode, "stealth", true, "Enable stealth mode")
	orchestratorCmd.Flags().BoolVar(&orchAdaptiveLearning, "adaptive", true, "Enable adaptive learning")
	orchestratorCmd.Flags().StringVar(&orchReportOutput, "report", "", "Output file for attack report")
}

func displayOrchestratorResults(orch *orchestrator.AIOrchestrator, graph *orchestrator.AttackGraph, duration time.Duration) {
	stats := orch.GetStats()
	
	color.Cyan("\n🎯 AI ORCHESTRATOR RESULTS")
	color.Cyan("=" + strings.Repeat("=", 40))
	
	color.White("Target: %s", stats["target"])
	color.White("Duration: %v", duration)
	color.White("Total Techniques: %d", stats["total_nodes"])
	color.White("Successful Techniques: %d", stats["successful_nodes"])
	color.Green("Success Rate: %.1f%%", stats["success_rate"].(float64)*100)
	
	if stats["ai_enabled"].(bool) {
		color.Blue("🤖 AI-Enhanced Execution")
	}
	
	if stats["adaptive_learning"].(bool) {
		color.Blue("🧠 Adaptive Learning Active")
	}
	
	// Display attack phases
	color.Cyan("\n📊 ATTACK PHASE BREAKDOWN:")
	phaseStats := calculatePhaseStats(graph)
	
	for phase, count := range phaseStats {
		emoji := getOrchestratorPhaseEmoji(phase)
		color.White("%s %s: %d techniques", emoji, phase, count)
	}
	
	// Display successful techniques
	successfulTechniques := getSuccessfulTechniques(graph)
	if len(successfulTechniques) > 0 {
		color.Red("\n💀 SUCCESSFUL ATTACKS:")
		for _, technique := range successfulTechniques {
			color.Red("  ✅ %s", technique)
		}
	}
	
	// Overall assessment
	successRate := stats["success_rate"].(float64)
	color.Cyan("\n🎭 CYNICAL ASSESSMENT:")
	
	if successRate > 0.7 {
		color.Red("🖕 This target is weaker than wet toilet paper!")
		color.Red("💀 Admin should find a new career - maybe flipping burgers")
	} else if successRate > 0.4 {
		color.Yellow("🎪 Decent challenge, but still got skull-fucked")
		color.Yellow("🤡 Security team needs some serious training")
	} else if successRate > 0.2 {
		color.Green("🛡️ Not bad, but we still found some juicy holes")
		color.Green("🎯 Room for improvement, keep trying")
	} else {
		color.Blue("👑 Impressive defenses! Almost elite-level security")
		color.Blue("🥷 Respect to the security team")
	}
}

func calculatePhaseStats(graph *orchestrator.AttackGraph) map[string]int {
	stats := make(map[string]int)
	
	for _, node := range graph.Nodes {
		stats[string(node.Phase)]++
	}
	
	return stats
}

func getOrchestratorPhaseEmoji(phase string) string {
	emojis := map[string]string{
		"reconnaissance":        "🔍",
		"vulnerability_discovery": "🎯",
		"exploitation":          "💀",
		"privilege_escalation":  "⬆️",
		"lateral_movement":      "↔️",
		"data_exfiltration":     "📤",
		"cleanup":               "🧹",
	}
	
	if emoji, exists := emojis[phase]; exists {
		return emoji
	}
	return "🎭"
}

func getSuccessfulTechniques(graph *orchestrator.AttackGraph) []string {
	var successful []string
	
	for _, node := range graph.Nodes {
		if node.Success {
			successful = append(successful, node.Technique)
		}
	}
	
	return successful
}

func generateOrchestratorReport(orch *orchestrator.AIOrchestrator, filename string) error {
	report, err := orch.GenerateReport()
	if err != nil {
		return err
	}
	
	return os.WriteFile(filename, []byte(report), 0644)
}