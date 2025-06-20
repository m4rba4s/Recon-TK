package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"recon-toolkit/pkg/exploit"
)

var (
	msfURL          string
	msfUser         string
	msfPass         string
	autoPorts       string
	autoAggressive  bool
	autoStealth     bool
	autoLearning    bool
	autoPrivEsc     bool
	autoLateral     bool
	autoPersist     bool
	autoCleanup     bool
	autoTimeout     int
	autoDelay       int
	autoMaxSessions int
	autoOutput      string
)

var autopwnCmd = &cobra.Command{
	Use:   "autopwn",
	Short: "💀 Autonomous penetration testing with Metasploit integration",
	Long: `💀 AUTO-PWN ENGINE - Autonomous Exploitation Framework

Advanced autonomous penetration testing with Metasploit RPC integration:

🤖 AUTONOMOUS FEATURES:
  • Intelligent service fingerprinting
  • Automated vulnerability discovery
  • Smart exploit selection and execution
  • Multi-phase attack orchestration
  • Adaptive learning from success/failure

💀 EXPLOITATION CAPABILITIES:
  • Metasploit RPC integration
  • Automated payload selection
  • Session management and interaction
  • Privilege escalation automation
  • Lateral movement techniques

⚡ ATTACK PHASES:
  1. Reconnaissance & Service Discovery
  2. Vulnerability Assessment
  3. Automated Exploitation
  4. Privilege Escalation
  5. Lateral Movement
  6. Persistence Installation
  7. Data Collection
  8. Cleanup & Covering Tracks

🛡️ SAFETY FEATURES:
  • Stealth mode with timing randomization
  • Conservative vs aggressive modes
  • Session limits and timeouts
  • Automated cleanup capabilities
  • Learning mode for pattern recognition

👑 METASPLOIT INTEGRATION:
  • Real-time RPC communication
  • Dynamic exploit database queries
  • Advanced payload generation
  • Session management and control
  • Post-exploitation modules

Examples:
  recon-toolkit autopwn -t 192.168.1.100 --msf-url http://localhost:55553/api
  recon-toolkit autopwn -t target.com --aggressive --auto-lateral --auto-persist
  recon-toolkit autopwn -t 10.0.0.0/24 --stealth --learning --ports 80,443,22,3389`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target is required")
		}

		if msfURL == "" {
			return fmt.Errorf("Metasploit RPC URL is required (--msf-url)")
		}

		ctx := context.Background()

		if !silent {
			color.Red("💀 AUTO-PWN ENGINE ACTIVATED")
			color.Yellow("Target: %s", target)
			color.Yellow("MSF RPC: %s", msfURL)
			color.Yellow("Timeout: %d minutes", autoTimeout)
			
			if autoAggressive {
				color.Red("🚨 AGGRESSIVE MODE - FULL AUTO-PWN")
			} else {
				color.Green("🛡️ CONSERVATIVE MODE - SAFE EXPLOITATION")
			}
			
			if autoStealth {
				color.Magenta("🥷 STEALTH MODE ENABLED")
			}
			
			if autoLearning {
				color.Blue("🧠 LEARNING MODE ACTIVE")
			}
		}

		config := &exploit.ExploiterConfig{
			Aggressive:     autoAggressive,
			MaxAttempts:    5,
			Timeout:        time.Duration(autoTimeout) * time.Minute,
			DelayBetween:   time.Duration(autoDelay) * time.Second,
			StealthMode:    autoStealth,
			LearningMode:   autoLearning,
			AutoPrivEsc:    autoPrivEsc,
			AutoLateral:    autoLateral,
			AutoPersist:    autoPersist,
			CleanupAfter:   autoCleanup,
			MaxSessions:    autoMaxSessions,
			AvoidDetection: autoStealth,
		}

		autoExploiter := exploit.NewAutoExploiter(msfURL, config)

		if !silent {
			color.Cyan("🔗 Connecting to Metasploit RPC...")
		}

		err := autoExploiter.ConnectMSF(msfUser, msfPass)
		if err != nil {
			color.Red("❌ Failed to connect to Metasploit: %v", err)
			return err
		}

		if !silent {
			color.Green("✅ Connected to Metasploit successfully")
			color.Cyan("🚀 Starting autonomous penetration test...")
			fmt.Println()
		}

		start := time.Now()
		attackChain, err := autoExploiter.ExecuteAutoPwn(ctx, target)
		duration := time.Since(start)

		if err != nil {
			color.Red("❌ Auto-pwn execution failed: %v", err)
			return err
		}

		if !silent {
			displayAutoPwnResults(autoExploiter, attackChain, duration)
		}

		if autoOutput != "" {
			err = saveAutoPwnResults(attackChain, autoOutput)
			if err != nil {
				color.Red("Failed to save results: %v", err)
			} else {
				color.Green("📊 Results saved: %s", autoOutput)
			}
		}

		autoExploiter.Disconnect()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(autopwnCmd)

	autopwnCmd.Flags().StringVar(&msfURL, "msf-url", "http://localhost:55553/api", "Metasploit RPC URL")
	autopwnCmd.Flags().StringVar(&msfUser, "msf-user", "msf", "Metasploit RPC username")
	autopwnCmd.Flags().StringVar(&msfPass, "msf-pass", "msf", "Metasploit RPC password")
	autopwnCmd.Flags().StringVar(&autoPorts, "ports", "21,22,23,25,53,80,110,143,443,993,995,3306,5432,6379,8080,8443", "Ports to scan")
	autopwnCmd.Flags().BoolVar(&autoAggressive, "aggressive", false, "Enable aggressive exploitation")
	autopwnCmd.Flags().BoolVar(&autoStealth, "stealth", true, "Enable stealth mode")
	autopwnCmd.Flags().BoolVar(&autoLearning, "learning", true, "Enable learning mode")
	autopwnCmd.Flags().BoolVar(&autoPrivEsc, "auto-privesc", true, "Enable automatic privilege escalation")
	autopwnCmd.Flags().BoolVar(&autoLateral, "auto-lateral", false, "Enable automatic lateral movement")
	autopwnCmd.Flags().BoolVar(&autoPersist, "auto-persist", false, "Enable automatic persistence")
	autopwnCmd.Flags().BoolVar(&autoCleanup, "auto-cleanup", true, "Enable automatic cleanup")
	autopwnCmd.Flags().IntVar(&autoTimeout, "timeout", 30, "Timeout in minutes")
	autopwnCmd.Flags().IntVar(&autoDelay, "delay", 3, "Delay between attempts in seconds")
	autopwnCmd.Flags().IntVar(&autoMaxSessions, "max-sessions", 10, "Maximum concurrent sessions")
	autopwnCmd.Flags().StringVar(&autoOutput, "output", "", "Output file for results")
}

func displayAutoPwnResults(ae *exploit.AutoExploiter, chain *exploit.AttackChain, duration time.Duration) {
	color.Cyan("\n💀 AUTO-PWN RESULTS")
	color.Cyan("=" + strings.Repeat("=", 35))
	
	color.White("Target: %s", chain.Target)
	color.White("Duration: %v", duration)
	color.White("Attack Chain ID: %s", chain.ID)
	color.White("Total Phases: %d", len(chain.Phases))
	color.White("Compromised Hosts: %d", len(chain.CompromisedHosts))
	color.White("Active Sessions: %d", len(chain.ActiveSessions))
	
	if chain.Success {
		color.Green("✅ ATTACK CHAIN SUCCESSFUL")
	} else {
		color.Red("❌ ATTACK CHAIN FAILED")
	}

	color.Cyan("\n📊 PHASE BREAKDOWN:")
	for i, phase := range chain.Phases {
		statusIcon := "❌"
		statusColor := color.New(color.FgRed)
		if phase.Success {
			statusIcon = "✅"
			statusColor = color.New(color.FgGreen)
		}
		
		phaseEmoji := getPhaseEmoji(phase.Name)
		statusColor.Printf("%s Phase %d: %s %s (%v)\n", 
			statusIcon, i+1, phaseEmoji, phase.Name, phase.Duration)
		
		if len(phase.Techniques) > 0 {
			color.White("  Techniques executed: %d", len(phase.Techniques))
			for _, technique := range phase.Techniques {
				techStatus := "❌"
				if technique.Success {
					techStatus = "✅"
				}
				color.White("    %s %s (%v)", techStatus, technique.Name, technique.Duration)
				if technique.SessionID != "" {
					color.Green("      💻 Session: %s", technique.SessionID)
				}
			}
		}
		
		if len(phase.Errors) > 0 {
			color.Red("  Errors: %d", len(phase.Errors))
			for _, err := range phase.Errors {
				color.Red("    ⚠️ %s", err)
			}
		}
		fmt.Println()
	}

	sessions := ae.GetActiveSessions()
	if len(sessions) > 0 {
		color.Green("\n💻 ACTIVE SESSIONS:")
		for sessionID, session := range sessions {
			if session.Active {
				color.Green("• Session %s: %s@%s:%d (%s)", 
					sessionID, session.User, session.Host, session.Port, session.OS)
				color.White("  Type: %s | Privileges: %s | Shell: %s", 
					session.Type, session.Privileges, session.Shell)
				color.White("  Last Contact: %v", session.LastContact.Format("15:04:05"))
				
				if len(session.Credentials) > 0 {
					color.Yellow("  🔑 Credentials found: %d", len(session.Credentials))
					for _, cred := range session.Credentials {
						color.Yellow("    %s:%s@%s", cred.Username, cred.Password, cred.Domain)
					}
				}
				
				if len(session.Persistence) > 0 {
					color.Magenta("  🔗 Persistence installed: %d", len(session.Persistence))
					for _, persist := range session.Persistence {
						color.Magenta("    %s: %s", persist.Type, persist.Method)
					}
				}
				fmt.Println()
			}
		}
	}

	if len(chain.CredentialsFound) > 0 {
		color.Yellow("\n🔑 CREDENTIALS HARVESTED:")
		for _, cred := range chain.CredentialsFound {
			adminIcon := ""
			if cred.Admin {
				adminIcon = "👑"
			}
			color.Yellow("• %s%s:%s@%s (%s:%d)", 
				adminIcon, cred.Username, cred.Password, cred.Domain, cred.Service, cred.Port)
		}
	}

	if len(chain.DataExfiltrated) > 0 {
		color.Cyan("\n📊 DATA EXFILTRATED:")
		for _, data := range chain.DataExfiltrated {
			color.Cyan("• %s", data)
		}
	}

	color.Cyan("\n🎭 CYNICAL ASSESSMENT:")
	sessionCount := len(chain.ActiveSessions)
	compromisedCount := len(chain.CompromisedHosts)
	credCount := len(chain.CredentialsFound)

	if sessionCount > 5 {
		color.Red("🖕 This network is more fucked than a pornstar!")
		color.Red("💀 Admin should quit and become a barista")
	} else if sessionCount > 2 {
		color.Yellow("🎪 Decent compromise achieved - network security is a joke")
		color.Yellow("🤡 Someone forgot to patch their shit")
	} else if sessionCount > 0 {
		color.Green("🛡️ Got some sessions, not bad for auto-pwn")
		color.Green("🎯 Limited but successful penetration")
	} else if compromisedCount > 0 {
		color.Blue("👑 Partial success - some services compromised")
		color.Blue("🥷 Network has some defenses but vulnerabilities exist")
	} else {
		color.Blue("🔍 No successful exploitation - impressive defenses")
		color.Blue("🤔 Either well-secured or we need better exploits...")
	}

	if credCount > 10 {
		color.Red("\n🔑 Credential goldmine discovered - %d accounts harvested!", credCount)
	} else if credCount > 0 {
		color.Yellow("\n🔑 Some credentials harvested - %d accounts", credCount)
	}
}

func getPhaseEmoji(phaseName string) string {
	emojis := map[string]string{
		"reconnaissance":        "🔍",
		"vulnerability_discovery": "🎯",
		"exploitation":          "💀",
		"privilege_escalation":  "⬆️",
		"lateral_movement":      "↔️",
		"persistence":           "🔗",
		"data_collection":       "📊",
		"cleanup":               "🧹",
	}
	
	if emoji, exists := emojis[phaseName]; exists {
		return emoji
	}
	return "🎭"
}

func saveAutoPwnResults(chain *exploit.AttackChain, filename string) error {
	data, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(filename, data, 0644)
}

func parsePorts(portStr string) []int {
	ports := make([]int, 0)
	parts := strings.Split(portStr, ",")
	
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if port, err := strconv.Atoi(part); err == nil {
			ports = append(ports, port)
		}
	}
	
	return ports
}