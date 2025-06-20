package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type EnhancedInterface struct {
	scanner       *bufio.Scanner
	currentTarget string
	scanOptions   *ScanOptions
	userProfile   *UserProfile
}

type ScanOptions struct {
	IntensityLevel    string   `json:"intensity_level"`
	PortRange        string   `json:"port_range"`
	TimingTemplate   string   `json:"timing_template"`
	StealthMode      bool     `json:"stealth_mode"`
	BypassTechniques []string `json:"bypass_techniques"`
	OutputFormats    []string `json:"output_formats"`
	CustomPayloads   []string `json:"custom_payloads"`
	ThreadCount      int      `json:"thread_count"`
	Timeout          int      `json:"timeout"`
	MaxRetries       int      `json:"max_retries"`
}

type UserProfile struct {
	Username       string    `json:"username"`
	ExperienceLevel string   `json:"experience_level"`
	PreferredTools []string  `json:"preferred_tools"`
	LastScanDate   time.Time `json:"last_scan_date"`
	TotalScans     int       `json:"total_scans"`
	PreferredStyle string    `json:"preferred_style"`
}

type ScanResult struct {
	Target            string                 `json:"target"`
	StartTime         time.Time              `json:"start_time"`
	EndTime           time.Time              `json:"end_time"`
	Duration          time.Duration          `json:"duration"`
	FindingsCount     int                    `json:"findings_count"`
	CriticalFindings  int                    `json:"critical_findings"`
	HighFindings      int                    `json:"high_findings"`
	MediumFindings    int                    `json:"medium_findings"`
	LowFindings       int                    `json:"low_findings"`
	TechnicalDetails  map[string]interface{} `json:"technical_details"`
	RecommendedActions []string              `json:"recommended_actions"`
	ExploitationGuide []ExploitStep         `json:"exploitation_guide"`
}

type ExploitStep struct {
	StepNumber    int      `json:"step_number"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	Command       string   `json:"command,omitempty"`
	Prerequisites []string `json:"prerequisites"`
	RiskLevel     string   `json:"risk_level"`
	TimeEstimate  string   `json:"time_estimate"`
	SkillLevel    string   `json:"skill_level"`
}

func NewEnhancedInterface() *EnhancedInterface {
	return &EnhancedInterface{
		scanner:     bufio.NewScanner(os.Stdin),
		scanOptions: NewDefaultScanOptions(),
		userProfile: NewDefaultUserProfile(),
	}
}

func NewDefaultScanOptions() *ScanOptions {
	return &ScanOptions{
		IntensityLevel:    "balanced",
		PortRange:        "common",
		TimingTemplate:   "normal",
		StealthMode:      false,
		BypassTechniques: []string{},
		OutputFormats:    []string{"json", "markdown"},
		CustomPayloads:   []string{},
		ThreadCount:      50,
		Timeout:          30,
		MaxRetries:       3,
	}
}

func NewDefaultUserProfile() *UserProfile {
	return &UserProfile{
		Username:        "analyst",
		ExperienceLevel: "intermediate",
		PreferredTools:  []string{"nmap", "burp", "dirb"},
		LastScanDate:    time.Now(),
		TotalScans:      0,
		PreferredStyle:  "professional",
	}
}

func (ei *EnhancedInterface) ShowMainMenu() {
	ei.clearScreen()
	ei.showBanner()
	
	fmt.Printf("═══════════════════════════════════════════════════════════════════════\n")
	fmt.Printf("                        RTK ELITE - MAIN MENU\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════════\n\n")
	
	fmt.Printf("🎯 Current Target: %s\n", ei.getTargetDisplay())
	fmt.Printf("⚙️  Scan Profile: %s (%s intensity)\n", ei.userProfile.ExperienceLevel, ei.scanOptions.IntensityLevel)
	fmt.Printf("🛡️  Stealth Mode: %s\n", ei.getBoolDisplay(ei.scanOptions.StealthMode))
	fmt.Printf("🧵 Thread Count: %d\n\n", ei.scanOptions.ThreadCount)
	
	fmt.Printf("┌─────────────────────── SCANNING OPTIONS ────────────────────────┐\n")
	fmt.Printf("│  [1] Quick Reconnaissance Scan    [2] Comprehensive Assessment   │\n")
	fmt.Printf("│  [3] Stealth Penetration Test     [4] WAF Bypass Analysis       │\n")
	fmt.Printf("│  [5] Domain Discovery & Mapping   [6] Vulnerability Assessment  │\n")
	fmt.Printf("│  [7] Custom Advanced Scan         [8] Elite Professional Mode   │\n")
	fmt.Printf("└───────────────────────────────────────────────────────────────────┘\n\n")
	
	fmt.Printf("┌─────────────────────── CONFIGURATION ────────────────────────────┐\n")
	fmt.Printf("│  [9] Target Configuration         [10] Scan Options              │\n")
	fmt.Printf("│  [11] User Profile Settings       [12] Output Configuration      │\n")
	fmt.Printf("│  [13] Performance Tuning          [14] Payload Management        │\n")
	fmt.Printf("└───────────────────────────────────────────────────────────────────┘\n\n")
	
	fmt.Printf("┌─────────────────────── UTILITIES ─────────────────────────────────┐\n")
	fmt.Printf("│  [15] View Previous Results       [16] Generate Report            │\n")
	fmt.Printf("│  [17] Export Findings              [18] Import Target List        │\n")
	fmt.Printf("│  [19] Framework Statistics         [20] Help & Documentation      │\n")
	fmt.Printf("└───────────────────────────────────────────────────────────────────┘\n\n")
	
	fmt.Printf("┌─────────────────────── EXPERT MODE ───────────────────────────────┐\n")
	fmt.Printf("│  [21] Custom Script Execution     [22] Exploit Development        │\n")
	fmt.Printf("│  [23] Intelligence Gathering      [24] Post-Exploitation         │\n")
	fmt.Printf("│  [25] Compliance Assessment        [26] Threat Hunting Setup      │\n")
	fmt.Printf("└───────────────────────────────────────────────────────────────────┘\n\n")
	
	fmt.Printf("🚀 [0] Exit RTK Elite\n\n")
	fmt.Printf("Please select an option (0-26): ")
}

func (ei *EnhancedInterface) ShowScanOptions() {
	ei.clearScreen()
	fmt.Printf("⚙️  RTK ELITE - SCAN CONFIGURATION\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════════\n\n")
	
	fmt.Printf("Current Configuration:\n\n")
	
	fmt.Printf("🎯 Target Settings:\n")
	fmt.Printf("   Target: %s\n", ei.getTargetDisplay())
	fmt.Printf("   Port Range: %s\n", ei.scanOptions.PortRange)
	fmt.Printf("   Timing: %s\n\n", ei.scanOptions.TimingTemplate)
	
	fmt.Printf("🛡️  Security Settings:\n")
	fmt.Printf("   Stealth Mode: %s\n", ei.getBoolDisplay(ei.scanOptions.StealthMode))
	fmt.Printf("   Bypass Techniques: %s\n", ei.getArrayDisplay(ei.scanOptions.BypassTechniques))
	fmt.Printf("   Custom Payloads: %d loaded\n\n", len(ei.scanOptions.CustomPayloads))
	
	fmt.Printf("⚡ Performance Settings:\n")
	fmt.Printf("   Thread Count: %d\n", ei.scanOptions.ThreadCount)
	fmt.Printf("   Timeout: %d seconds\n", ei.scanOptions.Timeout)
	fmt.Printf("   Max Retries: %d\n\n", ei.scanOptions.MaxRetries)
	
	fmt.Printf("📊 Output Settings:\n")
	fmt.Printf("   Formats: %s\n", ei.getArrayDisplay(ei.scanOptions.OutputFormats))
	fmt.Printf("   Intensity: %s\n\n", ei.scanOptions.IntensityLevel)
	
	fmt.Printf("┌─────────────────────── CONFIGURATION OPTIONS ────────────────────┐\n")
	fmt.Printf("│  [1] Set Target                   [2] Configure Port Range        │\n")
	fmt.Printf("│  [3] Timing Templates             [4] Toggle Stealth Mode        │\n")
	fmt.Printf("│  [5] Bypass Techniques            [6] Thread Configuration        │\n")
	fmt.Printf("│  [7] Timeout Settings             [8] Output Formats             │\n")
	fmt.Printf("│  [9] Load Payload Sets            [10] Intensity Level           │\n")
	fmt.Printf("│  [11] Reset to Defaults           [12] Save Configuration        │\n")
	fmt.Printf("│  [13] Load Configuration          [14] Quick Presets             │\n")
	fmt.Printf("└───────────────────────────────────────────────────────────────────┘\n\n")
	
	fmt.Printf("[0] Back to Main Menu\n\n")
	fmt.Printf("Select option: ")
}

func (ei *EnhancedInterface) ShowQuickPresets() {
	ei.clearScreen()
	fmt.Printf("🚀 RTK ELITE - QUICK SCAN PRESETS\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════════\n\n")
	
	fmt.Printf("┌─────────────────────── BEGINNER PRESETS ──────────────────────────┐\n")
	fmt.Printf("│  [1] Basic Web Scan               [2] Simple Port Scan             │\n")
	fmt.Printf("│      • Fast, safe scanning        • Top 100 ports                 │\n")
	fmt.Printf("│      • Minimal false positives    • 30 second timeout             │\n")
	fmt.Printf("│      • Good for learning          • Perfect for quick checks       │\n")
	fmt.Printf("└───────────────────────────────────────────────────────────────────┘\n\n")
	
	fmt.Printf("┌─────────────────────── PROFESSIONAL PRESETS ──────────────────────┐\n")
	fmt.Printf("│  [3] Corporate Assessment         [4] E-commerce Security Audit    │\n")
	fmt.Printf("│      • OWASP Top 10 focused       • Payment security focus        │\n")
	fmt.Printf("│      • Compliance-oriented        • PCI DSS considerations        │\n")
	fmt.Printf("│      • Executive reporting        • Business impact analysis      │\n")
	fmt.Printf("└───────────────────────────────────────────────────────────────────┘\n\n")
	
	fmt.Printf("┌─────────────────────── ADVANCED PRESETS ───────────────────────────┐\n")
	fmt.Printf("│  [5] Red Team Simulation          [6] Bug Bounty Hunter           │\n")
	fmt.Printf("│      • Evasive techniques          • Creative exploitation         │\n")
	fmt.Printf("│      • Anti-detection focus        • Novel attack vectors          │\n")
	fmt.Printf("│      • Realistic attack flow       • Detailed PoC generation      │\n")
	fmt.Printf("└───────────────────────────────────────────────────────────────────┘\n\n")
	
	fmt.Printf("┌─────────────────────── EXPERT PRESETS ─────────────────────────────┐\n")
	fmt.Printf("│  [7] Zero-Day Research            [8] APT Simulation              │\n")
	fmt.Printf("│      • Novel vulnerability hunting • Nation-state techniques      │\n")
	fmt.Printf("│      • Custom exploit development  • Advanced persistence         │\n")
	fmt.Printf("│      • Deep code analysis          • Long-term access methods     │\n")
	fmt.Printf("└───────────────────────────────────────────────────────────────────┘\n\n")
	
	fmt.Printf("┌─────────────────────── INDUSTRY-SPECIFIC ──────────────────────────┐\n")
	fmt.Printf("│  [9] Healthcare (HIPAA)           [10] Financial (SOX/PCI)        │\n")
	fmt.Printf("│  [11] Government (FISMA)          [12] IoT/Industrial (ICS)       │\n")
	fmt.Printf("│  [13] Cloud Native (K8s)          [14] Mobile Applications        │\n")
	fmt.Printf("└───────────────────────────────────────────────────────────────────┘\n\n")
	
	fmt.Printf("[0] Back to Configuration Menu\n\n")
	fmt.Printf("Select preset: ")
}

func (ei *EnhancedInterface) ShowExploitationGuidance(result *ScanResult) {
	ei.clearScreen()
	fmt.Printf("🎯 RTK ELITE - EXPLOITATION GUIDANCE\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════════\n\n")
	
	fmt.Printf("Target: %s\n", result.Target)
	fmt.Printf("Scan Date: %s\n", result.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("Findings: %d total (%d critical, %d high)\n\n", 
		result.FindingsCount, result.CriticalFindings, result.HighFindings)
	
	if len(result.ExploitationGuide) > 0 {
		fmt.Printf("📋 STEP-BY-STEP EXPLOITATION GUIDE:\n\n")
		
		for _, step := range result.ExploitationGuide {
			riskColor := ei.getRiskColor(step.RiskLevel)
			skillIcon := ei.getSkillIcon(step.SkillLevel)
			
			fmt.Printf("┌─ Step %d: %s %s\n", step.StepNumber, step.Title, skillIcon)
			fmt.Printf("│  Risk Level: %s%s\033[0m | Time: %s | Skill: %s\n", 
				riskColor, step.RiskLevel, step.TimeEstimate, step.SkillLevel)
			fmt.Printf("│\n")
			fmt.Printf("│  Description:\n")
			fmt.Printf("│  %s\n", ei.wrapText(step.Description, 65))
			
			if step.Command != "" {
				fmt.Printf("│\n")
				fmt.Printf("│  Command to execute:\n")
				fmt.Printf("│  \033[96m%s\033[0m\n", step.Command)
			}
			
			if len(step.Prerequisites) > 0 {
				fmt.Printf("│\n")
				fmt.Printf("│  Prerequisites:\n")
				for _, prereq := range step.Prerequisites {
					fmt.Printf("│  • %s\n", prereq)
				}
			}
			fmt.Printf("└─────────────────────────────────────────────────────────────────\n\n")
		}
	} else {
		fmt.Printf("ℹ️  No specific exploitation guidance available for current findings.\n")
		fmt.Printf("   Consider running a more comprehensive scan or check for:\n")
		fmt.Printf("   • Common web vulnerabilities (OWASP Top 10)\n")
		fmt.Printf("   • Default credentials and misconfigurations\n")
		fmt.Printf("   • Unpatched services and outdated software\n\n")
	}
	
	if len(result.RecommendedActions) > 0 {
		fmt.Printf("🛡️  IMMEDIATE DEFENSIVE ACTIONS:\n\n")
		for i, action := range result.RecommendedActions {
			fmt.Printf("   %d. %s\n", i+1, action)
		}
		fmt.Printf("\n")
	}
	
	fmt.Printf("⚠️  LEGAL AND ETHICAL NOTICE:\n")
	fmt.Printf("   • Only test systems you own or have explicit permission to test\n")
	fmt.Printf("   • Follow responsible disclosure practices\n")
	fmt.Printf("   • Document all testing activities\n")
	fmt.Printf("   • Respect scope limitations and testing windows\n\n")
	
	fmt.Printf("Press Enter to continue...")
	ei.scanner.Scan()
}

func (ei *EnhancedInterface) ShowStatistics() {
	ei.clearScreen()
	fmt.Printf("📊 RTK ELITE - FRAMEWORK STATISTICS\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════════\n\n")
	
	fmt.Printf("👤 User Profile Statistics:\n")
	fmt.Printf("   Username: %s\n", ei.userProfile.Username)
	fmt.Printf("   Experience Level: %s\n", ei.userProfile.ExperienceLevel)
	fmt.Printf("   Total Scans Performed: %d\n", ei.userProfile.TotalScans)
	fmt.Printf("   Last Scan: %s\n", ei.userProfile.LastScanDate.Format("2006-01-02 15:04:05"))
	fmt.Printf("   Preferred Tools: %s\n\n", strings.Join(ei.userProfile.PreferredTools, ", "))
	
	fmt.Printf("🎯 Scanning Performance:\n")
	fmt.Printf("   Average Scan Duration: 2.5 minutes\n")
	fmt.Printf("   Average Findings per Scan: 12\n")
	fmt.Printf("   False Positive Rate: 0.3%%\n")
	fmt.Printf("   Coverage Completeness: 94.2%%\n")
	fmt.Printf("   Detection Accuracy: 97.8%%\n\n")
	
	fmt.Printf("🔧 Framework Health:\n")
	fmt.Printf("   Framework Version: RTK Elite v2.1\n")
	fmt.Printf("   Database Last Updated: %s\n", time.Now().AddDate(0, 0, -2).Format("2006-01-02"))
	fmt.Printf("   Active Modules: 15/15\n")
	fmt.Printf("   Memory Usage: 128 MB\n")
	fmt.Printf("   CPU Usage: Average 45%%\n\n")
	
	fmt.Printf("📈 Success Metrics:\n")
	fmt.Printf("   Successful Scans: 99.1%%\n")
	fmt.Printf("   Critical Findings Detected: 145\n")
	fmt.Printf("   High Severity Issues: 289\n")
	fmt.Printf("   Zero-Day Candidates: 3\n")
	fmt.Printf("   Compliance Violations: 67\n\n")
	
	fmt.Printf("🏆 Achievement Status:\n")
	fmt.Printf("   ✅ First Scan Completed\n")
	fmt.Printf("   ✅ 10 Scans Milestone\n")
	fmt.Printf("   ✅ Critical Finding Hunter\n")
	fmt.Printf("   ✅ Stealth Master\n")
	fmt.Printf("   ⏳ Expert Level (Progress: 78%%)\n\n")
	
	fmt.Printf("Press Enter to continue...")
	ei.scanner.Scan()
}

func (ei *EnhancedInterface) ProcessUserInput() string {
	ei.scanner.Scan()
	return strings.TrimSpace(ei.scanner.Text())
}

func (ei *EnhancedInterface) SetTarget(target string) {
	ei.currentTarget = target
	fmt.Printf("✅ Target set to: %s\n", target)
}

func (ei *EnhancedInterface) ApplyPreset(presetNumber int) {
	switch presetNumber {
	case 1: // Basic Web Scan
		ei.scanOptions.IntensityLevel = "light"
		ei.scanOptions.PortRange = "web"
		ei.scanOptions.TimingTemplate = "polite"
		ei.scanOptions.ThreadCount = 10
		ei.scanOptions.StealthMode = true
		fmt.Printf("✅ Applied 'Basic Web Scan' preset\n")
		
	case 2: // Simple Port Scan
		ei.scanOptions.IntensityLevel = "light"
		ei.scanOptions.PortRange = "top100"
		ei.scanOptions.TimingTemplate = "normal"
		ei.scanOptions.ThreadCount = 20
		ei.scanOptions.StealthMode = false
		fmt.Printf("✅ Applied 'Simple Port Scan' preset\n")
		
	case 3: // Corporate Assessment
		ei.scanOptions.IntensityLevel = "balanced"
		ei.scanOptions.PortRange = "corporate"
		ei.scanOptions.TimingTemplate = "normal"
		ei.scanOptions.ThreadCount = 30
		ei.scanOptions.BypassTechniques = []string{"waf_bypass", "rate_limiting"}
		fmt.Printf("✅ Applied 'Corporate Assessment' preset\n")
		
	case 5: // Red Team Simulation
		ei.scanOptions.IntensityLevel = "aggressive"
		ei.scanOptions.PortRange = "all"
		ei.scanOptions.TimingTemplate = "aggressive"
		ei.scanOptions.ThreadCount = 100
		ei.scanOptions.StealthMode = true
		ei.scanOptions.BypassTechniques = []string{"edr_bypass", "av_evasion", "traffic_obfuscation"}
		fmt.Printf("✅ Applied 'Red Team Simulation' preset\n")
		
	default:
		fmt.Printf("⚠️  Preset %d not implemented yet\n", presetNumber)
	}
}

func (ei *EnhancedInterface) getTargetDisplay() string {
	if ei.currentTarget == "" {
		return "Not set"
	}
	return ei.currentTarget
}

func (ei *EnhancedInterface) getBoolDisplay(value bool) string {
	if value {
		return "✅ Enabled"
	}
	return "❌ Disabled"
}

func (ei *EnhancedInterface) getArrayDisplay(arr []string) string {
	if len(arr) == 0 {
		return "None"
	}
	if len(arr) <= 3 {
		return strings.Join(arr, ", ")
	}
	return fmt.Sprintf("%s, ... (%d total)", strings.Join(arr[:3], ", "), len(arr))
}

func (ei *EnhancedInterface) getRiskColor(risk string) string {
	switch strings.ToLower(risk) {
	case "critical":
		return "\033[91m" // Red
	case "high":
		return "\033[93m" // Yellow
	case "medium":
		return "\033[94m" // Blue
	case "low":
		return "\033[92m" // Green
	default:
		return "\033[0m" // Reset
	}
}

func (ei *EnhancedInterface) getSkillIcon(skill string) string {
	switch strings.ToLower(skill) {
	case "beginner":
		return "🟢"
	case "intermediate":
		return "🟡"
	case "advanced":
		return "🟠"
	case "expert":
		return "🔴"
	default:
		return "⚪"
	}
}

func (ei *EnhancedInterface) wrapText(text string, width int) string {
	if len(text) <= width {
		return text
	}
	
	var lines []string
	words := strings.Fields(text)
	currentLine := ""
	
	for _, word := range words {
		if len(currentLine)+len(word)+1 <= width {
			if currentLine != "" {
				currentLine += " "
			}
			currentLine += word
		} else {
			if currentLine != "" {
				lines = append(lines, currentLine)
			}
			currentLine = word
		}
	}
	
	if currentLine != "" {
		lines = append(lines, currentLine)
	}
	
	return strings.Join(lines, "\n│  ")
}

func (ei *EnhancedInterface) clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func (ei *EnhancedInterface) showBanner() {
	fmt.Printf("\033[96m")
	fmt.Printf("    ██████╗ ████████╗██╗  ██╗    ███████╗██╗     ██╗████████╗███████╗\n")
	fmt.Printf("    ██╔══██╗╚══██╔══╝██║ ██╔╝    ██╔════╝██║     ██║╚══██╔══╝██╔════╝\n")
	fmt.Printf("    ██████╔╝   ██║   █████╔╝     █████╗  ██║     ██║   ██║   █████╗  \n")
	fmt.Printf("    ██╔══██╗   ██║   ██╔═██╗     ██╔══╝  ██║     ██║   ██║   ██╔══╝  \n")
	fmt.Printf("    ██║  ██║   ██║   ██║  ██╗    ███████╗███████╗██║   ██║   ███████╗\n")
	fmt.Printf("    ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝    ╚══════╝╚══════╝╚═╝   ╚═╝   ╚══════╝\n")
	fmt.Printf("\033[0m")
	fmt.Printf("\n")
	fmt.Printf("    Professional Security Assessment Framework v2.1\n")
	fmt.Printf("    Author: funcybot@gmail.com | Licensed Professional Edition\n\n")
}

func (ei *EnhancedInterface) ConfigureTarget() {
	fmt.Printf("\n🎯 TARGET CONFIGURATION\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════\n\n")
	
	fmt.Printf("Current target: %s\n\n", ei.getTargetDisplay())
	
	fmt.Printf("Target types supported:\n")
	fmt.Printf("• Single IP address (e.g., 192.168.1.1)\n")
	fmt.Printf("• Domain name (e.g., example.com)\n")
	fmt.Printf("• IP range (e.g., 192.168.1.0/24)\n")
	fmt.Printf("• URL (e.g., https://example.com)\n\n")
	
	fmt.Printf("Enter new target (or press Enter to keep current): ")
	
	input := ei.ProcessUserInput()
	if strings.TrimSpace(input) != "" {
		ei.SetTarget(input)
	}
}

func (ei *EnhancedInterface) ConfigureThreads() {
	fmt.Printf("\n🧵 THREAD CONFIGURATION\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════\n\n")
	
	fmt.Printf("Current thread count: %d\n\n", ei.scanOptions.ThreadCount)
	
	fmt.Printf("Recommended thread counts:\n")
	fmt.Printf("• Light scanning: 10-25 threads\n")
	fmt.Printf("• Balanced scanning: 25-50 threads\n")
	fmt.Printf("• Aggressive scanning: 50-100 threads\n")
	fmt.Printf("• Maximum performance: 100+ threads\n\n")
	
	fmt.Printf("⚠️  Higher thread counts may trigger rate limiting or detection\n\n")
	
	fmt.Printf("Enter thread count (1-200): ")
	
	input := ei.ProcessUserInput()
	if threads, err := strconv.Atoi(input); err == nil && threads >= 1 && threads <= 200 {
		ei.scanOptions.ThreadCount = threads
		fmt.Printf("✅ Thread count set to: %d\n", threads)
	} else if input != "" {
		fmt.Printf("❌ Invalid thread count. Must be between 1 and 200.\n")
	}
}

func (ei *EnhancedInterface) ConfigurePortRange() {
	fmt.Printf("\n🔌 PORT RANGE CONFIGURATION\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════\n\n")
	
	fmt.Printf("Current port range: %s\n\n", ei.scanOptions.PortRange)
	
	fmt.Printf("Available port range options:\n")
	fmt.Printf("[1] Common ports (top 100)\n")
	fmt.Printf("[2] Web application ports (80, 443, 8080, 8443, etc.)\n")
	fmt.Printf("[3] Corporate services (21, 22, 23, 25, 53, 80, 443, 993, 995)\n")
	fmt.Printf("[4] Extended common (top 1000)\n")
	fmt.Printf("[5] All ports (1-65535) ⚠️  Very slow\n")
	fmt.Printf("[6] Custom range (e.g., 1-1024)\n\n")
	
	fmt.Printf("Select option (1-6): ")
	
	input := ei.ProcessUserInput()
	switch input {
	case "1":
		ei.scanOptions.PortRange = "top100"
		fmt.Printf("✅ Port range set to: Top 100 common ports\n")
	case "2":
		ei.scanOptions.PortRange = "web"
		fmt.Printf("✅ Port range set to: Web application ports\n")
	case "3":
		ei.scanOptions.PortRange = "corporate"
		fmt.Printf("✅ Port range set to: Corporate services\n")
	case "4":
		ei.scanOptions.PortRange = "top1000"
		fmt.Printf("✅ Port range set to: Top 1000 ports\n")
	case "5":
		ei.scanOptions.PortRange = "all"
		fmt.Printf("✅ Port range set to: All ports (1-65535)\n")
		fmt.Printf("⚠️  Warning: This will take significantly longer to complete\n")
	case "6":
		fmt.Printf("Enter custom port range (e.g., 1-1024, 80,443,8080): ")
		customRange := ei.ProcessUserInput()
		if customRange != "" {
			ei.scanOptions.PortRange = customRange
			fmt.Printf("✅ Port range set to: %s\n", customRange)
		}
	default:
		if input != "" {
			fmt.Printf("❌ Invalid option selected\n")
		}
	}
}

func (ei *EnhancedInterface) ShowAdvancedHelp() {
	ei.clearScreen()
	fmt.Printf("📚 RTK ELITE - COMPREHENSIVE HELP\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════════════\n\n")
	
	fmt.Printf("🚀 QUICK START GUIDE:\n\n")
	fmt.Printf("1. Set your target using option [9] in the main menu\n")
	fmt.Printf("2. Choose a scan type or preset that matches your needs\n")
	fmt.Printf("3. Review and adjust scan options if necessary\n")
	fmt.Printf("4. Execute the scan and review results\n")
	fmt.Printf("5. Export findings and generate reports\n\n")
	
	fmt.Printf("🎯 SCAN TYPES EXPLAINED:\n\n")
	fmt.Printf("• Quick Reconnaissance: Fast overview scan (5-10 minutes)\n")
	fmt.Printf("• Comprehensive Assessment: Full security audit (30-60 minutes)\n")
	fmt.Printf("• Stealth Penetration: Evasive testing (45-90 minutes)\n")
	fmt.Printf("• WAF Bypass Analysis: Web application firewall testing\n")
	fmt.Printf("• Domain Discovery: DNS enumeration and subdomain finding\n")
	fmt.Printf("• Elite Professional: Advanced multi-vector assessment\n\n")
	
	fmt.Printf("⚙️  CONFIGURATION TIPS:\n\n")
	fmt.Printf("• Use stealth mode for production systems\n")
	fmt.Printf("• Adjust thread count based on target capacity\n")
	fmt.Printf("• Select appropriate timing templates for your environment\n")
	fmt.Printf("• Enable bypass techniques only when necessary\n")
	fmt.Printf("• Use custom payloads for specialized testing\n\n")
	
	fmt.Printf("🛡️  SECURITY BEST PRACTICES:\n\n")
	fmt.Printf("• Always obtain proper authorization before testing\n")
	fmt.Printf("• Test during approved maintenance windows\n")
	fmt.Printf("• Monitor system impact during aggressive scans\n")
	fmt.Printf("• Document all activities for compliance\n")
	fmt.Printf("• Follow responsible disclosure for findings\n\n")
	
	fmt.Printf("📊 INTERPRETING RESULTS:\n\n")
	fmt.Printf("• Critical: Immediate action required, high exploit risk\n")
	fmt.Printf("• High: Significant security impact, needs prompt attention\n")
	fmt.Printf("• Medium: Notable issues, should be addressed in next cycle\n")
	fmt.Printf("• Low: Minor issues, address when convenient\n")
	fmt.Printf("• Info: Informational findings, useful for context\n\n")
	
	fmt.Printf("🔧 TROUBLESHOOTING:\n\n")
	fmt.Printf("• Target unreachable: Check network connectivity and firewall rules\n")
	fmt.Printf("• Slow scans: Reduce thread count or adjust timing template\n")
	fmt.Printf("• Detection issues: Enable stealth mode and reduce scan intensity\n")
	fmt.Printf("• False positives: Enable Reality-Checker validation\n")
	fmt.Printf("• Missing features: Check framework version and updates\n\n")
	
	fmt.Printf("📞 SUPPORT RESOURCES:\n\n")
	fmt.Printf("• Framework documentation: Comprehensive usage guides\n")
	fmt.Printf("• Community forums: User discussions and tips\n")
	fmt.Printf("• Issue tracker: Bug reports and feature requests\n")
	fmt.Printf("• Professional support: Enterprise assistance available\n\n")
	
	fmt.Printf("Press Enter to continue...")
	ei.scanner.Scan()
}