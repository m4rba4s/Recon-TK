package ui

import (
	"fmt"
	"strings"
	"os"
	"os/exec"
	"time"

	"github.com/fatih/color"
)

type InteractiveUI struct {
	target      string
	attackMode  int
	stealthMode int
	cynicalMode int
	aiMode      int
	reportMode  int
	exploitMode int
	perfMode    int
	width       int
	height      int
}

var (
	red    = color.New(color.FgRed, color.Bold)
	green  = color.New(color.FgGreen, color.Bold)
	blue   = color.New(color.FgBlue, color.Bold)
	cyan   = color.New(color.FgCyan, color.Bold)
	yellow = color.New(color.FgYellow, color.Bold)
	purple = color.New(color.FgMagenta, color.Bold)
	white  = color.New(color.FgWhite, color.Bold)
)

func NewInteractiveUI() *InteractiveUI {
	return &InteractiveUI{
		target:      "",
		attackMode:  1,
		stealthMode: 1,
		cynicalMode: 0,
		aiMode:      1,
		reportMode:  1,
		exploitMode: 1,
		perfMode:    1,
		width:       120,
		height:      35,
	}
}

func (ui *InteractiveUI) clearScreen() {
	cmd := exec.Command("clear")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func (ui *InteractiveUI) getSkullArt() string {
	return `
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⠴⠶⠶⠤⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⢀⣤⠶⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠶⣤⡀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⢀⡴⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⢦⡀⠀⠀⠀⠀
    ⠀⠀⠀⣰⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣆⠀⠀⠀
    ⠀⠀⢠⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡄⠀⠀
    ⠀⠀⣿⠁⠀⠀⢸⣿⣿⣶⡀⠀⠀⠀⠀⠀⠀⠀⢀⣶⣿⣿⡇⠀⠀⠀⠈⣿⠀⠀
    ⠀⢸⡏⠀⠀⠀⢸⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⡇⠀⠀⠀⠀⢹⡇⠀
    ⠀⣿⠀⠀⠀⠀⠀⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠀⠀⠀⠀⠀⠀⣿⠀
    ⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀
    ⠀⢿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡿⠀
    ⠀⠘⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⠃⠀
    ⠀⠀⠹⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠏⠀⠀
    ⠀⠀⠀⠙⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⠋⠀⠀⠀
    ⠀⠀⠀⠀⠀⠛⢦⣄⡀⠀⠀⠀⢰⣿⣿⡆⠀⠀⠀⠀⢀⣠⡴⠛⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠈⠙⠳⠶⣤⣈⣉⣉⣁⣤⠶⠚⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
`
}

func (ui *InteractiveUI) drawBorder(title string, content string) {
	borderChar := "═"
	cornerTL := "╔"
	cornerTR := "╗"
	cornerBL := "╚"
	cornerBR := "╝"
	vertical := "║"
	
	titleLine := fmt.Sprintf("%s %s %s", cornerTL, title, cornerTR)
	red.Print(titleLine)
	for i := len(titleLine) - 10; i < ui.width; i++ {
		red.Print(borderChar)
	}
	fmt.Println()
	
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		red.Print(vertical)
		fmt.Print(line)
		spaces := ui.width - len(line) - 2
		for i := 0; i < spaces; i++ {
			fmt.Print(" ")
		}
		red.Print(vertical)
		fmt.Println()
	}
	
	red.Print(cornerBL)
	for i := 0; i < ui.width-2; i++ {
		red.Print(borderChar)
	}
	red.Print(cornerBR)
	fmt.Println()
}

func (ui *InteractiveUI) drawHeader() {
	skull := ui.getSkullArt()
	
	header := fmt.Sprintf(`%s
🚀 RECON-TK v2.0 - ELITE ATTACK ORCHESTRATOR 🚀
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💀 "Time to skull-fuck some firewalls and make admins cry"
⚡ Advanced AI-Powered Penetration Testing Framework
🎯 Multi-Vector Attack Orchestration System`, skull)

	cyan.Println(header)
	fmt.Println()
}

func (ui *InteractiveUI) drawTargetInput() {
	green.Print("🎯 TARGET: ")
	if ui.target == "" {
		yellow.Print("[Enter target hostname or IP] ")
	} else {
		white.Printf("[%s] ", ui.target)
	}
	fmt.Println()
	fmt.Println()
}

func (ui *InteractiveUI) drawOptions() {
	attackModes := []string{"🔍 Recon Only", "💀 Full Elite", "🎭 Custom Chain"}
	stealthModes := []string{"👻 Ghost Scan", "🥷 Max Stealth", "🔥 Loud & Proud"}
	cynicalModes := []string{"🎪 Savage English", "💣 Brutal Russian", "🎭 Professional"}
	aiModes := []string{"🤖 GPT-4", "🧠 Auto-Learn", "✋ Manual"}
	reportModes := []string{"📊 Live", "📄 HTML", "🔧 JSON"}
	exploitModes := []string{"🛡️ Safe", "⚔️ Aggressive", "☢️ Nuclear"}
	perfModes := []string{"⚡ Fast", "⚖️ Balanced", "🔍 Thorough"}

	fmt.Printf("%-20s %-20s %-20s %-20s\n", 
		purple.Sprint("🎭 Attack Mode:"), 
		blue.Sprint("🥷 Stealth Mode:"), 
		cyan.Sprint("🤖 AI Mode:"), 
		green.Sprint("📊 Reporting:"))
	
	for i := 0; i < 3; i++ {
		marker1 := " "
		marker2 := " "
		marker3 := " "
		marker4 := " "
		
		if i == ui.attackMode { marker1 = "●" }
		if i == ui.stealthMode { marker2 = "●" }
		if i == ui.aiMode { marker3 = "●" }
		if i == ui.reportMode { marker4 = "●" }
		
		fmt.Printf("[%s] %-16s [%s] %-16s [%s] %-16s [%s] %-16s\n",
			marker1, attackModes[i],
			marker2, stealthModes[i], 
			marker3, aiModes[i],
			marker4, reportModes[i])
	}
	
	fmt.Println()
	
	fmt.Printf("%-20s %-20s %-20s %-20s\n",
		red.Sprint("💀 Exploit Level:"),
		yellow.Sprint("🎪 Cynical Mode:"),
		purple.Sprint("⚡ Performance:"),
		white.Sprint("🔧 Advanced:"))
		
	for i := 0; i < 3; i++ {
		marker1 := " "
		marker2 := " "
		marker3 := " "
		
		if i == ui.exploitMode { marker1 = "●" }
		if i == ui.cynicalMode { marker2 = "●" }
		if i == ui.perfMode { marker3 = "●" }
		
		advancedOptions := []string{"🔧 Custom", "🌐 Proxies", "🔑 API Keys"}
		
		fmt.Printf("[%s] %-16s [%s] %-16s [%s] %-16s [ ] %-16s\n",
			marker1, exploitModes[i],
			marker2, cynicalModes[i],
			marker3, perfModes[i],
			advancedOptions[i])
	}
}

func (ui *InteractiveUI) drawControls() {
	fmt.Println()
	red.Print("🚀 [L] LAUNCH ATTACK")
	fmt.Print(" | ")
	blue.Print("📋 [P] LOAD PRESET") 
	fmt.Print(" | ")
	green.Print("⚙️ [S] SETTINGS")
	fmt.Print(" | ")
	yellow.Print("❌ [Q] EXIT")
	fmt.Println()
	fmt.Println()
	
	cyan.Print("💡 Controls: ")
	white.Print("[1-3] Attack Mode | [4-6] Stealth | [7-9] AI | [A-C] Cynical | [T] Target")
	fmt.Println()
}

func (ui *InteractiveUI) waitForInput() string {
	fmt.Print(green.Sprint(">>> "))
	var input string
	fmt.Scanln(&input)
	return strings.ToLower(input)
}

func (ui *InteractiveUI) processInput(input string) bool {
	switch input {
	case "q", "quit", "exit":
		return false
	case "l", "launch":
		ui.launchAttack()
	case "t", "target":
		ui.setTarget()
	case "1":
		ui.attackMode = 0
	case "2":
		ui.attackMode = 1
	case "3":
		ui.attackMode = 2
	case "4":
		ui.stealthMode = 0
	case "5":
		ui.stealthMode = 1
	case "6":
		ui.stealthMode = 2
	case "7":
		ui.aiMode = 0
	case "8":
		ui.aiMode = 1
	case "9":
		ui.aiMode = 2
	case "a":
		ui.cynicalMode = 0
	case "b":
		ui.cynicalMode = 1
	case "c":
		ui.cynicalMode = 2
	case "p", "preset":
		ui.loadPreset()
	case "s", "settings":
		ui.showSettings()
	}
	return true
}

func (ui *InteractiveUI) setTarget() {
	ui.clearScreen()
	ui.drawHeader()
	
	cyan.Println("🎯 TARGET CONFIGURATION")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━")
	
	white.Print("Enter target (hostname/IP/CIDR): ")
	fmt.Scanln(&ui.target)
	
	if ui.target != "" {
		green.Printf("✅ Target set: %s\n", ui.target)
		time.Sleep(1 * time.Second)
	}
}

func (ui *InteractiveUI) launchAttack() {
	if ui.target == "" {
		red.Println("❌ Please set a target first! Press [T] to configure.")
		time.Sleep(2 * time.Second)
		return
	}
	
	ui.clearScreen()
	ui.drawHeader()
	
	red.Println("🚀 LAUNCHING ELITE ATTACK SEQUENCE")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	
	yellow.Printf("Target: %s\n", ui.target)
	
	cynicalMessages := []string{
		"💀 Time to skull-fuck this firewall",
		"🖕 Admin's about to have a very bad day",
		"⚡ Preparing to penetrate harder than a prison shower",
		"🔥 This target's gonna get fucked sideways",
	}
	
	for i, msg := range cynicalMessages {
		red.Printf("[%d/4] %s\n", i+1, msg)
		time.Sleep(500 * time.Millisecond)
	}
	
	fmt.Println()
	green.Println("✅ Attack launched! Check main CLI for results...")
	
	ui.buildCommand()
	
	white.Print("Press Enter to return to menu...")
	fmt.Scanln()
}

func (ui *InteractiveUI) buildCommand() string {
	cmd := fmt.Sprintf("./recon-toolkit elite -t %s", ui.target)
	
	if ui.attackMode == 1 {
		cmd += " --exploit --bypass"
	}
	if ui.stealthMode == 1 {
		cmd += " --evasion"
	}
	if ui.aiMode == 0 {
		cmd += " --ai"
	}
	if ui.cynicalMode < 2 {
		levels := []string{"savage", "brutal"}
		cmd += fmt.Sprintf(" --cynical --level %s", levels[ui.cynicalMode])
	}
	if ui.exploitMode == 1 {
		cmd += " --aggressive"
	}
	if ui.reportMode < 2 {
		formats := []string{"html", "json"}
		cmd += fmt.Sprintf(" --report --format %s", formats[ui.reportMode])
	}
	
	cyan.Printf("Generated command: %s\n", cmd)
	return cmd
}

func (ui *InteractiveUI) loadPreset() {
	presets := []string{
		"🎯 Quick Recon",
		"💀 Full Nuclear",
		"🥷 Ghost Mode",
		"🤖 AI Autonomous",
	}
	
	ui.clearScreen()
	ui.drawHeader()
	
	green.Println("📋 ATTACK PRESETS")
	fmt.Println("━━━━━━━━━━━━━━━━━━")
	
	for i, preset := range presets {
		fmt.Printf("[%d] %s\n", i+1, preset)
	}
	
	white.Print("\nSelect preset (1-4): ")
	var choice string
	fmt.Scanln(&choice)
	
	switch choice {
	case "1":
		ui.attackMode, ui.stealthMode, ui.exploitMode = 0, 1, 0
	case "2":
		ui.attackMode, ui.stealthMode, ui.exploitMode = 1, 2, 2
		ui.cynicalMode = 0
	case "3":
		ui.attackMode, ui.stealthMode, ui.exploitMode = 1, 0, 0
	case "4":
		ui.attackMode, ui.aiMode, ui.cynicalMode = 1, 0, 0
	}
	
	green.Println("✅ Preset loaded!")
	time.Sleep(1 * time.Second)
}

func (ui *InteractiveUI) showSettings() {
	ui.clearScreen()
	ui.drawHeader()
	
	blue.Println("⚙️ ADVANCED SETTINGS")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━")
	
	settings := []string{
		"🌐 Proxy Configuration",
		"🔑 API Keys Setup", 
		"🎨 Color Themes",
		"💾 Save Configuration",
		"🔄 Reset to Defaults",
	}
	
	for i, setting := range settings {
		fmt.Printf("[%d] %s\n", i+1, setting)
	}
	
	white.Print("\nPress Enter to return...")
	fmt.Scanln()
}

func (ui *InteractiveUI) Run() {
	for {
		ui.clearScreen()
		ui.drawHeader()
		ui.drawTargetInput()
		ui.drawOptions()
		ui.drawControls()
		
		input := ui.waitForInput()
		if !ui.processInput(input) {
			break
		}
	}
	
	red.Println("💀 Thanks for using RECON-TK! Happy skull-fucking! 🚀")
}