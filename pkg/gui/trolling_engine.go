package gui

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"

	"recon-toolkit/pkg/core"
)

// TrollingEngine - Legendary sarcastic humor and roasting engine
type TrollingEngine struct {
	logger         core.Logger
	config         *TrollingConfig
	roastDatabase  *RoastDatabase
	humorLevel     HumorLevel
	personality    PersonalityType
	targetContext  map[string]interface{}
	mutex          sync.RWMutex
}

type TrollingConfig struct {
	HumorLevel      HumorLevel      `json:"humor_level"`
	Personality     PersonalityType `json:"personality"`
	EnableRoasting  bool            `json:"enable_roasting"`
	EnableSarcasm   bool            `json:"enable_sarcasm"`
	EnableCynicism  bool            `json:"enable_cynicism"`
	EnableSavagery  bool            `json:"enable_savagery"`
	AdaptiveHumor   bool            `json:"adaptive_humor"`
	ContextAware    bool            `json:"context_aware"`
	SafeMode        bool            `json:"safe_mode"`
}

type HumorLevel int
type PersonalityType int

const (
	HumorChill HumorLevel = iota
	HumorSarcastic
	HumorBrutal
	HumorSavage
	HumorNuclear
)

const (
	PersonalityEliteHacker PersonalityType = iota
	PersonalityMadScientist
	PersonalityCyberNinja
	PersonalityAIOverlord
	PersonalityComedyGenius
)

type RoastDatabase struct {
	vulnerabilityRoasts map[string][]RoastTemplate
	generalRoasts       []RoastTemplate
	contextualRoasts    map[string][]RoastTemplate
	severityRoasts      map[core.Severity][]RoastTemplate
	personalityRoasts   map[PersonalityType][]RoastTemplate
	mutex               sync.RWMutex
}

type RoastTemplate struct {
	Template    string      `json:"template"`
	Variables   []string    `json:"variables"`
	HumorLevel  HumorLevel  `json:"humor_level"`
	Personality PersonalityType `json:"personality"`
	Context     string      `json:"context"`
	Severity    string      `json:"severity"`
	Timestamp   time.Time   `json:"timestamp"`
	UsageCount  int         `json:"usage_count"`
	Rating      float64     `json:"rating"`
}

type InteractiveGUI struct {
	logger        core.Logger
	trollEngine   *TrollingEngine
	webServer     *http.Server
	config        *GUIConfig
	sessionData   map[string]*SessionContext
	templates     *template.Template
	mutex         sync.RWMutex
}

type GUIConfig struct {
	Port           int    `json:"port"`
	Theme          string `json:"theme"`
	EnableWebUI    bool   `json:"enable_web_ui"`
	EnableTerminal bool   `json:"enable_terminal"`
	AutoRoast      bool   `json:"auto_roast"`
	LiveFeed       bool   `json:"live_feed"`
}

type SessionContext struct {
	SessionID     string                 `json:"session_id"`
	StartTime     time.Time              `json:"start_time"`
	Target        string                 `json:"target"`
	Findings      []VulnerabilityFinding `json:"findings"`
	RoastHistory  []string               `json:"roast_history"`
	UserProfile   UserProfile            `json:"user_profile"`
	Preferences   map[string]interface{} `json:"preferences"`
}

type VulnerabilityFinding struct {
	Type        string        `json:"type"`
	Severity    core.Severity `json:"severity"`
	Description string        `json:"description"`
	Target      string        `json:"target"`
	Evidence    string        `json:"evidence"`
	Roast       string        `json:"roast"`
	Timestamp   time.Time     `json:"timestamp"`
}

type UserProfile struct {
	Experience  string `json:"experience"`
	Preferences string `json:"preferences"`
	Humor       string `json:"humor"`
}

// NewTrollingEngine creates legendary roasting engine
func NewTrollingEngine(logger core.Logger, config *TrollingConfig) *TrollingEngine {
	if config == nil {
		config = &TrollingConfig{
			HumorLevel:     HumorSarcastic,
			Personality:    PersonalityEliteHacker,
			EnableRoasting: true,
			EnableSarcasm:  true,
			EnableCynicism: true,
			EnableSavagery: false,
			AdaptiveHumor:  true,
			ContextAware:   true,
			SafeMode:       false,
		}
	}

	engine := &TrollingEngine{
		logger:        logger,
		config:        config,
		humorLevel:    config.HumorLevel,
		personality:   config.Personality,
		targetContext: make(map[string]interface{}),
		roastDatabase: &RoastDatabase{
			vulnerabilityRoasts: make(map[string][]RoastTemplate),
			generalRoasts:       make([]RoastTemplate, 0),
			contextualRoasts:    make(map[string][]RoastTemplate),
			severityRoasts:      make(map[core.Severity][]RoastTemplate),
			personalityRoasts:   make(map[PersonalityType][]RoastTemplate),
		},
	}

	// Initialize roast database
	engine.initializeRoastDatabase()

	return engine
}

// GenerateRoast creates legendary roasts for vulnerabilities
func (t *TrollingEngine) GenerateRoast(vuln *VulnerabilityFinding) string {
	t.logger.Debug("🎭 Generating legendary roast for vulnerability", 
		core.NewField("type", vuln.Type),
		core.NewField("severity", vuln.Severity))

	// Select appropriate roast based on context
	var roastTemplates []RoastTemplate

	// Check for vulnerability-specific roasts
	if templates, exists := t.roastDatabase.vulnerabilityRoasts[vuln.Type]; exists {
		roastTemplates = templates
	} else if templates, exists := t.roastDatabase.severityRoasts[vuln.Severity]; exists {
		roastTemplates = templates
	} else {
		roastTemplates = t.roastDatabase.generalRoasts
	}

	// Filter by humor level and personality
	filteredTemplates := t.filterTemplates(roastTemplates)
	
	if len(filteredTemplates) == 0 {
		return t.generateFallbackRoast(vuln)
	}

	// Select random template
	template := filteredTemplates[t.randomInt(len(filteredTemplates))]
	
	// Generate roast with context
	roast := t.processRoastTemplate(template, vuln)
	
	// Update usage statistics
	template.UsageCount++
	
	return roast
}

// initializeRoastDatabase populates the legendary roast database
func (t *TrollingEngine) initializeRoastDatabase() {
	t.logger.Info("🎪 Initializing legendary roast database - preparing maximum humor!")

	// SQL Injection roasts
	t.roastDatabase.vulnerabilityRoasts["sql_injection"] = []RoastTemplate{
		{
			Template:    "SQL injection found! This database security is weaker than {{.context.admin_password}}",
			HumorLevel:  HumorSarcastic,
			Personality: PersonalityEliteHacker,
			Context:     "sql_injection",
		},
		{
			Template:    "🤡 SQL injection detected! Did the developer learn SQL from a cereal box?",
			HumorLevel:  HumorBrutal,
			Personality: PersonalityMadScientist,
			Context:     "sql_injection",
		},
		{
			Template:    "💀 SQL injection! Their input validation is more broken than your heart after your ex left",
			HumorLevel:  HumorSavage,
			Personality: PersonalityComedyGenius,
			Context:     "sql_injection",
		},
		{
			Template:    "☠️ SQL injection found! This query protection is about as useful as a screen door on a submarine",
			HumorLevel:  HumorNuclear,
			Personality: PersonalityAIOverlord,
			Context:     "sql_injection",
		},
	}

	// XSS roasts
	t.roastDatabase.vulnerabilityRoasts["xss"] = []RoastTemplate{
		{
			Template:    "🎯 XSS vulnerability! Input sanitization is clearly optional in their development process",
			HumorLevel:  HumorSarcastic,
			Personality: PersonalityEliteHacker,
			Context:     "xss",
		},
		{
			Template:    "💥 XSS found! Their JavaScript validation is faker than their security confidence",
			HumorLevel:  HumorBrutal,
			Personality: PersonalityCyberNinja,
			Context:     "xss",
		},
		{
			Template:    "🔥 XSS detected! Client-side filtering? More like client-side comedy hour!",
			HumorLevel:  HumorSavage,
			Personality: PersonalityComedyGenius,
			Context:     "xss",
		},
	}

	// Directory traversal roasts
	t.roastDatabase.vulnerabilityRoasts["directory_traversal"] = []RoastTemplate{
		{
			Template:    "📁 Directory traversal! Path validation is apparently a foreign concept here",
			HumorLevel:  HumorSarcastic,
			Personality: PersonalityEliteHacker,
			Context:     "directory_traversal",
		},
		{
			Template:    "🗂️ Path traversal found! Their file system security has more holes than Swiss cheese",
			HumorLevel:  HumorBrutal,
			Personality: PersonalityMadScientist,
			Context:     "directory_traversal",
		},
		{
			Template:    "💀 Directory traversal! File access controls are more open than a 24/7 diner",
			HumorLevel:  HumorSavage,
			Personality: PersonalityAIOverlord,
			Context:     "directory_traversal",
		},
	}

	// Command injection roasts
	t.roastDatabase.vulnerabilityRoasts["command_injection"] = []RoastTemplate{
		{
			Template:    "⚡ Command injection! Input validation is clearly a myth in this codebase",
			HumorLevel:  HumorSarcastic,
			Personality: PersonalityEliteHacker,
			Context:     "command_injection",
		},
		{
			Template:    "💀 Command injection found! System calls without validation? That's some next-level stupidity",
			HumorLevel:  HumorBrutal,
			Personality: PersonalityMadScientist,
			Context:     "command_injection",
		},
		{
			Template:    "🖕 Command injection! Shell access easier than ordering a fucking pizza",
			HumorLevel:  HumorNuclear,
			Personality: PersonalityAIOverlord,
			Context:     "command_injection",
		},
	}

	// Severity-based roasts
	t.roastDatabase.severityRoasts[core.SeverityCritical] = []RoastTemplate{
		{
			Template:    "🚨 CRITICAL vulnerability! This is more dangerous than pineapple on pizza",
			HumorLevel:  HumorSarcastic,
			Personality: PersonalityEliteHacker,
		},
		{
			Template:    "💥 CRITICAL finding! Security level: Wet tissue paper in a hurricane",
			HumorLevel:  HumorBrutal,
			Personality: PersonalityMadScientist,
		},
		{
			Template:    "☠️ CRITICAL vulnerability! Their security team must be on permanent vacation in Fuckoffistan",
			HumorLevel:  HumorNuclear,
			Personality: PersonalityAIOverlord,
		},
	}

	t.roastDatabase.severityRoasts[core.SeverityHigh] = []RoastTemplate{
		{
			Template:    "🔥 HIGH severity issue! Another day, another amateur hour security implementation",
			HumorLevel:  HumorSarcastic,
			Personality: PersonalityEliteHacker,
		},
		{
			Template:    "⚡ HIGH risk vulnerability! Did they outsource security to a magic 8-ball?",
			HumorLevel:  HumorBrutal,
			Personality: PersonalityComedyGenius,
		},
	}

	t.roastDatabase.severityRoasts[core.SeverityMedium] = []RoastTemplate{
		{
			Template:    "⚠️ MEDIUM severity finding! Not terrible, but still disappointing",
			HumorLevel:  HumorSarcastic,
			Personality: PersonalityEliteHacker,
		},
		{
			Template:    "🎭 MEDIUM risk issue! Security implementation: 'It works on my machine' level",
			HumorLevel:  HumorBrutal,
			Personality: PersonalityComedyGenius,
		},
	}

	// General roasts for unknown vulnerabilities
	t.roastDatabase.generalRoasts = []RoastTemplate{
		{
			Template:    "🎯 Vulnerability detected! Another gem in this security dumpster fire",
			HumorLevel:  HumorSarcastic,
			Personality: PersonalityEliteHacker,
		},
		{
			Template:    "💀 Security issue found! This code has more vulnerabilities than a soap opera has drama",
			HumorLevel:  HumorBrutal,
			Personality: PersonalityComedyGenius,
		},
		{
			Template:    "🔥 Security flaw detected! Protection level: About as effective as thoughts and prayers",
			HumorLevel:  HumorSavage,
			Personality: PersonalityAIOverlord,
		},
	}

	// Personality-specific roasts
	t.roastDatabase.personalityRoasts[PersonalityEliteHacker] = []RoastTemplate{
		{
			Template:    "🥷 *adjusts black hoodie* Another vulnerability falls to my elite skills",
			HumorLevel:  HumorSarcastic,
			Personality: PersonalityEliteHacker,
		},
	}

	t.roastDatabase.personalityRoasts[PersonalityMadScientist] = []RoastTemplate{
		{
			Template:    "🧪 *evil laugh* YESSS! Another specimen for my vulnerability collection!",
			HumorLevel:  HumorBrutal,
			Personality: PersonalityMadScientist,
		},
	}

	t.roastDatabase.personalityRoasts[PersonalityAIOverlord] = []RoastTemplate{
		{
			Template:    "🤖 ANALYZING... HUMAN SECURITY INCOMPETENCE LEVEL: MAXIMUM",
			HumorLevel:  HumorNuclear,
			Personality: PersonalityAIOverlord,
		},
	}

	t.logger.Info("🎪 Roast database initialized - ready to deliver legendary burns!")
}

// NewInteractiveGUI creates legendary interactive interface
func NewInteractiveGUI(logger core.Logger, trollEngine *TrollingEngine, config *GUIConfig) *InteractiveGUI {
	if config == nil {
		config = &GUIConfig{
			Port:           8080,
			Theme:          "dark_hacker",
			EnableWebUI:    true,
			EnableTerminal: true,
			AutoRoast:      true,
			LiveFeed:       true,
		}
	}

	gui := &InteractiveGUI{
		logger:      logger,
		trollEngine: trollEngine,
		config:      config,
		sessionData: make(map[string]*SessionContext),
	}

	// Initialize web server
	if config.EnableWebUI {
		gui.initializeWebServer()
	}

	return gui
}

// Start launches the interactive GUI
func (g *InteractiveGUI) Start(ctx context.Context) error {
	g.logger.Info("🎮 Starting legendary interactive GUI - prepare for maximum chaos!", 
		core.NewField("port", g.config.Port),
		core.NewField("theme", g.config.Theme))

	if g.config.EnableWebUI {
		go func() {
			if err := g.webServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				g.logger.Error("Web server failed", core.NewField("error", err.Error()))
			}
		}()
	}

	if g.config.EnableTerminal {
		g.startTerminalUI(ctx)
	}

	return nil
}

// initializeWebServer sets up the web interface
func (g *InteractiveGUI) initializeWebServer() {
	mux := http.NewServeMux()

	// Main dashboard
	mux.HandleFunc("/", g.handleDashboard)
	mux.HandleFunc("/api/scan", g.handleAPIScan)
	mux.HandleFunc("/api/roast", g.handleAPIRoast)
	mux.HandleFunc("/api/session", g.handleAPISession)
	mux.HandleFunc("/ws", g.handleWebSocket)

	// Static files
	mux.HandleFunc("/static/", g.handleStatic)

	g.webServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", g.config.Port),
		Handler: mux,
	}
}

// handleDashboard serves the main dashboard
func (g *InteractiveGUI) handleDashboard(w http.ResponseWriter, r *http.Request) {
	dashboardHTML := g.generateDashboardHTML()
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(dashboardHTML))
}

// generateDashboardHTML creates the legendary dashboard
func (g *InteractiveGUI) generateDashboardHTML() string {
	return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>💀 RECON-TK v2.0 - The Sysadmin's Worst Nightmare</title>
    <style>
        body {
            background: linear-gradient(45deg, #0a0a0a, #1a1a2e, #16213e);
            color: #00ff00;
            font-family: 'Courier New', monospace;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            border: 2px solid #00ff00;
            padding: 20px;
            border-radius: 10px;
            background: rgba(0, 255, 0, 0.1);
        }
        
        .ascii-art {
            font-size: 12px;
            line-height: 1;
            white-space: pre;
            color: #ff0040;
        }
        
        .control-panel {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .panel {
            border: 1px solid #00ff00;
            padding: 20px;
            border-radius: 5px;
            background: rgba(0, 0, 0, 0.7);
        }
        
        .scan-button {
            background: linear-gradient(45deg, #ff0040, #ff4500);
            color: white;
            border: none;
            padding: 15px 30px;
            font-size: 18px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .scan-button:hover {
            transform: scale(1.05);
            box-shadow: 0 0 20px #ff0040;
        }
        
        .results-feed {
            border: 1px solid #00ff00;
            padding: 20px;
            border-radius: 5px;
            background: rgba(0, 0, 0, 0.8);
            height: 400px;
            overflow-y: auto;
        }
        
        .vulnerability {
            margin: 10px 0;
            padding: 10px;
            border-left: 4px solid #ff0040;
            background: rgba(255, 0, 64, 0.1);
        }
        
        .roast {
            color: #ffa500;
            font-style: italic;
            margin-top: 5px;
        }
        
        .trolling-controls {
            text-align: center;
            margin: 20px 0;
        }
        
        .humor-slider {
            width: 300px;
            margin: 10px;
        }
        
        input, select {
            background: #1a1a2e;
            border: 1px solid #00ff00;
            color: #00ff00;
            padding: 10px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="ascii-art">
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ████████╗██╗  ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚══██╔══╝██║ ██╔╝
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║       ██║   █████╔╝ 
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║       ██║   ██╔═██╗ 
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║       ██║   ██║  ██╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝   ╚═╝  ╚═╝
        </div>
        <h1>💀 The Legendary Penetration Testing Framework 💀</h1>
        <p>Licensed FUNCYBOT™ - Making sysadmins cry since 2024</p>
    </div>

    <div class="control-panel">
        <div class="panel">
            <h3>🎯 Target Configuration</h3>
            <input type="text" id="target" placeholder="Enter target (IP/domain)" style="width: 100%; margin: 10px 0;">
            <select id="scan-type" style="width: 100%; margin: 10px 0;">
                <option value="full">Full Legendary Scan</option>
                <option value="ghost">Ghost Mode</option>
                <option value="iot">IoT Domination</option>
                <option value="mobile">Mobile/Cloud</option>
                <option value="firmware">Firmware Analysis</option>
            </select>
            <button class="scan-button" onclick="startScan()">🚀 UNLEASH HELL</button>
        </div>

        <div class="panel">
            <h3>🎭 Trolling Engine</h3>
            <div class="trolling-controls">
                <label>Humor Level:</label><br>
                <input type="range" id="humor-level" class="humor-slider" min="0" max="4" value="2">
                <div id="humor-display">Sarcastic</div>
                
                <label>Personality:</label><br>
                <select id="personality" style="width: 200px; margin: 10px;">
                    <option value="elite_hacker">Elite Hacker</option>
                    <option value="mad_scientist">Mad Scientist</option>
                    <option value="cyber_ninja">Cyber Ninja</option>
                    <option value="ai_overlord">AI Overlord</option>
                    <option value="comedy_genius">Comedy Genius</option>
                </select>
            </div>
        </div>
    </div>

    <div class="results-feed" id="results">
        <h3>📊 Live Results Feed - Watching targets suffer in real-time</h3>
        <div class="vulnerability">
            <strong>🎯 Demo SQL Injection:</strong> target.com/login.php<br>
            <div class="roast">💀 SQL injection found! This database security is weaker than your ex's commitment to the relationship</div>
        </div>
    </div>

    <script>
        const humorLevels = ['Chill', 'Sarcastic', 'Brutal', 'Savage', 'Nuclear'];
        
        document.getElementById('humor-level').addEventListener('input', function(e) {
            document.getElementById('humor-display').textContent = humorLevels[e.target.value];
        });

        function startScan() {
            const target = document.getElementById('target').value;
            const scanType = document.getElementById('scan-type').value;
            const humorLevel = document.getElementById('humor-level').value;
            const personality = document.getElementById('personality').value;

            if (!target) {
                alert('🤡 Enter a target first, amateur!');
                return;
            }

            // Add scanning animation
            const resultsDiv = document.getElementById('results');
            resultsDiv.innerHTML += '<div class="vulnerability">🔄 Scanning ' + target + ' - Preparing to own some sysadmins...</div>';

            // Simulate scan results
            setTimeout(() => {
                const roasts = [
                    "💀 XSS found! Input validation is clearly optional in their development process",
                    "🤡 Directory traversal! Path validation is apparently a foreign concept here", 
                    "⚡ Command injection! System calls without validation? That's some next-level stupidity",
                    "🔥 Weak passwords detected! Security level: Wet tissue paper in a hurricane"
                ];

                for (let i = 0; i < 3; i++) {
                    setTimeout(() => {
                        const roast = roasts[Math.floor(Math.random() * roasts.length)];
                        resultsDiv.innerHTML += '<div class="vulnerability"><strong>🎯 Vulnerability #' + (i+1) + ':</strong> ' + target + '<br><div class="roast">' + roast + '</div></div>';
                        resultsDiv.scrollTop = resultsDiv.scrollHeight;
                    }, i * 1000);
                }
            }, 2000);
        }

        // Auto-scroll and live updates
        setInterval(() => {
            const jokes = [
                "💭 Still waiting for a worthy opponent...",
                "🎭 Another day, another security dumpster fire",
                "🤖 Analyzing human incompetence levels...",
                "💀 EDR bypass successful - they never saw it coming"
            ];
            
            if (Math.random() < 0.1) {
                const resultsDiv = document.getElementById('results');
                const joke = jokes[Math.floor(Math.random() * jokes.length)];
                resultsDiv.innerHTML += '<div style="color: #666; font-style: italic; margin: 5px 0;">' + joke + '</div>';
            }
        }, 5000);
    </script>
</body>
</html>`
}

// Helper functions for the trolling engine
func (t *TrollingEngine) filterTemplates(templates []RoastTemplate) []RoastTemplate {
	var filtered []RoastTemplate
	
	for _, template := range templates {
		if template.HumorLevel <= t.humorLevel && 
		   (template.Personality == t.personality || template.Personality == PersonalityEliteHacker) {
			filtered = append(filtered, template)
		}
	}
	
	return filtered
}

func (t *TrollingEngine) processRoastTemplate(template RoastTemplate, vuln *VulnerabilityFinding) string {
	// Simple template processing - real implementation would use Go templates
	roast := template.Template
	
	// Replace common variables
	roast = strings.ReplaceAll(roast, "{{.target}}", vuln.Target)
	roast = strings.ReplaceAll(roast, "{{.type}}", vuln.Type)
	roast = strings.ReplaceAll(roast, "{{.severity}}", string(vuln.Severity))
	
	return roast
}

func (t *TrollingEngine) generateFallbackRoast(vuln *VulnerabilityFinding) string {
	fallbacks := []string{
		"🎯 Another vulnerability in the wild! Security level: Amateur hour",
		"💀 Vulnerability detected! This is why we can't have nice things",
		"🔥 Security flaw found! Protection effectiveness: Thoughts and prayers",
	}
	
	return fallbacks[t.randomInt(len(fallbacks))]
}

func (t *TrollingEngine) randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	b := make([]byte, 1)
	rand.Read(b)
	return int(b[0]) % max
}

// Additional handler methods
func (g *InteractiveGUI) handleAPIScan(w http.ResponseWriter, r *http.Request) {
	// API endpoint for scan requests
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "scan_initiated"})
}

func (g *InteractiveGUI) handleAPIRoast(w http.ResponseWriter, r *http.Request) {
	// API endpoint for roast requests
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"roast": "🎭 API roast delivered!"})
}

func (g *InteractiveGUI) handleAPISession(w http.ResponseWriter, r *http.Request) {
	// API endpoint for session management
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"session": "active"})
}

func (g *InteractiveGUI) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// WebSocket for real-time updates (simplified)
	w.Write([]byte("WebSocket endpoint"))
}

func (g *InteractiveGUI) handleStatic(w http.ResponseWriter, r *http.Request) {
	// Static file server
	http.ServeFile(w, r, r.URL.Path[1:])
}

func (g *InteractiveGUI) startTerminalUI(ctx context.Context) {
	g.logger.Info("🖥️ Starting terminal UI - old school hacker style!")
	
	// Terminal UI implementation would go here
	// For now, just a placeholder
}

// Stop gracefully shuts down the GUI
func (g *InteractiveGUI) Stop(ctx context.Context) error {
	g.logger.Info("🛑 Shutting down legendary GUI...")
	
	if g.webServer != nil {
		return g.webServer.Shutdown(ctx)
	}
	
	return nil
}