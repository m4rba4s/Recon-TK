package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"recon-toolkit/pkg/core"
	"recon-toolkit/pkg/gui"
)

var (
	guiPort           int
	guiTheme          string
	guiEnableWeb      bool
	guiEnableTerminal bool
	guiAutoRoast      bool
	guiLiveFeed       bool
	guiHumorLevel     int
	guiPersonality    string
	guiEnableRoasting bool
	guiEnableSarcasm  bool
	guiEnableSavagery bool
)

var guiCmd = &cobra.Command{
	Use:   "gui",
	Short: "🎭 Interactive GUI with legendary trolling engine",
	Long: `🎭 INTERACTIVE GUI WITH LEGENDARY TROLLING ENGINE

Advanced interactive interface with maximum humor and roasting capabilities:

🎮 GUI FEATURES:
  • Web-based dashboard with real-time updates
  • Terminal UI with vim-style hotkeys
  • Live vulnerability feed with instant roasts
  • Interactive scan controls and configuration
  • Real-time progress monitoring

🎭 TROLLING ENGINE:
  • Adaptive humor levels (Chill → Sarcastic → Brutal → Savage → Nuclear)
  • Multiple personality types (Elite Hacker, Mad Scientist, AI Overlord)
  • Context-aware roasting based on vulnerability type
  • Legendary sarcasm and cynicism engine
  • Professional mode for corporate environments

😏 HUMOR LEVELS:
  • Chill: Professional with subtle humor
  • Sarcastic: Witty observations and dry humor
  • Brutal: Direct roasting with no mercy
  • Savage: Hardcore roasting that cuts deep
  • Nuclear: Maximum destruction humor mode

🤖 PERSONALITY TYPES:
  • Elite Hacker: Cool, calculated, superior attitude
  • Mad Scientist: Maniacal laughter and experiments
  • Cyber Ninja: Stealthy with sharp wit
  • AI Overlord: Cold, logical, dismissive of humans
  • Comedy Genius: Pure humor and entertainment

🌟 INTERACTIVE FEATURES:
  • Drag & drop target configuration
  • Real-time scan visualization
  • Custom payload testing
  • Exploit generation interface
  • Report generation with humor

Examples:
  recon-toolkit gui --port 8080 --theme dark_hacker
  recon-toolkit gui --humor-level 3 --personality ai_overlord
  recon-toolkit gui --enable-savagery --live-feed`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if !silent {
			color.Red("🎭 INTERACTIVE GUI WITH LEGENDARY TROLLING ENGINE")
			color.Yellow("Port: %d", guiPort)
			color.Yellow("Theme: %s", guiTheme)
			color.Green("🎮 Web Interface: %t", guiEnableWeb)
			color.Green("🖥️ Terminal UI: %t", guiEnableTerminal)
			color.Green("🎭 Auto-Roast: %t", guiAutoRoast)
			color.Magenta("⚠️  MAXIMUM HUMOR MODE ACTIVATED")
		}

		// Configure trolling engine
		trollConfig := &gui.TrollingConfig{
			HumorLevel:     gui.HumorLevel(guiHumorLevel),
			Personality:    parsePersonality(guiPersonality),
			EnableRoasting: guiEnableRoasting,
			EnableSarcasm:  guiEnableSarcasm,
			EnableSavagery: guiEnableSavagery,
			AdaptiveHumor:  true,
			ContextAware:   true,
			SafeMode:       false,
		}

		// Configure GUI
		guiConfig := &gui.GUIConfig{
			Port:           guiPort,
			Theme:          guiTheme,
			EnableWebUI:    guiEnableWeb,
			EnableTerminal: guiEnableTerminal,
			AutoRoast:      guiAutoRoast,
			LiveFeed:       guiLiveFeed,
		}

		// Setup logger
		logger := &GUILogger{
			logger: logrus.New(),
			silent: silent,
		}
		if silent {
			logger.logger.SetLevel(logrus.ErrorLevel)
		} else {
			logger.logger.SetLevel(logrus.InfoLevel)
		}

		// Create trolling engine
		trollEngine := gui.NewTrollingEngine(logger, trollConfig)

		// Create interactive GUI
		interactiveGUI := gui.NewInteractiveGUI(logger, trollEngine, guiConfig)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Handle shutdown gracefully
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			if !silent {
				color.Yellow("\n🛑 Shutting down GUI...")
			}
			interactiveGUI.Stop(ctx)
			cancel()
		}()

		if !silent {
			color.Cyan("\n🎮 Starting interactive GUI...")
			if guiEnableWeb {
				color.Green("🌐 Web interface available at: http://localhost:%d", guiPort)
			}
			if guiEnableTerminal {
				color.Green("🖥️ Terminal interface starting...")
			}
			color.Cyan("🎭 Trolling engine ready to roast some vulnerabilities!")
		}

		// Start GUI
		err := interactiveGUI.Start(ctx)
		if err != nil {
			return fmt.Errorf("GUI startup failed: %w", err)
		}

		// Keep running until shutdown
		<-ctx.Done()

		if !silent {
			color.Green("\n✨ GUI shutdown completed")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(guiCmd)

	guiCmd.Flags().IntVar(&guiPort, "port", 8080, "Web interface port")
	guiCmd.Flags().StringVar(&guiTheme, "theme", "dark_hacker", "GUI theme (dark_hacker, matrix, cyberpunk)")
	guiCmd.Flags().BoolVar(&guiEnableWeb, "enable-web", true, "Enable web interface")
	guiCmd.Flags().BoolVar(&guiEnableTerminal, "enable-terminal", true, "Enable terminal interface")
	guiCmd.Flags().BoolVar(&guiAutoRoast, "auto-roast", true, "Enable automatic roasting")
	guiCmd.Flags().BoolVar(&guiLiveFeed, "live-feed", true, "Enable live results feed")
	guiCmd.Flags().IntVar(&guiHumorLevel, "humor-level", 2, "Humor level (0-4: Chill, Sarcastic, Brutal, Savage, Nuclear)")
	guiCmd.Flags().StringVar(&guiPersonality, "personality", "elite_hacker", "Personality type")
	guiCmd.Flags().BoolVar(&guiEnableRoasting, "enable-roasting", true, "Enable roasting mode")
	guiCmd.Flags().BoolVar(&guiEnableSarcasm, "enable-sarcasm", true, "Enable sarcasm mode")
	guiCmd.Flags().BoolVar(&guiEnableSavagery, "enable-savagery", false, "Enable savagery mode (extreme humor)")
}

// GUILogger implements core.Logger interface
type GUILogger struct {
	logger *logrus.Logger
	silent bool
}

func (l *GUILogger) Debug(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Debug(msg)
}

func (l *GUILogger) Info(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Info(msg)
}

func (l *GUILogger) Warn(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Warn(msg)
}

func (l *GUILogger) Error(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Error(msg)
}

func (l *GUILogger) Fatal(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Fatal(msg)
}

func (l *GUILogger) fieldsToLogrus(fields []core.Field) logrus.Fields {
	logrusFields := make(logrus.Fields)
	for _, field := range fields {
		logrusFields[field.Key()] = field.Value()
	}
	return logrusFields
}

// parsePersonality converts string to PersonalityType
func parsePersonality(personality string) gui.PersonalityType {
	switch personality {
	case "elite_hacker":
		return gui.PersonalityEliteHacker
	case "mad_scientist":
		return gui.PersonalityMadScientist
	case "cyber_ninja":
		return gui.PersonalityCyberNinja
	case "ai_overlord":
		return gui.PersonalityAIOverlord
	case "comedy_genius":
		return gui.PersonalityComedyGenius
	default:
		return gui.PersonalityEliteHacker
	}
}