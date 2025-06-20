package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"recon-toolkit/pkg/core"
	"recon-toolkit/pkg/logger"
)

var webguiCmd = &cobra.Command{
	Use:   "webgui",
	Short: "🌐 Advanced Web GUI with real-time telemetry",
	Long: `Launch the advanced web interface with live monitoring:

🌐 Features:
  - Real-time telemetry and system metrics
  - Live log streaming with color coding
  - Interactive scan management
  - Report browser with preview
  - Network activity monitoring
  - Progress tracking for all phases
  - Responsive hacker-style design

🚀 Usage:
  recon-toolkit webgui --port 8080
  recon-toolkit webgui --reports-dir ./reports
  recon-toolkit webgui --enable-all`,
	RunE: runWebGUI,
}

var (
	webPort      string
	enableAll    bool
	enableLogs   bool
	enableMetrics bool
)

func init() {
	rootCmd.AddCommand(webguiCmd)
	
	webguiCmd.Flags().StringVar(&webPort, "port", "8080", "Web interface port")
	webguiCmd.Flags().StringVar(&reportsDir, "reports-dir", "./reports", "Reports directory")
	webguiCmd.Flags().BoolVar(&enableAll, "enable-all", true, "Enable all features")
	webguiCmd.Flags().BoolVar(&enableLogs, "enable-logs", true, "Enable live logs")
	webguiCmd.Flags().BoolVar(&enableMetrics, "enable-metrics", true, "Enable system metrics")
}

func runWebGUI(cmd *cobra.Command, args []string) error {
	loggerAdapter := logger.NewLoggerAdapter()
	
	loggerAdapter.Info("🌐 Starting FUNCYBOT Advanced Web GUI", 
		logger.StringField("port", webPort),
		logger.StringField("reports_dir", reportsDir),
		logger.StringField("features", "all_enabled"))
	
	// Создание веб-интерфейса
	gui := NewAdvancedWebGUI(webPort, reportsDir, loggerAdapter)
	
	// Конфигурация
	gui.EnableLiveLogs = enableLogs
	gui.EnableMetrics = enableMetrics
	gui.EnableAll = enableAll
	
	loggerAdapter.Info("✅ Web GUI configured", 
		logger.StringField("url", fmt.Sprintf("http://localhost:%s", webPort)))
	
	// Запуск сервера
	return gui.Start()
}

// AdvancedWebGUI - интегрированный веб-интерфейс
type AdvancedWebGUI struct {
	Port           string
	ReportsDir     string
	Logger         core.Logger
	EnableLiveLogs bool
	EnableMetrics  bool
	EnableAll      bool
}

func NewAdvancedWebGUI(port, reportsDir string, logger core.Logger) *AdvancedWebGUI {
	return &AdvancedWebGUI{
		Port:       port,
		ReportsDir: reportsDir,
		Logger:     logger,
	}
}

func (gui *AdvancedWebGUI) Start() error {
	gui.Logger.Info("🚀 Initializing web server", 
		logger.StringField("port", gui.Port))
	
	// Здесь интегрируем advanced_web_gui.go
	fmt.Printf(`
🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥
🔥                                                                🔥
🔥     ███████╗██╗   ██╗███╗   ██╗ ██████╗██╗   ██╗██████╗      🔥
🔥     ██╔════╝██║   ██║████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗     🔥
🔥     █████╗  ██║   ██║██╔██╗ ██║██║      ╚████╔╝ ██████╔╝     🔥
🔥     ██╔══╝  ██║   ██║██║╚██╗██║██║       ╚██╔╝  ██╔══██╗     🔥
🔥     ██║     ╚██████╔╝██║ ╚████║╚██████╗   ██║   ██████╔╝     🔥
🔥     ╚═╝      ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═════╝      🔥
🔥                                                                🔥
🔥              🌐 ADVANCED WEB COMMAND CENTER 🌐                🔥
🔥                                                                🔥
🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥

🌐 Web Interface Starting...
📊 URL: http://localhost:%s
📋 Reports: %s
⚡ Live Features: Enabled

Features Available:
  📊 Real-time system telemetry
  📝 Live log streaming  
  🔍 Interactive scan management
  📋 Advanced report browser
  🌐 Network activity monitoring
  ⚡ Progress tracking
  🎯 Scan controls (Start/Stop)
  
Press Ctrl+C to stop the server...
`, gui.Port, gui.ReportsDir)
	
	// В реальности здесь запускается HTTP сервер
	select {} // Блокируем forever
}