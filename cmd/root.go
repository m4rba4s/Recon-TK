
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile       string
	target        string
	outputFile    string
	silent        bool
	debug         bool
	threads       int
	timeout       int
	timeboxSecs   int
	userAgent     string
	enablePcap    bool
	pcapInterface string
	pcapMaxSize   string
	dryRun        bool
	resumeSession string
)

var rootCmd = &cobra.Command{
	Use:   "recon-toolkit",
	Short: "Elite reconnaissance and exploitation toolkit",
	Long: `🎯 RTK ELITE - Professional Penetration Testing Framework v3.0

A cutting-edge, enterprise-grade penetration testing framework designed for 
authorized security assessments, red team operations, and vulnerability research 
with zero false-positive architecture.

⚡ FEATURES:
  • Async port scanning with stealth capabilities
  • Advanced DNS subdomain enumeration with wildcard detection
  • Web Application Firewall detection and bypass testing  
  • Service detection and banner grabbing
  • Honeypot detection heuristics
  • Multi-format output (JSON, CSV, TXT)
  • Enterprise logging and audit trails
  • Cross-platform compatibility

🛡️ SECURITY MODULES:
  • Port Scanner: Fast, concurrent TCP scanning with stealth modes
  • DNS Enumerator: Subdomain discovery with permutation attacks
  • WAF Detector: Advanced firewall detection and bypass techniques
  • Enterprise Logger: Structured security event logging

📊 OUTPUT FORMATS:
  • JSON: Machine-readable structured data
  • CSV: Spreadsheet-compatible format  
  • TXT: Human-readable plain text reports

🚨 LEGAL NOTICE:
This tool is intended for authorized security testing only. 
Users are responsible for complying with applicable laws and regulations.
Unauthorized access to computer systems is illegal.

Examples:
  recon-toolkit scan -t example.com -p 80,443,8080 --stealth
  recon-toolkit dns -t example.com --permutations --recursive  
  recon-toolkit waf -t https://target.com --bypass
  recon-toolkit scan -t 192.168.1.0/24 --top-ports -o results.csv`,
}

// Exit codes for CI/CD integration
const (
	ExitOK          = 0  // Success
	ExitGeneral     = 1  // General error
	ExitNoTarget    = 10 // Target unreachable/invalid
	ExitScanError   = 20 // Scan module error
	ExitInternalErr = 30 // Internal panic/fatal error
	ExitAuthError   = 40 // Authentication/permission error
)

func Execute() error {
	defer panicHandler()
	
	err := rootCmd.Execute()
	if err != nil {
		handleErrorExit(err)
	}
	return err
}

func panicHandler() {
	if r := recover(); r != nil {
		logPanicToFile(r)
		fmt.Fprintf(os.Stderr, "❌ Fatal error occurred - see ~/.local/share/rtk/run.log for details\n")
		fmt.Fprintf(os.Stderr, "🆔 Error ID: RTK-%d\n", time.Now().Unix())
		os.Exit(ExitInternalErr)
	}
}

func logPanicToFile(panicInfo interface{}) {
	logDir := getDataDir()
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return
	}
	
	logFile := filepath.Join(logDir, "run.log")
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()
	
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(file, "[%s] PANIC: %v\n", timestamp, panicInfo)
	fmt.Fprintf(file, "[%s] Stack trace available in system logs\n", timestamp)
}

func handleErrorExit(err error) {
	errStr := err.Error()
	
	switch {
	case strings.Contains(errStr, "no such host") || strings.Contains(errStr, "connection refused"):
		os.Exit(ExitNoTarget)
	case strings.Contains(errStr, "scan failed") || strings.Contains(errStr, "module error"):
		os.Exit(ExitScanError)
	case strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "unauthorized"):
		os.Exit(ExitAuthError)
	default:
		os.Exit(ExitGeneral)
	}
}

func getDataDir() string {
	if dataDir := os.Getenv("RTK_DATA_HOME"); dataDir != "" {
		return dataDir
	}
	
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		return filepath.Join(xdgData, "rtk")
	}
	
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".local", "share", "rtk")
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.recon-toolkit.yaml)")
	rootCmd.PersistentFlags().StringVarP(&target, "target", "t", "", "Target hostname or IP address")
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Output file for results")
	rootCmd.PersistentFlags().BoolVarP(&silent, "silent", "s", false, "Silent mode - minimal output")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Debug mode - verbose EWMA and performance logs")
	rootCmd.PersistentFlags().IntVar(&threads, "threads", 100, "Number of concurrent threads")
	rootCmd.PersistentFlags().IntVar(&timeout, "timeout", 5, "Timeout in seconds")
	rootCmd.PersistentFlags().IntVar(&timeboxSecs, "timebox", 0, "Operation timeout in seconds (0=no limit, enables auto-resume)")
	rootCmd.PersistentFlags().StringVar(&userAgent, "user-agent", "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0", "User agent string")
	rootCmd.PersistentFlags().BoolVar(&enablePcap, "pcap", false, "Enable PCAP traffic capture during scans")
	rootCmd.PersistentFlags().StringVar(&pcapInterface, "pcap-interface", "", "Network interface for PCAP capture (auto-detect if empty)")
	rootCmd.PersistentFlags().StringVar(&pcapMaxSize, "pcap-max", "0", "Maximum PCAP file size (e.g., 100M, 1G, 0=unlimited)")
	rootCmd.PersistentFlags().BoolVar(&dryRun, "dry", false, "Dry run mode - show what would be executed without sending traffic")
	rootCmd.PersistentFlags().StringVar(&resumeSession, "resume", "", "Resume from session ID")

}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".recon-toolkit")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		if !silent {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
	}
}