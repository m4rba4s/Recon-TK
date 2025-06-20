
package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"recon-toolkit/pkg/scanner"
)

var (
	ports       string
	scanStealthMode bool
	bannerGrab  bool
	serviceScan bool
	topPorts    bool
	allPorts    bool
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Fast async port scanner with stealth capabilities",
	Long: `High-performance port scanner with stealth and evasion features.

Features:
  • Async/concurrent scanning with configurable threads
  • Stealth mode with timing jitter and randomization  
  • Service detection and banner grabbing
  • Honeypot detection heuristics
  • Custom port ranges and common port lists

Examples:
  recon-toolkit scan -t example.com -p 80,443,8080
  recon-toolkit scan -t 192.168.1.1 -p 1-1000 --stealth
  recon-toolkit scan -t target.com --top-ports --silent
  recon-toolkit scan -t example.com -p 22,80,443 -o results.json`,
	
	RunE: func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target is required")
		}

		var portList []int
		var err error

		if allPorts {
			for i := 1; i <= 65535; i++ {
				portList = append(portList, i)
			}
		} else if topPorts {
			portList = scanner.TopPorts()
		} else if ports == "" {
			portList = scanner.CommonPorts()
		} else {
			portList, err = scanner.ParsePortRange(ports)
			if err != nil {
				return fmt.Errorf("invalid port range: %w", err)
			}
		}

		if !silent {
			color.Yellow("🎯 Target: %s", target)
			color.Yellow("📡 Ports to scan: %d", len(portList))
		}

		scannerOptions := []func(*scanner.Scanner){
			scanner.WithThreads(threads),
			scanner.WithTimeout(time.Duration(timeout) * time.Second),
		}

		if scanStealthMode {
			scannerOptions = append(scannerOptions, scanner.WithStealth())
		}

		if silent {
			scannerOptions = append(scannerOptions, scanner.WithSilent())
		}

		s := scanner.NewScanner(target, portList, scannerOptions...)

		ctx := context.Background()
		result, err := s.Scan(ctx)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		if outputFile != "" {
			return saveResults(result, outputFile)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&ports, "ports", "p", "", "Port range (e.g., 80,443,8080 or 1-1000)")
	scanCmd.Flags().BoolVar(&scanStealthMode, "stealth", false, "Enable stealth mode (randomization, jitter)")
	scanCmd.Flags().BoolVar(&bannerGrab, "banner", true, "Enable banner grabbing")
	scanCmd.Flags().BoolVar(&serviceScan, "service", true, "Enable service detection")
	scanCmd.Flags().BoolVar(&topPorts, "top-ports", false, "Scan top 1000 most common ports")
	scanCmd.Flags().BoolVar(&allPorts, "all-ports", false, "Scan all 65535 ports (SLOW!)")
}

func saveResults(result *scanner.ScanResult, filename string) error {
	var err error

	if strings.HasSuffix(filename, ".json") {
		err = saveResultsJSON(result, filename)
	} else if strings.HasSuffix(filename, ".csv") {
		err = saveResultsCSV(result, filename)
	} else if strings.HasSuffix(filename, ".txt") {
		err = saveResultsTXT(result, filename)
	} else {
		err = saveResultsJSON(result, filename)
	}

	if err != nil {
		return fmt.Errorf("failed to save results: %w", err)
	}

	if !silent {
		color.Green("💾 Results saved to %s", filename)
	}

	return nil
}

func saveResultsJSON(result *scanner.ScanResult, filename string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return os.WriteFile(filename, data, 0644)
}

func saveResultsCSV(result *scanner.ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"Port", "State", "Service", "Banner", "Version", "ResponseTime"}); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, port := range result.Ports {
		if port.State == "open" {
			record := []string{
				strconv.Itoa(port.Port),
				port.State,
				port.Service,
				strings.ReplaceAll(port.Banner, "\n", " "),
				port.Version,
				port.Response.String(),
			}
			if err := writer.Write(record); err != nil {
				return fmt.Errorf("failed to write CSV record: %w", err)
			}
		}
	}

	return nil
}

func saveResultsTXT(result *scanner.ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create TXT file: %w", err)
	}
	defer file.Close()

	fmt.Fprintf(file, "Port Scan Results for %s\n", result.Target)
	fmt.Fprintf(file, "===========================================\n")
	fmt.Fprintf(file, "Open Ports: %d/%d\n", result.OpenPorts, len(result.Ports))
	fmt.Fprintf(file, "Scan Time: %v\n", result.ScanTime)
	fmt.Fprintf(file, "Stealth Mode: %v\n", result.Stealth)
	fmt.Fprintf(file, "Honeypot Detected: %v\n", result.Honeypot)
	fmt.Fprintf(file, "OS Fingerprint: %s\n\n", result.Fingerprint)

	fmt.Fprintf(file, "%-6s %-10s %-12s %-30s %s\n", "PORT", "STATE", "SERVICE", "VERSION", "BANNER")
	fmt.Fprintf(file, "%s\n", strings.Repeat("-", 80))

	for _, port := range result.Ports {
		if port.State == "open" {
			banner := strings.ReplaceAll(port.Banner, "\n", " ")
			if len(banner) > 30 {
				banner = banner[:27] + "..."
			}
			fmt.Fprintf(file, "%-6d %-10s %-12s %-30s %s\n", 
				port.Port, port.State, port.Service, port.Version, banner)
		}
	}

	return nil
}