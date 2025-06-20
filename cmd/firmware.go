package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"recon-toolkit/pkg/core"
	"recon-toolkit/pkg/firmware"
)

var (
	firmwareAnalysisTypes []string
	firmwareExtractMode   bool
	firmwareAnalyzeMode   bool
	firmwareDeepScan      bool
	firmwareYaraScan      bool
	firmwareExploitGen    bool
	firmwareStringAnalysis bool
	firmwareCryptoAnalysis bool
	firmwareOutput        string
	firmwareFormat        string
	firmwareVerbose       bool
	firmwareTimeout       int
)

var firmwareCmd = &cobra.Command{
	Use:   "firmware",
	Short: "🔬 Advanced binary analysis and firmware extraction framework",
	Long: `🔬 BINARY/FIRMWARE ANALYSIS ENGINE

Advanced binary analysis and firmware extraction framework for comprehensive security assessment:

🔍 BINARY ANALYSIS CAPABILITIES:
  • Static Analysis - PE, ELF, Mach-O binary structure analysis
  • String Extraction - ASCII/Unicode string discovery and classification
  • Cryptographic Analysis - Algorithm detection and weakness identification
  • Disassembly Analysis - Function detection and vulnerability analysis
  • Entropy Analysis - Packed/encrypted section detection
  • Import/Export Analysis - Dangerous function detection

📦 FIRMWARE EXTRACTION METHODS:
  • Binwalk-style extraction - Filesystem detection and extraction
  • Unpacking analysis - Bootloader and kernel detection
  • Filesystem analysis - SquashFS, JFFS2, CRAMFS support
  • Configuration extraction - Secret and credential detection
  • Certificate analysis - Weak crypto and key extraction
  • Service discovery - Running services and attack surface

🎯 BINARY FORMATS SUPPORTED:
  • ELF - Linux/Unix executables and libraries
  • PE - Windows executables and DLLs
  • Mach-O - macOS binaries and frameworks
  • Firmware - Router, IoT, mobile, embedded systems
  • BIOS/UEFI - System firmware and bootloaders
  • Drivers - Kernel modules and device drivers

🔍 FIRMWARE TYPES SUPPORTED:
  • Router Firmware - OpenWrt, DD-WRT, commercial router firmware
  • IoT Device Firmware - Smart devices, cameras, sensors
  • Mobile Firmware - Android, iOS bootloaders and system images
  • Embedded Systems - Industrial controllers, automotive ECUs
  • BIOS/UEFI - System firmware and boot environments
  • Bootloaders - U-Boot, GRUB, custom bootloaders

💀 VULNERABILITY DETECTION:
  • Buffer Overflow - Stack and heap-based vulnerabilities
  • Format String - Printf family vulnerabilities
  • Use-After-Free - Memory corruption vulnerabilities
  • Integer Overflow - Arithmetic vulnerabilities
  • Dangerous Functions - strcpy, sprintf, system, exec usage
  • Weak Cryptography - DES, MD5, RC4, weak key sizes
  • Embedded Secrets - Hardcoded passwords, API keys, certificates

🎯 EXPLOIT GENERATION:
  • Automated PoC Generation - Buffer overflow exploits
  • ROP Gadget Discovery - Return-oriented programming chains
  • Memory Corruption - Heap spray and corruption techniques
  • Code Injection - Shellcode injection vectors
  • Privilege Escalation - SUID, capability abuse
  • Return-to-libc - Function chaining attacks

🔬 YARA RULE SCANNING:
  • Malware Detection - Backdoor and trojan signatures
  • Credential Harvesting - Embedded password detection
  • Suspicious Patterns - Obfuscation and packing detection
  • Custom Rules - User-defined pattern matching
  • Threat Intelligence - Known vulnerability patterns

Examples:
  recon-toolkit firmware -f /path/to/binary --analyze --deep-scan --exploit-gen
  recon-toolkit firmware -f /path/to/firmware.bin --extract --yara-scan
  recon-toolkit firmware -f malware.exe --types static,strings,crypto --format json -o results.json
  recon-toolkit firmware -f router.bin --extract --analyze --deep-scan --format text -o analysis.txt`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("firmware file path is required")
		}

		filePath := args[0]
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %s", filePath)
		}

		if !silent {
			color.Red("🔬 BINARY/FIRMWARE ANALYSIS ENGINE ACTIVATED")
			color.Yellow("Target File: %s", filePath)
			if firmwareExtractMode {
				color.Green("📦 Firmware Extraction: ENABLED")
			}
			if firmwareAnalyzeMode {
				color.Green("🔍 Binary Analysis: ENABLED")
			}
			if firmwareDeepScan {
				color.Blue("🔬 Deep Scan: ENABLED")
			}
			if firmwareYaraScan {
				color.Magenta("🎯 YARA Scanning: ENABLED")
			}
			if firmwareExploitGen {
				color.Red("💀 Exploit Generation: ENABLED")
			}
			color.Magenta("⚠️  FIRMWARE AT RISK - MAXIMUM ANALYSIS")
		}

		// Configure firmware engine
		config := &firmware.FirmwareConfig{
			AnalysisTypes:     firmwareAnalysisTypes,
			ExtractionMethods: []string{"binwalk", "unpack", "filesystem"},
			DeepAnalysis:      firmwareDeepScan,
			StringAnalysis:    firmwareStringAnalysis,
			CryptoAnalysis:    firmwareCryptoAnalysis,
			ExploitGeneration: firmwareExploitGen,
			YaraScanning:      firmwareYaraScan,
			MaxFileSize:       100 * 1024 * 1024, // 100MB
			TempDir:          "/tmp/firmware-analysis",
		}

		// If no analysis types specified, use defaults
		if len(config.AnalysisTypes) == 0 {
			if firmwareAnalyzeMode {
				config.AnalysisTypes = []string{"static", "strings", "crypto", "disasm"}
			}
		}

		// Setup logger
		logger := &FirmwareLogger{
			logger: logrus.New(),
			silent: silent,
		}
		if silent {
			logger.logger.SetLevel(logrus.ErrorLevel)
		} else if firmwareVerbose {
			logger.logger.SetLevel(logrus.DebugLevel)
		}

		// Create firmware engine
		binaryEngine := firmware.NewBinaryEngine(logger, config)

		ctx := context.Background()

		var analysisResult *firmware.AnalysisResult
		var extractionResult *firmware.ExtractionResult
		var err error

		// Execute firmware extraction if requested
		if firmwareExtractMode {
			if !silent {
				color.Cyan("\n📦 Initiating firmware extraction and analysis...")
				color.Cyan("🔍 Extracting filesystems, bootloaders, and configurations...")
			}

			extractionResult, err = binaryEngine.ExtractFirmware(ctx, filePath)
			if err != nil {
				return fmt.Errorf("firmware extraction failed: %w", err)
			}
		}

		// Execute binary analysis if requested
		if firmwareAnalyzeMode {
			if !silent {
				color.Cyan("\n🔬 Initiating binary analysis...")
				color.Cyan("🔍 Analyzing structure, strings, crypto, and vulnerabilities...")
			}

			analysisResult, err = binaryEngine.AnalyzeBinary(ctx, filePath)
			if err != nil {
				return fmt.Errorf("binary analysis failed: %w", err)
			}
		}

		// Display results
		err = displayFirmwareResults(analysisResult, extractionResult)
		if err != nil {
			return fmt.Errorf("failed to display results: %w", err)
		}

		// Save results if requested
		if firmwareOutput != "" {
			err = saveFirmwareResults(analysisResult, extractionResult, firmwareFormat, firmwareOutput)
			if err != nil {
				color.Red("Failed to save results: %v", err)
			} else if !silent {
				color.Green("💾 Results saved to: %s", firmwareOutput)
			}
		}

		if !silent {
			color.Green("\n✨ Firmware analysis completed successfully")
			if analysisResult != nil {
				color.Yellow("🔍 Vulnerabilities found: %d", len(analysisResult.Vulnerabilities))
				color.Yellow("💀 Exploits generated: %d", len(analysisResult.Exploits))
				color.Yellow("🎯 Strings extracted: %d", len(analysisResult.Strings))
				color.Red("⚠️  Risk Score: %.1f/100", analysisResult.RiskScore)
			}
			if extractionResult != nil {
				color.Yellow("📦 Files extracted: %d", len(extractionResult.ExtractedFiles))
				color.Yellow("🔒 Certificates found: %d", len(extractionResult.Certificates))
				color.Yellow("🗝️  Keys discovered: %d", len(extractionResult.Keys))
				color.Red("⚠️  Risk Score: %.1f/100", extractionResult.RiskScore)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(firmwareCmd)

	firmwareCmd.Flags().StringSliceVar(&firmwareAnalysisTypes, "types", []string{}, "Analysis types (static,strings,crypto,disasm)")
	firmwareCmd.Flags().BoolVar(&firmwareExtractMode, "extract", false, "Enable firmware extraction mode")
	firmwareCmd.Flags().BoolVar(&firmwareAnalyzeMode, "analyze", false, "Enable binary analysis mode")
	firmwareCmd.Flags().BoolVar(&firmwareDeepScan, "deep-scan", false, "Enable deep vulnerability scanning")
	firmwareCmd.Flags().BoolVar(&firmwareYaraScan, "yara-scan", true, "Enable YARA rule scanning")
	firmwareCmd.Flags().BoolVar(&firmwareExploitGen, "exploit-gen", false, "Enable exploit generation")
	firmwareCmd.Flags().BoolVar(&firmwareStringAnalysis, "string-analysis", true, "Enable string extraction and analysis")
	firmwareCmd.Flags().BoolVar(&firmwareCryptoAnalysis, "crypto-analysis", true, "Enable cryptographic analysis")
	firmwareCmd.Flags().StringVar(&firmwareOutput, "output", "", "Output file path")
	firmwareCmd.Flags().StringVar(&firmwareFormat, "format", "json", "Output format (json, text)")
	firmwareCmd.Flags().BoolVar(&firmwareVerbose, "verbose", false, "Verbose logging output")
	firmwareCmd.Flags().IntVar(&firmwareTimeout, "timeout", 300, "Analysis timeout in seconds")
}

// FirmwareLogger implements core.Logger interface
type FirmwareLogger struct {
	logger *logrus.Logger
	silent bool
}

func (l *FirmwareLogger) Debug(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Debug(msg)
}

func (l *FirmwareLogger) Info(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Info(msg)
}

func (l *FirmwareLogger) Warn(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Warn(msg)
}

func (l *FirmwareLogger) Error(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Error(msg)
}

func (l *FirmwareLogger) Fatal(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Fatal(msg)
}

func (l *FirmwareLogger) fieldsToLogrus(fields []core.Field) logrus.Fields {
	logrusFields := make(logrus.Fields)
	for _, field := range fields {
		logrusFields[field.Key()] = field.Value()
	}
	return logrusFields
}

// displayFirmwareResults displays binary/firmware analysis results
func displayFirmwareResults(analysisResult *firmware.AnalysisResult, extractionResult *firmware.ExtractionResult) error {
	if !silent {
		color.Cyan("\n🔬 BINARY/FIRMWARE ANALYSIS RESULTS")
		color.Cyan("=" + strings.Repeat("=", 50))

		// Binary analysis results
		if analysisResult != nil {
			binary := analysisResult.Binary
			color.White("Binary: %s", binary.Name)
			color.White("Size: %d bytes", binary.Size)
			color.White("Type: %s", getBinaryTypeString(binary.Type))
			color.White("Architecture: %s", binary.Architecture)
			color.White("Format: %s", binary.Format)

			// Vulnerabilities
			if len(analysisResult.Vulnerabilities) > 0 {
				color.Red("\n💀 Binary Vulnerabilities:")
				color.Red("-" + strings.Repeat("-", 60))

				for _, vuln := range analysisResult.Vulnerabilities {
					severityColor := getSeverityColor(vuln.Severity)
					severityColor.Printf("💀 %s\n", vuln.Description)
					color.White("   Type: %s", vuln.Type)
					color.White("   ID: %s", vuln.ID)
					if vuln.CVE != "" {
						color.White("   CVE: %s", vuln.CVE)
					}
					if vuln.Exploitable {
						color.Red("   ⚠️ EXPLOITABLE!")
					}
					fmt.Println()
				}
			}

			// Exploits
			if len(analysisResult.Exploits) > 0 {
				color.Red("\n🎯 Generated Exploits:")
				color.Red("-" + strings.Repeat("-", 60))

				for _, exploit := range analysisResult.Exploits {
					severityColor := getSeverityColor(exploit.Severity)
					severityColor.Printf("🎯 %s\n", exploit.Name)
					color.White("   Type: %s", getFirmwareExploitTypeString(int(exploit.Type)))
					color.White("   Description: %s", exploit.Description)
					if exploit.CVSS > 0 {
						color.White("   CVSS: %.1f", exploit.CVSS)
					}
					if exploit.Automated {
						color.Green("   ✅ AUTOMATED EXPLOIT")
					}
					fmt.Println()
				}
			}

			// Suspicious code
			if len(analysisResult.SuspiciousCode) > 0 {
				color.Yellow("\n⚠️ Suspicious Code Patterns:")
				color.Yellow("-" + strings.Repeat("-", 60))

				for _, suspicious := range analysisResult.SuspiciousCode {
					severityColor := getSeverityColor(suspicious.Severity)
					severityColor.Printf("⚠️ %s\n", suspicious.Description)
					color.White("   Type: %s", suspicious.Type)
					color.White("   Location: 0x%x", suspicious.Location)
					fmt.Println()
				}
			}

			// Crypto elements
			if len(analysisResult.CryptoElements) > 0 {
				color.Magenta("\n🔐 Cryptographic Elements:")
				color.Magenta("-" + strings.Repeat("-", 60))

				for _, crypto := range analysisResult.CryptoElements {
					statusColor := color.New(color.FgGreen)
					if crypto.Weak {
						statusColor = color.New(color.FgRed)
					}
					statusColor.Printf("🔐 %s (%s)\n", crypto.Algorithm, crypto.Type)
					color.White("   Location: 0x%x", crypto.Location)
					if crypto.Weak {
						color.Red("   ⚠️ WEAK CRYPTOGRAPHY!")
					}
					fmt.Println()
				}
			}

			// Risk assessment
			color.Cyan("\n📊 BINARY RISK ASSESSMENT:")
			riskLevel := "LOW"
			riskColor := color.New(color.FgGreen)

			if analysisResult.RiskScore > 80 {
				riskLevel = "CRITICAL"
				riskColor = color.New(color.FgRed, color.Bold)
			} else if analysisResult.RiskScore > 60 {
				riskLevel = "HIGH"
				riskColor = color.New(color.FgRed)
			} else if analysisResult.RiskScore > 40 {
				riskLevel = "MEDIUM"
				riskColor = color.New(color.FgYellow)
			}

			riskColor.Printf("Binary Risk: %s (%.1f/100)\n", riskLevel, analysisResult.RiskScore)
		}

		// Firmware extraction results
		if extractionResult != nil {
			color.Cyan("\n📦 FIRMWARE EXTRACTION RESULTS")
			color.Cyan("=" + strings.Repeat("=", 50))

			firmware := extractionResult.Firmware
			color.White("Firmware: %s", firmware.Name)
			color.White("Size: %d bytes", firmware.Size)
			color.White("Type: %s", getFirmwareTypeString(firmware.Type))
			color.White("Vendor: %s", firmware.Vendor)
			color.White("Version: %s", firmware.Version)

			// Filesystem info
			if extractionResult.Filesystem != nil {
				fs := extractionResult.Filesystem
				color.Green("\n🗂️ Filesystem Information:")
				color.White("   Type: %s", fs.Type)
				color.White("   Files: %d", fs.FileCount)
				color.White("   Mount Points: %s", strings.Join(fs.MountPoints, ", "))
			}

			// Bootloader and kernel
			if extractionResult.BootLoader != nil {
				boot := extractionResult.BootLoader
				color.Blue("\n🚀 Bootloader Information:")
				color.White("   Type: %s", boot.Type)
				color.White("   Version: %s", boot.Version)
				color.White("   Address: 0x%x", boot.Address)
			}

			if extractionResult.Kernel != nil {
				kernel := extractionResult.Kernel
				color.Blue("\n🐧 Kernel Information:")
				color.White("   Version: %s", kernel.Version)
				color.White("   Architecture: %s", kernel.Architecture)
				color.White("   Modules: %s", strings.Join(kernel.Modules, ", "))
			}

			// Services
			if len(extractionResult.Services) > 0 {
				color.Green("\n🔧 Discovered Services:")
				color.Green("-" + strings.Repeat("-", 60))

				for _, service := range extractionResult.Services {
					color.Green("🔧 %s", service.Name)
					color.White("   Binary: %s", service.Binary)
					color.White("   User: %s", service.User)
					color.White("   Startup: %s", service.StartupType)
					if len(service.Ports) > 0 {
						color.White("   Ports: %v", service.Ports)
					}
					fmt.Println()
				}
			}

			// Certificates and keys
			if len(extractionResult.Certificates) > 0 {
				color.Magenta("\n🔒 Certificates:")
				for _, cert := range extractionResult.Certificates {
					statusColor := color.New(color.FgGreen)
					if cert.KeySize < 2048 {
						statusColor = color.New(color.FgRed)
					}
					statusColor.Printf("🔒 %s\n", cert.Subject)
					color.White("   Issuer: %s", cert.Issuer)
					color.White("   Algorithm: %s (%d bits)", cert.Algorithm, cert.KeySize)
					if cert.SelfSigned {
						color.Yellow("   ⚠️ SELF-SIGNED")
					}
					fmt.Println()
				}
			}

			// Firmware vulnerabilities
			if len(extractionResult.Vulnerabilities) > 0 {
				color.Red("\n💀 Firmware Vulnerabilities:")
				color.Red("-" + strings.Repeat("-", 60))

				for _, vuln := range extractionResult.Vulnerabilities {
					severityColor := getSeverityColor(vuln.Severity)
					severityColor.Printf("💀 %s\n", vuln.Description)
					color.White("   Type: %s", vuln.Type)
					color.White("   File: %s", vuln.File)
					if vuln.CVE != "" {
						color.White("   CVE: %s", vuln.CVE)
					}
					fmt.Println()
				}
			}

			// Risk assessment
			color.Cyan("\n📊 FIRMWARE RISK ASSESSMENT:")
			riskLevel := "LOW"
			riskColor := color.New(color.FgGreen)

			if extractionResult.RiskScore > 80 {
				riskLevel = "CRITICAL"
				riskColor = color.New(color.FgRed, color.Bold)
			} else if extractionResult.RiskScore > 60 {
				riskLevel = "HIGH"
				riskColor = color.New(color.FgRed)
			} else if extractionResult.RiskScore > 40 {
				riskLevel = "MEDIUM"
				riskColor = color.New(color.FgYellow)
			}

			riskColor.Printf("Firmware Risk: %s (%.1f/100)\n", riskLevel, extractionResult.RiskScore)
		}
	}

	return nil
}

// saveFirmwareResults saves firmware analysis results
func saveFirmwareResults(analysisResult *firmware.AnalysisResult, extractionResult *firmware.ExtractionResult, format, filename string) error {
	results := map[string]interface{}{
		"analysis":   analysisResult,
		"extraction": extractionResult,
	}

	switch format {
	case "json":
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filename, data, 0644)

	case "text":
		file, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer file.Close()

		fmt.Fprintf(file, "BINARY/FIRMWARE ANALYSIS RESULTS\n")
		fmt.Fprintf(file, "===============================\n\n")

		if analysisResult != nil {
			fmt.Fprintf(file, "Binary: %s\n", analysisResult.Binary.Name)
			fmt.Fprintf(file, "Vulnerabilities: %d\n", len(analysisResult.Vulnerabilities))
			fmt.Fprintf(file, "Risk Score: %.1f\n\n", analysisResult.RiskScore)
		}

		if extractionResult != nil {
			fmt.Fprintf(file, "Firmware: %s\n", extractionResult.Firmware.Name)
			fmt.Fprintf(file, "Extracted Files: %d\n", len(extractionResult.ExtractedFiles))
			fmt.Fprintf(file, "Risk Score: %.1f\n\n", extractionResult.RiskScore)
		}

		return nil

	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// Helper functions
func getBinaryTypeString(binaryType firmware.BinaryType) string {
	switch binaryType {
	case 0:
		return "ELF"
	case 1:
		return "PE"
	case 2:
		return "Mach-O"
	case 3:
		return "Shellcode"
	case 4:
		return "Firmware"
	case 5:
		return "Driver"
	case 6:
		return "Library"
	default:
		return "Unknown"
	}
}

func getFirmwareTypeString(firmwareType firmware.FirmwareType) string {
	switch firmwareType {
	case 0:
		return "Router"
	case 1:
		return "IoT Device"
	case 2:
		return "Mobile"
	case 3:
		return "Embedded System"
	case 4:
		return "BIOS"
	case 5:
		return "UEFI"
	case 6:
		return "Bootloader"
	default:
		return "Unknown"
	}
}

func getFirmwareExploitTypeString(exploitType int) string {
	switch exploitType {
	case 0:
		return "Buffer Overflow"
	case 1:
		return "Stack Overflow"
	case 2:
		return "Heap Overflow"
	case 3:
		return "Format String"
	case 4:
		return "Integer Overflow"
	case 5:
		return "Use After Free"
	case 6:
		return "Race Condition"
	case 7:
		return "Privilege Escalation"
	case 8:
		return "Code Injection"
	case 9:
		return "Memory Corruption"
	default:
		return "Unknown"
	}
}