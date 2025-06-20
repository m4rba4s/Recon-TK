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
	"recon-toolkit/pkg/iot"
)

var (
	iotIndustrialProtocols []string
	iotProtocols          []string
	iotDeepScan           bool
	iotStealth            bool
	iotPersistence        bool
	iotExploit            bool
	iotOutput             string
	iotFormat             string
	iotVerbose            bool
	iotMaxConcurrent      int
	iotTimeout            int
)

var iotCmd = &cobra.Command{
	Use:   "iot",
	Short: "🏭 IoT/OT Domination Engine - Industrial & IoT Network Takeover",
	Long: `🏭 IoT/OT DOMINATION ENGINE - Complete Industrial Network Control

Advanced IoT and Industrial Control System (ICS) penetration framework:

🏭 INDUSTRIAL PROTOCOLS:
  • Modbus TCP/RTU - Manufacturing and energy systems
  • DNP3 - Power grid and water treatment systems  
  • BACnet - Building automation and HVAC systems
  • IEC 61850 - Electrical substation automation
  • OPC UA - Industrial communication standard

📡 IoT PROTOCOLS:
  • CoAP - Constrained Application Protocol
  • MQTT - Message Queuing Telemetry Transport
  • Zigbee - Low-power mesh networking
  • Z-Wave - Home automation protocol
  • LoRaWAN - Long range wide area network

💀 ATTACK CAPABILITIES:
  • Automated device discovery and fingerprinting
  • Protocol-specific vulnerability scanning
  • Industrial system exploitation
  • SCADA/HMI interface manipulation
  • PLC logic modification
  • Sensor data manipulation

🔧 EXPLOITATION FEATURES:
  • Default credential testing
  • Protocol fuzzing and injection
  • Firmware extraction and analysis
  • Memory corruption exploits
  • Privilege escalation techniques
  • Lateral movement planning

🏴‍☠️ PERSISTENCE MECHANISMS:
  • Backdoor user creation
  • Scheduled task installation
  • Firmware modification
  • Network configuration changes
  • Command and control channels

🗺️ NETWORK MAPPING:
  • Industrial network topology discovery
  • Critical system identification
  • Dependency analysis
  • Risk assessment and scoring
  • Attack path visualization

🥷 STEALTH OPERATIONS:
  • Protocol-aware evasion
  • Timing attack mitigation  
  • Traffic pattern mimicry
  • Anti-forensics cleanup
  • Legitimate command abuse

Examples:
  recon-toolkit iot -t 192.168.1.100 --industrial modbus,dnp3,bacnet
  recon-toolkit iot -t 10.0.0.0/24 --deep-scan --exploit --persistence
  recon-toolkit iot -t plc.factory.com --stealth --protocols mqtt,coap
  recon-toolkit iot -t scada.plant.local --industrial all --format json -o results.json`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target is required for IoT/OT domination")
		}

		if !silent {
			color.Red("🏭 IoT/OT DOMINATION ENGINE ACTIVATED")
			color.Yellow("Target: %s", target)
			if len(iotIndustrialProtocols) > 0 {
				color.Green("🏭 Industrial Protocols: %s", strings.Join(iotIndustrialProtocols, ", "))
			}
			if len(iotProtocols) > 0 {
				color.Green("📡 IoT Protocols: %s", strings.Join(iotProtocols, ", "))
			}
			if iotDeepScan {
				color.Green("🔍 Deep Scan: ENABLED")
			}
			if iotStealth {
				color.Blue("🥷 Stealth Mode: ENABLED")
			}
			if iotExploit {
				color.Red("💀 Exploitation: ENABLED")
			}
			if iotPersistence {
				color.Red("🏴‍☠️ Persistence: ENABLED")
			}
			color.Magenta("⚠️  INDUSTRIAL SYSTEMS AT RISK - PROCEED WITH CAUTION")
		}

		// Configure IoT engine
		config := &iot.IoTConfig{
			IndustrialProtocols: iotIndustrialProtocols,
			IoTProtocols:       iotProtocols,
			NetworkProtocols:   []string{"tcp", "udp"},
			MaxConcurrent:      iotMaxConcurrent,
			StealthMode:        iotStealth,
			PersistenceEnabled: iotPersistence,
			DeepScan:          iotDeepScan,
		}

		// If no protocols specified, use defaults
		if len(config.IndustrialProtocols) == 0 {
			config.IndustrialProtocols = []string{"modbus", "dnp3", "bacnet"}
		}
		if len(config.IoTProtocols) == 0 {
			config.IoTProtocols = []string{"coap", "mqtt"}
		}

		// Setup logger
		logger := &IoTLogger{
			logger: logrus.New(),
			silent: silent,
		}
		if silent {
			logger.logger.SetLevel(logrus.ErrorLevel)
		} else if iotVerbose {
			logger.logger.SetLevel(logrus.DebugLevel)
		}

		// Create domination engine
		dominationEngine := iot.NewDominationEngine(logger, config)

		// Create target
		targetObj := core.NewBaseTarget(target, core.TargetTypeHost)

		ctx := context.Background()

		if !silent {
			color.Cyan("\n🏭 Initiating industrial network domination...")
			color.Cyan("🎯 Scanning for vulnerable industrial systems...")
		}

		// Execute domination attack
		result, err := dominationEngine.DominateNetwork(ctx, targetObj)
		if err != nil {
			return fmt.Errorf("domination failed: %w", err)
		}

		// Display results
		err = displayIoTResults(result)
		if err != nil {
			return fmt.Errorf("failed to display results: %w", err)
		}

		// Save results if requested
		if iotOutput != "" {
			err = saveIoTResults(result, iotFormat, iotOutput)
			if err != nil {
				color.Red("Failed to save results: %v", err)
			} else if !silent {
				color.Green("💾 Results saved to: %s", iotOutput)
			}
		}

		if !silent {
			color.Green("\n✨ IoT/OT domination completed successfully")
			color.Yellow("🏭 Industrial systems under control: %d", len(result.ExploitedDevices))
			color.Red("🏴‍☠️ Persistence methods active: %d", len(result.PersistenceMethods))
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(iotCmd)

	iotCmd.Flags().StringSliceVar(&iotIndustrialProtocols, "industrial", []string{}, "Industrial protocols to scan (modbus,dnp3,bacnet,iec61850,opcua)")
	iotCmd.Flags().StringSliceVar(&iotProtocols, "protocols", []string{}, "IoT protocols to scan (coap,mqtt,zigbee,zwave)")
	iotCmd.Flags().BoolVar(&iotDeepScan, "deep-scan", false, "Enable deep vulnerability scanning")
	iotCmd.Flags().BoolVar(&iotStealth, "stealth", true, "Enable stealth mode operations")
	iotCmd.Flags().BoolVar(&iotPersistence, "persistence", false, "Enable persistence installation")
	iotCmd.Flags().BoolVar(&iotExploit, "exploit", false, "Enable automated exploitation")
	iotCmd.Flags().StringVar(&iotOutput, "output", "", "Output file path")
	iotCmd.Flags().StringVar(&iotFormat, "format", "json", "Output format (json, text)")
	iotCmd.Flags().BoolVar(&iotVerbose, "verbose", false, "Verbose logging output")
	iotCmd.Flags().IntVar(&iotMaxConcurrent, "max-concurrent", 50, "Maximum concurrent scans")
	iotCmd.Flags().IntVar(&iotTimeout, "timeout", 30, "Scan timeout in seconds")
}

// IoTLogger implements core.Logger interface
type IoTLogger struct {
	logger *logrus.Logger
	silent bool
}

func (l *IoTLogger) Debug(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Debug(msg)
}

func (l *IoTLogger) Info(msg string, fields ...core.Field) {
	if l.silent {
		return
	}
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Info(msg)
}

func (l *IoTLogger) Warn(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Warn(msg)
}

func (l *IoTLogger) Error(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Error(msg)
}

func (l *IoTLogger) Fatal(msg string, fields ...core.Field) {
	entry := l.logger.WithFields(l.fieldsToLogrus(fields))
	entry.Fatal(msg)
}

func (l *IoTLogger) fieldsToLogrus(fields []core.Field) logrus.Fields {
	logrusFields := make(logrus.Fields)
	for _, field := range fields {
		logrusFields[field.Key()] = field.Value()
	}
	return logrusFields
}

// displayIoTResults displays IoT domination results
func displayIoTResults(result *iot.DominationResult) error {
	if !silent {
		color.Cyan("\n🏭 IoT/OT DOMINATION RESULTS")
		color.Cyan("=" + strings.Repeat("=", 50))

		// Summary
		color.White("Target: %s", result.GetTarget().GetAddress())
		color.White("Devices Found: %d", len(result.DevicesFound))
		color.White("Devices Exploited: %d", len(result.ExploitedDevices))
		color.White("Persistence Methods: %d", len(result.PersistenceMethods))

		// Device discoveries
		if len(result.DevicesFound) > 0 {
			color.Cyan("\n🔍 Discovered Devices:")
			color.Cyan("-" + strings.Repeat("-", 60))

			for _, device := range result.DevicesFound {
				deviceTypeStr := getDeviceTypeString(device.DeviceType)
				color.Blue("📡 %s (%s)", device.Address, deviceTypeStr)
				color.White("   Protocol: %s", device.Protocol)
				color.White("   Manufacturer: %s", device.Manufacturer)
				color.White("   Model: %s", device.Model)
				if device.Firmware != "" {
					color.White("   Firmware: %s", device.Firmware)
				}
				color.White("   Risk Score: %.1f", device.RiskScore)
				
				if len(device.Vulnerabilities) > 0 {
					color.Yellow("   Vulnerabilities:")
					for _, vuln := range device.Vulnerabilities {
						severityColor := getSeverityColor(vuln.Severity)
						severityColor.Printf("     • %s ", vuln.Description)
						fmt.Printf("(%s)\n", core.SeverityToString(vuln.Severity))
						if vuln.CVE != "" {
							color.Yellow("       CVE: %s", vuln.CVE)
						}
					}
				}

				fmt.Println()
			}
		}

		// Exploited devices
		if len(result.ExploitedDevices) > 0 {
			color.Red("\n💀 Successfully Exploited Devices:")
			color.Red("-" + strings.Repeat("-", 60))

			for _, device := range result.ExploitedDevices {
				deviceTypeStr := getDeviceTypeString(device.DeviceType)
				color.Red("🏴‍☠️ %s (%s) - ACCESS GAINED", device.Address, deviceTypeStr)
				color.White("   Access Level: %s", getAccessLevelString(device.AccessLevel))
				color.White("   Protocol: %s", device.Protocol)
				fmt.Println()
			}
		}

		// Network topology
		if result.NetworkMap != nil && len(result.NetworkMap.Nodes) > 0 {
			color.Cyan("\n🗺️ Network Topology:")
			color.Cyan("-" + strings.Repeat("-", 60))
			
			for _, node := range result.NetworkMap.Nodes {
				deviceTypeStr := getDeviceTypeString(node.DeviceType)
				riskColor := getRiskColor(node.Risk)
				riskColor.Printf("🔗 %s (%s) - Risk: %.1f\n", node.Address, deviceTypeStr, node.Risk)
			}
		}

		// Lateral movement paths
		if len(result.LateralMovementPaths) > 0 {
			color.Magenta("\n🔄 Lateral Movement Opportunities:")
			color.Magenta("-" + strings.Repeat("-", 60))
			
			for _, path := range result.LateralMovementPaths {
				color.Magenta("🎯 From: %s", path.Source)
				color.White("   Targets: %s", strings.Join(path.Targets, ", "))
				color.White("   Method: %s", path.Method)
				color.White("   Success Probability: %.1f%%", path.Probability*100)
				fmt.Println()
			}
		}

		// Risk assessment
		color.Cyan("\n📊 RISK ASSESSMENT:")
		totalRisk := 0.0
		for _, device := range result.DevicesFound {
			totalRisk += device.RiskScore
		}
		
		riskLevel := "LOW"
		riskColor := color.New(color.FgGreen)
		
		if totalRisk > 50 {
			riskLevel = "CRITICAL"
			riskColor = color.New(color.FgRed, color.Bold)
		} else if totalRisk > 25 {
			riskLevel = "HIGH"
			riskColor = color.New(color.FgRed)
		} else if totalRisk > 10 {
			riskLevel = "MEDIUM"
			riskColor = color.New(color.FgYellow)
		}
		
		riskColor.Printf("Total Risk Score: %s (%.1f)\n", riskLevel, totalRisk)
		
		if len(result.ExploitedDevices) > 0 {
			color.Red("🚨 CRITICAL: Industrial systems have been compromised!")
			color.Red("🏭 Immediate remediation required for production safety!")
		}
	}

	return nil
}

// saveIoTResults saves IoT domination results
func saveIoTResults(result *iot.DominationResult, format, filename string) error {
	switch format {
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
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

		fmt.Fprintf(file, "IoT/OT DOMINATION RESULTS\n")
		fmt.Fprintf(file, "========================\n\n")
		fmt.Fprintf(file, "Target: %s\n", result.GetTarget().GetAddress())
		fmt.Fprintf(file, "Timestamp: %s\n", result.GetTimestamp().Format("2006-01-02 15:04:05"))
		fmt.Fprintf(file, "Devices Found: %d\n", len(result.DevicesFound))
		fmt.Fprintf(file, "Devices Exploited: %d\n", len(result.ExploitedDevices))
		fmt.Fprintf(file, "Persistence Methods: %d\n\n", len(result.PersistenceMethods))

		for i, device := range result.DevicesFound {
			fmt.Fprintf(file, "[%d] %s (%s)\n", i+1, device.Address, getDeviceTypeString(device.DeviceType))
			fmt.Fprintf(file, "    Protocol: %s\n", device.Protocol)
			fmt.Fprintf(file, "    Manufacturer: %s\n", device.Manufacturer)
			fmt.Fprintf(file, "    Model: %s\n", device.Model)
			fmt.Fprintf(file, "    Risk Score: %.1f\n", device.RiskScore)
			
			if len(device.Vulnerabilities) > 0 {
				fmt.Fprintf(file, "    Vulnerabilities:\n")
				for _, vuln := range device.Vulnerabilities {
					fmt.Fprintf(file, "      - %s (%s)\n", vuln.Description, core.SeverityToString(vuln.Severity))
				}
			}
			fmt.Fprintf(file, "\n")
		}

		return nil

	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// Helper functions
func getDeviceTypeString(deviceType iot.DeviceType) string {
	switch deviceType {
	case 0: // DeviceTypePLC
		return "PLC"
	case 1: // DeviceTypeHMI
		return "HMI"
	case 2: // DeviceTypeRTU
		return "RTU"
	case 3: // DeviceTypeSCADA
		return "SCADA"
	case 4: // DeviceTypeSmartMeter
		return "Smart Meter"
	case 5: // DeviceTypeIoTSensor
		return "IoT Sensor"
	case 6: // DeviceTypeIPCamera
		return "IP Camera"
	case 7: // DeviceTypeRouter
		return "Router"
	case 8: // DeviceTypeSwitch
		return "Switch"
	case 9: // DeviceTypeFirewall
		return "Firewall"
	case 10: // DeviceTypeInverter
		return "Inverter"
	case 11: // DeviceTypeUPS
		return "UPS"
	case 12: // DeviceTypeBMS
		return "BMS"
	default:
		return "Unknown"
	}
}

func getAccessLevelString(accessLevel iot.AccessLevel) string {
	switch accessLevel {
	case 0: // AccessLevelNone
		return "None"
	case 1: // AccessLevelRead
		return "Read"
	case 2: // AccessLevelWrite
		return "Write"
	case 3: // AccessLevelAdmin
		return "Admin"
	case 4: // AccessLevelRoot
		return "Root"
	case 5: // AccessLevelSystem
		return "System"
	default:
		return "Unknown"
	}
}

func getRiskColor(risk float64) *color.Color {
	if risk > 7.5 {
		return color.New(color.FgRed, color.Bold)
	} else if risk > 5.0 {
		return color.New(color.FgRed)
	} else if risk > 2.5 {
		return color.New(color.FgYellow)
	}
	return color.New(color.FgGreen)
}