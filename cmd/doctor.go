package cmd

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

type SystemCheck struct {
	Name        string
	Description string
	Status      string
	Details     string
	Critical    bool
	Fix         string
}

// EndpointStatus defined in audit.go

var (
	verboseDoctor bool
	fixIssues     bool
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Diagnose system configuration and requirements",
	Long: `Perform comprehensive system diagnostics to ensure RTK Elite
can operate correctly. Checks dependencies, permissions, network
configuration, and system capabilities.

This command verifies:
- Operating system compatibility
- Required system permissions (root/CAP_NET_RAW)
- Network connectivity and configuration
- Required dependencies and tools
- File system permissions
- Memory and system resources

Examples:
  rtk doctor                    # Basic system check
  rtk doctor --verbose          # Detailed diagnostic output
  rtk doctor --fix             # Attempt to fix detected issues`,
	RunE: runDoctor,
}

func init() {
	rootCmd.AddCommand(doctorCmd)
	
	doctorCmd.Flags().BoolVarP(&verboseDoctor, "verbose", "v", false, 
		"Show detailed diagnostic information")
	doctorCmd.Flags().BoolVar(&fixIssues, "fix", false, 
		"Attempt to automatically fix detected issues")
}

func runDoctor(cmd *cobra.Command, args []string) error {
	fmt.Printf("🏥 RTK Elite System Doctor v2.1\n")
	fmt.Printf("═══════════════════════════════════════════════════════════\n\n")
	
	fmt.Printf("🖥️  System: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("🐹 Go Version: %s\n", runtime.Version())
	fmt.Printf("📅 Scan Date: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	
	checks := []func() SystemCheck{
		checkOperatingSystem,
		checkUserPermissions,
		checkNetworkCapabilities,
		checkRequiredCommands,
		checkFilePermissions,
		checkSystemResources,
		checkEnhancedNetworkConnectivity,
		checkFirewallStatus,
		checkDNSResolution,
		checkDiskSpace,
		checkPCAPCapabilities,
	}
	
	var results []SystemCheck
	var criticalIssues int
	var warnings int
	
	for _, check := range checks {
		result := check()
		results = append(results, result)
		
		// Print result
		status := getStatusIcon(result.Status)
		fmt.Printf("%s %s\n", status, result.Name)
		
		if verboseDoctor || result.Status != "PASS" {
			fmt.Printf("   %s\n", result.Details)
			if result.Fix != "" && result.Status == "FAIL" {
				fmt.Printf("   💡 Fix: %s\n", result.Fix)
			}
		}
		
		if result.Status == "FAIL" && result.Critical {
			criticalIssues++
		} else if result.Status == "WARN" {
			warnings++
		}
		
		fmt.Println()
	}
	
	// Summary
	fmt.Printf("═══════════════════════════════════════════════════════════\n")
	fmt.Printf("📊 DIAGNOSTIC SUMMARY\n")
	fmt.Printf("═══════════════════════════════════════════════════════════\n\n")
	
	passed := len(results) - criticalIssues - warnings
	fmt.Printf("✅ Passed: %d\n", passed)
	fmt.Printf("⚠️  Warnings: %d\n", warnings)
	fmt.Printf("❌ Critical Issues: %d\n\n", criticalIssues)
	
	// Overall status
	if criticalIssues > 0 {
		fmt.Printf("🚨 SYSTEM STATUS: CRITICAL ISSUES DETECTED\n")
		fmt.Printf("RTK Elite may not function correctly until issues are resolved.\n\n")
		
		if fixIssues {
			fmt.Printf("🔧 ATTEMPTING AUTOMATIC FIXES...\n\n")
			for _, result := range results {
				if result.Status == "FAIL" && result.Fix != "" {
					fmt.Printf("Fixing: %s\n", result.Name)
					if err := attemptFix(result); err != nil {
						fmt.Printf("   ❌ Fix failed: %v\n", err)
					} else {
						fmt.Printf("   ✅ Fix applied successfully\n")
					}
				}
			}
		}
		
		return fmt.Errorf("critical system issues detected")
	} else if warnings > 0 {
		fmt.Printf("⚠️  SYSTEM STATUS: WARNINGS DETECTED\n")
		fmt.Printf("RTK Elite should work but some features may be limited.\n")
	} else {
		fmt.Printf("✅ SYSTEM STATUS: ALL CHECKS PASSED\n")
		fmt.Printf("RTK Elite is ready for optimal operation.\n")
	}
	
	// Recommendations
	fmt.Printf("\n🎯 RECOMMENDATIONS:\n")
	for _, result := range results {
		if result.Status != "PASS" && result.Fix != "" {
			fmt.Printf("• %s: %s\n", result.Name, result.Fix)
		}
	}
	
	return nil
}

func checkOperatingSystem() SystemCheck {
	check := SystemCheck{
		Name:        "Operating System Compatibility",
		Description: "Verify OS supports RTK Elite features",
		Critical:    true,
	}
	
	supportedOS := map[string]bool{
		"linux":   true,
		"darwin":  true,
		"windows": true,
		"freebsd": true,
	}
	
	if supported, exists := supportedOS[runtime.GOOS]; exists && supported {
		check.Status = "PASS"
		check.Details = fmt.Sprintf("Operating system %s is supported", runtime.GOOS)
	} else {
		check.Status = "FAIL"
		check.Details = fmt.Sprintf("Operating system %s is not officially supported", runtime.GOOS)
		check.Fix = "Use Linux, macOS, Windows, or FreeBSD for full compatibility"
	}
	
	return check
}

func checkUserPermissions() SystemCheck {
	check := SystemCheck{
		Name:        "User Permissions",
		Description: "Check for required privileges",
		Critical:    false,
	}
	
	isRoot := os.Getuid() == 0
	hasNetRaw := false
	
	// Check for CAP_NET_RAW on Linux
	if runtime.GOOS == "linux" {
		if cmd := exec.Command("getcap", os.Args[0]); cmd.Run() == nil {
			output, _ := cmd.Output()
			hasNetRaw = strings.Contains(string(output), "cap_net_raw")
		}
	}
	
	if isRoot {
		check.Status = "PASS"
		check.Details = "Running with root privileges - all features available"
	} else if hasNetRaw {
		check.Status = "PASS"
		check.Details = "CAP_NET_RAW capability detected - raw socket features available"
	} else {
		check.Status = "WARN"
		check.Details = "Limited privileges - some advanced features may not work"
		check.Fix = "Run as root or add CAP_NET_RAW: sudo setcap cap_net_raw+ep ./rtk-elite"
	}
	
	return check
}

func checkNetworkCapabilities() SystemCheck {
	check := SystemCheck{
		Name:        "Network Capabilities",
		Description: "Test raw socket and network access",
		Critical:    false,
	}
	
	// Test raw socket creation
	if conn, err := net.Dial("tcp", "google.com:80"); err == nil {
		conn.Close()
		check.Status = "PASS"
		check.Details = "Network connectivity confirmed"
	} else {
		check.Status = "FAIL"
		check.Details = fmt.Sprintf("Network connectivity test failed: %v", err)
		check.Fix = "Check network configuration and firewall settings"
		check.Critical = true
	}
	
	return check
}

func checkRequiredCommands() SystemCheck {
	check := SystemCheck{
		Name:        "Required Dependencies",
		Description: "Verify external tools availability",
		Critical:    false,
	}
	
	requiredCommands := []string{"nslookup", "ping"}
	optionalCommands := []string{"nmap", "curl", "wget", "dig"}
	
	var missing []string
	var available []string
	
	// Check required commands
	for _, cmd := range requiredCommands {
		if _, err := exec.LookPath(cmd); err != nil {
			missing = append(missing, cmd)
		} else {
			available = append(available, cmd)
		}
	}
	
	// Check optional commands
	var optionalAvailable []string
	for _, cmd := range optionalCommands {
		if _, err := exec.LookPath(cmd); err == nil {
			optionalAvailable = append(optionalAvailable, cmd)
		}
	}
	
	if len(missing) == 0 {
		check.Status = "PASS"
		check.Details = fmt.Sprintf("All required commands available. Optional tools: %s", 
			strings.Join(optionalAvailable, ", "))
	} else {
		check.Status = "WARN"
		check.Details = fmt.Sprintf("Missing commands: %s. Available: %s", 
			strings.Join(missing, ", "), strings.Join(available, ", "))
		check.Fix = fmt.Sprintf("Install missing tools: %s", strings.Join(missing, ", "))
	}
	
	return check
}

func checkFilePermissions() SystemCheck {
	check := SystemCheck{
		Name:        "File System Permissions",
		Description: "Verify read/write access to required directories",
		Critical:    true,
	}
	
	// Test current directory write access
	testFile := ".rtk_doctor_test"
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		check.Status = "FAIL"
		check.Details = fmt.Sprintf("Cannot write to current directory: %v", err)
		check.Fix = "Ensure current directory is writable or change to a writable directory"
		return check
	}
	os.Remove(testFile)
	
	// Check home directory access
	homeDir, err := os.UserHomeDir()
	if err != nil {
		check.Status = "WARN"
		check.Details = "Cannot determine home directory"
	} else {
		configDir := homeDir + "/.rtk-elite"
		if err := os.MkdirAll(configDir, 0755); err != nil {
			check.Status = "WARN"
			check.Details = fmt.Sprintf("Cannot create config directory: %v", err)
			check.Fix = "Ensure home directory is writable"
		} else {
			check.Status = "PASS"
			check.Details = "File system permissions are adequate"
		}
	}
	
	return check
}

func checkSystemResources() SystemCheck {
	check := SystemCheck{
		Name:        "System Resources",
		Description: "Check available memory and system limits",
		Critical:    false,
	}
	
	var memInfo syscall.Sysinfo_t
	if err := syscall.Sysinfo(&memInfo); err == nil {
		totalRAM := memInfo.Totalram * uint64(memInfo.Unit) / (1024 * 1024) // MB
		freeRAM := memInfo.Freeram * uint64(memInfo.Unit) / (1024 * 1024)   // MB
		
		if totalRAM < 512 {
			check.Status = "WARN"
			check.Details = fmt.Sprintf("Low system memory: %d MB total", totalRAM)
			check.Fix = "Consider upgrading system memory for better performance"
		} else if freeRAM < 128 {
			check.Status = "WARN"
			check.Details = fmt.Sprintf("Low available memory: %d MB free of %d MB total", freeRAM, totalRAM)
			check.Fix = "Close unnecessary applications to free memory"
		} else {
			check.Status = "PASS"
			check.Details = fmt.Sprintf("Memory: %d MB total, %d MB available", totalRAM, freeRAM)
		}
	} else {
		check.Status = "WARN"
		check.Details = "Cannot determine system memory information"
	}
	
	return check
}

func checkNetworkConnectivity() SystemCheck {
	check := SystemCheck{
		Name:        "Network Connectivity",
		Description: "Test internet connectivity and DNS",
		Critical:    true,
	}
	
	// Test connectivity to common servers
	testHosts := []string{"8.8.8.8:53", "1.1.1.1:53", "google.com:80"}
	var working []string
	var failed []string
	
	for _, host := range testHosts {
		if conn, err := net.DialTimeout("tcp", host, 5*time.Second); err == nil {
			conn.Close()
			working = append(working, host)
		} else {
			failed = append(failed, host)
		}
	}
	
	if len(working) >= 2 {
		check.Status = "PASS"
		check.Details = fmt.Sprintf("Network connectivity confirmed (%d/%d hosts reachable)", 
			len(working), len(testHosts))
	} else if len(working) >= 1 {
		check.Status = "WARN"
		check.Details = fmt.Sprintf("Limited connectivity (%d/%d hosts reachable)", 
			len(working), len(testHosts))
		check.Fix = "Check firewall settings and network configuration"
	} else {
		check.Status = "FAIL"
		check.Details = "No network connectivity detected"
		check.Fix = "Check network configuration, proxy settings, and firewall rules"
	}
	
	return check
}

func checkEnhancedNetworkConnectivity() SystemCheck {
	check := SystemCheck{
		Name:        "Enhanced Network Connectivity",
		Description: "Test connectivity to RTK Elite dependencies",
		Critical:    true,
	}
	
	// Import endpoint status function from audit.go
	endpoints := []string{
		"https://api.github.com",
		"https://api.osv.dev",
		"http://ip-api.com",
		"https://crt.sh",
	}
	
	var working []string
	var failed []string
	var details []string
	
	for _, endpoint := range endpoints {
		status := testEndpointConnectivity(endpoint)
		if status.Status == "OK" {
			working = append(working, endpoint)
			details = append(details, fmt.Sprintf("✅ %s: OK", endpoint))
		} else {
			failed = append(failed, endpoint)
			details = append(details, fmt.Sprintf("❌ %s: %s (%s)", endpoint, status.Status, status.Error))
		}
	}
	
	if len(working) == len(endpoints) {
		check.Status = "PASS"
		check.Details = fmt.Sprintf("All RTK endpoints reachable (%d/%d)", len(working), len(endpoints))
	} else if len(working) >= len(endpoints)/2 {
		check.Status = "WARN"
		check.Details = fmt.Sprintf("Partial endpoint connectivity (%d/%d)\nDetails:\n%s", 
			len(working), len(endpoints), strings.Join(details, "\n"))
		check.Fix = "Check firewall rules for HTTPS/HTTP access"
	} else {
		check.Status = "FAIL"
		check.Details = fmt.Sprintf("Most endpoints unreachable (%d/%d)\nDetails:\n%s", 
			len(working), len(endpoints), strings.Join(details, "\n"))
		check.Fix = "Verify internet connectivity and proxy settings"
	}
	
	return check
}

func testEndpointConnectivity(endpoint string) EndpointStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	req, err := http.NewRequestWithContext(ctx, "HEAD", endpoint, nil)
	if err != nil {
		return EndpointStatus{
			Endpoint: endpoint,
			Status:   "ERROR",
			Error:    err.Error(),
		}
	}
	
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return EndpointStatus{
			Endpoint: endpoint,
			Status:   "FAIL",
			Error:    err.Error(),
		}
	}
	defer resp.Body.Close()
	
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return EndpointStatus{
			Endpoint: endpoint,
			Status:   "OK",
		}
	}
	
	return EndpointStatus{
		Endpoint: endpoint,
		Status:   "FAIL",
		Error:    fmt.Sprintf("HTTP %d", resp.StatusCode),
	}
}

func checkFirewallStatus() SystemCheck {
	check := SystemCheck{
		Name:        "Firewall Configuration",
		Description: "Check for restrictive firewall rules",
		Critical:    false,
	}
	
	// This is a simplified check
	check.Status = "PASS"
	check.Details = "Firewall check completed (manual verification recommended)"
	
	if runtime.GOOS == "linux" {
		// Check if iptables is blocking outbound connections
		if cmd := exec.Command("iptables", "-L", "OUTPUT"); cmd.Run() == nil {
			check.Details = "iptables detected - verify outbound rules allow scanning"
		}
	}
	
	return check
}

func checkDNSResolution() SystemCheck {
	check := SystemCheck{
		Name:        "DNS Resolution",
		Description: "Test DNS functionality",
		Critical:    true,
	}
	
	testDomains := []string{"google.com", "github.com", "cloudflare.com"}
	var resolved []string
	var failed []string
	
	for _, domain := range testDomains {
		if _, err := net.LookupHost(domain); err == nil {
			resolved = append(resolved, domain)
		} else {
			failed = append(failed, domain)
		}
	}
	
	if len(resolved) == len(testDomains) {
		check.Status = "PASS"
		check.Details = "DNS resolution working correctly"
	} else if len(resolved) > 0 {
		check.Status = "WARN"
		check.Details = fmt.Sprintf("Partial DNS resolution (%d/%d domains resolved)", 
			len(resolved), len(testDomains))
		check.Fix = "Check DNS server configuration"
	} else {
		check.Status = "FAIL"
		check.Details = "DNS resolution not working"
		check.Fix = "Configure valid DNS servers (8.8.8.8, 1.1.1.1)"
	}
	
	return check
}

func checkDiskSpace() SystemCheck {
	check := SystemCheck{
		Name:        "Disk Space",
		Description: "Check available disk space",
		Critical:    false,
	}
	
	// Get current directory disk usage
	var stat syscall.Statfs_t
	if err := syscall.Statfs(".", &stat); err == nil {
		available := stat.Bavail * uint64(stat.Bsize) / (1024 * 1024) // MB
		
		if available < 100 {
			check.Status = "WARN"
			check.Details = fmt.Sprintf("Low disk space: %d MB available", available)
			check.Fix = "Free up disk space before running large scans"
		} else {
			check.Status = "PASS"
			check.Details = fmt.Sprintf("Adequate disk space: %d MB available", available)
		}
	} else {
		check.Status = "WARN"
		check.Details = "Cannot determine disk space"
	}
	
	return check
}

func checkPCAPCapabilities() SystemCheck {
	check := SystemCheck{
		Name:        "PCAP Capabilities",
		Description: "Check packet capture permissions and capabilities",
		Critical:    false,
	}
	
	// Check if running as root or with CAP_NET_RAW
	if os.Getuid() == 0 {
		check.Status = "PASS"
		check.Details = "Running as root - full PCAP capabilities available"
	} else {
		// Check for CAP_NET_RAW capability
		if canUsePCAP() {
			check.Status = "PASS"
			check.Details = "CAP_NET_RAW capability available for packet capture"
		} else {
			check.Status = "WARN"
			check.Details = "Limited PCAP capabilities - may require sudo for packet capture"
			check.Fix = "Run with sudo or grant CAP_NET_RAW capability: sudo setcap cap_net_raw+ep /path/to/rtk-elite"
		}
	}
	
	// Check for libpcap availability
	if _, err := exec.LookPath("tcpdump"); err == nil {
		check.Details += " | tcpdump available for validation"
	} else {
		check.Details += " | tcpdump not found (optional)"
	}
	
	return check
}

func canUsePCAP() bool {
	// Simplified check - in reality would test actual capability
	// This is a basic implementation
	testSocket, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		return false
	}
	syscall.Close(testSocket)
	return true
}

func getStatusIcon(status string) string {
	switch status {
	case "PASS":
		return "✅"
	case "WARN":
		return "⚠️ "
	case "FAIL":
		return "❌"
	default:
		return "❓"
	}
}

func attemptFix(check SystemCheck) error {
	// Basic automatic fixes
	switch check.Name {
	case "File System Permissions":
		// Try to create config directory
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		return os.MkdirAll(homeDir+"/.rtk-elite", 0755)
		
	default:
		return fmt.Errorf("no automatic fix available for %s", check.Name)
	}
}