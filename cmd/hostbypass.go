package cmd

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"recon-toolkit/pkg/logger"
)

var hostbypassCmd = &cobra.Command{
	Use:   "hostbypass [ip]",
	Short: "🔓 Host header bypass techniques",
	Long: `Advanced Host header bypass for 403 Forbidden responses:

🔓 BYPASS TECHNIQUES:
  - Common hostname enumeration
  - Domain guessing based on IP ranges
  - Virtual host discovery
  - Host header injection testing
  - HTTP/HTTPS protocol testing

🎯 TARGET SCENARIOS:
  - 403 Forbidden responses
  - Virtual host restrictions
  - Cloudflare origin protection
  - Load balancer configurations

Usage:
  recon-toolkit hostbypass 172.67.68.228
  recon-toolkit hostbypass 192.168.1.100 --wordlist custom.txt`,
	Args: cobra.ExactArgs(1),
	RunE: runHostBypass,
}

var (
	hostBypassWordlist string
	hostBypassTimeout  int
)

func init() {
	rootCmd.AddCommand(hostbypassCmd)
	
	hostbypassCmd.Flags().StringVar(&hostBypassWordlist, "wordlist", "", "Custom wordlist for hostnames")
	hostbypassCmd.Flags().IntVar(&hostBypassTimeout, "timeout", 10, "HTTP timeout in seconds")
}

func runHostBypass(cmd *cobra.Command, args []string) error {
	targetIP := args[0]
	
	loggerAdapter := logger.NewLoggerAdapter()
	loggerAdapter.Info("🔓 HOST HEADER BYPASS ACTIVATED", 
		logger.StringField("target", targetIP))
	
	fmt.Printf("🔓 Starting Host header bypass on %s\n", targetIP)
	
	// Test baseline request
	fmt.Println("📊 Testing baseline request...")
	baseline := testRequest(targetIP, targetIP)
	fmt.Printf("Baseline response: %d %s\n", baseline.StatusCode, baseline.Status)
	
	if baseline.StatusCode != 403 && baseline.StatusCode != 404 {
		fmt.Println("✅ Target doesn't appear to be protected by Host header filtering")
		return nil
	}
	
	// Generate hostname candidates
	hostnames := generateHostnameCandidates(targetIP)
	
	fmt.Printf("🎯 Testing %d hostname candidates...\n", len(hostnames))
	
	successfulHosts := make([]HostBypassResult, 0)
	
	for i, hostname := range hostnames {
		if i%50 == 0 {
			fmt.Printf("Progress: %d/%d\n", i, len(hostnames))
		}
		
		result := testRequest(targetIP, hostname)
		if result.StatusCode != baseline.StatusCode && result.StatusCode != 404 {
			success := HostBypassResult{
				Hostname:   hostname,
				StatusCode: result.StatusCode,
				Status:     result.Status,
				Headers:    getImportantHeaders(result),
			}
			successfulHosts = append(successfulHosts, success)
			
			fmt.Printf("✅ BYPASS SUCCESS: %s -> %d %s\n", hostname, result.StatusCode, result.Status)
			
			// If we found a 200, try to get more info
			if result.StatusCode == 200 {
				fmt.Printf("🎯 200 OK response found! Testing further...\n")
				analyzeSuccessfulBypass(targetIP, hostname)
			}
		}
	}
	
	// Print results
	printHostBypassResults(targetIP, baseline, successfulHosts)
	
	return nil
}

type HostBypassResult struct {
	Hostname   string            `json:"hostname"`
	StatusCode int               `json:"status_code"`
	Status     string            `json:"status"`
	Headers    map[string]string `json:"headers"`
}

func testRequest(ip, hostname string) *http.Response {
	client := &http.Client{
		Timeout: time.Duration(hostBypassTimeout) * time.Second,
	}
	
	testURL := fmt.Sprintf("http://%s", ip)
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return &http.Response{StatusCode: 0, Status: "Request Error"}
	}
	
	req.Host = hostname
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	
	resp, err := client.Do(req)
	if err != nil {
		return &http.Response{StatusCode: 0, Status: "Connection Error"}
	}
	
	return resp
}

func generateHostnameCandidates(ip string) []string {
	hostnames := []string{
		// Original IP
		ip,
		
		// Common hostnames
		"localhost", "www.localhost", "local.dev", "dev.local",
		"admin", "panel", "cpanel", "webmail", "mail",
		"www", "web", "site", "portal", "dashboard",
		"api", "app", "application", "service",
		"internal", "intranet", "private", "secure",
		"staging", "test", "dev", "development",
		"prod", "production", "live",
		
		// Domain variations based on IP
		"site.com", "example.com", "test.com", "domain.com",
		"website.com", "server.com", "host.com",
		
		// Common TLDs with generic names
		"site.net", "site.org", "site.io", "site.co",
		"app.com", "web.com", "api.com",
		
		// Cloudflare specific attempts
		"origin.example.com", "direct.example.com",
		"backend.example.com", "server.example.com",
	}
	
	// Add IP-based variations
	ipParts := strings.Split(ip, ".")
	if len(ipParts) == 4 {
		// Add variations like 172-67-68-228.example.com
		ipDashed := strings.Join(ipParts, "-")
		hostnames = append(hostnames, []string{
			fmt.Sprintf("%s.example.com", ipDashed),
			fmt.Sprintf("%s.cloudflare.com", ipDashed),
			fmt.Sprintf("%s.herokuapp.com", ipDashed),
			fmt.Sprintf("%s.github.io", ipDashed),
			fmt.Sprintf("ip-%s.amazonaws.com", ipDashed),
		}...)
	}
	
	// Add numeric variations
	for i := 1; i <= 10; i++ {
		hostnames = append(hostnames, fmt.Sprintf("server%d.com", i))
		hostnames = append(hostnames, fmt.Sprintf("web%d.com", i))
		hostnames = append(hostnames, fmt.Sprintf("site%d.example.com", i))
	}
	
	return hostnames
}

func getImportantHeaders(resp *http.Response) map[string]string {
	important := map[string]string{}
	
	importantHeaders := []string{
		"Server", "X-Powered-By", "X-Frame-Options",
		"Content-Type", "Set-Cookie", "Location",
		"CF-Ray", "CF-Cache-Status",
	}
	
	for _, header := range importantHeaders {
		if value := resp.Header.Get(header); value != "" {
			important[header] = value
		}
	}
	
	return important
}

func analyzeSuccessfulBypass(ip, hostname string) {
	fmt.Printf("🔍 Analyzing successful bypass for %s...\n", hostname)
	
	// Test different paths
	paths := []string{"/", "/admin", "/panel", "/login", "/api", "/status", "/health"}
	
	for _, path := range paths {
		testURL := fmt.Sprintf("http://%s%s", ip, path)
		req, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}
		
		req.Host = hostname
		
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		
		if resp.StatusCode == 200 {
			fmt.Printf("  ✅ %s -> %d OK\n", path, resp.StatusCode)
		}
	}
}

func printHostBypassResults(ip string, baseline *http.Response, results []HostBypassResult) {
	fmt.Printf(`
🔓 HOST HEADER BYPASS RESULTS

Target IP: %s
Baseline Response: %d %s
Successful Bypasses: %d

`, ip, baseline.StatusCode, baseline.Status, len(results))

	if len(results) > 0 {
		fmt.Println("🎯 SUCCESSFUL BYPASSES:")
		fmt.Println("=" + strings.Repeat("=", 60))
		
		for i, result := range results {
			fmt.Printf(`
%d. Hostname: %s
   Response: %d %s
   Headers: %v
   
`, i+1, result.Hostname, result.StatusCode, result.Status, result.Headers)
		}
		
		fmt.Println("🚨 SECURITY IMPACT:")
		fmt.Println("- Host header filtering can be bypassed")
		fmt.Println("- Potential access to protected virtual hosts")
		fmt.Println("- May reveal internal services or admin panels")
		fmt.Println("- Could lead to further exploitation opportunities")
		
	} else {
		fmt.Println("❌ No successful bypasses found")
		fmt.Println("✅ Host header filtering appears to be properly configured")
	}
}