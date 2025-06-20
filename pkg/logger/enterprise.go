
package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type SecurityEventType string

const (
	EventPortScan     SecurityEventType = "port_scan"
	EventDNSEnum      SecurityEventType = "dns_enumeration"
	EventWAFDetection SecurityEventType = "waf_detection"
	EventBypassTest   SecurityEventType = "bypass_test"
	EventHoneypot     SecurityEventType = "honeypot_detected"
	EventError        SecurityEventType = "error"
	EventStart        SecurityEventType = "scan_start"
	EventComplete     SecurityEventType = "scan_complete"
)

type SecurityEvent struct {
	Timestamp   time.Time         `json:"timestamp"`
	EventType   SecurityEventType `json:"event_type"`
	Target      string            `json:"target"`
	Source      string            `json:"source_ip,omitempty"`
	Module      string            `json:"module"`
	Action      string            `json:"action"`
	Result      string            `json:"result"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Risk        string            `json:"risk_level"`
	UserAgent   string            `json:"user_agent,omitempty"`
}

type EnterpriseLogger struct {
	logger    *logrus.Logger
	sessionID string
	target    string
	outputDir string
}

func NewEnterpriseLogger(sessionID, target, outputDir string) (*EnterpriseLogger, error) {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339,
		PrettyPrint:     false,
	})

	if outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		logFile := filepath.Join(outputDir, fmt.Sprintf("recon_%s_%s.log", 
			sanitizeTarget(target), time.Now().Format("20060102_150405")))
		
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}

		logger.SetOutput(file)
	}

	return &EnterpriseLogger{
		logger:    logger,
		sessionID: sessionID,
		target:    target,
		outputDir: outputDir,
	}, nil
}

func (el *EnterpriseLogger) LogSecurityEvent(event SecurityEvent) {
	event.Timestamp = time.Now()
	
	if event.Details == nil {
		event.Details = make(map[string]interface{})
	}
	event.Details["session_id"] = el.sessionID
	event.Details["framework"] = "recon-toolkit"
	
	event = el.filterSensitiveData(event)
	
	switch event.Risk {
	case "high":
		el.logger.WithFields(logrus.Fields(event.Details)).
			WithField("event_type", event.EventType).
			WithField("target", event.Target).
			WithField("result", event.Result).
			Error(event.Action)
	case "medium":
		el.logger.WithFields(logrus.Fields(event.Details)).
			WithField("event_type", event.EventType).
			WithField("target", event.Target).
			WithField("result", event.Result).
			Warn(event.Action)
	default:
		el.logger.WithFields(logrus.Fields(event.Details)).
			WithField("event_type", event.EventType).
			WithField("target", event.Target).
			WithField("result", event.Result).
			Info(event.Action)
	}
}

func (el *EnterpriseLogger) LogPortScan(target string, ports []int, result map[int]string) {
	openPorts := 0
	for _, state := range result {
		if state == "open" {
			openPorts++
		}
	}

	event := SecurityEvent{
		EventType: EventPortScan,
		Target:    target,
		Module:    "scanner",
		Action:    "port_scan_completed",
		Result:    "success",
		Risk:      "medium",
		Details: map[string]interface{}{
			"ports_scanned": len(ports),
			"open_ports":    openPorts,
			"scan_type":     "tcp_connect",
		},
	}

	el.LogSecurityEvent(event)
}

func (el *EnterpriseLogger) LogDNSEnumeration(domain string, subdomainsFound int, techniques []string) {
	risk := "low"
	if subdomainsFound > 50 {
		risk = "medium"
	}
	if subdomainsFound > 100 {
		risk = "high"
	}

	event := SecurityEvent{
		EventType: EventDNSEnum,
		Target:    domain,
		Module:    "dns",
		Action:    "subdomain_enumeration_completed",
		Result:    "success",
		Risk:      risk,
		Details: map[string]interface{}{
			"subdomains_found": subdomainsFound,
			"techniques_used":  techniques,
		},
	}

	el.LogSecurityEvent(event)
}

func (el *EnterpriseLogger) LogWAFDetection(target, wafType string, confidence float64, bypassed bool) {
	risk := "medium"
	if bypassed {
		risk = "high"
	}

	result := "waf_detected"
	if wafType == "" {
		result = "no_waf_detected"
		risk = "low"
	}

	event := SecurityEvent{
		EventType: EventWAFDetection,
		Target:    target,
		Module:    "waf",
		Action:    "waf_detection_completed",
		Result:    result,
		Risk:      risk,
		Details: map[string]interface{}{
			"waf_type":   wafType,
			"confidence": confidence,
			"bypassed":   bypassed,
		},
	}

	el.LogSecurityEvent(event)
}

func (el *EnterpriseLogger) LogHoneypotDetection(target string, indicators []string) {
	event := SecurityEvent{
		EventType: EventHoneypot,
		Target:    target,
		Module:    "scanner",
		Action:    "honeypot_detected",
		Result:    "warning",
		Risk:      "high",
		Details: map[string]interface{}{
			"indicators": indicators,
			"warning":    "possible_honeypot_environment",
		},
	}

	el.LogSecurityEvent(event)
}

func (el *EnterpriseLogger) LogError(module, action string, err error, details map[string]interface{}) {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["error"] = err.Error()

	event := SecurityEvent{
		EventType: EventError,
		Target:    el.target,
		Module:    module,
		Action:    action,
		Result:    "error",
		Risk:      "medium",
		Details:   details,
	}

	el.LogSecurityEvent(event)
}

func (el *EnterpriseLogger) LogScanStart(target, scanType string, config map[string]interface{}) {
	event := SecurityEvent{
		EventType: EventStart,
		Target:    target,
		Module:    "core",
		Action:    "scan_session_started",
		Result:    "initiated",
		Risk:      "low",
		Details:   config,
	}

	el.LogSecurityEvent(event)
}

func (el *EnterpriseLogger) LogScanComplete(target string, duration time.Duration, summary map[string]interface{}) {
	if summary == nil {
		summary = make(map[string]interface{})
	}
	summary["duration_seconds"] = duration.Seconds()

	event := SecurityEvent{
		EventType: EventComplete,
		Target:    target,
		Module:    "core",
		Action:    "scan_session_completed",
		Result:    "success",
		Risk:      "low",
		Details:   summary,
	}

	el.LogSecurityEvent(event)
}

func (el *EnterpriseLogger) filterSensitiveData(event SecurityEvent) SecurityEvent {
	sensitiveKeys := []string{"password", "token", "key", "secret", "auth"}
	
	for key, value := range event.Details {
		keyLower := strings.ToLower(key)
		for _, sensitive := range sensitiveKeys {
			if strings.Contains(keyLower, sensitive) {
				event.Details[key] = "[FILTERED]"
				break
			}
		}
		
		if str, ok := value.(string); ok {
			if strings.Contains(str, "127.0.0.1") || strings.Contains(str, "localhost") {
				event.Details[key] = "[LOCAL_IP]"
			}
		}
	}

	return event
}

func sanitizeTarget(target string) string {
	target = strings.ReplaceAll(target, "https://", "")
	target = strings.ReplaceAll(target, "http://", "")
	target = strings.ReplaceAll(target, "/", "_")
	target = strings.ReplaceAll(target, ":", "_")
	target = strings.ReplaceAll(target, "?", "_")
	return target
}

func (el *EnterpriseLogger) Close() error {
	if closer, ok := el.logger.Out.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}