package core

import (
	"context"
	"time"
)

// Scanner interface - Single Responsibility Principle
type Scanner interface {
	Scan(ctx context.Context, target Target) (*ScanResult, error)
	Configure(config Config) error
	GetCapabilities() []string
}

// Target interface - abstraction for any scannable target
type Target interface {
	GetAddress() string
	GetType() TargetType
	GetMetadata() map[string]interface{}
}

// ScanResult interface - standardized result format
type ScanResult interface {
	GetTarget() Target
	GetFindings() []Finding
	GetMetadata() map[string]interface{}
	GetTimestamp() time.Time
}

// Finding interface - standardized vulnerability/finding format
type Finding interface {
	GetID() string
	GetSeverity() Severity
	GetTitle() string
	GetDescription() string
	GetEvidence() []Evidence
	GetRecommendations() []string
}

// Evidence interface - proof of finding
type Evidence interface {
	GetType() EvidenceType
	GetData() interface{}
	GetContext() string
}

// Config interface - configuration abstraction
type Config interface {
	Get(key string) interface{}
	Set(key string, value interface{}) error
	Validate() error
}

// Logger interface - logging abstraction
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Fatal(msg string, fields ...Field)
}

// Field interface - structured logging fields
type Field interface {
	Key() string
	Value() interface{}
}

// Plugin interface - hot-swappable modules
type Plugin interface {
	GetName() string
	GetVersion() string
	GetDescription() string
	Initialize(config Config) error
	Execute(ctx context.Context, params map[string]interface{}) (interface{}, error)
	Cleanup() error
}

// Stealth interface - anti-detection capabilities
type Stealth interface {
	ObfuscateTraffic(data []byte) ([]byte, error)
	RandomizeTimings() time.Duration
	GetProxyChain() []ProxyNode
	CleanTraces() error
}

// ProxyNode interface - proxy abstraction
type ProxyNode interface {
	GetAddress() string
	GetType() ProxyType
	Connect(ctx context.Context) error
	Close() error
}

// ThreatIntel interface - threat intelligence integration
type ThreatIntel interface {
	GetCVEs(target Target) ([]CVE, error)
	GetIOCs(target Target) ([]IOC, error)
	UpdateFeeds() error
}

// CVE interface - vulnerability information
type CVE interface {
	GetID() string
	GetCVSS() float64
	GetDescription() string
	GetExploits() []Exploit
}

// Exploit interface - exploit information
type Exploit interface {
	GetID() string
	GetType() ExploitType
	GetReliability() Reliability
	Execute(ctx context.Context, target Target) (*ExploitResult, error)
}

// ExploitResult interface - exploitation results
type ExploitResult interface {
	IsSuccessful() bool
	GetSession() Session
	GetEvidence() []Evidence
}

// Session interface - compromised system session
type Session interface {
	GetID() string
	Execute(command string) (string, error)
	Upload(localPath, remotePath string) error
	Download(remotePath, localPath string) error
	Close() error
}

// Enums and types
type TargetType int
type Severity int
type EvidenceType int
type ProxyType int
type ExploitType int
type Reliability int

const (
	// Target types
	TargetTypeHost TargetType = iota
	TargetTypeNetwork
	TargetTypeWebapp
	TargetTypeAPI
	TargetTypeIoT
	TargetTypeCloud
	TargetTypeMobile
)

const (
	// Severity levels
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

const (
	// Evidence types
	EvidenceTypePacket EvidenceType = iota
	EvidenceTypeScreenshot
	EvidenceTypeLog
	EvidenceTypeFile
	EvidenceTypeMemory
)

const (
	// Proxy types
	ProxyTypeHTTP ProxyType = iota
	ProxyTypeSOCKS4
	ProxyTypeSOCKS5
	ProxyTypeTor
	ProxyTypeVPN
)

const (
	// Exploit types
	ExploitTypeRemote ExploitType = iota
	ExploitTypeLocal
	ExploitTypeWebApp
	ExploitTypeSocial
)

const (
	// Reliability levels
	ReliabilityExcellent Reliability = iota
	ReliabilityGood
	ReliabilityNormal
	ReliabilityUnreliable
)

// IOC interface - Indicator of Compromise
type IOC interface {
	GetType() string
	GetValue() string
	GetThreatLevel() Severity
	GetSource() string
}