package core

import (
	"sync"
	"time"
)

// BaseTarget - базовая реализация Target
type BaseTarget struct {
	address  string
	target_type TargetType
	metadata map[string]interface{}
	mutex    sync.RWMutex
}

func NewBaseTarget(address string, targetType TargetType) *BaseTarget {
	return &BaseTarget{
		address:     address,
		target_type: targetType,
		metadata:    make(map[string]interface{}),
	}
}

func (t *BaseTarget) GetAddress() string {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.address
}

func (t *BaseTarget) GetType() TargetType {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.target_type
}

func (t *BaseTarget) GetMetadata() map[string]interface{} {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	result := make(map[string]interface{})
	for k, v := range t.metadata {
		result[k] = v
	}
	return result
}

func (t *BaseTarget) SetMetadata(key string, value interface{}) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.metadata[key] = value
}

// BaseScanResult - базовая реализация ScanResult
type BaseScanResult struct {
	target    Target
	findings  []Finding
	metadata  map[string]interface{}
	timestamp time.Time
	mutex     sync.RWMutex
}

func NewBaseScanResult(target Target) *BaseScanResult {
	return &BaseScanResult{
		target:    target,
		findings:  make([]Finding, 0),
		metadata:  make(map[string]interface{}),
		timestamp: time.Now(),
	}
}

func (r *BaseScanResult) GetTarget() Target {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.target
}

func (r *BaseScanResult) GetFindings() []Finding {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	result := make([]Finding, len(r.findings))
	copy(result, r.findings)
	return result
}

func (r *BaseScanResult) AddFinding(finding Finding) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.findings = append(r.findings, finding)
}

func (r *BaseScanResult) GetMetadata() map[string]interface{} {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	result := make(map[string]interface{})
	for k, v := range r.metadata {
		result[k] = v
	}
	return result
}

func (r *BaseScanResult) SetMetadata(key string, value interface{}) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.metadata[key] = value
}

func (r *BaseScanResult) GetTimestamp() time.Time {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	return r.timestamp
}

// BaseFinding - базовая реализация Finding
type BaseFinding struct {
	id              string
	severity        Severity
	title           string
	description     string
	evidence        []Evidence
	recommendations []string
	mutex           sync.RWMutex
}

func NewBaseFinding(id, title, description string, severity Severity) *BaseFinding {
	return &BaseFinding{
		id:              id,
		severity:        severity,
		title:           title,
		description:     description,
		evidence:        make([]Evidence, 0),
		recommendations: make([]string, 0),
	}
}

func (f *BaseFinding) GetID() string {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return f.id
}

func (f *BaseFinding) GetSeverity() Severity {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return f.severity
}

func (f *BaseFinding) GetTitle() string {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return f.title
}

func (f *BaseFinding) GetDescription() string {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return f.description
}

func (f *BaseFinding) GetEvidence() []Evidence {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	result := make([]Evidence, len(f.evidence))
	copy(result, f.evidence)
	return result
}

func (f *BaseFinding) AddEvidence(evidence Evidence) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.evidence = append(f.evidence, evidence)
}

func (f *BaseFinding) GetRecommendations() []string {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	result := make([]string, len(f.recommendations))
	copy(result, f.recommendations)
	return result
}

func (f *BaseFinding) AddRecommendation(recommendation string) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.recommendations = append(f.recommendations, recommendation)
}

// BaseEvidence - базовая реализация Evidence
type BaseEvidence struct {
	evidenceType EvidenceType
	data         interface{}
	context      string
	mutex        sync.RWMutex
}

func NewBaseEvidence(evidenceType EvidenceType, data interface{}, context string) *BaseEvidence {
	return &BaseEvidence{
		evidenceType: evidenceType,
		data:         data,
		context:      context,
	}
}

func (e *BaseEvidence) GetType() EvidenceType {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.evidenceType
}

func (e *BaseEvidence) GetData() interface{} {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.data
}

func (e *BaseEvidence) GetContext() string {
	e.mutex.RLock()
	defer e.mutex.RUnlock()
	return e.context
}

// BaseConfig - базовая реализация Config
type BaseConfig struct {
	values map[string]interface{}
	mutex  sync.RWMutex
}

func NewBaseConfig() *BaseConfig {
	return &BaseConfig{
		values: make(map[string]interface{}),
	}
}

func (c *BaseConfig) Get(key string) interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.values[key]
}

func (c *BaseConfig) Set(key string, value interface{}) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.values[key] = value
	return nil
}

func (c *BaseConfig) Validate() error {
	// Basic validation - can be extended
	return nil
}

func (c *BaseConfig) GetAll() map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	result := make(map[string]interface{})
	for k, v := range c.values {
		result[k] = v
	}
	return result
}

// BaseField - базовая реализация Field для логирования
type BaseField struct {
	key   string
	value interface{}
}

func NewField(key string, value interface{}) *BaseField {
	return &BaseField{
		key:   key,
		value: value,
	}
}

func (f *BaseField) Key() string {
	return f.key
}

func (f *BaseField) Value() interface{} {
	return f.value
}

// Utility functions
func SeverityToString(severity Severity) string {
	switch severity {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func StringToSeverity(s string) Severity {
	switch s {
	case "INFO":
		return SeverityInfo
	case "LOW":
		return SeverityLow
	case "MEDIUM":
		return SeverityMedium
	case "HIGH":
		return SeverityHigh
	case "CRITICAL":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}