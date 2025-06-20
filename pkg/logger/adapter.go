package logger

import (
	"recon-toolkit/pkg/core"
)

// LoggerAdapter - адаптер для интеграции с core.Logger интерфейсом
type LoggerAdapter struct {
	cynical *CynicalLogger
}

// Field implementation for core.Logger compatibility
type LogField struct {
	key   string
	value interface{}
}

func (f LogField) Key() string {
	return f.key
}

func (f LogField) Value() interface{} {
	return f.value
}

// NewLoggerAdapter создает адаптер для существующего логгера
func NewLoggerAdapter() core.Logger {
	cynical := NewCynicalLogger("MASTER", LevelChill)
	return &LoggerAdapter{
		cynical: cynical,
	}
}

// Debug implements core.Logger
func (a *LoggerAdapter) Debug(msg string, fields ...core.Field) {
	fieldMap := make(map[string]interface{})
	for _, field := range fields {
		fieldMap[field.Key()] = field.Value()
	}
	a.cynical.Debug(msg, fieldMap)
}

// Info implements core.Logger  
func (a *LoggerAdapter) Info(msg string, fields ...core.Field) {
	fieldMap := make(map[string]interface{})
	for _, field := range fields {
		fieldMap[field.Key()] = field.Value()
	}
	a.cynical.Info(msg, fieldMap)
}

// Warn implements core.Logger
func (a *LoggerAdapter) Warn(msg string, fields ...core.Field) {
	fieldMap := make(map[string]interface{})
	for _, field := range fields {
		fieldMap[field.Key()] = field.Value()
	}
	a.cynical.Warn(msg, fieldMap)
}

// Error implements core.Logger
func (a *LoggerAdapter) Error(msg string, fields ...core.Field) {
	fieldMap := make(map[string]interface{})
	for _, field := range fields {
		fieldMap[field.Key()] = field.Value()
	}
	a.cynical.Error(msg, fieldMap)
}

// Fatal implements core.Logger
func (a *LoggerAdapter) Fatal(msg string, fields ...core.Field) {
	fieldMap := make(map[string]interface{})
	for _, field := range fields {
		fieldMap[field.Key()] = field.Value()
	}
	a.cynical.Error(msg, fieldMap) // CynicalLogger не имеет Fatal, используем Error
}

// Success - дополнительный метод для успешных операций
func (a *LoggerAdapter) Success(msg string, fields ...core.Field) {
	fieldMap := make(map[string]interface{})
	for _, field := range fields {
		fieldMap[field.Key()] = field.Value()
	}
	a.cynical.Info(msg, fieldMap) // Используем Info вместо несуществующего Success
}

// Helper functions для создания полей
func StringField(key, value string) core.Field {
	return LogField{key: key, value: value}
}

func IntField(key string, value int) core.Field {
	return LogField{key: key, value: value}
}

func BoolField(key string, value bool) core.Field {
	return LogField{key: key, value: value}
}

func FloatField(key string, value float64) core.Field {
	return LogField{key: key, value: value}
}

func AnyField(key string, value interface{}) core.Field {
	return LogField{key: key, value: value}
}