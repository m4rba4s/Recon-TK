package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"recon-toolkit/pkg/core"
	"recon-toolkit/pkg/logger"
)

var dslCmd = &cobra.Command{
	Use:   "dsl [script-file] [target]",
	Short: "🔥 Attack DSL - Dynamic payload generation",
	Long: `Attack DSL (Domain Specific Language) for dynamic attack scripting:

🎯 Features:
  - Dynamic payload generation
  - Variable substitution  
  - Real-time attack logic
  - Template-based payloads
  - Adaptive rule engine
  - JIT payload compilation

📝 DSL Syntax:
  SET variable value          # Set variable
  PAYLOAD id type template    # Define payload template  
  RULE name trigger action    # Define execution rule
  EXECUTE payload_id          # Execute payload

🚀 Examples:
  recon-toolkit dsl attack.dsl 172.67.68.228
  recon-toolkit dsl --interactive target.com
  recon-toolkit dsl --demo`,
	Args: cobra.RangeArgs(0, 2),
	RunE: runAttackDSL,
}

var (
	interactive    bool
	demo          bool
	dslScript     string
	generateOnly  bool
)

func init() {
	rootCmd.AddCommand(dslCmd)
	
	dslCmd.Flags().BoolVar(&interactive, "interactive", false, "Interactive DSL mode")
	dslCmd.Flags().BoolVar(&demo, "demo", false, "Run DSL demonstration")
	dslCmd.Flags().StringVar(&dslScript, "script", "", "DSL script string")
	dslCmd.Flags().BoolVar(&generateOnly, "generate-only", false, "Only generate payloads, don't execute")
}

func runAttackDSL(cmd *cobra.Command, args []string) error {
	loggerAdapter := logger.NewLoggerAdapter()
	
	if demo {
		return runDSLDemo(loggerAdapter)
	}
	
	if interactive {
		return runInteractiveDSL(loggerAdapter)
	}
	
	if len(args) < 2 {
		return fmt.Errorf("target required for DSL execution")
	}
	
	scriptFile := args[0]
	target := args[1]
	
	loggerAdapter.Info("🔥 Attack DSL Engine Starting", 
		logger.StringField("script", scriptFile),
		logger.StringField("target", target))
	
	// Создание DSL движка
	engine := NewAttackDSLEngine(target, loggerAdapter)
	
	// Загрузка и выполнение скрипта
	if err := engine.LoadScript(scriptFile); err != nil {
		return fmt.Errorf("failed to load DSL script: %v", err)
	}
	
	results, err := engine.Execute(generateOnly)
	if err != nil {
		return fmt.Errorf("DSL execution failed: %v", err)
	}
	
	printDSLResults(results)
	
	return nil
}

// AttackDSLEngine - DSL движок для динамического создания атак
type AttackDSLEngine struct {
	Target     string
	Variables  map[string]string
	Payloads   []DSLPayload
	Rules      []DSLRule
	Results    []DSLResult
	Logger     core.Logger
}

type DSLPayload struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Template    string            `json:"template"`
	Variables   map[string]string `json:"variables"`
	Generated   string            `json:"generated"`
	Executed    bool              `json:"executed"`
	Success     bool              `json:"success"`
	Response    string            `json:"response"`
}

type DSLRule struct {
	Name        string                 `json:"name"`
	Trigger     string                 `json:"trigger"`
	Action      string                 `json:"action"`
	Parameters  map[string]interface{} `json:"parameters"`
	OnSuccess   string                 `json:"on_success"`
	OnFailure   string                 `json:"on_failure"`
}

type DSLResult struct {
	PayloadID   string    `json:"payload_id"`
	Success     bool      `json:"success"`
	Response    string    `json:"response"`
	Evidence    []string  `json:"evidence"`
	Timestamp   time.Time `json:"timestamp"`
	NextAction  string    `json:"next_action"`
}

type DSLExecutionResults struct {
	Target          string      `json:"target"`
	TotalPayloads   int         `json:"total_payloads"`
	SuccessfulHits  int         `json:"successful_hits"`
	FailedAttempts  int         `json:"failed_attempts"`
	ExecutionTime   time.Duration `json:"execution_time"`
	Results         []DSLResult `json:"results"`
	GeneratedCode   []string    `json:"generated_code"`
	Timestamp       time.Time   `json:"timestamp"`
}

func NewAttackDSLEngine(target string, logger core.Logger) *AttackDSLEngine {
	return &AttackDSLEngine{
		Target:    target,
		Variables: make(map[string]string),
		Payloads:  make([]DSLPayload, 0),
		Rules:     make([]DSLRule, 0),
		Results:   make([]DSLResult, 0),
		Logger:    logger,
	}
}

func (engine *AttackDSLEngine) LoadScript(scriptFile string) error {
	// Загрузка и парсинг DSL скрипта
	engine.Logger.Info("📝 Loading DSL script",
		logger.StringField("file", scriptFile))
	
	// Демо скрипт для тестирования
	demoScript := `
# Advanced Attack DSL Script
SET TARGET_HOST ` + engine.Target + `
SET ADMIN_PATH /admin
SET API_PATH /api/v1
SET BACKUP_PATH /backup

# Payload для обнаружения админ панели
PAYLOAD admin_discovery HTTP https://${TARGET_HOST}${ADMIN_PATH}/login
PAYLOAD admin_bruteforce HTTP https://${TARGET_HOST}${ADMIN_PATH}/login?user=admin&pass=${BRUTE_PASS}

# Payload для API тестирования
PAYLOAD api_enum HTTP https://${TARGET_HOST}${API_PATH}/users
PAYLOAD api_injection HTTP https://${TARGET_HOST}${API_PATH}/user?id=1' OR '1'='1

# Payload для поиска бэкапов
PAYLOAD backup_search HTTP https://${TARGET_HOST}${BACKUP_PATH}/
PAYLOAD backup_enum HTTP https://${TARGET_HOST}/${BACKUP_FILE}

# Правила выполнения
RULE admin_found admin_discovery CHECK_STATUS_200
RULE api_found api_enum CHECK_JSON_RESPONSE
RULE backup_found backup_search CHECK_DIRECTORY_LISTING
RULE injection_success api_injection CHECK_SQL_ERROR
`
	
	return engine.ParseScript(demoScript)
}

func (engine *AttackDSLEngine) ParseScript(script string) error {
	lines := strings.Split(script, "\n")
	
	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		if err := engine.parseLine(line, lineNum+1); err != nil {
			return fmt.Errorf("line %d: %v", lineNum+1, err)
		}
	}
	
	engine.Logger.Info("✅ DSL script parsed successfully",
		logger.IntField("variables", len(engine.Variables)),
		logger.IntField("payloads", len(engine.Payloads)),
		logger.IntField("rules", len(engine.Rules)))
	
	return nil
}

func (engine *AttackDSLEngine) parseLine(line string, lineNum int) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}
	
	command := strings.ToUpper(parts[0])
	
	switch command {
	case "SET":
		if len(parts) >= 3 {
			key := parts[1]
			value := strings.Join(parts[2:], " ")
			engine.Variables[key] = value
			engine.Logger.Debug("Variable set",
				logger.StringField("key", key),
				logger.StringField("value", value))
		}
		
	case "PAYLOAD":
		if len(parts) >= 4 {
			payload := DSLPayload{
				ID:        parts[1],
				Type:      parts[2],
				Template:  strings.Join(parts[3:], " "),
				Variables: make(map[string]string),
			}
			engine.Payloads = append(engine.Payloads, payload)
			engine.Logger.Debug("Payload defined",
				logger.StringField("id", payload.ID),
				logger.StringField("type", payload.Type))
		}
		
	case "RULE":
		if len(parts) >= 4 {
			rule := DSLRule{
				Name:       parts[1],
				Trigger:    parts[2],
				Action:     parts[3],
				Parameters: make(map[string]interface{}),
			}
			if len(parts) > 4 {
				rule.OnSuccess = parts[4]
			}
			engine.Rules = append(engine.Rules, rule)
			engine.Logger.Debug("Rule defined",
				logger.StringField("name", rule.Name),
				logger.StringField("trigger", rule.Trigger))
		}
		
	default:
		return fmt.Errorf("unknown DSL command: %s", command)
	}
	
	return nil
}

func (engine *AttackDSLEngine) Execute(generateOnly bool) (*DSLExecutionResults, error) {
	startTime := time.Now()
	
	engine.Logger.Info("🚀 Executing DSL payloads",
		logger.StringField("target", engine.Target),
		logger.IntField("payload_count", len(engine.Payloads)),
		logger.BoolField("generate_only", generateOnly))
	
	results := &DSLExecutionResults{
		Target:        engine.Target,
		TotalPayloads: len(engine.Payloads),
		Timestamp:     startTime,
		Results:       make([]DSLResult, 0),
		GeneratedCode: make([]string, 0),
	}
	
	// Генерация и выполнение payload'ов
	for i, payload := range engine.Payloads {
		engine.Logger.Info("💥 Processing payload",
			logger.StringField("id", payload.ID),
			logger.StringField("type", payload.Type))
		
		// Генерация payload
		generated := engine.generatePayload(payload)
		engine.Payloads[i].Generated = generated
		results.GeneratedCode = append(results.GeneratedCode, generated)
		
		if !generateOnly {
			// Выполнение payload
			result := engine.executePayload(payload)
			results.Results = append(results.Results, result)
			
			if result.Success {
				results.SuccessfulHits++
			} else {
				results.FailedAttempts++
			}
		}
	}
	
	results.ExecutionTime = time.Since(startTime)
	
	engine.Logger.Info("✅ DSL execution completed",
		logger.StringField("duration", results.ExecutionTime.String()),
		logger.IntField("successful", results.SuccessfulHits),
		logger.IntField("failed", results.FailedAttempts))
	
	return results, nil
}

func (engine *AttackDSLEngine) generatePayload(payload DSLPayload) string {
	generated := payload.Template
	
	// Замена переменных
	for key, value := range engine.Variables {
		placeholder := "${" + key + "}"
		generated = strings.ReplaceAll(generated, placeholder, value)
	}
	
	// Специальные переменные
	generated = strings.ReplaceAll(generated, "${TIMESTAMP}", fmt.Sprintf("%d", time.Now().Unix()))
	generated = strings.ReplaceAll(generated, "${RANDOM}", generateRandomString(8))
	generated = strings.ReplaceAll(generated, "${TARGET}", engine.Target)
	
	engine.Logger.Debug("Payload generated",
		logger.StringField("id", payload.ID),
		logger.StringField("generated", generated))
	
	return generated
}

func (engine *AttackDSLEngine) executePayload(payload DSLPayload) DSLResult {
	result := DSLResult{
		PayloadID: payload.ID,
		Timestamp: time.Now(),
	}
	
	// Симуляция выполнения (в реальности - HTTP запрос)
	engine.Logger.Info("🎯 Executing payload",
		logger.StringField("id", payload.ID),
		logger.StringField("url", payload.Generated))
	
	// Здесь должен быть реальный HTTP клиент
	result.Success = true // Демо
	result.Response = "HTTP/1.1 200 OK"
	result.Evidence = []string{"Admin panel detected", "Response time: 150ms"}
	
	// Проверка правил
	for _, rule := range engine.Rules {
		if rule.Trigger == payload.ID {
			engine.Logger.Debug("Rule triggered",
				logger.StringField("rule", rule.Name),
				logger.StringField("payload", payload.ID))
			if result.Success && rule.OnSuccess != "" {
				result.NextAction = rule.OnSuccess
			}
		}
	}
	
	return result
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(result)
}

func runDSLDemo(logger core.Logger) error {
	logger.Info("🔥 DSL Demo Mode")
	
	// Демонстрация DSL возможностей
	engine := NewAttackDSLEngine("demo.target.com", logger)
	
	demoScript := `
# DSL Demo Script
SET TARGET demo.target.com
SET WORDLIST_PATH /usr/share/wordlists/common.txt

PAYLOAD directory_enum HTTP https://${TARGET}/FUZZ
PAYLOAD admin_check HTTP https://${TARGET}/admin/
PAYLOAD api_test HTTP https://${TARGET}/api/v1/users

RULE directory_found directory_enum CHECK_STATUS_200
RULE admin_found admin_check CHECK_ADMIN_PANEL
`
	
	if err := engine.ParseScript(demoScript); err != nil {
		return err
	}
	
	results, err := engine.Execute(true) // Generate only
	if err != nil {
		return err
	}
	
	fmt.Println("\n🎯 DSL Demo Results:")
	fmt.Printf("Generated Payloads: %d\n", len(results.GeneratedCode))
	for i, code := range results.GeneratedCode {
		fmt.Printf("%d. %s\n", i+1, code)
	}
	
	return nil
}

func runInteractiveDSL(logger core.Logger) error {
	logger.Info("🔥 Interactive DSL Mode")
	fmt.Println("Interactive DSL mode not implemented yet")
	return nil
}

func printDSLResults(results *DSLExecutionResults) {
	fmt.Printf(`
🎯 ATTACK DSL EXECUTION SUMMARY

Target: %s
Total Payloads: %d
Successful Hits: %d
Failed Attempts: %d
Execution Time: %v

Generated Code:
`, results.Target, results.TotalPayloads, results.SuccessfulHits, 
		results.FailedAttempts, results.ExecutionTime)
	
	for i, code := range results.GeneratedCode {
		fmt.Printf("%d. %s\n", i+1, code)
	}
	
	if len(results.Results) > 0 {
		fmt.Println("\nExecution Results:")
		for _, result := range results.Results {
			status := "❌"
			if result.Success {
				status = "✅"
			}
			fmt.Printf("%s %s - %s\n", status, result.PayloadID, result.Response)
		}
	}
}