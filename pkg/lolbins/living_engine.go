package lolbins

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"recon-toolkit/pkg/core"
)

type LivingEngine struct {
	config     *LolBinsConfig
	logger     core.Logger
	techniques []LolBinTechnique
	binaries   map[string]*LolBinary
	chains     []AttackChain
	mutex      sync.RWMutex
}

type LolBinsConfig struct {
	TargetOS           string        `json:"target_os"`
	TechniqueTypes     []string      `json:"technique_types"`
	ExecutionTimeout   time.Duration `json:"execution_timeout"`
	StealthMode        bool          `json:"stealth_mode"`
	ChainExecution     bool          `json:"chain_execution"`
	AntiDetection      bool          `json:"anti_detection"`
	MaxConcurrency     int           `json:"max_concurrency"`
	OutputObfuscation  bool          `json:"output_obfuscation"`
}

type LolBinary struct {
	Name            string                 `json:"name"`
	Path            string                 `json:"path"`
	Description     string                 `json:"description"`
	OS              []string               `json:"os"`
	Techniques      []TechniqueType        `json:"techniques"`
	Commands        []Command              `json:"commands"`
	DetectionRisk   DetectionLevel         `json:"detection_risk"`
	Privileges      PrivilegeLevel         `json:"privileges"`
	Dependencies    []string               `json:"dependencies"`
	AlternativeNames []string              `json:"alternative_names"`
	Metadata        map[string]interface{} `json:"metadata"`
}

type LolBinTechnique struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Type            TechniqueType  `json:"type"`
	Description     string         `json:"description"`
	MITRE_ID        string         `json:"mitre_id"`
	Binary          *LolBinary     `json:"binary"`
	Command         Command        `json:"command"`
	DetectionRisk   DetectionLevel `json:"detection_risk"`
	Success         bool           `json:"success"`
	Output          string         `json:"output"`
	Evidence        []core.Evidence `json:"evidence"`
}

type Command struct {
	Template    string            `json:"template"`
	Parameters  map[string]string `json:"parameters"`
	Description string            `json:"description"`
	Obfuscated  string            `json:"obfuscated"`
	FileLess    bool              `json:"file_less"`
}

type AttackChain struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Techniques  []LolBinTechnique `json:"techniques"`
	Success     bool             `json:"success"`
	Timeline    []ChainStep      `json:"timeline"`
}

type ChainStep struct {
	TechniqueID string    `json:"technique_id"`
	Timestamp   time.Time `json:"timestamp"`
	Success     bool      `json:"success"`
	Output      string    `json:"output"`
}

// Enums
type TechniqueType int
type DetectionLevel int
type PrivilegeLevel int

const (
	// Technique Types (MITRE ATT&CK)
	TechniqueFileDownload TechniqueType = iota
	TechniqueFileUpload
	TechniqueCommandExecution
	TechniqueDataExfiltration
	TechniqueReconnaissance
	TechniquePersistence
	TechniquePrivilegeEscalation
	TechniqueDefenseEvasion
	TechniqueLateralMovement
	TechniqueCredentialAccess
	TechniqueCodeExecution
	TechniqueProcessInjection
)

const (
	// Detection Levels
	DetectionVeryLow DetectionLevel = iota
	DetectionLow
	DetectionMedium
	DetectionHigh
	DetectionCritical
)

const (
	// Privilege Levels
	PrivilegeUser PrivilegeLevel = iota
	PrivilegeAdmin
	PrivilegeSystem
	PrivilegeKernel
)

// NewLivingEngine creates Living-off-the-Land attack engine
func NewLivingEngine(logger core.Logger, config *LolBinsConfig) *LivingEngine {
	if config == nil {
		config = &LolBinsConfig{
			TargetOS:          runtime.GOOS,
			TechniqueTypes:    []string{"file_download", "command_execution", "reconnaissance"},
			ExecutionTimeout:  30 * time.Second,
			StealthMode:       true,
			ChainExecution:    true,
			AntiDetection:     true,
			MaxConcurrency:    10,
			OutputObfuscation: true,
		}
	}

	engine := &LivingEngine{
		config:     config,
		logger:     logger,
		techniques: make([]LolBinTechnique, 0),
		binaries:   make(map[string]*LolBinary),
		chains:     make([]AttackChain, 0),
	}

	// Initialize binary database
	engine.initializeBinaryDatabase()
	engine.loadAttackChains()

	return engine
}

// ExecuteLivingOffTheLand performs living-off-the-land attacks
func (e *LivingEngine) ExecuteLivingOffTheLand(ctx context.Context, target core.Target) (*LivingResult, error) {
	e.logger.Info("🥷 INITIATING LIVING-OFF-THE-LAND ATTACKS", core.NewField("target", target.GetAddress()))

	result := &LivingResult{
		BaseScanResult:     core.NewBaseScanResult(target),
		ExecutedTechniques: make([]LolBinTechnique, 0),
		SuccessfulChains:   make([]AttackChain, 0),
		AvailableBinaries:  make([]*LolBinary, 0),
		DetectionRisk:      DetectionVeryLow,
	}

	// Phase 1: Binary Discovery and Enumeration
	availableBinaries := e.discoverAvailableBinaries(ctx)
	result.AvailableBinaries = availableBinaries

	// Phase 2: Technique Execution
	if len(availableBinaries) > 0 {
		techniques := e.executeTechniques(ctx, availableBinaries)
		result.ExecutedTechniques = techniques
	}

	// Phase 3: Attack Chain Execution
	if e.config.ChainExecution {
		chains := e.executeAttackChains(ctx, result.ExecutedTechniques)
		result.SuccessfulChains = chains
	}

	// Phase 4: Risk Assessment
	result.DetectionRisk = e.calculateDetectionRisk(result)

	e.logger.Info("🥷 Living-off-the-Land attacks completed", 
		core.NewField("techniques_executed", len(result.ExecutedTechniques)),
		core.NewField("successful_chains", len(result.SuccessfulChains)),
		core.NewField("detection_risk", result.DetectionRisk))

	return result, nil
}

// discoverAvailableBinaries finds available LOLBins on the system
func (e *LivingEngine) discoverAvailableBinaries(ctx context.Context) []*LolBinary {
	e.logger.Debug("🔍 Discovering available LOLBins")
	
	availableBinaries := make([]*LolBinary, 0)
	
	for name, binary := range e.binaries {
		// Check if binary supports current OS
		osSupported := false
		for _, supportedOS := range binary.OS {
			if supportedOS == e.config.TargetOS || supportedOS == "all" {
				osSupported = true
				break
			}
		}
		
		if !osSupported {
			continue
		}

		// Check if binary exists on system
		if e.binaryExists(binary.Path) {
			e.logger.Debug("Found LOLBin", core.NewField("binary", name), core.NewField("path", binary.Path))
			availableBinaries = append(availableBinaries, binary)
		} else {
			// Try alternative paths
			for _, altName := range binary.AlternativeNames {
				if e.binaryExists(altName) {
					binary.Path = altName
					availableBinaries = append(availableBinaries, binary)
					break
				}
			}
		}
	}
	
	e.logger.Info("Binary discovery completed", core.NewField("found", len(availableBinaries)))
	return availableBinaries
}

// executeTechniques executes LOLBin techniques
func (e *LivingEngine) executeTechniques(ctx context.Context, binaries []*LolBinary) []LolBinTechnique {
	e.logger.Debug("💀 Executing LOLBin techniques")
	
	executedTechniques := make([]LolBinTechnique, 0)
	var wg sync.WaitGroup
	var mutex sync.Mutex
	
	// Limit concurrency
	semaphore := make(chan struct{}, e.config.MaxConcurrency)
	
	for _, binary := range binaries {
		for _, techniqueType := range binary.Techniques {
			// Check if technique type is requested
			if !e.isTechniqueTypeRequested(techniqueType) {
				continue
			}
			
			wg.Add(1)
			go func(bin *LolBinary, techType TechniqueType) {
				defer wg.Done()
				semaphore <- struct{}{}
				defer func() { <-semaphore }()
				
				technique := e.executeTechnique(ctx, bin, techType)
				if technique != nil {
					mutex.Lock()
					executedTechniques = append(executedTechniques, *technique)
					mutex.Unlock()
				}
			}(binary, techniqueType)
		}
	}
	
	wg.Wait()
	return executedTechniques
}

// executeTechnique executes a specific LOLBin technique
func (e *LivingEngine) executeTechnique(ctx context.Context, binary *LolBinary, techType TechniqueType) *LolBinTechnique {
	technique := &LolBinTechnique{
		ID:            fmt.Sprintf("%s-%s", binary.Name, e.techniqueTypeToString(techType)),
		Name:          fmt.Sprintf("%s %s", binary.Name, e.techniqueTypeToString(techType)),
		Type:          techType,
		Description:   fmt.Sprintf("Using %s for %s", binary.Name, e.techniqueTypeToString(techType)),
		Binary:        binary,
		DetectionRisk: binary.DetectionRisk,
		Success:       false,
		Evidence:      make([]core.Evidence, 0),
	}

	// Get appropriate command for technique
	command := e.getCommandForTechnique(binary, techType)
	if command == nil {
		return nil
	}
	
	technique.Command = *command

	// Execute command
	success, output, err := e.executeCommand(ctx, command)
	technique.Success = success
	technique.Output = output
	
	if err != nil {
		e.logger.Warn("Technique execution failed", 
			core.NewField("technique", technique.ID),
			core.NewField("error", err.Error()))
		return technique
	}

	if success {
		e.logger.Info("✅ Technique executed successfully", 
			core.NewField("technique", technique.ID),
			core.NewField("binary", binary.Name))
		
		// Create evidence
		evidence := core.NewBaseEvidence(
			core.EvidenceTypeLog,
			map[string]interface{}{
				"binary":      binary.Name,
				"technique":   e.techniqueTypeToString(techType),
				"command":     command.Template,
				"output":      output,
				"file_less":   command.FileLess,
			},
			fmt.Sprintf("Successfully executed %s using %s", e.techniqueTypeToString(techType), binary.Name),
		)
		technique.Evidence = append(technique.Evidence, evidence)
	}

	return technique
}

// executeAttackChains executes predefined attack chains
func (e *LivingEngine) executeAttackChains(ctx context.Context, availableTechniques []LolBinTechnique) []AttackChain {
	e.logger.Debug("⛓️ Executing attack chains")
	
	successfulChains := make([]AttackChain, 0)
	
	for _, chain := range e.chains {
		e.logger.Debug("Executing attack chain", core.NewField("chain", chain.Name))
		
		chainResult := e.executeAttackChain(ctx, &chain, availableTechniques)
		if chainResult.Success {
			successfulChains = append(successfulChains, chainResult)
			e.logger.Info("✅ Attack chain completed", core.NewField("chain", chain.Name))
		}
	}
	
	return successfulChains
}

// executeAttackChain executes a specific attack chain
func (e *LivingEngine) executeAttackChain(ctx context.Context, chain *AttackChain, availableTechniques []LolBinTechnique) AttackChain {
	chainResult := AttackChain{
		ID:          chain.ID,
		Name:        chain.Name,
		Description: chain.Description,
		Techniques:  make([]LolBinTechnique, 0),
		Success:     true,
		Timeline:    make([]ChainStep, 0),
	}
	
	for _, requiredTechnique := range chain.Techniques {
		// Find matching available technique
		found := false
		for _, availableTech := range availableTechniques {
			if availableTech.Type == requiredTechnique.Type && availableTech.Success {
				chainResult.Techniques = append(chainResult.Techniques, availableTech)
				
				step := ChainStep{
					TechniqueID: availableTech.ID,
					Timestamp:   time.Now(),
					Success:     true,
					Output:      availableTech.Output,
				}
				chainResult.Timeline = append(chainResult.Timeline, step)
				found = true
				break
			}
		}
		
		if !found {
			chainResult.Success = false
			step := ChainStep{
				TechniqueID: requiredTechnique.ID,
				Timestamp:   time.Now(),
				Success:     false,
				Output:      "Technique not available or failed",
			}
			chainResult.Timeline = append(chainResult.Timeline, step)
		}
	}
	
	return chainResult
}

// Helper methods
func (e *LivingEngine) binaryExists(path string) bool {
	if strings.Contains(path, "/") || strings.Contains(path, "\\") {
		// Absolute or relative path
		_, err := os.Stat(path)
		return err == nil
	} else {
		// Check in PATH
		_, err := exec.LookPath(path)
		return err == nil
	}
}

func (e *LivingEngine) executeCommand(ctx context.Context, command *Command) (bool, string, error) {
	if e.config.StealthMode && e.config.AntiDetection {
		// Add random delay to avoid pattern detection
		time.Sleep(time.Duration(500+time.Now().UnixNano()%1500) * time.Millisecond)
	}

	// Use obfuscated command if available and obfuscation is enabled
	cmdStr := command.Template
	if e.config.OutputObfuscation && command.Obfuscated != "" {
		cmdStr = command.Obfuscated
	}

	// Replace parameters
	for key, value := range command.Parameters {
		cmdStr = strings.ReplaceAll(cmdStr, "{"+key+"}", value)
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", cmdStr)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", cmdStr)
	}

	// Set timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, e.config.ExecutionTimeout)
	defer cancel()
	cmd = exec.CommandContext(timeoutCtx, cmd.Args[0], cmd.Args[1:]...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, string(output), err
	}

	return true, string(output), nil
}

func (e *LivingEngine) getCommandForTechnique(binary *LolBinary, techType TechniqueType) *Command {
	// This would normally lookup technique-specific commands
	// For now, return the first available command
	if len(binary.Commands) > 0 {
		return &binary.Commands[0]
	}
	return nil
}

func (e *LivingEngine) isTechniqueTypeRequested(techType TechniqueType) bool {
	techStr := e.techniqueTypeToString(techType)
	for _, requestedType := range e.config.TechniqueTypes {
		if requestedType == techStr || requestedType == "all" {
			return true
		}
	}
	return false
}

func (e *LivingEngine) techniqueTypeToString(techType TechniqueType) string {
	switch techType {
	case TechniqueFileDownload:
		return "file_download"
	case TechniqueFileUpload:
		return "file_upload"
	case TechniqueCommandExecution:
		return "command_execution"
	case TechniqueDataExfiltration:
		return "data_exfiltration"
	case TechniqueReconnaissance:
		return "reconnaissance"
	case TechniquePersistence:
		return "persistence"
	case TechniquePrivilegeEscalation:
		return "privilege_escalation"
	case TechniqueDefenseEvasion:
		return "defense_evasion"
	case TechniqueLateralMovement:
		return "lateral_movement"
	case TechniqueCredentialAccess:
		return "credential_access"
	case TechniqueCodeExecution:
		return "code_execution"
	case TechniqueProcessInjection:
		return "process_injection"
	default:
		return "unknown"
	}
}

func (e *LivingEngine) calculateDetectionRisk(result *LivingResult) DetectionLevel {
	totalRisk := 0
	techniqueCount := len(result.ExecutedTechniques)
	
	if techniqueCount == 0 {
		return DetectionVeryLow
	}
	
	for _, technique := range result.ExecutedTechniques {
		totalRisk += int(technique.DetectionRisk)
	}
	
	avgRisk := totalRisk / techniqueCount
	
	// Adjust for stealth mode
	if e.config.StealthMode {
		avgRisk = avgRisk / 2
	}
	
	if avgRisk >= 4 {
		return DetectionCritical
	} else if avgRisk >= 3 {
		return DetectionHigh
	} else if avgRisk >= 2 {
		return DetectionMedium
	} else if avgRisk >= 1 {
		return DetectionLow
	}
	
	return DetectionVeryLow
}

// initializeBinaryDatabase initializes the LOLBins database
func (e *LivingEngine) initializeBinaryDatabase() {
	// Windows LOLBins
	e.binaries["powershell"] = &LolBinary{
		Name:        "PowerShell",
		Path:        "powershell.exe",
		Description: "Windows PowerShell command-line shell",
		OS:          []string{"windows"},
		Techniques:  []TechniqueType{TechniqueFileDownload, TechniqueCommandExecution, TechniqueDataExfiltration},
		Commands: []Command{
			{
				Template:    "powershell.exe -Command \"Invoke-WebRequest -Uri '{url}' -OutFile '{output}'\"",
				Parameters:  map[string]string{"url": "http://example.com/file.txt", "output": "downloaded.txt"},
				Description: "Download file using PowerShell",
				Obfuscated:  "powershell.exe -e <base64_encoded_command>",
				FileLess:    true,
			},
		},
		DetectionRisk: DetectionMedium,
		Privileges:    PrivilegeUser,
		AlternativeNames: []string{"pwsh.exe", "powershell_ise.exe"},
	}

	e.binaries["certutil"] = &LolBinary{
		Name:        "CertUtil",
		Path:        "certutil.exe",
		Description: "Certificate utility for downloading files",
		OS:          []string{"windows"},
		Techniques:  []TechniqueType{TechniqueFileDownload, TechniqueDataExfiltration},
		Commands: []Command{
			{
				Template:    "certutil.exe -urlcache -split -f \"{url}\" \"{output}\"",
				Parameters:  map[string]string{"url": "http://example.com/file.txt", "output": "downloaded.txt"},
				Description: "Download file using CertUtil",
				FileLess:    false,
			},
		},
		DetectionRisk: DetectionLow,
		Privileges:    PrivilegeUser,
	}

	e.binaries["bitsadmin"] = &LolBinary{
		Name:        "BitsAdmin",
		Path:        "bitsadmin.exe",
		Description: "Background Intelligent Transfer Service administration utility",
		OS:          []string{"windows"},
		Techniques:  []TechniqueType{TechniqueFileDownload, TechniqueDataExfiltration},
		Commands: []Command{
			{
				Template:    "bitsadmin /transfer myDownloadJob /download /priority normal \"{url}\" \"{output}\"",
				Parameters:  map[string]string{"url": "http://example.com/file.txt", "output": "C:\\temp\\downloaded.txt"},
				Description: "Download file using BitsAdmin",
				FileLess:    false,
			},
		},
		DetectionRisk: DetectionLow,
		Privileges:    PrivilegeUser,
	}

	// Linux LOLBins
	e.binaries["curl"] = &LolBinary{
		Name:        "cURL",
		Path:        "/usr/bin/curl",
		Description: "Command line tool for transferring data",
		OS:          []string{"linux", "darwin"},
		Techniques:  []TechniqueType{TechniqueFileDownload, TechniqueDataExfiltration, TechniqueReconnaissance},
		Commands: []Command{
			{
				Template:    "curl -s -o \"{output}\" \"{url}\"",
				Parameters:  map[string]string{"url": "http://example.com/file.txt", "output": "downloaded.txt"},
				Description: "Download file using cURL",
				FileLess:    false,
			},
		},
		DetectionRisk: DetectionVeryLow,
		Privileges:    PrivilegeUser,
		AlternativeNames: []string{"curl", "/bin/curl"},
	}

	e.binaries["wget"] = &LolBinary{
		Name:        "Wget",
		Path:        "/usr/bin/wget",
		Description: "Network downloader",
		OS:          []string{"linux"},
		Techniques:  []TechniqueType{TechniqueFileDownload, TechniqueDataExfiltration},
		Commands: []Command{
			{
				Template:    "wget -q -O \"{output}\" \"{url}\"",
				Parameters:  map[string]string{"url": "http://example.com/file.txt", "output": "downloaded.txt"},
				Description: "Download file using Wget",
				FileLess:    false,
			},
		},
		DetectionRisk: DetectionVeryLow,
		Privileges:    PrivilegeUser,
		AlternativeNames: []string{"wget", "/bin/wget"},
	}

	e.binaries["bash"] = &LolBinary{
		Name:        "Bash",
		Path:        "/bin/bash",
		Description: "Bourne Again SHell",
		OS:          []string{"linux", "darwin"},
		Techniques:  []TechniqueType{TechniqueCommandExecution, TechniqueReconnaissance, TechniqueDataExfiltration},
		Commands: []Command{
			{
				Template:    "bash -c \"{command}\"",
				Parameters:  map[string]string{"command": "whoami"},
				Description: "Execute command using Bash",
				FileLess:    true,
			},
		},
		DetectionRisk: DetectionVeryLow,
		Privileges:    PrivilegeUser,
		AlternativeNames: []string{"bash", "/usr/bin/bash", "sh"},
	}
}

// loadAttackChains loads predefined attack chains
func (e *LivingEngine) loadAttackChains() {
	// Data Exfiltration Chain
	dataExfilChain := AttackChain{
		ID:          "chain-data-exfil",
		Name:        "Data Exfiltration Chain",
		Description: "Multi-stage data exfiltration using native binaries",
		Techniques: []LolBinTechnique{
			{Type: TechniqueReconnaissance},
			{Type: TechniqueDataExfiltration},
			{Type: TechniqueFileUpload},
		},
	}
	e.chains = append(e.chains, dataExfilChain)

	// Persistence Chain
	persistenceChain := AttackChain{
		ID:          "chain-persistence",
		Name:        "Persistence Establishment Chain",
		Description: "Establish persistence using legitimate tools",
		Techniques: []LolBinTechnique{
			{Type: TechniqueFileDownload},
			{Type: TechniquePersistence},
			{Type: TechniqueDefenseEvasion},
		},
	}
	e.chains = append(e.chains, persistenceChain)
}

// Result types
type LivingResult struct {
	*core.BaseScanResult
	ExecutedTechniques []LolBinTechnique `json:"executed_techniques"`
	SuccessfulChains   []AttackChain     `json:"successful_chains"`
	AvailableBinaries  []*LolBinary      `json:"available_binaries"`
	DetectionRisk      DetectionLevel    `json:"detection_risk"`
	TotalTechniques    int               `json:"total_techniques"`
	SuccessRate        float64           `json:"success_rate"`
}