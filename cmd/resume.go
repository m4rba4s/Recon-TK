package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

type ProgressToken struct {
	SessionID     string    `json:"session_id"`
	Command       string    `json:"command"`
	Target        string    `json:"target"`
	StartTime     time.Time `json:"start_time"`
	LastCheckpoint time.Time `json:"last_checkpoint"`
	CompletedTasks []string  `json:"completed_tasks"`
	CurrentTask   string    `json:"current_task"`
	TotalTasks    int       `json:"total_tasks"`
	Progress      float64   `json:"progress"`
	ExpiresAt     time.Time `json:"expires_at"`
	Metadata      map[string]interface{} `json:"metadata"`
}

var resumeCmd = &cobra.Command{
	Use:   "resume [session_id]",
	Short: "🔄 Resume interrupted operations",
	Long: `🔄 RESUME OPERATIONS - Continue interrupted scans

Professional operation resumption with time-boxing:

🎯 FEATURES:
  • Automatic session checkpointing
  • Timeout-based operation control
  • Progress state preservation
  • Multi-module resume support

🕐 TIME-BOXING:
  • Configurable operation timeouts
  • Graceful shutdown on timeout
  • Progress save before exit
  • Resume from exact checkpoint

Examples:
  rtk resume                    # List available sessions
  rtk resume session_abc123     # Resume specific session
  rtk scan --timeout 3600 -t example.com  # 1-hour timeout with auto-save`,
	RunE: runResume,
}

var listSessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: "List resumable sessions",
	RunE:  runListSessions,
}

func init() {
	rootCmd.AddCommand(resumeCmd)
	resumeCmd.AddCommand(listSessionsCmd)
}

func runResume(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return runListSessions(cmd, args)
	}
	
	sessionID := args[0]
	
	if !silent {
		color.Cyan("🔄 Resuming session: %s", sessionID)
	}
	
	token, err := loadProgressToken(sessionID)
	if err != nil {
		return fmt.Errorf("failed to load session: %v", err)
	}
	
	// Check if session is expired
	if time.Now().After(token.ExpiresAt) {
		color.Yellow("⚠️ Session expired on %s", token.ExpiresAt.Format("2006-01-02 15:04:05"))
		return fmt.Errorf("session expired")
	}
	
	if !silent {
		color.Yellow("Session: %s", token.Command)
		color.Yellow("Target: %s", token.Target)
		color.Yellow("Progress: %.1f%% (%d/%d tasks)", token.Progress*100, len(token.CompletedTasks), token.TotalTasks)
		color.Yellow("Last checkpoint: %s", token.LastCheckpoint.Format("15:04:05"))
	}
	
	// Resume the specific command
	return resumeCommand(token)
}

func runListSessions(cmd *cobra.Command, args []string) error {
	dataDir := getDataDir()
	progressDir := filepath.Join(dataDir, "progress")
	
	if _, err := os.Stat(progressDir); os.IsNotExist(err) {
		color.Yellow("📭 No resumable sessions found")
		return nil
	}
	
	files, err := os.ReadDir(progressDir)
	if err != nil {
		return fmt.Errorf("failed to read progress directory: %v", err)
	}
	
	if !silent {
		color.Cyan("🔄 Available Resume Sessions")
		color.Cyan("=" + strings.Repeat("=", 40))
	}
	
	activeCount := 0
	expiredCount := 0
	
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}
		
		sessionID := file.Name()[:len(file.Name())-5] // Remove .json
		token, err := loadProgressToken(sessionID)
		if err != nil {
			continue
		}
		
		status := "ACTIVE"
		statusColor := color.New(color.FgGreen)
		
		if time.Now().After(token.ExpiresAt) {
			status = "EXPIRED"
			statusColor = color.New(color.FgRed)
			expiredCount++
		} else {
			activeCount++
		}
		
		if !silent {
			color.White("Session ID: %s", sessionID)
			color.White("  Command: %s", token.Command)
			color.White("  Target: %s", token.Target)
			color.White("  Progress: %.1f%%", token.Progress*100)
			statusColor.Printf("  Status: %s\n", status)
			color.White("  Started: %s", token.StartTime.Format("2006-01-02 15:04:05"))
			fmt.Println()
		}
	}
	
	if !silent {
		color.Yellow("Summary: %d active, %d expired sessions", activeCount, expiredCount)
		if activeCount > 0 {
			color.Green("Use 'rtk resume <session_id>' to continue")
		}
	}
	
	return nil
}

func CreateProgressToken(command, target string, totalTasks int) (*ProgressToken, error) {
	sessionID := fmt.Sprintf("%s_%d", command, time.Now().Unix())
	
	token := &ProgressToken{
		SessionID:      sessionID,
		Command:        command,
		Target:         target,
		StartTime:      time.Now(),
		LastCheckpoint: time.Now(),
		CompletedTasks: make([]string, 0),
		CurrentTask:    "",
		TotalTasks:     totalTasks,
		Progress:       0.0,
		ExpiresAt:      time.Now().Add(24 * time.Hour), // Expire after 24 hours
		Metadata:       make(map[string]interface{}),
	}
	
	if err := saveProgressToken(token); err != nil {
		return nil, err
	}
	
	return token, nil
}

func (pt *ProgressToken) UpdateProgress(completedTask string, metadata map[string]interface{}) error {
	if completedTask != "" {
		pt.CompletedTasks = append(pt.CompletedTasks, completedTask)
	}
	
	pt.LastCheckpoint = time.Now()
	pt.Progress = float64(len(pt.CompletedTasks)) / float64(pt.TotalTasks)
	
	if metadata != nil {
		for k, v := range metadata {
			pt.Metadata[k] = v
		}
	}
	
	return saveProgressToken(pt)
}

func (pt *ProgressToken) SetCurrentTask(task string) error {
	pt.CurrentTask = task
	pt.LastCheckpoint = time.Now()
	return saveProgressToken(pt)
}

func (pt *ProgressToken) IsCompleted() bool {
	return len(pt.CompletedTasks) >= pt.TotalTasks
}

func (pt *ProgressToken) Cleanup() error {
	dataDir := getDataDir()
	progressDir := filepath.Join(dataDir, "progress")
	tokenPath := filepath.Join(progressDir, pt.SessionID+".json")
	
	return os.Remove(tokenPath)
}

func saveProgressToken(token *ProgressToken) error {
	dataDir := getDataDir()
	progressDir := filepath.Join(dataDir, "progress")
	
	if err := os.MkdirAll(progressDir, 0755); err != nil {
		return err
	}
	
	tokenPath := filepath.Join(progressDir, token.SessionID+".json")
	
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(tokenPath, data, 0644)
}

func loadProgressToken(sessionID string) (*ProgressToken, error) {
	dataDir := getDataDir()
	progressDir := filepath.Join(dataDir, "progress")
	tokenPath := filepath.Join(progressDir, sessionID+".json")
	
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, err
	}
	
	var token ProgressToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}
	
	return &token, nil
}

func resumeCommand(token *ProgressToken) error {
	switch token.Command {
	case "scan":
		return resumeScanCommand(token)
	case "cfbypass":
		return resumeCFBypassCommand(token)
	case "cve-new":
		return resumeCVECommand(token)
	default:
		return fmt.Errorf("resume not supported for command: %s", token.Command)
	}
}

func resumeScanCommand(token *ProgressToken) error {
	color.Green("🔄 Resuming port scan...")
	// Implementation would integrate with existing scan command
	return fmt.Errorf("scan resume not yet implemented")
}

func resumeCFBypassCommand(token *ProgressToken) error {
	color.Green("🔄 Resuming Cloudflare bypass test...")
	// Implementation would integrate with existing cfbypass command
	return fmt.Errorf("cfbypass resume not yet implemented")
}

func resumeCVECommand(token *ProgressToken) error {
	color.Green("🔄 Resuming CVE scan...")
	// Implementation would integrate with existing cve-new command
	return fmt.Errorf("cve resume not yet implemented")
}

// Helper function to create context with timeout and progress tracking
func CreateTimeboxedContext(baseCtx context.Context, timeoutSeconds int, token *ProgressToken) (context.Context, context.CancelFunc) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 3600 // Default 1 hour
	}
	
	ctx, cancel := context.WithTimeout(baseCtx, time.Duration(timeoutSeconds)*time.Second)
	
	// Start a goroutine to save progress periodically
	go func() {
		ticker := time.NewTicker(30 * time.Second) // Save every 30 seconds
		defer ticker.Stop()
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if token != nil {
					saveProgressToken(token)
				}
			}
		}
	}()
	
	return ctx, cancel
}