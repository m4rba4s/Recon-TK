package cmd

import (
	"github.com/spf13/cobra"
	"recon-toolkit/pkg/ui"
)

var interactiveCmd = &cobra.Command{
	Use:   "interactive",
	Short: "🎭 Launch interactive command center with skull art",
	Long: `🚀 INTERACTIVE ELITE COMMAND CENTER

Launch the advanced interactive terminal interface with:
• 💀 Badass skull ASCII art
• 🎯 Point-and-click target selection  
• 🎭 Visual attack mode configuration
• 🌈 RGB color schemes
• ⚡ Real-time option preview
• 🔥 Cynical status messages

Perfect for lazy pentesters who want maximum elite vibes!

Example:
  recon-toolkit interactive`,

	Run: func(cmd *cobra.Command, args []string) {
		ui := ui.NewInteractiveUI()
		ui.Run()
	},
}

func init() {
	rootCmd.AddCommand(interactiveCmd)
}