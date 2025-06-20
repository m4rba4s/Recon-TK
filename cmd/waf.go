
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"recon-toolkit/pkg/waf"
)

var (
	testBypass bool
)

var wafCmd = &cobra.Command{
	Use:   "waf",
	Short: "Advanced WAF detection and bypass testing",
	Long: `Advanced Web Application Firewall detection with bypass techniques.

Features:
  • Multi-signature WAF detection
  • Confidence scoring for detection accuracy
  • Common WAF fingerprinting (CloudFlare, Akamai, AWS WAF, etc.)
  • Bypass technique testing and validation
  • Response analysis for evasion validation

Examples:
  recon-toolkit waf -t https://example.com
  recon-toolkit waf -t https://target.com --bypass
  recon-toolkit waf -t https://site.com --timeout 10 -o waf_results.json`,

	RunE: func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target URL is required")
		}

		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}

		if !silent {
			color.Yellow("🎯 Target: %s", target)
			color.Yellow("⏱️  Timeout: %d seconds", timeout)
			if testBypass {
				color.Yellow("🔓 Bypass testing: enabled")
			}
		}

		detectorOptions := []func(*waf.Detector){}

		if silent {
			detectorOptions = append(detectorOptions, waf.WithSilent())
		}

		if testBypass {
			detectorOptions = append(detectorOptions, waf.WithBypassTesting())
		}

		detectorOptions = append(detectorOptions, waf.WithTimeout(time.Duration(timeout) * time.Second))

		detector := waf.NewDetector(target, detectorOptions...)

		ctx := context.Background()
		result, err := detector.Detect(ctx)
		if err != nil {
			return fmt.Errorf("WAF detection failed: %w", err)
		}

		if outputFile != "" {
			return saveWAFResults(result, outputFile)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(wafCmd)

	wafCmd.Flags().BoolVar(&testBypass, "bypass", false, "Test WAF bypass techniques")
}

func saveWAFResults(result *waf.WAFResult, filename string) error {
	var err error

	if strings.HasSuffix(filename, ".json") {
		err = saveWAFResultsJSON(result, filename)
	} else {
		err = saveWAFResultsJSON(result, filename)
	}

	if err != nil {
		return fmt.Errorf("failed to save WAF results: %w", err)
	}

	if !silent {
		color.Green("💾 Results saved to %s", filename)
	}

	return nil
}

func saveWAFResultsJSON(result *waf.WAFResult, filename string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return os.WriteFile(filename, data, 0644)
}