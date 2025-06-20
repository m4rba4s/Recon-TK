
package cmd

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"recon-toolkit/pkg/dns"
)

var (
	wordlistFiles   []string
	resolvers       []string
	permutations    bool
	recursive       bool
	zoneTransfer    bool
	filterWildcards bool
)

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Advanced DNS subdomain enumeration",
	Long: `High-performance DNS subdomain enumeration with multiple discovery techniques.

Features:
  • Multi-threaded DNS resolution
  • Wildcard detection and filtering
  • Custom wordlist support
  • Subdomain permutation attacks
  • Zone transfer detection
  • Recursive subdomain discovery

Examples:
  recon-toolkit dns -t example.com
  recon-toolkit dns -t example.com -w subdomains.txt
  recon-toolkit dns -t example.com --permutations --recursive
  recon-toolkit dns -t example.com --resolvers 8.8.8.8,1.1.1.1`,
	
	RunE: func(cmd *cobra.Command, args []string) error {
		if target == "" {
			return fmt.Errorf("target domain is required")
		}

		if !silent {
			color.Yellow("🎯 Target: %s", target)
			color.Yellow("🧵 Threads: %d", threads)
		}

		var resolverList []string
		if len(resolvers) > 0 {
			for _, resolver := range resolvers {
				parts := strings.Split(resolver, ",")
				for _, part := range parts {
					part = strings.TrimSpace(part)
					if !strings.Contains(part, ":") {
						part += ":53"
					}
					resolverList = append(resolverList, part)
				}
			}
		}

		enumOptions := []func(*dns.Enumerator){}

		if len(wordlistFiles) > 0 {
			enumOptions = append(enumOptions, dns.WithWordlists(wordlistFiles))
		}

		if len(resolverList) > 0 {
			enumOptions = append(enumOptions, dns.WithResolvers(resolverList))
		}

		if permutations {
			enumOptions = append(enumOptions, dns.WithPermutations())
		}

		if recursive {
			enumOptions = append(enumOptions, dns.WithRecursive())
		}

		if silent {
			enumOptions = append(enumOptions, dns.WithSilent())
		}

		enumerator := dns.NewEnumerator(target, enumOptions...)

		ctx := context.Background()
		result, err := enumerator.Enumerate(ctx)
		if err != nil {
			return fmt.Errorf("enumeration failed: %w", err)
		}

		if outputFile != "" {
			return saveDNSResults(result, outputFile)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(dnsCmd)

	dnsCmd.Flags().StringSliceVarP(&wordlistFiles, "wordlist", "w", []string{}, "Wordlist files for subdomain bruteforce")
	dnsCmd.Flags().StringSliceVar(&resolvers, "resolvers", []string{}, "Custom DNS resolvers (comma-separated)")
	dnsCmd.Flags().BoolVar(&permutations, "permutations", false, "Generate subdomain permutations")
	dnsCmd.Flags().BoolVar(&recursive, "recursive", false, "Recursive subdomain discovery")
	dnsCmd.Flags().BoolVar(&zoneTransfer, "zone-transfer", true, "Attempt zone transfer")
	dnsCmd.Flags().BoolVar(&filterWildcards, "filter-wildcards", true, "Filter wildcard responses")
}

func saveDNSResults(result *dns.EnumResult, filename string) error {
	var err error

	if strings.HasSuffix(filename, ".json") {
		err = saveDNSResultsJSON(result, filename)
	} else if strings.HasSuffix(filename, ".csv") {
		err = saveDNSResultsCSV(result, filename)
	} else if strings.HasSuffix(filename, ".txt") {
		err = saveDNSResultsTXT(result, filename)
	} else {
		err = saveDNSResultsJSON(result, filename)
	}

	if err != nil {
		return fmt.Errorf("failed to save DNS results: %w", err)
	}

	if !silent {
		color.Green("💾 Results saved to %s", filename)
	}

	return nil
}

func saveDNSResultsJSON(result *dns.EnumResult, filename string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return os.WriteFile(filename, data, 0644)
}

func saveDNSResultsCSV(result *dns.EnumResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"Subdomain", "Type", "IPs", "CNAME", "TTL", "Source", "Wildcard"}); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	for _, sub := range result.Subdomains {
		record := []string{
			sub.Subdomain,
			sub.Type,
			strings.Join(sub.IPs, ";"),
			sub.CNAME,
			strconv.FormatUint(uint64(sub.TTL), 10),
			sub.Source,
			strconv.FormatBool(sub.Wildcard),
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	return nil
}

func saveDNSResultsTXT(result *dns.EnumResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create TXT file: %w", err)
	}
	defer file.Close()

	fmt.Fprintf(file, "DNS Enumeration Results for %s\n", result.Domain)
	fmt.Fprintf(file, "==========================================\n")
	fmt.Fprintf(file, "Total subdomains found: %d\n", result.TotalFound)
	fmt.Fprintf(file, "Enumeration time: %v\n", result.EnumTime)
	fmt.Fprintf(file, "Zone transfer possible: %v\n", result.ZoneTransfer)
	if result.WildcardDomain != "" {
		fmt.Fprintf(file, "Wildcard IPs: %s\n", result.WildcardDomain)
	}
	fmt.Fprintf(file, "\nSubdomains:\n")
	fmt.Fprintf(file, "%s\n", strings.Repeat("-", 80))

	for _, sub := range result.Subdomains {
		if !sub.Wildcard {
			fmt.Fprintf(file, "%s\n", sub.Subdomain)
		}
	}

	return nil
}