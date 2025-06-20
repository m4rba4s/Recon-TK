
package dns

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/miekg/dns"
	"github.com/schollz/progressbar/v3"
	"github.com/sirupsen/logrus"
)

type SubdomainResult struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips"`
	CNAME     string   `json:"cname,omitempty"`
	Type      string   `json:"type"`
	TTL       uint32   `json:"ttl"`
	Wildcard  bool     `json:"wildcard"`
	Source    string   `json:"source"`
}

type EnumResult struct {
	Domain         string            `json:"domain"`
	Subdomains     []SubdomainResult `json:"subdomains"`
	TotalFound     int               `json:"total_found"`
	WildcardDomain string            `json:"wildcard_domain,omitempty"`
	ZoneTransfer   bool              `json:"zone_transfer_possible"`
	EnumTime       time.Duration     `json:"enum_time"`
	Nameservers    []string          `json:"nameservers"`
}

type Enumerator struct {
	Domain       string
	Wordlists    []string
	Resolvers    []string
	Threads      int
	Timeout      time.Duration
	Silent       bool
	Permutations bool
	ZoneTransfer bool
	Recursive    bool
	FilterWildcards bool
	logger       *logrus.Logger
	wildcardIPs  []string
}

func NewEnumerator(domain string, options ...func(*Enumerator)) *Enumerator {
	e := &Enumerator{
		Domain:          domain,
		Wordlists:       []string{},
		Resolvers:       []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"},
		Threads:         50,
		Timeout:         time.Second * 3,
		Silent:          false,
		Permutations:    false,
		ZoneTransfer:    true,
		Recursive:       false,
		FilterWildcards: true,
		logger:          logrus.New(),
	}

	for _, option := range options {
		option(e)
	}

	if e.Silent {
		e.logger.SetLevel(logrus.WarnLevel)
	}

	return e
}

func WithWordlists(wordlists []string) func(*Enumerator) {
	return func(e *Enumerator) {
		e.Wordlists = wordlists
	}
}

func WithResolvers(resolvers []string) func(*Enumerator) {
	return func(e *Enumerator) {
		e.Resolvers = resolvers
	}
}

func WithPermutations() func(*Enumerator) {
	return func(e *Enumerator) {
		e.Permutations = true
	}
}

func WithRecursive() func(*Enumerator) {
	return func(e *Enumerator) {
		e.Recursive = true
	}
}

func WithSilent() func(*Enumerator) {
	return func(e *Enumerator) {
		e.Silent = true
	}
}

func (e *Enumerator) Enumerate(ctx context.Context) (*EnumResult, error) {
	startTime := time.Now()

	if !e.Silent {
		color.Cyan("🔍 Starting DNS enumeration for %s", e.Domain)
	}

	nameservers, err := e.getNameservers()
	if err != nil {
		e.logger.Warnf("Could not get nameservers: %v", err)
	}

	if e.FilterWildcards {
		e.detectWildcard()
	}

	var zoneTransferPossible bool
	if e.ZoneTransfer {
		zoneTransferPossible = e.attemptZoneTransfer()
	}

	var allSubdomains []string

	if len(e.Wordlists) > 0 {
		wordlistSubs := e.loadWordlists()
		allSubdomains = append(allSubdomains, wordlistSubs...)
	} else {
		allSubdomains = append(allSubdomains, e.getDefaultWordlist()...)
	}

	if e.Permutations {
		permSubs := e.generatePermutations()
		allSubdomains = append(allSubdomains, permSubs...)
	}

	allSubdomains = e.removeDuplicates(allSubdomains)

	if !e.Silent {
		color.Yellow("📝 Testing %d potential subdomains", len(allSubdomains))
		if len(e.wildcardIPs) > 0 {
			color.Yellow("🌟 Wildcard detected: %v", e.wildcardIPs)
		}
	}

	results := e.resolveSubdomains(ctx, allSubdomains)

	if e.Recursive {
		recursiveResults := e.recursiveDiscovery(ctx, results)
		results = append(results, recursiveResults...)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Subdomain < results[j].Subdomain
	})

	enumResult := &EnumResult{
		Domain:         e.Domain,
		Subdomains:     results,
		TotalFound:     len(results),
		ZoneTransfer:   zoneTransferPossible,
		EnumTime:       time.Since(startTime),
		Nameservers:    nameservers,
	}

	if len(e.wildcardIPs) > 0 {
		enumResult.WildcardDomain = strings.Join(e.wildcardIPs, ",")
	}

	if !e.Silent {
		e.printResults(enumResult)
	}

	return enumResult, nil
}

func (e *Enumerator) getNameservers() ([]string, error) {
	var nameservers []string

	c := &dns.Client{}
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(e.Domain), dns.TypeNS)

	for _, resolver := range e.Resolvers {
		r, _, err := c.Exchange(m, resolver)
		if err != nil {
			continue
		}

		for _, ans := range r.Answer {
			if ns, ok := ans.(*dns.NS); ok {
				nameservers = append(nameservers, ns.Ns)
			}
		}

		if len(nameservers) > 0 {
			break
		}
	}

	return nameservers, nil
}

func (e *Enumerator) detectWildcard() {
	randomSub := fmt.Sprintf("nonexistentsubdomain%d.%s", time.Now().Unix(), e.Domain)
	
	ips, _ := e.resolveA(randomSub)
	if len(ips) > 0 {
		e.wildcardIPs = ips
		if !e.Silent {
			color.Yellow("🌟 Wildcard DNS detected: %s -> %v", randomSub, ips)
		}
	}
}

func (e *Enumerator) attemptZoneTransfer() bool {
	nameservers, err := e.getNameservers()
	if err != nil || len(nameservers) == 0 {
		return false
	}

	for _, ns := range nameservers {
		nsAddr := strings.TrimSuffix(ns, ".")
		if !strings.Contains(nsAddr, ":") {
			nsAddr += ":53"
		}

		transfer := &dns.Transfer{}
		m := &dns.Msg{}
		m.SetAxfr(dns.Fqdn(e.Domain))

		env, err := transfer.In(m, nsAddr)
		if err != nil {
			continue
		}

		for envelope := range env {
			if envelope.Error != nil {
				continue
			}
			
			if len(envelope.RR) > 0 {
				if !e.Silent {
					color.Green("🚨 Zone transfer possible on %s!", ns)
				}
				return true
			}
		}
	}

	return false
}

func (e *Enumerator) loadWordlists() []string {
	var subdomains []string

	for _, wordlist := range e.Wordlists {
		file, err := os.Open(wordlist)
		if err != nil {
			e.logger.Warnf("Could not open wordlist %s: %v", wordlist, err)
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				subdomains = append(subdomains, line)
			}
		}
	}

	return subdomains
}

func (e *Enumerator) getDefaultWordlist() []string {
	return []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
		"cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog",
		"pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new",
		"mysql", "old", "lists", "support", "mobile", "mx", "static", "docs", "beta", "shop",
		"sql", "secure", "demo", "cp", "calendar", "wiki", "web", "media", "email", "images",
		"img", "www1", "intranet", "portal", "video", "sip", "dns2", "api", "cdn", "stats",
		"dns1", "ns4", "www3", "dns", "search", "staging", "server", "mx1", "chat", "wap",
		"my", "svn", "mail1", "sites", "proxy", "ads", "host", "crm", "cms", "backup",
		"mx2", "lyncdiscover", "info", "apps", "download", "remote", "db", "forums", "store",
		"relay", "files", "newsletter", "app", "live", "owa", "en", "start", "sms", "office",
		"exchange", "ipv4", "mail3", "help", "blogs", "helpdesk", "web1", "home", "library",
		"ftp2", "ntp", "monitor", "login", "service", "correo", "www4", "moodle", "it",
		"gateway", "gw", "i", "stat", "stage", "ldap", "tv", "ssl", "web2", "ns5",
		"upload", "nagios", "smtp2", "online", "ad", "survey", "data", "radio", "extranet",
		"test2", "mssql", "dns3", "jobs", "services", "panel", "irc", "hosting", "cloud",
		"de", "gmail", "s", "bbs", "cs", "ww", "mrtg", "git", "image", "s1",
		"meet", "preview", "fr", "cloudflare-resolve-to", "dev2", "photo", "jabber", "legacy",
		"go", "es", "ssh", "redmine", "partner", "vps", "server1", "sv", "s2", "admin2",
	}
}

func (e *Enumerator) generatePermutations() []string {
	var permutations []string
	
	baseWords := []string{"dev", "test", "prod", "staging", "admin", "api", "beta", "demo"}
	separators := []string{"-", "_", ""}
	numbers := []string{"", "1", "2", "01", "02"}

	for _, base := range baseWords {
		for _, sep := range separators {
			for _, num := range numbers {
				if sep == "" && num == "" {
					continue
				}
				permutations = append(permutations, base+sep+num)
				if num != "" {
					permutations = append(permutations, num+sep+base)
				}
			}
		}
	}

	return permutations
}

func (e *Enumerator) removeDuplicates(subdomains []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, sub := range subdomains {
		if !keys[sub] {
			keys[sub] = true
			result = append(result, sub)
		}
	}

	return result
}

func (e *Enumerator) resolveSubdomains(ctx context.Context, subdomains []string) []SubdomainResult {
	semaphore := make(chan struct{}, e.Threads)
	results := make(chan SubdomainResult, len(subdomains))
	var wg sync.WaitGroup

	var bar *progressbar.ProgressBar
	if !e.Silent {
		bar = progressbar.NewOptions(len(subdomains),
			progressbar.OptionSetDescription("Resolving subdomains"),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "█",
				SaucerHead:    "█",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
		)
	}

	for _, subdomain := range subdomains {
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			fullDomain := sub + "." + e.Domain
			result := e.resolveDomain(fullDomain, "bruteforce")
			
			if len(result.IPs) > 0 {
					if e.FilterWildcards && e.isWildcardResponse(result.IPs) {
					result.Wildcard = true
						if !e.Silent && bar != nil {
						bar.Add(1)
					}
					return
				}
				results <- result
			}

			if !e.Silent && bar != nil {
				bar.Add(1)
			}
		}(subdomain)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var subdomainResults []SubdomainResult
	for result := range results {
		subdomainResults = append(subdomainResults, result)
	}

	return subdomainResults
}

func (e *Enumerator) resolveDomain(domain, source string) SubdomainResult {
	result := SubdomainResult{
		Subdomain: domain,
		Source:    source,
	}

	ips, ttl := e.resolveA(domain)
	if len(ips) > 0 {
		result.IPs = ips
		result.Type = "A"
		result.TTL = ttl
		return result
	}

	ipv6s, ttl := e.resolveAAAA(domain)
	if len(ipv6s) > 0 {
		result.IPs = ipv6s
		result.Type = "AAAA"
		result.TTL = ttl
		return result
	}

	cname, ttl := e.resolveCNAME(domain)
	if cname != "" {
		result.CNAME = cname
		result.Type = "CNAME"
		result.TTL = ttl
		
		targetIPs, _ := e.resolveA(cname)
		result.IPs = targetIPs
	}

	return result
}

func (e *Enumerator) resolveA(domain string) ([]string, uint32) {
	var ips []string
	var ttl uint32

	c := &dns.Client{}
	c.Timeout = e.Timeout
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	for _, resolver := range e.Resolvers {
		r, _, err := c.Exchange(m, resolver)
		if err != nil {
			continue
		}

		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				ips = append(ips, a.A.String())
				ttl = a.Hdr.Ttl
			}
		}

		if len(ips) > 0 {
			break
		}
	}

	return ips, ttl
}

func (e *Enumerator) resolveAAAA(domain string) ([]string, uint32) {
	var ips []string
	var ttl uint32

	c := &dns.Client{}
	c.Timeout = e.Timeout
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)

	for _, resolver := range e.Resolvers {
		r, _, err := c.Exchange(m, resolver)
		if err != nil {
			continue
		}

		for _, ans := range r.Answer {
			if aaaa, ok := ans.(*dns.AAAA); ok {
				ips = append(ips, aaaa.AAAA.String())
				ttl = aaaa.Hdr.Ttl
			}
		}

		if len(ips) > 0 {
			break
		}
	}

	return ips, ttl
}

func (e *Enumerator) resolveCNAME(domain string) (string, uint32) {
	c := &dns.Client{}
	c.Timeout = e.Timeout
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCNAME)

	for _, resolver := range e.Resolvers {
		r, _, err := c.Exchange(m, resolver)
		if err != nil {
			continue
		}

		for _, ans := range r.Answer {
			if cname, ok := ans.(*dns.CNAME); ok {
				return cname.Target, cname.Hdr.Ttl
			}
		}
	}

	return "", 0
}

func (e *Enumerator) isWildcardResponse(ips []string) bool {
	if len(e.wildcardIPs) == 0 {
		return false
	}

	for _, ip := range ips {
		for _, wildcardIP := range e.wildcardIPs {
			if ip == wildcardIP {
				return true
			}
		}
	}
	return false
}

func (e *Enumerator) recursiveDiscovery(ctx context.Context, foundSubdomains []SubdomainResult) []SubdomainResult {
	if !e.Silent {
		color.Cyan("🔄 Performing recursive discovery...")
	}

	var additionalSubs []string
	commonSubs := []string{"www", "mail", "admin", "test", "dev", "staging"}

	for _, result := range foundSubdomains {
		parts := strings.Split(result.Subdomain, ".")
		if len(parts) > 2 {
			baseSubdomain := parts[0]
			
			for _, common := range commonSubs {
				if common != baseSubdomain {
					newSub := common + "." + baseSubdomain
					additionalSubs = append(additionalSubs, newSub)
				}
			}
		}
	}

	if len(additionalSubs) == 0 {
		return []SubdomainResult{}
	}

	return e.resolveSubdomains(ctx, additionalSubs)
}

func (e *Enumerator) printResults(result *EnumResult) {
	fmt.Println()
	color.Green("📊 DNS Enumeration Results for %s", result.Domain)
	color.White("=" + strings.Repeat("=", 50))

	if result.ZoneTransfer {
		color.Red("🚨 Zone transfer possible!")
	}

	color.Cyan("Total subdomains found: %d", result.TotalFound)
	color.Cyan("Enumeration time: %v", result.EnumTime)

	if result.WildcardDomain != "" {
		color.Yellow("Wildcard IPs: %s", result.WildcardDomain)
	}

	fmt.Println()
	fmt.Printf("%-40s %-15s %-20s %s\n", "SUBDOMAIN", "TYPE", "IP/CNAME", "TTL")
	fmt.Println(strings.Repeat("-", 100))

	for _, sub := range result.Subdomains {
		target := strings.Join(sub.IPs, ", ")
		if sub.CNAME != "" {
			target = sub.CNAME + " (" + target + ")"
		}
		
		subColor := color.GreenString(sub.Subdomain)
		if sub.Wildcard {
			subColor = color.YellowString(sub.Subdomain + " [WILDCARD]")
		}

		fmt.Printf("%-40s %-15s %-20s %d\n", subColor, sub.Type, target, sub.TTL)
	}
}