package cloud

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type CloudProvider string

const (
	ProviderAWS   CloudProvider = "aws"
	ProviderAzure CloudProvider = "azure"
	ProviderGCP   CloudProvider = "gcp"
	ProviderDO    CloudProvider = "digitalocean"
	ProviderVuln  CloudProvider = "vultr"
)

type CloudAsset struct {
	Provider     CloudProvider     `json:"provider"`
	Service      string            `json:"service"`
	URL          string            `json:"url"`
	Region       string            `json:"region"`
	Status       string            `json:"status"`
	Exposed      bool              `json:"exposed"`
	Credentials  map[string]string `json:"credentials"`
	Metadata     map[string]string `json:"metadata"`
	Risk         string            `json:"risk"`
	Discovered   time.Time         `json:"discovered"`
	Vulnerable   bool              `json:"vulnerable"`
	Exploitable  []string          `json:"exploitable"`
}

type CloudScanner struct {
	target         string
	timeout        time.Duration
	threads        int
	aggressive     bool
	client         *http.Client
	logger         *logrus.Logger
	mutex          sync.RWMutex
	assets         []*CloudAsset
	providers      []CloudProvider
	serviceChecks  map[CloudProvider][]string
	regions        map[CloudProvider][]string
	credPatterns   map[string]*regexp.Regexp
	metadataURLs   map[CloudProvider][]string
}

func NewCloudScanner(target string, options ...func(*CloudScanner)) *CloudScanner {
	cs := &CloudScanner{
		target:    target,
		timeout:   time.Second * 10,
		threads:   20,
		aggressive: false,
		logger:    logrus.New(),
		assets:    make([]*CloudAsset, 0),
		providers: []CloudProvider{ProviderAWS, ProviderAzure, ProviderGCP, ProviderDO, ProviderVuln},
	}

	cs.client = &http.Client{
		Timeout: cs.timeout,
	}

	for _, option := range options {
		option(cs)
	}

	cs.initializeServiceChecks()
	cs.initializeRegions()
	cs.initializeCredPatterns()
	cs.initializeMetadataURLs()

	return cs
}

func WithAggressive() func(*CloudScanner) {
	return func(cs *CloudScanner) {
		cs.aggressive = true
	}
}

func WithThreads(threads int) func(*CloudScanner) {
	return func(cs *CloudScanner) {
		cs.threads = threads
	}
}

func (cs *CloudScanner) initializeServiceChecks() {
	cs.serviceChecks = map[CloudProvider][]string{
		ProviderAWS: {
			"s3", "ec2", "rds", "lambda", "iam", "cloudfront",
			"elasticsearch", "redshift", "dynamodb", "sns", "sqs",
			"apigateway", "cloudformation", "ecs", "eks",
		},
		ProviderAzure: {
			"storage", "compute", "database", "functions", "ad",
			"cdn", "search", "cosmosdb", "servicebus", "keyvault",
			"webapp", "aks", "containerinstances",
		},
		ProviderGCP: {
			"storage", "compute", "sql", "functions", "iam",
			"cdn", "bigquery", "pubsub", "kubernetes", "appengine",
			"cloudrun", "firestore", "secretmanager",
		},
		ProviderDO: {
			"droplets", "spaces", "database", "functions", "kubernetes",
			"loadbalancer", "cdn", "vpc", "firewall",
		},
		ProviderVuln: {
			"instances", "storage", "database", "kubernetes",
			"loadbalancer", "dns", "firewall",
		},
	}
}

func (cs *CloudScanner) initializeRegions() {
	cs.regions = map[CloudProvider][]string{
		ProviderAWS: {
			"us-east-1", "us-west-2", "eu-west-1", "eu-central-1",
			"ap-southeast-1", "ap-northeast-1", "ca-central-1",
		},
		ProviderAzure: {
			"eastus", "westus2", "westeurope", "northeurope",
			"southeastasia", "japaneast", "canadacentral",
		},
		ProviderGCP: {
			"us-central1", "us-west1", "europe-west1", "asia-southeast1",
			"asia-northeast1", "australia-southeast1",
		},
	}
}

func (cs *CloudScanner) initializeCredPatterns() {
	cs.credPatterns = map[string]*regexp.Regexp{
		"aws_access_key":    regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
		"aws_secret_key":    regexp.MustCompile(`(?i)[A-Za-z0-9/+=]{40}`),
		"aws_session_token": regexp.MustCompile(`(?i)FQoGZXIvYXdz[A-Za-z0-9/+=]+`),
		"azure_tenant":      regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
		"gcp_key":           regexp.MustCompile(`(?i)"type":\s*"service_account"`),
		"docker_config":     regexp.MustCompile(`(?i)"auths":`),
		"kube_config":       regexp.MustCompile(`(?i)apiVersion:\s*v1`),
	}
}

func (cs *CloudScanner) initializeMetadataURLs() {
	cs.metadataURLs = map[CloudProvider][]string{
		ProviderAWS: {
			"http://169.254.169.254/latest/meta-data/",
			"http://169.254.169.254/latest/user-data/",
			"http://169.254.169.254/latest/dynamic/instance-identity/document",
		},
		ProviderAzure: {
			"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
			"http://169.254.169.254/metadata/identity/oauth2/token",
		},
		ProviderGCP: {
			"http://metadata.google.internal/computeMetadata/v1/",
			"http://169.254.169.254/computeMetadata/v1/instance/",
		},
	}
}

func (cs *CloudScanner) Scan(ctx context.Context) ([]*CloudAsset, error) {
	cs.logger.Infof("☁️ Starting cloud infrastructure scan of %s", cs.target)

	// Phase 1: DNS and subdomain enumeration for cloud services
	cs.enumerateCloudDomains(ctx)

	// Phase 2: Service-specific enumeration
	cs.enumerateCloudServices(ctx)

	// Phase 3: Metadata service checks
	cs.checkMetadataServices(ctx)

	// Phase 4: Credential and configuration checks
	cs.searchCredentials(ctx)

	// Phase 5: Misconfigurations and vulnerabilities
	cs.checkMisconfigurations(ctx)

	cs.logger.Infof("☁️ Cloud scan complete: discovered %d assets", len(cs.assets))
	return cs.assets, nil
}

func (cs *CloudScanner) enumerateCloudDomains(ctx context.Context) {
	cs.logger.Info("🔍 Enumerating cloud service domains")

	domainPatterns := map[CloudProvider][]string{
		ProviderAWS: {
			"%s.s3.amazonaws.com",
			"%s.s3-website.us-east-1.amazonaws.com",
			"%s.s3-website-us-east-1.amazonaws.com",
			"%s.amazonaws.com",
			"%s.cloudfront.net",
			"%s.execute-api.us-east-1.amazonaws.com",
		},
		ProviderAzure: {
			"%s.blob.core.windows.net",
			"%s.azurewebsites.net",
			"%s.database.windows.net",
			"%s.vault.azure.net",
			"%s.azurehdinsight.net",
		},
		ProviderGCP: {
			"%s.storage.googleapis.com",
			"%s.appspot.com",
			"%s.cloudfunctions.net",
			"%s.run.app",
		},
	}

	targetName := strings.Split(cs.target, ".")[0]
	permutations := cs.generatePermutations(targetName)

	for provider, patterns := range domainPatterns {
		for _, pattern := range patterns {
			for _, perm := range permutations {
				domainURL := fmt.Sprintf("https://"+pattern, perm)
				cs.checkCloudAsset(ctx, provider, "domain", domainURL, "")
			}
		}
	}
}

func (cs *CloudScanner) generatePermutations(base string) []string {
	permutations := []string{base}

	suffixes := []string{
		"dev", "test", "staging", "prod", "production",
		"api", "www", "app", "web", "admin", "backup",
		"data", "db", "logs", "media", "assets",
		"1", "2", "v1", "v2", "new", "old",
	}

	for _, suffix := range suffixes {
		permutations = append(permutations,
			base+"-"+suffix,
			base+"_"+suffix,
			base+suffix,
			suffix+"-"+base,
			suffix+"_"+base,
		)
	}

	return permutations
}

func (cs *CloudScanner) enumerateCloudServices(ctx context.Context) {
	cs.logger.Info("🌐 Enumerating cloud services")

	for provider, services := range cs.serviceChecks {
		for _, service := range services {
			cs.checkServiceEndpoints(ctx, provider, service)
		}
	}
}

func (cs *CloudScanner) checkServiceEndpoints(ctx context.Context, provider CloudProvider, service string) {
	var endpoints []string

	switch provider {
	case ProviderAWS:
		for _, region := range cs.regions[provider] {
			endpoints = append(endpoints,
				fmt.Sprintf("https://%s.%s.amazonaws.com", service, region),
				fmt.Sprintf("https://%s-%s.amazonaws.com", service, region),
			)
		}
	case ProviderAzure:
		endpoints = append(endpoints,
			fmt.Sprintf("https://%s.azure.com", service),
			fmt.Sprintf("https://management.azure.com"),
		)
	case ProviderGCP:
		endpoints = append(endpoints,
			fmt.Sprintf("https://%s.googleapis.com", service),
			fmt.Sprintf("https://console.cloud.google.com"),
		)
	}

	for _, endpoint := range endpoints {
		cs.checkCloudAsset(ctx, provider, service, endpoint, "")
	}
}

func (cs *CloudScanner) checkMetadataServices(ctx context.Context) {
	cs.logger.Info("🔍 Checking metadata services")

	for provider, urls := range cs.metadataURLs {
		for _, metadataURL := range urls {
			cs.checkMetadataEndpoint(ctx, provider, metadataURL)
		}
	}
}

func (cs *CloudScanner) checkMetadataEndpoint(ctx context.Context, provider CloudProvider, metadataURL string) {
	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		return
	}

	// Add required headers for some metadata services
	switch provider {
	case ProviderAzure:
		req.Header.Set("Metadata", "true")
	case ProviderGCP:
		req.Header.Set("Metadata-Flavor", "Google")
	}

	resp, err := cs.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		asset := &CloudAsset{
			Provider:    provider,
			Service:     "metadata",
			URL:         metadataURL,
			Status:      "accessible",
			Exposed:     true,
			Risk:        "HIGH",
			Discovered:  time.Now(),
			Vulnerable:  true,
			Credentials: make(map[string]string),
			Metadata:    make(map[string]string),
			Exploitable: []string{"SSRF", "Metadata extraction", "Credential theft"},
		}

		cs.mutex.Lock()
		cs.assets = append(cs.assets, asset)
		cs.mutex.Unlock()

		cs.logger.Warnf("💀 Exposed metadata service: %s", metadataURL)
	}
}

func (cs *CloudScanner) searchCredentials(ctx context.Context) {
	cs.logger.Info("🔑 Searching for exposed credentials")

	credentialPaths := []string{
		"/.aws/credentials",
		"/.aws/config",
		"/.azure/credentials",
		"/gcp-key.json",
		"/.docker/config.json",
		"/.kube/config",
		"/config.json",
		"/credentials.json",
		"/secret.json",
		"/env",
		"/.env",
		"/docker-compose.yml",
		"/kubernetes.yml",
	}

	for _, path := range credentialPaths {
		testURL := strings.TrimSuffix(cs.target, "/") + path
		cs.checkCredentialFile(ctx, testURL)
	}
}

func (cs *CloudScanner) checkCredentialFile(ctx context.Context, fileURL string) {
	req, err := http.NewRequestWithContext(ctx, "GET", fileURL, nil)
	if err != nil {
		return
	}

	resp, err := cs.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 && resp.ContentLength > 0 {
		asset := &CloudAsset{
			Provider:    "unknown",
			Service:     "credentials",
			URL:         fileURL,
			Status:      "exposed",
			Exposed:     true,
			Risk:        "CRITICAL",
			Discovered:  time.Now(),
			Vulnerable:  true,
			Credentials: make(map[string]string),
			Metadata:    make(map[string]string),
			Exploitable: []string{"Credential theft", "Privilege escalation", "Lateral movement"},
		}

		cs.mutex.Lock()
		cs.assets = append(cs.assets, asset)
		cs.mutex.Unlock()

		cs.logger.Errorf("🚨 CRITICAL: Exposed credential file: %s", fileURL)
	}
}

func (cs *CloudScanner) checkMisconfigurations(ctx context.Context) {
	cs.logger.Info("⚠️ Checking for misconfigurations")

	misconfigChecks := []struct {
		name string
		path string
		risk string
	}{
		{"Docker API", ":2375/version", "HIGH"},
		{"Docker API SSL", ":2376/version", "MEDIUM"},
		{"Kubernetes API", ":8080/api/v1", "CRITICAL"},
		{"Kubernetes API SSL", ":6443/api/v1", "HIGH"},
		{"Consul API", ":8500/v1/status/leader", "HIGH"},
		{"Etcd API", ":2379/v2/keys", "CRITICAL"},
		{"Redis", ":6379", "HIGH"},
		{"MongoDB", ":27017", "HIGH"},
		{"Elasticsearch", ":9200/_cluster/health", "MEDIUM"},
	}

	for _, check := range misconfigChecks {
		testURL := fmt.Sprintf("http://%s%s", cs.target, check.path)
		cs.checkMisconfiguration(ctx, check.name, testURL, check.risk)
	}
}

func (cs *CloudScanner) checkMisconfiguration(ctx context.Context, name, testURL, risk string) {
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return
	}

	resp, err := cs.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		asset := &CloudAsset{
			Provider:    "infrastructure",
			Service:     name,
			URL:         testURL,
			Status:      "misconfigured",
			Exposed:     true,
			Risk:        risk,
			Discovered:  time.Now(),
			Vulnerable:  true,
			Credentials: make(map[string]string),
			Metadata:    make(map[string]string),
			Exploitable: []string{"Unauthorized access", "Data exposure", "Service manipulation"},
		}

		cs.mutex.Lock()
		cs.assets = append(cs.assets, asset)
		cs.mutex.Unlock()

		cs.logger.Warnf("⚠️ Misconfiguration found: %s at %s", name, testURL)
	}
}

func (cs *CloudScanner) checkCloudAsset(ctx context.Context, provider CloudProvider, service, assetURL, region string) {
	req, err := http.NewRequestWithContext(ctx, "GET", assetURL, nil)
	if err != nil {
		return
	}

	resp, err := cs.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if cs.isInterestingResponse(resp) {
		asset := &CloudAsset{
			Provider:    provider,
			Service:     service,
			URL:         assetURL,
			Region:      region,
			Status:      cs.getStatusFromResponse(resp),
			Exposed:     cs.isExposed(resp),
			Risk:        cs.calculateRisk(resp, service),
			Discovered:  time.Now(),
			Credentials: make(map[string]string),
			Metadata:    make(map[string]string),
		}

		cs.mutex.Lock()
		cs.assets = append(cs.assets, asset)
		cs.mutex.Unlock()
	}
}

func (cs *CloudScanner) isInterestingResponse(resp *http.Response) bool {
	return resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 401
}

func (cs *CloudScanner) getStatusFromResponse(resp *http.Response) string {
	switch resp.StatusCode {
	case 200:
		return "accessible"
	case 403:
		return "forbidden"
	case 401:
		return "unauthorized"
	default:
		return "unknown"
	}
}

func (cs *CloudScanner) isExposed(resp *http.Response) bool {
	return resp.StatusCode == 200
}

func (cs *CloudScanner) calculateRisk(resp *http.Response, service string) string {
	if resp.StatusCode == 200 {
		highRiskServices := []string{"s3", "storage", "database", "iam", "admin"}
		for _, hrs := range highRiskServices {
			if strings.Contains(service, hrs) {
				return "HIGH"
			}
		}
		return "MEDIUM"
	}
	return "LOW"
}

func (cs *CloudScanner) GetStats() map[string]interface{} {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_assets": len(cs.assets),
	}

	// Count by provider
	providerCounts := make(map[CloudProvider]int)
	riskCounts := make(map[string]int)
	vulnerableCount := 0
	exposedCount := 0

	for _, asset := range cs.assets {
		providerCounts[asset.Provider]++
		riskCounts[asset.Risk]++
		if asset.Vulnerable {
			vulnerableCount++
		}
		if asset.Exposed {
			exposedCount++
		}
	}

	stats["provider_counts"] = providerCounts
	stats["risk_counts"] = riskCounts
	stats["vulnerable_assets"] = vulnerableCount
	stats["exposed_assets"] = exposedCount

	return stats
}