package mobile

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"recon-toolkit/pkg/core"
)

type CloudEngine struct {
	config       *CloudConfig
	logger       core.Logger
	platforms    map[string]PlatformHandler
	containers   []Container
	clusters     []KubernetesCluster
	cloudAssets  []CloudAsset
	exploits     []CloudExploit
	mutex        sync.RWMutex
}

type CloudConfig struct {
	Platforms         []string      `json:"platforms"`
	ContainerRuntimes []string      `json:"container_runtimes"`
	CloudProviders    []string      `json:"cloud_providers"`
	ScanTimeout       time.Duration `json:"scan_timeout"`
	MaxConcurrent     int           `json:"max_concurrent"`
	DeepScan          bool          `json:"deep_scan"`
	EscapeAttempts    bool          `json:"escape_attempts"`
	K8sExploitation   bool          `json:"k8s_exploitation"`
	CloudRecon        bool          `json:"cloud_recon"`
	MobileAnalysis    bool          `json:"mobile_analysis"`
}

type PlatformHandler interface {
	Scan(ctx context.Context, target string) (*PlatformResult, error)
	Exploit(ctx context.Context, asset *CloudAsset) (*ExploitResult, error)
	GetCapabilities() []string
}

type Container struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Image        string                 `json:"image"`
	Runtime      string                 `json:"runtime"`
	Status       ContainerStatus        `json:"status"`
	Ports        []Port                 `json:"ports"`
	Volumes      []Volume               `json:"volumes"`
	Environment  map[string]string      `json:"environment"`
	Capabilities []string               `json:"capabilities"`
	Privileged   bool                   `json:"privileged"`
	Vulnerabilities []ContainerVuln     `json:"vulnerabilities"`
	EscapePaths  []EscapePath           `json:"escape_paths"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type KubernetesCluster struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	APIServer    string                 `json:"api_server"`
	Nodes        []K8sNode              `json:"nodes"`
	Namespaces   []string               `json:"namespaces"`
	Services     []K8sService           `json:"services"`
	Pods         []K8sPod               `json:"pods"`
	Secrets      []K8sSecret            `json:"secrets"`
	ConfigMaps   []K8sConfigMap         `json:"config_maps"`
	RBAC         *RBACInfo              `json:"rbac"`
	Vulnerabilities []K8sVuln           `json:"vulnerabilities"`
	ExploitPaths []K8sExploitPath       `json:"exploit_paths"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type CloudAsset struct {
	ID           string                 `json:"id"`
	Type         AssetType              `json:"type"`
	Provider     CloudProvider          `json:"provider"`
	Region       string                 `json:"region"`
	Name         string                 `json:"name"`
	Status       AssetStatus            `json:"status"`
	Configuration map[string]interface{} `json:"configuration"`
	Security     *SecurityConfig        `json:"security"`
	Networking   *NetworkConfig         `json:"networking"`
	Storage      []StorageConfig        `json:"storage"`
	Vulnerabilities []CloudVuln         `json:"vulnerabilities"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type MobileApp struct {
	Package      string                 `json:"package"`
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Platform     MobilePlatform         `json:"platform"`
	Permissions  []string               `json:"permissions"`
	Activities   []string               `json:"activities"`
	Services     []string               `json:"services"`
	Receivers    []string               `json:"receivers"`
	Providers    []string               `json:"providers"`
	Certificates []Certificate          `json:"certificates"`
	Libraries    []Library              `json:"libraries"`
	Vulnerabilities []MobileVuln        `json:"vulnerabilities"`
	Metadata     map[string]interface{} `json:"metadata"`
}

type CloudExploit struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Type         ExploitType    `json:"type"`
	Platform     string         `json:"platform"`
	Description  string         `json:"description"`
	Severity     core.Severity  `json:"severity"`
	CVSS         float64        `json:"cvss"`
	Prerequisites []string      `json:"prerequisites"`
	Payload      []byte         `json:"payload"`
	Success      bool           `json:"success"`
	Evidence     []core.Evidence `json:"evidence"`
}

// Enums
type ContainerStatus int
type AssetType int
type CloudProvider int
type AssetStatus int
type MobilePlatform int
type ExploitType int

const (
	// Container Status
	ContainerRunning ContainerStatus = iota
	ContainerStopped
	ContainerPaused
	ContainerRestarting
)

const (
	// Asset Types
	AssetTypeVM AssetType = iota
	AssetTypeContainer
	AssetTypeFunction
	AssetTypeDatabase
	AssetTypeStorage
	AssetTypeNetwork
	AssetTypeLoadBalancer
	AssetTypeAPI
)

const (
	// Cloud Providers
	ProviderAWS CloudProvider = iota
	ProviderAzure
	ProviderGCP
	ProviderDigitalOcean
	ProviderVultr
	ProviderLinode
)

const (
	// Asset Status
	AssetRunning AssetStatus = iota
	AssetStopped
	AssetTerminated
	AssetPending
)

const (
	// Mobile Platforms
	PlatformAndroid MobilePlatform = iota
	PlatformiOS
	PlatformReactNative
	PlatformFlutter
	PlatformXamarin
)

const (
	// Exploit Types
	ExploitContainerEscape ExploitType = iota
	ExploitK8sPrivilegeEscalation
	ExploitCloudMetadata
	ExploitServerlessFunctionAbuse
	ExploitMobileAppVuln
)

// NewCloudEngine creates mobile/cloud exploitation engine
func NewCloudEngine(logger core.Logger, config *CloudConfig) *CloudEngine {
	if config == nil {
		config = &CloudConfig{
			Platforms:         []string{"docker", "kubernetes", "aws", "azure", "gcp"},
			ContainerRuntimes: []string{"docker", "containerd", "cri-o"},
			CloudProviders:    []string{"aws", "azure", "gcp"},
			ScanTimeout:       60 * time.Second,
			MaxConcurrent:     20,
			DeepScan:          true,
			EscapeAttempts:    true,
			K8sExploitation:   true,
			CloudRecon:        true,
			MobileAnalysis:    true,
		}
	}

	engine := &CloudEngine{
		config:      config,
		logger:      logger,
		platforms:   make(map[string]PlatformHandler),
		containers:  make([]Container, 0),
		clusters:    make([]KubernetesCluster, 0),
		cloudAssets: make([]CloudAsset, 0),
		exploits:    make([]CloudExploit, 0),
	}

	// Initialize platform handlers
	engine.initializePlatformHandlers()
	engine.loadExploitDatabase()

	return engine
}

// DominateCloudInfrastructure performs comprehensive cloud/mobile penetration
func (e *CloudEngine) DominateCloudInfrastructure(ctx context.Context, target core.Target) (*CloudDominationResult, error) {
	e.logger.Info("☁️ INITIATING CLOUD/MOBILE INFRASTRUCTURE DOMINATION", core.NewField("target", target.GetAddress()))

	result := &CloudDominationResult{
		BaseScanResult:      core.NewBaseScanResult(target),
		DiscoveredContainers: make([]Container, 0),
		KubernetesClusters:  make([]KubernetesCluster, 0),
		CloudAssets:         make([]CloudAsset, 0),
		MobileApps:          make([]MobileApp, 0),
		SuccessfulEscapes:   make([]EscapeAttempt, 0),
		ExploitedServices:   make([]CloudExploit, 0),
	}

	var wg sync.WaitGroup
	
	// Phase 1: Container Discovery and Analysis
	if contains(e.config.Platforms, "docker") || contains(e.config.Platforms, "containers") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			containers := e.discoverContainers(ctx, target)
			result.mutex.Lock()
			result.DiscoveredContainers = containers
			result.mutex.Unlock()
		}()
	}

	// Phase 2: Kubernetes Cluster Discovery
	if e.config.K8sExploitation && contains(e.config.Platforms, "kubernetes") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			clusters := e.discoverKubernetesClusters(ctx, target)
			result.mutex.Lock()
			result.KubernetesClusters = clusters
			result.mutex.Unlock()
		}()
	}

	// Phase 3: Cloud Asset Discovery
	if e.config.CloudRecon {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assets := e.discoverCloudAssets(ctx, target)
			result.mutex.Lock()
			result.CloudAssets = assets
			result.mutex.Unlock()
		}()
	}

	// Phase 4: Mobile App Analysis
	if e.config.MobileAnalysis {
		wg.Add(1)
		go func() {
			defer wg.Done()
			apps := e.analyzeMobileApps(ctx, target)
			result.mutex.Lock()
			result.MobileApps = apps
			result.mutex.Unlock()
		}()
	}

	wg.Wait()

	// Phase 5: Container Escape Attempts
	if e.config.EscapeAttempts && len(result.DiscoveredContainers) > 0 {
		escapes := e.attemptContainerEscapes(ctx, result.DiscoveredContainers)
		result.SuccessfulEscapes = escapes
	}

	// Phase 6: Kubernetes Exploitation
	if e.config.K8sExploitation && len(result.KubernetesClusters) > 0 {
		exploits := e.exploitKubernetes(ctx, result.KubernetesClusters)
		result.ExploitedServices = append(result.ExploitedServices, exploits...)
	}

	// Phase 7: Cloud Service Exploitation
	if len(result.CloudAssets) > 0 {
		cloudExploits := e.exploitCloudServices(ctx, result.CloudAssets)
		result.ExploitedServices = append(result.ExploitedServices, cloudExploits...)
	}

	e.logger.Info("☁️ Cloud/Mobile domination completed", 
		core.NewField("containers", len(result.DiscoveredContainers)),
		core.NewField("k8s_clusters", len(result.KubernetesClusters)),
		core.NewField("cloud_assets", len(result.CloudAssets)),
		core.NewField("mobile_apps", len(result.MobileApps)),
		core.NewField("successful_escapes", len(result.SuccessfulEscapes)))

	return result, nil
}

// discoverContainers discovers running containers
func (e *CloudEngine) discoverContainers(ctx context.Context, target core.Target) []Container {
	e.logger.Debug("🐳 Discovering containers")
	
	containers := make([]Container, 0)
	
	// Mock container discovery
	container := Container{
		ID:      "container-123456",
		Name:    "webapp-frontend",
		Image:   "nginx:latest",
		Runtime: "docker",
		Status:  ContainerRunning,
		Ports: []Port{
			{Number: 80, Protocol: "tcp", Exposed: true},
			{Number: 443, Protocol: "tcp", Exposed: true},
		},
		Environment: map[string]string{
			"NODE_ENV": "production",
			"API_KEY":  "secret-key-123",
		},
		Capabilities: []string{"NET_ADMIN", "SYS_ADMIN"},
		Privileged:   false,
		Vulnerabilities: []ContainerVuln{
			{
				ID:          "CVE-2021-30465",
				Description: "Container escape via /proc/self/exe",
				Severity:    core.SeverityHigh,
				Exploitable: true,
			},
		},
		EscapePaths: []EscapePath{
			{
				Method:      "proc_self_exe",
				Description: "Escape via /proc/self/exe symlink manipulation",
				Complexity:  "medium",
				Success:     false,
			},
		},
	}
	
	containers = append(containers, container)
	return containers
}

// discoverKubernetesClusters discovers Kubernetes clusters
func (e *CloudEngine) discoverKubernetesClusters(ctx context.Context, target core.Target) []KubernetesCluster {
	e.logger.Debug("⚓ Discovering Kubernetes clusters")
	
	clusters := make([]KubernetesCluster, 0)
	
	// Try to detect Kubernetes API server
	apiURL := fmt.Sprintf("https://%s:6443", target.GetAddress())
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	
	resp, err := client.Get(apiURL + "/version")
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		
		cluster := KubernetesCluster{
			Name:      "target-cluster",
			Version:   "v1.25.0",
			APIServer: apiURL,
			Nodes: []K8sNode{
				{
					Name:   "master-node",
					Role:   "master",
					Status: "Ready",
					Version: "v1.25.0",
				},
			},
			Namespaces: []string{"default", "kube-system", "kube-public"},
			Vulnerabilities: []K8sVuln{
				{
					ID:          "K8S-2021-001",
					Description: "Unauthenticated API server access",
					Severity:    core.SeverityCritical,
					Component:   "api-server",
				},
			},
			ExploitPaths: []K8sExploitPath{
				{
					Type:        "privilege_escalation",
					Description: "Escalate to cluster-admin via RBAC misconfiguration",
					Steps:       []string{"list_pods", "create_privileged_pod", "mount_host_filesystem"},
				},
			},
		}
		
		clusters = append(clusters, cluster)
	}
	
	return clusters
}

// discoverCloudAssets discovers cloud assets
func (e *CloudEngine) discoverCloudAssets(ctx context.Context, target core.Target) []CloudAsset {
	e.logger.Debug("☁️ Discovering cloud assets")
	
	assets := make([]CloudAsset, 0)
	
	// Mock cloud asset discovery
	asset := CloudAsset{
		ID:       "i-1234567890abcdef0",
		Type:     AssetTypeVM,
		Provider: ProviderAWS,
		Region:   "us-east-1",
		Name:     "webapp-server",
		Status:   AssetRunning,
		Configuration: map[string]interface{}{
			"instance_type": "t3.micro",
			"ami_id":       "ami-0abcdef1234567890",
			"key_pair":     "my-key-pair",
		},
		Security: &SecurityConfig{
			SecurityGroups: []string{"sg-web", "sg-ssh"},
			IAMRole:       "WebAppRole",
			PublicIP:      true,
		},
		Vulnerabilities: []CloudVuln{
			{
				ID:          "AWS-2021-001",
				Description: "Instance metadata service v1 enabled",
				Severity:    core.SeverityMedium,
				Service:     "EC2",
			},
		},
	}
	
	assets = append(assets, asset)
	return assets
}

// analyzeMobileApps analyzes mobile applications
func (e *CloudEngine) analyzeMobileApps(ctx context.Context, target core.Target) []MobileApp {
	e.logger.Debug("📱 Analyzing mobile applications")
	
	apps := make([]MobileApp, 0)
	
	// Mock mobile app analysis
	app := MobileApp{
		Package:  "com.example.webapp",
		Name:     "WebApp Mobile",
		Version:  "2.1.0",
		Platform: PlatformAndroid,
		Permissions: []string{
			"android.permission.INTERNET",
			"android.permission.ACCESS_FINE_LOCATION",
			"android.permission.CAMERA",
			"android.permission.READ_CONTACTS",
		},
		Activities: []string{
			"MainActivity",
			"LoginActivity",
			"ProfileActivity",
		},
		Vulnerabilities: []MobileVuln{
			{
				ID:          "MOBILE-2021-001",
				Description: "Insecure data storage in shared preferences",
				Severity:    core.SeverityMedium,
				Category:    "data_storage",
			},
			{
				ID:          "MOBILE-2021-002", 
				Description: "Weak SSL/TLS certificate validation",
				Severity:    core.SeverityHigh,
				Category:    "network_security",
			},
		},
	}
	
	apps = append(apps, app)
	return apps
}

// attemptContainerEscapes attempts container escape techniques
func (e *CloudEngine) attemptContainerEscapes(ctx context.Context, containers []Container) []EscapeAttempt {
	e.logger.Info("🏃‍♂️ Attempting container escapes")
	
	escapes := make([]EscapeAttempt, 0)
	
	for _, container := range containers {
		for _, escapePath := range container.EscapePaths {
			e.logger.Debug("Attempting escape", 
				core.NewField("container", container.ID),
				core.NewField("method", escapePath.Method))
			
			// Mock escape attempt
			escape := EscapeAttempt{
				ContainerID: container.ID,
				Method:      escapePath.Method,
				Success:     false,
				Timestamp:   time.Now(),
				Evidence:    make([]core.Evidence, 0),
			}
			
			// Simulate successful escape for demo
			if escapePath.Method == "proc_self_exe" {
				escape.Success = true
				escape.HostAccess = true
				escape.Privileges = "root"
				
				evidence := core.NewBaseEvidence(
					core.EvidenceTypeLog,
					map[string]interface{}{
						"method":     escapePath.Method,
						"container":  container.ID,
						"host_path":  "/",
						"privileges": "root",
					},
					"Successfully escaped container using /proc/self/exe technique",
				)
				escape.Evidence = append(escape.Evidence, evidence)
				
				e.logger.Info("✅ Container escape successful!", 
					core.NewField("container", container.ID),
					core.NewField("method", escapePath.Method))
			}
			
			escapes = append(escapes, escape)
		}
	}
	
	return escapes
}

// exploitKubernetes exploits Kubernetes clusters
func (e *CloudEngine) exploitKubernetes(ctx context.Context, clusters []KubernetesCluster) []CloudExploit {
	e.logger.Info("⚓ Exploiting Kubernetes clusters")
	
	exploits := make([]CloudExploit, 0)
	
	for _, cluster := range clusters {
		for _, vuln := range cluster.Vulnerabilities {
			exploit := CloudExploit{
				ID:          fmt.Sprintf("K8S-EXPLOIT-%s", vuln.ID),
				Name:        fmt.Sprintf("Kubernetes %s exploitation", vuln.Component),
				Type:        ExploitK8sPrivilegeEscalation,
				Platform:    "kubernetes",
				Description: vuln.Description,
				Severity:    vuln.Severity,
				Success:     false,
				Evidence:    make([]core.Evidence, 0),
			}
			
			// Simulate successful exploitation
			if vuln.ID == "K8S-2021-001" {
				exploit.Success = true
				
				evidence := core.NewBaseEvidence(
					core.EvidenceTypeLog,
					map[string]interface{}{
						"cluster":    cluster.Name,
						"api_server": cluster.APIServer,
						"access":     "cluster-admin",
						"method":     "unauthenticated_api",
					},
					"Gained cluster-admin access via unauthenticated API server",
				)
				exploit.Evidence = append(exploit.Evidence, evidence)
				
				e.logger.Info("✅ Kubernetes cluster compromised!", 
					core.NewField("cluster", cluster.Name),
					core.NewField("vulnerability", vuln.ID))
			}
			
			exploits = append(exploits, exploit)
		}
	}
	
	return exploits
}

// exploitCloudServices exploits cloud services
func (e *CloudEngine) exploitCloudServices(ctx context.Context, assets []CloudAsset) []CloudExploit {
	e.logger.Info("☁️ Exploiting cloud services")
	
	exploits := make([]CloudExploit, 0)
	
	for _, asset := range assets {
		for _, vuln := range asset.Vulnerabilities {
			exploit := CloudExploit{
				ID:          fmt.Sprintf("CLOUD-EXPLOIT-%s", vuln.ID),
				Name:        fmt.Sprintf("%s %s exploitation", getProviderString(asset.Provider), vuln.Service),
				Type:        ExploitCloudMetadata,
				Platform:    getProviderString(asset.Provider),
				Description: vuln.Description,
				Severity:    vuln.Severity,
				Success:     false,
				Evidence:    make([]core.Evidence, 0),
			}
			
			// Simulate successful exploitation  
			if vuln.ID == "AWS-2021-001" {
				exploit.Success = true
				
				evidence := core.NewBaseEvidence(
					core.EvidenceTypeLog,
					map[string]interface{}{
						"asset_id":      asset.ID,
						"provider":      getProviderString(asset.Provider),
						"metadata_url":  "http://169.254.169.254/latest/meta-data/",
						"iam_role":      asset.Security.IAMRole,
					},
					"Retrieved AWS instance metadata and IAM credentials",
				)
				exploit.Evidence = append(exploit.Evidence, evidence)
				
				e.logger.Info("✅ Cloud service exploited!", 
					core.NewField("asset", asset.ID),
					core.NewField("provider", getProviderString(asset.Provider)))
			}
			
			exploits = append(exploits, exploit)
		}
	}
	
	return exploits
}

// Helper functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func getProviderString(provider CloudProvider) string {
	switch provider {
	case ProviderAWS:
		return "AWS"
	case ProviderAzure:
		return "Azure"
	case ProviderGCP:
		return "GCP"
	case ProviderDigitalOcean:
		return "DigitalOcean"
	case ProviderVultr:
		return "Vultr"
	case ProviderLinode:
		return "Linode"
	default:
		return "Unknown"
	}
}

// initializePlatformHandlers initializes platform handlers
func (e *CloudEngine) initializePlatformHandlers() {
	e.platforms["docker"] = &DockerHandler{logger: e.logger}
	e.platforms["kubernetes"] = &KubernetesHandler{logger: e.logger}
	e.platforms["aws"] = &AWSHandler{logger: e.logger}
	e.platforms["azure"] = &AzureHandler{logger: e.logger}
	e.platforms["gcp"] = &GCPHandler{logger: e.logger}
}

// loadExploitDatabase loads cloud/mobile exploits
func (e *CloudEngine) loadExploitDatabase() {
	// Load container escape exploits, K8s exploits, cloud service exploits
}

// Additional types
type Port struct {
	Number   int    `json:"number"`
	Protocol string `json:"protocol"`
	Exposed  bool   `json:"exposed"`
}

type Volume struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ReadOnly    bool   `json:"read_only"`
}

type ContainerVuln struct {
	ID          string        `json:"id"`
	Description string        `json:"description"`
	Severity    core.Severity `json:"severity"`
	Exploitable bool          `json:"exploitable"`
}

type EscapePath struct {
	Method      string `json:"method"`
	Description string `json:"description"`
	Complexity  string `json:"complexity"`
	Success     bool   `json:"success"`
}

type K8sNode struct {
	Name    string `json:"name"`
	Role    string `json:"role"`
	Status  string `json:"status"`
	Version string `json:"version"`
}

type K8sService struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Type      string            `json:"type"`
	Ports     []Port            `json:"ports"`
	Selector  map[string]string `json:"selector"`
}

type K8sPod struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Status    string `json:"status"`
	Node      string `json:"node"`
}

type K8sSecret struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Type      string            `json:"type"`
	Data      map[string]string `json:"data"`
}

type K8sConfigMap struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Data      map[string]string `json:"data"`
}

type RBACInfo struct {
	ClusterRoles []string `json:"cluster_roles"`
	Roles        []string `json:"roles"`
	Bindings     []string `json:"bindings"`
}

type K8sVuln struct {
	ID          string        `json:"id"`
	Description string        `json:"description"`
	Severity    core.Severity `json:"severity"`
	Component   string        `json:"component"`
}

type K8sExploitPath struct {
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Steps       []string `json:"steps"`
}

type SecurityConfig struct {
	SecurityGroups []string `json:"security_groups"`
	IAMRole        string   `json:"iam_role"`
	PublicIP       bool     `json:"public_ip"`
}

type NetworkConfig struct {
	VPC     string   `json:"vpc"`
	Subnet  string   `json:"subnet"`
	Subnets []string `json:"subnets"`
}

type StorageConfig struct {
	Type       string `json:"type"`
	Size       int    `json:"size"`
	Encrypted  bool   `json:"encrypted"`
	Mountpoint string `json:"mountpoint"`
}

type CloudVuln struct {
	ID          string        `json:"id"`
	Description string        `json:"description"`
	Severity    core.Severity `json:"severity"`
	Service     string        `json:"service"`
}

type Certificate struct {
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after"`
}

type Library struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	License string `json:"license"`
}

type MobileVuln struct {
	ID          string        `json:"id"`
	Description string        `json:"description"`
	Severity    core.Severity `json:"severity"`
	Category    string        `json:"category"`
}

type EscapeAttempt struct {
	ContainerID string          `json:"container_id"`
	Method      string          `json:"method"`
	Success     bool            `json:"success"`
	HostAccess  bool            `json:"host_access"`
	Privileges  string          `json:"privileges"`
	Timestamp   time.Time       `json:"timestamp"`
	Evidence    []core.Evidence `json:"evidence"`
}

type CloudDominationResult struct {
	*core.BaseScanResult
	DiscoveredContainers []Container       `json:"discovered_containers"`
	KubernetesClusters   []KubernetesCluster `json:"kubernetes_clusters"`
	CloudAssets          []CloudAsset      `json:"cloud_assets"`
	MobileApps           []MobileApp       `json:"mobile_apps"`
	SuccessfulEscapes    []EscapeAttempt   `json:"successful_escapes"`
	ExploitedServices    []CloudExploit    `json:"exploited_services"`
	mutex                sync.RWMutex
}

type PlatformResult struct {
	Platform string                 `json:"platform"`
	Assets   []CloudAsset           `json:"assets"`
	Metadata map[string]interface{} `json:"metadata"`
}

type ExploitResult struct {
	Success     bool                   `json:"success"`
	AccessLevel string                 `json:"access_level"`
	Evidence    []core.Evidence        `json:"evidence"`
	Metadata    map[string]interface{} `json:"metadata"`
}