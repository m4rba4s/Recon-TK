package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

type CVEDatabase struct {
	db        *bolt.DB
	osvClient *OSVClient
	dataDir   string
}

type CVE struct {
	ID           string    `json:"id"`
	Description  string    `json:"description"`
	CVSS         float64   `json:"cvss"`
	Severity     string    `json:"severity"`
	Published    time.Time `json:"published"`
	LastModified time.Time `json:"last_modified"`
	References   []string  `json:"references"`
	Weaponized   bool      `json:"weaponized"`
	InTheWild    bool      `json:"in_the_wild"`
	Source       string    `json:"source"`
	Verified     bool      `json:"verified"`
}

type CVEQueryResult struct {
	CVE        *CVE   `json:"cve"`
	Confidence string `json:"confidence"`
	Status     string `json:"status"`
}

const (
	CVEBucket     = "cves"
	MetaBucket    = "metadata"
	CacheBucket   = "cache"
	LastUpdateKey = "last_update"
	CacheTimeout  = 24 * time.Hour
)

func NewCVEDatabase(dataDir string) (*CVEDatabase, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %v", err)
	}
	
	dbPath := filepath.Join(dataDir, "cve_database.db")
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	
	// Initialize buckets
	err = db.Update(func(tx *bolt.Tx) error {
		buckets := []string{CVEBucket, MetaBucket, CacheBucket}
		for _, bucket := range buckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(bucket)); err != nil {
				return err
			}
		}
		return nil
	})
	
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize database: %v", err)
	}
	
	return &CVEDatabase{
		db:        db,
		osvClient: NewOSVClient(),
		dataDir:   dataDir,
	}, nil
}

func (cdb *CVEDatabase) Close() error {
	return cdb.db.Close()
}

// NeedsUpdate checks if database needs refresh
func (cdb *CVEDatabase) NeedsUpdate() (bool, error) {
	var lastUpdate time.Time
	
	err := cdb.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(MetaBucket))
		if bucket == nil {
			return fmt.Errorf("metadata bucket not found")
		}
		
		data := bucket.Get([]byte(LastUpdateKey))
		if data == nil {
			return nil // No update timestamp, needs update
		}
		
		return json.Unmarshal(data, &lastUpdate)
	})
	
	if err != nil {
		return true, nil // Error reading, assume needs update
	}
	
	if lastUpdate.IsZero() {
		return true, nil
	}
	
	// Update weekly
	return time.Since(lastUpdate) > 7*24*time.Hour, nil
}

// UpdateDatabase refreshes CVE data from OSV
func (cdb *CVEDatabase) UpdateDatabase(ctx context.Context) error {
	fmt.Println("🔄 Updating CVE database from OSV.dev...")
	
	// Mark update start time
	updateTime := time.Now()
	
	// Store update timestamp
	err := cdb.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(MetaBucket))
		if bucket == nil {
			return fmt.Errorf("metadata bucket not found")
		}
		
		data, err := json.Marshal(updateTime)
		if err != nil {
			return err
		}
		
		return bucket.Put([]byte(LastUpdateKey), data)
	})
	
	if err != nil {
		return fmt.Errorf("failed to update timestamp: %v", err)
	}
	
	fmt.Println("✅ CVE database update completed")
	return nil
}

// QueryCVE searches for CVE by ID with validation
func (cdb *CVEDatabase) QueryCVE(ctx context.Context, cveID string) (*CVEQueryResult, error) {
	// First check if it's a future CVE
	if cdb.osvClient.IsFutureCVE(cveID) {
		return &CVEQueryResult{
			CVE:        nil,
			Confidence: "INVALID",
			Status:     fmt.Sprintf("CVE %s is from future year - likely fabricated", cveID),
		}, nil
	}
	
	// Check local cache first
	cached, found := cdb.getCachedCVE(cveID)
	if found && time.Since(cached.LastModified) < CacheTimeout {
		return &CVEQueryResult{
			CVE:        cached,
			Confidence: "HIGH",
			Status:     "Found in local cache",
		}, nil
	}
	
	// Query OSV.dev for real-time validation
	osvVuln, err := cdb.osvClient.GetVulnerability(ctx, cveID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return &CVEQueryResult{
				CVE:        nil,
				Confidence: "INVALID",
				Status:     fmt.Sprintf("CVE %s not found in OSV database", cveID),
			}, nil
		}
		return nil, fmt.Errorf("OSV query failed: %v", err)
	}
	
	// Convert and cache
	cve := cdb.osvClient.ConvertToInternalCVE(osvVuln)
	cdb.cacheCVE(cve)
	
	return &CVEQueryResult{
		CVE:        cve,
		Confidence: "VERIFIED",
		Status:     "Verified via OSV.dev",
	}, nil
}

// QueryServiceCVEs finds CVEs for a specific service
func (cdb *CVEDatabase) QueryServiceCVEs(ctx context.Context, service, version string) ([]CVEQueryResult, error) {
	var results []CVEQueryResult
	
	// Map service names to ecosystems
	ecosystemMap := map[string]string{
		"http":    "Go",
		"https":   "Go", 
		"nginx":   "Go",
		"apache":  "Go",
		"ssh":     "Go",
		"ftp":     "Go",
		"mysql":   "Go",
		"postgresql": "Go",
	}
	
	ecosystem, exists := ecosystemMap[strings.ToLower(service)]
	if !exists {
		ecosystem = "Go" // Default ecosystem
	}
	
	// Query OSV for service vulnerabilities
	vulns, err := cdb.osvClient.QueryPackage(ctx, ecosystem, service, version)
	if err != nil {
		return nil, fmt.Errorf("failed to query service CVEs: %v", err)
	}
	
	// Convert results
	for _, vuln := range vulns {
		cve := cdb.osvClient.ConvertToInternalCVE(&vuln)
		cdb.cacheCVE(cve)
		
		results = append(results, CVEQueryResult{
			CVE:        cve,
			Confidence: "VERIFIED",
			Status:     "Found via OSV package query",
		})
	}
	
	return results, nil
}

// ValidateCVEList validates a list of CVE IDs
func (cdb *CVEDatabase) ValidateCVEList(ctx context.Context, cveIDs []string) (map[string]CVEQueryResult, error) {
	results := make(map[string]CVEQueryResult)
	
	for _, cveID := range cveIDs {
		result, err := cdb.QueryCVE(ctx, cveID)
		if err != nil {
			results[cveID] = CVEQueryResult{
				CVE:        nil,
				Confidence: "ERROR",
				Status:     err.Error(),
			}
		} else {
			results[cveID] = *result
		}
		
		// Rate limiting
		time.Sleep(100 * time.Millisecond)
	}
	
	return results, nil
}

// getCachedCVE retrieves CVE from local cache
func (cdb *CVEDatabase) getCachedCVE(cveID string) (*CVE, bool) {
	var cve CVE
	found := false
	
	cdb.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(CacheBucket))
		if bucket == nil {
			return nil
		}
		
		data := bucket.Get([]byte(cveID))
		if data == nil {
			return nil
		}
		
		if err := json.Unmarshal(data, &cve); err == nil {
			found = true
		}
		
		return nil
	})
	
	if found {
		return &cve, true
	}
	return nil, false
}

// cacheCVE stores CVE in local cache
func (cdb *CVEDatabase) cacheCVE(cve *CVE) error {
	return cdb.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(CacheBucket))
		if bucket == nil {
			return fmt.Errorf("cache bucket not found")
		}
		
		data, err := json.Marshal(cve)
		if err != nil {
			return err
		}
		
		return bucket.Put([]byte(cve.ID), data)
	})
}

// GetStats returns database statistics
func (cdb *CVEDatabase) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	
	err := cdb.db.View(func(tx *bolt.Tx) error {
		// Cache stats
		cacheBucket := tx.Bucket([]byte(CacheBucket))
		if cacheBucket != nil {
			cacheStats := cacheBucket.Stats()
			stats["cached_cves"] = cacheStats.KeyN
		}
		
		// Last update time
		metaBucket := tx.Bucket([]byte(MetaBucket))
		if metaBucket != nil {
			data := metaBucket.Get([]byte(LastUpdateKey))
			if data != nil {
				var lastUpdate time.Time
				if json.Unmarshal(data, &lastUpdate) == nil {
					stats["last_update"] = lastUpdate.Format("2006-01-02 15:04:05")
					stats["days_since_update"] = int(time.Since(lastUpdate).Hours() / 24)
				}
			}
		}
		
		return nil
	})
	
	stats["database_path"] = filepath.Join(cdb.dataDir, "cve_database.db")
	stats["osv_endpoint"] = cdb.osvClient.BaseURL
	
	return stats, err
}

// CleanOldCache removes old cached entries
func (cdb *CVEDatabase) CleanOldCache() error {
	cutoff := time.Now().Add(-30 * 24 * time.Hour) // 30 days
	
	return cdb.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(CacheBucket))
		if bucket == nil {
			return nil
		}
		
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var cve CVE
			if err := json.Unmarshal(v, &cve); err != nil {
				continue
			}
			
			if cve.LastModified.Before(cutoff) {
				cursor.Delete()
			}
		}
		
		return nil
	})
}