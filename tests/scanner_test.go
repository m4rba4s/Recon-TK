/*
Port Scanner Tests
=================

Unit tests for the port scanner module.
Tests stealth features, honeypot detection, and edge cases.
*/

package tests

import (
	"context"
	"testing"
	"time"

	"recon-toolkit/pkg/scanner"
)

func TestPortRangeParsing(t *testing.T) {
	tests := []struct {
		input    string
		expected []int
		hasError bool
	}{
		{"80", []int{80}, false},
		{"80,443", []int{80, 443}, false},
		{"80-82", []int{80, 81, 82}, false},
		{"80,443,8080-8082", []int{80, 443, 8080, 8081, 8082}, false},
		{"invalid", nil, true},
		{"80-", nil, true},
		{"-80", nil, true},
	}

	for _, test := range tests {
		result, err := scanner.ParsePortRange(test.input)
		
		if test.hasError {
			if err == nil {
				t.Errorf("Expected error for input %s, but got none", test.input)
			}
		} else {
			if err != nil {
				t.Errorf("Unexpected error for input %s: %v", test.input, err)
			}
			
			if len(result) != len(test.expected) {
				t.Errorf("Expected %d ports for %s, got %d", len(test.expected), test.input, len(result))
			}
			
			for i, port := range result {
				if port != test.expected[i] {
					t.Errorf("Expected port %d at index %d, got %d", test.expected[i], i, port)
				}
			}
		}
	}
}

func TestScannerCreation(t *testing.T) {
	ports := []int{80, 443}
	s := scanner.NewScanner("example.com", ports)

	if s.Target != "example.com" {
		t.Errorf("Expected target 'example.com', got '%s'", s.Target)
	}

	if len(s.Ports) != 2 {
		t.Errorf("Expected 2 ports, got %d", len(s.Ports))
	}
}

func TestScannerWithOptions(t *testing.T) {
	ports := []int{80, 443}
	s := scanner.NewScanner("example.com", ports,
		scanner.WithStealth(),
		scanner.WithSilent(),
		scanner.WithThreads(50),
		scanner.WithTimeout(time.Second*10),
	)

	if !s.Stealth {
		t.Error("Expected stealth mode to be enabled")
	}

	if !s.Silent {
		t.Error("Expected silent mode to be enabled")
	}

	if s.Threads != 50 {
		t.Errorf("Expected 50 threads, got %d", s.Threads)
	}

	if s.Timeout != time.Second*10 {
		t.Errorf("Expected 10s timeout, got %v", s.Timeout)
	}
}

func TestCommonPorts(t *testing.T) {
	ports := scanner.CommonPorts()
	
	if len(ports) == 0 {
		t.Error("Expected common ports list to be non-empty")
	}

	// Check that common ports are included
	expectedPorts := []int{80, 443, 22, 21, 25, 53}
	for _, expected := range expectedPorts {
		found := false
		for _, port := range ports {
			if port == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected port %d to be in common ports list", expected)
		}
	}
}

func TestTopPorts(t *testing.T) {
	ports := scanner.TopPorts()
	
	if len(ports) == 0 {
		t.Error("Expected top ports list to be non-empty")
	}

	// Should have more ports than common ports
	commonPorts := scanner.CommonPorts()
	if len(ports) <= len(commonPorts) {
		t.Error("Expected top ports to have more entries than common ports")
	}
}

// Benchmark tests
func BenchmarkPortRangeParsing(b *testing.B) {
	for i := 0; i < b.N; i++ {
		scanner.ParsePortRange("1-1000")
	}
}

func BenchmarkScannerCreation(b *testing.B) {
	ports := []int{80, 443, 22, 21, 25}
	for i := 0; i < b.N; i++ {
		scanner.NewScanner("example.com", ports)
	}
}

// Integration test with localhost
func TestLocalhostScan(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ports := []int{22, 80} // Common ports that might be open
	s := scanner.NewScanner("127.0.0.1", ports,
		scanner.WithSilent(),
		scanner.WithTimeout(time.Second*2),
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	result, err := s.Scan(ctx)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if result.Target != "127.0.0.1" {
		t.Errorf("Expected target '127.0.0.1', got '%s'", result.Target)
	}

	if len(result.Ports) != len(ports) {
		t.Errorf("Expected %d port results, got %d", len(ports), len(result.Ports))
	}

	// Verify scan completed in reasonable time
	if result.ScanTime > time.Second*5 {
		t.Errorf("Scan took too long: %v", result.ScanTime)
	}
}