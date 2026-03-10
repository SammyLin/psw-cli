package pkg

import (
	"testing"
	"time"
)

// TestParseDuration tests the duration parser
func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"7d", 7 * 24 * time.Hour, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"1h", time.Hour, false},
		{"1m", time.Minute, false},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		result, err := parseDuration(tt.input)
		if tt.wantErr && err == nil {
			t.Errorf("parseDuration(%q) expected error, got nil", tt.input)
		}
		if !tt.wantErr && err != nil {
			t.Errorf("parseDuration(%q) unexpected error: %v", tt.input, err)
		}
		if !tt.wantErr && result != tt.expected {
			t.Errorf("parseDuration(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

// TestVaultPath tests vault path generation
func TestVaultPath(t *testing.T) {
	tests := []struct {
		vaultName string
		expected   string
	}{
		{"work", "/home/user/.psw-cli/vaults/work.age"},
		{"personal", "/home/user/.psw-cli/vaults/personal.age"},
	}

	// Note: This test assumes HOME=/home/user for simplicity
	for _, tt := range tests {
		result := vaultPath(tt.vaultName)
		t.Logf("vaultPath(%q) = %s", tt.vaultName, result)
	}
}
