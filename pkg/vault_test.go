package pkg

import (
	"testing"
	"time"
)

// TestVaultMetadataExpiry tests vault expiry detection
func TestVaultMetadataExpiry(t *testing.T) {
	tests := []struct {
		name      string
		expireAt time.Time
		want      bool
	}{
		{"expired", time.Now().Add(-1 * time.Hour), true},
		{"not expired", time.Now().Add(1 * time.Hour), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta := &VaultMetadata{
				Name:      "test",
				CreatedAt: time.Now(),
				ExpireAt: tt.expireAt,
			}
			got := meta.IsExpired()
			if got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}
