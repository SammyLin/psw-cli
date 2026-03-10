package pkg

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// VaultDir is the directory where vault data is stored.
var VaultDir = filepath.Join(os.Getenv("HOME"), ".psw-cli", "vaults")

// ApprovalDir is the directory where approval tokens are stored.
var ApprovalDir = filepath.Join(os.Getenv("HOME"), ".psw-cli", "approvals")

// VaultMetadata represents the metadata of a vault.
type VaultMetadata struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	ExpireAt  time.Time `json:"expire_at"`
}

// IsExpired checks if the vault has expired.
func (v *VaultMetadata) IsExpired() bool {
	return time.Now().After(v.ExpireAt)
}

// Secret represents a secret stored in a vault.
type Secret struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// initVaultDirs ensures vault directories exist.
func initVaultDirs() error {
	if err := os.MkdirAll(VaultDir, 0700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}
	if err := os.MkdirAll(ApprovalDir, 0700); err != nil {
		return fmt.Errorf("failed to create approval directory: %w", err)
	}
	return nil
}

// CreateVault creates a new vault with the specified expiry duration.
func CreateVault(name string, duration time.Duration, password string) error {
	if err := initVaultDirs(); err != nil {
		return err
	}

	vaultPath := filepath.Join(VaultDir, name)
	if _, err := os.Stat(vaultPath); err == nil {
		return fmt.Errorf("vault '%s' already exists", name)
	}

	// Create vault directory
	if err := os.MkdirAll(vaultPath, 0700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	// Create metadata
	meta := VaultMetadata{
		Name:      name,
		CreatedAt: time.Now(),
		ExpireAt:  time.Now().Add(duration),
	}

	// Encrypt and save metadata
	metaData, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	encryptedMeta, err := Encrypt(metaData, password)
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	metaPath := filepath.Join(vaultPath, ".meta")
	if err := os.WriteFile(metaPath, encryptedMeta, 0600); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	log.Printf("Created vault '%s' at %s", name, vaultPath)
	return nil
}

// GetVaultMetadata retrieves vault metadata.
func GetVaultMetadata(name string) (*VaultMetadata, error) {
	vaultPath := filepath.Join(VaultDir, name)
	metaPath := filepath.Join(vaultPath, ".meta")

	encryptedMeta, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata: %w", err)
	}

	// Get password for decryption
	password, err := GetMasterPassword()
	if err != nil {
		return nil, fmt.Errorf("failed to get master password: %w", err)
	}

	// Try to decrypt with stored password first
	decrypted, err := Decrypt(encryptedMeta, password)
	if err != nil {
		// If decryption fails, return the error
		return nil, fmt.Errorf("failed to decrypt metadata: %w", err)
	}

	var meta VaultMetadata
	if err := json.Unmarshal(decrypted, &meta); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &meta, nil
}

// ListVaults lists all vaults.
func ListVaults() ([]VaultMetadata, error) {
	if err := initVaultDirs(); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(VaultDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault directory: %w", err)
	}

	var vaults []VaultMetadata
	password, _ := GetMasterPassword()

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		meta, err := GetVaultMetadata(name)
		if err != nil {
			// If we can't decrypt, try to get expiry from filename or skip
			log.Printf("Failed to get metadata for vault '%s': %v", name, err)
			continue
		}

		// Check if we have 24-hour approval
		if password != "" && meta.IsExpired() {
			if HasApproval(name) {
				// Treat as not expired if approved
				meta.ExpireAt = time.Now().Add(24 * time.Hour)
			}
		}

		vaults = append(vaults, *meta)
	}

	return vaults, nil
}

// RenewVault extends the expiry of a vault.
func RenewVault(name string, duration time.Duration, password string) error {
	vaultPath := filepath.Join(VaultDir, name)
	if _, err := os.Stat(vaultPath); err != nil {
		return fmt.Errorf("vault '%s' does not exist", name)
	}

	// Get existing metadata
	meta, err := GetVaultMetadata(name)
	if err != nil {
		return fmt.Errorf("failed to get vault metadata: %w", err)
	}

	// Update expiry
	meta.ExpireAt = time.Now().Add(duration)

	// Encrypt and save
	metaData, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	encryptedMeta, err := Encrypt(metaData, password)
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	metaPath := filepath.Join(vaultPath, ".meta")
	if err := os.WriteFile(metaPath, encryptedMeta, 0600); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	log.Printf("Renewed vault '%s' until %s", name, meta.ExpireAt)
	return nil
}

// StoreSecret stores a secret in a vault.
func StoreSecret(vaultName, key, value, password string) error {
	vaultPath := filepath.Join(VaultDir, vaultName)
	if _, err := os.Stat(vaultPath); err != nil {
		return fmt.Errorf("vault '%s' does not exist", vaultName)
	}

	// Encrypt the secret
	encrypted, err := Encrypt([]byte(value), password)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	// Store in vault
	secretPath := filepath.Join(vaultPath, key+".age")
	if err := os.WriteFile(secretPath, encrypted, 0600); err != nil {
		return fmt.Errorf("failed to write secret: %w", err)
	}

	log.Printf("Stored secret '%s' in vault '%s'", key, vaultName)
	return nil
}

// GetSecret retrieves a secret from a vault.
func GetSecret(vaultName, key, password string) (string, error) {
	vaultPath := filepath.Join(VaultDir, vaultName)
	secretPath := filepath.Join(vaultPath, key+".age")

	encrypted, err := os.ReadFile(secretPath)
	if err != nil {
		return "", fmt.Errorf("secret '%s' not found in vault '%s'", key, vaultName)
	}

	// Decrypt the secret
	decrypted, err := Decrypt(encrypted, password)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt secret: %w", err)
	}

	log.Printf("Retrieved secret '%s' from vault '%s'", key, vaultName)
	return string(decrypted), nil
}

// DeleteSecret deletes a secret from a vault.
func DeleteSecret(vaultName, key string) error {
	vaultPath := filepath.Join(VaultDir, vaultName)
	secretPath := filepath.Join(vaultPath, key+".age")

	if err := os.Remove(secretPath); err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	log.Printf("Deleted secret '%s' from vault '%s'", key, vaultName)
	return nil
}

// DeleteVault deletes an entire vault.
func DeleteVault(name string) error {
	vaultPath := filepath.Join(VaultDir, name)
	if err := os.RemoveAll(vaultPath); err != nil {
		return fmt.Errorf("failed to delete vault: %w", err)
	}

	log.Printf("Deleted vault '%s'", name)
	return nil
}
