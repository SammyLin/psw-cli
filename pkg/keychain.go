package pkg

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// KeychainService is the service name used in Keychain.
const KeychainService = "psw-cli"

// StoreMasterPassword stores the master password in macOS Keychain.
func StoreMasterPassword(password string) error {
	// First try to delete any existing password
	cmd := exec.Command("security", "delete-generic-password", "-s", KeychainService)
	_ = cmd.Run()

	// Add new password
	cmd = exec.Command("security", "add-generic-password", "-s", KeychainService, "-a", "master", "-w", password)
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Keychain error output: %s", string(output))
		return fmt.Errorf("failed to store password in Keychain: %w", err)
	}

	log.Println("Master password stored in macOS Keychain")
	return nil
}

// GetMasterPassword retrieves the master password from macOS Keychain.
func GetMasterPassword() (string, error) {
	cmd := exec.Command("security", "find-generic-password", "-s", KeychainService, "-a", "master", "-w")
	output, err := cmd.Output()
	if err != nil {
		// Check if it's "item not found" error
		if strings.Contains(string(output), "could not find") || strings.Contains(err.Error(), "exit status 45") {
			log.Println("No master password found in Keychain")
			return "", nil
		}
		log.Printf("Failed to get password from Keychain: %v", err)
		log.Printf("Output: %s", string(output))
		return "", fmt.Errorf("failed to get password from Keychain: %w", err)
	}

	password := strings.TrimSpace(string(output))
	log.Println("Retrieved master password from macOS Keychain")
	return password, nil
}

// DeleteMasterPassword deletes the master password from macOS Keychain.
func DeleteMasterPassword() error {
	cmd := exec.Command("security", "delete-generic-password", "-s", KeychainService)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Ignore "item not found" errors
		if strings.Contains(string(output), "could not find") {
			return nil
		}
		log.Printf("Failed to delete password from Keychain: %v", err)
		return fmt.Errorf("failed to delete password from Keychain: %w", err)
	}

	log.Println("Master password deleted from macOS Keychain")
	return nil
}

// CheckKeychainAccess checks if we can access the Keychain.
func CheckKeychainAccess() error {
	cmd := exec.Command("security", "find-generic-password", "-s", KeychainService, "-a", "master")
	_, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("Keychain not accessible: %w", err)
	}
	return nil
}
