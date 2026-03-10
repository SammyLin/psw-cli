package pkg

import (
	"bytes"
	"fmt"
	"io"
	"log"

	"filippo.io/age"
	"golang.org/x/crypto/argon2"
)

// Encrypt encrypts data using age encryption with the given password.
// Age uses scrypt for key derivation.
func Encrypt(data []byte, password string) ([]byte, error) {
	// Generate a random recipient using password-based encryption
	recipient, err := age.NewScryptRecipient(password)
	if err != nil {
		log.Printf("Failed to create ScryptRecipient: %v", err)
		return nil, fmt.Errorf("failed to create recipient: %w", err)
	}

	// Encrypt the data - age.Encrypt takes a recipient and returns an io.WriteCloser
	var buf bytes.Buffer
	encrypted, err := age.Encrypt(&buf, recipient)
	if err != nil {
		log.Printf("Failed to encrypt data: %v", err)
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	// Write data and close to finalize encryption
	if _, err := encrypted.Write(data); err != nil {
		log.Printf("Failed to write to encrypt: %v", err)
		return nil, fmt.Errorf("failed to write data: %w", err)
	}
	if err := encrypted.Close(); err != nil {
		log.Printf("Failed to close encrypt: %v", err)
		return nil, fmt.Errorf("failed to finalize encryption: %w", err)
	}

	return buf.Bytes(), nil
}

// Decrypt decrypts data using age encryption with the given password.
func Decrypt(encryptedData []byte, password string) ([]byte, error) {
	// Create identity from password
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		log.Printf("Failed to create ScryptIdentity: %v", err)
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}

	// Decrypt the data - age.Decrypt takes an io.Reader and returns an io.Reader
	decrypted, err := age.Decrypt(bytes.NewReader(encryptedData), identity)
	if err != nil {
		log.Printf("Failed to decrypt data: %v", err)
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	// Read all data from the decrypted reader
	data, err := io.ReadAll(decrypted)
	if err != nil {
		log.Printf("Failed to read decrypted data: %v", err)
		return nil, fmt.Errorf("failed to read decrypted data: %w", err)
	}

	return data, nil
}

// DeriveKey derives a key from password using Argon2id.
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}
