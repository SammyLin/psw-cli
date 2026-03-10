package pkg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// VerificationToken represents a verification token.
type VerificationToken struct {
	Vault      string    `json:"vault"`
	Token      string    `json:"token"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Used       bool      `json:"used"`
	ApprovedAt time.Time `json:"approved_at,omitempty"`
}

// Config holds the application configuration.
type Config struct {
	VerificationURL string
	TelegramBotURL  string
	TelegramChatID  string
}

// VerifyTokenDir is the directory where verification tokens are stored.
var VerifyTokenDir = filepath.Join(os.Getenv("HOME"), ".psw-cli", "tokens")

// HMACKey is used to sign verification URLs (in production, use environment variable).
var HMACKey = []byte("psw-cli-default-key-change-in-production")

func init() {
	// Try to load HMAC key from environment
	if key := os.Getenv("PSW_CLI_HMAC_KEY"); key != "" {
		HMACKey = []byte(key)
	}
}

// initVerifyTokenDir ensures verification token directory exists.
func initVerifyTokenDir() error {
	return os.MkdirAll(VerifyTokenDir, 0700)
}

// GenerateVerificationURL generates a verification URL for expired vault re-authentication.
func GenerateVerificationURL(vaultName, baseURL string) (string, error) {
	if err := initVerifyTokenDir(); err != nil {
		return "", err
	}

	// Generate UUID token
	token := uuid.New().String()

	// Create verification token record
	vt := VerificationToken{
		Vault:     vaultName,
		Token:     token,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Used:      false,
	}

	// Save token to file
	tokenPath := filepath.Join(VerifyTokenDir, token+".json")
	tokenData, err := json.Marshal(vt)
	if err != nil {
		return "", fmt.Errorf("failed to marshal token: %w", err)
	}

	if err := os.WriteFile(tokenPath, tokenData, 0600); err != nil {
		return "", fmt.Errorf("failed to write token: %w", err)
	}

	// Generate HMAC signature
	expireTimestamp := vt.ExpiresAt.Unix()
	message := fmt.Sprintf("vault=%s&token=%s&expire=%d", vaultName, token, expireTimestamp)
	signature := GenerateHMAC(message, HMACKey)

	// Build verification URL
	verificationURL := fmt.Sprintf("%s?vault=%s&token=%s&expire=%d&sig=%s",
		baseURL, vaultName, token, expireTimestamp, signature)

	log.Printf("Generated verification URL for vault '%s'", vaultName)
	return verificationURL, nil
}

// GenerateHMAC generates an HMAC signature.
func GenerateHMAC(message string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHMAC verifies an HMAC signature.
func VerifyHMAC(message, signature string, key []byte) bool {
	expected := GenerateHMAC(message, key)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// ValidateVerificationToken validates a verification token from URL.
func ValidateVerificationToken(vaultName, tokenStr, signature string, expireTimestamp int64) (*VerificationToken, error) {
	// Verify HMAC
	message := fmt.Sprintf("vault=%s&token=%s&expire=%d", vaultName, tokenStr, expireTimestamp)
	if !VerifyHMAC(message, signature, HMACKey) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Check if token expired
	if time.Now().Unix() > expireTimestamp {
		return nil, fmt.Errorf("verification link expired")
	}

	// Load token from file
	tokenPath := filepath.Join(VerifyTokenDir, tokenStr+".json")
	tokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("token not found")
	}

	var vt VerificationToken
	if err := json.Unmarshal(tokenData, &vt); err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Check if token matches
	if vt.Token != tokenStr || vt.Vault != vaultName {
		return nil, fmt.Errorf("token mismatch")
	}

	// Check if already used
	if vt.Used {
		return nil, fmt.Errorf("token already used")
	}

	return &vt, nil
}

// MarkTokenUsed marks a verification token as used and creates 24-hour approval.
func MarkTokenUsed(tokenStr string) error {
	tokenPath := filepath.Join(VerifyTokenDir, tokenStr+".json")
	tokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("token not found: %w", err)
	}

	var vt VerificationToken
	if err := json.Unmarshal(tokenData, &vt); err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	// Mark as used
	vt.Used = true
	vt.ApprovedAt = time.Now()

	// Save updated token
	tokenData, err = json.Marshal(vt)
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	if err := os.WriteFile(tokenPath, tokenData, 0600); err != nil {
		return fmt.Errorf("failed to write token: %w", err)
	}

	// Create 24-hour approval
	approval := Approval{
		Vault:       vt.Vault,
		ApprovedAt:  time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}
	if err := SaveApproval(vt.Vault, &approval); err != nil {
		return fmt.Errorf("failed to save approval: %w", err)
	}

	log.Printf("Token '%s' marked as used, 24-hour approval granted for vault '%s'", tokenStr, vt.Vault)
	return nil
}

// Approval represents a 24-hour approval for accessing an expired vault.
type Approval struct {
	Vault       string    `json:"vault"`
	ApprovedAt  time.Time `json:"approved_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// SaveApproval saves an approval to file.
func SaveApproval(vaultName string, approval *Approval) error {
	if err := os.MkdirAll(ApprovalDir, 0700); err != nil {
		return fmt.Errorf("failed to create approval directory: %w", err)
	}

	approvalPath := filepath.Join(ApprovalDir, vaultName+".json")
	approvalData, err := json.Marshal(approval)
	if err != nil {
		return fmt.Errorf("failed to marshal approval: %w", err)
	}

	if err := os.WriteFile(approvalPath, approvalData, 0600); err != nil {
		return fmt.Errorf("failed to write approval: %w", err)
	}

	return nil
}

// HasApproval checks if there is a valid 24-hour approval for a vault.
func HasApproval(vaultName string) bool {
	approvalPath := filepath.Join(ApprovalDir, vaultName+".json")
	approvalData, err := os.ReadFile(approvalPath)
	if err != nil {
		return false
	}

	var approval Approval
	if err := json.Unmarshal(approvalData, &approval); err != nil {
		return false
	}

	// Check if approval is still valid
	if time.Now().After(approval.ExpiresAt) {
		return false
	}

	return true
}

// GetApproval gets the approval for a vault.
func GetApproval(vaultName string) (*Approval, error) {
	approvalPath := filepath.Join(ApprovalDir, vaultName+".json")
	approvalData, err := os.ReadFile(approvalPath)
	if err != nil {
		return nil, fmt.Errorf("no approval found: %w", err)
	}

	var approval Approval
	if err := json.Unmarshal(approvalData, &approval); err != nil {
		return nil, fmt.Errorf("failed to parse approval: %w", err)
	}

	return &approval, nil
}

// RevokeApproval revokes a vault's 24-hour approval.
func RevokeApproval(vaultName string) error {
	approvalPath := filepath.Join(ApprovalDir, vaultName+".json")
	if err := os.Remove(approvalPath); err != nil {
		return fmt.Errorf("failed to revoke approval: %w", err)
	}

	log.Printf("Revoked approval for vault '%s'", vaultName)
	return nil
}

// SendTelegramNotification sends a verification URL via Telegram.
func SendTelegramNotification(chatID, message string) error {
	botToken := os.Getenv("TELEGRAM_BOT_TOKEN")
	if botToken == "" {
		log.Println("TELEGRAM_BOT_TOKEN not set, skipping Telegram notification")
		return nil
	}

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)

	payload := map[string]interface{}{
		"chat_id": chatID,
		"text":    message,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(payloadBytes))
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("Telegram API error: %s", string(body))
		return fmt.Errorf("Telegram API returned status %d", resp.StatusCode)
	}

	log.Printf("Telegram notification sent to chat %s", chatID)
	return nil
}

// Encrypt encrypts data using AES-GCM.
func EncryptAESGCM(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-GCM.
func DecryptAESGCM(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
