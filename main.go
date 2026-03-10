package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/SammyLin/psw-cli/cmd"
)

type Config struct {
	VerificationURL string
	TelegramBotURL  string
	TelegramChatID  string
}

func main() {
	// Ensure log directory exists
	logDir := filepath.Join(os.Getenv("HOME"), ".psw-cli", "logs")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create log directory: %v\n", err)
		os.Exit(1)
	}

	// Setup logging to file
	logFile := filepath.Join(logDir, "psw-cli.log")
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Load configuration from environment variables
	config := &Config{
		VerificationURL: getEnv("PSW_CLI_VERIFY_URL", "https://psw-cli.3mi.tw/verify"),
		TelegramBotURL:  getEnv("PSW_CLI_TELEGRAM_URL", "https://api.telegram.org/bot"),
		TelegramChatID:  getEnv("PSW_CLI_TELEGRAM_CHAT_ID", ""),
	}

	ctx := context.WithValue(context.Background(), "config", config)

	// Run CLI
	if err := cmd.Run(ctx); err != nil {
		log.Printf("Error: %v", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
