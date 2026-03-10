package cmd

import (
	"context"
	"fmt"
	"log"

	"github.com/SammyLin/psw-cli/pkg"
	"github.com/urfave/cli/v3"
)

// Get decrypts and displays a secret from the specified vault.
func Get(ctx context.Context) *cli.Command {
	return &cli.Command{
		Name:      "get",
		Usage:     "Decrypt and display a secret from a vault",
		ArgsUsage: "<key>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "vault",
				Aliases:  []string{"v"},
				Usage:    "Vault name",
				Required: true,
			},
			&cli.BoolFlag{
				Name:  "raw",
				Usage: "Output only the secret value without prefix",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			key := cmd.Args().First()
			if key == "" {
				return fmt.Errorf("key is required")
			}

			vaultName := cmd.String("vault")

			// Get vault metadata to check expiry
			vaultMeta, err := pkg.GetVaultMetadata(vaultName)
			if err != nil {
				log.Printf("Failed to get vault metadata: %v", err)
				return fmt.Errorf("vault '%s' does not exist", vaultName)
			}

			// Check if vault is expired and no valid approval exists
			if vaultMeta.IsExpired() && !pkg.HasApproval(vaultName) {
				log.Printf("Vault '%s' is expired and no valid approval found", vaultName)

				// Generate verification URL
				config := ctx.Value("config")
				var verifyURL, telegramChatID string
				if cfg, ok := config.(*pkg.Config); ok {
					verifyURL = cfg.VerificationURL
					telegramChatID = cfg.TelegramChatID
				}

				verificationURL, err := pkg.GenerateVerificationURL(vaultName, verifyURL)
				if err != nil {
					log.Printf("Failed to generate verification URL: %v", err)
					return fmt.Errorf("vault is expired. Please renew the vault first")
				}

				fmt.Printf("⚠️ Vault '%s' is expired\n", vaultName)
				fmt.Printf("Verification URL: %s\n", verificationURL)

				// Send to Telegram if configured
				if telegramChatID != "" && verificationURL != "" {
					if err := pkg.SendTelegramNotification(telegramChatID, verificationURL); err != nil {
						log.Printf("Failed to send Telegram notification: %v", err)
					} else {
						fmt.Println("✓ Verification URL sent via Telegram")
					}
				}

				return fmt.Errorf("vault is expired. Use the verification URL to re-authenticate")
			}

			if vaultMeta.IsExpired() {
				log.Printf("Using 24-hour approval for vault '%s'", vaultName)
			}

			// Get master password from Keychain
			password, err := pkg.GetMasterPassword()
			if err != nil {
				log.Printf("Failed to get master password: %v", err)
				return fmt.Errorf("failed to get master password: %w", err)
			}

			if password == "" {
				return fmt.Errorf("master password not set. Run 'psw-cli init' first")
			}

			// Get secret
			secret, err := pkg.GetSecret(vaultName, key, password)
			if err != nil {
				log.Printf("Failed to get secret: %v", err)
				return fmt.Errorf("failed to get secret: %w", err)
			}

			log.Printf("Retrieved secret '%s' from vault '%s'", key, vaultName)
			if cmd.Bool("raw") {
				fmt.Print(secret)
			} else {
				fmt.Printf("Secret: %s\n", secret)
			}
			return nil
		},
	}
}
