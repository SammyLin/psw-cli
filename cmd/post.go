package cmd

import (
	"context"
	"fmt"
	"log"

	"github.com/SammyLin/psw-cli/pkg"
	"github.com/urfave/cli/v3"
)

// Set encrypts and stores a secret in the specified vault.
func Set(ctx context.Context) *cli.Command {
	return &cli.Command{
		Name:      "set",
		Usage:     "Encrypt and store a secret in a vault",
		ArgsUsage: "<key> <value>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "vault",
				Aliases:  []string{"v"},
				Usage:    "Vault name",
				Required: true,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			key := cmd.Args().First()
			value := cmd.Args().Get(1)

			if key == "" || value == "" {
				return fmt.Errorf("key and value are required")
			}

			vaultName := cmd.String("vault")

			// Get master password from Keychain
			password, err := pkg.GetMasterPassword()
			if err != nil {
				log.Printf("Failed to get master password: %v", err)
				return fmt.Errorf("failed to get master password: %w", err)
			}

			if password == "" {
				return fmt.Errorf("master password not set. Run 'psw-cli init' first")
			}

			// Store secret
			if err := pkg.StoreSecret(vaultName, key, value, password); err != nil {
				log.Printf("Failed to store secret: %v", err)
				return fmt.Errorf("failed to store secret: %w", err)
			}

			log.Printf("Stored secret '%s' in vault '%s'", key, vaultName)
			fmt.Printf("✓ Secret '%s' stored in vault '%s'\n", key, vaultName)
			return nil
		},
	}
}
