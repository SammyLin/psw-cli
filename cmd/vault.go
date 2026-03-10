package cmd

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/SammyLin/psw-cli/pkg"
	"github.com/urfave/cli/v3"
)

// Vault manages vault operations: create, list, renew.
func Vault(ctx context.Context) *cli.Command {
	return &cli.Command{
		Name:  "vault",
		Usage: "Manage vaults (create, list, renew)",
		Commands: []*cli.Command{
			VaultCreate(ctx),
			VaultList(ctx),
			VaultRenew(ctx),
		},
	}
}

// VaultCreate creates a new vault with expiry.
func VaultCreate(ctx context.Context) *cli.Command {
	return &cli.Command{
		Name:      "create",
		Usage:     "Create a new vault with expiry",
		ArgsUsage: "<vault>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "expire",
				Aliases:  []string{"e"},
				Usage:    "Expiration duration (e.g., 7d, 30d, 90d)",
				Required: true,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			vaultName := cmd.Args().First()
			if vaultName == "" {
				return fmt.Errorf("vault name is required")
			}

			expireStr := cmd.String("expire")
			duration, err := parseDuration(expireStr)
			if err != nil {
				return fmt.Errorf("invalid expiration duration: %w", err)
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

			// Create vault
			if err := pkg.CreateVault(vaultName, duration, password); err != nil {
				log.Printf("Failed to create vault: %v", err)
				return fmt.Errorf("failed to create vault: %w", err)
			}

			log.Printf("Created vault '%s' with expiry %s", vaultName, expireStr)
			fmt.Printf("✓ Vault '%s' created (expires in %s)\n", vaultName, expireStr)
			return nil
		},
	}
}

// VaultList lists all vaults and their expiry status.
func VaultList(ctx context.Context) *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "List all vaults and their expiry status",
		Action: func(ctx context.Context, cmd *cli.Command) error {
			vaults, err := pkg.ListVaults()
			if err != nil {
				log.Printf("Failed to list vaults: %v", err)
				return fmt.Errorf("failed to list vaults: %w", err)
			}

			if len(vaults) == 0 {
				fmt.Println("No vaults found")
				return nil
			}

			fmt.Println("Vaults:")
			fmt.Println("--------")
			for _, v := range vaults {
				expireAt := v.ExpireAt.Format("2006-01-02 15:04:05")
				status := "✓ Active"
				if v.IsExpired() {
					status = "✗ Expired"
				}
				fmt.Printf("  %s - %s (expires: %s)\n", v.Name, status, expireAt)
			}
			return nil
		},
	}
}

// VaultRenew extends vault expiry.
func VaultRenew(ctx context.Context) *cli.Command {
	return &cli.Command{
		Name:      "renew",
		Usage:     "Extend vault expiry",
		ArgsUsage: "<vault>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "expire",
				Aliases:  []string{"e"},
				Usage:    "New expiration duration (e.g., 7d, 30d, 90d)",
				Required: true,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			vaultName := cmd.Args().First()
			if vaultName == "" {
				return fmt.Errorf("vault name is required")
			}

			expireStr := cmd.String("expire")
			duration, err := parseDuration(expireStr)
			if err != nil {
				return fmt.Errorf("invalid expiration duration: %w", err)
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

			// Renew vault
			if err := pkg.RenewVault(vaultName, duration, password); err != nil {
				log.Printf("Failed to renew vault: %v", err)
				return fmt.Errorf("failed to renew vault: %w", err)
			}

			log.Printf("Renewed vault '%s' with new expiry %s", vaultName, expireStr)
			fmt.Printf("✓ Vault '%s' renewed (new expiry: %s)\n", vaultName, expireStr)
			return nil
		},
	}
}

// parseDuration parses duration string like "7d", "30d", "90d".
func parseDuration(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration format")
	}

	var unit string
	var value string
	switch s[len(s)-1] {
	case 'd':
		unit = "day"
		value = s[:len(s)-1]
	case 'h':
		unit = "hour"
		value = s[:len(s)-1]
	case 'm':
		unit = "minute"
		value = s[:len(s)-1]
	default:
		return 0, fmt.Errorf("unknown unit (use d, h, m)")
	}

	var num int
	_, err := fmt.Sscanf(value, "%d", &num)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %w", err)
	}

	switch unit {
	case "day":
		return time.Duration(num) * 24 * time.Hour, nil
	case "hour":
		return time.Duration(num) * time.Hour, nil
	case "minute":
		return time.Duration(num) * time.Minute, nil
	}

	return 0, nil
}
