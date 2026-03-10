package cmd

import (
	"context"
	"fmt"
	"log"

	"github.com/SammyLin/psw-cli/pkg"
	"github.com/urfave/cli/v3"
)

// Remove deletes a secret from the specified vault.
func Remove(ctx context.Context) *cli.Command {
	return &cli.Command{
		Name:      "rm",
		Usage:     "Delete a secret from a vault",
		ArgsUsage: "<key>",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "vault",
				Aliases:  []string{"v"},
				Usage:    "Vault name",
				Required: true,
			},
			&cli.BoolFlag{
				Name:  "force",
				Usage: "Force deletion without confirmation",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			key := cmd.Args().First()
			if key == "" {
				return fmt.Errorf("key is required")
			}

			vaultName := cmd.String("vault")
			force := cmd.Bool("force")

			if !force {
				fmt.Printf("Are you sure you want to delete secret '%s' from vault '%s'? (y/N): ", key, vaultName)
				var confirm string
				fmt.Scanln(&confirm)
				if confirm != "y" && confirm != "Y" {
					fmt.Println("Cancelled")
					return nil
				}
			}

			// Delete secret
			if err := pkg.DeleteSecret(vaultName, key); err != nil {
				log.Printf("Failed to delete secret: %v", err)
				return fmt.Errorf("failed to delete secret: %w", err)
			}

			log.Printf("Deleted secret '%s' from vault '%s'", key, vaultName)
			fmt.Printf("✓ Secret '%s' deleted from vault '%s'\n", key, vaultName)
			return nil
		},
	}
}
