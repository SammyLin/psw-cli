package cmd

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/SammyLin/psw-cli/pkg"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

// Init sets the master password and stores it in macOS Keychain.
func Init(ctx context.Context) *cli.Command {
	return &cli.Command{
		Name:  "init",
		Usage: "Set master password and store in macOS Keychain",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "password",
				Usage: "Master password (will prompt if not provided)",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			password := cmd.String("password")
			if password == "" {
				fmt.Print("Enter master password: ")
				bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println() // New line after hidden input
				password = string(bytePassword)
				if err != nil {
					return fmt.Errorf("failed to read password: %w", err)
				}
			}

			if password == "" {
				return fmt.Errorf("password cannot be empty")
			}

			// Store in Keychain
			if err := pkg.StoreMasterPassword(password); err != nil {
				log.Printf("Failed to store master password: %v", err)
				return fmt.Errorf("failed to store master password in Keychain: %w", err)
			}

			log.Println("Master password stored successfully in macOS Keychain")
			fmt.Println("✓ Master password initialized successfully")
			return nil
		},
	}
}
