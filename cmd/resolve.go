package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/SammyLin/psw-cli/pkg"
	"github.com/urfave/cli/v3"
)

// resolveRequest is the input format for the OpenClaw SecretRef exec provider protocol.
type resolveRequest struct {
	ProtocolVersion int      `json:"protocolVersion"`
	Provider        string   `json:"provider"`
	IDs             []string `json:"ids"`
}

// resolveResponse is the output format for the OpenClaw SecretRef exec provider protocol.
type resolveResponse struct {
	ProtocolVersion int                    `json:"protocolVersion"`
	Values          map[string]string      `json:"values"`
	Errors          map[string]resolveError `json:"errors,omitempty"`
}

// resolveError represents an error for a single secret resolution.
type resolveError struct {
	Message string `json:"message"`
}

// Resolve reads secret IDs from stdin and outputs their values as JSON,
// implementing the OpenClaw SecretRef exec provider protocol.
func Resolve(ctx context.Context) *cli.Command {
	return &cli.Command{
		Name:  "resolve",
		Usage: "Resolve secrets for OpenClaw SecretRef exec provider",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "vault",
				Aliases:  []string{"v"},
				Usage:    "Vault name",
				Required: true,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			vaultName := cmd.String("vault")

			// Parse JSON request from stdin
			var req resolveRequest
			if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
				log.Printf("Failed to parse stdin JSON: %v", err)
				return fmt.Errorf("failed to parse input: %w", err)
			}

			if req.ProtocolVersion != 1 {
				return fmt.Errorf("unsupported protocol version: %d", req.ProtocolVersion)
			}

			// Validate vault exists and check expiry
			vaultMeta, err := pkg.GetVaultMetadata(vaultName)
			if err != nil {
				log.Printf("Failed to get vault metadata: %v", err)
				return fmt.Errorf("vault '%s' does not exist", vaultName)
			}

			if vaultMeta.IsExpired() && !pkg.HasApproval(vaultName) {
				log.Printf("Vault '%s' is expired and no valid approval found", vaultName)
				return fmt.Errorf("vault '%s' is expired", vaultName)
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

			// Resolve each secret
			resp := resolveResponse{
				ProtocolVersion: 1,
				Values:          make(map[string]string),
			}

			for _, id := range req.IDs {
				secret, err := pkg.GetSecret(vaultName, id, password)
				if err != nil {
					log.Printf("Failed to resolve secret '%s': %v", id, err)
					if resp.Errors == nil {
						resp.Errors = make(map[string]resolveError)
					}
					resp.Errors[id] = resolveError{Message: err.Error()}
					continue
				}
				resp.Values[id] = secret
			}

			// Output JSON response to stdout
			output, err := json.Marshal(resp)
			if err != nil {
				log.Printf("Failed to marshal response: %v", err)
				return fmt.Errorf("failed to marshal response: %w", err)
			}

			fmt.Println(string(output))
			log.Printf("Resolved %d secrets from vault '%s' (%d errors)", len(resp.Values), vaultName, len(resp.Errors))
			return nil
		},
	}
}
