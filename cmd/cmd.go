package cmd

import (
	"context"

	"github.com/urfave/cli/v3"
)

// Run executes the CLI application.
func Run(ctx context.Context) error {
	app := &cli.Command{
		Name:                 "psw-cli",
		Usage:                "Secure CLI password manager",
		UseShortOptionHandling: true,
		Commands: []*cli.Command{
			Init(ctx),
			Post(ctx),
			Get(ctx),
			Remove(ctx),
			Vault(ctx),
		},
	}

	return app.Run(ctx, []string{"psw-cli"})
}
