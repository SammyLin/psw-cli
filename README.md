# psw-cli

[![Go Reference](https://pkg.go.dev/badge/github.com/SammyLin/psw-cli.svg)](https://pkg.go.dev/github.com/SammyLin/psw-cli)
[![Tests](https://github.com/SammyLin/psw-cli/actions/workflows/test.yml/badge.svg)](https://github.com/SammyLin/psw-cli/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/SammyLin/psw-cli)](https://goreportcard.com/report/github.com/SammyLin/psw-cli)
[![age](https://img.shields.io/badge/age-v1-blue)](https://age-encryption.org/v1)
[![macOS](https://img.shields.io/badge/macOS-Keychain-green)](https://developer.apple.com/documentation/security/keychain_services)

A secure CLI password manager with age encryption and macOS Keychain integration.

## Features

- **Master Password Storage**: Securely store your master password in macOS Keychain
- **Age Encryption**: All secrets are encrypted using [age](https://github.com/FiloSottile/age) encryption
- **Vault System**: Organize secrets into vaults with expiration times
- **Vault Expiry**: Vaults automatically expire after a specified duration
- **Verification Flow**: Re-authenticate expired vaults via secure HMAC-signed URLs
- **24-Hour Approval**: One-time verification grants 24-hour access to expired vaults

## Installation

### Homebrew (recommended)

```bash
brew tap SammyLin/tap
brew install --cask psw-cli
```

To upgrade:

```bash
brew upgrade --cask psw-cli
```

### From Source

```bash
git clone https://github.com/SammyLin/psw-cli.git
cd psw-cli
go build -o psw-cli .
```

### ⚠️ macOS Gatekeeper Warning

If you see a security warning when running psw-cli for the first time:

> "Apple cannot verify whether psw-cli is malicious software"

This is because psw-cli is not notarized by Apple. To allow it:

1. Go to **System Settings** → **Privacy & Security**
2. Click **"Open Anyway"** (or "Still Open")

Or disable Gatekeeper temporarily:

```bash
sudo spctl --master-disable
```

## Usage

### Initialize Master Password

Set your master password (stored in macOS Keychain):

```bash
psw-cli init
```

You will be prompted to enter a master password. Alternatively, pass it via flag:

```bash
psw-cli init --password "your-secure-password"
```

### Create a Vault

Create a vault with an expiration time:

```bash
psw-cli vault create my-vault --expire 30d
```

Expiration format: `Nd` (days), `Nh` (hours), `Nm` (minutes)

### Store a Secret

Store a secret in a vault:

```bash
psw-cli set github-token ghp_xxxxxxx --vault my-vault
```

### Retrieve a Secret

Get a secret from a vault:

```bash
psw-cli get github-token --vault my-vault
```

If the vault is expired, you will receive a verification URL to re-authenticate.

### Delete a Secret

Delete a secret from a vault:

```bash
psw-cli rm github-token --vault my-vault
```

### List Vaults

List all vaults and their expiry status:

```bash
psw-cli vault list
```

### Renew a Vault

Extend a vault's expiration:

```bash
psw-cli vault renew my-vault --expire 30d
```

## Security

### Encryption

- All secrets are encrypted using [age](https://github.com/FiloSottile/age) encryption
- Master password is stored in macOS Keychain using `security` command
- Age uses scrypt for key derivation (memory-hard function)

### Verification Flow

When accessing an expired vault:

1. A UUID token is generated
2. HMAC-SHA256 signature is created
3. Verification URL is generated
4. User clicks the link to confirm
5. Token is marked as used, 24-hour approval is written to `~/.psw-cli/verify/approved/{vault}/{token}.json`

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PSW_CLI_VERIFY_URL` | Base URL for verification links | `http://localhost:8080` |
| `PSW_CLI_HMAC_SECRET` | HMAC secret for signing verification URLs | - |
| `PORT` | Server port | `8080` |
| `LOG_DIR` | Directory for log files | - |

## Directory Structure

```
psw-cli/
├── main.go          # Entry point
├── cmd/             # CLI commands
│   ├── cmd.go       # CLI runner
│   ├── init.go      # init command
│   ├── post.go      # post command
│   get.go          # get command
│   rm.go           # rm command
│   └── vault.go    # vault management commands
├── pkg/             # Core packages
│   ├── crypto.go    # Age encryption
│   ├── keychain.go  # macOS Keychain integration
│   ├── vault.go    # Vault management
│   └── verify.go   # Verification URL generation
├── go.mod           # Go module
└── README.md        # This file
```

## Data Storage

- **Vaults**: `~/.psw-cli/vaults/`
- **Logs**: `~/.psw-cli/logs/`
- **Verification Tokens**: `~/.psw-cli/tokens/`
- **Approvals**: `~/.psw-cli/approvals/`
- **Verification Approvals**: `~/.psw-cli/verify/approved/{vault}/{token}.json`
- **Master Password**: macOS Keychain (service: `psw-cli`)

## OpenClaw SecretRef Integration

psw-cli works as an [OpenClaw](https://github.com/openclaw/openclaw) SecretRef exec provider. This means your OpenClaw config can reference secrets stored in psw-cli vaults instead of storing API keys as plaintext.

### Before (plaintext)

```json
{
  "tools": {
    "web": {
      "search": {
        "apiKey": "BSAlrRE9ka..."
      }
    }
  }
}
```

### After (SecretRef)

```json
{
  "tools": {
    "web": {
      "search": {
        "apiKey": {
          "source": "exec",
          "provider": "psw",
          "id": "brave_search_key"
        }
      }
    }
  }
}
```

### Setup

1. Add psw-cli as a secrets provider in your OpenClaw config:

```json
{
  "secrets": {
    "providers": {
      "psw": {
        "source": "exec",
        "command": "/opt/homebrew/bin/psw-cli",
        "args": ["resolve", "-v", "my-vault"],
        "passEnv": ["HOME", "PATH"],
        "jsonOnly": true
      }
    }
  }
}
```

2. Store your secrets:

```bash
psw-cli set brave_search_key "your-api-key" -v my-vault
psw-cli set openai_api_key "sk-..." -v my-vault
```

3. Replace plaintext values with SecretRef objects in your config.

4. Verify with OpenClaw:

```bash
# Audit — should show plaintext=0
openclaw secrets audit

# Reload secrets
openclaw secrets reload
```

### How it works

OpenClaw sends a JSON request to psw-cli via stdin:

```json
{"protocolVersion": 1, "provider": "psw", "ids": ["brave_search_key", "openai_api_key"]}
```

psw-cli decrypts and returns:

```json
{"protocolVersion": 1, "values": {"brave_search_key": "BSA...", "openai_api_key": "sk-..."}}
```

Secrets are resolved at startup into an in-memory snapshot — they never touch disk as plaintext.

### Shell scripting

Use `--raw` to get just the value (no `Secret:` prefix):

```bash
API_KEY=$(psw-cli get my-key -v my-vault --raw)
curl -H "Authorization: Bearer $API_KEY" https://api.example.com
```

## Commands

| Command | Description |
|---------|-------------|
| `psw-cli init` | Set master password |
| `psw-cli set <key> <value> --vault <vault>` | Store a secret |
| `psw-cli get <key> --vault <vault>` | Retrieve a secret |
| `psw-cli get <key> --vault <vault> --raw` | Retrieve value only (no prefix) |
| `psw-cli rm <key> --vault <vault>` | Delete a secret |
| `psw-cli resolve --vault <vault>` | SecretRef exec provider (stdin/stdout JSON) |
| `psw-cli vault create <vault> --expire <duration>` | Create a vault |
| `psw-cli vault list` | List all vaults |
| `psw-cli vault renew <vault> --expire <duration>` | Renew a vault |

## License

MIT License
