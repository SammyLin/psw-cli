package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

type Config struct {
	VerificationURL string
	HMACSecret      string
}

type usedToken struct {
	usedAt time.Time
}

type Approval struct {
	Vault      string    `json:"vault"`
	Token      string    `json:"token"`
	ApprovedAt time.Time `json:"approved_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

var (
	usedTokens sync.Map // map[string]usedToken
	config     *Config
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Access</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 500px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .card {
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            margin-bottom: 20px;
            font-size: 24px;
        }
        .info {
            background: #f0f7ff;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .info p {
            margin: 5px 0;
            color: #555;
        }
        .label {
            font-weight: 600;
            color: #333;
        }
        .btn {
            display: block;
            width: 100%;
            padding: 15px;
            background: #4CAF50;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 18px;
            cursor: pointer;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #45a049;
        }
        .btn:disabled {
            background: #ccc;
            cursor: not-allowed;
        }
        .message {
            padding: 15px;
            border-radius: 8px;
            margin-top: 20px;
            text-align: center;
        }
        .success {
            background: #d4edda;
            color: #155724;
        }
        .error {
            background: #f8d7da;
            color: #721c24;
        }
    </style>
</head>
<body>
    <div class="card">
        {{if .Success}}
            <h1>✅ Verification Successful!</h1>
            <div class="message success">
                <p>Your access has been confirmed. The vault <strong>{{.Vault}}</strong> has been authorized.</p>
            </div>
        {{else if .Error}}
            <h1>❌ Verification Failed</h1>
            <div class="message error">
                <p>{{.Error}}</p>
            </div>
        {{else}}
            <h1>🔐 Verify Access Request</h1>
            <div class="info">
                <p><span class="label">Vault:</span> {{.Vault}}</p>
                <p><span class="label">Token:</span> {{.Token}}</p>
                <p><span class="label">Expires:</span> {{.Expire}}</p>
            </div>
            <form method="POST" action="/verify/confirm">
                <input type="hidden" name="vault" value="{{.Vault}}">
                <input type="hidden" name="token" value="{{.Token}}">
                <input type="hidden" name="expire" value="{{.Expire}}">
                <input type="hidden" name="sig" value="{{.Sig}}">
                <button type="submit" class="btn">Confirm Access</button>
            </form>
        {{end}}
    </div>
</body>
</html>`

var tmpl = template.Must(template.New("verify").Parse(htmlTemplate))

type pageData struct {
	Vault   string
	Token   string
	Expire  string
	Sig     string
	Success bool
	Error   string
}

func verifyHMAC(vault, token, expire, sig string) bool {
	if config.HMACSecret == "" {
		log.Println("Warning: HMAC_SECRET not set, skipping verification")
		return true
	}

	data := fmt.Sprintf("vault=%s&token=%s&expire=%s", vault, token, expire)
	mac := hmac.New(sha256.New, []byte(config.HMACSecret))
	mac.Write([]byte(data))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(expectedSig), []byte(sig))
}

func writeApprovalFile(vault, token string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	// Create approval directory: ~/.psw-cli/verify/approved/{vault}/
	approveDir := filepath.Join(homeDir, ".psw-cli", "verify", "approved", vault)
	if err := os.MkdirAll(approveDir, 0700); err != nil {
		return fmt.Errorf("failed to create approval directory: %w", err)
	}

	// Approval expires in 24 hours
	expiresAt := time.Now().Add(24 * time.Hour)

	approval := Approval{
		Vault:      vault,
		Token:      token,
		ApprovedAt: time.Now(),
		ExpiresAt:  expiresAt,
	}

	// Write to {token}.json
	approvalFile := filepath.Join(approveDir, token+".json")
	data, err := json.MarshalIndent(approval, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal approval: %w", err)
	}

	if err := os.WriteFile(approvalFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write approval file: %w", err)
	}

	log.Printf("Approval file written: %s", approvalFile)
	return nil
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	vault := r.URL.Query().Get("vault")
	token := r.URL.Query().Get("token")
	expire := r.URL.Query().Get("expire")
	sig := r.URL.Query().Get("sig")

	if vault == "" || token == "" || expire == "" {
		data := pageData{Error: "Missing required parameters"}
		tmpl.Execute(w, data)
		return
	}

	// Check if token already used
	if _, ok := usedTokens.Load(token); ok {
		data := pageData{Vault: vault, Token: token, Expire: expire, Sig: sig, Error: "Token already used"}
		tmpl.Execute(w, data)
		return
	}

	// Check expiration - expire is Unix timestamp
	expireInt, err := strconv.ParseInt(expire, 10, 64)
	if err != nil {
		data := pageData{Vault: vault, Token: token, Expire: expire, Sig: sig, Error: "Invalid expiration format"}
		tmpl.Execute(w, data)
		return
	}

	expireTime := time.Unix(expireInt, 0)
	if time.Now().After(expireTime) {
		data := pageData{Vault: vault, Token: token, Expire: expire, Sig: sig, Error: "Token has expired"}
		tmpl.Execute(w, data)
		return
	}

	// Verify HMAC signature
	if sig != "" && !verifyHMAC(vault, token, expire, sig) {
		data := pageData{Vault: vault, Token: token, Expire: expire, Sig: sig, Error: "Invalid signature"}
		tmpl.Execute(w, data)
		return
	}

	data := pageData{
		Vault:  vault,
		Token:  token,
		Expire: expire,
		Sig:    sig,
	}
	tmpl.Execute(w, data)
}

func confirmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// Preserve query parameters when redirecting
		http.Redirect(w, r, r.URL.RequestURI(), http.StatusFound)
		return
	}

	r.ParseForm()
	vault := r.Form.Get("vault")
	token := r.Form.Get("token")

	if vault == "" || token == "" {
		data := pageData{Error: "Missing required parameters"}
		tmpl.Execute(w, data)
		return
	}

	// Check if token already used - use Load first, then Store
	if _, ok := usedTokens.Load(token); ok {
		data := pageData{Vault: vault, Token: token, Error: "Token already used"}
		tmpl.Execute(w, data)
		return
	}
	usedTokens.Store(token, usedToken{usedAt: time.Now()})

	// Write approval file
	if err := writeApprovalFile(vault, token); err != nil {
		log.Printf("Failed to write approval file: %v", err)
		data := pageData{Vault: vault, Error: "Failed to create approval"}
		tmpl.Execute(w, data)
		return
	}

	data := pageData{Vault: vault, Success: true}
	tmpl.Execute(w, data)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	// Load configuration
	config = &Config{
		VerificationURL: getEnv("PSW_CLI_VERIFY_URL", "http://localhost:8080"),
		HMACSecret:      getEnv("PSW_CLI_HMAC_SECRET", "psw-cli-default-key-change-in-production"),
	}

	port := getEnv("PORT", "8080")

	// Setup logging
	logDir := os.Getenv("LOG_DIR")
	if logDir != "" {
		logFile := logDir + "/verify-server.log"
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			log.SetOutput(f)
		}
	}
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Printf("Starting verify server on port %s", port)
	log.Printf("Verification URL: %s", config.VerificationURL)

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/verify", verifyHandler)
	r.Post("/verify/confirm", confirmHandler)
	r.Get("/health", healthHandler)

	// Serve static files from current directory for any additional assets
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		// If there are query parameters (verification request), redirect to /verify with them
		// Otherwise just redirect to /verify
		if r.URL.RawQuery != "" {
			http.Redirect(w, r, "/verify?"+r.URL.RawQuery, http.StatusFound)
		} else {
			http.Redirect(w, r, "/verify", http.StatusFound)
		}
	})

	log.Printf("Server started at http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
