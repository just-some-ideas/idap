package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var proxyURL = "http://localhost:8080"

// Session stored in memory (demo only).
type session struct {
	AccessToken string
	IDToken     string
	Sub         string
	Claims      map[string]any
}

var currentSession *session
var pendingState string
var pendingNonce string

func main() {
	if v := os.Getenv("PROXY_URL"); v != "" {
		proxyURL = v
	}
	addr := ":9090"
	if v := os.Getenv("PORT"); v != "" {
		addr = ":" + v
	}

	// Init structured logging
	format := os.Getenv("LOG_FORMAT")
	var handler slog.Handler
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if strings.ToLower(format) == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/clear", handleClear)

	slog.Info("idap-demo listening", "addr", addr, "proxy", proxyURL)
	if err := http.ListenAndServe(addr, nil); err != nil {
		slog.Error("listen failed", "error", err)
		os.Exit(1)
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func callbackURL() string {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9090"
	}
	return fmt.Sprintf("http://localhost:%s/callback", port)
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	tmpl.Execute(w, map[string]any{
		"Page":     "home",
		"ProxyURL": proxyURL,
		"Session":  currentSession,
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	provider, err := oidc.NewProvider(ctx, proxyURL)
	if err != nil {
		renderError(w, "OIDC discovery failed: "+err.Error())
		return
	}

	oauth2Config := &oauth2.Config{
		ClientID:    "idap-demo",
		RedirectURL: callbackURL(),
		Endpoint:    provider.Endpoint(),
		Scopes:      []string{oidc.ScopeOpenID, "pubkey"},
	}

	state := randomHex(16)
	nonce := randomHex(16)
	pendingState = state
	pendingNonce = nonce

	authURL := oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce))
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		renderError(w, "Missing code parameter")
		return
	}
	if pendingState != "" && state != pendingState {
		renderError(w, "Invalid state parameter")
		return
	}

	ctx := r.Context()

	// OIDC discovery
	provider, err := oidc.NewProvider(ctx, proxyURL)
	if err != nil {
		renderError(w, "OIDC discovery failed: "+err.Error())
		return
	}

	oauth2Config := &oauth2.Config{
		ClientID:    "idap-demo",
		RedirectURL: callbackURL(),
		Endpoint:    provider.Endpoint(),
		Scopes:      []string{oidc.ScopeOpenID, "pubkey"},
	}

	// Exchange code for tokens using standard oauth2 library
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		renderError(w, "Token exchange failed: "+err.Error())
		return
	}

	// Extract and verify the ID token using go-oidc
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		renderError(w, "No id_token in token response")
		return
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: "idap-demo"})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		renderError(w, "ID token verification failed: "+err.Error())
		return
	}

	// Verify nonce
	if pendingNonce != "" && idToken.Nonce != pendingNonce {
		renderError(w, "Invalid nonce in ID token")
		return
	}

	// Extract all claims
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		renderError(w, "Failed to parse claims: "+err.Error())
		return
	}

	currentSession = &session{
		AccessToken: token.AccessToken,
		IDToken:     rawIDToken,
		Sub:         idToken.Subject,
		Claims:      claims,
	}
	pendingState = ""
	pendingNonce = ""

	slog.Info("callback received", "sub", idToken.Subject)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleClear(w http.ResponseWriter, r *http.Request) {
	slog.Info("session cleared")
	currentSession = nil
	pendingState = ""
	pendingNonce = ""
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func renderError(w http.ResponseWriter, msg string) {
	tmpl.Execute(w, map[string]any{
		"Page":     "error",
		"ProxyURL": proxyURL,
		"Error":    msg,
	})
}

var tmpl = template.Must(template.New("").Funcs(template.FuncMap{
	"truncateKey": func(s string) string {
		if len(s) > 12 {
			return s[:8] + "..."
		}
		return s
	},
}).Parse(pageHTML))

const pageHTML = `{{define ""}}<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IDAP Demo Client</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #0a0a0a; color: #e0e0e0;
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
  }
  .card {
    background: #141414; border: 1px solid #2a2a2a; border-radius: 12px;
    padding: 40px; max-width: 520px; width: 100%; margin: 20px;
  }
  .logo { font-size: 14px; font-weight: 600; letter-spacing: 2px; text-transform: uppercase; color: #666; margin-bottom: 8px; }
  h1 { font-size: 24px; font-weight: 600; margin-bottom: 24px; color: #fff; }
  .btn {
    display: inline-block; padding: 12px 24px; border: none; border-radius: 8px;
    font-size: 14px; font-weight: 600; cursor: pointer; text-decoration: none;
    transition: background 0.2s; text-align: center; width: 100%;
  }
  .btn-primary { background: #4a9eff; color: #fff; }
  .btn-primary:hover { background: #3a8eef; }
  .btn-danger { background: #333; color: #ccc; }
  .btn-danger:hover { background: #444; }
  .success-badge {
    display: inline-block; background: #1a3a1a; color: #4caf50;
    border: 1px solid #2a4a2a; padding: 4px 12px; border-radius: 20px;
    font-size: 13px; font-weight: 600; margin-bottom: 16px;
  }
  .claim-row {
    display: flex; justify-content: space-between; padding: 8px 0;
    border-bottom: 1px solid #1a1a1a; font-size: 14px;
  }
  .claim-key { color: #888; }
  .claim-val { color: #fff; font-weight: 500; font-family: monospace; }
  .token-section { margin-top: 20px; }
  .token-section h3 {
    font-size: 13px; font-weight: 600; color: #4a9eff; margin-bottom: 8px;
    text-transform: uppercase; letter-spacing: 1px;
  }
  .jwt-box {
    background: #0a0a0a; border: 1px solid #222; border-radius: 8px; padding: 12px;
    font-family: monospace; font-size: 12px; word-break: break-all; color: #888;
    margin-bottom: 16px; max-height: 120px; overflow-y: auto;
  }
  .error-box {
    background: #2a1a1a; border: 1px solid #4a2a2a; border-radius: 8px;
    padding: 16px; color: #e06c75; font-size: 14px; margin-bottom: 20px;
  }
  .divider { border: none; border-top: 1px solid #222; margin: 20px 0; }
  .footer { margin-top: 24px; text-align: center; font-size: 12px; color: #444; }
  .sub-text { font-size: 13px; color: #555; margin-top: 12px; text-align: center; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">IDAP Demo</div>

  {{if eq .Page "home"}}
    {{if and .Session .Session.AccessToken}}
      <h1>Connected</h1>
      <span class="success-badge">Authenticated</span>
      <div class="claim-row">
        <span class="claim-key">Identity</span>
        <span class="claim-val">{{truncateKey .Session.Sub}}</span>
      </div>
      <div class="claim-row">
        <span class="claim-key">Token Type</span>
        <span class="claim-val">Bearer</span>
      </div>
      <div class="token-section">
        <h3>JWT Claims</h3>
        {{range $k, $v := .Session.Claims}}
        <div class="claim-row">
          <span class="claim-key">{{$k}}</span>
          <span class="claim-val">{{$v}}</span>
        </div>
        {{end}}
      </div>
      <div class="token-section">
        <h3>ID Token (JWT)</h3>
        <div class="jwt-box">{{.Session.IDToken}}</div>
      </div>
      <hr class="divider">
      <form action="/clear" method="post">
        <button type="submit" class="btn btn-danger">Clear Session</button>
      </form>
    {{else}}
      <h1>Sign In with IDAP</h1>
      <p style="color:#888; font-size:14px; margin-bottom:20px;">
        Click below to authenticate using your IDAP identity.
      </p>
      <a href="/login" class="btn btn-primary">Sign In with IDAP</a>
      <div class="sub-text">Proxy: {{.ProxyURL}}</div>
    {{end}}

  {{else if eq .Page "error"}}
    <h1>Error</h1>
    <div class="error-box">{{.Error}}</div>
    <a href="/" class="btn btn-primary">Back</a>
  {{end}}

  <div class="footer">idap-demo-client &middot; testing only</div>
</div>
</body>
</html>{{end}}`
