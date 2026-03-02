package handlers

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/idap/proxy/internal/auth"
	"github.com/idap/proxy/internal/db"

	"github.com/google/uuid"
)

// Server holds shared state for all handlers.
type Server struct {
	DB          *sql.DB
	ProviderKey *db.ProviderKey
	Host        string
	DevMode     bool
	Logger      *slog.Logger
	wsUpgrader  websocket.Upgrader
	wsConns     map[string]*websocket.Conn
	wsConnsMu   sync.RWMutex
}

func NewServer(database *sql.DB, providerKey *db.ProviderKey, host string, devMode bool, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	return &Server{DB: database, ProviderKey: providerKey, Host: host, DevMode: devMode, Logger: logger, wsUpgrader: upgrader, wsConns: make(map[string]*websocket.Conn)}
}

// Router returns an http.ServeMux wired to all handlers.
func (s *Server) Router() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)

	// Keys — {pubkey} is base64url-encoded Ed25519 public key
	mux.HandleFunc("PUT /keys/{pubkey}", s.handlePutKey)
	mux.HandleFunc("GET /keys/{pubkey}", s.handleGetKey)
	mux.HandleFunc("GET /jwks", s.handleJWKS)

	// Discovery
	mux.HandleFunc("GET /.well-known/idap-configuration", s.handleIDAPConfig)
	mux.HandleFunc("GET /.well-known/openid-configuration", s.handleOIDCDiscovery)

	// Inbox
	mux.HandleFunc("POST /inbox/{pubkey}", s.handleInboxPost)
	mux.HandleFunc("GET /inbox/{pubkey}", s.handleInboxGet)
	mux.HandleFunc("GET /inbox/{pubkey}/{messageId}/payload", s.handleInboxPayload)
	mux.HandleFunc("DELETE /inbox/{pubkey}/{messageId}", s.handleInboxDelete)

	// Access codes
	mux.HandleFunc("POST /inbox/{pubkey}/access-code", s.handleAccessCodeCreate)
	mux.HandleFunc("GET /inbox/resolve/{code}", s.handleAccessCodeResolve)

	// Profile
	// Profile endpoints removed — no current use case for public profile storage

	// Auth
	mux.HandleFunc("POST /auth/login-code", s.handleLoginCode)
	mux.HandleFunc("GET /auth/authorize", s.handleOIDCAuthorizePage)
	mux.HandleFunc("POST /auth/authorize", s.handleOIDCAuthorizeSubmit)
	mux.HandleFunc("GET /auth/authorize/poll/{id}", s.handleOIDCAuthorizePoll)
	mux.HandleFunc("GET /ws", s.handleOIDCWebSocket)
	mux.HandleFunc("POST /auth/token", s.handleOIDCToken)
	mux.HandleFunc("GET /auth/userinfo", s.handleOIDCUserinfo)

	// Recovery shards
	mux.HandleFunc("POST /recovery/shard/{pubkey}", s.handleShardPost)
	mux.HandleFunc("GET /recovery/shard/{pubkey}/{id}", s.handleShardGet)

	// Migration
	mux.HandleFunc("GET /migration/{pubkey}", s.handleMigrationGet)
	mux.HandleFunc("POST /migration/{pubkey}", s.handleMigrationPost)

	return mux
}

// ---- helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// pubkeyFromPath extracts the public key from a URL path segment.
// Path segments use base64url encoding; DB/headers use standard base64.
func pubkeyFromPath(r *http.Request) string {
	return b64urlToStd(r.PathValue("pubkey"))
}

// b64urlToStd converts base64url (no padding) to standard base64.
func b64urlToStd(s string) string {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// Maybe it's already standard base64
		return s
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// stdToB64url converts standard base64 to base64url (no padding).
func stdToB64url(s string) string {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return s
		}
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---- health ----

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ---- keys ----

func (s *Server) handlePutKey(w http.ResponseWriter, r *http.Request) {
	pubkey := pubkeyFromPath(r)

	var bundle auth.KeyBundle
	if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if bundle.SigningKey.Key == "" || bundle.AgreementKey.Key == "" {
		writeError(w, http.StatusBadRequest, "signing_key and agreement_key required")
		return
	}
	if bundle.SigningKey.Kty != "ed25519" {
		writeError(w, http.StatusBadRequest, "signing_key.kty must be ed25519")
		return
	}
	if bundle.AgreementKey.Kty != "x25519" {
		writeError(w, http.StatusBadRequest, "agreement_key.kty must be x25519")
		return
	}

	// Verify signing_key matches the URL pubkey (both are the Ed25519 public key)
	sigKeyBytes, err := bundle.SigningKey.Decode()
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid signing_key")
		return
	}
	// pubkey is standard base64; compare raw bytes
	pubkeyBytes, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		pubkeyBytes, err = base64.RawStdEncoding.DecodeString(pubkey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid pubkey")
			return
		}
	}
	if !bytesEqual(sigKeyBytes, pubkeyBytes) {
		writeError(w, http.StatusBadRequest, "signing_key must match URL pubkey")
		return
	}

	// Check if user already exists — if so, verify signature
	var existing string
	err = s.DB.QueryRow(`SELECT pubkey_bundle FROM users WHERE pubkey = ?`, pubkey).Scan(&existing)
	if err != nil && err != sql.ErrNoRows {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if err == nil {
		// Existing user: require signature
		if _, sigErr := auth.VerifyRequestSignature(r, s.DB); sigErr != nil {
			writeError(w, http.StatusUnauthorized, sigErr.Error())
			return
		}
	}

	bundleJSON, _ := json.Marshal(bundle)
	_, err = s.DB.Exec(
		`INSERT INTO users(pubkey, pubkey_bundle, signing_key) VALUES(?,?,?) ON CONFLICT(pubkey) DO UPDATE SET pubkey_bundle=excluded.pubkey_bundle, signing_key=excluded.signing_key`,
		pubkey, string(bundleJSON), bundle.SigningKey.Key,
	)
	if err != nil {
		s.Logger.Error("failed to register user", "pubkey", pubkey[:8], "error", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.Logger.Info("user registered", "pubkey", pubkey[:8])
	writeJSON(w, http.StatusCreated, map[string]string{"pubkey": pubkey})
}

func (s *Server) handleGetKey(w http.ResponseWriter, r *http.Request) {
	pubkey := pubkeyFromPath(r)
	var bundleJSON string
	err := s.DB.QueryRow(`SELECT pubkey_bundle FROM users WHERE pubkey = ?`, pubkey).Scan(&bundleJSON)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	var bundle auth.KeyBundle
	_ = json.Unmarshal([]byte(bundleJSON), &bundle)
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	pk := s.ProviderKey
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": pk.KID,
				"n":   base64.RawURLEncoding.EncodeToString(pk.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pk.PublicKey.E)).Bytes()),
			},
		},
	}
	writeJSON(w, http.StatusOK, jwks)
}

// ---- discovery ----

func (s *Server) handleIDAPConfig(w http.ResponseWriter, r *http.Request) {
	host := s.Host
	if host == "" {
		host = "http://" + r.Host
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"issuer":                 host,
		"protocol_version":       "1",
		"authorization_endpoint": host + "/auth/authorize",
		"jwks_uri":               host + "/jwks",
		"key_endpoint":           host + "/keys",
		"inbox_endpoint":         host + "/inbox",
		"recovery_endpoint":      host + "/recovery",
	})
}

func (s *Server) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	host := s.Host
	if host == "" {
		host = "http://" + r.Host
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                host,
		"authorization_endpoint":                host + "/auth/authorize",
		"token_endpoint":                        host + "/auth/token",
		"userinfo_endpoint":                     host + "/auth/userinfo",
		"jwks_uri":                              host + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"grant_types_supported":                 []string{"authorization_code"},
		"response_modes_supported":              []string{"query"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "pubkey"},
	})
}

// ---- inbox ----

func (s *Server) handleInboxPost(w http.ResponseWriter, r *http.Request) {
	recipient := pubkeyFromPath(r)

	var body struct {
		Header      string `json:"header"`
		Payload     string `json:"payload"`
		AccessCode  string `json:"access_code"`
		AccessProof string `json:"access_proof"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.Header == "" {
		writeError(w, http.StatusBadRequest, "header required")
		return
	}

	// Access control: require access_code or access_proof
	if body.AccessCode == "" && body.AccessProof == "" {
		writeError(w, http.StatusForbidden, "access_code or access_proof required")
		return
	}
	if body.AccessCode != "" {
		var codeExpiresAt int64
		var used int
		var codePubkey string
		err := s.DB.QueryRow(
			`SELECT pubkey, expires_at, used FROM access_codes WHERE code = ?`, body.AccessCode,
		).Scan(&codePubkey, &codeExpiresAt, &used)
		if err == sql.ErrNoRows {
			writeError(w, http.StatusForbidden, "invalid access code")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "db error")
			return
		}
		if used != 0 {
			writeError(w, http.StatusForbidden, "access code already used")
			return
		}
		if time.Now().Unix() > codeExpiresAt {
			writeError(w, http.StatusForbidden, "access code expired")
			return
		}
		// Mark code as used
		_, _ = s.DB.Exec(`UPDATE access_codes SET used = 1 WHERE code = ?`, body.AccessCode)
	}
	// If access_proof is present (non-empty), accept it for now

	id := uuid.New().String()
	now := time.Now().Unix()
	ttl := int64(30 * 24 * 60 * 60) // 30 days

	var payloadVal any
	if body.Payload != "" {
		payloadVal = body.Payload
	}

	_, err := s.DB.Exec(
		`INSERT INTO inbox(id, recipient, header, payload, delivered_at, expires_at) VALUES(?,?,?,?,?,?)`,
		id, recipient, body.Header, payloadVal, now, now+ttl,
	)
	if err != nil {
		s.Logger.Error("inbox insert failed", "recipient", recipient[:8], "error", err)
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	s.Logger.Info("message delivered", "id", id, "recipient", recipient[:8])
	_ = s.pushToPubkey(recipient, map[string]string{
		"type":   "inbox_message",
		"id":     id,
		"header": body.Header,
	})
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (s *Server) handleInboxGet(w http.ResponseWriter, r *http.Request) {
	pubkey := pubkeyFromPath(r)

	authedKey, err := auth.VerifyRequestSignature(r, s.DB)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if authedKey != pubkey {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	rows, err := s.DB.Query(
		`SELECT id, header, delivered_at FROM inbox WHERE recipient = ? AND expires_at > ? ORDER BY delivered_at ASC`,
		pubkey, time.Now().Unix(),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	type msg struct {
		ID          string `json:"id"`
		Header      string `json:"header"`
		DeliveredAt int64  `json:"delivered_at"`
	}
	var messages []msg
	for rows.Next() {
		var m msg
		if err := rows.Scan(&m.ID, &m.Header, &m.DeliveredAt); err != nil {
			continue
		}
		messages = append(messages, m)
	}
	if messages == nil {
		messages = []msg{}
	}
	writeJSON(w, http.StatusOK, messages)
}

func (s *Server) handleInboxPayload(w http.ResponseWriter, r *http.Request) {
	pubkey := pubkeyFromPath(r)
	messageID := r.PathValue("messageId")

	authedKey, err := auth.VerifyRequestSignature(r, s.DB)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if authedKey != pubkey {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var payload sql.NullString
	var recipient string
	err = s.DB.QueryRow(
		`SELECT recipient, payload FROM inbox WHERE id = ?`, messageID,
	).Scan(&recipient, &payload)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if recipient != pubkey {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if !payload.Valid {
		writeJSON(w, http.StatusOK, map[string]any{"payload": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"payload": payload.String})
}

func (s *Server) handleInboxDelete(w http.ResponseWriter, r *http.Request) {
	pubkey := pubkeyFromPath(r)
	messageID := r.PathValue("messageId")

	authedKey, err := auth.VerifyRequestSignature(r, s.DB)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if authedKey != pubkey {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	// Verify ownership
	var recipient string
	err = s.DB.QueryRow(`SELECT recipient FROM inbox WHERE id = ?`, messageID).Scan(&recipient)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if recipient != pubkey {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	_, err = s.DB.Exec(`DELETE FROM inbox WHERE id = ?`, messageID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- access codes ----

func (s *Server) handleAccessCodeCreate(w http.ResponseWriter, r *http.Request) {
	pubkey := pubkeyFromPath(r)

	authedKey, err := auth.VerifyRequestSignature(r, s.DB)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if authedKey != pubkey {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	code := generateLoginCode()
	expiresAt := time.Now().Unix() + 300

	_, err = s.DB.Exec(
		`INSERT INTO access_codes(code, pubkey, expires_at) VALUES(?,?,?)`,
		code, pubkey, expiresAt,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}

	s.Logger.Info("access code generated", "pubkey", pubkey[:8])
	writeJSON(w, http.StatusCreated, map[string]any{
		"code":       code,
		"expires_in": 300,
	})
}

func (s *Server) handleAccessCodeResolve(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")

	var pubkey string
	var expiresAt int64
	var used int
	err := s.DB.QueryRow(
		`SELECT pubkey, expires_at, used FROM access_codes WHERE code = ?`, code,
	).Scan(&pubkey, &expiresAt, &used)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "code not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if used != 0 {
		writeError(w, http.StatusNotFound, "code not found")
		return
	}
	if time.Now().Unix() > expiresAt {
		writeError(w, http.StatusNotFound, "code not found")
		return
	}

	// Look up user's key bundle
	var bundleJSON string
	err = s.DB.QueryRow(`SELECT pubkey_bundle FROM users WHERE pubkey = ?`, pubkey).Scan(&bundleJSON)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}

	var bundle auth.KeyBundle
	_ = json.Unmarshal([]byte(bundleJSON), &bundle)

	writeJSON(w, http.StatusOK, map[string]any{
		"pubkey":     pubkey,
		"key_bundle": bundle,
	})
}

// ---- WebSocket connection registry ----

func (s *Server) registerWSConn(pubkey string, conn *websocket.Conn) {
	s.wsConnsMu.Lock()
	defer s.wsConnsMu.Unlock()
	s.wsConns[pubkey] = conn
}

func (s *Server) deregisterWSConn(pubkey string, conn *websocket.Conn) {
	s.wsConnsMu.Lock()
	defer s.wsConnsMu.Unlock()
	if s.wsConns[pubkey] == conn {
		delete(s.wsConns, pubkey)
	}
}

func (s *Server) pushToPubkey(pubkey string, msg any) error {
	s.wsConnsMu.RLock()
	conn := s.wsConns[pubkey]
	s.wsConnsMu.RUnlock()
	if conn == nil {
		return fmt.Errorf("no ws connection for %s", pubkey[:8])
	}
	return conn.WriteJSON(msg)
}

// ---- OIDC ----

// loginCodeAlphabet excludes ambiguous characters 0/O/1/I
const loginCodeAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

func generateLoginCode() string {
	b := make([]byte, 6)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(loginCodeAlphabet))))
		b[i] = loginCodeAlphabet[n.Int64()]
	}
	return string(b[:3]) + "-" + string(b[3:])
}

func (s *Server) handleLoginCode(w http.ResponseWriter, r *http.Request) {
	pubkey, err := auth.VerifyRequestSignature(r, s.DB)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	code := generateLoginCode()
	expiresAt := time.Now().Unix() + 300

	_, err = s.DB.Exec(
		`INSERT INTO access_codes(code, pubkey, expires_at) VALUES(?,?,?)`,
		code, pubkey, expiresAt,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}

	s.Logger.Info("login code generated", "pubkey", pubkey[:8])
	writeJSON(w, http.StatusCreated, map[string]any{
		"code":       code,
		"expires_in": 300,
	})
}

// ---- HTML templates for browser-based OIDC authorize flow ----

var authorizePageTmpl = template.Must(template.New("authorize").Parse(authorizePageHTML))
var authorizeWaitingTmpl = template.Must(template.New("waiting").Parse(authorizeWaitingHTML))

const authorizePageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign In — IDAP</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #0a0a0a; color: #e0e0e0;
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
  }
  .card {
    background: #141414; border: 1px solid #2a2a2a; border-radius: 12px;
    padding: 40px; max-width: 480px; width: 100%; margin: 20px;
  }
  .logo { font-size: 14px; font-weight: 600; letter-spacing: 2px; text-transform: uppercase; color: #666; margin-bottom: 8px; }
  h1 { font-size: 24px; font-weight: 600; margin-bottom: 24px; color: #fff; }
  label { display: block; font-size: 13px; font-weight: 500; color: #888; margin-bottom: 6px; }
  input[type="text"] {
    width: 100%; padding: 14px 18px; background: #0a0a0a; border: 1px solid #333;
    border-radius: 8px; color: #fff; font-size: 24px; font-family: monospace;
    letter-spacing: 4px; text-align: center; text-transform: uppercase;
    margin-bottom: 20px; outline: none;
  }
  input[type="text"]:focus { border-color: #4a9eff; }
  .btn {
    display: inline-block; padding: 12px 24px; border: none; border-radius: 8px;
    font-size: 14px; font-weight: 600; cursor: pointer; width: 100%;
    background: #4a9eff; color: #fff; transition: background 0.2s;
  }
  .btn:hover { background: #3a8eef; }
  .hint { color: #888; font-size: 14px; margin-bottom: 20px; }
  .service { color: #4a9eff; font-weight: 600; }
  .error-box { background: #2a1a1a; border: 1px solid #4a2a2a; border-radius: 8px; padding: 16px; color: #e06c75; font-size: 14px; margin-bottom: 20px; }
  .footer { margin-top: 24px; text-align: center; font-size: 12px; color: #444; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">IDAP</div>
  <h1>Sign In</h1>
  {{if .Error}}<div class="error-box">{{.Error}}</div>{{end}}
  <p class="hint">
    <span class="service">{{.ClientID}}</span> wants to verify your identity.<br>
    Open your IDAP app and tap <strong style="color:#ccc">Log In</strong> to get a code.
  </p>
  <form method="post" action="/auth/authorize">
    <label for="code">Login Code</label>
    <input type="text" id="code" name="code" placeholder="XXX-XXX" maxlength="7" autocomplete="off" autofocus>
    <input type="hidden" name="client_id" value="{{.ClientID}}">
    <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
    <input type="hidden" name="nonce" value="{{.Nonce}}">
    <input type="hidden" name="state" value="{{.State}}">
    <input type="hidden" name="response_type" value="code">
    <button type="submit" class="btn">Continue</button>
  </form>
  <div class="footer">Powered by IDAP</div>
</div>
</body>
</html>`

const authorizeWaitingHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Confirm — IDAP</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #0a0a0a; color: #e0e0e0;
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
  }
  .card {
    background: #141414; border: 1px solid #2a2a2a; border-radius: 12px;
    padding: 40px; max-width: 480px; width: 100%; margin: 20px; text-align: center;
  }
  .logo { font-size: 14px; font-weight: 600; letter-spacing: 2px; text-transform: uppercase; color: #666; margin-bottom: 8px; }
  h1 { font-size: 24px; font-weight: 600; margin-bottom: 16px; color: #fff; }
  .spinner {
    display: inline-block; width: 32px; height: 32px;
    border: 3px solid #333; border-top-color: #4a9eff; border-radius: 50%;
    animation: spin 0.8s linear infinite; margin: 16px 0;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  #status { color: #666; font-size: 14px; margin-top: 8px; }
  .footer { margin-top: 24px; font-size: 12px; color: #444; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">IDAP</div>
  <h1>Confirm on Your Device</h1>
  <div class="spinner"></div>
  <div id="status">Waiting for approval...</div>
  <div class="footer">Powered by IDAP</div>
</div>
<script>
(function() {
  var pollURL = "{{.PollURL}}";
  var interval = setInterval(function() {
    fetch(pollURL).then(function(r) { return r.json(); }).then(function(data) {
      if (data.status === "approved" && data.redirect) {
        clearInterval(interval);
        window.location.href = data.redirect;
      } else if (data.status === "expired") {
        clearInterval(interval);
        document.getElementById("status").innerHTML = '<span style="color:#e06c75">Session expired. Please try again.</span>';
      }
    }).catch(function() {});
  }, 1500);
})();
</script>
</body>
</html>`

// handleOIDCAuthorizePage serves the HTML code input form (GET /auth/authorize).
func (s *Server) handleOIDCAuthorizePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	nonce := q.Get("nonce")
	state := q.Get("state")

	if clientID == "" || redirectURI == "" || nonce == "" {
		writeError(w, http.StatusBadRequest, "client_id, redirect_uri, nonce required")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	authorizePageTmpl.Execute(w, map[string]string{
		"ClientID":    clientID,
		"RedirectURI": redirectURI,
		"Nonce":       nonce,
		"State":       state,
	})
}

// handleOIDCAuthorizeSubmit processes the code form submission (POST /auth/authorize).
func (s *Server) handleOIDCAuthorizeSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form")
		return
	}

	code := strings.ToUpper(r.FormValue("code"))
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	nonce := r.FormValue("nonce")
	state := r.FormValue("state")

	if code == "" || clientID == "" || redirectURI == "" || nonce == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		authorizePageTmpl.Execute(w, map[string]string{
			"ClientID":    clientID,
			"RedirectURI": redirectURI,
			"Nonce":       nonce,
			"State":       state,
			"Error":       "Login code is required.",
		})
		return
	}

	// Look up and validate access code
	var pubkey string
	var codeExpiresAt int64
	var used int
	err := s.DB.QueryRow(
		`SELECT pubkey, expires_at, used FROM access_codes WHERE code = ?`, code,
	).Scan(&pubkey, &codeExpiresAt, &used)
	if err == sql.ErrNoRows {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		authorizePageTmpl.Execute(w, map[string]string{
			"ClientID":    clientID,
			"RedirectURI": redirectURI,
			"Nonce":       nonce,
			"State":       state,
			"Error":       "Invalid code. Please try again.",
		})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if used != 0 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		authorizePageTmpl.Execute(w, map[string]string{
			"ClientID":    clientID,
			"RedirectURI": redirectURI,
			"Nonce":       nonce,
			"State":       state,
			"Error":       "Code already used. Generate a new one.",
		})
		return
	}
	if time.Now().Unix() > codeExpiresAt {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		authorizePageTmpl.Execute(w, map[string]string{
			"ClientID":    clientID,
			"RedirectURI": redirectURI,
			"Nonce":       nonce,
			"State":       state,
			"Error":       "Code expired. Generate a new one.",
		})
		return
	}

	// Mark code as used
	_, _ = s.DB.Exec(`UPDATE access_codes SET used = 1 WHERE code = ?`, code)

	sessionID := uuid.New().String()
	expiresAt := time.Now().Unix() + 120

	_, err = s.DB.Exec(
		`INSERT INTO oidc_sessions(id, pubkey, service, nonce, number_match, redirect_uri, state, expires_at) VALUES(?,?,?,?,?,?,?,?)`,
		sessionID, pubkey, clientID, nonce, 0, redirectURI, state, expiresAt,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}

	// Push auth request to app via WebSocket
	pushPayload := map[string]any{
		"type":               "auth_request",
		"requestId":          sessionID,
		"service":            clientID,
		"serviceDisplayName": clientID,
		"nonce":              nonce,
		"expiresAt":          expiresAt,
	}
	s.Logger.Info("oidc session created", "session_id", sessionID, "pubkey", pubkey[:8], "service", clientID)
	if err := s.pushToPubkey(pubkey, pushPayload); err != nil {
		s.Logger.Warn("ws push failed (user not connected)", "pubkey", pubkey[:8], "error", err)
	}

	host := s.Host
	if host == "" {
		host = "http://" + r.Host
	}
	pollURL := host + "/auth/authorize/poll/" + sessionID

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	authorizeWaitingTmpl.Execute(w, map[string]any{
		"PollURL": pollURL,
	})
}

// handleOIDCAuthorizePoll returns the session status as JSON (GET /auth/authorize/poll/{id}).
func (s *Server) handleOIDCAuthorizePoll(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("id")

	var approved int
	var expiresAt int64
	var redirectURI, state string
	err := s.DB.QueryRow(
		`SELECT approved, expires_at, redirect_uri, state FROM oidc_sessions WHERE id = ?`,
		sessionID,
	).Scan(&approved, &expiresAt, &redirectURI, &state)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"status": "not_found"})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}

	if approved != 0 {
		// Build redirect URL
		u, _ := url.Parse(redirectURI)
		q := u.Query()
		q.Set("code", sessionID)
		if state != "" {
			q.Set("state", state)
		}
		u.RawQuery = q.Encode()
		writeJSON(w, http.StatusOK, map[string]string{"status": "approved", "redirect": u.String()})
		return
	}

	if time.Now().Unix() > expiresAt {
		writeJSON(w, http.StatusOK, map[string]string{"status": "expired"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "waiting"})
}

func (s *Server) handleOIDCWebSocket(w http.ResponseWriter, r *http.Request) {
	// Authenticate via request signature headers (available during WS handshake)
	pubkey, err := auth.VerifyRequestSignature(r, s.DB)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	conn, err := s.wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		s.Logger.Error("ws upgrade failed", "pubkey", pubkey[:8], "error", err)
		return
	}
	defer func() {
		s.deregisterWSConn(pubkey, conn)
		s.Logger.Info("ws disconnected", "pubkey", pubkey[:8])
		conn.Close()
	}()

	s.registerWSConn(pubkey, conn)
	s.Logger.Info("ws connected", "pubkey", pubkey[:8])

	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			return
		}

		var msg map[string]any
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			continue
		}

		msgType, _ := msg["type"].(string)
		if msgType != "auth_assertion" {
			continue
		}

		requestID, _ := msg["requestId"].(string)
		jwt, _ := msg["jwt"].(string)
		if requestID == "" || jwt == "" {
			continue
		}

		// Look up session and verify
		var sessionPubkey, sessionNonce string
		var expiresAt int64
		err = s.DB.QueryRow(
			`SELECT pubkey, nonce, expires_at FROM oidc_sessions WHERE id = ?`,
			requestID,
		).Scan(&sessionPubkey, &sessionNonce, &expiresAt)
		if err != nil {
			_ = conn.WriteJSON(map[string]string{"type": "error", "message": "session not found"})
			continue
		}

		if time.Now().Unix() > expiresAt {
			_ = conn.WriteJSON(map[string]string{"type": "auth_expired"})
			continue
		}

		// Verify the JWT signature against the user's public key
		if err := verifyAssertionJWT(s.DB, sessionPubkey, jwt); err != nil {
			_ = conn.WriteJSON(map[string]string{"type": "error", "message": "invalid assertion"})
			continue
		}

		_, _ = s.DB.Exec(
			`UPDATE oidc_sessions SET approved = 1, signed_assertion = ? WHERE id = ?`,
			jwt, requestID,
		)
		_ = conn.WriteJSON(map[string]string{"type": "auth_approved", "code": requestID})
	}
}

// verifyAssertionJWT verifies an Ed25519-signed JWT against the stored public key.
func verifyAssertionJWT(db *sql.DB, pubkeyB64, jwtStr string) error {
	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format")
	}

	// Verify the user exists
	var exists int
	err := db.QueryRow(`SELECT 1 FROM users WHERE pubkey = ?`, pubkeyB64).Scan(&exists)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// The pubkey column is the Ed25519 signing key — use it directly
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubkeyB64)
	if err != nil {
		pubKeyBytes, err = base64.RawStdEncoding.DecodeString(pubkeyB64)
		if err != nil {
			return fmt.Errorf("invalid public key")
		}
	}

	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}

	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), []byte(signingInput), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// mintIDToken creates a provider-signed RS256 JWT for the given user.
func (s *Server) mintIDToken(pubkey, service, nonce, sessionID, issuer string) (string, error) {
	now := time.Now()
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": s.ProviderKey.KID,
	}
	payload := map[string]any{
		"iss":            issuer,
		"sub":            pubkey,
		"aud":            service,
		"nonce":          nonce,
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
		"request_id":     sessionID,
		"idap_pubkey":    pubkey,
		"idap_algorithm": "EdDSA",
		"idap_inbox":     issuer + "/inbox",
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.ProviderKey.PrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *Server) handleOIDCToken(w http.ResponseWriter, r *http.Request) {
	var grantType, code, clientID string

	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "invalid form")
			return
		}
		grantType = r.FormValue("grant_type")
		code = r.FormValue("code")
		clientID = r.FormValue("client_id")
	} else {
		var body struct {
			GrantType string `json:"grant_type"`
			Code      string `json:"code"`
			ClientID  string `json:"client_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid body")
			return
		}
		grantType = body.GrantType
		code = body.Code
		clientID = body.ClientID
	}
	_ = grantType
	_ = clientID
	if code == "" {
		writeError(w, http.StatusBadRequest, "code required")
		return
	}

	var pubkey, service, nonce string
	var approved int
	var expiresAt int64
	err := s.DB.QueryRow(
		`SELECT pubkey, service, nonce, approved, expires_at FROM oidc_sessions WHERE id = ?`,
		code,
	).Scan(&pubkey, &service, &nonce, &approved, &expiresAt)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusBadRequest, "invalid code")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	if approved == 0 {
		writeError(w, http.StatusBadRequest, "session not approved")
		return
	}
	if time.Now().Unix() > expiresAt+60 { // small grace period after approval
		writeError(w, http.StatusBadRequest, "session expired")
		return
	}

	// Use client_id from request if provided, otherwise fall back to session service
	if clientID != "" {
		service = clientID
	}

	issuer := s.Host
	if issuer == "" {
		issuer = "http://" + r.Host
	}

	idToken, err := s.mintIDToken(pubkey, service, nonce, code, issuer)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to mint token")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": idToken,
		"id_token":     idToken,
		"token_type":   "Bearer",
		"sub":          pubkey,
	})
}

func (s *Server) handleOIDCUserinfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "bearer token required")
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	// Verify RS256 signature against provider key
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	hash := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(s.ProviderKey.PublicKey, crypto.SHA256, hash[:], sig); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token signature")
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	sub, _ := claims["sub"].(string)
	writeJSON(w, http.StatusOK, map[string]string{"sub": sub})
}

// ---- recovery shards ----

func (s *Server) handleShardPost(w http.ResponseWriter, r *http.Request) {
	pubkey := pubkeyFromPath(r)

	authedKey, err := auth.VerifyRequestSignature(r, s.DB)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if authedKey != pubkey {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var body struct {
		ID   string `json:"id"`
		Blob string `json:"blob"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if body.ID == "" || body.Blob == "" {
		writeError(w, http.StatusBadRequest, "id and blob required")
		return
	}

	_, err = s.DB.Exec(
		`INSERT INTO shards(id, pubkey, encrypted_blob) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET encrypted_blob=excluded.encrypted_blob, updated_at=unixepoch()`,
		body.ID, pubkey, body.Blob,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": body.ID})
}

func (s *Server) handleShardGet(w http.ResponseWriter, r *http.Request) {
	pubkey := pubkeyFromPath(r)
	shardID := r.PathValue("id")

	// Timed code verification
	code := r.Header.Get("X-IDAP-Timed-Code")
	nonce := r.Header.Get("X-IDAP-Code-Nonce")
	tsStr := r.Header.Get("X-IDAP-Code-Timestamp")
	sigB64 := r.Header.Get("X-IDAP-Code-Signature")

	if code == "" || nonce == "" || tsStr == "" || sigB64 == "" {
		writeError(w, http.StatusUnauthorized, "timed code headers required")
		return
	}

	// Check nonce not already used
	var used int
	_ = s.DB.QueryRow(`SELECT 1 FROM used_nonces WHERE nonce = ?`, nonce).Scan(&used)
	if used != 0 {
		writeError(w, http.StatusForbidden, "nonce already used")
		return
	}

	// Validate timestamp (15 min window)
	var ts int64
	if _, err := fmt.Sscanf(tsStr, "%d", &ts); err != nil {
		writeError(w, http.StatusBadRequest, "invalid timestamp")
		return
	}
	now := time.Now().Unix()
	if now-ts > 15*60 {
		writeError(w, http.StatusForbidden, "code expired")
		return
	}

	// The shard holder (a contact) signs the code — look up their key
	// Header X-IDAP-Holder-Key identifies who generated the code (base64 pubkey)
	holderKey := r.Header.Get("X-IDAP-Holder-Key")
	if holderKey == "" {
		// Fall back: the user themselves is retrieving their own shard
		holderKey = pubkey
	}

	// Verify holder exists
	var holderExists int
	err := s.DB.QueryRow(`SELECT 1 FROM users WHERE pubkey = ?`, holderKey).Scan(&holderExists)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "holder not found")
		return
	}

	// holderKey is the Ed25519 signing key (stored in pubkey column) — use it directly
	pubKeyBytes, err := base64.StdEncoding.DecodeString(holderKey)
	if err != nil {
		pubKeyBytes, _ = base64.RawStdEncoding.DecodeString(holderKey)
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		sig, _ = base64.RawStdEncoding.DecodeString(sigB64)
	}

	message := fmt.Sprintf("%s:%s:%s", shardID, tsStr, nonce)
	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), []byte(message), sig) {
		writeError(w, http.StatusForbidden, "invalid signature")
		return
	}

	// Mark nonce as used
	_, _ = s.DB.Exec(`INSERT INTO used_nonces(nonce) VALUES(?)`, nonce)

	// Return shard
	var blob string
	err = s.DB.QueryRow(`SELECT encrypted_blob FROM shards WHERE id = ? AND pubkey = ?`, shardID, pubkey).Scan(&blob)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "shard not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": shardID, "blob": blob})
}

// ---- migration ----

func (s *Server) handleMigrationGet(w http.ResponseWriter, r *http.Request) {
	pubkey := pubkeyFromPath(r)
	var record string
	err := s.DB.QueryRow(`SELECT signed_record FROM migrations WHERE pubkey = ?`, pubkey).Scan(&record)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "no migration record")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, record)
}

func (s *Server) handleMigrationPost(w http.ResponseWriter, r *http.Request) {
	pubkey := pubkeyFromPath(r)

	authedKey, err := auth.VerifyRequestSignature(r, s.DB)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if authedKey != pubkey {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var record map[string]any
	if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	// Verify the migration record signature
	sigRaw, hasSig := record["signature"]
	if !hasSig {
		writeError(w, http.StatusUnprocessableEntity, "missing signature")
		return
	}
	sigB64, _ := sigRaw.(string)

	// Build the canonical signing input (everything except signature field)
	recordWithoutSig := make(map[string]any)
	for k, v := range record {
		if k != "signature" {
			recordWithoutSig[k] = v
		}
	}
	canonical, _ := json.Marshal(recordWithoutSig)

	// pubkey is the Ed25519 signing key — use it directly for signature verification
	pubKeyBytes, err2 := base64.StdEncoding.DecodeString(pubkey)
	if err2 != nil {
		pubKeyBytes, _ = base64.RawStdEncoding.DecodeString(pubkey)
	}
	sig, _ := base64.StdEncoding.DecodeString(sigB64)

	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), canonical, sig) {
		writeError(w, http.StatusUnprocessableEntity, "invalid signature")
		return
	}

	recordJSON, _ := json.Marshal(record)
	_, err = s.DB.Exec(
		`INSERT INTO migrations(pubkey, signed_record) VALUES(?,?) ON CONFLICT(pubkey) DO UPDATE SET signed_record=excluded.signed_record, published_at=unixepoch()`,
		pubkey, string(recordJSON),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"pubkey": pubkey})
}
