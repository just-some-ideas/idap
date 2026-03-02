package handlers_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/idap/proxy/internal/auth"
	"github.com/idap/proxy/internal/db"
	"github.com/idap/proxy/internal/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

// testEnv holds a test server + associated state.
type testEnv struct {
	server      *httptest.Server
	db          *sql.DB
	providerKey *db.ProviderKey
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	// Unique in-memory DB per test
	dbPath := fmt.Sprintf("file:testdb%d?mode=memory&cache=shared", time.Now().UnixNano())
	database, err := db.Open(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })

	providerKey, err := db.GenerateAndStoreProviderKey(database, "test")
	require.NoError(t, err)

	srv := handlers.NewServer(database, providerKey, "", false, testLogger)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)

	return &testEnv{server: ts, db: database, providerKey: providerKey}
}

// verifyProviderJWT verifies an RS256 JWT signed by the provider key and returns the claims.
func verifyProviderJWT(t *testing.T, env *testEnv, jwtStr string) map[string]any {
	t.Helper()
	parts := strings.Split(jwtStr, ".")
	require.Len(t, parts, 3, "JWT should have 3 parts")

	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)

	hash := sha256.Sum256([]byte(signingInput))
	err = rsa.VerifyPKCS1v15(env.providerKey.PublicKey, crypto.SHA256, hash[:], sig)
	require.NoError(t, err, "JWT signature should verify against provider key")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

// stdToB64url converts standard base64 to base64url (no padding).
func stdToB64url(s string) string {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// typedBundle builds a V2 typed key bundle from an Ed25519 public key.
// It generates a dummy X25519 agreement key for testing.
func typedBundle(pubkeyB64 string) auth.KeyBundle {
	return auth.KeyBundle{
		SigningKey:   auth.NewTypedKey("ed25519", mustDecodeB64(pubkeyB64)),
		AgreementKey: auth.NewTypedKey("x25519", make([]byte, 32)), // dummy agreement key
	}
}

func mustDecodeB64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		b, _ = base64.RawStdEncoding.DecodeString(s)
	}
	return b
}

// Helper: register a user by pubkey and return the keypair + base64 pubkey.
func registerUser(t *testing.T, env *testEnv) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	pubkeyB64 := base64.StdEncoding.EncodeToString(pub)
	pubkeyURL := stdToB64url(pubkeyB64)

	bundle := typedBundle(pubkeyB64)
	body, _ := json.Marshal(bundle)

	resp, err := http.NewRequest(http.MethodPut, env.server.URL+"/keys/"+pubkeyURL, bytes.NewReader(body))
	require.NoError(t, err)
	resp.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(resp)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusCreated, res.StatusCode)

	return pub, priv, pubkeyB64
}

// Helper: create a signed request with X-IDAP-* headers.
func signedRequest(t *testing.T, method, url string, body io.Reader, pubkeyB64 string, priv ed25519.PrivateKey) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	urlPath := req.URL.Path
	message := method + ":" + urlPath + ":" + ts
	sig := ed25519.Sign(priv, []byte(message))

	req.Header.Set("X-IDAP-Key", pubkeyB64)
	req.Header.Set("X-IDAP-Timestamp", ts)
	req.Header.Set("X-IDAP-Signature", base64.StdEncoding.EncodeToString(sig))
	return req
}

// Helper: generate a login code via the signed endpoint.
func generateLoginCodeHelper(t *testing.T, env *testEnv, pubkeyB64 string, priv ed25519.PrivateKey) string {
	t.Helper()
	req := signedRequest(t, http.MethodPost, env.server.URL+"/auth/login-code", nil, pubkeyB64, priv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusCreated, res.StatusCode)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
	code, ok := resp["code"].(string)
	require.True(t, ok)
	return code
}

// Helper: generate an access code for inbox delivery.
func generateAccessCodeHelper(t *testing.T, env *testEnv, pubkeyB64 string, priv ed25519.PrivateKey) string {
	t.Helper()
	pubkeyURL := stdToB64url(pubkeyB64)
	req := signedRequest(t, http.MethodPost, env.server.URL+"/inbox/"+pubkeyURL+"/access-code", nil, pubkeyB64, priv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusCreated, res.StatusCode)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
	code, ok := resp["code"].(string)
	require.True(t, ok)
	return code
}

// Helper: post an inbox message with access code.
func postInboxWithCode(t *testing.T, env *testEnv, recipientPubkeyB64, header, payload, accessCode string) string {
	t.Helper()
	pubkeyURL := stdToB64url(recipientPubkeyB64)
	body := map[string]string{"header": header, "access_code": accessCode}
	if payload != "" {
		body["payload"] = payload
	}
	bodyBytes, _ := json.Marshal(body)
	res, err := http.Post(env.server.URL+"/inbox/"+pubkeyURL, "application/json", bytes.NewReader(bodyBytes))
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusCreated, res.StatusCode)

	var resp map[string]string
	require.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
	return resp["id"]
}

// Helper: POST the authorize form and return the session from DB.
func authorizeWithCode(t *testing.T, env *testEnv, code, nonce, clientID string) string {
	t.Helper()
	form := url.Values{}
	form.Set("code", code)
	form.Set("nonce", nonce)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "http://localhost:9090/callback")
	form.Set("state", "teststate")

	res, err := http.PostForm(env.server.URL+"/auth/authorize", form)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)

	// Read session from DB (most recently created for this nonce)
	var sessionID string
	err = env.db.QueryRow(
		`SELECT id FROM oidc_sessions WHERE nonce = ? ORDER BY expires_at DESC LIMIT 1`, nonce,
	).Scan(&sessionID)
	require.NoError(t, err, "session should exist in DB after authorize")

	return sessionID
}

// Helper: build a signed Ed25519 JWT.
func buildSignedJWT(t *testing.T, sub, clientID, nonce string, priv ed25519.PrivateKey) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"sub":"%s","aud":"%s","nonce":"%s","iat":%d,"exp":%d}`,
		sub, clientID, nonce, time.Now().Unix(), time.Now().Unix()+60,
	)))
	signingInput := header + "." + payload
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// Helper: connect a WebSocket with signed auth headers.
func connectWSHelper(t *testing.T, env *testEnv, pubkeyB64 string, priv ed25519.PrivateKey) *websocket.Conn {
	t.Helper()
	wsURL := strings.Replace(env.server.URL, "http://", "ws://", 1) + "/ws"

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	message := "GET:/ws:" + ts
	sig := ed25519.Sign(priv, []byte(message))

	dialer := websocket.Dialer{}
	headers := http.Header{}
	headers.Set("X-IDAP-Key", pubkeyB64)
	headers.Set("X-IDAP-Timestamp", ts)
	headers.Set("X-IDAP-Signature", base64.StdEncoding.EncodeToString(sig))

	conn, _, err := dialer.Dial(wsURL, headers)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return conn
}

// Helper: read a JSON message from WS with timeout.
func readWSJSON(t *testing.T, conn *websocket.Conn, timeout time.Duration) map[string]any {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(timeout))
	_, msgBytes, err := conn.ReadMessage()
	require.NoError(t, err)
	var msg map[string]any
	require.NoError(t, json.Unmarshal(msgBytes, &msg))
	return msg
}

// ---- Health ----

func TestHealthEndpoint(t *testing.T) {
	env := newTestEnv(t)
	res, err := http.Get(env.server.URL + "/health")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)

	var body map[string]string
	require.NoError(t, json.NewDecoder(res.Body).Decode(&body))
	assert.Equal(t, "ok", body["status"])
}

// ---- Key management ----

func TestRegisterKey_Success(t *testing.T) {
	env := newTestEnv(t)
	pub, _, _ := ed25519.GenerateKey(nil)
	pubkeyB64 := base64.StdEncoding.EncodeToString(pub)
	pubkeyURL := stdToB64url(pubkeyB64)
	bundle := typedBundle(pubkeyB64)
	body, _ := json.Marshal(bundle)

	req, _ := http.NewRequest(http.MethodPut, env.server.URL+"/keys/"+pubkeyURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusCreated, res.StatusCode)
}

func TestRegisterKey_InvalidSignature(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)

	// Bundle uses the correct signing key (matching URL), but request is signed with wrong private key
	bundle := typedBundle(pubkeyB64)
	body, _ := json.Marshal(bundle)

	_, wrongPriv, _ := ed25519.GenerateKey(nil)
	_ = priv

	req := signedRequest(t, http.MethodPut, env.server.URL+"/keys/"+pubkeyURL, bytes.NewReader(body), pubkeyB64, wrongPriv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestGetKey_NotFound(t *testing.T) {
	env := newTestEnv(t)
	// Use a dummy base64url key
	res, err := http.Get(env.server.URL + "/keys/dW5rbm93bg")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
}

func TestGetKey_ReturnsBundle(t *testing.T) {
	env := newTestEnv(t)
	pub, _, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)

	res, err := http.Get(env.server.URL + "/keys/" + pubkeyURL)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)

	var bundle auth.KeyBundle
	require.NoError(t, json.NewDecoder(res.Body).Decode(&bundle))
	sigKeyBytes, err := bundle.SigningKey.Decode()
	require.NoError(t, err)
	assert.Equal(t, []byte(pub), sigKeyBytes)
	assert.Equal(t, "ed25519", bundle.SigningKey.Kty)
	assert.Equal(t, "x25519", bundle.AgreementKey.Kty)
}

func TestJWKSFormat(t *testing.T) {
	env := newTestEnv(t)

	res, err := http.Get(env.server.URL + "/jwks")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)

	var jwks map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&jwks))
	keys, ok := jwks["keys"].([]any)
	require.True(t, ok, "keys field should be array")
	require.Len(t, keys, 1)
	key := keys[0].(map[string]any)
	assert.Equal(t, "RSA", key["kty"])
	assert.Equal(t, "sig", key["use"])
	assert.Equal(t, "RS256", key["alg"])
	assert.NotEmpty(t, key["kid"])
	assert.NotEmpty(t, key["n"])
	assert.NotEmpty(t, key["e"])
}

// ---- Discovery ----

func TestIDAPConfigurationShape(t *testing.T) {
	env := newTestEnv(t)
	res, err := http.Get(env.server.URL + "/.well-known/idap-configuration")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)

	var cfg map[string]string
	require.NoError(t, json.NewDecoder(res.Body).Decode(&cfg))
	assert.NotEmpty(t, cfg["issuer"])
	assert.NotEmpty(t, cfg["authorization_endpoint"])
	assert.NotEmpty(t, cfg["key_endpoint"])
	assert.NotEmpty(t, cfg["inbox_endpoint"])
}

func TestOIDCDiscoveryDocument(t *testing.T) {
	env := newTestEnv(t)
	res, err := http.Get(env.server.URL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)

	var cfg map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&cfg))
	assert.NotEmpty(t, cfg["authorization_endpoint"])
	assert.NotEmpty(t, cfg["token_endpoint"])

	grantTypes, ok := cfg["grant_types_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, grantTypes, "authorization_code")

	responseModes, ok := cfg["response_modes_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, responseModes, "query")

	sigAlgs, ok := cfg["id_token_signing_alg_values_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, sigAlgs, "RS256")

	scopes, ok := cfg["scopes_supported"].([]any)
	require.True(t, ok)
	assert.Contains(t, scopes, "openid")
	assert.Contains(t, scopes, "pubkey")
}

// ---- Inbox ----

func TestPostInboxWithAccessCode_Succeeds(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	code := generateAccessCodeHelper(t, env, pubkeyB64, priv)
	pubkeyURL := stdToB64url(pubkeyB64)
	body := fmt.Sprintf(`{"header":"headerdata","payload":"payloaddata","access_code":"%s"}`, code)
	res, err := http.Post(env.server.URL+"/inbox/"+pubkeyURL, "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusCreated, res.StatusCode)
}

func TestPostInboxWithoutCodeOrProof_Returns403(t *testing.T) {
	env := newTestEnv(t)
	_, _, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)
	body := `{"header":"headerdata","payload":"payloaddata"}`
	res, err := http.Post(env.server.URL+"/inbox/"+pubkeyURL, "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
}

func TestPostInboxWithAccessProof_Succeeds(t *testing.T) {
	env := newTestEnv(t)
	_, _, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)
	body := `{"header":"headerdata","access_proof":"someproof"}`
	res, err := http.Post(env.server.URL+"/inbox/"+pubkeyURL, "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusCreated, res.StatusCode)
}

func TestPostInboxUsedCode_Returns403(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	code := generateAccessCodeHelper(t, env, pubkeyB64, priv)
	pubkeyURL := stdToB64url(pubkeyB64)

	// First use succeeds
	body := fmt.Sprintf(`{"header":"h1","access_code":"%s"}`, code)
	res, err := http.Post(env.server.URL+"/inbox/"+pubkeyURL, "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusCreated, res.StatusCode)

	// Second use fails
	body2 := fmt.Sprintf(`{"header":"h2","access_code":"%s"}`, code)
	res2, err := http.Post(env.server.URL+"/inbox/"+pubkeyURL, "application/json", bytes.NewBufferString(body2))
	require.NoError(t, err)
	defer res2.Body.Close()
	assert.Equal(t, http.StatusForbidden, res2.StatusCode)
}

func TestPostInboxExpiredCode_Returns403(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	code := generateAccessCodeHelper(t, env, pubkeyB64, priv)
	pubkeyURL := stdToB64url(pubkeyB64)

	// Expire the code
	_, err := env.db.Exec(`UPDATE access_codes SET expires_at = ? WHERE code = ?`, time.Now().Unix()-1, code)
	require.NoError(t, err)

	body := fmt.Sprintf(`{"header":"h","access_code":"%s"}`, code)
	res, err := http.Post(env.server.URL+"/inbox/"+pubkeyURL, "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
}

func TestPostInbox_PushesWSNotification(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)

	// Connect WebSocket for recipient
	ws := connectWSHelper(t, env, pubkeyB64, priv)

	// Generate access code and POST to inbox
	code := generateAccessCodeHelper(t, env, pubkeyB64, priv)
	pubkeyURL := stdToB64url(pubkeyB64)
	body := fmt.Sprintf(`{"header":"test_header","payload":"test_payload","access_code":"%s"}`, code)
	res, err := http.Post(env.server.URL+"/inbox/"+pubkeyURL, "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusCreated, res.StatusCode)

	var postResp map[string]string
	require.NoError(t, json.NewDecoder(res.Body).Decode(&postResp))
	msgID := postResp["id"]

	// Read the WebSocket notification
	msg := readWSJSON(t, ws, 2*time.Second)
	assert.Equal(t, "inbox_message", msg["type"])
	assert.Equal(t, msgID, msg["id"])
	assert.Equal(t, "test_header", msg["header"])
}

func TestGetInboxNoAuth_Returns401(t *testing.T) {
	env := newTestEnv(t)
	_, _, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)
	res, err := http.Get(env.server.URL + "/inbox/" + pubkeyURL)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestGetInboxWithAuth_ReturnsHeaders(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)
	code := generateAccessCodeHelper(t, env, pubkeyB64, priv)

	msgID := postInboxWithCode(t, env, pubkeyB64, "test_header", "test_payload", code)

	req := signedRequest(t, http.MethodGet, env.server.URL+"/inbox/"+pubkeyURL, nil, pubkeyB64, priv)
	res2, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res2.Body.Close()
	assert.Equal(t, http.StatusOK, res2.StatusCode)

	var msgs []map[string]any
	require.NoError(t, json.NewDecoder(res2.Body).Decode(&msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "test_header", msgs[0]["header"])
	assert.Equal(t, msgID, msgs[0]["id"])
	// GET inbox should NOT return payload
	_, hasPayload := msgs[0]["payload"]
	assert.False(t, hasPayload, "GET inbox should return headers only, not payload")
}

func TestGetInboxPayload_ReturnsPayload(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)
	code := generateAccessCodeHelper(t, env, pubkeyB64, priv)

	msgID := postInboxWithCode(t, env, pubkeyB64, "hdr", "my_payload", code)

	req := signedRequest(t, http.MethodGet, env.server.URL+"/inbox/"+pubkeyURL+"/"+msgID+"/payload", nil, pubkeyB64, priv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
	assert.Equal(t, "my_payload", resp["payload"])
}

func TestGetInboxPayload_NotFound(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)

	req := signedRequest(t, http.MethodGet, env.server.URL+"/inbox/"+pubkeyURL+"/nonexistent/payload", nil, pubkeyB64, priv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
}

func TestGetInboxPayload_RequiresAuth(t *testing.T) {
	env := newTestEnv(t)
	_, _, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)

	res, err := http.Get(env.server.URL + "/inbox/" + pubkeyURL + "/someid/payload")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestDeleteInbox_RemovesMessage(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)
	code := generateAccessCodeHelper(t, env, pubkeyB64, priv)

	msgID := postInboxWithCode(t, env, pubkeyB64, "todelete_header", "", code)

	req := signedRequest(t, http.MethodDelete, env.server.URL+"/inbox/"+pubkeyURL+"/"+msgID, nil, pubkeyB64, priv)
	res2, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res2.Body.Close()
	assert.Equal(t, http.StatusNoContent, res2.StatusCode)

	req3 := signedRequest(t, http.MethodGet, env.server.URL+"/inbox/"+pubkeyURL, nil, pubkeyB64, priv)
	res3, err := http.DefaultClient.Do(req3)
	require.NoError(t, err)
	defer res3.Body.Close()
	var msgs []map[string]any
	require.NoError(t, json.NewDecoder(res3.Body).Decode(&msgs))
	assert.Len(t, msgs, 0)
}

func TestDeleteInboxWrongOwner_Returns403(t *testing.T) {
	env := newTestEnv(t)
	_, alicePriv, alicePK := registerUser(t, env)
	_, bobPriv, bobPK := registerUser(t, env)
	bobURL := stdToB64url(bobPK)

	code := generateAccessCodeHelper(t, env, alicePK, alicePriv)
	msgID := postInboxWithCode(t, env, alicePK, "secret_header", "", code)

	// Bob tries to delete Alice's message using his own path
	req := signedRequest(t, http.MethodDelete, env.server.URL+"/inbox/"+bobURL+"/"+msgID, nil, bobPK, bobPriv)
	res2, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res2.Body.Close()
	assert.Equal(t, http.StatusForbidden, res2.StatusCode)
}

func TestInboxMessageExpiry(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)

	_, err := env.db.Exec(
		`INSERT INTO inbox(id, recipient, header, payload, delivered_at, expires_at) VALUES('expired-id',?,'hdr','payload',?,?)`,
		pubkeyB64, time.Now().Unix()-100, time.Now().Unix()-1,
	)
	require.NoError(t, err)

	req := signedRequest(t, http.MethodGet, env.server.URL+"/inbox/"+pubkeyURL, nil, pubkeyB64, priv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	var msgs []map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&msgs))
	assert.Len(t, msgs, 0, "expired message should not appear")
}

// ---- Key with slash/plus in base64 ----

// registerUserWithKey registers a user using a specific Ed25519 key pair (from 32-byte seed).
func registerUserWithKey(t *testing.T, env *testEnv, privSeed []byte) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(privSeed)
	pub := priv.Public().(ed25519.PublicKey)
	pubkeyB64 := base64.StdEncoding.EncodeToString(pub)
	pubkeyURL := stdToB64url(pubkeyB64)

	bundle := typedBundle(pubkeyB64)
	body, _ := json.Marshal(bundle)
	resp, err := http.NewRequest(http.MethodPut, env.server.URL+"/keys/"+pubkeyURL, bytes.NewReader(body))
	require.NoError(t, err)
	resp.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(resp)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusCreated, res.StatusCode)
	return pub, priv, pubkeyB64
}

func TestSlashKeyFullRoundtrip(t *testing.T) {
	// Ed25519 key derived from mnemonic: sense voyage tip lake unveil pledge ...
	// Public key base64 contains "/" and "+" characters.
	privSeed, err := base64.StdEncoding.DecodeString("YG0UiN97ZaKdjIXIa1XBqqPfX4d86uu/ZsjKGS6VZMA=")
	require.NoError(t, err)

	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUserWithKey(t, env, privSeed)

	// Verify this key actually has problematic characters
	assert.Contains(t, pubkeyB64, "/", "test key should contain /")
	assert.Contains(t, pubkeyB64, "+", "test key should contain +")

	// 1. Generate an access code
	code := generateAccessCodeHelper(t, env, pubkeyB64, priv)
	assert.Len(t, code, 7)

	// 2. Post a message using the access code
	msgID := postInboxWithCode(t, env, pubkeyB64, "slash_header", "slash_payload", code)
	assert.NotEmpty(t, msgID)

	// 3. Fetch inbox headers
	pubkeyURL := stdToB64url(pubkeyB64)
	req := signedRequest(t, http.MethodGet, env.server.URL+"/inbox/"+pubkeyURL, nil, pubkeyB64, priv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)

	var msgs []map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&msgs))
	require.Len(t, msgs, 1)
	assert.Equal(t, "slash_header", msgs[0]["header"])

	// 4. Fetch payload
	req2 := signedRequest(t, http.MethodGet, env.server.URL+"/inbox/"+pubkeyURL+"/"+msgID+"/payload", nil, pubkeyB64, priv)
	res2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer res2.Body.Close()
	require.Equal(t, http.StatusOK, res2.StatusCode)

	var payloadResp map[string]any
	require.NoError(t, json.NewDecoder(res2.Body).Decode(&payloadResp))
	assert.Equal(t, "slash_payload", payloadResp["payload"])

	// 5. Delete the message
	req3 := signedRequest(t, http.MethodDelete, env.server.URL+"/inbox/"+pubkeyURL+"/"+msgID, nil, pubkeyB64, priv)
	res3, err := http.DefaultClient.Do(req3)
	require.NoError(t, err)
	defer res3.Body.Close()
	assert.Equal(t, http.StatusNoContent, res3.StatusCode)

	// 6. Resolve access code should return this user's bundle
	// (code was already used, so generate a new one)
	code2 := generateAccessCodeHelper(t, env, pubkeyB64, priv)
	resolveRes, err := http.Get(env.server.URL + "/inbox/resolve/" + code2)
	require.NoError(t, err)
	defer resolveRes.Body.Close()
	require.Equal(t, http.StatusOK, resolveRes.StatusCode)

	var resolved map[string]any
	require.NoError(t, json.NewDecoder(resolveRes.Body).Decode(&resolved))
	assert.Equal(t, pubkeyB64, resolved["pubkey"])
}

// ---- OIDC ----

func TestLoginCode_RequiresAuth(t *testing.T) {
	env := newTestEnv(t)
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/auth/login-code", nil)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestLoginCode_ReturnsCode(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)

	req := signedRequest(t, http.MethodPost, env.server.URL+"/auth/login-code", nil, pubkeyB64, priv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusCreated, res.StatusCode)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
	code, ok := resp["code"].(string)
	require.True(t, ok)
	assert.Len(t, code, 7) // XXX-XXX
	assert.Contains(t, code, "-")

	expiresIn, ok := resp["expires_in"].(float64)
	require.True(t, ok)
	assert.Equal(t, float64(300), expiresIn)
}

func TestAuthorizePage_ReturnsHTML(t *testing.T) {
	env := newTestEnv(t)
	res, err := http.Get(env.server.URL + "/auth/authorize?client_id=test.com&redirect_uri=http://localhost/cb&nonce=abc")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, res.Header.Get("Content-Type"), "text/html")

	body, _ := io.ReadAll(res.Body)
	assert.Contains(t, string(body), "test.com")
	assert.Contains(t, string(body), "Login Code")
}

func TestAuthorizePage_MissingParams(t *testing.T) {
	env := newTestEnv(t)
	res, err := http.Get(env.server.URL + "/auth/authorize?client_id=test.com")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestAuthorizeSubmit_InvalidCode(t *testing.T) {
	env := newTestEnv(t)
	form := url.Values{}
	form.Set("code", "INVALID")
	form.Set("nonce", "abc")
	form.Set("client_id", "test.com")
	form.Set("redirect_uri", "http://localhost/cb")

	res, err := http.PostForm(env.server.URL+"/auth/authorize", form)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)

	body, _ := io.ReadAll(res.Body)
	assert.Contains(t, string(body), "Invalid code")
}

func TestAuthorizeSubmit_ExpiredCode(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)

	_, err := env.db.Exec(`UPDATE access_codes SET expires_at = ? WHERE code = ?`, time.Now().Unix()-1, code)
	require.NoError(t, err)

	form := url.Values{}
	form.Set("code", code)
	form.Set("nonce", "abc")
	form.Set("client_id", "test.com")
	form.Set("redirect_uri", "http://localhost/cb")

	res, err := http.PostForm(env.server.URL+"/auth/authorize", form)
	require.NoError(t, err)
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	assert.Contains(t, string(body), "expired")
}

func TestAuthorizeSubmit_UsedCode(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)

	form := url.Values{}
	form.Set("code", code)
	form.Set("nonce", "abc")
	form.Set("client_id", "test.com")
	form.Set("redirect_uri", "http://localhost/cb")
	res, err := http.PostForm(env.server.URL+"/auth/authorize", form)
	require.NoError(t, err)
	res.Body.Close()

	form2 := url.Values{}
	form2.Set("code", code)
	form2.Set("nonce", "def")
	form2.Set("client_id", "test.com")
	form2.Set("redirect_uri", "http://localhost/cb")
	res2, err := http.PostForm(env.server.URL+"/auth/authorize", form2)
	require.NoError(t, err)
	defer res2.Body.Close()

	body, _ := io.ReadAll(res2.Body)
	assert.Contains(t, string(body), "already used")
}

func TestAuthorizeCreatesSession(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)

	sessionID := authorizeWithCode(t, env, code, "abc123", "gamesite.com")
	assert.NotEmpty(t, sessionID)

	var count int
	require.NoError(t, env.db.QueryRow(`SELECT COUNT(*) FROM oidc_sessions WHERE pubkey=?`, pubkeyB64).Scan(&count))
	assert.Equal(t, 1, count)
}

func TestAuthorizeStoresRedirectAndState(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)

	sessionID := authorizeWithCode(t, env, code, "n1", "svc.com")

	var redirectURI, state string
	err := env.db.QueryRow(`SELECT redirect_uri, state FROM oidc_sessions WHERE id = ?`, sessionID).Scan(&redirectURI, &state)
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:9090/callback", redirectURI)
	assert.Equal(t, "teststate", state)
}

func TestTokenExchangeValidAssertion(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)

	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)
	sessionID := authorizeWithCode(t, env, code, "n1", "svc.com")

	_, err := env.db.Exec(`UPDATE oidc_sessions SET approved=1 WHERE id=?`, sessionID)
	require.NoError(t, err)

	tokenBody := map[string]string{"grant_type": "authorization_code", "code": sessionID, "client_id": "svc.com"}
	tokenBytes, _ := json.Marshal(tokenBody)
	tokenRes, err := http.Post(env.server.URL+"/auth/token", "application/json", bytes.NewReader(tokenBytes))
	require.NoError(t, err)
	defer tokenRes.Body.Close()
	assert.Equal(t, http.StatusOK, tokenRes.StatusCode)

	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(tokenRes.Body).Decode(&tokenResp))
	assert.Equal(t, "Bearer", tokenResp["token_type"])
	assert.NotEmpty(t, tokenResp["id_token"])

	// Verify the JWT is signed by the provider
	claims := verifyProviderJWT(t, env, tokenResp["id_token"].(string))
	assert.Equal(t, pubkeyB64, claims["sub"])
	assert.Equal(t, "svc.com", claims["aud"])
	assert.Equal(t, pubkeyB64, claims["idap_pubkey"])
	assert.Equal(t, "EdDSA", claims["idap_algorithm"])
}

func TestTokenExchangeFormEncoded(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)

	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)
	sessionID := authorizeWithCode(t, env, code, "n1", "svc.com")

	_, err := env.db.Exec(`UPDATE oidc_sessions SET approved=1 WHERE id=?`, sessionID)
	require.NoError(t, err)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", sessionID)
	form.Set("client_id", "svc.com")

	tokenRes, err := http.PostForm(env.server.URL+"/auth/token", form)
	require.NoError(t, err)
	defer tokenRes.Body.Close()
	assert.Equal(t, http.StatusOK, tokenRes.StatusCode)

	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(tokenRes.Body).Decode(&tokenResp))
	assert.Equal(t, "Bearer", tokenResp["token_type"])
	assert.NotEmpty(t, tokenResp["id_token"])

	// Verify provider-signed JWT
	claims := verifyProviderJWT(t, env, tokenResp["id_token"].(string))
	assert.Equal(t, pubkeyB64, claims["sub"])
}

func TestTokenExchangeExpiredSession(t *testing.T) {
	env := newTestEnv(t)
	_, _, pubkeyB64 := registerUser(t, env)

	_, err := env.db.Exec(
		`INSERT INTO oidc_sessions(id,pubkey,service,nonce,number_match,redirect_uri,state,expires_at,approved) VALUES('expired-sess',?,'s.com','n',42,'','',?,1)`,
		pubkeyB64, time.Now().Unix()-100,
	)
	require.NoError(t, err)

	tokenBody := map[string]string{"code": "expired-sess"}
	tokenBytes, _ := json.Marshal(tokenBody)
	res, err := http.Post(env.server.URL+"/auth/token", "application/json", bytes.NewReader(tokenBytes))
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
}

func TestTokenExchangeNotApproved(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)
	sessionID := authorizeWithCode(t, env, code, "n2", "svc.com")

	tokenBody := map[string]string{"code": sessionID}
	tokenBytes, _ := json.Marshal(tokenBody)
	tokenRes, err := http.Post(env.server.URL+"/auth/token", "application/json", bytes.NewReader(tokenBytes))
	require.NoError(t, err)
	defer tokenRes.Body.Close()
	assert.Equal(t, http.StatusBadRequest, tokenRes.StatusCode)
}

func TestUserinfoReturnsPubkey(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)

	// Get a provider-signed JWT via token exchange
	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)
	sessionID := authorizeWithCode(t, env, code, "ui-nonce", "svc.com")
	_, err := env.db.Exec(`UPDATE oidc_sessions SET approved=1 WHERE id=?`, sessionID)
	require.NoError(t, err)

	tokenBody := map[string]string{"grant_type": "authorization_code", "code": sessionID, "client_id": "svc.com"}
	tokenBytes, _ := json.Marshal(tokenBody)
	tokenRes, err := http.Post(env.server.URL+"/auth/token", "application/json", bytes.NewReader(tokenBytes))
	require.NoError(t, err)
	defer tokenRes.Body.Close()
	require.Equal(t, http.StatusOK, tokenRes.StatusCode)

	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(tokenRes.Body).Decode(&tokenResp))
	jwt := tokenResp["access_token"].(string)

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/auth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)

	var claims map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&claims))
	assert.Equal(t, pubkeyB64, claims["sub"])
}

func TestUserinfoRejectsInvalidSignature(t *testing.T) {
	env := newTestEnv(t)

	// Build a JWT signed with a different RSA key (not the provider key)
	fakeKey, err := rsa.GenerateKey(crand.Reader, 2048)
	require.NoError(t, err)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"fakepubkey"}`))
	signingInput := header + "." + payload

	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(crand.Reader, fakeKey, crypto.SHA256, hash[:])
	require.NoError(t, err)
	jwt := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/auth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

// ---- Poll endpoint ----

func TestPollEndpoint_Waiting(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)
	sessionID := authorizeWithCode(t, env, code, "poll1", "svc.com")

	res, err := http.Get(env.server.URL + "/auth/authorize/poll/" + sessionID)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)

	var resp map[string]string
	require.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
	assert.Equal(t, "waiting", resp["status"])
}

func TestPollEndpoint_Approved(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)
	sessionID := authorizeWithCode(t, env, code, "poll2", "svc.com")

	_, err := env.db.Exec(`UPDATE oidc_sessions SET approved = 1 WHERE id = ?`, sessionID)
	require.NoError(t, err)

	res, err := http.Get(env.server.URL + "/auth/authorize/poll/" + sessionID)
	require.NoError(t, err)
	defer res.Body.Close()

	var resp map[string]string
	require.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
	assert.Equal(t, "approved", resp["status"])
	assert.Contains(t, resp["redirect"], "code="+sessionID)
	assert.Contains(t, resp["redirect"], "state=teststate")
}

func TestPollEndpoint_Expired(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)
	sessionID := authorizeWithCode(t, env, code, "poll3", "svc.com")

	_, err := env.db.Exec(`UPDATE oidc_sessions SET expires_at = ? WHERE id = ?`, time.Now().Unix()-1, sessionID)
	require.NoError(t, err)

	res, err := http.Get(env.server.URL + "/auth/authorize/poll/" + sessionID)
	require.NoError(t, err)
	defer res.Body.Close()

	var resp map[string]string
	require.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
	assert.Equal(t, "expired", resp["status"])
}

func TestPollEndpoint_NotFound(t *testing.T) {
	env := newTestEnv(t)
	res, err := http.Get(env.server.URL + "/auth/authorize/poll/nonexistent")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
}

// ---- E2E Tests ----

func TestE2E_FullAuthFlow(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)

	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)
	ws := connectWSHelper(t, env, pubkeyB64, priv)
	sessionID := authorizeWithCode(t, env, code, "e2e-nonce", "e2e-client")

	msg := readWSJSON(t, ws, 5*time.Second)
	assert.Equal(t, "auth_request", msg["type"])
	assert.Equal(t, sessionID, msg["requestId"])
	assert.Equal(t, "e2e-client", msg["service"])

	jwt := buildSignedJWT(t, pubkeyB64, "e2e-client", "e2e-nonce", priv)
	assertion := map[string]any{
		"type":      "auth_assertion",
		"requestId": sessionID,
		"jwt":       jwt,
	}
	err := ws.WriteJSON(assertion)
	require.NoError(t, err)

	resp := readWSJSON(t, ws, 5*time.Second)
	assert.Equal(t, "auth_approved", resp["type"])
	assert.Equal(t, sessionID, resp["code"])

	tokenBody := map[string]string{"grant_type": "authorization_code", "code": sessionID, "client_id": "e2e-client"}
	tokenBytes, _ := json.Marshal(tokenBody)
	tokenRes, err := http.Post(env.server.URL+"/auth/token", "application/json", bytes.NewReader(tokenBytes))
	require.NoError(t, err)
	defer tokenRes.Body.Close()
	assert.Equal(t, http.StatusOK, tokenRes.StatusCode)

	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(tokenRes.Body).Decode(&tokenResp))
	assert.Equal(t, "Bearer", tokenResp["token_type"])
	assert.NotEmpty(t, tokenResp["id_token"])
	assert.Equal(t, pubkeyB64, tokenResp["sub"])

	// Verify provider-signed JWT claims
	claims := verifyProviderJWT(t, env, tokenResp["id_token"].(string))
	assert.Equal(t, pubkeyB64, claims["sub"])
	assert.Equal(t, pubkeyB64, claims["idap_pubkey"])
	assert.Equal(t, "EdDSA", claims["idap_algorithm"])

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/auth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp["access_token"].(string))
	uiRes, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer uiRes.Body.Close()
	assert.Equal(t, http.StatusOK, uiRes.StatusCode)

	var userinfo map[string]any
	require.NoError(t, json.NewDecoder(uiRes.Body).Decode(&userinfo))
	assert.Equal(t, pubkeyB64, userinfo["sub"])
}

func TestE2E_InvalidJWTRejected(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)

	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)
	ws := connectWSHelper(t, env, pubkeyB64, priv)
	sessionID := authorizeWithCode(t, env, code, "bad-jwt-nonce", "svc.com")
	_ = readWSJSON(t, ws, 5*time.Second)

	_, wrongPriv, _ := ed25519.GenerateKey(nil)
	jwt := buildSignedJWT(t, pubkeyB64, "svc.com", "bad-jwt-nonce", wrongPriv)

	assertion := map[string]any{
		"type":      "auth_assertion",
		"requestId": sessionID,
		"jwt":       jwt,
	}
	err := ws.WriteJSON(assertion)
	require.NoError(t, err)

	resp := readWSJSON(t, ws, 5*time.Second)
	assert.Equal(t, "error", resp["type"])
	assert.Equal(t, "invalid assertion", resp["message"])
}

func TestE2E_ExpiredSessionRejected(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)

	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)
	ws := connectWSHelper(t, env, pubkeyB64, priv)
	sessionID := authorizeWithCode(t, env, code, "expired-nonce", "svc.com")
	_ = readWSJSON(t, ws, 5*time.Second)

	_, err := env.db.Exec(`UPDATE oidc_sessions SET expires_at = ? WHERE id = ?`, time.Now().Unix()-1, sessionID)
	require.NoError(t, err)

	jwt := buildSignedJWT(t, pubkeyB64, "svc.com", "expired-nonce", priv)
	assertion := map[string]any{
		"type":      "auth_assertion",
		"requestId": sessionID,
		"jwt":       jwt,
	}
	err = ws.WriteJSON(assertion)
	require.NoError(t, err)

	resp := readWSJSON(t, ws, 5*time.Second)
	assert.Equal(t, "auth_expired", resp["type"])
}

func TestE2E_WSReceivesPushOnAuthorize(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)

	ws := connectWSHelper(t, env, pubkeyB64, priv)
	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)
	authorizeWithCode(t, env, code, "push-nonce", "push-svc")

	msg := readWSJSON(t, ws, 5*time.Second)
	assert.Equal(t, "auth_request", msg["type"])
	assert.Equal(t, "push-svc", msg["service"])
}

func TestE2E_BrowserFlowEndToEnd(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)

	res, err := http.Get(env.server.URL + "/auth/authorize?client_id=demo&redirect_uri=http://localhost:9090/callback&nonce=browser-nonce&state=browser-state&response_type=code")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, res.Header.Get("Content-Type"), "text/html")

	body, _ := io.ReadAll(res.Body)
	assert.Contains(t, string(body), "demo")
	assert.Contains(t, string(body), "Login Code")

	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)

	form := url.Values{}
	form.Set("code", code)
	form.Set("nonce", "browser-nonce")
	form.Set("client_id", "demo")
	form.Set("redirect_uri", "http://localhost:9090/callback")
	form.Set("state", "browser-state")

	res2, err := http.PostForm(env.server.URL+"/auth/authorize", form)
	require.NoError(t, err)
	defer res2.Body.Close()
	assert.Equal(t, http.StatusOK, res2.StatusCode)

	body2, _ := io.ReadAll(res2.Body)
	html := string(body2)
	assert.Contains(t, html, "Confirm on Your Device")
	assert.Contains(t, html, "auth")

	var sessionID string
	err = env.db.QueryRow(`SELECT id FROM oidc_sessions WHERE nonce = 'browser-nonce'`).Scan(&sessionID)
	require.NoError(t, err)

	pollRes, err := http.Get(env.server.URL + "/auth/authorize/poll/" + sessionID)
	require.NoError(t, err)
	defer pollRes.Body.Close()
	var pollResp map[string]string
	require.NoError(t, json.NewDecoder(pollRes.Body).Decode(&pollResp))
	assert.Equal(t, "waiting", pollResp["status"])

	_, err = env.db.Exec(`UPDATE oidc_sessions SET approved=1 WHERE id=?`, sessionID)
	require.NoError(t, err)

	pollRes2, err := http.Get(env.server.URL + "/auth/authorize/poll/" + sessionID)
	require.NoError(t, err)
	defer pollRes2.Body.Close()
	var pollResp2 map[string]string
	require.NoError(t, json.NewDecoder(pollRes2.Body).Decode(&pollResp2))
	assert.Equal(t, "approved", pollResp2["status"])
	assert.Contains(t, pollResp2["redirect"], "code="+sessionID)
	assert.Contains(t, pollResp2["redirect"], "state=browser-state")
	assert.Contains(t, pollResp2["redirect"], "localhost:9090/callback")
}

// ---- Access Codes ----

func TestAccessCodeCreate_RequiresAuth(t *testing.T) {
	env := newTestEnv(t)
	_, _, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)
	req, _ := http.NewRequest(http.MethodPost, env.server.URL+"/inbox/"+pubkeyURL+"/access-code", nil)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestAccessCodeCreate_RejectsNonOwner(t *testing.T) {
	env := newTestEnv(t)
	_, _, alicePK := registerUser(t, env)
	_, bobPriv, bobPK := registerUser(t, env)
	aliceURL := stdToB64url(alicePK)

	req := signedRequest(t, http.MethodPost, env.server.URL+"/inbox/"+aliceURL+"/access-code", nil, bobPK, bobPriv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
}

func TestAccessCodeCreate_ReturnsValidFormat(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)

	code := generateAccessCodeHelper(t, env, pubkeyB64, priv)
	assert.Len(t, code, 7)
	assert.Contains(t, code, "-")
}

func TestAccessCodeResolve_ReturnsBundle(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)

	code := generateAccessCodeHelper(t, env, pubkeyB64, priv)

	res, err := http.Get(env.server.URL + "/inbox/resolve/" + code)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)

	var resp map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&resp))
	assert.Equal(t, pubkeyB64, resp["pubkey"])
	bundle, ok := resp["key_bundle"].(map[string]any)
	require.True(t, ok)
	sigKey, ok := bundle["signing_key"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "ed25519", sigKey["kty"])
	assert.NotEmpty(t, sigKey["key"])
}

func TestAccessCodeResolve_InvalidCode_404(t *testing.T) {
	env := newTestEnv(t)
	res, err := http.Get(env.server.URL + "/inbox/resolve/INVALID")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
}

func TestAccessCodeResolve_ExpiredCode_404(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	code := generateAccessCodeHelper(t, env, pubkeyB64, priv)

	// Expire the code
	_, err := env.db.Exec(`UPDATE access_codes SET expires_at = ? WHERE code = ?`, time.Now().Unix()-1, code)
	require.NoError(t, err)

	res, err := http.Get(env.server.URL + "/inbox/resolve/" + code)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusNotFound, res.StatusCode)
}

func TestIDTokenContainsInboxClaim(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)

	code := generateLoginCodeHelper(t, env, pubkeyB64, priv)
	sessionID := authorizeWithCode(t, env, code, "inbox-claim-nonce", "svc.com")

	_, err := env.db.Exec(`UPDATE oidc_sessions SET approved=1 WHERE id=?`, sessionID)
	require.NoError(t, err)

	tokenBody := map[string]string{"grant_type": "authorization_code", "code": sessionID, "client_id": "svc.com"}
	tokenBytes, _ := json.Marshal(tokenBody)
	tokenRes, err := http.Post(env.server.URL+"/auth/token", "application/json", bytes.NewReader(tokenBytes))
	require.NoError(t, err)
	defer tokenRes.Body.Close()
	require.Equal(t, http.StatusOK, tokenRes.StatusCode)

	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(tokenRes.Body).Decode(&tokenResp))

	claims := verifyProviderJWT(t, env, tokenResp["id_token"].(string))
	inboxClaim, ok := claims["idap_inbox"].(string)
	require.True(t, ok, "JWT should contain idap_inbox claim")
	assert.Contains(t, inboxClaim, "/inbox")
}

// ---- Shards ----

func TestStoreShardRequiresAuth(t *testing.T) {
	env := newTestEnv(t)
	_, _, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)
	body := `{"id":"shard1","blob":"encrypteddata"}`
	// No auth headers — uses a different pubkey in header vs path won't match
	res, err := http.Post(env.server.URL+"/recovery/shard/"+pubkeyURL, "application/json", bytes.NewBufferString(body))
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
}

func TestStoreShardSuccess(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)

	body := `{"id":"shard1","blob":"encryptedsharddata"}`
	req := signedRequest(t, http.MethodPost, env.server.URL+"/recovery/shard/"+pubkeyURL, bytes.NewBufferString(body), pubkeyB64, priv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusCreated, res.StatusCode)
}

func TestRetrieveShardValidCode(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)

	body := `{"id":"shardX","blob":"shardblob"}`
	req := signedRequest(t, http.MethodPost, env.server.URL+"/recovery/shard/"+pubkeyURL, bytes.NewBufferString(body), pubkeyB64, priv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusCreated, res.StatusCode)

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "unique-nonce-1"
	message := "shardX:" + ts + ":" + nonce
	sig := ed25519.Sign(priv, []byte(message))

	getReq, _ := http.NewRequest(http.MethodGet, env.server.URL+"/recovery/shard/"+pubkeyURL+"/shardX", nil)
	getReq.Header.Set("X-IDAP-Timed-Code", "TESTCODE")
	getReq.Header.Set("X-IDAP-Code-Nonce", nonce)
	getReq.Header.Set("X-IDAP-Code-Timestamp", ts)
	getReq.Header.Set("X-IDAP-Code-Signature", base64.StdEncoding.EncodeToString(sig))

	res2, err := http.DefaultClient.Do(getReq)
	require.NoError(t, err)
	defer res2.Body.Close()
	assert.Equal(t, http.StatusOK, res2.StatusCode)

	var resp map[string]string
	require.NoError(t, json.NewDecoder(res2.Body).Decode(&resp))
	assert.Equal(t, "shardblob", resp["blob"])
}

func TestRetrieveShardExpiredCode(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)

	body := `{"id":"shardY","blob":"shardblob2"}`
	req := signedRequest(t, http.MethodPost, env.server.URL+"/recovery/shard/"+pubkeyURL, bytes.NewBufferString(body), pubkeyB64, priv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	res.Body.Close()

	ts := strconv.FormatInt(time.Now().Unix()-16*60, 10)
	nonce := "nonce-expired"
	message := "shardY:" + ts + ":" + nonce
	sig := ed25519.Sign(priv, []byte(message))

	getReq, _ := http.NewRequest(http.MethodGet, env.server.URL+"/recovery/shard/"+pubkeyURL+"/shardY", nil)
	getReq.Header.Set("X-IDAP-Timed-Code", "EXPIREDCODE")
	getReq.Header.Set("X-IDAP-Code-Nonce", nonce)
	getReq.Header.Set("X-IDAP-Code-Timestamp", ts)
	getReq.Header.Set("X-IDAP-Code-Signature", base64.StdEncoding.EncodeToString(sig))

	res2, err := http.DefaultClient.Do(getReq)
	require.NoError(t, err)
	defer res2.Body.Close()
	assert.Equal(t, http.StatusForbidden, res2.StatusCode)
}

func TestRetrieveShardReplayedCode(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)

	body := `{"id":"shardZ","blob":"shardblob3"}`
	req := signedRequest(t, http.MethodPost, env.server.URL+"/recovery/shard/"+pubkeyURL, bytes.NewBufferString(body), pubkeyB64, priv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	res.Body.Close()

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "unique-nonce-replay"
	message := "shardZ:" + ts + ":" + nonce
	sig := ed25519.Sign(priv, []byte(message))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	makeReq := func() *http.Response {
		r, _ := http.NewRequest(http.MethodGet, env.server.URL+"/recovery/shard/"+pubkeyURL+"/shardZ", nil)
		r.Header.Set("X-IDAP-Timed-Code", "REPLAYCODE")
		r.Header.Set("X-IDAP-Code-Nonce", nonce)
		r.Header.Set("X-IDAP-Code-Timestamp", ts)
		r.Header.Set("X-IDAP-Code-Signature", sigB64)
		resp, _ := http.DefaultClient.Do(r)
		return resp
	}

	res1 := makeReq()
	defer res1.Body.Close()
	assert.Equal(t, http.StatusOK, res1.StatusCode)

	res2 := makeReq()
	defer res2.Body.Close()
	assert.Equal(t, http.StatusForbidden, res2.StatusCode)
}

// ---- Migration ----

func TestPublishMigration(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)

	record := map[string]any{
		"old_pubkey": pubkeyB64,
		"new_pubkey": "newkey123",
		"new_proxy":  "https://new.proxy.com",
		"timestamp":  time.Now().Unix(),
	}
	canonical, _ := json.Marshal(record)
	sig := ed25519.Sign(priv, canonical)
	record["signature"] = base64.StdEncoding.EncodeToString(sig)

	body, _ := json.Marshal(record)
	req := signedRequest(t, http.MethodPost, env.server.URL+"/migration/"+pubkeyURL, bytes.NewReader(body), pubkeyB64, priv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusCreated, res.StatusCode)
}

func TestFetchMigrationRecord(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)

	record := map[string]any{"old_pubkey": pubkeyB64, "new_pubkey": "newkey456", "timestamp": time.Now().Unix()}
	canonical, _ := json.Marshal(record)
	sig := ed25519.Sign(priv, canonical)
	record["signature"] = base64.StdEncoding.EncodeToString(sig)

	body, _ := json.Marshal(record)
	req := signedRequest(t, http.MethodPost, env.server.URL+"/migration/"+pubkeyURL, bytes.NewReader(body), pubkeyB64, priv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusCreated, res.StatusCode)

	res2, err := http.Get(env.server.URL + "/migration/" + pubkeyURL)
	require.NoError(t, err)
	defer res2.Body.Close()
	assert.Equal(t, http.StatusOK, res2.StatusCode)

	var fetched map[string]any
	require.NoError(t, json.NewDecoder(res2.Body).Decode(&fetched))
	assert.Equal(t, pubkeyB64, fetched["old_pubkey"])
}

func TestFetchMigrationTamperedSignatureReturns422(t *testing.T) {
	env := newTestEnv(t)
	_, priv, pubkeyB64 := registerUser(t, env)
	pubkeyURL := stdToB64url(pubkeyB64)

	record := map[string]any{
		"old_pubkey": pubkeyB64,
		"new_pubkey": "newkey789",
		"timestamp":  time.Now().Unix(),
		"signature":  base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}
	body, _ := json.Marshal(record)
	req := signedRequest(t, http.MethodPost, env.server.URL+"/migration/"+pubkeyURL, bytes.NewReader(body), pubkeyB64, priv)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusUnprocessableEntity, res.StatusCode)
}
