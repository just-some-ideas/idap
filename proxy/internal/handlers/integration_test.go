package handlers_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

// findDemoDir locates the demo/ directory relative to this test file.
func findDemoDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	demoDir := filepath.Join(repoRoot, "demo")
	if _, err := os.Stat(filepath.Join(demoDir, "main.go")); err != nil {
		t.Skipf("demo directory not found at %s: %v", demoDir, err)
	}
	return demoDir
}

// buildDemo compiles the demo binary and returns its path.
func buildDemo(t *testing.T) string {
	t.Helper()
	demoDir := findDemoDir(t)
	binPath := filepath.Join(t.TempDir(), "demo-test")

	cmd := exec.Command("go", "build", "-o", binPath, ".")
	cmd.Dir = demoDir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "demo build failed: %s", string(out))
	return binPath
}

// getFreePort returns an available TCP port.
func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// waitForServer polls a URL until it responds or timeout.
func waitForServer(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s did not start within %v", url, timeout)
}

// ---- Full Integration Test ----

func TestIntegration_FullOIDCFlowAcrossAllServices(t *testing.T) {
	// 1. Start the proxy on a real port
	dbPath := fmt.Sprintf("file:intdb%d?mode=memory&cache=shared", time.Now().UnixNano())
	database, err := db.Open(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })

	providerKey, err := db.GenerateAndStoreProviderKey(database, "test")
	require.NoError(t, err)

	proxySrv := handlers.NewServer(database, providerKey, "", false, testLogger)
	proxyTS := httptest.NewServer(proxySrv.Router())
	t.Cleanup(proxyTS.Close)
	proxyURL := proxyTS.URL
	t.Logf("Proxy running at %s", proxyURL)

	// 2. Build and start the demo
	demoBin := buildDemo(t)
	demoPort := getFreePort(t)
	demoURL := fmt.Sprintf("http://127.0.0.1:%d", demoPort)

	demoCmd := exec.Command(demoBin)
	demoCmd.Env = append(os.Environ(),
		"PROXY_URL="+proxyURL,
		"PORT="+strconv.Itoa(demoPort),
	)
	demoCmd.Stdout = os.Stdout
	demoCmd.Stderr = os.Stderr
	require.NoError(t, demoCmd.Start())
	t.Cleanup(func() { demoCmd.Process.Kill(); demoCmd.Wait() })

	waitForServer(t, demoURL+"/", 5*time.Second)
	t.Logf("Demo running at %s", demoURL)

	// 3. Register user on the proxy (simulating the IDAP app's initial setup)
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubkeyB64 := base64.StdEncoding.EncodeToString(pub)
	pubkeyURL := stdToB64url(pubkeyB64)
	bundle := auth.KeyBundle{
		SigningKey:   auth.NewTypedKey("ed25519", pub),
		AgreementKey: auth.NewTypedKey("x25519", make([]byte, 32)),
	}
	bundleJSON, _ := json.Marshal(bundle)
	req, _ := http.NewRequest(http.MethodPut, proxyURL+"/keys/"+pubkeyURL, bytes.NewReader(bundleJSON))
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	res.Body.Close()
	require.Equal(t, http.StatusCreated, res.StatusCode)
	t.Log("Registered user on proxy")

	// 4. Generate login code (simulating app's "Log In" tap)
	codeReq := signedRequest(t, http.MethodPost, proxyURL+"/auth/login-code", nil, pubkeyB64, priv)
	codeRes, err := http.DefaultClient.Do(codeReq)
	require.NoError(t, err)
	defer codeRes.Body.Close()
	require.Equal(t, http.StatusCreated, codeRes.StatusCode)

	var codeResp map[string]any
	require.NoError(t, json.NewDecoder(codeRes.Body).Decode(&codeResp))
	loginCode := codeResp["code"].(string)
	t.Logf("Login code: %s", loginCode)

	// 5. Connect WebSocket (simulating the app's persistent WS connection)
	wsURL := strings.Replace(proxyURL, "http://", "ws://", 1) + "/ws"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	wsMsg := "GET:/ws:" + ts
	wsSig := ed25519.Sign(priv, []byte(wsMsg))

	wsHeaders := http.Header{}
	wsHeaders.Set("X-IDAP-Key", pubkeyB64)
	wsHeaders.Set("X-IDAP-Timestamp", ts)
	wsHeaders.Set("X-IDAP-Signature", base64.StdEncoding.EncodeToString(wsSig))

	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, wsHeaders)
	require.NoError(t, err)
	t.Cleanup(func() { wsConn.Close() })
	t.Log("WebSocket connected")

	// 6. Simulate browser: visit demo home, find /login link
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	homeRes, err := http.Get(demoURL + "/")
	require.NoError(t, err)
	homeBody, _ := io.ReadAll(homeRes.Body)
	homeRes.Body.Close()
	assert.Equal(t, http.StatusOK, homeRes.StatusCode)
	assert.Contains(t, string(homeBody), "Sign In with IDAP")

	loginHref := extractHref(t, string(homeBody), "/login")
	require.NotEmpty(t, loginHref, "should find /login link in demo page")

	// Follow /login — demo does OIDC discovery and redirects to proxy authorize
	loginRes, err := noRedirectClient.Get(demoURL + loginHref)
	require.NoError(t, err)
	loginRes.Body.Close()
	require.Equal(t, http.StatusFound, loginRes.StatusCode)

	signInURL := loginRes.Header.Get("Location")
	require.NotEmpty(t, signInURL, "login should redirect to proxy authorize")
	t.Logf("Sign In URL: %s", signInURL)

	parsedSignInURL, _ := url.Parse(signInURL)
	oidcState := parsedSignInURL.Query().Get("state")
	oidcNonce := parsedSignInURL.Query().Get("nonce")
	require.NotEmpty(t, oidcState)
	require.NotEmpty(t, oidcNonce)

	// 7. Browser visits the proxy authorize page (GET)
	authPageRes, err := http.Get(signInURL)
	require.NoError(t, err)
	authPageBody, _ := io.ReadAll(authPageRes.Body)
	authPageRes.Body.Close()
	assert.Equal(t, http.StatusOK, authPageRes.StatusCode)
	assert.Contains(t, string(authPageBody), "Login Code")
	t.Log("Proxy authorize page loaded")

	// 8. Browser submits the login code (POST form to proxy)
	form := url.Values{}
	form.Set("code", loginCode)
	form.Set("client_id", "idap-demo")
	form.Set("redirect_uri", demoURL+"/callback")
	form.Set("nonce", oidcNonce)
	form.Set("state", oidcState)
	form.Set("response_type", "code")

	submitRes, err := http.PostForm(proxyURL+"/auth/authorize", form)
	require.NoError(t, err)
	submitBody, _ := io.ReadAll(submitRes.Body)
	submitRes.Body.Close()
	assert.Equal(t, http.StatusOK, submitRes.StatusCode)
	assert.Contains(t, string(submitBody), "Confirm on Your Device")
	t.Log("Login code submitted, waiting page shown")

	// 9. Read auth_request from WebSocket
	wsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, wsMsg2, err := wsConn.ReadMessage()
	require.NoError(t, err)

	var authReq map[string]any
	require.NoError(t, json.Unmarshal(wsMsg2, &authReq))
	assert.Equal(t, "auth_request", authReq["type"])
	assert.Equal(t, "idap-demo", authReq["service"])
	sessionID := authReq["requestId"].(string)
	t.Logf("Auth request received: sessionID=%s", sessionID)

	// 10. App approves: build JWT and send auth_assertion over WS
	jwt := buildSignedJWT(t, pubkeyB64, "idap-demo", oidcNonce, priv)
	assertion := map[string]any{
		"type":      "auth_assertion",
		"requestId": sessionID,
		"jwt":       jwt,
	}
	err = wsConn.WriteJSON(assertion)
	require.NoError(t, err)
	t.Log("Auth assertion sent")

	// 11. Read auth_approved response
	wsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, wsMsg3, err := wsConn.ReadMessage()
	require.NoError(t, err)
	var approvedResp map[string]any
	require.NoError(t, json.Unmarshal(wsMsg3, &approvedResp))
	assert.Equal(t, "auth_approved", approvedResp["type"])
	assert.Equal(t, sessionID, approvedResp["code"])
	t.Log("Auth approved over WS")

	// 12. Poll the proxy poll endpoint
	pollRes, err := http.Get(proxyURL + "/auth/authorize/poll/" + sessionID)
	require.NoError(t, err)
	defer pollRes.Body.Close()
	var pollResp map[string]string
	require.NoError(t, json.NewDecoder(pollRes.Body).Decode(&pollResp))
	assert.Equal(t, "approved", pollResp["status"])
	redirectURL := pollResp["redirect"]
	require.NotEmpty(t, redirectURL)
	assert.Contains(t, redirectURL, "code="+sessionID)
	assert.Contains(t, redirectURL, "state="+oidcState)
	t.Logf("Poll approved, redirect: %s", redirectURL)

	// 13. Browser follows redirect to demo callback
	callbackRes, err := noRedirectClient.Get(redirectURL)
	require.NoError(t, err)
	callbackRes.Body.Close()
	assert.Equal(t, http.StatusSeeOther, callbackRes.StatusCode)
	assert.Equal(t, "/", callbackRes.Header.Get("Location"))
	t.Log("Demo callback processed, redirecting to home")

	// 14. Browser visits demo home — should be authenticated
	finalRes, err := http.Get(demoURL + "/")
	require.NoError(t, err)
	finalBody, _ := io.ReadAll(finalRes.Body)
	finalRes.Body.Close()
	assert.Equal(t, http.StatusOK, finalRes.StatusCode)

	html := string(finalBody)
	// HTML encodes '+' as '&#43;' — use template.HTMLEscapeString for comparison
	escapedPubkey := template.HTMLEscapeString(pubkeyB64[:8])
	assert.Contains(t, html, escapedPubkey, "Demo should show truncated pubkey")
	assert.Contains(t, html, "Connected", "Demo should show Connected state")
	assert.Contains(t, html, "Authenticated", "Demo should show Authenticated badge")
	assert.NotContains(t, html, "Sign In with IDAP", "Should not show sign-in button when authenticated")
	t.Log("Demo shows authenticated state")

	// 15. Verify userinfo works with the token
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", sessionID)
	tokenForm.Set("client_id", "idap-demo")
	tokenRes, err := http.PostForm(proxyURL+"/auth/token", tokenForm)
	require.NoError(t, err)
	tokenBody, _ := io.ReadAll(tokenRes.Body)
	tokenRes.Body.Close()
	if tokenRes.StatusCode == http.StatusOK {
		var tokenResp map[string]any
		require.NoError(t, json.Unmarshal(tokenBody, &tokenResp))
		accessToken, ok := tokenResp["access_token"].(string)
		if ok && accessToken != "" {
			uiReq, _ := http.NewRequest(http.MethodGet, proxyURL+"/auth/userinfo", nil)
			uiReq.Header.Set("Authorization", "Bearer "+accessToken)
			uiRes, err := http.DefaultClient.Do(uiReq)
			require.NoError(t, err)
			defer uiRes.Body.Close()
			assert.Equal(t, http.StatusOK, uiRes.StatusCode)

			var userinfo map[string]any
			require.NoError(t, json.NewDecoder(uiRes.Body).Decode(&userinfo))
			assert.Equal(t, pubkeyB64, userinfo["sub"])
			t.Logf("Userinfo verified: sub=%s...", pubkeyB64[:8])
		}
	}

	// 16. Clear session on demo
	clearRes, err := noRedirectClient.Post(demoURL+"/clear", "", nil)
	require.NoError(t, err)
	clearRes.Body.Close()
	assert.Equal(t, http.StatusSeeOther, clearRes.StatusCode)

	afterClearRes, err := http.Get(demoURL + "/")
	require.NoError(t, err)
	afterClearBody, _ := io.ReadAll(afterClearRes.Body)
	afterClearRes.Body.Close()
	assert.Contains(t, string(afterClearBody), "Sign In with IDAP", "After clear, should show sign-in again")
	t.Log("Session cleared, demo back to sign-in state")

	t.Log("=== Integration test PASSED: Full OIDC flow across proxy + demo + simulated app ===")
}

// extractHref finds a link in HTML that contains the given substring and returns the full href value.
func extractHref(t *testing.T, html, substring string) string {
	t.Helper()
	idx := strings.Index(html, substring)
	if idx < 0 {
		return ""
	}
	before := html[:idx]
	hrefStart := strings.LastIndex(before, `href="`)
	if hrefStart < 0 {
		return ""
	}
	hrefStart += len(`href="`)
	rest := html[hrefStart:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	raw := rest[:end]
	raw = strings.ReplaceAll(raw, "&amp;", "&")
	return raw
}

// ---- Integration test: error paths ----

func TestIntegration_DemoShowsErrorOnInvalidCallback(t *testing.T) {
	dbPath := fmt.Sprintf("file:intdb%d?mode=memory&cache=shared", time.Now().UnixNano())
	database, err := db.Open(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })

	providerKey, err := db.GenerateAndStoreProviderKey(database, "test")
	require.NoError(t, err)

	proxySrv := handlers.NewServer(database, providerKey, "", false, testLogger)
	proxyTS := httptest.NewServer(proxySrv.Router())
	t.Cleanup(proxyTS.Close)
	proxyURL := proxyTS.URL

	demoBin := buildDemo(t)
	demoPort := getFreePort(t)
	demoURL := fmt.Sprintf("http://127.0.0.1:%d", demoPort)

	demoCmd := exec.Command(demoBin)
	demoCmd.Env = append(os.Environ(),
		"PROXY_URL="+proxyURL,
		"PORT="+strconv.Itoa(demoPort),
	)
	require.NoError(t, demoCmd.Start())
	t.Cleanup(func() { demoCmd.Process.Kill(); demoCmd.Wait() })
	waitForServer(t, demoURL+"/", 5*time.Second)

	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	res, err := noRedirectClient.Get(demoURL + "/callback?code=BOGUS&state=x")
	require.NoError(t, err)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Contains(t, string(body), "Error", "Demo should show error page for invalid code")
}

func TestIntegration_ProxyDiscoveryEndpoints(t *testing.T) {
	dbPath := fmt.Sprintf("file:intdb%d?mode=memory&cache=shared", time.Now().UnixNano())
	database, err := db.Open(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })

	providerKey, err := db.GenerateAndStoreProviderKey(database, "test")
	require.NoError(t, err)

	proxySrv := handlers.NewServer(database, providerKey, "", false, testLogger)
	proxyTS := httptest.NewServer(proxySrv.Router())
	t.Cleanup(proxyTS.Close)

	res, err := http.Get(proxyTS.URL + "/.well-known/openid-configuration")
	require.NoError(t, err)
	defer res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)

	var cfg map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&cfg))

	authEndpoint := cfg["authorization_endpoint"].(string)
	tokenEndpoint := cfg["token_endpoint"].(string)
	userinfoEndpoint := cfg["userinfo_endpoint"].(string)

	authRes, err := http.Get(authEndpoint + "?client_id=test&redirect_uri=http://localhost/cb&nonce=n")
	require.NoError(t, err)
	authRes.Body.Close()
	assert.Equal(t, http.StatusOK, authRes.StatusCode)

	tokenRes, err := http.Post(tokenEndpoint, "application/json", bytes.NewBufferString(`{}`))
	require.NoError(t, err)
	tokenRes.Body.Close()
	assert.Equal(t, http.StatusBadRequest, tokenRes.StatusCode)

	uiRes, err := http.Get(userinfoEndpoint)
	require.NoError(t, err)
	uiRes.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, uiRes.StatusCode)
}
