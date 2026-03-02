package auth

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// TypedKey is a typed public key for wire transmission.
type TypedKey struct {
	Kty string `json:"kty"`
	Key string `json:"key"` // base64url-encoded raw public key
}

// NewTypedKey creates a TypedKey from a key type and raw bytes.
func NewTypedKey(kty string, raw []byte) TypedKey {
	return TypedKey{
		Kty: kty,
		Key: base64.RawURLEncoding.EncodeToString(raw),
	}
}

// Decode returns the raw key bytes from the base64url string.
func (tk TypedKey) Decode() ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(tk.Key)
}

// KeyBundle is the stored public key bundle for a user.
type KeyBundle struct {
	SigningKey     TypedKey   `json:"signing_key"`
	AgreementKey   TypedKey   `json:"agreement_key"`
	SignedPreKey   *TypedKey  `json:"signed_pre_key,omitempty"`
	OneTimePreKeys []TypedKey `json:"one_time_pre_keys,omitempty"`
}

// ParseKeyBundle unmarshals a key bundle JSON string.
func ParseKeyBundle(s string) (*KeyBundle, error) {
	var kb KeyBundle
	if err := json.Unmarshal([]byte(s), &kb); err != nil {
		return nil, err
	}
	return &kb, nil
}

// VerifyRequestSignature verifies the X-IDAP-Signature header.
// Signed data: "{METHOD}:{PATH}:{TIMESTAMP}"
// The public key is read directly from the X-IDAP-Key header (base64 encoded).
// Returns the base64-encoded public key as identity.
func VerifyRequestSignature(r *http.Request, db *sql.DB) (string, error) {
	keyB64 := r.Header.Get("X-IDAP-Key")
	if keyB64 == "" {
		return "", fmt.Errorf("missing X-IDAP-Key")
	}
	sigB64 := r.Header.Get("X-IDAP-Signature")
	if sigB64 == "" {
		return "", fmt.Errorf("missing X-IDAP-Signature")
	}
	tsStr := r.Header.Get("X-IDAP-Timestamp")
	if tsStr == "" {
		return "", fmt.Errorf("missing X-IDAP-Timestamp")
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return "", fmt.Errorf("invalid timestamp")
	}
	now := time.Now().Unix()
	if now-ts > 60 || ts-now > 60 {
		slog.Debug("timestamp out of window", "pubkey", keyB64[:8], "ts", ts, "now", now)
		return "", fmt.Errorf("timestamp out of window")
	}

	slog.Debug("verifying request signature", "pubkey", keyB64[:8], "method", r.Method, "path", r.URL.Path)

	// Decode public key directly from header
	pubKeyBytes, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		pubKeyBytes, err = base64.RawStdEncoding.DecodeString(keyB64)
		if err != nil {
			return "", fmt.Errorf("decode public key: %w", err)
		}
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid public key size")
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		sig, err = base64.RawStdEncoding.DecodeString(sigB64)
		if err != nil {
			return "", fmt.Errorf("decode signature: %w", err)
		}
	}

	message := fmt.Sprintf("%s:%s:%s", r.Method, r.URL.Path, tsStr)
	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), []byte(message), sig) {
		slog.Debug("signature verification failed", "pubkey", keyB64[:8])
		return "", fmt.Errorf("invalid signature")
	}

	// Verify key is registered
	var exists int
	err = db.QueryRow(`SELECT 1 FROM users WHERE pubkey = ?`, keyB64).Scan(&exists)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("unknown key")
	}
	if err != nil {
		return "", fmt.Errorf("db error: %w", err)
	}

	slog.Debug("signature verified", "pubkey", keyB64[:8])
	return keyB64, nil
}
