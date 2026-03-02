package db

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

// ProviderKey holds the proxy's RSA signing key for OIDC JWTs.
type ProviderKey struct {
	ID         string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	KID        string // first 16 hex chars of SHA-256 of DER-encoded public key
}

// LoadProviderKey loads a provider key from the database by ID.
func LoadProviderKey(database *sql.DB, id string) (*ProviderKey, error) {
	var privDER, pubDER []byte
	err := database.QueryRow(`SELECT private_key, public_key FROM provider_keys WHERE id = ?`, id).Scan(&privDER, &pubDER)
	if err != nil {
		return nil, fmt.Errorf("load provider key: %w", err)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	rsaPriv, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	rsaPub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	kid := computeKID(pubDER)
	return &ProviderKey{ID: id, PrivateKey: rsaPriv, PublicKey: rsaPub, KID: kid}, nil
}

// GenerateAndStoreProviderKey generates an RSA 2048-bit key pair, stores it, and returns the ProviderKey.
func GenerateAndStoreProviderKey(database *sql.DB, id string) (*ProviderKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}

	_, err = database.Exec(
		`INSERT INTO provider_keys(id, private_key, public_key) VALUES(?,?,?)`,
		id, privDER, pubDER,
	)
	if err != nil {
		return nil, fmt.Errorf("store provider key: %w", err)
	}

	kid := computeKID(pubDER)
	return &ProviderKey{ID: id, PrivateKey: privKey, PublicKey: &privKey.PublicKey, KID: kid}, nil
}

func computeKID(pubDER []byte) string {
	h := sha256.Sum256(pubDER)
	return hex.EncodeToString(h[:])[:16]
}

//go:embed schema.sql
var schema string

// Open opens (or creates) a SQLite database at path and applies the schema.
// path may be a file path ("idap.db") or an in-memory DSN
// ("file:x?mode=memory&cache=shared").
func Open(path string) (*sql.DB, error) {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	dsn := path + sep + "_journal_mode=WAL&_foreign_keys=on"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return db, nil
}
