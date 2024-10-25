package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	_ "github.com/mattn/go-sqlite3"
)

// Key holds an RSA key pair
type Key struct {
	ID         string
	PrivateKey *rsa.PrivateKey
	Expiry     time.Time
}

var db *sql.DB

// initDB creates the database and keys table
func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", "./totally_not_my_privateKeys.db")
	if err != nil {
		return err
	}

	// Create keys table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS keys(
			kid INTEGER PRIMARY KEY AUTOINCREMENT,
			key BLOB NOT NULL,
			exp INTEGER NOT NULL
		)
	`)
	return err
}

// generateKey creates a new RSA key pair and adds it to the database
func generateKey(expired bool) error {
	// Generate RSA key
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Convert to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Set expiry
	expiry := time.Now().Add(24 * time.Hour)
	if expired {
		expiry = time.Now().Add(-1 * time.Hour)
	}

	// Store in database
	_, err := db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", privateKeyPEM, expiry.Unix())
	return err
}

// jwksHandler sends the public keys as a JWKS
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}

	// Get valid keys from database
	rows, err := db.Query("SELECT kid, key FROM keys WHERE exp > ?", time.Now().Unix())
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var pemKey []byte
		var kid int64
		if err := rows.Scan(&kid, &pemKey); err != nil {
			continue
		}

		// Parse the key
		block, _ := pem.Decode(pemKey)
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			continue
		}

		// Add to JWKS
		jwks.Keys = append(jwks.Keys, map[string]string{
			"kid": fmt.Sprintf("%d", kid),
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.E)).Bytes()),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// authHandler creates and sends a JWT
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	wantExpired := r.URL.Query().Get("expired") == "true"

	// Get key from database
	var query string
	if wantExpired {
		query = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY kid DESC LIMIT 1"
	} else {
		query = "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1"
	}

	var pemKey []byte
	var kid int64
	var expiry int64
	err := db.QueryRow(query, time.Now().Unix()).Scan(&kid, &pemKey, &expiry)
	if err != nil {
		http.Error(w, "No suitable key found", http.StatusNotFound)
		return
	}

	// Parse the key
	block, _ := pem.Decode(pemKey)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		http.Error(w, "Error parsing key", http.StatusInternalServerError)
		return
	}

	// Create and sign the JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp": expiry,
	})
	token.Header["kid"] = fmt.Sprintf("%d", kid)

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		http.Error(w, "Error signing token", http.StatusInternalServerError)
		return
	}

	// Return JWT in JSON format
	response := struct {
		Token string `json:"jwt"`
	}{
		Token: tokenString,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func main() {
	fmt.Println("Starting JWKS server...")

	if err := initDB(); err != nil {
		fmt.Printf("Failed to initialize database: %v\n", err)
		return
	}
	fmt.Println("Database initialized successfully")

	// Generate initial keys
	if err := generateKey(false); err != nil { // Valid key
		fmt.Printf("Error generating valid key: %v\n", err)
		return
	}
	fmt.Println("Generated valid key")

	if err := generateKey(true); err != nil { // Expired key
		fmt.Printf("Error generating expired key: %v\n", err)
		return
	}
	fmt.Println("Generated expired key")

	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/auth", authHandler)

	fmt.Println("Server listening on :8080")
	fmt.Println("Use Ctrl+C to stop the server")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
