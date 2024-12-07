/*
AI was used in parts of this project:
- Helped debug and fix test coverage issues, mostly with database cleanup between tests
- Helped troubleshoot SQL database interactions
- Suggested improvements for code functionality, such as proper database connection handling and better test isolation methods.

The core implementation and logic is my own work, with AI helping primarily with debugging and troubleshooting.
*/

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
)

// SQL statements for table creation
const (
	createKeysTableSQL = `
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )`

	createUsersTableSQL = `
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )`

	createAuthLogsTableSQL = `
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`
)

// argon2Params holds the configuration for password hashing
type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

// Global variables for database connection and argon2 configuration
var (
	db           *sql.DB
	argon2Config = &argon2Params{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		saltLength:  16,
		keyLength:   32,
	}
)

// generateSalt creates a cryptographically secure random salt
func generateSalt(length uint32) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	return salt, err
}

// hashPassword creates a secure hash of a password using Argon2
func hashPassword(password string, params *argon2Params) (string, error) {
	salt, err := generateSalt(params.saltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		params.keyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		params.memory,
		params.iterations,
		params.parallelism,
		b64Salt,
		b64Hash,
	)

	return encodedHash, nil
}

// initDB creates the database and required tables
func initDB() error {
	var err error
	db, err = sql.Open("sqlite3", "./totally_not_my_privateKeys.db")
	if err != nil {
		return err
	}

	for _, query := range []string{
		createKeysTableSQL,
		createUsersTableSQL,
		createAuthLogsTableSQL,
	} {
		if _, err := db.Exec(query); err != nil {
			return err
		}
	}

	return nil
}

// encryptKey encrypts a private key using AES-GCM
func encryptKey(key []byte) ([]byte, error) {
	encKey := os.Getenv("NOT_MY_KEY")
	if len(encKey) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes")
	}

	block, err := aes.NewCipher([]byte(encKey))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, key, nil), nil
}

// decryptKey decrypts a private key using AES-GCM
func decryptKey(encrypted []byte) ([]byte, error) {
	encKey := os.Getenv("NOT_MY_KEY")
	if len(encKey) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes")
	}

	block, err := aes.NewCipher([]byte(encKey))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// generateKey creates a new RSA key pair and stores it in the database
func generateKey(expired bool) error {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Convert to PEM
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encrypt the PEM data
	encryptedKey, err := encryptKey(privateKeyPEM)
	if err != nil {
		return fmt.Errorf("error encrypting key: %v", err)
	}

	// Set expiry
	expiry := time.Now().Add(24 * time.Hour)
	if expired {
		expiry = time.Now().Add(-1 * time.Hour)
	}

	// Store encrypted key
	_, err = db.Exec("INSERT INTO keys (key, exp) VALUES (?, ?)", encryptedKey, expiry.Unix())
	if err != nil {
		return fmt.Errorf("error storing key: %v", err)
	}

	return nil
}

// registerHandler processes new user registration requests
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	password := uuid.New().String()

	hashedPassword, err := hashPassword(password, argon2Config)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(
		"INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
		req.Username,
		hashedPassword,
		req.Email,
	)
	if err != nil {
		http.Error(w, "Username or email already exists", http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"password": password,
	})
}

// verifyPassword checks if a provided password matches the stored hash
func verifyPassword(password, username string) bool {
	// Get the stored hash for the user
	var storedHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&storedHash)
	if err != nil {
		fmt.Printf("Error retrieving password hash: %v\n", err)
		return false
	}

	// Parse the hash parameters
	parts := strings.Split(storedHash, "$")
	if len(parts) != 5 {
		fmt.Printf("Invalid hash format\n")
		return false
	}

	var params argon2Params
	_, err = fmt.Sscanf(parts[2], "v=19$m=%d,t=%d,p=%d", &params.memory, &params.iterations, &params.parallelism)
	if err != nil {
		fmt.Printf("Error parsing hash parameters: %v\n", err)
		return false
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		fmt.Printf("Error decoding salt: %v\n", err)
		return false
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		fmt.Printf("Error decoding hash: %v\n", err)
		return false
	}

	// Set key length from decoded hash
	params.keyLength = uint32(len(decodedHash))
	params.saltLength = uint32(len(salt))

	// Compute hash of provided password
	targetHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		params.keyLength,
	)

	// Compare in constant time
	match := subtle.ConstantTimeCompare(targetHash, decodedHash) == 1
	if !match {
		fmt.Printf("Password verification failed for user: %s\n", username)
	}

	return match
}

// updateLastLogin updates the last_login timestamp for a user
func updateLastLogin(userID int64) error {
	_, err := db.Exec(
		"UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
		userID,
	)
	return err
}

// logAuthRequest logs authentication requests and updates last login time
func logAuthRequest(userID int64, r *http.Request) error {
	if err := updateLastLogin(userID); err != nil {
		return err
	}

	_, err := db.Exec(
		"INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
		r.RemoteAddr,
		userID,
	)
	return err
}

// jwksHandler serves the JWKS (JSON Web Key Set) endpoint
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}

	rows, err := db.Query("SELECT kid, key FROM keys WHERE exp > ?", time.Now().Unix())
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var encryptedKey []byte
		var kid int64
		if err := rows.Scan(&kid, &encryptedKey); err != nil {
			continue
		}

		pemKey, err := decryptKey(encryptedKey)
		if err != nil {
			continue
		}

		block, _ := pem.Decode(pemKey)
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			continue
		}

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

// authHandler handles authentication requests and JWT token generation
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var userID int64
	username, password, hasBasic := r.BasicAuth()
	if hasBasic {
		err := db.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID)
		if err != nil || !verifyPassword(password, username) {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	} else {
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		err := db.QueryRow("SELECT id FROM users WHERE username = ?", creds.Username).Scan(&userID)
		if err != nil || !verifyPassword(creds.Password, creds.Username) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if err := logAuthRequest(userID, r); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	wantExpired := r.URL.Query().Get("expired") == "true"

	var query string
	if wantExpired {
		query = "SELECT kid, key FROM keys WHERE exp <= ? ORDER BY kid DESC LIMIT 1"
	} else {
		query = "SELECT kid, key FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1"
	}

	var encryptedKey []byte
	var kid int64
	err := db.QueryRow(query, time.Now().Unix()).Scan(&kid, &encryptedKey)
	if err != nil {
		http.Error(w, "No suitable key found", http.StatusNotFound)
		return
	}

	pemKey, err := decryptKey(encryptedKey)
	if err != nil {
		http.Error(w, "Error decrypting key", http.StatusInternalServerError)
		return
	}

	block, _ := pem.Decode(pemKey)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		http.Error(w, "Error parsing key", http.StatusInternalServerError)
		return
	}

	var exp int64
	err = db.QueryRow("SELECT exp FROM keys WHERE kid = ?", kid).Scan(&exp)
	if err != nil {
		http.Error(w, "Error getting expiry", http.StatusInternalServerError)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp": exp,
	})
	token.Header["kid"] = fmt.Sprintf("%d", kid)

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		http.Error(w, "Error signing token", http.StatusInternalServerError)
		return
	}

	response := struct {
		Token string `json:"jwt"`
	}{
		Token: tokenString,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// main initializes and starts the server
func main() {
	fmt.Println("Starting server...")

	// Check for encryption key
	if os.Getenv("NOT_MY_KEY") == "" {
		fmt.Println("Error: NOT_MY_KEY environment variable not set")
		fmt.Println("Please set a 32-byte encryption key, for example:")
		fmt.Println("export NOT_MY_KEY=12345678901234567890123456789012")
		return
	}

	if err := initDB(); err != nil {
		fmt.Printf("Failed to initialize database: %v\n", err)
		return
	}
	fmt.Println("Successfully initialized database!")

	// Create default user if it doesn't exist
	hashedPassword, err := hashPassword("password123", argon2Config)
	if err != nil {
		fmt.Printf("Error hashing default password: %v\n", err)
		return
	}

	_, err = db.Exec(
		"INSERT OR IGNORE INTO users (username, password_hash, email) VALUES (?, ?, ?)",
		"userABC",
		hashedPassword,
		"user@example.com",
	)
	if err != nil {
		fmt.Printf("Error creating default user: %v\n", err)
		return
	}

	if err := generateKey(false); err != nil {
		fmt.Printf("Error generating valid key: %v\n", err)
		return
	}
	fmt.Println("Valid key generated!")

	if err := generateKey(true); err != nil {
		fmt.Printf("Error generating expired key: %v\n", err)
		return
	}
	fmt.Println("Expired key generated!")

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)
	http.HandleFunc("/auth", authHandler)

	fmt.Println("Server listening on port 8080...")
	fmt.Println("Exit with Control + C...")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
