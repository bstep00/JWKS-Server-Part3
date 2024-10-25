/*
AI was used in parts of this project:
- Helped debug and fix test coverage issues, mostly with database cleanup between tests
- Helped troubleshoot SQL database interactions
- Suggested improvements for code functionality, such as proper database connection handling and better test isolation methods.

The core implementation and logic is my own work, with AI helping primarily with debugging and troubleshooting.
*/


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

// Key holds an RSA key pair and its metadata
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

// generateKey creates a new RSA key pair and adds it to keys
func generateKey(expired bool) error {
    privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

    // Convert private key to PEM format
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

    // Check Basic Auth
    username, password, hasBasic := r.BasicAuth()
    if !hasBasic || (username != "userABC" || password != "password123") {
        // Try JSON auth
        var creds struct {
            Username string `json:"username"`
            Password string `json:"password"`
        }
        if err := json.NewDecoder(r.Body).Decode(&creds); err != nil ||
           creds.Username != "userABC" || creds.Password != "password123" {
            w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
    }

    wantExpired := r.URL.Query().Get("expired") == "true"

    // Get key from database
    var query string
    if wantExpired {
        query = "SELECT kid, key FROM keys WHERE exp <= ? ORDER BY kid DESC LIMIT 1"
    } else {
        query = "SELECT kid, key FROM keys WHERE exp > ? ORDER BY kid DESC LIMIT 1"
    }

    var pemKey []byte
    var kid int64
    err := db.QueryRow(query, time.Now().Unix()).Scan(&kid, &pemKey)
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

    var exp int64
    err = db.QueryRow("SELECT exp FROM keys WHERE kid = ?", kid).Scan(&exp)
    if err != nil {
        http.Error(w, "Error getting expiry", http.StatusInternalServerError)
        return
    }

    // Create and sign the JWT
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
        "exp": exp,
    })
    token.Header["kid"] = fmt.Sprintf("%d", kid)

    tokenString, err := token.SignedString(privateKey)
    if err != nil {
        http.Error(w, "Error signing token", http.StatusInternalServerError)
        return
    }

    // Return JWT in JSON response
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
    fmt.Println("Starting server...")

    if err := initDB(); err != nil {
        fmt.Printf("Failed to initialize database: %v\n", err)
        return
    }
    fmt.Println("Successfully initialized database!")

    // Generate initial keys
    if err := generateKey(false); err != nil { // Valid key
        fmt.Printf("Error generating valid key: %v\n", err)
        return
    }
    fmt.Println("Valid key generated!")

    if err := generateKey(true); err != nil { // Expired key
        fmt.Printf("Error generating expired key: %v\n", err)
        return
    }
    fmt.Println("Expired key generated!")

    http.HandleFunc("/.well-known/jwks.json", jwksHandler)
    http.HandleFunc("/auth", authHandler)

    fmt.Println("Server listening on port 8080...")
    fmt.Println("Exit with Control + C...")

    if err := http.ListenAndServe(":8080", nil); err != nil {
        fmt.Printf("Server error: %v\n", err)
    }
}
