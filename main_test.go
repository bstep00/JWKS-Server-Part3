package main

import (
    "database/sql"
    "encoding/json"
    "io"
    "net/http"
    "net/http/httptest"
    "os"
    "strings"
    "testing"
    "time"
)

const testDBPath = "./test_keys.db"

func resetDB(t *testing.T) {
    // Close existing connection if any
    if db != nil {
        db.Close()
        db = nil
    }

    // Remove the database file
    os.Remove(testDBPath)

    // Create a new connection
    var err error
    db, err = sql.Open("sqlite3", testDBPath)
    if err != nil {
        t.Fatalf("Failed to open test database: %v", err)
    }

    // Initialize schema
    err = initDB()
    if err != nil {
        t.Fatalf("Failed to initialize test database: %v", err)
    }
}

func TestGenerateKey(t *testing.T) {
    resetDB(t)
    defer os.Remove(testDBPath)

    err := generateKey(false)
    if err != nil {
        t.Errorf("generateKey failed: %v", err)
    }

    err = generateKey(true)
    if err != nil {
        t.Errorf("generateKey failed: %v", err)
    }

    var count int
    err = db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
    if err != nil {
        t.Errorf("Failed to count keys: %v", err)
    }
    if count != 2 {
        t.Errorf("Expected 2 keys in database, got %d", count)
    }
}

func TestJWKSHandler(t *testing.T) {
    resetDB(t)
    defer os.Remove(testDBPath)

    // Generate a test key
    generateKey(false)

    req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
    rr := httptest.NewRecorder()
    jwksHandler(rr, req)

    if status := rr.Code; status != http.StatusOK {
        t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
    }

    var jwks struct {
        Keys []map[string]string `json:"keys"`
    }

    err := json.NewDecoder(rr.Body).Decode(&jwks)
    if err != nil {
        t.Errorf("Failed to parse JWKS response: %v", err)
    }

    if len(jwks.Keys) == 0 {
        t.Errorf("JWKS response contained no keys")
    }
}

func TestJWKSHandlerErrors(t *testing.T) {
    resetDB(t)
    defer os.Remove(testDBPath)

    tests := []struct {
        name           string
        method         string
        expectedStatus int
    }{
        {"Invalid Method POST", "POST", http.StatusMethodNotAllowed},
        {"Invalid Method PUT", "PUT", http.StatusMethodNotAllowed},
        {"Invalid Method DELETE", "DELETE", http.StatusMethodNotAllowed},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            req := httptest.NewRequest(tt.method, "/.well-known/jwks.json", nil)
            rr := httptest.NewRecorder()
            jwksHandler(rr, req)

            if status := rr.Code; status != tt.expectedStatus {
                t.Errorf("handler returned wrong status code: got %v want %v",
                    status, tt.expectedStatus)
            }
        })
    }
}

func TestAuthHandler(t *testing.T) {
    tests := []struct {
        name           string
        method         string
        queryParam     string
        setupKeys      bool
        expectedStatus int
    }{
        {"Valid JWT", "POST", "", true, http.StatusCreated},
        {"Expired JWT", "POST", "?expired=true", true, http.StatusCreated},
        {"Wrong Method", "GET", "", true, http.StatusMethodNotAllowed},
        {"No Suitable Key", "POST", "?expired=invalid", false, http.StatusNotFound},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            resetDB(t)
            defer os.Remove(testDBPath)

            if tt.setupKeys {
                generateKey(false)
                generateKey(true)
            }

            req := httptest.NewRequest(tt.method, "/auth"+tt.queryParam, nil)
            rr := httptest.NewRecorder()
            authHandler(rr, req)

            if status := rr.Code; status != tt.expectedStatus {
                t.Errorf("handler returned wrong status code: got %v want %v",
                    status, tt.expectedStatus)
            }

            if tt.expectedStatus == http.StatusCreated {
                var response struct {
                    Token string `json:"jwt"`
                }
                if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
                    t.Errorf("Failed to decode response: %v", err)
                }
                if response.Token == "" {
                    t.Error("Expected JWT in response, got none")
                }
            }
        })
    }
}

func TestDatabaseErrors(t *testing.T) {
    resetDB(t)
    defer os.Remove(testDBPath)

    // Test database error in JWKS handler
    if err := db.Close(); err != nil {
        t.Fatalf("Failed to close database: %v", err)
    }

    req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
    rr := httptest.NewRecorder()
    jwksHandler(rr, req)

    if status := rr.Code; status != http.StatusInternalServerError {
        t.Errorf("handler should return 500 on db error, got %v", status)
    }
}

func TestMainFunction(t *testing.T) {
    // Save original stdout
    originalStdout := os.Stdout
    r, w, _ := os.Pipe()
    os.Stdout = w

    // Run main in goroutine
    go func() {
        main()
    }()

    // Wait a bit for server to start
    time.Sleep(500 * time.Millisecond)

    // Close write end of pipe and restore stdout
    w.Close()
    os.Stdout = originalStdout

    // Read output
    output, _ := io.ReadAll(r)
    outputStr := string(output)

    // Check for expected output
    expectedMessages := []string{
        "Starting JWKS server...",
        "Database initialized successfully",
        "Generated valid key",
        "Generated expired key",
        "Server listening on :8080",
    }

    for _, msg := range expectedMessages {
        if !strings.Contains(outputStr, msg) {
            t.Errorf("Expected output to contain '%s', but it didn't", msg)
        }
    }

    // Clean up
    if db != nil {
        db.Close()
    }
    os.Remove("./totally_not_my_privateKeys.db")
}