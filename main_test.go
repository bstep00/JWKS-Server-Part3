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

func setupTest(t *testing.T) {
    // Drop existing database
    os.Remove(testDBPath)
    os.Remove("./totally_not_my_privateKeys.db")  // Also remove main database

    // Close existing connection if any
    if db != nil {
        db.Close()
        db = nil
    }

    // Create new database connection
    var err error
    db, err = sql.Open("sqlite3", testDBPath)
    if err != nil {
        t.Fatalf("Failed to open test database: %v", err)
    }

    // Drop and recreate table
    _, err = db.Exec("DROP TABLE IF EXISTS keys")
    if err != nil {
        t.Fatalf("Failed to drop table: %v", err)
    }

    // Create table
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    `)
    if err != nil {
        t.Fatalf("Failed to create table: %v", err)
    }
}

func cleanupTest() {
    if db != nil {
        db.Close()
        db = nil
    }
    os.Remove(testDBPath)
    os.Remove("./totally_not_my_privateKeys.db")
}

func TestGenerateKey(t *testing.T) {
    setupTest(t)
    defer cleanupTest()

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
    setupTest(t)
    defer cleanupTest()

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
    setupTest(t)
    defer cleanupTest()

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
        useBasicAuth   bool
        username       string
        password       string
        expectedStatus int
    }{
        {
            name:           "Valid JWT Basic Auth",
            method:         "POST",
            queryParam:     "",
            setupKeys:      true,
            useBasicAuth:   true,
            username:       "userABC",
            password:       "password123",
            expectedStatus: http.StatusCreated,
        },
        {
            name:           "Expired JWT Basic Auth",
            method:         "POST",
            queryParam:     "?expired=true",
            setupKeys:      true,
            useBasicAuth:   true,
            username:       "userABC",
            password:       "password123",
            expectedStatus: http.StatusCreated,
        },
        {
            name:           "Wrong Method",
            method:         "GET",
            queryParam:     "",
            setupKeys:      true,
            expectedStatus: http.StatusMethodNotAllowed,
        },
        {
            name:           "Invalid Auth",
            method:         "POST",
            queryParam:     "",
            setupKeys:      true,
            useBasicAuth:   true,
            username:       "wrong",
            password:       "wrong",
            expectedStatus: http.StatusUnauthorized,
        },
        {
            name:           "No Suitable Key",
            method:         "POST",
            queryParam:     "?expired=invalid",
            setupKeys:      false,
            useBasicAuth:   true,
            username:       "userABC",
            password:       "password123",
            expectedStatus: http.StatusNotFound,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            setupTest(t)
            defer cleanupTest()

            if tt.setupKeys {
                generateKey(false)
                generateKey(true)
            }

            req := httptest.NewRequest(tt.method, "/auth"+tt.queryParam, nil)
            if tt.useBasicAuth {
                req.SetBasicAuth(tt.username, tt.password)
            }
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

func TestAuthHandlerJSONAuth(t *testing.T) {
    setupTest(t)
    defer cleanupTest()
    generateKey(false)

    // Test JSON auth
    creds := struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }{
        Username: "userABC",
        Password: "password123",
    }

    body, err := json.Marshal(creds)
    if err != nil {
        t.Fatalf("Failed to marshal credentials: %v", err)
    }

    req := httptest.NewRequest("POST", "/auth", strings.NewReader(string(body)))
    req.Header.Set("Content-Type", "application/json")
    rr := httptest.NewRecorder()
    authHandler(rr, req)

    if status := rr.Code; status != http.StatusCreated {
        t.Errorf("handler returned wrong status code: got %v want %v",
            status, http.StatusCreated)
    }

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

func TestDatabaseErrors(t *testing.T) {
    setupTest(t)
    defer cleanupTest()

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
    setupTest(t)
    defer cleanupTest()

    originalStdout := os.Stdout
    r, w, _ := os.Pipe()
    os.Stdout = w

    go func() {
        main()
    }()

    time.Sleep(500 * time.Millisecond)

    w.Close()
    os.Stdout = originalStdout

    output, _ := io.ReadAll(r)
    outputStr := string(output)

    expectedMessages := []string{
        "Starting server...",
        "Successfully initialized database!",
        "Valid key generated!",
        "Expired key generated!",
        "Server listening on port 8080...",
    }

    for _, msg := range expectedMessages {
        if !strings.Contains(outputStr, msg) {
            t.Errorf("Expected output to contain '%s', but it didn't", msg)
        }
    }
}
