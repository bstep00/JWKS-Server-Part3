package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func setupTest(t *testing.T) {
	// Use test database
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}

	// Initialize the database
	err = initDB()
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenerateKey(t *testing.T) {
	setupTest(t)
	defer db.Close()

	err := generateKey(false)
	if err != nil {
		t.Errorf("generateKey failed: %v", err)
	}

	err = generateKey(true)
	if err != nil {
		t.Errorf("generateKey failed: %v", err)
	}

	// Verify keys in database
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
	defer db.Close()

	// Generate test keys
	generateKey(false)
	generateKey(true)

	req, err := http.NewRequest("GET", "/.well-known/jwks.json", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(jwksHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}

	err = json.Unmarshal(rr.Body.Bytes(), &jwks)
	if err != nil {
		t.Errorf("Failed to parse JWKS response: %v", err)
	}

	if len(jwks.Keys) == 0 {
		t.Errorf("JWKS response contained no keys")
	}

	// Test wrong HTTP method
	req, _ = http.NewRequest("POST", "/.well-known/jwks.json", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("handler returned wrong status code for POST: got %v want %v", status, http.StatusMethodNotAllowed)
	}
}

func TestAuthHandler(t *testing.T) {
	setupTest(t)
	defer db.Close()

	// Generate test keys
	generateKey(false)
	generateKey(true)

	tests := []struct {
		name           string
		method         string
		queryParam     string
		expectedStatus int
	}{
		{"Valid JWT", "POST", "", http.StatusCreated},
		{"Expired JWT", "POST", "?expired=true", http.StatusCreated},
		{"Wrong Method", "GET", "", http.StatusMethodNotAllowed},
		{"No Suitable Key", "POST", "?expired=invalid", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, "/auth"+tt.queryParam, nil)
			if err != nil {
				t.Fatal(err)
			}

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(authHandler)

			handler.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}

			if tt.expectedStatus == http.StatusCreated {
				if len(rr.Body.String()) == 0 {
					t.Errorf("Expected a JWT, got an empty response")
				}
			}
		})
	}
}

func TestMain(m *testing.M) {
	// Run tests
	code := m.Run()

	// Clean up
	if db != nil {
		db.Close()
	}
	os.Exit(code)
}
