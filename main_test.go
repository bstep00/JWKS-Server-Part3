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
	// Set encryption key for tests
	os.Setenv("NOT_MY_KEY", "12345678901234567890123456789012")

	// Remove existing database
	os.Remove(testDBPath)
	os.Remove("./totally_not_my_privateKeys.db")

	// Close existing connection
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

	// Foreign keys
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	// Remove existing tables
	_, err = db.Exec("DROP TABLE IF EXISTS auth_logs")
	if err != nil {
		t.Fatalf("Failed to drop auth_logs table: %v", err)
	}
	_, err = db.Exec("DROP TABLE IF EXISTS keys")
	if err != nil {
		t.Fatalf("Failed to drop keys table: %v", err)
	}
	_, err = db.Exec("DROP TABLE IF EXISTS users")
	if err != nil {
		t.Fatalf("Failed to drop users table: %v", err)
	}

	// Create tables
	for _, query := range []string{
		createKeysTableSQL,
		createUsersTableSQL,
		createAuthLogsTableSQL,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatalf("Failed to create table: %v", err)
		}
	}

	// Create test user
	hashedPassword, err := hashPassword("password123", argon2Config)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	t.Logf("Debug: Created hash: %s", hashedPassword)

	// Insert a test user
	_, err = db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", "testuser", "testhash")
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	result, err := db.Exec(
		"INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
		"userABC",
		hashedPassword,
		"user@example.com",
	)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		t.Fatalf("Failed to get rows affected: %v", err)
	}
	if rows != 1 {
		t.Fatal("Failed to create test user")
	}

	// Verify the hash was stored
	var storedHash string
	err = db.QueryRow("SELECT password_hash FROM users WHERE username = ?", "userABC").Scan(&storedHash)
	if err != nil {
		t.Fatalf("Failed to retrieve stored hash: %v", err)
	}
	t.Logf("Debug: Stored hash: %s", storedHash)
}

func cleanupTest() {
	if db != nil {
		// Clean up tables
		db.Exec("DROP TABLE IF EXISTS auth_logs")
		db.Exec("DROP TABLE IF EXISTS keys")
		db.Exec("DROP TABLE IF EXISTS users")

		db.Close()
		db = nil
	}
	os.Remove(testDBPath)
	os.Remove("./totally_not_my_privateKeys.db")
	os.Unsetenv("NOT_MY_KEY")
}

// Tests key generation
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

// Check valid JWKS response
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

// Verifies JWKS handler handles HTTP methods
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

// Tests AuthHandler methods with valid and invalid credentials
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
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Expired JWT Basic Auth",
			method:         "POST",
			queryParam:     "?expired=true",
			setupKeys:      true,
			useBasicAuth:   true,
			username:       "userABC",
			password:       "password123",
			expectedStatus: http.StatusOK,
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

			if tt.expectedStatus == http.StatusOK {
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

// Tests handling of user login requests
func TestAuthHandlerJSONAuth(t *testing.T) {
	setupTest(t)
	defer cleanupTest()
	generateKey(false)

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

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
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

// Simulates database connect issues
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

// Checks output of main and initialization of server
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

// Tests hashes and passwords
func TestPasswordHashing(t *testing.T) {
	setupTest(t)
	defer cleanupTest()

	// Delete test user to avoid any conflicts
	_, err := db.Exec("DELETE FROM users WHERE username = ? OR email = ?",
		"testuser", "test@example.com")
	if err != nil {
		t.Fatalf("Failed to clean up test user: %v", err)
	}

	password := "testpassword"
	hash, err := hashPassword(password, argon2Config)
	if err != nil {
		t.Fatalf("Password hashing failed: %v", err)
	}

	// Insert new user with the hash
	_, err = db.Exec(
		"INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
		"testuser",
		hash,
		"test@example.com",
	)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Verify the password works
	if !verifyPassword(password, "testuser") {
		t.Error("Password verification failed after hashing and storing")
	}
}

// Tests encyrption and decryption of keys
func TestKeyEncryption(t *testing.T) {
	setupTest(t)
	defer cleanupTest()

	// Test encryption/decryption
	originalData := []byte("test data")
	encrypted, err := encryptKey(originalData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := decryptKey(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(originalData) {
		t.Error("Decrypted data doesn't match original")
	}

	// Test invalid encryption key
	os.Setenv("NOT_MY_KEY", "tooshort")
	_, err = encryptKey([]byte("test"))
	if err == nil {
		t.Error("Expected error with invalid encryption key")
	}
}

// Tests logging of auth attempts
func TestAuthLogging(t *testing.T) {
	setupTest(t)
	defer cleanupTest()
	generateKey(false)

	req := httptest.NewRequest("POST", "/auth", nil)
	req.SetBasicAuth("userABC", "password123")
	rr := httptest.NewRecorder()
	authHandler(rr, req)

	// Verify log entry
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM auth_logs").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count auth logs: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 auth log entry, got %d", count)
	}

	// Verify log content
	var userID int64
	var requestIP string
	err = db.QueryRow("SELECT user_id, request_ip FROM auth_logs LIMIT 1").Scan(&userID, &requestIP)
	if err != nil {
		t.Fatalf("Failed to retrieve auth log: %v", err)
	}
	if userID == 0 {
		t.Error("Expected non-zero user_id in auth log")
	}
}

// Tests registration endpoint with valid and invalid input
func TestRegistrationEndpoint(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		requestBody   string
		expectedCode  int
		checkPassword bool
	}{
		{
			name:          "Valid Registration",
			method:        http.MethodPost,
			requestBody:   `{"username":"newuser","email":"new@example.com"}`,
			expectedCode:  http.StatusOK,
			checkPassword: true,
		},
		{
			name:          "Invalid JSON",
			method:        http.MethodPost,
			requestBody:   `{"username":`,
			expectedCode:  http.StatusBadRequest,
			checkPassword: false,
		},
		{
			name:          "Missing Email",
			method:        http.MethodPost,
			requestBody:   `{"username":"test"}`,
			expectedCode:  http.StatusBadRequest,
			checkPassword: false,
		},
		{
			name:          "Missing Username",
			method:        http.MethodPost,
			requestBody:   `{"email":"test@example.com"}`,
			expectedCode:  http.StatusBadRequest,
			checkPassword: false,
		},
		{
			name:          "Empty Username",
			method:        http.MethodPost,
			requestBody:   `{"username":"","email":"test@example.com"}`,
			expectedCode:  http.StatusBadRequest,
			checkPassword: false,
		},
		{
			name:          "Empty Email",
			method:        http.MethodPost,
			requestBody:   `{"username":"test","email":""}`,
			expectedCode:  http.StatusBadRequest,
			checkPassword: false,
		},
		{
			name:          "Wrong Method",
			method:        http.MethodGet,
			requestBody:   `{"username":"test","email":"test@example.com"}`,
			expectedCode:  http.StatusMethodNotAllowed,
			checkPassword: false,
		},
		{
			name:          "Duplicate Username",
			method:        http.MethodPost,
			requestBody:   `{"username":"userABC","email":"another@example.com"}`,
			expectedCode:  http.StatusConflict,
			checkPassword: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupTest(t)
			defer cleanupTest()

			req := httptest.NewRequest(tt.method, "/register", strings.NewReader(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			registerHandler(rr, req)

			if status := rr.Code; status != tt.expectedCode {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tt.expectedCode)
			}

			if tt.checkPassword {
				var response struct {
					Password string `json:"password"`
				}
				if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
					t.Errorf("Failed to decode response: %v", err)
				}
				if response.Password == "" {
					t.Error("Expected password in response, got none")
				}
			}
		})
	}
}

// Tests that expired keys are replaced with new keys
func TestKeyRotation(t *testing.T) {
	setupTest(t)
	defer cleanupTest()

	// Generate a valid and expired key
	err := generateKey(false)
	if err != nil {
		t.Fatalf("Failed to generate valid key: %v", err)
	}
	err = generateKey(true)
	if err != nil {
		t.Fatalf("Failed to generate expired key: %v", err)
	}

	// Verify both keys
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM keys").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count keys: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 keys, got %d", count)
	}

	// Verify only valid keys
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	jwksHandler(rr, req)

	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&jwks); err != nil {
		t.Fatalf("Failed to decode JWKS: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Errorf("Expected 1 valid key in JWKS, got %d", len(jwks.Keys))
	}
}

// Checks that last login timestamp is updated during auth attempts
func TestLastLoginUpdate(t *testing.T) {
	setupTest(t)
	defer cleanupTest()
	generateKey(false)

	// Get initial last_login
	var initialLastLogin sql.NullString
	err := db.QueryRow("SELECT last_login FROM users WHERE username = ?", "userABC").Scan(&initialLastLogin)
	if err != nil {
		t.Fatalf("Failed to get initial last_login: %v", err)
	}

	// Make auth request
	req := httptest.NewRequest("POST", "/auth", nil)
	req.SetBasicAuth("userABC", "password123")
	rr := httptest.NewRecorder()
	authHandler(rr, req)

	// Verify last_login was updated
	var newLastLogin sql.NullString
	err = db.QueryRow("SELECT last_login FROM users WHERE username = ?", "userABC").Scan(&newLastLogin)
	if err != nil {
		t.Fatalf("Failed to get new last_login: %v", err)
	}

	if !newLastLogin.Valid {
		t.Error("Expected last_login to be set")
	}
	if initialLastLogin.String == newLastLogin.String {
		t.Error("Expected last_login to be updated")
	}
}

// Validates database initialization
func TestDBInitialization(t *testing.T) {
	// Clean up any existing database
	os.Remove("./totally_not_my_privateKeys.db")
	if db != nil {
		db.Close()
		db = nil
	}

	err := initDB()
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}

	// Verify all tables exist
	tables := []string{"keys", "users", "auth_logs"}
	for _, table := range tables {
		var count int
		err = db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count)
		if err != nil {
			t.Errorf("Failed to check for table %s: %v", table, err)
		}
		if count != 1 {
			t.Errorf("Table %s was not created", table)
		}
	}
}

// Tests password verification
func TestVerifyPassword(t *testing.T) {
	setupTest(t)
	defer cleanupTest()

	// Test with correct password
	if !verifyPassword("password123", "userABC") {
		t.Error("Password verification failed for correct password")
	}

	// Test with incorrect password
	if verifyPassword("wrongpassword", "userABC") {
		t.Error("Password verification succeeded with wrong password")
	}

	// Test with non-existent user
	if verifyPassword("password123", "nonexistent") {
		t.Error("Password verification succeeded with non-existent user")
	}
}

// Simulates database initialization failures
func TestInitDBFailures(t *testing.T) {
	// Clean up any existing state
	if db != nil {
		db.Close()
		db = nil
	}

	// Create a directory and file with read only permissions
	testDir := "./readonly_test_dir"
	os.RemoveAll(testDir)
	err := os.Mkdir(testDir, 0755) // Create directory with normal permissions
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Create an empty file with read only permissions
	testFile := testDir + "/test.db"
	f, err := os.Create(testFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	f.Close()

	// Make the file read only
	err = os.Chmod(testFile, 0444)
	if err != nil {
		t.Fatalf("Failed to set file permissions: %v", err)
	}

	// Try to open and initialize the read only database
	testDb, err := sql.Open("sqlite3", testFile)
	if err != nil {
		return
	}
	defer testDb.Close()

	// Try to create tables
	_, err = testDb.Exec(createKeysTableSQL)
	if err == nil {
		t.Error("Expected error creating tables in read-only database")
	}
}

// Tests JWKS Handler with invalid keys
func TestJWKSHandlerWithInvalidKey(t *testing.T) {
	setupTest(t)
	defer cleanupTest()

	// Insert invalid key data
	_, err := db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		[]byte("not-valid-key-data"),
		time.Now().Add(time.Hour).Unix(),
	)
	if err != nil {
		t.Fatalf("Failed to insert invalid key: %v", err)
	}

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	rr := httptest.NewRecorder()
	jwksHandler(rr, req)

	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&jwks); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Should skip invalid key but not fail
	if len(jwks.Keys) != 0 {
		t.Errorf("Expected no valid keys, got %d", len(jwks.Keys))
	}
}

// Verifies auth handler's response to invalid inputs
func TestAuthHandlerWithInvalidKey(t *testing.T) {
	setupTest(t)
	defer cleanupTest()

	// Insert invalid key data
	_, err := db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		[]byte("not-valid-key-data"),
		time.Now().Add(time.Hour).Unix(),
	)
	if err != nil {
		t.Fatalf("Failed to insert invalid key: %v", err)
	}

	req := httptest.NewRequest("POST", "/auth", nil)
	req.SetBasicAuth("userABC", "password123")
	rr := httptest.NewRecorder()
	authHandler(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("Expected internal server error with invalid key, got %v", status)
	}
}

// Validates error handling
func TestDBErrorHandling(t *testing.T) {
	setupTest(t)
	defer cleanupTest()

	// Create a read only database to force write errors
	if err := db.Close(); err != nil {
		t.Fatalf("Failed to close database: %v", err)
	}

	dbPath := "./readonly.db"
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Test generateKey with db error
	err = generateKey(false)
	if err == nil {
		t.Error("Expected error generating key with readonly database")
	}

	// Test logAuthRequest with db error
	err = logAuthRequest(1, httptest.NewRequest("GET", "/", nil))
	if err == nil {
		t.Error("Expected error logging auth request with readonly database")
	}

	// Test updateLastLogin with db error
	err = updateLastLogin(1)
	if err == nil {
		t.Error("Expected error updating last login with readonly database")
	}
}

// Validates error handling
func TestKeyDecryptionError(t *testing.T) {
	setupTest(t)
	defer cleanupTest()

	// Test with invalid key size
	originalKey := os.Getenv("NOT_MY_KEY")
	os.Setenv("NOT_MY_KEY", "wrong-size-key")

	// Should fail encryption
	_, err := encryptKey([]byte("test"))
	if err == nil {
		t.Error("Expected error with wrong size key")
	}

	// Should fail decryption
	_, err = decryptKey([]byte("test"))
	if err == nil {
		t.Error("Expected error with wrong size key")
	}

	// Restore key
	os.Setenv("NOT_MY_KEY", originalKey)
}

// Checks response with invalid inputs
func TestAuthHandlerDatabaseErrors(t *testing.T) {
	setupTest(t)
	defer cleanupTest()
	generateKey(false)

	// Test with wrong key in database
	_, err := db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		[]byte("not-valid-encrypted-data"),
		time.Now().Add(time.Hour).Unix(),
	)
	if err != nil {
		t.Fatalf("Failed to insert invalid key: %v", err)
	}

	// This should cause a decryption error
	req := httptest.NewRequest("POST", "/auth", nil)
	req.SetBasicAuth("userABC", "password123")
	rr := httptest.NewRecorder()
	authHandler(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("Expected internal server error with invalid key data, got %v", status)
	}
}

// Tests response when environment variable is missing
func TestMainWithMissingEnvVar(t *testing.T) {
	origKey := os.Getenv("NOT_MY_KEY")
	os.Unsetenv("NOT_MY_KEY")
	defer os.Setenv("NOT_MY_KEY", origKey)

	originalStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	go func() {
		main()
	}()

	time.Sleep(100 * time.Millisecond)

	w.Close()
	os.Stdout = originalStdout

	output, _ := io.ReadAll(r)
	outputStr := string(output)

	if !strings.Contains(outputStr, "Error: NOT_MY_KEY environment variable not set") {
		t.Error("Expected error message about missing environment variable")
	}
}

// Tests database error handling
func TestInitDBPaths(t *testing.T) {
	// Clean up any existing state
	if db != nil {
		db.Close()
		db = nil
	}

	// Create a test file with read only permissions
	testFile := "./readonly.db"
	f, err := os.Create(testFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	f.Close()
	defer os.Remove(testFile)

	// Make the file read only
	err = os.Chmod(testFile, 0444)
	if err != nil {
		t.Fatalf("Failed to set file permissions: %v", err)
	}

	// Try to open and write to the read only database
	testDb, err := sql.Open("sqlite3", testFile)
	if err != nil {
		return
	}
	defer testDb.Close()

	// Try to create a table
	_, err = testDb.Exec(createKeysTableSQL)
	if err == nil {
		t.Error("Expected error creating table in read-only database")
	}
}

// Error handling for decrypting
func TestDecryptKeyErrors(t *testing.T) {
	setupTest(t)
	defer cleanupTest()

	// Test with nil input
	_, err := decryptKey(nil)
	if err == nil {
		t.Error("Expected error with nil input")
	}

	// Test with data shorter than nonce size
	shortData := []byte("too short")
	_, err = decryptKey(shortData)
	if err == nil {
		t.Error("Expected error with short data")
	}

	// Test with invalid nonce
	invalidData := make([]byte, 32)
	_, err = decryptKey(invalidData)
	if err == nil {
		t.Error("Expected error with invalid data")
	}
}

// Error handling for hashing passwords
func TestHashPasswordErrors(t *testing.T) {
	setupTest(t)
	defer cleanupTest()

	// Test with nil config
	_, err := hashPassword("test", nil)
	if err == nil {
		t.Error("Expected error with nil config")
	}

	// Test successful password hashing
	validConfig := &argon2Params{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		keyLength:   32,
	}

	hash, err := hashPassword("test", validConfig)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if hash == "" {
		t.Error("Expected non-empty hash")
	}

	// Verify hash format
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Error("Invalid hash format")
	}
}

// Error handling for encrypting
func TestEncryptKeyErrors(t *testing.T) {
	setupTest(t)
	defer cleanupTest()

	// Test with missing environment variable
	oldKey := os.Getenv("NOT_MY_KEY")
	os.Unsetenv("NOT_MY_KEY")
	_, err := encryptKey([]byte("test"))
	if err == nil {
		t.Error("Expected error with missing environment key")
	}
	os.Setenv("NOT_MY_KEY", oldKey)

	// Test encryption with empty data
	_, err = encryptKey([]byte(""))
	if err != nil {
		t.Errorf("Unexpected error with empty data: %v", err)
	}

	// Test encryption with nil data
	_, err = encryptKey(nil)
	if err != nil {
		t.Errorf("Unexpected error with nil data: %v", err)
	}
}

// More error handling for auth handler
func TestAuthHandlerErrors(t *testing.T) {
	setupTest(t)
	defer cleanupTest()

	// Test wrong JSON request
	badJSON := `{"username": "testuser", "password": }`
	req := httptest.NewRequest("POST", "/auth", strings.NewReader(badJSON))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	authHandler(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Expected bad request for malformed JSON, got %v", status)
	}

	// Test decryption error with invalid key data
	generateKey(false)

	// Insert an invalid key to cause a decryption error
	_, err := db.Exec(
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		[]byte("invalid-key-data"),
		time.Now().Add(time.Hour).Unix(),
	)
	if err != nil {
		t.Fatalf("Failed to insert invalid key: %v", err)
	}

	req = httptest.NewRequest("POST", "/auth", nil)
	req.SetBasicAuth("userABC", "password123")
	rr = httptest.NewRecorder()
	authHandler(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("Expected internal server error for decryption error, got %v", status)
	}
}
