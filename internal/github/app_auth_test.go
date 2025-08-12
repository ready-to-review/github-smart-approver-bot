package github

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestParsePrivateKey(t *testing.T) {
	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	tests := []struct {
		name    string
		pemData []byte
		wantErr bool
	}{
		{
			name:    "Valid PKCS1 key",
			pemData: generatePKCS1PEM(t, privateKey),
			wantErr: false,
		},
		{
			name:    "Valid PKCS8 key",
			pemData: generatePKCS8PEM(t, privateKey),
			wantErr: false,
		},
		{
			name:    "Invalid PEM data",
			pemData: []byte("not a valid PEM"),
			wantErr: true,
		},
		{
			name: "Invalid key data",
			pemData: pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: []byte("invalid key data"),
			}),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePrivateKey(tt.pemData)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePrivateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateJWT(t *testing.T) {
	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	appAuth := &AppAuth{
		appID:      12345,
		privateKey: privateKey,
	}

	// Generate JWT
	tokenString, err := appAuth.GenerateJWT()
	if err != nil {
		t.Fatalf("GenerateJWT() failed: %v", err)
	}

	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("Failed to parse generated JWT: %v", err)
	}

	if !token.Valid {
		t.Error("Generated JWT is not valid")
	}

	// Check claims
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		t.Fatal("Failed to get claims from token")
	}

	if claims.Issuer != "12345" {
		t.Errorf("Issuer = %v, want 12345", claims.Issuer)
	}

	// Check expiration (should be within 10 minutes)
	expTime := claims.ExpiresAt.Time
	now := time.Now()
	if expTime.Before(now) || expTime.After(now.Add(11*time.Minute)) {
		t.Errorf("Expiration time %v is not within expected range", expTime)
	}

	// Check issued at time
	issuedAt := claims.IssuedAt.Time
	if issuedAt.After(now) || issuedAt.Before(now.Add(-1*time.Minute)) {
		t.Errorf("IssuedAt time %v is not within expected range", issuedAt)
	}
}

func TestNewAppAuth(t *testing.T) {
	// Create a temporary key file
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "test-key-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// Write key to file
	pemData := generatePKCS1PEM(t, privateKey)
	if _, err := tmpFile.Write(pemData); err != nil {
		t.Fatalf("Failed to write key to file: %v", err)
	}
	_ = tmpFile.Close()

	tests := []struct {
		name           string
		appID          int64
		keyPath        string
		installationID int64
		wantErr        bool
	}{
		{
			name:           "Valid configuration",
			appID:          12345,
			keyPath:        tmpFile.Name(),
			installationID: 67890,
			wantErr:        false,
		},
		{
			name:           "Invalid app ID",
			appID:          0,
			keyPath:        tmpFile.Name(),
			installationID: 67890,
			wantErr:        true,
		},
		{
			name:           "Non-existent key file",
			appID:          12345,
			keyPath:        "/non/existent/file.pem",
			installationID: 67890,
			wantErr:        true,
		},
		{
			name:           "No installation ID (auto-detect)",
			appID:          12345,
			keyPath:        tmpFile.Name(),
			installationID: 0,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAppAuth(tt.appID, tt.keyPath, tt.installationID)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAppAuth() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Helper functions to generate PEM-encoded keys

func generatePKCS1PEM(t *testing.T, key *rsa.PrivateKey) []byte {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})
}

func generatePKCS8PEM(t *testing.T, key *rsa.PrivateKey) []byte {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS8 key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
}