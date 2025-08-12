package github

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v68/github"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

// AppAuth handles GitHub App authentication
type AppAuth struct {
	appID          int64
	privateKey     *rsa.PrivateKey
	installationID int64
	token          string
	tokenExpiry    time.Time
}

// NewAppAuth creates a new GitHub App authenticator
func NewAppAuth(appID int64, privateKeyPath string, installationID int64) (*AppAuth, error) {
	if appID <= 0 {
		return nil, fmt.Errorf("invalid app ID: %d", appID)
	}

	// Security: Validate private key path to prevent directory traversal
	if privateKeyPath == "" {
		return nil, fmt.Errorf("private key path cannot be empty")
	}
	
	// Security: Check for directory traversal attempts
	if strings.Contains(privateKeyPath, "../") || strings.Contains(privateKeyPath, "..\\") {
		return nil, fmt.Errorf("invalid private key path: directory traversal detected")
	}
	
	// Security: Ensure path is absolute to prevent relative path confusion
	if !filepath.IsAbs(privateKeyPath) {
		return nil, fmt.Errorf("private key path must be absolute")
	}

	// Read private key file with size limit to prevent memory exhaustion
	const maxKeySize = 64 * 1024 // 64KB should be more than enough for any RSA key
	file, err := os.Open(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("opening private key file: %w", err)
	}
	defer func() { _ = file.Close() }()
	
	// Get file info to check size
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("getting private key file info: %w", err)
	}
	
	if info.Size() > maxKeySize {
		return nil, fmt.Errorf("private key file too large: %d bytes (max %d)", info.Size(), maxKeySize)
	}
	
	// Read with size limit
	keyData := make([]byte, info.Size())
	_, err = io.ReadFull(file, keyData)
	if err != nil {
		return nil, fmt.Errorf("reading private key file: %w", err)
	}

	// Parse private key
	privateKey, err := parsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	return &AppAuth{
		appID:          appID,
		privateKey:     privateKey,
		installationID: installationID,
	}, nil
}

// parsePrivateKey parses a PEM-encoded RSA private key
func parsePrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS1 format first
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS8 format
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, fmt.Errorf("private key is not RSA")
	}

	return nil, fmt.Errorf("failed to parse private key")
}

// GenerateJWT generates a JWT for GitHub App authentication
func (a *AppAuth) GenerateJWT() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)), // GitHub max is 10 minutes
		Issuer:    strconv.FormatInt(a.appID, 10),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(a.privateKey)
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	return signedToken, nil
}

// ListInstallations returns all installations for this GitHub App
func (a *AppAuth) ListInstallations(ctx context.Context) ([]*github.Installation, error) {
	log.Printf("[GITHUB APP] Listing all installations for app ID %d...", a.appID)
	
	// Generate JWT
	jwtToken, err := a.GenerateJWT()
	if err != nil {
		return nil, fmt.Errorf("generating JWT: %w", err)
	}

	// Create a client with JWT authentication
	ts := &jwtTransport{
		token: jwtToken,
		base:  http.DefaultTransport,
	}
	client := &http.Client{Transport: ts}
	ghClient := github.NewClient(client)

	// List all installations
	var allInstallations []*github.Installation
	opts := &github.ListOptions{PerPage: 100}
	
	for {
		installations, resp, err := ghClient.Apps.ListInstallations(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("listing installations: %w", err)
		}
		
		allInstallations = append(allInstallations, installations...)
		
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	
	log.Printf("[GITHUB APP] Found %d installations", len(allInstallations))
	for _, inst := range allInstallations {
		log.Printf("[GITHUB APP]   - Installation ID: %d, Account: %s (%s)", 
			inst.GetID(), inst.GetAccount().GetLogin(), inst.GetAccount().GetType())
	}
	
	return allInstallations, nil
}

// GetInstallationToken exchanges a JWT for an installation access token
// It caches the token and only refreshes when expired or about to expire
func (a *AppAuth) GetInstallationToken(ctx context.Context) (string, error) {
	// Check if we have a valid cached token
	if a.token != "" && time.Now().Before(a.tokenExpiry.Add(-5*time.Minute)) {
		log.Printf("[GITHUB APP] Using cached installation token (expires: %s)", 
			a.tokenExpiry.Format(time.RFC3339))
		return a.token, nil
	}

	log.Printf("[GITHUB APP] Refreshing installation token...")
	// Generate JWT
	jwtToken, err := a.GenerateJWT()
	if err != nil {
		return "", fmt.Errorf("generating JWT: %w", err)
	}

	// Create a client with JWT authentication
	ts := &jwtTransport{
		token: jwtToken,
		base:  http.DefaultTransport,
	}
	client := &http.Client{Transport: ts}
	ghClient := github.NewClient(client)

	// If no installation ID provided, list installations and use the first one
	if a.installationID == 0 {
		log.Printf("[GITHUB APP] No installation ID provided, listing installations...")
		installations, _, err := ghClient.Apps.ListInstallations(ctx, nil)
		if err != nil {
			return "", fmt.Errorf("listing installations: %w", err)
		}

		if len(installations) == 0 {
			return "", fmt.Errorf("no installations found for this GitHub App")
		}

		// Use the first installation
		a.installationID = installations[0].GetID()
		log.Printf("[GITHUB APP] Using installation ID: %d (account: %s)", 
			a.installationID, installations[0].GetAccount().GetLogin())
	}

	// Create installation token
	token, _, err := ghClient.Apps.CreateInstallationToken(ctx, a.installationID, nil)
	if err != nil {
		return "", fmt.Errorf("creating installation token: %w", err)
	}

	// Cache the token
	a.token = token.GetToken()
	a.tokenExpiry = token.GetExpiresAt().Time

	log.Printf("[GITHUB APP] Successfully obtained installation token (expires: %s)", 
		a.tokenExpiry.Format(time.RFC3339))

	return a.token, nil
}

// jwtTransport adds the JWT token to requests
type jwtTransport struct {
	token string
	base  http.RoundTripper
}

func (t *jwtTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	return t.base.RoundTrip(req)
}

// NewClientWithApp creates a new GitHub client using GitHub App authentication
func NewClientWithApp(ctx context.Context, appID int64, privateKeyPath string, installationID int64) (*Client, error) {
	// Create app authenticator
	appAuth, err := NewAppAuth(appID, privateKeyPath, installationID)
	if err != nil {
		return nil, fmt.Errorf("creating app auth: %w", err)
	}

	// Get initial installation token
	token, err := appAuth.GetInstallationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting installation token: %w", err)
	}

	// Create a token source that automatically refreshes the token
	ts := &appTokenSource{
		appAuth: appAuth,
	}

	// Use initial token for immediate use
	ts.token = &oauth2.Token{
		AccessToken: token,
		Expiry:      appAuth.tokenExpiry,
	}

	tc := oauth2.NewClient(ctx, ts)

	return &Client{
		client:   github.NewClient(tc),
		clientV4: githubv4.NewClient(tc),
		appAuth:  appAuth,
	}, nil
}

// NewClientWithAppInstallation creates a new GitHub client for a specific installation.
func NewClientWithAppInstallation(ctx context.Context, appAuth *AppAuth, installationID int64) (*Client, error) {
	// Create a new AppAuth instance for this specific installation
	installAuth := &AppAuth{
		appID:          appAuth.appID,
		privateKey:     appAuth.privateKey,
		installationID: installationID,
	}

	// Get initial installation token
	token, err := installAuth.GetInstallationToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting installation token: %w", err)
	}

	// Create a token source that automatically refreshes the token
	ts := &appTokenSource{
		appAuth: installAuth,
	}

	// Use initial token for immediate use
	ts.token = &oauth2.Token{
		AccessToken: token,
		Expiry:      installAuth.tokenExpiry,
	}

	tc := oauth2.NewClient(ctx, ts)

	return &Client{
		client:   github.NewClient(tc),
		clientV4: githubv4.NewClient(tc),
		appAuth:  installAuth,
	}, nil
}

// appTokenSource provides auto-refreshing tokens for GitHub App authentication
type appTokenSource struct {
	appAuth *AppAuth
	token   *oauth2.Token
}

// Token returns a valid token, refreshing if necessary
func (ts *appTokenSource) Token() (*oauth2.Token, error) {
	// Check if token needs refresh (5 minutes before expiry)
	if ts.token == nil || time.Now().After(ts.token.Expiry.Add(-5*time.Minute)) {
		// Create a context with timeout for token refresh
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		token, err := ts.appAuth.GetInstallationToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("refreshing installation token: %w", err)
		}
		ts.token = &oauth2.Token{
			AccessToken: token,
			Expiry:      ts.appAuth.tokenExpiry,
		}
	}
	return ts.token, nil
}