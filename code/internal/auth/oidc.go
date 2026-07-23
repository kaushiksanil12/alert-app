// Package auth handles Microsoft Entra ID OIDC authentication.
// It uses go-oidc/v3 against Microsoft's OIDC discovery document,
// performs full token validation (signature, issuer, audience, nonce, expiry),
// and extracts the user's email, display name, and object ID from claims.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const microsoftIssuerBase = "https://login.microsoftonline.com"

// Claims holds the normalized identity extracted from a validated Microsoft ID token.
type Claims struct {
	Email string
	Name  string
	OID   string // Microsoft object ID — stable unique identifier across email changes
}

// OIDCClient wraps go-oidc/v3 and oauth2 for the Microsoft Entra ID auth flow.
type OIDCClient struct {
	provider *oidc.Provider
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewOIDCClient initialises the OIDC provider from Microsoft's discovery document.
// tenantID is the Azure AD tenant (e.g. "contoso.onmicrosoft.com" or a GUID).
// clientID and clientSecret are from the App Registration in Azure Portal.
// redirectURL must exactly match the redirect URI registered in Azure Portal.
func NewOIDCClient(ctx context.Context, tenantID, clientID, clientSecret, redirectURL string) (*OIDCClient, error) {
	issuer := fmt.Sprintf("%s/%s/v2.0", microsoftIssuerBase, tenantID)
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover provider at %s: %w", issuer, err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

	cfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	return &OIDCClient{
		provider: provider,
		config:   cfg,
		verifier: verifier,
	}, nil
}

// LoginURL returns the URL to redirect the browser to for Microsoft login.
// state and nonce are random values that must be stored in the session cookie
// before redirecting, and validated on return (CSRF + replay protection).
func (c *OIDCClient) LoginURL(state, nonce string) string {
	return c.config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("prompt", "select_account"),
	)
}

// Exchange validates the authorization code callback and returns the user's claims.
// state is compared against the value stored before the redirect.
// nonce is compared against the nonce claim in the ID token.
func (c *OIDCClient) Exchange(ctx context.Context, code, state, expectedState, expectedNonce string) (*Claims, error) {
	if state != expectedState {
		return nil, fmt.Errorf("oidc: state mismatch — possible CSRF")
	}

	token, err := c.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oidc: exchange code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("oidc: no id_token in response")
	}

	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: verify id_token: %w", err)
	}

	// Validate nonce (replay protection).
	var rawClaims struct {
		Nonce             string `json:"nonce"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
		OID               string `json:"oid"`
	}
	if err := idToken.Claims(&rawClaims); err != nil {
		return nil, fmt.Errorf("oidc: extract claims: %w", err)
	}
	if rawClaims.Nonce != expectedNonce {
		return nil, fmt.Errorf("oidc: nonce mismatch — possible replay")
	}

	email := rawClaims.Email
	if email == "" {
		email = rawClaims.PreferredUsername
	}
	if email == "" {
		return nil, fmt.Errorf("oidc: no email claim in token")
	}

	return &Claims{
		Email: email,
		Name:  rawClaims.Name,
		OID:   rawClaims.OID,
	}, nil
}

// GenerateToken returns a cryptographically random URL-safe base64 string
// suitable for use as a state or nonce value.
func GenerateToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// TokenAge is the validity window for state/nonce values stored in cookies.
const TokenAge = 10 * time.Minute
