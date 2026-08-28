// Package auth — RBAC + CSRF middleware.
// RequireSession redirects unauthenticated requests to /login.
// RequireRole returns 403 for sessions that lack the required role.
// CSRFToken generates + validates double-submit CSRF tokens on all non-GET/HEAD/OPTIONS requests.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kaushik/vuln-alert-service/internal/store"
)

type contextKey string

const sessionKey contextKey = "session"

const (
	RoleAdmin   = "admin"
	RoleManager = "manager"
	RoleMember  = "member"
	RoleViewer  = "viewer"
)

// SessionFromContext retrieves the current session from the request context.
// Returns nil if not present (only possible if RequireSession was bypassed).
func SessionFromContext(r *http.Request) *SessionData {
	v, _ := r.Context().Value(sessionKey).(*SessionData)
	return v
}

// RequireSession wraps a handler to enforce authentication.
// On every request it re-validates the user's current status in the user store
// to ensure revocation takes effect immediately (not just at session expiry).
func RequireSession(sessions *SessionStore, users *store.UserStore, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := sessions.Get(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Re-validate user status on every request for fast revocation.
		user, err := users.GetUser(sess.Email)
		if err != nil || user.Status != store.StatusActive {
			// User revoked or deleted — kill the session and redirect.
			_ = sessions.Delete(GetCookieID(r))
			DeleteCookie(w)
			http.Redirect(w, r, "/login?reason=revoked", http.StatusSeeOther)
			return
		}

		// Keep the session data up to date with the current role
		// (in case an Admin changed it since the session was created).
		sess.Role = string(user.Role)

		ctx := context.WithValue(r.Context(), sessionKey, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole wraps a handler to enforce role-based access control.
// Must be used inside RequireSession so that SessionFromContext works.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := SessionFromContext(r)
			if sess == nil || !allowed[sess.Role] {
				slog.Warn("role check failed",
					"path", r.URL.Path,
					"method", r.Method,
					"role", func() string {
						if sess == nil {
							return "(no session)"
						}
						return sess.Role
					}(),
				)
				http.Error(w, "403 Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

const csrfCookieName = "csrf_token"
const csrfHeaderName = "X-CSRF-Token"
const csrfFormField  = "csrf_token"

// CSRFMiddleware implements the double-submit cookie pattern.
// On GET requests it sets a random CSRF token cookie.
// On state-changing requests (POST/PUT/PATCH/DELETE) it requires that the
// submitted token (header or form field) matches the cookie value.
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method := strings.ToUpper(r.Method)

		// For safe methods, ensure the cookie exists so forms can read it.
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			if _, err := r.Cookie(csrfCookieName); err != nil {
				token, _ := generateCSRFToken()
				cookie := &http.Cookie{
					Name:     csrfCookieName,
					Value:    token,
					Path:     "/",
					SameSite: http.SameSiteStrictMode,
					HttpOnly: false, // JS must be able to read for fetch() calls
				}
				http.SetCookie(w, cookie)
				r.AddCookie(cookie)
			}
			next.ServeHTTP(w, r)
			return
		}

		// For state-changing methods, validate the token.
		cookie, err := r.Cookie(csrfCookieName)
		if err != nil {
			http.Error(w, "403 CSRF token missing", http.StatusForbidden)
			return
		}

		// Accept from header (fetch/XHR) or form field (plain form POST).
		submitted := r.Header.Get(csrfHeaderName)
		if submitted == "" {
			submitted = r.FormValue(csrfFormField)
		}

		if submitted == "" || submitted != cookie.Value {
			slog.Warn("CSRF validation failed", "path", r.URL.Path, "method", method)
			http.Error(w, "403 CSRF validation failed", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// CSRFToken returns the current CSRF token from the request cookie.
// Templates call this to embed the token in forms.
func CSRFToken(r *http.Request) string {
	c, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

func generateCSRFToken() (string, error) {
	b := make([]byte, 24)
	_, err := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), err
}
