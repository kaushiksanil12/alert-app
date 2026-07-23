// Package auth — server-side session store backed by bbolt.
// Sessions are opaque random IDs stored in a cookie; the actual data
// (email, role, expiry) lives server-side. This means revocation is
// immediate: the next request re-validates the user's status in the
// user store, so a revoked user is blocked within one session cycle.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.etcd.io/bbolt"
)

const (
	sessionCookieName = "vsession"
	bucketSessions    = "sessions"
)

// SessionData is what is stored server-side in bbolt for each session.
type SessionData struct {
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionStore manages server-side sessions in a bbolt bucket.
type SessionStore struct {
	db  *bbolt.DB
	ttl time.Duration
}

// NewSessionStore initialises the session bucket in the given bbolt DB.
func NewSessionStore(db *bbolt.DB, ttl time.Duration) (*SessionStore, error) {
	err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketSessions))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create sessions bucket: %w", err)
	}
	return &SessionStore{db: db, ttl: ttl}, nil
}

// Create stores a new session and sets the HttpOnly cookie on w.
func (s *SessionStore) Create(w http.ResponseWriter, email, role string) error {
	id, err := generateSessionID()
	if err != nil {
		return err
	}

	data := SessionData{
		Email:     email,
		Role:      role,
		ExpiresAt: time.Now().Add(s.ttl),
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	err = s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketSessions)).Put([]byte(id), raw)
	})
	if err != nil {
		return fmt.Errorf("store session: %w", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Secure: true, // uncomment in production (requires HTTPS)
		MaxAge: int(s.ttl.Seconds()),
	})
	return nil
}

// Get retrieves and validates the session from the request cookie.
// Returns nil if no valid session exists (cookie missing, expired, or not found).
func (s *SessionStore) Get(r *http.Request) *SessionData {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}

	var data SessionData
	err = s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketSessions))
		raw := b.Get([]byte(cookie.Value))
		if raw == nil {
			return fmt.Errorf("not found")
		}
		return json.Unmarshal(raw, &data)
	})
	if err != nil {
		return nil
	}

	if time.Now().After(data.ExpiresAt) {
		// Expired — clean up lazily.
		_ = s.Delete(cookie.Value)
		return nil
	}
	return &data
}

// Delete removes a session from the store and clears the cookie.
func (s *SessionStore) Delete(id string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketSessions)).Delete([]byte(id))
	})
}

// DeleteCookie clears the session cookie from the browser.
func DeleteCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// GetCookieID reads the raw session ID from the request (without DB lookup).
func GetCookieID(r *http.Request) string {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// PruneExpired removes all expired sessions from the store. Call periodically.
func (s *SessionStore) PruneExpired() error {
	now := time.Now()
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketSessions))
		var expired [][]byte
		err := b.ForEach(func(k, v []byte) error {
			var d SessionData
			if err := json.Unmarshal(v, &d); err != nil || now.After(d.ExpiresAt) {
				cp := make([]byte, len(k))
				copy(cp, k)
				expired = append(expired, cp)
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, k := range expired {
			_ = b.Delete(k)
		}
		return nil
	})
}

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
