// Package store — user management store backed by bbolt.
// Accounts are Admin-provisioned (no self-signup).
// A user must exist with status "invited" or "active" in this store
// before Microsoft SSO login grants them access to the app.
package store

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.etcd.io/bbolt"
)

var bucketUsers = []byte("users")

// Role defines the four access levels in the application.
type Role string

const (
	RoleAdmin   Role = "admin"
	RoleManager Role = "manager"
	RoleMember  Role = "member"
	RoleViewer  Role = "viewer"
)

// UserStatus tracks the lifecycle of an invited user account.
type UserStatus string

const (
	StatusInvited UserStatus = "invited"
	StatusActive  UserStatus = "active"
	StatusRevoked UserStatus = "revoked"
)

// User represents a member of the team with app access.
type User struct {
	Email     string     `json:"email"`
	Name      string     `json:"name"`
	Role      Role       `json:"role"`
	Status    UserStatus `json:"status"`
	InvitedBy string     `json:"invited_by"`
	InvitedAt time.Time  `json:"invited_at"`
	LastLogin *time.Time `json:"last_login,omitempty"`
	OID       string     `json:"oid,omitempty"` // Microsoft object ID
}

// UserStore manages users in the bbolt "users" bucket.
type UserStore struct {
	db *bbolt.DB
}

// NewUserStore opens/creates the users bucket in the given DB.
func NewUserStore(db *bbolt.DB) (*UserStore, error) {
	err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketUsers)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create users bucket: %w", err)
	}
	return &UserStore{db: db}, nil
}

// Bootstrap auto-invites bootstrapEmail as Admin if the user store is empty.
// This resolves the chicken-and-egg problem of "who creates the first admin?"
// Set BOOTSTRAP_ADMIN_EMAIL on first startup; unset it once the admin has logged in.
func (s *UserStore) Bootstrap(bootstrapEmail string) error {
	if bootstrapEmail == "" {
		return nil
	}
	users, err := s.ListUsers()
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return nil // users exist, bootstrap not needed
	}

	slog.Info("bootstrapping first admin", "email", bootstrapEmail)
	return s.InviteUser(bootstrapEmail, RoleAdmin, "system-bootstrap")
}

// InviteUser creates a new user record with status "invited".
// invitedBy should be the email of the Admin who issued the invite, or "system-bootstrap".
func (s *UserStore) InviteUser(email string, role Role, invitedBy string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return fmt.Errorf("email is required")
	}

	// Check for duplicate.
	existing, _ := s.GetUser(email)
	if existing != nil && existing.Status != StatusRevoked {
		return fmt.Errorf("user %q already exists with status %q", email, existing.Status)
	}

	u := User{
		Email:     email,
		Role:      role,
		Status:    StatusInvited,
		InvitedBy: invitedBy,
		InvitedAt: time.Now(),
	}
	return s.save(u)
}

// ActivateUser transitions an invited user to active on first successful Microsoft login.
// It records the display name and Microsoft OID from the ID token claims.
func (s *UserStore) ActivateUser(email, name, oid string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	u, err := s.GetUser(email)
	if err != nil {
		return fmt.Errorf("activate: user %q not found: %w", email, err)
	}

	now := time.Now()
	u.Name = name
	u.OID = oid
	u.LastLogin = &now

	if u.Status == StatusInvited {
		u.Status = StatusActive
		slog.Info("user activated", "email", email, "role", u.Role)
	}
	return s.save(*u)
}

// RecordLogin updates the LastLogin timestamp for an already-active user.
func (s *UserStore) RecordLogin(email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	u, err := s.GetUser(email)
	if err != nil {
		return err
	}
	now := time.Now()
	u.LastLogin = &now
	return s.save(*u)
}

// RevokeUser transitions a user to revoked status.
// Their next authenticated request will be rejected immediately.
func (s *UserStore) RevokeUser(email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	u, err := s.GetUser(email)
	if err != nil {
		return fmt.Errorf("revoke: user %q not found: %w", email, err)
	}
	u.Status = StatusRevoked
	slog.Info("user revoked", "email", email)
	return s.save(*u)
}

// ChangeRole updates the role of an existing user.
func (s *UserStore) ChangeRole(email string, role Role) error {
	email = strings.ToLower(strings.TrimSpace(email))
	u, err := s.GetUser(email)
	if err != nil {
		return fmt.Errorf("change role: user %q not found: %w", email, err)
	}
	oldRole := u.Role
	u.Role = role
	slog.Info("user role changed", "email", email, "from", oldRole, "to", role)
	return s.save(*u)
}

// GetUser retrieves a user by email (case-insensitive).
func (s *UserStore) GetUser(email string) (*User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var u User
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		raw := b.Get([]byte(email))
		if raw == nil {
			return fmt.Errorf("user %q not found", email)
		}
		return json.Unmarshal(raw, &u)
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ListUsers returns all users ordered by invite date (most recent last).
func (s *UserStore) ListUsers() ([]User, error) {
	var users []User
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketUsers)
		return b.ForEach(func(_, v []byte) error {
			var u User
			if err := json.Unmarshal(v, &u); err != nil {
				return err
			}
			users = append(users, u)
			return nil
		})
	})
	return users, err
}

// UserCount returns the total number of user records.
func (s *UserStore) UserCount() (int, error) {
	users, err := s.ListUsers()
	return len(users), err
}

func (s *UserStore) save(u User) error {
	raw, err := json.Marshal(u)
	if err != nil {
		return fmt.Errorf("marshal user: %w", err)
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketUsers).Put([]byte(u.Email), raw)
	})
}
