// Package web — Microsoft Entra ID OIDC login flow handlers.
// GET  /login          — renders the sign-in page
// GET  /auth/callback  — exchanges the code, validates the token, gates on the invite list
// GET  /logout         — destroys the session and redirects to /login
package web

import (
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kaushik/vuln-alert-service/internal/auth"
	"github.com/kaushik/vuln-alert-service/internal/store"
)

// LoginHandler manages the OIDC auth flow.
type LoginHandler struct {
	oidc      *auth.OIDCClient
	sessions  *auth.SessionStore
	users     *store.UserStore
	loginTmpl *template.Template
}

// NewLoginHandler constructs a LoginHandler, parsing the login template.
func NewLoginHandler(oidc *auth.OIDCClient, sessions *auth.SessionStore, users *store.UserStore) (*LoginHandler, error) {
	tmpl, err := template.New("login").Parse(loginHTML)
	if err != nil {
		return nil, err
	}
	return &LoginHandler{
		oidc:      oidc,
		sessions:  sessions,
		users:     users,
		loginTmpl: tmpl,
	}, nil
}

// ServeHTTP renders the login page.
func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reason := r.URL.Query().Get("reason")
	var errMsg string
	switch reason {
	case "revoked":
		errMsg = "Your access has been revoked. Contact your administrator."
	case "unauthorized":
		errMsg = "Your Microsoft account is not authorized to access this application. Contact your administrator."
	case "failed":
		errMsg = "Authentication failed. Please try again."
	}
	_ = h.loginTmpl.Execute(w, map[string]any{"Error": errMsg})
}

// CallbackHandler handles the OIDC redirect from Microsoft.
func (h *LoginHandler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Read the state and nonce that were stored in cookies before the redirect.
	stateCookie, err := r.Cookie("oidc_state")
	if err != nil {
		slog.Warn("oidc callback: missing state cookie")
		http.Redirect(w, r, "/login?reason=failed", http.StatusSeeOther)
		return
	}
	nonceCookie, err := r.Cookie("oidc_nonce")
	if err != nil {
		slog.Warn("oidc callback: missing nonce cookie")
		http.Redirect(w, r, "/login?reason=failed", http.StatusSeeOther)
		return
	}

	if errStr := r.FormValue("error"); errStr != "" {
		slog.Warn("oidc callback error from provider", "error", errStr, "desc", r.FormValue("error_description"))
		http.Redirect(w, r, "/login?reason=failed", http.StatusSeeOther)
		return
	}

	code := r.FormValue("code")
	state := r.FormValue("state")

	if code == "" {
		slog.Warn("oidc callback: missing code parameter")
		http.Redirect(w, r, "/login?reason=failed", http.StatusSeeOther)
		return
	}

	// Validate the token and extract claims.
	claims, err := h.oidc.Exchange(
		r.Context(),
		code,
		state,
		stateCookie.Value,
		nonceCookie.Value,
	)
	if err != nil {
		slog.Warn("oidc token exchange failed", "err", err)
		http.Redirect(w, r, "/login?reason=failed", http.StatusSeeOther)
		return
	}

	// Clear the one-time cookies.
	clearCookie(w, "oidc_state")
	clearCookie(w, "oidc_nonce")

	email := strings.ToLower(strings.TrimSpace(claims.Email))

	// Gate: the user must exist in the invite store.
	user, err := h.users.GetUser(email)
	if err != nil || (user.Status != store.StatusInvited && user.Status != store.StatusActive) {
		slog.Warn("oidc: access denied — not in invite list", "email", email)
		http.Redirect(w, r, "/login?reason=unauthorized", http.StatusSeeOther)
		return
	}

	// Activate on first login or record subsequent login.
	if user.Status == store.StatusInvited {
		if err := h.users.ActivateUser(email, claims.Name, claims.OID); err != nil {
			slog.Error("oidc: failed to activate user", "email", email, "err", err)
			http.Redirect(w, r, "/login?reason=failed", http.StatusSeeOther)
			return
		}
		// Re-fetch for the updated status/role.
		user, _ = h.users.GetUser(email)
	} else {
		_ = h.users.RecordLogin(email)
	}

	// Create server-side session.
	if err := h.sessions.Create(w, email, string(user.Role)); err != nil {
		slog.Error("oidc: failed to create session", "email", email, "err", err)
		http.Redirect(w, r, "/login?reason=failed", http.StatusSeeOther)
		return
	}

	slog.Info("user logged in", "email", email, "role", user.Role)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// InitiateHandler starts the OIDC flow by redirecting to Microsoft.
func (h *LoginHandler) InitiateHandler(w http.ResponseWriter, r *http.Request) {
	state, err := auth.GenerateToken(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := auth.GenerateToken(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Store state and nonce in short-lived cookies for validation on callback.
	setTempCookie(w, "oidc_state", state)
	setTempCookie(w, "oidc_nonce", nonce)

	http.Redirect(w, r, h.oidc.LoginURL(state, nonce), http.StatusSeeOther)
}

// LogoutHandler destroys the session and redirects to the login page.
func (h *LoginHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	id := auth.GetCookieID(r)
	if id != "" {
		_ = h.sessions.Delete(id)
	}
	auth.DeleteCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func setTempCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // Lax for the initial redirect back
		MaxAge:   600,                  // 10 min — enough for the login flow
	})
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

// loginHTML is the Void Dark themed login page.
const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VulnWatch — Sign In</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-base:    #050505;
      --bg-card:    #0d0d0d;
      --border:     #222222;
      --text-1:     #ffffff;
      --text-2:     #a3a3a3;
      --text-3:     #737373;
      --accent:     #0066FF;
      --accent-hover: #1a75ff;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg-base:    #f8f9fa;
        --bg-card:    #ffffff;
        --border:     #e5e5e5;
        --text-1:     #171717;
        --text-2:     #525252;
        --text-3:     #737373;
        --accent:     #0066FF;
        --accent-hover: #005ce6;
      }
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Outfit', sans-serif;
      background: var(--bg-base);
      color: var(--text-1);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 48px 40px;
      width: 100%;
      max-width: 400px;
      text-align: center;
    }
    .logo {
      font-size: 13px;
      font-weight: 500;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--accent);
      margin-bottom: 8px;
    }
    h1 {
      font-size: 24px;
      font-weight: 600;
      color: var(--text-1);
      margin-bottom: 8px;
    }
    p.sub {
      font-size: 14px;
      color: var(--text-3);
      margin-bottom: 36px;
      line-height: 1.5;
    }
    .btn-ms {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 12px;
      width: 100%;
      padding: 14px 20px;
      background: var(--accent);
      color: #fff;
      border: none;
      border-radius: 8px;
      font-family: 'Outfit', sans-serif;
      font-size: 15px;
      font-weight: 500;
      cursor: pointer;
      text-decoration: none;
      transition: background 0.2s, transform 0.2s;
    }
    .btn-ms:hover {
      background: var(--accent-hover);
      transform: translateY(-1px);
    }
    .btn-ms svg { flex-shrink: 0; }
    .error {
      background: rgba(239,68,68,0.08);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 6px;
      color: #ef4444;
      font-size: 13px;
      text-align: left;
    }
    .error-msg strong {
      display: block;
      margin-bottom: 4px;
      color: #f87171;
    }
    .divider {
      border: none;
      border-top: 1px solid var(--border);
      margin: 24px 0;
    }
    .footer {
      font-size: 12px;
      color: #404040;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">VulnWatch</div>
    <h1>Security Dashboard</h1>
    <p class="sub">Sign in with your Microsoft work account to access vulnerability monitoring.</p>
    {{if .Error}}
    <div class="error">{{.Error}}</div>
    {{end}}
    <a href="/auth/initiate" class="btn-ms">
      <svg width="20" height="20" viewBox="0 0 21 21" xmlns="http://www.w3.org/2000/svg">
        <rect x="1" y="1" width="9" height="9" fill="#f25022"/>
        <rect x="11" y="1" width="9" height="9" fill="#7fba00"/>
        <rect x="1" y="11" width="9" height="9" fill="#00a4ef"/>
        <rect x="11" y="11" width="9" height="9" fill="#ffb900"/>
      </svg>
      Sign in with Microsoft
    </a>
    <hr class="divider">
    <p class="footer">Access is restricted to authorized accounts only.</p>
  </div>
</body>
</html>`
