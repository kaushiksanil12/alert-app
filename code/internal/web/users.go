// Package web — Admin user management handlers.
// All routes here require Admin role. CSRF is enforced by the global middleware.
package web

import (
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kaushik/vuln-alert-service/internal/auth"
	"github.com/kaushik/vuln-alert-service/internal/store"
)

// UsersHandler serves the Admin user management UI.
type UsersHandler struct {
	users    *store.UserStore
	usersTmpl *template.Template
}

// NewUsersHandler parses the admin_users template and returns the handler.
func NewUsersHandler(users *store.UserStore) (*UsersHandler, error) {
	tmpl, err := template.New("admin_users").Funcs(template.FuncMap{
		"csrfToken": func() string { return "" }, // placeholder; overridden per-request
	}).ParseFiles("internal/web/templates/admin_users.html")
	if err != nil {
		// Fall back to embedded template
		tmpl2, err2 := template.New("admin_users").Parse(adminUsersHTMLFallback)
		if err2 != nil {
			return nil, err2
		}
		return &UsersHandler{users: users, usersTmpl: tmpl2}, nil
	}
	return &UsersHandler{users: users, usersTmpl: tmpl}, nil
}

// ServeHTTP renders the user management page (GET) or handles admin actions (POST).
func (h *UsersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listPage(w, r)
	case http.MethodPost:
		action := r.URL.Query().Get("action")
		switch action {
		case "invite":
			h.invite(w, r)
		case "revoke":
			h.revoke(w, r)
		case "role":
			h.changeRole(w, r)
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *UsersHandler) listPage(w http.ResponseWriter, r *http.Request) {
	users, err := h.users.ListUsers()
	if err != nil {
		http.Error(w, "failed to list users", http.StatusInternalServerError)
		return
	}
	sess := auth.SessionFromContext(r)
	data := map[string]any{
		"Users":     users,
		"Session":   sess,
		"CSRFToken": auth.CSRFToken(r),
		"Flash":     r.URL.Query().Get("flash"),
	}
	if err := h.usersTmpl.Execute(w, data); err != nil {
		slog.Error("render admin_users template", "err", err)
	}
}

func (h *UsersHandler) invite(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	role := store.Role(r.FormValue("role"))
	sess := auth.SessionFromContext(r)

	if err := h.users.InviteUser(email, role, sess.Email); err != nil {
		slog.Warn("invite user failed", "email", email, "err", err)
		http.Redirect(w, r, "/admin/users?flash="+encodeFlash("Error: "+err.Error()), http.StatusSeeOther)
		return
	}
	slog.Info("user invited", "email", email, "role", role, "by", sess.Email)
	http.Redirect(w, r, "/admin/users?flash="+encodeFlash("Invited "+email), http.StatusSeeOther)
}

func (h *UsersHandler) revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	sess := auth.SessionFromContext(r)

	// Prevent self-revocation.
	if email == sess.Email {
		http.Redirect(w, r, "/admin/users?flash="+encodeFlash("Cannot revoke your own account"), http.StatusSeeOther)
		return
	}

	if err := h.users.RevokeUser(email); err != nil {
		slog.Warn("revoke user failed", "email", email, "err", err)
		http.Redirect(w, r, "/admin/users?flash="+encodeFlash("Error: "+err.Error()), http.StatusSeeOther)
		return
	}
	slog.Info("user revoked", "email", email, "by", sess.Email)
	http.Redirect(w, r, "/admin/users?flash="+encodeFlash("Revoked "+email), http.StatusSeeOther)
}

func (h *UsersHandler) changeRole(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	role := store.Role(r.FormValue("role"))
	sess := auth.SessionFromContext(r)

	if err := h.users.ChangeRole(email, role); err != nil {
		slog.Warn("change role failed", "email", email, "err", err)
		http.Redirect(w, r, "/admin/users?flash="+encodeFlash("Error: "+err.Error()), http.StatusSeeOther)
		return
	}
	slog.Info("user role changed", "email", email, "role", role, "by", sess.Email)
	http.Redirect(w, r, "/admin/users?flash="+encodeFlash("Role updated for "+email), http.StatusSeeOther)
}

func encodeFlash(msg string) string {
	return strings.ReplaceAll(msg, " ", "+")
}

const adminUsersHTMLFallback = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VulnWatch — User Management</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
  <script>
    if (localStorage.getItem('theme') === 'light' || (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: light)').matches)) {
      document.documentElement.setAttribute('data-theme', 'light');
    }
    function toggleTheme() {
      const isLight = document.documentElement.getAttribute('data-theme') === 'light';
      const next = isLight ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('theme', next);
    }
  </script>
  <style>
    :root {
      --bg-base:    #050505;
      --bg-card:    #0d0d0d;
      --bg-input:   #0a0a0a;
      --border:     #1a1a1a;
      --border-lit: #2a2a2a;
      --text-1:     #ffffff;
      --text-2:     #a3a3a3;
      --text-3:     #737373;
      --accent:     #0066FF;
      --accent-hover: #0052cc;
    }
    :root[data-theme="light"] {
        --bg-base:    #f8f9fa;
        --bg-card:    #ffffff;
        --bg-input:   #ffffff;
        --border:     #e5e5e5;
        --border-lit: #d4d4d4;
        --text-1:     #171717;
        --text-2:     #525252;
        --text-3:     #737373;
        --accent:     #0066FF;
        --accent-hover: #005ce6;
    }
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Outfit',sans-serif;background:var(--bg-base);color:var(--text-1);min-height:100vh;padding:24px}
    .nav{display:flex;align-items:center;gap:16px;padding:0 0 24px;border-bottom:1px solid var(--border);margin-bottom:28px}
    .nav a{color:var(--text-2);text-decoration:none;font-size:14px;transition:color .2s}
    .nav a:hover{color:var(--text-1)}
    .nav a.active{color:var(--accent)}
    h1{font-size:22px;font-weight:600;margin-bottom:4px}
    .sub{font-size:13px;color:var(--text-3);margin-bottom:28px}
    .card{background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:24px;margin-bottom:24px}
    .card h2{font-size:12px;font-weight:600;margin-bottom:16px;color:var(--text-2);text-transform:uppercase;letter-spacing:.06em}
    .form-row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
    input,select{background:var(--bg-input);border:1px solid var(--border-lit);color:var(--text-1);border-radius:6px;padding:9px 12px;font-family:'Outfit',sans-serif;font-size:14px;outline:none;transition:border-color .2s}
    input:focus,select:focus{border-color:var(--accent)}
    input{flex:1;min-width:200px}
    .btn{padding:9px 18px;border:none;border-radius:6px;font-family:'Outfit',sans-serif;font-size:14px;font-weight:500;cursor:pointer;transition:background .2s,transform .1s}
    .btn:active{transform:scale(.98)}
    .btn-primary{background:var(--accent);color:#fff}
    .btn-primary:hover{background:var(--accent-hover)}
    .btn-danger{background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.2)}
    .btn-danger:hover{background:rgba(239,68,68,.2)}
    .btn-sm{padding:5px 12px;font-size:12px}
    table{width:100%;border-collapse:collapse}
    th{text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--text-3);padding:0 0 12px;border-bottom:1px solid var(--border)}
    td{padding:14px 0;border-bottom:1px solid var(--border);font-size:14px}
    .badge{display:inline-block;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
    .badge-admin{background:rgba(139,92,246,.15);color:#8b5cf6}
    .badge-manager{background:rgba(6,182,212,.15);color:#06b6d4}
    .badge-member{background:rgba(34,197,94,.15);color:#22c55e}
    .badge-viewer{background:rgba(163,163,163,.1);color:#737373}
    .badge-active{background:rgba(34,197,94,.1);color:#22c55e}
    .badge-invited{background:rgba(245,158,11,.1);color:#f59e0b}
    .badge-revoked{background:rgba(239,68,68,.1);color:#ef4444}
    .flash{background:rgba(6,182,212,.08);border:1px solid rgba(6,182,212,.2);border-radius:8px;padding:10px 16px;font-size:13px;color:#06b6d4;margin-bottom:20px}
    .td-actions{display:flex;gap:8px;align-items:center}
    select.role-select{background:var(--bg-card);border:1px solid var(--border-lit);color:var(--text-2);font-size:12px;padding:4px 8px;border-radius:4px}
  </style>
</head>
<body>
  <nav class="nav">
    <a href="/">Dashboard</a>
    <a href="/tasks">My Tasks</a>
    <a href="/admin/users" class="active">Users</a>
    <div style="margin-left:auto;display:flex;gap:16px;align-items:center">
      <button onclick="toggleTheme()" class="btn btn-sm" title="Toggle Theme" style="background:transparent;border:1px solid var(--border);color:var(--text-1);padding:4px 8px;display:flex;align-items:center;justify-content:center">
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
      </button>
      <a href="/logout" class="btn btn-sm" style="border:1px solid var(--border-lit)">Sign out</a>
    </div>
  </nav>
  <h1>User Management</h1>
  <p class="sub">Invite team members and manage their access. Users must sign in with their Microsoft work account.</p>
  {{if .Flash}}<div class="flash">{{.Flash}}</div>{{end}}

  <div class="card">
    <h2>Invite New User</h2>
    <form method="POST" action="/admin/users?action=invite" class="form-row">
      <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
      <input type="email" name="email" placeholder="work.email@company.com" required>
      <select name="role">
        <option value="viewer">Viewer</option>
        <option value="member">Member</option>
        <option value="manager">Manager</option>
        <option value="admin">Admin</option>
      </select>
      <button type="submit" class="btn btn-primary">Invite</button>
    </form>
  </div>

  <div class="card">
    <h2>Team Members</h2>
    <table>
      <thead>
        <tr>
          <th>Email</th><th>Name</th><th>Role</th><th>Status</th><th>Last Login</th><th>Actions</th>
        </tr>
      </thead>
      <tbody>
      {{range .Users}}
      <tr>
        <td>{{.Email}}</td>
        <td>{{if .Name}}{{.Name}}{{else}}<span style="color:#404040">—</span>{{end}}</td>
        <td><span class="badge badge-{{.Role}}">{{.Role}}</span></td>
        <td><span class="badge badge-{{.Status}}">{{.Status}}</span></td>
        <td style="color:#737373;font-size:12px">
          {{if .LastLogin}}{{.LastLogin.Format "2006-01-02 15:04"}}{{else}}Never{{end}}
        </td>
        <td>
          <div class="td-actions">
            {{if eq .Status "revoked"}}
              <span style="color:#404040;font-size:12px">Revoked</span>
            {{else}}
              <form method="POST" action="/admin/users?action=role" style="display:flex;gap:6px;align-items:center">
                <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                <input type="hidden" name="email" value="{{.Email}}">
                <select name="role" class="role-select">
                  <option value="viewer" {{if eq .Role "viewer"}}selected{{end}}>Viewer</option>
                  <option value="member" {{if eq .Role "member"}}selected{{end}}>Member</option>
                  <option value="manager" {{if eq .Role "manager"}}selected{{end}}>Manager</option>
                  <option value="admin" {{if eq .Role "admin"}}selected{{end}}>Admin</option>
                </select>
                <button type="submit" class="btn btn-sm btn-primary">Save</button>
              </form>
              <form method="POST" action="/admin/users?action=revoke">
                <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                <input type="hidden" name="email" value="{{.Email}}">
                <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Revoke access for {{.Email}}?')">Revoke</button>
              </form>
            {{end}}
          </div>
        </td>
      </tr>
      {{else}}
      <tr><td colspan="6" style="color:#404040;text-align:center;padding:32px">No users yet. Invite someone above.</td></tr>
      {{end}}
      </tbody>
    </table>
  </div>
</body>
</html>`
