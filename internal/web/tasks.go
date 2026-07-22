// Package web — Task management HTTP handlers.
// POST /api/tasks           — create a task (Admin/Manager)
// POST /api/tasks/bulk      — bulk assign (Admin/Manager)
// POST /api/tasks/{id}/status   — update status (Member: own only; Admin/Manager: any)
// POST /api/tasks/{id}/reassign — reassign (Admin/Manager)
// POST /api/tasks/{id}/note     — add note (owner or Admin/Manager)
// GET  /tasks               — "My Tasks" view for Members
package web

import (
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/kaushik/vuln-alert-service/internal/auth"
	"github.com/kaushik/vuln-alert-service/internal/store"
)

// TasksHandler handles task CRUD operations.
type TasksHandler struct {
	tasks    *store.TaskStore
	users    *store.UserStore
	tasksTmpl *template.Template
}

// NewTasksHandler creates the handler with a parsed task template.
func NewTasksHandler(tasks *store.TaskStore, users *store.UserStore) (*TasksHandler, error) {
	tmpl, err := template.New("tasks").Funcs(template.FuncMap{
		"lower": strings.ToLower,
		"overdue": func(t store.Task) bool {
			return t.DueDate != nil && t.DueDate.Before(time.Now())
		},
	}).Parse(tasksHTML)
	if err != nil {
		return nil, err
	}
	return &TasksHandler{tasks: tasks, users: users, tasksTmpl: tmpl}, nil
}

// CreateTaskHandler creates a single task. Admin/Manager only.
func (h *TasksHandler) CreateTaskHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess := auth.SessionFromContext(r)

	var req struct {
		FindingKey string  `json:"finding_key"`
		Technology string  `json:"technology"`
		CVEID      string  `json:"cve_id"`
		Severity   string  `json:"severity"`
		AssignedTo string  `json:"assigned_to"`
		DueDate    *string `json:"due_date"` // RFC3339
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var dueDate *time.Time
	if req.DueDate != nil {
		t, err := time.Parse("2006-01-02", *req.DueDate)
		if err == nil {
			dueDate = &t
		}
	}

	task, err := h.tasks.CreateTask(req.FindingKey, req.Technology, req.CVEID, req.Severity, req.AssignedTo, sess.Email, dueDate)
	if err != nil {
		slog.Error("create task", "err", err)
		http.Error(w, "failed to create task", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(task)
}

// BulkCreateHandler creates multiple tasks in one shot. Admin/Manager only.
func (h *TasksHandler) BulkCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess := auth.SessionFromContext(r)

	var req struct {
		Findings   []store.BulkTaskInput `json:"findings"`
		AssignedTo string                `json:"assigned_to"`
		DueDate    *string               `json:"due_date"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var dueDate *time.Time
	if req.DueDate != nil {
		t, err := time.Parse("2006-01-02", *req.DueDate)
		if err == nil {
			dueDate = &t
		}
	}

	tasks, err := h.tasks.BulkCreateTasks(req.Findings, req.AssignedTo, sess.Email, dueDate)
	if err != nil {
		slog.Error("bulk create tasks", "err", err)
		http.Error(w, "failed to bulk create tasks", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"created": len(tasks)})
}

// UpdateStatusHandler changes the status of a task.
// Members can only update their own tasks; Admin/Manager can update any.
func (h *TasksHandler) UpdateStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	taskID := extractPathSuffix(r.URL.Path, "/status")
	sess := auth.SessionFromContext(r)

	var req struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Role check: Members can only modify their own tasks.
	if sess.Role == auth.RoleMember {
		task, err := h.tasks.GetTask(taskID)
		if err != nil || task.AssignedTo != sess.Email {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
	}

	if err := h.tasks.UpdateStatus(taskID, store.TaskStatus(req.Status), sess.Email, req.Note); err != nil {
		slog.Error("update task status", "id", taskID, "err", err)
		http.Error(w, "failed to update task", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// ReassignHandler changes the assignee of a task. Admin/Manager only.
func (h *TasksHandler) ReassignHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	taskID := extractPathSuffix(r.URL.Path, "/reassign")
	sess := auth.SessionFromContext(r)

	var req struct {
		AssignedTo string `json:"assigned_to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if err := h.tasks.Reassign(taskID, req.AssignedTo, sess.Email); err != nil {
		slog.Error("reassign task", "id", taskID, "err", err)
		http.Error(w, "failed to reassign task", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// AddNoteHandler appends a note to a task's audit thread.
func (h *TasksHandler) AddNoteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	taskID := extractPathSuffix(r.URL.Path, "/note")
	sess := auth.SessionFromContext(r)

	var req struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Members may only note on their own tasks.
	if sess.Role == auth.RoleMember {
		task, err := h.tasks.GetTask(taskID)
		if err != nil || task.AssignedTo != sess.Email {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
	}

	if err := h.tasks.AddNote(taskID, sess.Email, req.Note); err != nil {
		slog.Error("add task note", "id", taskID, "err", err)
		http.Error(w, "failed to add note", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// MyTasksHandler renders the "My Tasks" page (default view for Members).
func (h *TasksHandler) MyTasksHandler(w http.ResponseWriter, r *http.Request) {
	sess := auth.SessionFromContext(r)

	filter := store.TaskFilter{}
	// Members only see their own tasks.
	if sess.Role == auth.RoleMember {
		filter.AssignedTo = sess.Email
	}
	// Admin/Manager: optional filter by assignee.
	if assignee := r.URL.Query().Get("assignee"); assignee != "" {
		filter.AssignedTo = assignee
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = store.TaskStatus(status)
	}

	tasks, err := h.tasks.ListTasks(filter)
	if err != nil {
		http.Error(w, "failed to load tasks", http.StatusInternalServerError)
		return
	}

	var users []store.User
	if sess != nil && (sess.Role == auth.RoleAdmin || sess.Role == auth.RoleManager) {
		allUsers, _ := h.users.ListUsers()
		for _, u := range allUsers {
			if string(u.Role) == auth.RoleViewer {
				continue
			}
			if sess.Role == auth.RoleManager && string(u.Role) == auth.RoleAdmin {
				continue
			}
			users = append(users, u)
		}
	}
	data := map[string]any{
		"Tasks":     tasks,
		"Users":     users,
		"Session":   sess,
		"CSRFToken": auth.CSRFToken(r),
	}
	if err := h.tasksTmpl.Execute(w, data); err != nil {
		slog.Error("render tasks template", "err", err)
	}
}

func extractPathSuffix(path, suffix string) string {
	// /api/tasks/{id}/status  →  {id}
	path = strings.TrimSuffix(path, suffix)
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

const tasksHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VulnWatch — My Tasks</title>
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
    .nav a:hover{color:var(--text-1)}.nav a.active{color:var(--accent)}
    h1{font-size:22px;font-weight:600;margin-bottom:4px}
    .sub{font-size:13px;color:var(--text-3);margin-bottom:28px}
    .filters{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap}
    .filters select{background:var(--bg-input);border:1px solid var(--border-lit);color:var(--text-2);border-radius:6px;padding:8px 12px;font-family:'Outfit',sans-serif;font-size:13px}
    table{width:100%;border-collapse:collapse}
    th{text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--text-3);padding:0 0 12px;border-bottom:1px solid var(--border)}
    td{padding:14px 12px;border-bottom:1px solid var(--border);font-size:14px}
    td:first-child{padding-left:0}
    .badge{display:inline-block;padding:3px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
    .badge-critical{background:rgba(239,68,68,.15);color:#ef4444}
    .badge-high{background:rgba(249,115,22,.15);color:#f97316}
    .badge-medium{background:rgba(234,179,8,.12);color:#eab308}
    .badge-low{background:rgba(163,163,163,.1);color:#737373}
    .badge-open{background:rgba(6,182,212,.1);color:#06b6d4}
    .badge-in_progress{background:rgba(139,92,246,.1);color:#8b5cf6}
    .badge-resolved{background:rgba(34,197,94,.1);color:#22c55e}
    .badge-wont_fix{background:rgba(163,163,163,.08);color:#737373}
    .badge-ignored{background:rgba(163,163,163,.1);color:#737373}
    .overdue{color:#ef4444;font-weight:600}
    .cve{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent)}
    .empty{color:var(--text-3);text-align:center;padding:48px 0}
    .btn-sm{padding:5px 12px;font-size:12px;border:none;border-radius:5px;cursor:pointer;font-family:'Outfit',sans-serif;font-weight:500}
    .btn-primary{background:var(--accent);color:#fff}
    .btn-primary:hover{background:var(--accent-hover)}
    select.status-sel{background:var(--bg-card);border:1px solid var(--border-lit);color:var(--text-2);font-size:12px;padding:4px 8px;border-radius:4px;font-family:'Outfit',sans-serif}
    .td-actions{display:flex;gap:8px;align-items:center}
  </style>
</head>
<body>
  <nav class="nav">
    <a href="/">Dashboard</a>
    <a href="/tasks" class="active">My Tasks</a>
    {{if eq .Session.Role "admin"}}<a href="/admin/users">Users</a>{{end}}
    <div style="margin-left:auto;display:flex;gap:16px;align-items:center">
      <button onclick="toggleTheme()" class="btn btn-sm" title="Toggle Theme" style="background:transparent;border:1px solid var(--border);color:var(--text-1);padding:4px 8px;display:flex;align-items:center;justify-content:center">
        <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
      </button>
      <a href="/logout" class="btn btn-sm" style="border:1px solid var(--border-lit)">Sign out</a>
    </div>
  </nav>
  <h1>{{if eq .Session.Role "member"}}My Tasks{{else}}All Tasks{{end}}</h1>
  <p class="sub">Track and update the security tasks assigned to you.</p>

  <div class="filters">
    <select onchange="window.location.search='?status='+this.value">
      <option value="">All Statuses</option>
      <option value="open">Open</option>
      <option value="in_progress">In Progress</option>
      <option value="resolved">Resolved</option>
      <option value="wont_fix">Won't Fix</option>
    </select>
  </div>

  <table>
    <thead>
      <tr><th>CVE / Finding</th><th>Technology</th><th>Severity</th><th>Assigned To</th><th>Due Date</th><th>Status</th><th>Actions</th></tr>
    </thead>
    <tbody>
    {{range .Tasks}}
    <tr>
      <td><span class="cve">{{.CVEID}}</span></td>
      <td>{{.Technology}}</td>
      <td><span class="badge badge-{{.Severity | lower}}">{{.Severity}}</span></td>
      <td style="color:#a3a3a3;font-size:13px">{{.AssignedTo}}</td>
      <td style="font-size:13px">
        {{if .DueDate}}
          <span {{if overdue .}}class="overdue"{{end}}>{{.DueDate.Format "2006-01-02"}}</span>
        {{else}}<span style="color:#404040">—</span>{{end}}
      </td>
      <td><span class="badge badge-{{.Status}}">{{.Status}}</span></td>
      <td>
        <div class="td-actions">
          <select class="status-sel" data-task-id="{{.ID}}" onchange="updateStatus(this)">
            <option value="" disabled selected>Change status…</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="resolved">Resolved</option>
            <option value="wont_fix">Won't Fix</option>
            <option value="ignored">Ignore</option>
          </select>
        </div>
      </td>
    </tr>
    {{else}}
    <tr><td colspan="7" class="empty">No tasks found.</td></tr>
    {{end}}
    </tbody>
  </table>

  <script>
    const csrf = "{{.CSRFToken}}";
    async function updateStatus(sel) {
      const id = sel.dataset.taskId;
      const status = sel.value;
      if (!status) return;
      const note = prompt("Optional note for this status change (press OK to skip):", "");
      const res = await fetch("/api/tasks/" + id + "/status", {
        method: "POST",
        headers: {"Content-Type":"application/json","X-CSRF-Token": csrf},
        body: JSON.stringify({status, note: note || ""})
      });
      if (res.ok) location.reload();
      else alert("Failed to update status.");
    }
  </script>
</body>
</html>`
