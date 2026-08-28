// Package store — Task assignment store backed by bbolt.
// Tasks link findings (identified by source:cve_id) to team members.
// Every status change or reassignment is appended to an audit note thread.
package store

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"go.etcd.io/bbolt"
)

var bucketTasks = []byte("tasks")

// TaskStatus represents the lifecycle state of a task.
type TaskStatus string

const (
	TaskOpen       TaskStatus = "open"
	TaskInProgress TaskStatus = "in_progress"
	TaskResolved   TaskStatus = "resolved"
	TaskWontFix    TaskStatus = "wont_fix"
	TaskIgnored    TaskStatus = "ignored"
)

// TaskNote is a single entry in the audit/comment thread.
type TaskNote struct {
	Author    string    `json:"author"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// Task represents a security finding that has been assigned to a team member.
type Task struct {
	ID          string     `json:"id"`
	FindingKey  string     `json:"finding_key"`  // "source\x00cve_id"
	Technology  string     `json:"technology"`   // snapshot, survives finding pruning
	CVEID       string     `json:"cve_id"`       // snapshot
	Severity    string     `json:"severity"`     // snapshot
	AssignedTo  string     `json:"assigned_to"`  // user email
	AssignedBy  string     `json:"assigned_by"`  // user email
	Status      TaskStatus `json:"status"`
	DueDate     *time.Time `json:"due_date,omitempty"`
	Notes       []TaskNote `json:"notes"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// TaskStore manages tasks in the bbolt "tasks" bucket.
type TaskStore struct {
	db *bbolt.DB
}

// NewTaskStore opens/creates the tasks bucket in the given DB.
func NewTaskStore(db *bbolt.DB) (*TaskStore, error) {
	err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketTasks)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create tasks bucket: %w", err)
	}
	return &TaskStore{db: db}, nil
}

// CreateTask creates a single task for a finding. If a task already exists (even if resolved), it reopens and reassigns it instead of duplicating.
func (s *TaskStore) CreateTask(findingKey, technology, cveID, severity, assignedTo, assignedBy string, dueDate *time.Time) (*Task, error) {
	// First check if a task already exists for this finding
	existingTasks, err := s.GetTasksForFinding(findingKey)
	if err == nil && len(existingTasks) > 0 {
		// Pick the most recently updated one to reuse
		t := existingTasks[0]
		for _, et := range existingTasks {
			if et.UpdatedAt.After(t.UpdatedAt) {
				t = et
			}
		}

		oldAssignee := t.AssignedTo
		oldStatus := t.Status
		
		t.AssignedTo = assignedTo
		t.AssignedBy = assignedBy
		t.DueDate = dueDate
		t.Status = TaskOpen
		t.UpdatedAt = time.Now()
		
		noteBody := fmt.Sprintf("Task reassigned from %s to %s and due date updated.", oldAssignee, assignedTo)
		if oldStatus != TaskOpen && oldStatus != TaskInProgress {
			noteBody = fmt.Sprintf("Task reopened (was %s) and reassigned from %s to %s.", oldStatus, oldAssignee, assignedTo)
		}
		
		t.Notes = append(t.Notes, TaskNote{
			Author:    assignedBy,
			Body:      noteBody,
			CreatedAt: t.UpdatedAt,
		})
		
		if err := s.save(t); err != nil {
			return nil, err
		}
		slog.Info("task reused instead of duplicated", "id", t.ID, "assigned_to", assignedTo, "finding", findingKey)
		return &t, nil
	}

	now := time.Now()
	t := Task{
		ID:         uuid.NewString(),
		FindingKey: findingKey,
		Technology: technology,
		CVEID:      cveID,
		Severity:   severity,
		AssignedTo: assignedTo,
		AssignedBy: assignedBy,
		Status:     TaskOpen,
		DueDate:    dueDate,
		Notes: []TaskNote{{
			Author:    assignedBy,
			Body:      fmt.Sprintf("Task created and assigned to %s.", assignedTo),
			CreatedAt: now,
		}},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.save(t); err != nil {
		return nil, err
	}
	slog.Info("task created", "id", t.ID, "assigned_to", assignedTo, "finding", findingKey)
	return &t, nil
}

// BulkCreateTasks creates multiple tasks in a single transaction. Reassigns/reopens existing tasks to avoid duplicates.
func (s *TaskStore) BulkCreateTasks(findings []BulkTaskInput, assignedTo, assignedBy string, dueDate *time.Time) ([]*Task, error) {
	now := time.Now()
	var tasks []*Task

	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketTasks)
		
		// Pre-load a map of all tasks by findingKey to avoid O(N) bucket scans. Pick the most recent.
		existingTasks := make(map[string]Task)
		_ = b.ForEach(func(_, v []byte) error {
			var t Task
			if err := json.Unmarshal(v, &t); err == nil {
				if existing, ok := existingTasks[t.FindingKey]; !ok || t.UpdatedAt.After(existing.UpdatedAt) {
					existingTasks[t.FindingKey] = t
				}
			}
			return nil
		})

		for _, f := range findings {
			if existing, ok := existingTasks[f.FindingKey]; ok {
				// Update existing task
				oldAssignee := existing.AssignedTo
				oldStatus := existing.Status
				
				existing.AssignedTo = assignedTo
				existing.AssignedBy = assignedBy
				existing.DueDate = dueDate
				existing.Status = TaskOpen
				existing.UpdatedAt = now
				
				noteBody := fmt.Sprintf("Task bulk-reassigned from %s to %s.", oldAssignee, assignedTo)
				if oldStatus != TaskOpen && oldStatus != TaskInProgress {
					noteBody = fmt.Sprintf("Task reopened (was %s) via bulk assign to %s.", oldStatus, assignedTo)
				}
				
				existing.Notes = append(existing.Notes, TaskNote{
					Author:    assignedBy,
					Body:      noteBody,
					CreatedAt: now,
				})
				raw, err := json.Marshal(existing)
				if err != nil {
					return err
				}
				if err := b.Put([]byte(existing.ID), raw); err != nil {
					return err
				}
				tasks = append(tasks, &existing)
			} else {
				// Create new task
				t := Task{
					ID:         uuid.NewString(),
					FindingKey: f.FindingKey,
					Technology: f.Technology,
					CVEID:      f.CVEID,
					Severity:   f.Severity,
					AssignedTo: assignedTo,
					AssignedBy: assignedBy,
					Status:     TaskOpen,
					DueDate:    dueDate,
					Notes: []TaskNote{{
						Author:    assignedBy,
						Body:      fmt.Sprintf("Task created via bulk assign to %s.", assignedTo),
						CreatedAt: now,
					}},
					CreatedAt: now,
					UpdatedAt: now,
				}
				raw, err := json.Marshal(t)
				if err != nil {
					return err
				}
				if err := b.Put([]byte(t.ID), raw); err != nil {
					return err
				}
				tasks = append(tasks, &t)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("bulk create tasks: %w", err)
	}
	slog.Info("bulk tasks processed", "count", len(tasks), "assigned_to", assignedTo)
	return tasks, nil
}

// BulkTaskInput carries the minimal finding info needed to create a task.
type BulkTaskInput struct {
	FindingKey string
	Technology string
	CVEID      string
	Severity   string
}

// UpdateStatus transitions a task's status and appends to the audit thread.
// Members can only update tasks assigned to them; Admin/Manager can update any.
// The actor argument is the email of the person making the change.
func (s *TaskStore) UpdateStatus(taskID string, newStatus TaskStatus, actor, note string) error {
	t, err := s.GetTask(taskID)
	if err != nil {
		return err
	}

	old := t.Status
	t.Status = newStatus
	t.UpdatedAt = time.Now()

	body := fmt.Sprintf("Status changed from %q to %q.", old, newStatus)
	if note != "" {
		body += " Note: " + note
	}
	t.Notes = append(t.Notes, TaskNote{
		Author:    actor,
		Body:      body,
		CreatedAt: t.UpdatedAt,
	})

	slog.Info("task status updated", "id", taskID, "from", old, "to", newStatus, "by", actor)
	return s.save(*t)
}

// AddNote appends a free-form note to the audit thread without changing status.
func (s *TaskStore) AddNote(taskID, actor, note string) error {
	t, err := s.GetTask(taskID)
	if err != nil {
		return err
	}
	now := time.Now()
	t.Notes = append(t.Notes, TaskNote{Author: actor, Body: note, CreatedAt: now})
	t.UpdatedAt = now
	return s.save(*t)
}

// Reassign changes the assignee and appends an audit note.
func (s *TaskStore) Reassign(taskID, newAssignee, actor string) error {
	t, err := s.GetTask(taskID)
	if err != nil {
		return err
	}
	old := t.AssignedTo
	t.AssignedTo = newAssignee
	t.AssignedBy = actor
	t.UpdatedAt = time.Now()
	t.Notes = append(t.Notes, TaskNote{
		Author:    actor,
		Body:      fmt.Sprintf("Task reassigned from %s to %s.", old, newAssignee),
		CreatedAt: t.UpdatedAt,
	})
	slog.Info("task reassigned", "id", taskID, "from", old, "to", newAssignee, "by", actor)
	return s.save(*t)
}

// GetTask retrieves a single task by ID.
func (s *TaskStore) GetTask(id string) (*Task, error) {
	var t Task
	err := s.db.View(func(tx *bbolt.Tx) error {
		raw := tx.Bucket(bucketTasks).Get([]byte(id))
		if raw == nil {
			return fmt.Errorf("task %q not found", id)
		}
		return json.Unmarshal(raw, &t)
	})
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// TaskFilter holds optional filter criteria for ListTasks.
type TaskFilter struct {
	AssignedTo string     // filter by assignee email (empty = all)
	Status     TaskStatus // filter by status (empty = all)
}

// ListTasks returns tasks matching the filter, sorted newest-first by UpdatedAt.
func (s *TaskStore) ListTasks(filter TaskFilter) ([]Task, error) {
	var tasks []Task
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketTasks).ForEach(func(_, v []byte) error {
			var t Task
			if err := json.Unmarshal(v, &t); err != nil {
				return err
			}
			if filter.AssignedTo != "" && t.AssignedTo != filter.AssignedTo {
				return nil
			}
			if filter.Status != "" && t.Status != filter.Status {
				return nil
			}
			tasks = append(tasks, t)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	// Sort newest-updated first.
	for i := 0; i < len(tasks)-1; i++ {
		for j := i + 1; j < len(tasks); j++ {
			if tasks[j].UpdatedAt.After(tasks[i].UpdatedAt) {
				tasks[i], tasks[j] = tasks[j], tasks[i]
			}
		}
	}
	return tasks, nil
}

// GetTasksForFinding returns all tasks linked to a finding key.
func (s *TaskStore) GetTasksForFinding(findingKey string) ([]Task, error) {
	var tasks []Task
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketTasks).ForEach(func(_, v []byte) error {
			var t Task
			if err := json.Unmarshal(v, &t); err != nil {
				return err
			}
			if t.FindingKey == findingKey {
				tasks = append(tasks, t)
			}
			return nil
		})
	})
	return tasks, err
}

// OverdueTasks returns all tasks that are past their due date and not closed.
func (s *TaskStore) OverdueTasks(now time.Time) ([]Task, error) {
	var tasks []Task
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketTasks).ForEach(func(_, v []byte) error {
			var t Task
			if err := json.Unmarshal(v, &t); err != nil {
				return err
			}
			if t.DueDate == nil {
				return nil
			}
			if t.Status == TaskResolved || t.Status == TaskWontFix {
				return nil
			}
			if now.After(*t.DueDate) {
				tasks = append(tasks, t)
			}
			return nil
		})
	})
	return tasks, err
}

func (s *TaskStore) save(t Task) error {
	raw, err := json.Marshal(t)
	if err != nil {
		return fmt.Errorf("marshal task: %w", err)
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketTasks).Put([]byte(t.ID), raw)
	})
}
