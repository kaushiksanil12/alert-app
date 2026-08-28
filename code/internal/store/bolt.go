package store

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"go.etcd.io/bbolt"

	"github.com/kaushik/vuln-alert-service/internal/fetchers"
)

var (
	bucketDedup      = []byte("dedup")      // "source\x00cve_id" → int64 unix-nano timestamp; NEVER pruned
	bucketFindings   = []byte("findings")   // "source\x00cve_id" → JSON(StoredFinding); pruned by RETENTION_DAYS
	bucketSourceMeta = []byte("source_meta") // per-source state: baseline, failure count, status
	bucketRunMeta    = []byte("run_meta")    // global state: last_run timestamp
)

// SourceStatus holds per-source run status for dashboard display and meta-alerting.
type SourceStatus struct {
	OK                  bool      `json:"ok"`
	Error               string    `json:"error,omitempty"`
	LastAttempt         time.Time `json:"last_attempt"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	FindingsThisRun     int       `json:"findings_this_run"`
}

// Store wraps a bbolt database and provides all persistence operations
// required by the vulnerability alert service.
type Store struct {
	db *bbolt.DB
}

// Open opens or creates the bbolt database at path.
func Open(path string) (*Store, error) {
	db, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bbolt db at %q: %w", path, err)
	}
	s := &Store{db: db}
	if err := s.initBuckets(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) initBuckets() error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		for _, name := range [][]byte{bucketDedup, bucketFindings, bucketSourceMeta, bucketRunMeta} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("create bucket %q: %w", name, err)
			}
		}
		return nil
	})
}

// Close shuts down the database cleanly.
func (s *Store) Close() error { return s.db.Close() }

// DB returns the underlying bbolt.DB instance.
func (s *Store) DB() *bbolt.DB { return s.db }

// ─── Baseline ────────────────────────────────────────────────────────────────

// IsBaselineDone reports whether the first-run baseline has been recorded for source.
func (s *Store) IsBaselineDone(source string) (bool, error) {
	var done bool
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketSourceMeta).Get([]byte("baseline\x00" + source))
		done = len(v) > 0
		return nil
	})
	return done, err
}

// MarkBaseline records all current finding IDs as "seen" in the dedup bucket and 
// writes full finding records to the findings bucket so they are visible in the UI,
// but they do not trigger alerts during the first run.
func (s *Store) MarkBaseline(source string, findings []fetchers.Finding) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		dedup := tx.Bucket(bucketDedup)
		findingsBucket := tx.Bucket(bucketFindings)
		meta := tx.Bucket(bucketSourceMeta)

		now := time.Now()
		tsBytes := unixNanoBytes(now)
		for _, f := range findings {
			key := []byte(source + "\x00" + f.CVEID)
			if err := dedup.Put(key, tsBytes); err != nil {
				return fmt.Errorf("baseline dedup put: %w", err)
			}

			// Store full finding record so it's visible in the UI
			sf := fetchers.StoredFinding{
				Finding:   f,
				FirstSeen: now,
			}
			data, err := json.Marshal(sf)
			if err != nil {
				return fmt.Errorf("marshal baseline finding: %w", err)
			}
			if err := findingsBucket.Put(key, data); err != nil {
				return fmt.Errorf("baseline findings put: %w", err)
			}
		}
		if err := meta.Put([]byte("baseline\x00"+source), []byte("1")); err != nil {
			return fmt.Errorf("mark baseline meta: %w", err)
		}
		slog.Info("first-run baseline recorded", "source", source, "count", len(findings))
		return nil
	})
}

// ─── Deduplication ───────────────────────────────────────────────────────────

// IsNew reports whether cveID has not been seen before for source.
func (s *Store) IsNew(source, cveID string) (bool, error) {
	var isNew bool
	err := s.db.View(func(tx *bbolt.Tx) error {
		key := []byte(source + "\x00" + cveID)
		isNew = tx.Bucket(bucketDedup).Get(key) == nil
		return nil
	})
	return isNew, err
}

// RecordFinding stores a finding in both the dedup bucket (forever) and the findings
// bucket (subject to RETENTION_DAYS pruning).
func (s *Store) RecordFinding(sf fetchers.StoredFinding) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		key := []byte(sf.Source + "\x00" + sf.CVEID)

		// Dedup entry — retained indefinitely, prevents re-alerting on pruned findings.
		if err := tx.Bucket(bucketDedup).Put(key, unixNanoBytes(sf.FirstSeen)); err != nil {
			return fmt.Errorf("dedup put: %w", err)
		}

		// Full finding record — pruned after RETENTION_DAYS.
		data, err := json.Marshal(sf)
		if err != nil {
			return fmt.Errorf("marshal finding: %w", err)
		}
		if err := tx.Bucket(bucketFindings).Put(key, data); err != nil {
			return fmt.Errorf("findings put: %w", err)
		}
		return nil
	})
}

// ─── Querying ─────────────────────────────────────────────────────────────────

// FindingFilter specifies optional criteria for GetFindings.
type FindingFilter struct {
	ShowAcknowledged bool
	Severity         string    // empty = all severities
	From             time.Time // zero = no lower bound
	To               time.Time // zero = no upper bound
	Source           string    // empty = all sources
}

// GetFindings returns stored findings matching the filter, ordered by first-seen descending.
func (s *Store) GetFindings(f FindingFilter) ([]fetchers.StoredFinding, error) {
	var results []fetchers.StoredFinding
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketFindings).ForEach(func(k, v []byte) error {
			var sf fetchers.StoredFinding
			if err := json.Unmarshal(v, &sf); err != nil {
				slog.Warn("skipping malformed finding in store", "key", string(k), "err", err)
				return nil
			}
			if !f.ShowAcknowledged && sf.Acknowledged {
				return nil
			}
			if f.Severity != "" && string(sf.Severity) != f.Severity {
				return nil
			}
			if !f.From.IsZero() && sf.Published.Before(f.From) {
				return nil
			}
			if !f.To.IsZero() && sf.Published.After(f.To) {
				return nil
			}
			if f.Source != "" && sf.Source != f.Source {
				return nil
			}
			results = append(results, sf)
			return nil
		})
	})

	// Sort findings by Published date, descending (newest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Published.After(results[j].Published)
	})

	return results, err
}

// GetFindingsSince returns all findings (including acknowledged) first-seen after t.
func (s *Store) GetFindingsSince(since time.Time) ([]fetchers.StoredFinding, error) {
	var results []fetchers.StoredFinding
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketFindings).ForEach(func(k, v []byte) error {
			var sf fetchers.StoredFinding
			if err := json.Unmarshal(v, &sf); err != nil {
				return nil
			}
			if sf.FirstSeen.After(since) {
				results = append(results, sf)
			}
			return nil
		})
	})
	return results, err
}

// ─── Source Status & Meta-alerting ───────────────────────────────────────────

// RecordSourceStatus updates per-source status and increments/resets consecutive failure count.
func (s *Store) RecordSourceStatus(source string, ok bool, errMsg string, findings int) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketSourceMeta)
		key := []byte("status\x00" + source)

		var status SourceStatus
		if v := b.Get(key); v != nil {
			_ = json.Unmarshal(v, &status)
		}

		status.OK = ok
		status.LastAttempt = time.Now()
		status.FindingsThisRun = findings
		if ok {
			status.ConsecutiveFailures = 0
			status.Error = ""
		} else {
			status.ConsecutiveFailures++
			status.Error = errMsg
		}

		data, err := json.Marshal(status)
		if err != nil {
			return err
		}
		return b.Put(key, data)
	})
}

// GetSourceStatus returns the current status for a source.
func (s *Store) GetSourceStatus(source string) (SourceStatus, error) {
	var status SourceStatus
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketSourceMeta).Get([]byte("status\x00" + source))
		if v == nil {
			return nil
		}
		return json.Unmarshal(v, &status)
	})
	return status, err
}

// GetAllSourceStatuses returns the status for all sources that have ever run.
func (s *Store) GetAllSourceStatuses() (map[string]SourceStatus, error) {
	statuses := make(map[string]SourceStatus)
	prefix := "status\x00"
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketSourceMeta).ForEach(func(k, v []byte) error {
			key := string(k)
			if len(key) > len(prefix) && key[:len(prefix)] == prefix {
				source := key[len(prefix):]
				var st SourceStatus
				if err := json.Unmarshal(v, &st); err == nil {
					statuses[source] = st
				}
			}
			return nil
		})
	})
	return statuses, err
}

// ─── Run Metadata ─────────────────────────────────────────────────────────────

// SetLastRunTime records the timestamp of the most recent completed run.
func (s *Store) SetLastRunTime(t time.Time) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket(bucketRunMeta).Put([]byte("last_run"), []byte(t.Format(time.RFC3339)))
	})
}

// GetLastRunTime returns the last completed run time, or zero if never run.
func (s *Store) GetLastRunTime() (time.Time, error) {
	var t time.Time
	err := s.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bucketRunMeta).Get([]byte("last_run"))
		if v == nil {
			return nil
		}
		var err error
		t, err = time.Parse(time.RFC3339, string(v))
		return err
	})
	return t, err
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func unixNanoBytes(t time.Time) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(t.UnixNano()))
	return b
}
