package store

import (
	"encoding/json"
	"fmt"
	"time"

	"go.etcd.io/bbolt"

	"github.com/kaushik/vuln-alert-service/internal/fetchers"
)

// Acknowledge sets Acknowledged=true on a stored finding. This is a state-only
// change — it does NOT touch the dedup bucket, so the CVE remains "already seen"
// and will never trigger a re-alert (§3.12).
func (s *Store) Acknowledge(source, cveID string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketFindings)
		key := []byte(source + "\x00" + cveID)

		v := b.Get(key)
		if v == nil {
			return fmt.Errorf("finding not found: source=%q cve=%q", source, cveID)
		}

		var sf fetchers.StoredFinding
		if err := json.Unmarshal(v, &sf); err != nil {
			return fmt.Errorf("unmarshal finding: %w", err)
		}

		now := time.Now()
		sf.Acknowledged = true
		sf.AcknowledgedAt = &now

		updated, err := json.Marshal(sf)
		if err != nil {
			return fmt.Errorf("marshal updated finding: %w", err)
		}
		return b.Put(key, updated)
	})
}

// Unacknowledge reverses an acknowledge action (§3.12 — the toggle is reversible).
func (s *Store) Unacknowledge(source, cveID string) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketFindings)
		key := []byte(source + "\x00" + cveID)

		v := b.Get(key)
		if v == nil {
			return fmt.Errorf("finding not found: source=%q cve=%q", source, cveID)
		}

		var sf fetchers.StoredFinding
		if err := json.Unmarshal(v, &sf); err != nil {
			return fmt.Errorf("unmarshal finding: %w", err)
		}

		sf.Acknowledged = false
		sf.AcknowledgedAt = nil

		updated, err := json.Marshal(sf)
		if err != nil {
			return fmt.Errorf("marshal updated finding: %w", err)
		}
		return b.Put(key, updated)
	})
}
