package store

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"go.etcd.io/bbolt"

	"github.com/kaushik/vuln-alert-service/internal/fetchers"
)

// Prune deletes finding records older than retentionDays from the findings bucket.
// The dedup bucket is NEVER touched — this ensures that a CVE pruned from full
// records is still recognized as "already seen" and never re-alerted (§3.9).
func (s *Store) Prune(retentionDays int) (int, error) {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	var pruned int

	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(bucketFindings)

		// Collect keys to delete (can't delete inside ForEach safely).
		var toDelete [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var sf fetchers.StoredFinding
			if err := json.Unmarshal(v, &sf); err != nil {
				// Malformed entry — remove it too.
				toDelete = append(toDelete, append([]byte{}, k...))
				return nil
			}
			if sf.FirstSeen.Before(cutoff) {
				toDelete = append(toDelete, append([]byte{}, k...))
			}
			return nil
		}); err != nil {
			return fmt.Errorf("scan findings for pruning: %w", err)
		}

		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return fmt.Errorf("delete finding %q: %w", k, err)
			}
		}
		pruned = len(toDelete)
		return nil
	})

	if err != nil {
		return 0, err
	}
	if pruned > 0 {
		slog.Info("retention prune complete",
			"pruned", pruned,
			"retention_days", retentionDays,
			"cutoff", cutoff.Format(time.RFC3339),
		)
	}
	return pruned, nil
}
