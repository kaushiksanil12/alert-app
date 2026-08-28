package fetchers

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"time"
)

// WithRetry wraps any Fetcher with automatic retry using exponential backoff.
// maxAttempts is the total number of tries (1 = no retry).
// baseDelay is the delay before the first retry.
func WithRetry(f Fetcher, maxAttempts int, baseDelay time.Duration) Fetcher {
	return &retryFetcher{inner: f, maxAttempts: maxAttempts, baseDelay: baseDelay}
}

type retryFetcher struct {
	inner       Fetcher
	maxAttempts int
	baseDelay   time.Duration
}

func (r *retryFetcher) Name() string { return r.inner.Name() }

func (r *retryFetcher) Fetch(ctx context.Context) ([]Finding, error) {
	var lastErr error
	for attempt := 0; attempt < r.maxAttempts; attempt++ {
		if attempt > 0 {
			delay := r.backoffDelay(attempt)
			slog.Info("retrying fetch after backoff",
				"source", r.Name(),
				"attempt", attempt+1,
				"max_attempts", r.maxAttempts,
				"delay", delay,
			)
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("fetch cancelled before retry %d: %w", attempt+1, ctx.Err())
			case <-time.After(delay):
			}
		}

		findings, err := r.inner.Fetch(ctx)
		if err == nil {
			return findings, nil
		}

		// Context cancellation is not a transient error — don't retry.
		if ctx.Err() != nil {
			return nil, err
		}

		lastErr = err
		slog.Warn("fetch attempt failed",
			"source", r.Name(),
			"attempt", attempt+1,
			"err", err,
		)
	}
	return nil, fmt.Errorf("all %d attempts failed for %s: %w", r.maxAttempts, r.Name(), lastErr)
}

// backoffDelay returns the delay for the nth retry (0-indexed, so n=1 is first retry).
// Formula: baseDelay * 2^(n-1), capped at 5 minutes.
func (r *retryFetcher) backoffDelay(attempt int) time.Duration {
	exp := math.Pow(2, float64(attempt-1))
	delay := time.Duration(float64(r.baseDelay) * exp)
	const maxDelay = 5 * time.Minute
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}
