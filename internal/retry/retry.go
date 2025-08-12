// Package retry provides retry functionality with exponential backoff and jitter
// using the codeGROOVE-dev/retry library for robust error handling.
package retry

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/retry"
)

// Do executes the given function with exponential backoff retry logic with jitter.
// It will retry with exponential backoff up to 2 minutes.
func Do(ctx context.Context, maxAttempts int, fn func() error) error {
	if ctx == nil {
		return fmt.Errorf("context cannot be nil")
	}

	if fn == nil {
		return fmt.Errorf("function cannot be nil")
	}

	if maxAttempts < 1 {
		maxAttempts = 1
	}

	// Ensure maxAttempts doesn't cause overflow
	if maxAttempts > 100 {
		maxAttempts = 100
	}

	// Configure retry with exponential backoff and jitter, waiting up to 2 minutes
	err := retry.Do(
		func() error {
			// Log each attempt for debugging
			log.Printf("[RETRY] Attempting operation...")
			return fn()
		},
		retry.Context(ctx),
		retry.Attempts(uint(maxAttempts)),
		retry.Delay(250*time.Millisecond),
		retry.MaxDelay(2*time.Minute), // Wait up to 2 minutes as specified
		retry.DelayType(retry.BackOffDelay),
		retry.MaxJitter(5*time.Second), // Increase jitter for longer delays
		retry.LastErrorOnly(true),
		retry.RetryIf(func(err error) bool {
			retryable := IsRetryable(err)
			if retryable {
				log.Printf("[RETRY] Retryable error encountered: %v", err)
			} else {
				log.Printf("[RETRY] Non-retryable error encountered: %v", err)
			}
			return retryable
		}),
		retry.OnRetry(func(n uint, err error) {
			log.Printf("[RETRY] Attempt %d/%d failed: %v", n+1, maxAttempts, err)
		}),
	)
	if err != nil {
		return fmt.Errorf("operation failed after %d attempts: %w", maxAttempts, err)
	}

	log.Printf("[RETRY] Operation succeeded")
	return nil
}

// WithRetryableCheck wraps a function to handle retryable errors distinctly.
// If the error is retryable, it returns it as-is for retry.Do to handle.
// If not retryable, it wraps the error with the provided wrapper function.
func WithRetryableCheck(fn func() error, wrapNonRetryable func(error) error) func() error {
	return func() error {
		err := fn()
		if err == nil {
			return nil
		}
		if IsRetryable(err) {
			log.Printf("[RETRY] Retryable error detected: %v", err)
			return err // Let retry.Do handle it
		}
		// Non-retryable error, wrap it
		log.Printf("[RETRY] Non-retryable error detected, wrapping: %v", err)
		return wrapNonRetryable(err)
	}
}

// IsRetryable determines if an error should be retried.
// This checks for common transient errors that are safe to retry.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Check if context was cancelled - don't retry in this case
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	// Add specific error checks here based on your needs
	// For now, we'll consider network errors and timeouts as retryable
	errStr := strings.ToLower(err.Error())
	retryableErrors := []string{
		"connection refused",
		"timeout",
		"temporary failure",
		"too many requests",
		"rate limit",
		"service unavailable",
		"bad gateway",
		"gateway timeout",
		"i/o timeout",
		"network is unreachable",
		"no such host",
		"eof",
		"connection reset",
		"broken pipe",
		"resource temporarily unavailable",
	}

	for _, retryable := range retryableErrors {
		if strings.Contains(errStr, retryable) {
			return true
		}
	}

	// Check for specific HTTP status codes in error messages
	// GitHub API often includes status codes in error messages
	httpRetryableCodes := []string{
		"429", // Too Many Requests
		"500", // Internal Server Error
		"502", // Bad Gateway
		"503", // Service Unavailable
		"504", // Gateway Timeout
		"408", // Request Timeout
	}

	for _, code := range httpRetryableCodes {
		if strings.Contains(errStr, code) {
			return true
		}
	}

	// Special handling for GitHub secondary rate limits (403 with specific message)
	if strings.Contains(errStr, "403") &&
		(strings.Contains(errStr, "rate limit") ||
			strings.Contains(errStr, "secondary rate limit")) {
		return true
	}

	// Handle Gemini API specific errors
	if strings.Contains(errStr, "gemini") || strings.Contains(errStr, "generativeai") {
		// Retry on quota exceeded or overloaded
		if strings.Contains(errStr, "quota") ||
			strings.Contains(errStr, "capacity") ||
			strings.Contains(errStr, "overloaded") {
			return true
		}
	}

	return false
}

