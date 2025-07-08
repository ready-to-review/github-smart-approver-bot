// Package retry provides retry functionality with exponential backoff and jitter.
package retry

import (
	"context"
	"strings"
	"time"

	"github.com/avast/retry-go/v4"
)

// Do executes the given function with exponential backoff retry logic with jitter.
// It will retry up to maxAttempts times with exponential backoff between attempts.
func Do(ctx context.Context, maxAttempts int, fn func() error) error {
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	opts := []retry.Option{
		retry.Attempts(uint(maxAttempts)),
		retry.Delay(250 * time.Millisecond),
		retry.DelayType(retry.BackOffDelay),
		retry.MaxJitter(100 * time.Millisecond), // Add jitter to prevent thundering herd
		retry.Context(ctx),
		retry.RetryIf(func(err error) bool {
			// Only retry if the error is retryable
			return IsRetryable(err)
		}),
		retry.OnRetry(func(n uint, err error) {
			// Optional: could add logging here if needed
			// log.Printf("Retry attempt %d after error: %v", n, err)
		}),
	}

	return retry.Do(fn, opts...)
}

// DoWithOptions executes the given function with custom retry options.
// This allows fine-tuning retry behavior for specific use cases.
func DoWithOptions(fn func() error, opts ...retry.Option) error {
	// Set default options that can be overridden
	defaultOpts := []retry.Option{
		retry.Attempts(10),
		retry.Delay(250 * time.Millisecond),
		retry.DelayType(retry.BackOffDelay),
		retry.MaxJitter(100 * time.Millisecond),
		retry.RetryIf(func(err error) bool {
			return IsRetryable(err)
		}),
	}

	// Append custom options (which will override defaults)
	allOpts := append(defaultOpts, opts...)

	return retry.Do(fn, allOpts...)
}

// IsRetryable determines if an error should be retried.
// This checks for common transient errors that are safe to retry.
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Check if context was cancelled - don't retry in this case
	if err == context.Canceled || err == context.DeadlineExceeded {
		return false
	}

	// Add specific error checks here based on your needs
	// For now, we'll consider network errors and timeouts as retryable
	errStr := err.Error()
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
		"EOF",
	}

	for _, retryable := range retryableErrors {
		if containsIgnoreCase(errStr, retryable) {
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

	return false
}

// containsIgnoreCase checks if s contains substr, case-insensitive
func containsIgnoreCase(s, substr string) bool {
	s = strings.ToLower(s)
	substr = strings.ToLower(substr)
	return strings.Contains(s, substr)
}
