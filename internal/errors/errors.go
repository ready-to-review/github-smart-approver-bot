// Package errors provides custom error types for the trivial-auto-approve application.
package errors

import (
	"errors"
	"fmt"
)

// Common sentinel errors
var (
	// ErrNoGitHubToken indicates that no GitHub authentication token was found.
	ErrNoGitHubToken = errors.New("no GitHub token found")

	// ErrNoGeminiKey indicates that the GEMINI_API_KEY environment variable is not set.
	ErrNoGeminiKey = errors.New("GEMINI_API_KEY environment variable not set")

	// ErrInvalidPRURL indicates that the provided PR URL could not be parsed.
	ErrInvalidPRURL = errors.New("invalid pull request URL format")

	// ErrPRNotOpen indicates that the PR is not in an open state.
	ErrPRNotOpen = errors.New("pull request is not open")

	// ErrPRReadyToMerge indicates that a PR is already in clean status and ready to merge.
	ErrPRReadyToMerge = errors.New("PR is already in clean status and ready to merge")

	// ErrBranchUpToDate indicates that the branch is already up to date.
	ErrBranchUpToDate = errors.New("branch already up to date")
)

// ValidationError represents an error in configuration or input validation.
type ValidationError struct {
	Field string
	Value interface{}
	Msg   string
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for %s (value: %v): %s", e.Field, e.Value, e.Msg)
}

// APIError represents an error from an external API.
type APIError struct {
	Service string
	Method  string
	Err     error
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return fmt.Sprintf("%s API error in %s: %v", e.Service, e.Method, e.Err)
}

// Unwrap returns the underlying error.
func (e *APIError) Unwrap() error {
	return e.Err
}

// AnalysisError represents an error during PR analysis.
type AnalysisError struct {
	PR     string
	Reason string
	Err    error
}

// Error implements the error interface.
func (e *AnalysisError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("analysis error for PR %s: %s: %v", e.PR, e.Reason, e.Err)
	}
	return fmt.Sprintf("analysis error for PR %s: %s", e.PR, e.Reason)
}

// Unwrap returns the underlying error.
func (e *AnalysisError) Unwrap() error {
	return e.Err
}
