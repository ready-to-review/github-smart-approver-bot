// Package errors provides custom error types for the trivial-auto-approve application.
package errors

import (
	"errors"
	"fmt"
)

// Common sentinel errors.
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

// API creates a new APIError.
func API(service, method string, err error) error {
	if err == nil {
		return nil
	}
	return &APIError{
		Service: service,
		Method:  method,
		Err:     err,
	}
}

// Validation creates a new ValidationError.
func Validation(field string, value interface{}, msg string) error {
	return &ValidationError{
		Field: field,
		Value: value,
		Msg:   msg,
	}
}
