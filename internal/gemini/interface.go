// Package gemini provides interfaces and implementations for Gemini AI API operations.
package gemini

import "context"

// API defines the interface for Gemini AI operations.
type API interface {
	// AnalyzePRChanges analyzes PR changes to determine if they alter behavior.
	AnalyzePRChanges(ctx context.Context, files []FileChange) (*AnalysisResult, error)
	
	// Close closes the Gemini client connection.
	Close() error
}