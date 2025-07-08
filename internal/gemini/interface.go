// Package gemini provides interfaces and implementations for Gemini AI API operations.
package gemini

import "context"

// PRContext contains context information about a pull request
type PRContext struct {
	Title             string
	Description       string
	Author            string
	AuthorAssociation string
	Organization      string
	Repository        string
	PullRequestNumber int
	URL               string
}

// API defines the interface for Gemini AI operations.
type API interface {
	// AnalyzePRChanges analyzes PR changes to determine if they alter behavior.
	AnalyzePRChanges(ctx context.Context, files []FileChange, prContext PRContext) (*AnalysisResult, error)

	// Close closes the Gemini client connection.
	Close() error
}
