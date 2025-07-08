// Package analyzer provides pull request analysis functionality.
// It coordinates between GitHub and Gemini APIs to determine if a PR
// is safe to auto-approve based on configured criteria.
package analyzer

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v68/github"
	"github.com/thegroove/trivial-auto-approve/internal/constants"
	"github.com/thegroove/trivial-auto-approve/internal/errors"
	"github.com/thegroove/trivial-auto-approve/internal/gemini"
	githubAPI "github.com/thegroove/trivial-auto-approve/internal/github"
)

// Config holds configuration for the analyzer.
type Config struct {
	// MaxFiles is the maximum number of files changed in a PR for auto-approval.
	// Must be positive.
	MaxFiles int
	
	// SkipFirstTime indicates whether to skip first-time contributors.
	SkipFirstTime bool
	
	// RequirePassingChecks indicates whether to require all CI checks to pass.
	RequirePassingChecks bool
	
	// IgnoreSigningChecks indicates whether to ignore signing checks for bot authors.
	IgnoreSigningChecks bool
	
	// UseGemini indicates whether to use Gemini AI for analysis.
	UseGemini bool
	
	// DryRun indicates whether to run in dry-run mode (no actual approvals).
	DryRun bool
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		MaxFiles:             constants.DefaultMaxFiles,
		SkipFirstTime:        true,
		RequirePassingChecks: true,
		IgnoreSigningChecks:  true,
		UseGemini:           true,
		DryRun:              false,
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if c.MaxFiles < 1 {
		return &errors.ValidationError{
			Field: "MaxFiles",
			Value: c.MaxFiles,
			Msg:   "must be at least 1",
		}
	}
	return nil
}

// Analyzer analyzes pull requests for auto-approval.
type Analyzer struct {
	gh     githubAPI.API
	gemini gemini.API
	config *Config
}

// New creates a new analyzer with the provided dependencies.
// If config is nil, DefaultConfig() will be used.
func New(gh githubAPI.API, gemini gemini.API, config *Config) (*Analyzer, error) {
	if config == nil {
		config = DefaultConfig()
	}
	
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	
	return &Analyzer{
		gh:     gh,
		gemini: gemini,
		config: config,
	}, nil
}

// Result represents the analysis result for a PR.
type Result struct {
	Approvable bool
	Reason     string
	Details    []string
}

// AnalyzePullRequest analyzes a single pull request.
func (a *Analyzer) AnalyzePullRequest(ctx context.Context, owner, repo string, number int) (*Result, error) {
	pr, err := a.gh.GetPullRequest(ctx, owner, repo, number)
	if err != nil {
		return nil, fmt.Errorf("getting PR: %w", err)
	}

	result := &Result{
		Approvable: true,
		Details:    []string{},
	}

	// Check if PR is already merged or closed
	if pr.GetState() != constants.PRStateOpen {
		result.Approvable = false
		result.Reason = "PR is not open"
		return result, nil
	}

	// Check for existing reviews
	if reason, details := a.checkExistingReviews(ctx, owner, repo, number); reason != "" {
		result.Approvable = false
		result.Reason = reason
		result.Details = details
		return result, nil
	}

	// Check for comments from collaborators  
	if reason, details := a.checkCollaboratorComments(ctx, owner, repo, number); reason != "" {
		result.Approvable = false
		result.Reason = reason
		result.Details = details
		return result, nil
	}

	// Check first-time contributor
	if a.config.SkipFirstTime && pr.User != nil && pr.User.Login != nil {
		isFirstTime, err := a.gh.IsFirstTimeContributor(ctx, owner, repo, *pr.User.Login)
		if err != nil {
			return nil, fmt.Errorf("checking first-time contributor: %w", err)
		}
		if isFirstTime {
			result.Approvable = false
			result.Reason = "First-time contributor"
			result.Details = append(result.Details, fmt.Sprintf("User %s is a first-time contributor", *pr.User.Login))
			return result, nil
		}
	}

	// Get PR files
	files, err := a.gh.GetPullRequestFiles(ctx, owner, repo, number)
	if err != nil {
		return nil, fmt.Errorf("getting PR files: %w", err)
	}

	// Check file count
	if len(files) > a.config.MaxFiles {
		result.Approvable = false
		result.Reason = fmt.Sprintf("Too many files changed (%d > %d)", len(files), a.config.MaxFiles)
		return result, nil
	}

	// Check CI status
	if a.config.RequirePassingChecks && pr.Head != nil && pr.Head.SHA != nil {
		status, err := a.gh.GetCombinedStatus(ctx, owner, repo, *pr.Head.SHA)
		if err != nil {
			return nil, fmt.Errorf("getting CI status: %w", err)
		}

		if !a.isStatusPassing(status, pr.User) {
			result.Approvable = false
			result.Reason = "CI checks not passing"
			result.Details = append(result.Details, a.getFailingChecks(status)...)
			return result, nil
		}
	}

	// Analyze content of changes
	if reason, details := a.analyzeChangeContent(ctx, files); reason != "" {
		result.Approvable = false
		result.Reason = reason
		result.Details = append(result.Details, details...)
		return result, nil
	}

	// If we got here, all content analysis passed
	if len(result.Details) > 0 {
		result.Reason = "All checks passed"
	}

	return result, nil
}

// checkExistingReviews checks if there are any existing reviews on the PR
func (a *Analyzer) checkExistingReviews(ctx context.Context, owner, repo string, number int) (string, []string) {
	reviews, err := a.gh.ListReviews(ctx, owner, repo, number)
	if err != nil {
		// Return error as reason but don't fail the analysis
		return fmt.Sprintf("Error checking reviews: %v", err), nil
	}
	
	for _, review := range reviews {
		if review.State != nil && (*review.State == constants.ReviewStateApproved || 
			*review.State == constants.ReviewStateChangesRequested || 
			*review.State == constants.ReviewStateCommented) {
			return "PR has existing reviews", []string{
				fmt.Sprintf("Review by %s: %s", review.User.GetLogin(), review.GetState()),
			}
		}
	}
	return "", nil
}

// checkCollaboratorComments checks for comments from collaborators
func (a *Analyzer) checkCollaboratorComments(ctx context.Context, owner, repo string, number int) (string, []string) {
	// Check issue comments
	issueComments, err := a.gh.ListIssueComments(ctx, owner, repo, number)
	if err != nil {
		return fmt.Sprintf("Error checking issue comments: %v", err), nil
	}
	
	for _, comment := range issueComments {
		if comment.AuthorAssociation != nil && isCollaborator(*comment.AuthorAssociation) {
			return "PR has comments from collaborators", []string{
				fmt.Sprintf("Comment by %s (%s)", comment.User.GetLogin(), *comment.AuthorAssociation),
			}
		}
	}
	
	// Check PR review comments
	prComments, err := a.gh.ListPullRequestComments(ctx, owner, repo, number)
	if err != nil {
		return fmt.Sprintf("Error checking PR comments: %v", err), nil
	}
	
	for _, comment := range prComments {
		if comment.AuthorAssociation != nil && isCollaborator(*comment.AuthorAssociation) {
			return "PR has review comments from collaborators", []string{
				fmt.Sprintf("Review comment by %s (%s)", comment.User.GetLogin(), *comment.AuthorAssociation),
			}
		}
	}
	
	return "", nil
}

// analyzeChangeContent analyzes the actual content of the changes using Gemini or basic heuristics
func (a *Analyzer) analyzeChangeContent(ctx context.Context, files []*github.CommitFile) (string, []string) {
	var details []string
	
	if a.config.UseGemini && a.gemini != nil {
		geminiResult, err := a.analyzeWithGemini(ctx, files)
		if err != nil {
			// Don't fail if Gemini analysis fails, just log it
			details = append(details, fmt.Sprintf("Gemini analysis failed: %v", err))
		} else {
			if geminiResult.AltersBehavior {
				return "Changes alter application behavior", []string{geminiResult.Reason}
			}
			
			if !geminiResult.IsImprovement {
				return "Changes do not appear to be an improvement", []string{geminiResult.Reason}
			}

			if geminiResult.IsTrivial {
				details = append(details, fmt.Sprintf("Trivial change detected: %s", geminiResult.Category))
			}
		}
	} else {
		// Without Gemini, do basic trivial change detection
		isTrivial, category := a.detectTrivialChanges(files)
		if !isTrivial {
			return "Cannot verify change is trivial without AI analysis", nil
		}
		details = append(details, fmt.Sprintf("Trivial change detected: %s", category))
	}
	
	return "", details
}

// isStatusPassing checks if the combined status is passing.
func (a *Analyzer) isStatusPassing(status *github.CombinedStatus, prAuthor *github.User) bool {
	state := status.GetState()
	if state == constants.CheckStateSuccess {
		return true
	}
	
	if state == constants.CheckStatePending {
		return false
	}

	// Check individual statuses
	hasFailures := false
	onlyReviewRequired := true
	for _, s := range status.Statuses {
		if s.GetState() == constants.CheckStateFailure || s.GetState() == constants.CheckStateError {
			// Ignore signing checks for bot authors if configured
			if a.config.IgnoreSigningChecks && prAuthor != nil && prAuthor.Type != nil && *prAuthor.Type == "Bot" {
				if strings.Contains(strings.ToLower(s.GetContext()), "sign") {
					continue
				}
			}
			
			// Check if this is just a review required check
			ctx := strings.ToLower(s.GetContext())
			desc := ""
			if s.Description != nil {
				desc = strings.ToLower(*s.Description)
			}
			
			if !strings.Contains(ctx, "review") && !strings.Contains(desc, "review required") && !strings.Contains(desc, "awaiting review") {
				onlyReviewRequired = false
			}
			
			hasFailures = true
		}
	}

	// If only review-required checks are failing, we can still proceed
	if hasFailures && onlyReviewRequired {
		return true
	}

	return !hasFailures
}

// getFailingChecks returns a list of failing check descriptions.
func (a *Analyzer) getFailingChecks(status *github.CombinedStatus) []string {
	var failing []string
	for _, s := range status.Statuses {
		if s.GetState() == constants.CheckStateFailure || s.GetState() == constants.CheckStateError {
			desc := fmt.Sprintf("[%s] %s", s.GetState(), s.GetContext())
			if s.Description != nil {
				desc += ": " + *s.Description
			}
			if s.TargetURL != nil {
				desc += fmt.Sprintf(" (see: %s)", *s.TargetURL)
			}
			failing = append(failing, desc)
		}
	}
	return failing
}

// isCollaborator checks if the author association indicates write access.
func isCollaborator(association string) bool {
	switch association {
	case constants.AuthorAssociationOwner,
	     constants.AuthorAssociationMember,
	     constants.AuthorAssociationCollaborator:
		return true
	default:
		return false
	}
}

// analyzeWithGemini uses Gemini to analyze PR changes.
func (a *Analyzer) analyzeWithGemini(ctx context.Context, files []*github.CommitFile) (*gemini.AnalysisResult, error) {
	var changes []gemini.FileChange
	for _, f := range files {
		change := gemini.FileChange{
			Filename:  f.GetFilename(),
			Additions: f.GetAdditions(),
			Deletions: f.GetDeletions(),
		}
		if f.Patch != nil {
			change.Patch = *f.Patch
		}
		changes = append(changes, change)
	}

	return a.gemini.AnalyzePRChanges(ctx, changes)
}

// detectTrivialChanges performs basic trivial change detection without AI.
func (a *Analyzer) detectTrivialChanges(files []*github.CommitFile) (bool, string) {
	// Simple heuristics for detecting trivial changes
	for _, f := range files {
		filename := f.GetFilename()
		
		// Check if it's a documentation file
		if strings.HasSuffix(filename, ".md") || 
		   strings.HasSuffix(filename, ".txt") ||
		   strings.Contains(filename, "README") ||
		   strings.Contains(filename, "LICENSE") {
			continue
		}

		// For code files, we can't reliably determine if changes are trivial without AI
		if strings.HasSuffix(filename, ".go") ||
		   strings.HasSuffix(filename, ".js") ||
		   strings.HasSuffix(filename, ".py") ||
		   strings.HasSuffix(filename, ".java") ||
		   strings.HasSuffix(filename, ".cpp") ||
		   strings.HasSuffix(filename, ".c") {
			// Without AI, we can't safely determine if code changes are trivial
			return false, ""
		}
	}

	// If we only have documentation changes, it's likely trivial
	return true, "documentation"
}