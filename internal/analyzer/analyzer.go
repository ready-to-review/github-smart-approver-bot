// Package analyzer provides pull request analysis functionality.
// It coordinates between GitHub and Gemini APIs to determine if a PR
// is safe to auto-approve based on configured criteria.
package analyzer

import (
	"context"
	"fmt"
	"strings"
	"time"

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

	// MaxLines is the maximum number of lines changed in a PR for auto-approval.
	// Must be positive.
	MaxLines int

	// SkipFirstTime indicates whether to skip first-time contributors.
	SkipFirstTime bool

	// SkipDraft indicates whether to skip draft PRs.
	SkipDraft bool

	// RequirePassingChecks indicates whether to require all CI checks to pass.
	RequirePassingChecks bool

	// IgnoreSigningChecks indicates whether to ignore signing checks for bot authors.
	IgnoreSigningChecks bool

	// UseGemini indicates whether to use Gemini AI for analysis.
	UseGemini bool

	// DryRun indicates whether to run in dry-run mode (no actual approvals).
	DryRun bool

	// MinOpenTime is the minimum time a PR must be open before auto-approval.
	MinOpenTime time.Duration

	// MaxOpenTime is the maximum time a PR can be open for auto-approval.
	MaxOpenTime time.Duration
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		MaxFiles:             constants.DefaultMaxFiles,
		MaxLines:             125,
		SkipFirstTime:        true,
		SkipDraft:            true,
		RequirePassingChecks: true,
		IgnoreSigningChecks:  true,
		UseGemini:            true,
		DryRun:               false,
		MinOpenTime:          4 * time.Hour,
		MaxOpenTime:          90 * 24 * time.Hour, // 90 days
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
	if c.MaxLines < 1 {
		return &errors.ValidationError{
			Field: "MaxLines",
			Value: c.MaxLines,
			Msg:   "must be at least 1",
		}
	}
	if c.MinOpenTime < 0 {
		return &errors.ValidationError{
			Field: "MinOpenTime",
			Value: c.MinOpenTime,
			Msg:   "must not be negative",
		}
	}
	if c.MaxOpenTime < 0 {
		return &errors.ValidationError{
			Field: "MaxOpenTime",
			Value: c.MaxOpenTime,
			Msg:   "must not be negative",
		}
	}
	if c.MaxOpenTime > 0 && c.MinOpenTime > c.MaxOpenTime {
		return &errors.ValidationError{
			Field: "MinOpenTime/MaxOpenTime",
			Value: fmt.Sprintf("min=%v, max=%v", c.MinOpenTime, c.MaxOpenTime),
			Msg:   "MinOpenTime must not exceed MaxOpenTime",
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
	Approvable          bool
	Reason              string
	Details             []string
	AlreadyApprovedByUs bool // Indicates if we've already approved this PR
	IsOwnPR             bool // Indicates if the current user is the PR author
}

// AnalyzePullRequest analyzes a single pull request.
func (a *Analyzer) AnalyzePullRequest(ctx context.Context, owner, repo string, number int) (*Result, error) {
	pr, err := a.gh.GetPullRequest(ctx, owner, repo, number)
	if err != nil {
		return nil, fmt.Errorf("getting PR: %w", err)
	}

	// Get current authenticated user for checking existing approvals and PR authorship
	currentUser, err := a.gh.GetAuthenticatedUser(ctx)
	if err != nil {
		// Don't fail the analysis if we can't get current user
		currentUser = nil
	}

	result := &Result{
		Approvable:          true,
		Details:             []string{},
		AlreadyApprovedByUs: false,
	}

	// Check if PR is from dependabot
	isDependabot := a.isDependabotPR(pr)

	// === Early checks that don't require additional API calls ===

	// Check if PR is already merged or closed
	if pr.GetState() != constants.PRStateOpen {
		result.Approvable = false
		result.Reason = "PR is not open"
		return result, nil
	}

	// Check if current user is the PR author (can't approve own PRs)
	if currentUser != nil && pr.User != nil &&
		currentUser.GetLogin() != "" && pr.User.GetLogin() == currentUser.GetLogin() {
		result.IsOwnPR = true
		result.Details = append(result.Details, fmt.Sprintf("PR author (%s) is the current user", pr.User.GetLogin()))
		// Don't set Approvable to false here - we might still want to auto-merge
		// The processor will skip approval but can still do auto-merge
	}

	// Check if PR is a draft
	if a.config.SkipDraft && pr.GetDraft() {
		result.Approvable = false
		result.Reason = "PR is a draft"
		return result, nil
	}

	// Check PR age
	if reason := a.checkPRAge(pr); reason != "" {
		result.Approvable = false
		result.Reason = reason
		return result, nil
	}

	// Check file count (available in PR object without additional API call)
	if pr.ChangedFiles != nil && *pr.ChangedFiles > a.config.MaxFiles {
		result.Approvable = false
		result.Reason = fmt.Sprintf("Too many files changed (%d > %d)", *pr.ChangedFiles, a.config.MaxFiles)
		return result, nil
	}

	// Check line count (skip for dependabot)
	if !isDependabot {
		totalLines := 0
		if pr.Additions != nil {
			totalLines += *pr.Additions
		}
		if pr.Deletions != nil {
			totalLines += *pr.Deletions
		}
		if totalLines > a.config.MaxLines {
			result.Approvable = false
			result.Reason = fmt.Sprintf("Too many lines changed (%d > %d)", totalLines, a.config.MaxLines)
			return result, nil
		}
	}

	// Add PR details
	result.Details = append(result.Details, a.formatPRDetails(pr)...)

	// Check for existing reviews
	if reason, details, alreadyApprovedByUs := a.checkExistingReviews(ctx, owner, repo, number, currentUser); reason != "" {
		// If the only review is our approval, we can continue
		if alreadyApprovedByUs {
			result.AlreadyApprovedByUs = true
			result.Details = append(result.Details, "Already approved by current user")
		} else {
			result.Approvable = false
			result.Reason = reason
			result.Details = details
			return result, nil
		}
	}

	// Check for comments from collaborators
	if reason, details := a.checkCollaboratorComments(ctx, owner, repo, number); reason != "" {
		result.Approvable = false
		result.Reason = reason
		result.Details = details
		return result, nil
	}

	// Check first-time contributor using author_association
	if a.config.SkipFirstTime && pr.AuthorAssociation != nil {
		// Check if the author association indicates a first-time contributor
		if *pr.AuthorAssociation == constants.AuthorAssociationFirstTimeContributor {
			result.Approvable = false
			result.Reason = "First-time contributor"
			if pr.User != nil && pr.User.Login != nil {
				result.Details = append(result.Details, fmt.Sprintf("User %s is a first-time contributor", *pr.User.Login))
			}
			return result, nil
		}
	}

	// Get PR files (only if we need them for content analysis)
	var files []*github.CommitFile
	if a.config.UseGemini && a.gemini != nil {
		files, err = a.gh.GetPullRequestFiles(ctx, owner, repo, number)
		if err != nil {
			return nil, fmt.Errorf("getting PR files: %w", err)
		}
	}

	// Check CI status (both commit statuses and check runs)
	if a.config.RequirePassingChecks && pr.Head != nil && pr.Head.SHA != nil {
		// Check commit statuses
		status, err := a.gh.GetCombinedStatus(ctx, owner, repo, *pr.Head.SHA)
		if err != nil {
			return nil, fmt.Errorf("getting CI status: %w", err)
		}

		// Check GitHub Actions check runs
		checkRuns, err := a.gh.ListCheckRunsForRef(ctx, owner, repo, *pr.Head.SHA)
		if err != nil {
			return nil, fmt.Errorf("getting check runs: %w", err)
		}

		if !a.isStatusPassing(status, pr.User) || !a.areCheckRunsPassing(checkRuns) {
			result.Approvable = false
			result.Reason = "CI checks not passing"
			result.Details = append(result.Details, a.getFailingChecks(status)...)
			result.Details = append(result.Details, a.getFailingCheckRuns(checkRuns)...)
			return result, nil
		}
	}

	// Analyze content of changes
	if a.config.UseGemini && a.gemini != nil {
		reason, details := a.analyzeChangeContent(ctx, pr, files, isDependabot)
		// Always add the Gemini analysis details
		if len(details) > 0 {
			result.Details = append(result.Details, details...)
		}

		if reason != "" {
			result.Approvable = false
			result.Reason = reason
			return result, nil
		}
	} else {
		// Without AI, we can't verify if changes are trivial
		result.Approvable = false
		result.Reason = "Cannot verify changes without AI analysis (use --model to enable)"
		return result, nil
	}

	// If we got here, all content analysis passed
	if len(result.Details) > 0 {
		result.Reason = "All checks passed"
	}

	return result, nil
}

// checkExistingReviews checks if there are any existing reviews on the PR
// Returns: reason, details, alreadyApprovedByUs
func (a *Analyzer) checkExistingReviews(ctx context.Context, owner, repo string, number int, currentUser *github.User) (string, []string, bool) {
	reviews, err := a.gh.ListReviews(ctx, owner, repo, number)
	if err != nil {
		// Return error as reason but don't fail the analysis
		return fmt.Sprintf("error checking reviews: %v", err), nil, false
	}

	// Track reviews by user
	var ourApproval bool
	var otherReviews []string
	currentUserLogin := ""
	if currentUser != nil && currentUser.Login != nil {
		currentUserLogin = *currentUser.Login
	}

	for _, review := range reviews {
		if review.State != nil && review.User != nil && (*review.State == constants.ReviewStateApproved ||
			*review.State == constants.ReviewStateChangesRequested ||
			*review.State == constants.ReviewStateCommented) {

			reviewerLogin := review.User.GetLogin()
			if currentUserLogin != "" && reviewerLogin == currentUserLogin && *review.State == constants.ReviewStateApproved {
				ourApproval = true
			} else {
				otherReviews = append(otherReviews, fmt.Sprintf("Review by %s: %s", reviewerLogin, review.GetState()))
			}
		}
	}

	// If there are reviews from other users, fail
	if len(otherReviews) > 0 {
		return "PR has existing reviews", otherReviews, false
	}

	// If the only review is our approval, return that info
	if ourApproval && len(otherReviews) == 0 {
		return "PR already approved by us", nil, true
	}

	return "", nil, false
}

// checkCollaboratorComments checks for comments from collaborators
func (a *Analyzer) checkCollaboratorComments(ctx context.Context, owner, repo string, number int) (string, []string) {
	// Check issue comments
	issueComments, err := a.gh.ListIssueComments(ctx, owner, repo, number)
	if err != nil {
		return fmt.Sprintf("error checking issue comments: %v", err), nil
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
		return fmt.Sprintf("error checking PR comments: %v", err), nil
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
func (a *Analyzer) analyzeChangeContent(ctx context.Context, pr *github.PullRequest, files []*github.CommitFile, isDependabot bool) (string, []string) {
	var details []string

	if a.config.UseGemini && a.gemini != nil {
		geminiResult, err := a.analyzeWithGemini(ctx, pr, files)
		if err != nil {
			// Don't fail if Gemini analysis fails, just log it
			details = append(details, fmt.Sprintf("Gemini analysis failed: %v", err))
		} else {
			// Build user-friendly Gemini analysis output
			var geminiIssues []string

			// Map flags to issues - ordered by severity
			flagChecks := []struct {
				flag  bool
				issue string
			}{
				{geminiResult.PossiblyMalicious, "possibly malicious intent"},
				{geminiResult.Vandalism, "destructive/harmful changes"},
				{geminiResult.InsecureChange, "potential security vulnerabilities"},
				{geminiResult.MajorVersionBump, "major version bump detected"},
				{geminiResult.Risky, "high risk of breakage"},
				{geminiResult.AltersBehavior, "alters application behavior"},
				{geminiResult.NotImprovement, "not an improvement"},
				{geminiResult.NonTrivial && !isDependabot, "non-trivial changes"}, // Skip for dependabot
				{geminiResult.TitleDescMismatch, "title/description doesn't match changes"},
				{geminiResult.Confusing, "reduces code clarity"},
				{geminiResult.Superfluous, "unnecessary/redundant changes"},
			}

			for _, check := range flagChecks {
				if check.flag {
					geminiIssues = append(geminiIssues, check.issue)
				}
			}

			// Format the output based on issues found
			var geminiOutput string
			if len(geminiIssues) == 0 {
				geminiOutput = "Gemini found no issues with this PR"
				if geminiResult.Category != "" {
					geminiOutput += fmt.Sprintf(" (%s change)", geminiResult.Category)
				}
			} else {
				// Format issues more readably
				if len(geminiIssues) == 1 {
					geminiOutput = fmt.Sprintf("Gemini flagged: %s", geminiIssues[0])
				} else if len(geminiIssues) <= 3 {
					geminiOutput = fmt.Sprintf("Gemini flagged %d issues: %s", len(geminiIssues), strings.Join(geminiIssues, ", "))
				} else {
					// For many issues, use a bulleted list
					geminiOutput = fmt.Sprintf("Gemini flagged %d issues:\n", len(geminiIssues))
					for _, issue := range geminiIssues {
						geminiOutput += fmt.Sprintf("  • %s\n", issue)
					}
					geminiOutput = strings.TrimSuffix(geminiOutput, "\n")
				}
				if geminiResult.Category != "" {
					geminiOutput += fmt.Sprintf(" (%s change)", geminiResult.Category)
				}
			}

			// Add the reason if provided
			if geminiResult.Reason != "" {
				geminiOutput += fmt.Sprintf(". Analysis: %s", geminiResult.Reason)
			}

			details = append(details, geminiOutput)

			// Check flags in priority order - return on first failure
			rejectionChecks := []struct {
				flag   bool
				reason string
			}{
				// Critical security issues first
				{geminiResult.PossiblyMalicious, "Changes appear potentially malicious"},
				{geminiResult.Vandalism, "Changes appear to be vandalism"},
				{geminiResult.InsecureChange, "Changes may introduce security vulnerabilities"},

				// Major version bumps are always concerning
				{geminiResult.MajorVersionBump, "Major version bump detected - requires manual review"},

				// High risk issues
				{geminiResult.Risky, "Changes are high risk"},

				// Quality issues
				{geminiResult.TitleDescMismatch, "PR title/description does not match the changes"},
				{geminiResult.AltersBehavior, "Changes alter application behavior"},
				{geminiResult.NotImprovement, "Changes do not appear to be an improvement"},
				{geminiResult.NonTrivial && !isDependabot, "Changes are non-trivial"}, // Skip for dependabot
				{geminiResult.Confusing, "Changes may introduce confusion"},
				{geminiResult.Superfluous, "Changes appear superfluous"},

				// Required fields
				{geminiResult.Category == "", "Cannot determine change category"},
			}

			for _, check := range rejectionChecks {
				if check.flag {
					return check.reason, details
				}
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

	// Don't treat pending as a failure - just continue checking other statuses
	// if state == constants.CheckStatePending {
	// 	return false
	// }

	// Check individual statuses
	hasActualFailures := false
	onlyReviewRequired := true
	for _, s := range status.Statuses {
		// Skip pending checks - they don't count as failures
		if s.GetState() == constants.CheckStatePending {
			continue
		}

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

			hasActualFailures = true
		}
	}

	// If only review-required checks are failing, we can still proceed
	if hasActualFailures && onlyReviewRequired {
		return true
	}

	return !hasActualFailures
}

// getFailingChecks returns a list of failing check descriptions.
func (a *Analyzer) getFailingChecks(status *github.CombinedStatus) []string {
	var failing []string
	var pending []string

	for _, s := range status.Statuses {
		state := s.GetState()
		context := s.GetContext()

		if state == constants.CheckStateFailure || state == constants.CheckStateError {
			desc := fmt.Sprintf("%s: %s", context, state)
			if s.Description != nil && *s.Description != "" {
				desc = fmt.Sprintf("%s (%s)", context, *s.Description)
			}
			failing = append(failing, desc)
		} else if state == constants.CheckStatePending {
			pending = append(pending, context)
		}
	}

	// Add pending checks info if any
	if len(pending) > 0 {
		failing = append(failing, fmt.Sprintf("Pending checks: %s", strings.Join(pending, ", ")))
	}

	return failing
}

// areCheckRunsPassing checks if all check runs are passing
func (a *Analyzer) areCheckRunsPassing(checkRuns []*github.CheckRun) bool {
	if len(checkRuns) == 0 {
		return true
	}

	for _, check := range checkRuns {
		if check.Status == nil {
			continue
		}

		// Skip if check is still in progress
		if *check.Status == "in_progress" || *check.Status == "queued" {
			continue
		}

		// Check if the conclusion indicates failure
		if *check.Status == "completed" && check.Conclusion != nil {
			if *check.Conclusion != "success" && *check.Conclusion != "neutral" && *check.Conclusion != "skipped" {
				return false
			}
		}
	}

	return true
}

// getFailingCheckRuns returns details about failing check runs
func (a *Analyzer) getFailingCheckRuns(checkRuns []*github.CheckRun) []string {
	var failing []string
	var pending []string

	for _, check := range checkRuns {
		if check.Name == nil {
			continue
		}

		if check.Status != nil && (*check.Status == "in_progress" || *check.Status == "queued") {
			pending = append(pending, *check.Name)
			continue
		}

		if check.Status != nil && *check.Status == "completed" && check.Conclusion != nil {
			if *check.Conclusion != "success" && *check.Conclusion != "neutral" && *check.Conclusion != "skipped" {
				detail := fmt.Sprintf("%s (%s)", *check.Name, *check.Conclusion)
				if check.Output != nil && check.Output.Title != nil {
					detail = fmt.Sprintf("%s: %s", *check.Name, *check.Output.Title)
				}
				failing = append(failing, detail)
			}
		}
	}

	if len(pending) > 0 {
		failing = append(failing, fmt.Sprintf("Pending checks: %s", strings.Join(pending, ", ")))
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
func (a *Analyzer) analyzeWithGemini(ctx context.Context, pr *github.PullRequest, files []*github.CommitFile) (*gemini.AnalysisResult, error) {
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

	// Build PR context
	prContext := gemini.PRContext{
		Title:       pr.GetTitle(),
		Description: pr.GetBody(),
		Author:      pr.GetUser().GetLogin(),
	}

	// Add author association if available
	if pr.AuthorAssociation != nil {
		prContext.AuthorAssociation = *pr.AuthorAssociation
	}

	// Extract org and repo from base
	if pr.Base != nil && pr.Base.Repo != nil {
		if pr.Base.Repo.Owner != nil {
			prContext.Organization = pr.Base.Repo.Owner.GetLogin()
		}
		prContext.Repository = pr.Base.Repo.GetName()
		prContext.PullRequestNumber = pr.GetNumber()
		prContext.URL = fmt.Sprintf("https://github.com/%s/%s/pull/%d",
			prContext.Organization, prContext.Repository, prContext.PullRequestNumber)
	}

	return a.gemini.AnalyzePRChanges(ctx, changes, prContext)
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

// isDependabotPR checks if the PR is from dependabot
func (a *Analyzer) isDependabotPR(pr *github.PullRequest) bool {
	if pr.User == nil {
		return false
	}
	login := pr.User.GetLogin()
	return login == "dependabot[bot]" || login == "dependabot"
}

// checkPRAge checks if the PR meets age requirements
func (a *Analyzer) checkPRAge(pr *github.PullRequest) string {
	var lastActivity time.Time
	if pr.UpdatedAt != nil {
		lastActivity = pr.UpdatedAt.Time
	} else if pr.CreatedAt != nil {
		lastActivity = pr.CreatedAt.Time
	}

	if lastActivity.IsZero() {
		return ""
	}

	prAge := time.Since(lastActivity)

	if a.config.MinOpenTime > 0 && prAge < a.config.MinOpenTime {
		return fmt.Sprintf("PR updated too recently (last push: %v ago, required: %v)",
			prAge.Round(time.Minute), a.config.MinOpenTime)
	}

	if a.config.MaxOpenTime > 0 && prAge > a.config.MaxOpenTime {
		return fmt.Sprintf("PR has been stale too long (last push: %v ago, max: %v)",
			prAge.Round(time.Hour), a.config.MaxOpenTime)
	}

	return ""
}

// formatPRDetails formats PR details for output
func (a *Analyzer) formatPRDetails(pr *github.PullRequest) []string {
	var details []string

	// Add author information
	if pr.User != nil {
		authorInfo := fmt.Sprintf("Author: %s", pr.User.GetLogin())
		if pr.AuthorAssociation != nil {
			authorInfo += fmt.Sprintf(" (%s)", *pr.AuthorAssociation)
		}
		details = append(details, authorInfo)
	}

	// Add last push time
	var lastActivity time.Time
	if pr.UpdatedAt != nil {
		lastActivity = pr.UpdatedAt.Time
	} else if pr.CreatedAt != nil {
		lastActivity = pr.CreatedAt.Time
	}

	if !lastActivity.IsZero() {
		lastPushAge := time.Since(lastActivity)
		details = append(details, fmt.Sprintf("Last push: %v ago", lastPushAge.Round(time.Minute)))
	}

	return details
}
