package github

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/google/go-github/v68/github"
	"github.com/shurcooL/githubv4"
	"github.com/thegroove/trivial-auto-approve/internal/constants"
	"github.com/thegroove/trivial-auto-approve/internal/errors"
	"github.com/thegroove/trivial-auto-approve/internal/retry"
	"golang.org/x/oauth2"
)

// Client implements the API interface for GitHub operations.
type Client struct {
	client   *github.Client
	clientV4 *githubv4.Client
	appAuth  *AppAuth // Optional: set when using GitHub App authentication
}

// NewClient creates a new GitHub client using the gh CLI token.
func NewClient(ctx context.Context) (*Client, error) {
	token, err := getGHToken(ctx)
	if err != nil {
		return nil, err
	}

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)

	return &Client{
		client:   github.NewClient(tc),
		clientV4: githubv4.NewClient(tc),
	}, nil
}

// ensure Client implements API interface.
var _ API = (*Client)(nil)

// AuthenticatedUser retrieves the currently authenticated user.
func (c *Client) AuthenticatedUser(ctx context.Context) (*github.User, error) {
	user, _, err := c.client.Users.Get(ctx, "")
	if err != nil {
		return nil, errors.API("GitHub", "Users.Get", err)
	}
	return user, nil
}

// getGHToken retrieves the GitHub token using gh CLI.
func getGHToken(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "gh", "auth", "token")
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("gh auth token timed out: %w", ctx.Err())
		}
		return "", errors.API("gh CLI", "auth token", err)
	}

	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", errors.ErrNoGitHubToken
	}

	return token, nil
}

// withTimeout wraps a context with a timeout for API calls.
func withTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok {
		// If parent context already has a deadline, use the earlier one
		if time.Until(deadline) < timeout {
			return ctx, func() {} // no-op cancel
		}
	}
	return context.WithTimeout(ctx, timeout)
}

// PullRequest retrieves a pull request by owner, repo, and number.
func (c *Client) PullRequest(ctx context.Context, owner, repo string, number int) (*github.PullRequest, error) {
	// Input validation
	if owner == "" || repo == "" {
		return nil, fmt.Errorf("owner and repo cannot be empty")
	}
	if number <= 0 {
		return nil, fmt.Errorf("invalid PR number: %d", number)
	}
	
	// Add timeout for this operation
	ctx, cancel := withTimeout(ctx, 30*time.Second)
	defer cancel()

	var pr *github.PullRequest
	err := retry.Do(ctx, constants.MaxRetryAttempts, retry.WithRetryableCheck(
		func() error {
			var err error
			pr, _, err = c.client.PullRequests.Get(ctx, owner, repo, number)
			return err
		},
		func(err error) error {
			return errors.API("GitHub", fmt.Sprintf("PullRequest %s/%s#%d", owner, repo, number), err)
		},
	))
	if err != nil {
		return pr, fmt.Errorf("failed to get pull request after retries: %w", err)
	}
	return pr, nil
}

// ListOrgPullRequests lists all open pull requests for an organization or user.
// Note: This uses the Search API which returns limited PR data. The analyzer
// will need to fetch full PR details when needed.
func (c *Client) ListOrgPullRequests(ctx context.Context, org string) ([]*github.PullRequest, error) {
	// Add timeout for this potentially long operation
	ctx, cancel := withTimeout(ctx, 2*time.Minute)
	defer cancel()

	// First, check if this is an organization or a user
	user, _, err := c.client.Users.Get(ctx, org)
	if err != nil {
		return nil, errors.API("GitHub", "Users.Get", err)
	}

	opt := &github.SearchOptions{
		ListOptions: github.ListOptions{
			PerPage: constants.GitHubAPIPageSize,
		},
	}

	var allPRs []*github.PullRequest
	// Use appropriate search qualifier based on account type
	var query string
	if user.GetType() == "Organization" {
		query = fmt.Sprintf("org:%s is:pr is:open", org)
	} else {
		query = fmt.Sprintf("user:%s is:pr is:open", org)
	}

	for {
		result, resp, err := c.client.Search.Issues(ctx, query, opt)
		if err != nil {
			return nil, errors.API("GitHub", "Search.Issues", err)
		}

		// Convert search results to minimal PR objects
		// This avoids N additional API calls
		for _, issue := range result.Issues {
			if issue.PullRequestLinks != nil && issue.RepositoryURL != nil {
				// Parse repository URL to get owner and repo name
				// Format: https://api.github.com/repos/OWNER/REPO
				parts := strings.Split(*issue.RepositoryURL, "/")
				if len(parts) >= 2 {
					owner := parts[len(parts)-2]
					repo := parts[len(parts)-1]

					pr := &github.PullRequest{
						Number:    issue.Number,
						State:     issue.State,
						Title:     issue.Title,
						Body:      issue.Body,
						CreatedAt: issue.CreatedAt,
						UpdatedAt: issue.UpdatedAt,
						User:      issue.User,
						Draft:     issue.Draft,
						Base: &github.PullRequestBranch{
							Repo: &github.Repository{
								Name: github.String(repo),
								Owner: &github.User{
									Login: github.String(owner),
								},
							},
						},
					}
					allPRs = append(allPRs, pr)
				}
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allPRs, nil
}

// PullRequestFiles retrieves the files changed in a pull request.
func (c *Client) PullRequestFiles(ctx context.Context, owner, repo string, number int) ([]*github.CommitFile, error) {
	// Add timeout for this operation
	ctx, cancel := withTimeout(ctx, 1*time.Minute)
	defer cancel()

	opt := &github.ListOptions{PerPage: constants.GitHubAPIPageSize}
	var allFiles []*github.CommitFile

	for {
		var files []*github.CommitFile
		var resp *github.Response
		err := retry.Do(ctx, constants.MaxRetryAttempts, retry.WithRetryableCheck(
			func() error {
				var err error
				files, resp, err = c.client.PullRequests.ListFiles(ctx, owner, repo, number, opt)
				return err
			},
			func(err error) error {
				return errors.API("GitHub", "PullRequests.ListFiles", err)
			},
		))
		if err != nil {
			return nil, fmt.Errorf("failed to list PR files after retries: %w", err)
		}

		allFiles = append(allFiles, files...)

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allFiles, nil
}

// CombinedStatus retrieves the combined status for a PR.
func (c *Client) CombinedStatus(ctx context.Context, owner, repo, ref string) (*github.CombinedStatus, error) {
	var status *github.CombinedStatus
	err := retry.Do(ctx, constants.MaxRetryAttempts, retry.WithRetryableCheck(
		func() error {
			var err error
			status, _, err = c.client.Repositories.GetCombinedStatus(ctx, owner, repo, ref, nil)
			return err
		},
		func(err error) error {
			return errors.API("GitHub", "Repositories.GetCombinedStatus", err)
		},
	))
	return status, err
}

// ListCheckRunsForRef lists all check runs for a specific git ref.
func (c *Client) ListCheckRunsForRef(ctx context.Context, owner, repo, ref string) ([]*github.CheckRun, error) {
	// Add timeout for this operation
	ctx, cancel := withTimeout(ctx, 1*time.Minute)
	defer cancel()

	opt := &github.ListCheckRunsOptions{
		ListOptions: github.ListOptions{
			PerPage: constants.GitHubAPIPageSize,
		},
	}

	var allCheckRuns []*github.CheckRun
	for {
		var result *github.ListCheckRunsResults
		var resp *github.Response
		err := retry.Do(ctx, constants.MaxRetryAttempts, retry.WithRetryableCheck(
			func() error {
				var err error
				result, resp, err = c.client.Checks.ListCheckRunsForRef(ctx, owner, repo, ref, opt)
				return err
			},
			func(err error) error {
				return errors.API("GitHub", "Checks.ListCheckRunsForRef", err)
			},
		))
		if err != nil {
			return nil, fmt.Errorf("failed to list check runs after retries: %w", err)
		}

		if result != nil && result.CheckRuns != nil {
			allCheckRuns = append(allCheckRuns, result.CheckRuns...)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allCheckRuns, nil
}

// ApprovePullRequest approves a pull request.
func (c *Client) ApprovePullRequest(ctx context.Context, owner, repo string, number int, body string) error {
	// Add timeout for this operation
	ctx, cancel := withTimeout(ctx, 30*time.Second)
	defer cancel()

	review := &github.PullRequestReviewRequest{
		Body:  github.String(body),
		Event: github.String(constants.ReviewEventApprove),
	}

	err := retry.Do(ctx, constants.MaxRetryAttempts, retry.WithRetryableCheck(
		func() error {
			_, _, err := c.client.PullRequests.CreateReview(ctx, owner, repo, number, review)
			return err
		},
		func(err error) error {
			return errors.API("GitHub", "PullRequests.CreateReview", err)
		},
	))
	if err != nil {
		return fmt.Errorf("failed to approve PR after retries: %w", err)
	}

	return nil
}

// EnableAutoMerge enables auto-merge for a pull request.
func (c *Client) EnableAutoMerge(ctx context.Context, owner, repo string, number int) error {
	// First, get the PR to check if auto-merge is already enabled
	pr, err := c.PullRequest(ctx, owner, repo, number)
	if err != nil {
		return fmt.Errorf("getting PR for auto-merge: %w", err)
	}

	// Check if auto-merge is already enabled
	if pr.AutoMerge != nil {
		// Auto-merge is already enabled
		return nil
	}

	// Check if PR is already mergeable
	if pr.GetMergeableState() == "clean" {
		// PR is ready to merge now - auto-merge isn't needed
		return errors.ErrPRReadyToMerge
	}

	// Get the PR node ID for GraphQL
	if pr.NodeID == nil {
		return fmt.Errorf("GitHub PR missing node ID required for GraphQL operations (owner=%s, repo=%s, number=%d)", owner, repo, number)
	}

	// GraphQL mutation to enable auto-merge
	var mutation struct {
		EnablePullRequestAutoMerge struct {
			PullRequest struct {
				ID githubv4.ID
			}
		} `graphql:"enablePullRequestAutoMerge(input: $input)"`
	}

	mergeMethod := githubv4.PullRequestMergeMethodSquash
	input := githubv4.EnablePullRequestAutoMergeInput{
		PullRequestID: githubv4.ID(*pr.NodeID),
		MergeMethod:   &mergeMethod,
	}

	err = c.clientV4.Mutate(ctx, &mutation, input, nil)
	if err != nil {
		// Check for specific error about PR being in clean status
		errStr := err.Error()
		if strings.Contains(errStr, "Pull request is in clean status") {
			return errors.ErrPRReadyToMerge
		}
		return errors.API("GitHub GraphQL", "enablePullRequestAutoMerge", err)
	}

	return nil
}

// GetUserPermissionLevel gets a user's permission level for a repository
func (c *Client) GetUserPermissionLevel(ctx context.Context, owner, repo, username string) (string, error) {
	// Add timeout for this operation
	ctx, cancel := withTimeout(ctx, 10*time.Second)
	defer cancel()

	var permission string
	err := retry.Do(ctx, constants.MaxRetryAttempts, retry.WithRetryableCheck(
		func() error {
			// Use GitHub API to get repository permissions for user
			perm, _, err := c.client.Repositories.GetPermissionLevel(ctx, owner, repo, username)
			if err != nil {
				return err
			}
			
			if perm == nil || perm.Permission == nil {
				return fmt.Errorf("no permission data returned")
			}
			
			permission = *perm.Permission
			return nil
		},
		func(err error) error {
			return errors.API("GitHub", "GetPermissionLevel", err)
		},
	))
	
	if err != nil {
		return "", errors.API("GitHub", fmt.Sprintf("GetPermissionLevel(%s/%s, %s)", owner, repo, username), err)
	}
	
	return permission, nil
}

// MergePullRequest merges a pull request.
func (c *Client) MergePullRequest(ctx context.Context, owner, repo string, number int) error {
	// Add timeout for this operation
	ctx, cancel := withTimeout(ctx, 30*time.Second)
	defer cancel()

	mergeOpts := &github.PullRequestOptions{
		MergeMethod: "squash",
	}

	err := retry.Do(ctx, constants.MaxRetryAttempts, retry.WithRetryableCheck(
		func() error {
			_, _, err := c.client.PullRequests.Merge(ctx, owner, repo, number, "", mergeOpts)
			return err
		},
		func(err error) error {
			return errors.API("GitHub", "PullRequests.Merge", err)
		},
	))
	if err != nil {
		return fmt.Errorf("failed to merge PR after retries: %w", err)
	}

	return nil
}

// ListReviews lists all reviews for a pull request.
func (c *Client) ListReviews(ctx context.Context, owner, repo string, number int) ([]*github.PullRequestReview, error) {
	// Add timeout for this operation
	ctx, cancel := withTimeout(ctx, 1*time.Minute)
	defer cancel()

	opt := &github.ListOptions{PerPage: constants.GitHubAPIPageSize}
	var allReviews []*github.PullRequestReview

	for {
		var reviews []*github.PullRequestReview
		var resp *github.Response
		err := retry.Do(ctx, constants.MaxRetryAttempts, retry.WithRetryableCheck(
			func() error {
				var err error
				reviews, resp, err = c.client.PullRequests.ListReviews(ctx, owner, repo, number, opt)
				return err
			},
			func(err error) error {
				return errors.API("GitHub", "PullRequests.ListReviews", err)
			},
		))
		if err != nil {
			return nil, fmt.Errorf("failed to list reviews after retries: %w", err)
		}

		allReviews = append(allReviews, reviews...)

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allReviews, nil
}

// ListIssueComments lists all issue comments for a pull request.
func (c *Client) ListIssueComments(ctx context.Context, owner, repo string, number int) ([]*github.IssueComment, error) {
	// Add timeout for this operation
	ctx, cancel := withTimeout(ctx, 1*time.Minute)
	defer cancel()

	opt := &github.IssueListCommentsOptions{
		ListOptions: github.ListOptions{PerPage: constants.GitHubAPIPageSize},
	}
	var allComments []*github.IssueComment

	for {
		var comments []*github.IssueComment
		var resp *github.Response
		err := retry.Do(ctx, constants.MaxRetryAttempts, retry.WithRetryableCheck(
			func() error {
				var err error
				comments, resp, err = c.client.Issues.ListComments(ctx, owner, repo, number, opt)
				return err
			},
			func(err error) error {
				return errors.API("GitHub", "Issues.ListComments", err)
			},
		))
		if err != nil {
			return nil, fmt.Errorf("failed to list issue comments after retries: %w", err)
		}

		allComments = append(allComments, comments...)

		if resp.NextPage == 0 {
			break
		}
		opt.ListOptions.Page = resp.NextPage
	}

	return allComments, nil
}

// ListPullRequestComments lists all PR review comments for a pull request.
func (c *Client) ListPullRequestComments(ctx context.Context, owner, repo string, number int) ([]*github.PullRequestComment, error) {
	// Add timeout for this operation
	ctx, cancel := withTimeout(ctx, 1*time.Minute)
	defer cancel()

	opt := &github.PullRequestListCommentsOptions{
		ListOptions: github.ListOptions{PerPage: constants.GitHubAPIPageSize},
	}
	var allComments []*github.PullRequestComment

	for {
		var comments []*github.PullRequestComment
		var resp *github.Response
		err := retry.Do(ctx, constants.MaxRetryAttempts, retry.WithRetryableCheck(
			func() error {
				var err error
				comments, resp, err = c.client.PullRequests.ListComments(ctx, owner, repo, number, opt)
				return err
			},
			func(err error) error {
				return errors.API("GitHub", "PullRequests.ListComments", err)
			},
		))
		if err != nil {
			return nil, fmt.Errorf("failed to list PR comments after retries: %w", err)
		}

		allComments = append(allComments, comments...)

		if resp.NextPage == 0 {
			break
		}
		opt.ListOptions.Page = resp.NextPage
	}

	return allComments, nil
}

// ListRepoPullRequests lists all open pull requests for a repository.
func (c *Client) ListRepoPullRequests(ctx context.Context, owner, repo string) ([]*github.PullRequest, error) {
	// Add timeout for this operation
	ctx, cancel := withTimeout(ctx, 2*time.Minute)
	defer cancel()

	opt := &github.PullRequestListOptions{
		State: constants.PRStateOpen,
		ListOptions: github.ListOptions{
			PerPage: constants.GitHubAPIPageSize,
		},
	}

	var allPRs []*github.PullRequest
	for {
		var prs []*github.PullRequest
		var resp *github.Response
		err := retry.Do(ctx, constants.MaxRetryAttempts, retry.WithRetryableCheck(
			func() error {
				var err error
				prs, resp, err = c.client.PullRequests.List(ctx, owner, repo, opt)
				return err
			},
			func(err error) error {
				return errors.API("GitHub", "PullRequests.List", err)
			},
		))
		if err != nil {
			return nil, fmt.Errorf("failed to list repo PRs after retries: %w", err)
		}

		allPRs = append(allPRs, prs...)

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allPRs, nil
}

// UpdateBranch updates the PR branch by rebasing or merging with the base branch.
func (c *Client) UpdateBranch(ctx context.Context, owner, repo string, number int) error {
	// Add timeout for this operation
	ctx, cancel := withTimeout(ctx, 1*time.Minute)
	defer cancel()

	// First, get the PR to check if it needs updating
	pr, err := c.PullRequest(ctx, owner, repo, number)
	if err != nil {
		return fmt.Errorf("getting PR for branch update: %w", err)
	}

	// Check if the branch is already up to date
	if pr.GetMergeableState() == "clean" || pr.GetMergeableState() == "unstable" {
		// Branch is already up to date or only has non-blocking checks failing
		return errors.ErrBranchUpToDate
	}

	// Update the branch using the GitHub API with retry
	err = retry.Do(ctx, constants.MaxRetryAttempts, retry.WithRetryableCheck(
		func() error {
			_, _, err := c.client.PullRequests.UpdateBranch(ctx, owner, repo, number, nil)
			return err
		},
		func(err error) error {
			// Check if the error indicates the branch is already up to date
			if strings.Contains(err.Error(), "already up to date") {
				return errors.ErrBranchUpToDate
			}
			return errors.API("GitHub", "PullRequests.UpdateBranch", err)
		},
	))
	if err != nil {
		return fmt.Errorf("failed to update branch after retries: %w", err)
	}

	return nil
}

// ListAppInstallations lists all installations for the GitHub App.
// This method only works when using GitHub App authentication.
func (c *Client) ListAppInstallations(ctx context.Context) ([]*github.Installation, error) {
	if c.appAuth == nil {
		return nil, fmt.Errorf("ListAppInstallations requires GitHub App authentication")
	}

	return c.appAuth.ListInstallations(ctx)
}

// AppAuth returns the GitHub App authenticator if available.
func (c *Client) AppAuth() *AppAuth {
	return c.appAuth
}

// ListUserRepositories lists repositories owned by a specific user.
// This only returns repositories where the user is the owner, not repositories
// from organizations they belong to.
func (c *Client) ListUserRepositories(ctx context.Context, user string) ([]*github.Repository, error) {
	// Input validation
	if user == "" {
		return nil, fmt.Errorf("user cannot be empty")
	}

	// Add timeout for this operation
	ctx, cancel := withTimeout(ctx, 60*time.Second)
	defer cancel()

	var allRepos []*github.Repository
	opt := &github.RepositoryListOptions{
		Type:        "owner", // Only repos owned by the user
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		repos, resp, err := c.client.Repositories.List(ctx, user, opt)
		if err != nil {
			return nil, errors.API("GitHub", "Repositories.List", err)
		}

		allRepos = append(allRepos, repos...)

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allRepos, nil
}

// ListUserPullRequests lists all open pull requests for repositories owned by a specific user.
// This only includes PRs from repositories where the user is the owner.
func (c *Client) ListUserPullRequests(ctx context.Context, user string) ([]*github.PullRequest, error) {
	// Input validation
	if user == "" {
		return nil, fmt.Errorf("user cannot be empty")
	}

	// First, get all repositories owned by the user
	repos, err := c.ListUserRepositories(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("listing user repositories: %w", err)
	}
	
	log.Printf("[GITHUB] Found %d repositories for user %s", len(repos), user)

	// Add timeout for PR fetching operations
	ctx, cancel := withTimeout(ctx, 120*time.Second)
	defer cancel()

	var allPRs []*github.PullRequest

	// For each repository, list open pull requests
	// Limit to avoid overwhelming the API with too many requests
	for _, repo := range repos {
		if repo.Name == nil {
			continue
		}
		
		// Check context cancellation
		select {
		case <-ctx.Done():
			return allPRs, ctx.Err()
		default:
		}

		opt := &github.PullRequestListOptions{
			State:       "open",
			ListOptions: github.ListOptions{PerPage: 100},
		}

		for {
			prs, resp, err := c.client.PullRequests.List(ctx, user, *repo.Name, opt)
			if err != nil {
				// Skip this repo if we can't list PRs (might be disabled, archived, etc.)
				// Continue with other repos
				break
			}

			allPRs = append(allPRs, prs...)

			if resp.NextPage == 0 {
				break
			}
			opt.Page = resp.NextPage
		}
	}

	return allPRs, nil
}

// ParsePullRequestURL parses a GitHub PR URL and returns owner, repo, and number.
// It supports two formats:
//   - https://github.com/owner/repo/pull/123
//   - owner/repo#123
func ParsePullRequestURL(url string) (owner, repo string, number int, err error) {
	if url == "" {
		return "", "", 0, errors.Validation("url", url, "empty URL")
	}
	
	// Limit URL length to prevent abuse
	const maxURLLength = 500
	if len(url) > maxURLLength {
		return "", "", 0, errors.Validation("url", url, fmt.Sprintf("URL exceeds maximum length of %d", maxURLLength))
	}

	if strings.Contains(url, "github.com") {
		parts := strings.Split(url, "/")
		if len(parts) < 7 || parts[5] != "pull" {
			return "", "", 0, errors.ErrInvalidPRURL
		}
		owner = parts[3]
		repo = parts[4]
		_, err = fmt.Sscanf(parts[6], "%d", &number)
		if err != nil {
			return "", "", 0, errors.Validation("url", parts[6], "invalid PR number")
		}
	} else if strings.Contains(url, "#") {
		parts := strings.Split(url, "#")
		if len(parts) != 2 {
			return "", "", 0, errors.ErrInvalidPRURL
		}

		repoParts := strings.Split(parts[0], "/")
		if len(repoParts) != 2 {
			return "", "", 0, errors.Validation("url", url, "expected owner/repo format")
		}

		owner = repoParts[0]
		repo = repoParts[1]
		_, err = fmt.Sscanf(parts[1], "%d", &number)
		if err != nil {
			return "", "", 0, errors.Validation("url", parts[1], "invalid PR number")
		}
	} else {
		return "", "", 0, errors.ErrInvalidPRURL
	}

	// Security: Validate owner and repo names to prevent injection
	if !isValidGitHubName(owner) {
		return "", "", 0, errors.Validation("owner", owner, "invalid owner name format")
	}
	if !isValidGitHubName(repo) {
		return "", "", 0, errors.Validation("repo", repo, "invalid repository name format")
	}
	
	// Security: Validate PR number is reasonable
	if number <= 0 || number > 999999999 {
		return "", "", 0, errors.Validation("number", fmt.Sprintf("%d", number), "PR number out of valid range")
	}

	return owner, repo, number, nil
}

// isValidGitHubName validates GitHub owner/repo names according to GitHub's rules
// GitHub names can contain alphanumeric characters, hyphens, periods, and underscores
// but cannot start with a hyphen or period
func isValidGitHubName(name string) bool {
	if name == "" {
		return false
	}
	
	// Length limits based on GitHub's constraints
	if len(name) > 100 {
		return false
	}
	
	// Cannot start with hyphen or period
	if name[0] == '-' || name[0] == '.' {
		return false
	}
	
	// Check each character
	for _, char := range name {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_' || char == '.') {
			return false
		}
	}
	
	return true
}
