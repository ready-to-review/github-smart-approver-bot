package github

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

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
}

// NewClient creates a new GitHub client using the gh CLI token.
func NewClient(ctx context.Context) (*Client, error) {
	token, err := getGHToken()
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

// ensure Client implements API interface
var _ API = (*Client)(nil)

// GetAuthenticatedUser retrieves the currently authenticated user.
func (c *Client) GetAuthenticatedUser(ctx context.Context) (*github.User, error) {
	user, _, err := c.client.Users.Get(ctx, "")
	if err != nil {
		return nil, &errors.APIError{
			Service: "GitHub",
			Method:  "Users.Get",
			Err:     err,
		}
	}
	return user, nil
}

// getGHToken retrieves the GitHub token using gh CLI.
func getGHToken() (string, error) {
	cmd := exec.Command("gh", "auth", "token")
	out, err := cmd.Output()
	if err != nil {
		return "", &errors.APIError{
			Service: "gh CLI",
			Method:  "auth token",
			Err:     err,
		}
	}

	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", errors.ErrNoGitHubToken
	}

	return token, nil
}

// GetPullRequest retrieves a pull request by owner, repo, and number.
func (c *Client) GetPullRequest(ctx context.Context, owner, repo string, number int) (*github.PullRequest, error) {
	var pr *github.PullRequest
	err := retry.Do(ctx, 10, func() error {
		var err error
		pr, _, err = c.client.PullRequests.Get(ctx, owner, repo, number)
		if err != nil && retry.IsRetryable(err) {
			return err
		} else if err != nil {
			// Non-retryable error, wrap and return
			return &errors.APIError{
				Service: "GitHub",
				Method:  fmt.Sprintf("GetPullRequest %s/%s#%d", owner, repo, number),
				Err:     err,
			}
		}
		return nil
	})
	return pr, err
}

// ListOrgPullRequests lists all open pull requests for an organization or user.
// Note: This uses the Search API which returns limited PR data. The analyzer
// will need to fetch full PR details when needed.
func (c *Client) ListOrgPullRequests(ctx context.Context, org string) ([]*github.PullRequest, error) {
	// First, check if this is an organization or a user
	user, _, err := c.client.Users.Get(ctx, org)
	if err != nil {
		return nil, &errors.APIError{
			Service: "GitHub",
			Method:  "Users.Get",
			Err:     err,
		}
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
			return nil, &errors.APIError{
				Service: "GitHub",
				Method:  "Search.Issues",
				Err:     err,
			}
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

// GetPullRequestFiles retrieves the files changed in a pull request.
func (c *Client) GetPullRequestFiles(ctx context.Context, owner, repo string, number int) ([]*github.CommitFile, error) {
	opt := &github.ListOptions{PerPage: constants.GitHubAPIPageSize}
	var allFiles []*github.CommitFile

	for {
		files, resp, err := c.client.PullRequests.ListFiles(ctx, owner, repo, number, opt)
		if err != nil {
			return nil, &errors.APIError{
				Service: "GitHub",
				Method:  "PullRequests.ListFiles",
				Err:     err,
			}
		}

		allFiles = append(allFiles, files...)

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allFiles, nil
}

// GetCombinedStatus retrieves the combined status for a PR.
func (c *Client) GetCombinedStatus(ctx context.Context, owner, repo, ref string) (*github.CombinedStatus, error) {
	var status *github.CombinedStatus
	err := retry.Do(ctx, 10, func() error {
		var err error
		status, _, err = c.client.Repositories.GetCombinedStatus(ctx, owner, repo, ref, nil)
		if err != nil && retry.IsRetryable(err) {
			return err
		} else if err != nil {
			return &errors.APIError{
				Service: "GitHub",
				Method:  "Repositories.GetCombinedStatus",
				Err:     err,
			}
		}
		return nil
	})
	return status, err
}

// ListCheckRunsForRef lists all check runs for a specific git ref.
func (c *Client) ListCheckRunsForRef(ctx context.Context, owner, repo, ref string) ([]*github.CheckRun, error) {
	opt := &github.ListCheckRunsOptions{
		ListOptions: github.ListOptions{
			PerPage: constants.GitHubAPIPageSize,
		},
	}

	var allCheckRuns []*github.CheckRun
	for {
		result, resp, err := c.client.Checks.ListCheckRunsForRef(ctx, owner, repo, ref, opt)
		if err != nil {
			return nil, &errors.APIError{
				Service: "GitHub",
				Method:  "Checks.ListCheckRunsForRef",
				Err:     err,
			}
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
	review := &github.PullRequestReviewRequest{
		Body:  github.String(body),
		Event: github.String(constants.ReviewEventApprove),
	}

	_, _, err := c.client.PullRequests.CreateReview(ctx, owner, repo, number, review)
	if err != nil {
		return &errors.APIError{
			Service: "GitHub",
			Method:  "PullRequests.CreateReview",
			Err:     err,
		}
	}

	return nil
}

// EnableAutoMerge enables auto-merge for a pull request.
func (c *Client) EnableAutoMerge(ctx context.Context, owner, repo string, number int) error {
	// First, get the PR to check if auto-merge is already enabled
	pr, err := c.GetPullRequest(ctx, owner, repo, number)
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
		return fmt.Errorf("pr node ID not available")
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
		return &errors.APIError{
			Service: "GitHub GraphQL",
			Method:  "enablePullRequestAutoMerge",
			Err:     err,
		}
	}

	return nil
}

// MergePullRequest merges a pull request.
func (c *Client) MergePullRequest(ctx context.Context, owner, repo string, number int) error {
	mergeOpts := &github.PullRequestOptions{
		MergeMethod: "squash",
	}

	_, _, err := c.client.PullRequests.Merge(ctx, owner, repo, number, "", mergeOpts)
	if err != nil {
		return &errors.APIError{
			Service: "GitHub",
			Method:  "PullRequests.Merge",
			Err:     err,
		}
	}

	return nil
}

// ListReviews lists all reviews for a pull request.
func (c *Client) ListReviews(ctx context.Context, owner, repo string, number int) ([]*github.PullRequestReview, error) {
	opt := &github.ListOptions{PerPage: constants.GitHubAPIPageSize}
	var allReviews []*github.PullRequestReview

	for {
		reviews, resp, err := c.client.PullRequests.ListReviews(ctx, owner, repo, number, opt)
		if err != nil {
			return nil, &errors.APIError{
				Service: "GitHub",
				Method:  "PullRequests.ListReviews",
				Err:     err,
			}
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
	opt := &github.IssueListCommentsOptions{
		ListOptions: github.ListOptions{PerPage: constants.GitHubAPIPageSize},
	}
	var allComments []*github.IssueComment

	for {
		comments, resp, err := c.client.Issues.ListComments(ctx, owner, repo, number, opt)
		if err != nil {
			return nil, &errors.APIError{
				Service: "GitHub",
				Method:  "Issues.ListComments",
				Err:     err,
			}
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
	opt := &github.PullRequestListCommentsOptions{
		ListOptions: github.ListOptions{PerPage: constants.GitHubAPIPageSize},
	}
	var allComments []*github.PullRequestComment

	for {
		comments, resp, err := c.client.PullRequests.ListComments(ctx, owner, repo, number, opt)
		if err != nil {
			return nil, &errors.APIError{
				Service: "GitHub",
				Method:  "PullRequests.ListComments",
				Err:     err,
			}
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
	opt := &github.PullRequestListOptions{
		State: constants.PRStateOpen,
		ListOptions: github.ListOptions{
			PerPage: constants.GitHubAPIPageSize,
		},
	}

	var allPRs []*github.PullRequest
	for {
		prs, resp, err := c.client.PullRequests.List(ctx, owner, repo, opt)
		if err != nil {
			return nil, &errors.APIError{
				Service: "GitHub",
				Method:  "PullRequests.List",
				Err:     err,
			}
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
	// First, get the PR to check if it needs updating
	pr, err := c.GetPullRequest(ctx, owner, repo, number)
	if err != nil {
		return fmt.Errorf("getting PR for branch update: %w", err)
	}

	// Check if the branch is already up to date
	if pr.GetMergeableState() == "clean" || pr.GetMergeableState() == "unstable" {
		// Branch is already up to date or only has non-blocking checks failing
		return errors.ErrBranchUpToDate
	}

	// Update the branch using the GitHub API
	_, _, err = c.client.PullRequests.UpdateBranch(ctx, owner, repo, number, nil)
	if err != nil {
		// Check if the error indicates the branch is already up to date
		if strings.Contains(err.Error(), "already up to date") {
			return errors.ErrBranchUpToDate
		}
		return &errors.APIError{
			Service: "GitHub",
			Method:  "PullRequests.UpdateBranch",
			Err:     err,
		}
	}

	return nil
}

// ParsePullRequestURL parses a GitHub PR URL and returns owner, repo, and number.
// It supports two formats:
//   - https://github.com/owner/repo/pull/123
//   - owner/repo#123
func ParsePullRequestURL(url string) (owner, repo string, number int, err error) {
	if url == "" {
		return "", "", 0, &errors.ValidationError{
			Field: "url",
			Value: url,
			Msg:   "empty URL",
		}
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
			return "", "", 0, &errors.ValidationError{
				Field: "url",
				Value: parts[6],
				Msg:   "invalid PR number",
			}
		}
	} else if strings.Contains(url, "#") {
		parts := strings.Split(url, "#")
		if len(parts) != 2 {
			return "", "", 0, errors.ErrInvalidPRURL
		}

		repoParts := strings.Split(parts[0], "/")
		if len(repoParts) != 2 {
			return "", "", 0, &errors.ValidationError{
				Field: "url",
				Value: url,
				Msg:   "expected owner/repo format",
			}
		}

		owner = repoParts[0]
		repo = repoParts[1]
		_, err = fmt.Sscanf(parts[1], "%d", &number)
		if err != nil {
			return "", "", 0, &errors.ValidationError{
				Field: "url",
				Value: parts[1],
				Msg:   "invalid PR number",
			}
		}
	} else {
		return "", "", 0, errors.ErrInvalidPRURL
	}

	return owner, repo, number, nil
}
