package github

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/google/go-github/v68/github"
	"github.com/thegroove/trivial-auto-approve/internal/constants"
	"github.com/thegroove/trivial-auto-approve/internal/errors"
	"golang.org/x/oauth2"
)

// Client implements the API interface for GitHub operations.
type Client struct {
	client *github.Client
}

// NewClient creates a new GitHub client using the gh CLI token.
func NewClient(ctx context.Context) (*Client, error) {
	token, err := getGHToken()
	if err != nil {
		return nil, fmt.Errorf("getting gh token: %w", err)
	}

	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)

	return &Client{
		client: github.NewClient(tc),
	}, nil
}

// ensure Client implements API interface
var _ API = (*Client)(nil)

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
	pr, _, err := c.client.PullRequests.Get(ctx, owner, repo, number)
	if err != nil {
		return nil, fmt.Errorf("getting PR %s/%s#%d: %w", owner, repo, number, err)
	}
	return pr, nil
}

// ListOrgPullRequests lists all open pull requests for an organization.
func (c *Client) ListOrgPullRequests(ctx context.Context, org string) ([]*github.PullRequest, error) {
	opt := &github.SearchOptions{
		ListOptions: github.ListOptions{
			PerPage: constants.GitHubAPIPageSize,
		},
	}

	var allPRs []*github.PullRequest
	query := fmt.Sprintf("org:%s is:pr is:open", org)
	
	for {
		result, resp, err := c.client.Search.Issues(ctx, query, opt)
		if err != nil {
			return nil, fmt.Errorf("searching PRs: %w", err)
		}

		for _, issue := range result.Issues {
			if issue.PullRequestLinks != nil {
				parts := strings.Split(*issue.PullRequestLinks.URL, "/")
				if len(parts) >= 4 {
					owner := parts[len(parts)-4]
					repo := parts[len(parts)-3]
					number := *issue.Number
					
					pr, err := c.GetPullRequest(ctx, owner, repo, number)
					if err != nil {
						return nil, err
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
			return nil, fmt.Errorf("listing PR files: %w", err)
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
	status, _, err := c.client.Repositories.GetCombinedStatus(ctx, owner, repo, ref, nil)
	if err != nil {
		return nil, fmt.Errorf("getting combined status: %w", err)
	}
	return status, nil
}

// IsFirstTimeContributor checks if the PR author is a first-time contributor.
func (c *Client) IsFirstTimeContributor(ctx context.Context, owner, repo, author string) (bool, error) {
	query := fmt.Sprintf("repo:%s/%s author:%s is:pr", owner, repo, author)
	result, _, err := c.client.Search.Issues(ctx, query, nil)
	if err != nil {
		return false, fmt.Errorf("searching contributor PRs: %w", err)
	}
	
	// If they have only 1 PR (the current one), they're a first-timer
	return result.GetTotal() <= 1, nil
}

// ApprovePullRequest approves a pull request.
func (c *Client) ApprovePullRequest(ctx context.Context, owner, repo string, number int, body string) error {
	review := &github.PullRequestReviewRequest{
		Body:  github.String(body),
		Event: github.String(constants.ReviewStateApproved),
	}
	
	_, _, err := c.client.PullRequests.CreateReview(ctx, owner, repo, number, review)
	if err != nil {
		return fmt.Errorf("creating review: %w", err)
	}
	
	return nil
}

// MergePullRequest merges a pull request.
func (c *Client) MergePullRequest(ctx context.Context, owner, repo string, number int) error {
	options := &github.PullRequestOptions{
		MergeMethod: constants.MergeMethodSquash,
	}
	
	_, _, err := c.client.PullRequests.Merge(ctx, owner, repo, number, "", options)
	if err != nil {
		return fmt.Errorf("merging PR: %w", err)
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
			return nil, fmt.Errorf("listing reviews: %w", err)
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
			return nil, fmt.Errorf("listing issue comments: %w", err)
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
			return nil, fmt.Errorf("listing PR comments: %w", err)
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
			return nil, fmt.Errorf("listing repo PRs: %w", err)
		}
		
		allPRs = append(allPRs, prs...)
		
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	
	return allPRs, nil
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
			return "", "", 0, fmt.Errorf("parsing PR number: %w", err)
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
			return "", "", 0, fmt.Errorf("parsing PR number: %w", err)
		}
	} else {
		return "", "", 0, errors.ErrInvalidPRURL
	}
	
	return owner, repo, number, nil
}