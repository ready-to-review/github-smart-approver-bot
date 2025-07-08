// Package github provides interfaces and implementations for GitHub API operations.
package github

import (
	"context"
	
	"github.com/google/go-github/v68/github"
)

// API defines the interface for GitHub API operations.
// This interface enables testing by allowing mock implementations.
type API interface {
	// GetPullRequest retrieves a pull request by owner, repo, and number.
	GetPullRequest(ctx context.Context, owner, repo string, number int) (*github.PullRequest, error)
	
	// ListOrgPullRequests lists all open pull requests for an organization.
	ListOrgPullRequests(ctx context.Context, org string) ([]*github.PullRequest, error)
	
	// ListRepoPullRequests lists all open pull requests for a repository.
	ListRepoPullRequests(ctx context.Context, owner, repo string) ([]*github.PullRequest, error)
	
	// GetPullRequestFiles retrieves the files changed in a pull request.
	GetPullRequestFiles(ctx context.Context, owner, repo string, number int) ([]*github.CommitFile, error)
	
	// GetCombinedStatus retrieves the combined status for a PR.
	GetCombinedStatus(ctx context.Context, owner, repo, ref string) (*github.CombinedStatus, error)
	
	// IsFirstTimeContributor checks if the PR author is a first-time contributor.
	IsFirstTimeContributor(ctx context.Context, owner, repo, author string) (bool, error)
	
	// ListReviews lists all reviews for a pull request.
	ListReviews(ctx context.Context, owner, repo string, number int) ([]*github.PullRequestReview, error)
	
	// ListIssueComments lists all issue comments for a pull request.
	ListIssueComments(ctx context.Context, owner, repo string, number int) ([]*github.IssueComment, error)
	
	// ListPullRequestComments lists all PR review comments for a pull request.
	ListPullRequestComments(ctx context.Context, owner, repo string, number int) ([]*github.PullRequestComment, error)
	
	// ApprovePullRequest approves a pull request.
	ApprovePullRequest(ctx context.Context, owner, repo string, number int, body string) error
	
	// MergePullRequest merges a pull request.
	MergePullRequest(ctx context.Context, owner, repo string, number int) error
}