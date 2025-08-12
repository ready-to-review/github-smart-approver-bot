// Package github provides interfaces and implementations for GitHub API operations.
package github

import (
	"context"

	"github.com/google/go-github/v68/github"
)

// API defines the interface for GitHub API operations.
// This interface enables testing by allowing mock implementations.
type API interface {
	// AuthenticatedUser retrieves the currently authenticated user.
	AuthenticatedUser(ctx context.Context) (*github.User, error)

	// PullRequest retrieves a pull request by owner, repo, and number.
	PullRequest(ctx context.Context, owner, repo string, number int) (*github.PullRequest, error)

	// ListOrgPullRequests lists all open pull requests for an organization.
	ListOrgPullRequests(ctx context.Context, org string) ([]*github.PullRequest, error)

	// ListRepoPullRequests lists all open pull requests for a repository.
	ListRepoPullRequests(ctx context.Context, owner, repo string) ([]*github.PullRequest, error)

	// PullRequestFiles retrieves the files changed in a pull request.
	PullRequestFiles(ctx context.Context, owner, repo string, number int) ([]*github.CommitFile, error)

	// CombinedStatus retrieves the combined status for a PR.
	CombinedStatus(ctx context.Context, owner, repo, ref string) (*github.CombinedStatus, error)

	// ListCheckRunsForRef lists all check runs for a specific git ref.
	ListCheckRunsForRef(ctx context.Context, owner, repo, ref string) ([]*github.CheckRun, error)

	// ListReviews lists all reviews for a pull request.
	ListReviews(ctx context.Context, owner, repo string, number int) ([]*github.PullRequestReview, error)

	// ListIssueComments lists all issue comments for a pull request.
	ListIssueComments(ctx context.Context, owner, repo string, number int) ([]*github.IssueComment, error)

	// ListPullRequestComments lists all PR review comments for a pull request.
	ListPullRequestComments(ctx context.Context, owner, repo string, number int) ([]*github.PullRequestComment, error)

	// ApprovePullRequest approves a pull request.
	ApprovePullRequest(ctx context.Context, owner, repo string, number int, body string) error

	// EnableAutoMerge enables auto-merge for a pull request.
	EnableAutoMerge(ctx context.Context, owner, repo string, number int) error

	// MergePullRequest merges a pull request.
	MergePullRequest(ctx context.Context, owner, repo string, number int) error

	// GetUserPermissionLevel gets a user's permission level for a repository (admin, maintain, write, triage, read)
	GetUserPermissionLevel(ctx context.Context, owner, repo, username string) (string, error)

	// UpdateBranch updates the PR branch by rebasing or merging with the base branch.
	UpdateBranch(ctx context.Context, owner, repo string, number int) error

	// ListAppInstallations lists all installations for the GitHub App (only works with App authentication).
	ListAppInstallations(ctx context.Context) ([]*github.Installation, error)

	// ListUserRepositories lists repositories owned by a specific user (not org repos they have access to).
	ListUserRepositories(ctx context.Context, user string) ([]*github.Repository, error)

	// ListUserPullRequests lists all open pull requests for repositories owned by a specific user.
	ListUserPullRequests(ctx context.Context, user string) ([]*github.PullRequest, error)
}
