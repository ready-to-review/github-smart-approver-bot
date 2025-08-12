// Package constants defines shared constants for the trivial-auto-approve application.
package constants

import "time"

// Default configuration values.
const (
	// DefaultMaxFiles is the default maximum number of files for auto-approval.
	DefaultMaxFiles = 5

	// DefaultMaxLines is the default maximum number of lines for auto-approval.
	DefaultMaxLines = 125

	// DefaultPollingInterval is the default interval for polling mode.
	DefaultPollingInterval = time.Hour

	// GitHubAPIPageSize is the number of items per page for GitHub API requests.
	GitHubAPIPageSize = 100

	// MaxRetryAttempts is the maximum number of retry attempts for API calls.
	MaxRetryAttempts = 10

	// DefaultMinOpenTime is the default minimum time a PR must be open.
	DefaultMinOpenTime = 4 * time.Hour

	// DefaultMaxOpenTime is the default maximum time a PR can be open.
	DefaultMaxOpenTime = 90 * 24 * time.Hour
)

// Author associations that indicate write access.
const (
	AuthorAssociationOwner                = "OWNER"
	AuthorAssociationMember               = "MEMBER"
	AuthorAssociationCollaborator         = "COLLABORATOR"
	AuthorAssociationFirstTimeContributor = "FIRST_TIME_CONTRIBUTOR"
)

// PR states.
const (
	PRStateOpen   = "open"
	PRStateClosed = "closed"
	PRStateMerged = "merged"
)

// Review states.
const (
	ReviewStateApproved         = "APPROVED"
	ReviewStateChangesRequested = "CHANGES_REQUESTED"
	ReviewStateCommented        = "COMMENTED"
)

// Review events (for creating reviews).
const (
	ReviewEventApprove        = "APPROVE"
	ReviewEventRequestChanges = "REQUEST_CHANGES"
	ReviewEventComment        = "COMMENT"
)

// Check states.
const (
	CheckStateSuccess = "success"
	CheckStatePending = "pending"
	CheckStateFailure = "failure"
	CheckStateError   = "error"
)
