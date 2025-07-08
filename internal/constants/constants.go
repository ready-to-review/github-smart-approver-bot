// Package constants defines shared constants for the trivial-auto-approve application.
package constants

import "time"

// Default configuration values
const (
	// DefaultMaxFiles is the default maximum number of files for auto-approval.
	DefaultMaxFiles = 5
	
	// DefaultPollingInterval is the default interval for polling mode.
	DefaultPollingInterval = time.Hour
	
	// GitHubAPIPageSize is the number of items per page for GitHub API requests.
	GitHubAPIPageSize = 100
)

// Author associations that indicate write access
const (
	AuthorAssociationOwner        = "OWNER"
	AuthorAssociationMember       = "MEMBER"
	AuthorAssociationCollaborator = "COLLABORATOR"
)

// PR states
const (
	PRStateOpen   = "open"
	PRStateClosed = "closed"
	PRStateMerged = "merged"
)

// Review states
const (
	ReviewStateApproved         = "APPROVED"
	ReviewStateChangesRequested = "CHANGES_REQUESTED"
	ReviewStateCommented        = "COMMENTED"
)

// Check states
const (
	CheckStateSuccess = "success"
	CheckStatePending = "pending"
	CheckStateFailure = "failure"
	CheckStateError   = "error"
)

// Merge methods
const (
	MergeMethodSquash = "squash"
	MergeMethodMerge  = "merge"
	MergeMethodRebase = "rebase"
)