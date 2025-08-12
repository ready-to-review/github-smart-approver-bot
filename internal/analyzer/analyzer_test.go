package analyzer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v68/github"
	"github.com/thegroove/trivial-auto-approve/internal/constants"
	"github.com/thegroove/trivial-auto-approve/internal/gemini"
)

func TestIsStatusPassing(t *testing.T) {
	a := &Analyzer{
		config: &Config{
			IgnoreSigningChecks: true,
		},
	}

	tests := []struct {
		name   string
		status *github.CombinedStatus
		author *github.User
		want   bool
	}{
		{
			name: "success state",
			status: &github.CombinedStatus{
				State: github.String("success"),
			},
			want: true,
		},
		{
			name: "pending state",
			status: &github.CombinedStatus{
				State: github.String("pending"),
				Statuses: []*github.RepoStatus{
					{
						State:   github.String("pending"),
						Context: github.String("build"),
					},
				},
			},
			want: true, // Pending checks don't count as failures
		},
		{
			name: "failure state",
			status: &github.CombinedStatus{
				State: github.String("failure"),
				Statuses: []*github.RepoStatus{
					{
						State:   github.String("failure"),
						Context: github.String("build"),
					},
				},
			},
			want: false,
		},
		{
			name: "ignore signing check for bot",
			status: &github.CombinedStatus{
				State: github.String("failure"),
				Statuses: []*github.RepoStatus{
					{
						State:   github.String("failure"),
						Context: github.String("commit-signing"),
					},
				},
			},
			author: &github.User{
				Type: github.String("Bot"),
			},
			want: true,
		},
		{
			name: "review required check only",
			status: &github.CombinedStatus{
				State: github.String("failure"),
				Statuses: []*github.RepoStatus{
					{
						State:       github.String("failure"),
						Context:     github.String("code-review/required"),
						Description: github.String("Review required"),
					},
				},
			},
			want: true,
		},
		{
			name: "mixed failures with review required",
			status: &github.CombinedStatus{
				State: github.String("failure"),
				Statuses: []*github.RepoStatus{
					{
						State:       github.String("failure"),
						Context:     github.String("code-review/required"),
						Description: github.String("Review required"),
					},
					{
						State:   github.String("failure"),
						Context: github.String("ci/tests"),
					},
				},
			},
			want: false,
		},
		{
			name: "awaiting review check",
			status: &github.CombinedStatus{
				State: github.String("failure"),
				Statuses: []*github.RepoStatus{
					{
						State:       github.String("failure"),
						Context:     github.String("approval"),
						Description: github.String("Awaiting review from team"),
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.isStatusPassing(tt.status, tt.author); got != tt.want {
				t.Errorf("isStatusPassing() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsCollaborator(t *testing.T) {
	tests := []struct {
		association string
		want        bool
	}{
		{"OWNER", true},
		{"MEMBER", true},
		{"COLLABORATOR", true},
		{"CONTRIBUTOR", false},
		{"FIRST_TIME_CONTRIBUTOR", false},
		{"FIRST_TIMER", false},
		{"NONE", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.association, func(t *testing.T) {
			if got := isCollaborator(tt.association); got != tt.want {
				t.Errorf("isCollaborator(%q) = %v, want %v", tt.association, got, tt.want)
			}
		})
	}
}

func TestGetFailingChecks(t *testing.T) {
	a := &Analyzer{}

	status := &github.CombinedStatus{
		Statuses: []*github.RepoStatus{
			{
				State:       github.String("failure"),
				Context:     github.String("ci/build"),
				Description: github.String("Build failed"),
				TargetURL:   github.String("https://ci.example.com/build/123"),
			},
			{
				State:   github.String("success"),
				Context: github.String("ci/lint"),
			},
			{
				State:       github.String("error"),
				Context:     github.String("ci/test"),
				Description: github.String("Tests timed out"),
			},
			{
				State:   github.String("pending"),
				Context: github.String("ci/deploy"),
			},
		},
	}

	failing := a.getFailingChecks(status)

	if len(failing) != 3 {
		t.Errorf("Expected 3 items (2 failures + 1 pending info), got %d", len(failing))
	}

	expectedStrings := []string{
		"ci/build (Build failed)",
		"ci/test (Tests timed out)",
		"Pending checks: ci/deploy",
	}

	for i, expected := range expectedStrings {
		if i >= len(failing) {
			t.Errorf("Missing expected item %d", i)
			continue
		}
		if failing[i] != expected {
			t.Errorf("Item %d = %q, want %q", i, failing[i], expected)
		}
	}
}

func TestAnalyzePullRequest_AuthorCheck(t *testing.T) {
	tests := []struct {
		name           string
		currentUser    *github.User
		prAuthor       *github.User
		wantApprovable bool
		wantReason     string
	}{
		{
			name: "different users",
			currentUser: &github.User{
				Login: github.String("reviewer"),
			},
			prAuthor: &github.User{
				Login: github.String("author"),
			},
			wantApprovable: true,
			wantReason:     "", // Should pass this check
		},
		{
			name: "same user",
			currentUser: &github.User{
				Login: github.String("author"),
			},
			prAuthor: &github.User{
				Login: github.String("author"),
			},
			wantApprovable: true, // Changed: own PRs are still marked approvable, but with IsOwnPR flag
			wantReason:     "",   // No error reason since we handle this with IsOwnPR flag
		},
		{
			name:        "current user nil",
			currentUser: nil,
			prAuthor: &github.User{
				Login: github.String("author"),
			},
			wantApprovable: true,
			wantReason:     "", // Should pass if we can't determine current user
		},
		{
			name: "pr author nil",
			currentUser: &github.User{
				Login: github.String("reviewer"),
			},
			prAuthor:       nil,
			wantApprovable: true,
			wantReason:     "", // Should pass if PR author is nil
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockGH := &mockGitHubAPI{
				pr: &github.PullRequest{
					State:        github.String("open"),
					User:         tt.prAuthor,
					ChangedFiles: github.Int(1),
				},
				currentUser: tt.currentUser,
				files: []*github.CommitFile{
					{Filename: github.String("README.md")},
				},
			}

			mockGemini := &mockGeminiAPI{
				result: &geminiAnalysisResult{
					AltersBehavior:    false,
					NotImprovement:    false,
					NonTrivial:        false,
					Category:          "documentation",
					Reason:            "Documentation update",
					Risky:             false,
					InsecureChange:    false,
					PossiblyMalicious: false,
					Superfluous:       false,
					Vandalism:         false,
					Confusing:         false,
					TitleDescMismatch: false,
				},
			}

			a, err := New(mockGH, mockGemini, DefaultConfig())
			if err != nil {
				t.Fatalf("Failed to create analyzer: %v", err)
			}

			result, err := a.AnalyzePullRequest(context.Background(), "owner", "repo", 1)
			if err != nil {
				t.Fatalf("AnalyzePullRequest failed: %v", err)
			}

			if result.Approvable != tt.wantApprovable {
				t.Errorf("Approvable = %v, want %v", result.Approvable, tt.wantApprovable)
			}

			if tt.wantReason != "" && result.Reason != tt.wantReason {
				t.Errorf("Reason = %q, want %q", result.Reason, tt.wantReason)
			}
		})
	}
}

func TestDetectTrivialChanges(t *testing.T) {
	a := &Analyzer{}

	tests := []struct {
		name         string
		files        []*github.CommitFile
		wantTrivial  bool
		wantCategory string
	}{
		{
			name: "markdown only",
			files: []*github.CommitFile{
				{Filename: github.String("README.md")},
				{Filename: github.String("docs/guide.md")},
			},
			wantTrivial:  true,
			wantCategory: "documentation",
		},
		{
			name: "contains code",
			files: []*github.CommitFile{
				{Filename: github.String("README.md")},
				{Filename: github.String("main.go")},
			},
			wantTrivial:  false,
			wantCategory: "",
		},
		{
			name: "license file",
			files: []*github.CommitFile{
				{Filename: github.String("LICENSE")},
			},
			wantTrivial:  true,
			wantCategory: "documentation",
		},
		{
			name: "text files",
			files: []*github.CommitFile{
				{Filename: github.String("CHANGELOG.txt")},
				{Filename: github.String("AUTHORS.txt")},
			},
			wantTrivial:  true,
			wantCategory: "documentation",
		},
		{
			name: "mixed code types",
			files: []*github.CommitFile{
				{Filename: github.String("script.py")},
				{Filename: github.String("helper.js")},
			},
			wantTrivial:  false,
			wantCategory: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTrivial, gotCategory := a.detectTrivialChanges(tt.files)
			if gotTrivial != tt.wantTrivial {
				t.Errorf("detectTrivialChanges() trivial = %v, want %v", gotTrivial, tt.wantTrivial)
			}
			if gotCategory != tt.wantCategory {
				t.Errorf("detectTrivialChanges() category = %v, want %v", gotCategory, tt.wantCategory)
			}
		})
	}
}

// mockGitHubAPI implements the github.API interface for testing
type mockGitHubAPI struct {
	reviews     []*github.PullRequestReview
	currentUser *github.User
	pr          *github.PullRequest
	files       []*github.CommitFile
}

func (m *mockGitHubAPI) AuthenticatedUser(ctx context.Context) (*github.User, error) {
	return m.currentUser, nil
}

func (m *mockGitHubAPI) PullRequest(ctx context.Context, owner, repo string, number int) (*github.PullRequest, error) {
	if m.pr != nil {
		return m.pr, nil
	}
	return &github.PullRequest{
		State: github.String("open"),
	}, nil
}

func (m *mockGitHubAPI) ListOrgPullRequests(ctx context.Context, org string) ([]*github.PullRequest, error) {
	return nil, nil
}

func (m *mockGitHubAPI) ListRepoPullRequests(ctx context.Context, owner, repo string) ([]*github.PullRequest, error) {
	return nil, nil
}

func (m *mockGitHubAPI) PullRequestFiles(ctx context.Context, owner, repo string, number int) ([]*github.CommitFile, error) {
	if m.files != nil {
		return m.files, nil
	}
	return nil, nil
}

func (m *mockGitHubAPI) CombinedStatus(ctx context.Context, owner, repo, ref string) (*github.CombinedStatus, error) {
	return nil, nil
}

func (m *mockGitHubAPI) ListCheckRunsForRef(ctx context.Context, owner, repo, ref string) ([]*github.CheckRun, error) {
	return nil, nil
}

func (m *mockGitHubAPI) ListReviews(ctx context.Context, owner, repo string, number int) ([]*github.PullRequestReview, error) {
	return m.reviews, nil
}

func (m *mockGitHubAPI) ListIssueComments(ctx context.Context, owner, repo string, number int) ([]*github.IssueComment, error) {
	return nil, nil
}

func (m *mockGitHubAPI) ListPullRequestComments(ctx context.Context, owner, repo string, number int) ([]*github.PullRequestComment, error) {
	return nil, nil
}

func (m *mockGitHubAPI) ApprovePullRequest(ctx context.Context, owner, repo string, number int, body string) error {
	return nil
}

func (m *mockGitHubAPI) EnableAutoMerge(ctx context.Context, owner, repo string, number int) error {
	return nil
}

func (m *mockGitHubAPI) MergePullRequest(ctx context.Context, owner, repo string, number int) error {
	return nil
}

func (m *mockGitHubAPI) UpdateBranch(ctx context.Context, owner, repo string, number int) error {
	return nil
}

func (m *mockGitHubAPI) ListAppInstallations(ctx context.Context) ([]*github.Installation, error) {
	return nil, nil
}

func (m *mockGitHubAPI) ListUserRepositories(ctx context.Context, user string) ([]*github.Repository, error) {
	return nil, nil
}

func (m *mockGitHubAPI) ListUserPullRequests(ctx context.Context, user string) ([]*github.PullRequest, error) {
	return nil, nil
}

func (m *mockGitHubAPI) GetUserPermissionLevel(ctx context.Context, owner, repo, username string) (string, error) {
	// Mock implementation - return "write" for all users
	return "write", nil
}

func TestCheckExistingReviews(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name                string
		reviews             []*github.PullRequestReview
		currentUser         *github.User
		wantReason          string
		wantAlreadyApproved bool
	}{
		{
			name:                "no reviews",
			reviews:             []*github.PullRequestReview{},
			currentUser:         &github.User{Login: github.String("testuser")},
			wantReason:          "",
			wantAlreadyApproved: false,
		},
		{
			name: "only our approval",
			reviews: []*github.PullRequestReview{
				{
					State: github.String(constants.ReviewStateApproved),
					User:  &github.User{Login: github.String("testuser")},
				},
			},
			currentUser:         &github.User{Login: github.String("testuser")},
			wantReason:          "PR already approved by us",
			wantAlreadyApproved: true,
		},
		{
			name: "other user approval",
			reviews: []*github.PullRequestReview{
				{
					State: github.String(constants.ReviewStateApproved),
					User:  &github.User{Login: github.String("otheruser")},
				},
			},
			currentUser:         &github.User{Login: github.String("testuser")},
			wantReason:          "PR has existing reviews",
			wantAlreadyApproved: false,
		},
		{
			name: "our approval plus other review",
			reviews: []*github.PullRequestReview{
				{
					State: github.String(constants.ReviewStateApproved),
					User:  &github.User{Login: github.String("testuser")},
				},
				{
					State: github.String(constants.ReviewStateCommented),
					User:  &github.User{Login: github.String("otheruser")},
				},
			},
			currentUser:         &github.User{Login: github.String("testuser")},
			wantReason:          "PR has existing reviews",
			wantAlreadyApproved: false,
		},
		{
			name: "changes requested by other",
			reviews: []*github.PullRequestReview{
				{
					State: github.String(constants.ReviewStateChangesRequested),
					User:  &github.User{Login: github.String("otheruser")},
				},
			},
			currentUser:         &github.User{Login: github.String("testuser")},
			wantReason:          "PR has existing reviews",
			wantAlreadyApproved: false,
		},
		{
			name: "nil current user",
			reviews: []*github.PullRequestReview{
				{
					State: github.String(constants.ReviewStateApproved),
					User:  &github.User{Login: github.String("testuser")},
				},
			},
			currentUser:         nil,
			wantReason:          "PR has existing reviews",
			wantAlreadyApproved: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAPI := &mockGitHubAPI{
				reviews:     tt.reviews,
				currentUser: tt.currentUser,
			}

			a := &Analyzer{
				gh:     mockAPI,
				config: &Config{},
			}

			gotReason, _, gotAlreadyApproved := a.checkExistingReviews(ctx, "owner", "repo", 1, tt.currentUser)

			if gotReason != tt.wantReason {
				t.Errorf("checkExistingReviews() reason = %v, want %v", gotReason, tt.wantReason)
			}

			if gotAlreadyApproved != tt.wantAlreadyApproved {
				t.Errorf("checkExistingReviews() alreadyApprovedByUs = %v, want %v", gotAlreadyApproved, tt.wantAlreadyApproved)
			}
		})
	}
}

func TestAreCheckRunsPassing(t *testing.T) {
	a := &Analyzer{}

	tests := []struct {
		name      string
		checkRuns []*github.CheckRun
		want      bool
	}{
		{
			name:      "no check runs",
			checkRuns: []*github.CheckRun{},
			want:      true,
		},
		{
			name: "all checks passing",
			checkRuns: []*github.CheckRun{
				{
					Name:       github.String("Test / test"),
					Status:     github.String("completed"),
					Conclusion: github.String("success"),
				},
				{
					Name:       github.String("Build / build"),
					Status:     github.String("completed"),
					Conclusion: github.String("success"),
				},
			},
			want: true,
		},
		{
			name: "check in progress",
			checkRuns: []*github.CheckRun{
				{
					Name:   github.String("Test / test"),
					Status: github.String("in_progress"),
				},
			},
			want: true, // In-progress checks don't count as failures
		},
		{
			name: "check queued",
			checkRuns: []*github.CheckRun{
				{
					Name:   github.String("Test / test"),
					Status: github.String("queued"),
				},
			},
			want: true, // Queued checks don't count as failures
		},
		{
			name: "check failed",
			checkRuns: []*github.CheckRun{
				{
					Name:       github.String("Test / test"),
					Status:     github.String("completed"),
					Conclusion: github.String("failure"),
				},
			},
			want: false,
		},
		{
			name: "mixed success and failure",
			checkRuns: []*github.CheckRun{
				{
					Name:       github.String("Build / build"),
					Status:     github.String("completed"),
					Conclusion: github.String("success"),
				},
				{
					Name:       github.String("Test / test"),
					Status:     github.String("completed"),
					Conclusion: github.String("failure"),
				},
			},
			want: false,
		},
		{
			name: "neutral conclusion",
			checkRuns: []*github.CheckRun{
				{
					Name:       github.String("Optional Check"),
					Status:     github.String("completed"),
					Conclusion: github.String("neutral"),
				},
			},
			want: true, // Neutral is not a failure
		},
		{
			name: "skipped conclusion",
			checkRuns: []*github.CheckRun{
				{
					Name:       github.String("Conditional Check"),
					Status:     github.String("completed"),
					Conclusion: github.String("skipped"),
				},
			},
			want: true, // Skipped is not a failure
		},
		{
			name: "timed out",
			checkRuns: []*github.CheckRun{
				{
					Name:       github.String("Test / test"),
					Status:     github.String("completed"),
					Conclusion: github.String("timed_out"),
				},
			},
			want: false,
		},
		{
			name: "action required",
			checkRuns: []*github.CheckRun{
				{
					Name:       github.String("Deploy / staging"),
					Status:     github.String("completed"),
					Conclusion: github.String("action_required"),
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.areCheckRunsPassing(tt.checkRuns); got != tt.want {
				t.Errorf("areCheckRunsPassing() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPRAgeCalculation(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	tests := []struct {
		name       string
		pr         *github.PullRequest
		minAge     time.Duration
		maxAge     time.Duration
		wantReason string
	}{
		{
			name: "PR updated recently",
			pr: &github.PullRequest{
				State:     github.String("open"),
				UpdatedAt: &github.Timestamp{Time: now.Add(-1 * time.Hour)},
			},
			minAge:     4 * time.Hour,
			maxAge:     90 * 24 * time.Hour,
			wantReason: "PR updated too recently",
		},
		{
			name: "PR updated too long ago",
			pr: &github.PullRequest{
				State:     github.String("open"),
				UpdatedAt: &github.Timestamp{Time: now.Add(-100 * 24 * time.Hour)},
			},
			minAge:     4 * time.Hour,
			maxAge:     90 * 24 * time.Hour,
			wantReason: "PR has been stale too long",
		},
		{
			name: "PR in valid age range",
			pr: &github.PullRequest{
				State:     github.String("open"),
				UpdatedAt: &github.Timestamp{Time: now.Add(-12 * time.Hour)},
			},
			minAge:     4 * time.Hour,
			maxAge:     90 * 24 * time.Hour,
			wantReason: "",
		},
		{
			name: "Use CreatedAt when UpdatedAt is nil",
			pr: &github.PullRequest{
				State:     github.String("open"),
				CreatedAt: &github.Timestamp{Time: now.Add(-1 * time.Hour)},
				UpdatedAt: nil,
			},
			minAge:     4 * time.Hour,
			maxAge:     90 * 24 * time.Hour,
			wantReason: "PR updated too recently",
		},
		{
			name: "No age limits set",
			pr: &github.PullRequest{
				State:     github.String("open"),
				UpdatedAt: &github.Timestamp{Time: now.Add(-1 * time.Hour)},
			},
			minAge:     0,
			maxAge:     0,
			wantReason: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAPI := &mockGitHubAPI{
				pr: tt.pr,
			}

			a := &Analyzer{
				gh: mockAPI,
				config: &Config{
					MinOpenTime: tt.minAge,
					MaxOpenTime: tt.maxAge,
				},
			}

			result, err := a.AnalyzePullRequest(ctx, "owner", "repo", 1)
			if err != nil {
				t.Fatalf("AnalyzePullRequest() error = %v", err)
			}

			if tt.wantReason != "" {
				if result.Approvable {
					t.Errorf("Expected PR to not be approvable, but it was")
				}
				if !strings.Contains(result.Reason, tt.wantReason) {
					t.Errorf("Expected reason to contain %q, got %q", tt.wantReason, result.Reason)
				}
				// Check that reason mentions "last push" instead of "age"
				if strings.Contains(result.Reason, "last push") {
					// Good - using the new terminology
				} else if strings.Contains(result.Reason, "age") && !strings.Contains(result.Reason, "last push") {
					t.Errorf("Reason should mention 'last push' not just 'age': %q", result.Reason)
				}
			} else {
				// Should be approvable (no age-related rejection)
				if !result.Approvable && strings.Contains(result.Reason, "PR updated") {
					t.Errorf("PR should not be rejected for age reasons, got: %q", result.Reason)
				}
			}
		})
	}
}

func TestAnalyzePullRequest_OwnPRDetection(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		prAuthor       string
		currentUser    string
		wantIsOwnPR    bool
		wantApprovable bool
	}{
		{
			name:           "Different users",
			prAuthor:       "alice",
			currentUser:    "bob",
			wantIsOwnPR:    false,
			wantApprovable: true, // Should be approvable (assuming other checks pass)
		},
		{
			name:           "Same user (own PR)",
			prAuthor:       "alice",
			currentUser:    "alice",
			wantIsOwnPR:    true,
			wantApprovable: true, // Still marked approvable but IsOwnPR flag is set
		},
		{
			name:           "No current user",
			prAuthor:       "alice",
			currentUser:    "",
			wantIsOwnPR:    false,
			wantApprovable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pr := &github.PullRequest{
				State: github.String("open"),
				User:  &github.User{Login: github.String(tt.prAuthor)},
			}

			var currentUser *github.User
			if tt.currentUser != "" {
				currentUser = &github.User{Login: github.String(tt.currentUser)}
			}

			mockAPI := &mockGitHubAPI{
				pr:          pr,
				currentUser: currentUser,
			}

			a := &Analyzer{
				gh: mockAPI,
				config: &Config{
					UseGemini: false, // Disable Gemini for this test
				},
			}

			result, err := a.AnalyzePullRequest(ctx, "owner", "repo", 1)
			if err != nil {
				t.Fatalf("AnalyzePullRequest() error = %v", err)
			}

			if result.IsOwnPR != tt.wantIsOwnPR {
				t.Errorf("IsOwnPR = %v, want %v", result.IsOwnPR, tt.wantIsOwnPR)
			}

			// Check that own PRs show appropriate message in details
			if tt.wantIsOwnPR {
				found := false
				for _, detail := range result.Details {
					if strings.Contains(detail, "is the current user") {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected to find 'is the current user' in details for own PR")
				}
			}
		})
	}
}

func TestGetFailingCheckRuns(t *testing.T) {
	a := &Analyzer{}

	checkRuns := []*github.CheckRun{
		{
			Name:       github.String("Test / test (pull_request)"),
			Status:     github.String("completed"),
			Conclusion: github.String("failure"),
			Output: &github.CheckRunOutput{
				Title: github.String("Tests failed"),
			},
		},
		{
			Name:       github.String("Build / build"),
			Status:     github.String("completed"),
			Conclusion: github.String("success"),
		},
		{
			Name:       github.String("Lint / lint"),
			Status:     github.String("completed"),
			Conclusion: github.String("timed_out"),
		},
		{
			Name:   github.String("Deploy / staging"),
			Status: github.String("in_progress"),
		},
		{
			Name:   github.String("Security / scan"),
			Status: github.String("queued"),
		},
	}

	failing := a.getFailingCheckRuns(checkRuns)

	// Should have 3 items: 2 failures + 1 pending summary
	if len(failing) != 3 {
		t.Errorf("Expected 3 items, got %d: %v", len(failing), failing)
	}

	// Check specific failure messages
	expectedFailures := []string{
		"Test / test (pull_request): Tests failed", // Has output title
		"Lint / lint (timed_out)",                  // No output title
		"Pending checks: Deploy / staging, Security / scan",
	}

	for i, expected := range expectedFailures {
		if i >= len(failing) {
			t.Errorf("Missing expected item %d: %s", i, expected)
			continue
		}
		if failing[i] != expected {
			t.Errorf("Item %d = %q, want %q", i, failing[i], expected)
		}
	}
}

// mockGeminiAPI implements the gemini.API interface for testing
type mockGeminiAPI struct {
	result *geminiAnalysisResult
	err    error
}

type geminiAnalysisResult struct {
	AltersBehavior    bool
	NotImprovement    bool
	NonTrivial        bool
	Category          string
	Reason            string
	Risky             bool
	InsecureChange    bool
	PossiblyMalicious bool
	Superfluous       bool
	Vandalism         bool
	Confusing         bool
	TitleDescMismatch bool
	MajorVersionBump  bool
}

func (m *mockGeminiAPI) AnalyzePRChanges(ctx context.Context, files []gemini.FileChange, prContext gemini.PRContext) (*gemini.AnalysisResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.result == nil {
		return &gemini.AnalysisResult{
			AltersBehavior:    false,
			NotImprovement:    false,
			NonTrivial:        false,
			Category:          "documentation",
			Reason:            "Default test response",
			Risky:             false,
			InsecureChange:    false,
			PossiblyMalicious: false,
			Superfluous:       false,
			Vandalism:         false,
			Confusing:         false,
			TitleDescMismatch: false,
			MajorVersionBump:  false,
		}, nil
	}
	return &gemini.AnalysisResult{
		AltersBehavior:    m.result.AltersBehavior,
		NotImprovement:    m.result.NotImprovement,
		NonTrivial:        m.result.NonTrivial,
		Category:          m.result.Category,
		Reason:            m.result.Reason,
		Risky:             m.result.Risky,
		InsecureChange:    m.result.InsecureChange,
		PossiblyMalicious: m.result.PossiblyMalicious,
		Superfluous:       m.result.Superfluous,
		Vandalism:         m.result.Vandalism,
		Confusing:         m.result.Confusing,
		TitleDescMismatch: m.result.TitleDescMismatch,
		MajorVersionBump:  m.result.MajorVersionBump,
	}, nil
}

func (m *mockGeminiAPI) Close() error {
	return nil
}

func TestMaxLinesCheck(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		additions   int
		deletions   int
		maxLines    int
		shouldPass  bool
		expectedMsg string
	}{
		{
			name:       "under limit",
			additions:  50,
			deletions:  25,
			maxLines:   100,
			shouldPass: true,
		},
		{
			name:       "exactly at limit",
			additions:  75,
			deletions:  50,
			maxLines:   125,
			shouldPass: true,
		},
		{
			name:        "over limit",
			additions:   100,
			deletions:   50,
			maxLines:    125,
			shouldPass:  false,
			expectedMsg: "Too many lines changed (150 > 125)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockGH := &mockGitHubAPI{
				pr: &github.PullRequest{
					State:             github.String("open"),
					Draft:             github.Bool(false),
					ChangedFiles:      github.Int(1),
					Additions:         github.Int(tt.additions),
					Deletions:         github.Int(tt.deletions),
					UpdatedAt:         &github.Timestamp{Time: time.Now().Add(-24 * time.Hour)},
					User:              &github.User{Login: github.String("testuser")},
					AuthorAssociation: github.String("CONTRIBUTOR"),
				},
				files: []*github.CommitFile{
					{
						Filename: github.String("README.md"),
						Patch:    github.String("@@ -1 +1 @@\n-old\n+new"),
					},
				},
			}

			// Create a mock Gemini that returns an approvable result
			mockGemini := &mockGeminiAPI{
				result: &geminiAnalysisResult{
					AltersBehavior: false,
					NotImprovement: false,
					Category:       "documentation",
				},
			}

			config := DefaultConfig()
			config.MaxLines = tt.maxLines
			config.UseGemini = true

			analyzer, err := New(mockGH, mockGemini, config)
			if err != nil {
				t.Fatalf("Failed to create analyzer: %v", err)
			}

			result, err := analyzer.AnalyzePullRequest(ctx, "owner", "repo", 1)
			if err != nil {
				t.Fatalf("Failed to analyze PR: %v", err)
			}

			if tt.shouldPass {
				if !result.Approvable {
					t.Errorf("Expected PR to be approvable, but got: %s", result.Reason)
				}
			} else {
				if result.Approvable {
					t.Error("Expected PR to not be approvable")
				}
				if result.Reason != tt.expectedMsg {
					t.Errorf("Expected reason %q, got %q", tt.expectedMsg, result.Reason)
				}
			}
		})
	}
}

func TestGeminiCategoryRequired(t *testing.T) {
	ctx := context.Background()

	mockGH := &mockGitHubAPI{
		pr: &github.PullRequest{
			State:             github.String("open"),
			Draft:             github.Bool(false),
			ChangedFiles:      github.Int(1),
			Additions:         github.Int(10),
			Deletions:         github.Int(5),
			UpdatedAt:         &github.Timestamp{Time: time.Now().Add(-24 * time.Hour)},
			User:              &github.User{Login: github.String("testuser")},
			AuthorAssociation: github.String("CONTRIBUTOR"),
		},
		files: []*github.CommitFile{
			{
				Filename: github.String("test.go"),
				Patch:    github.String("@@ -1 +1 @@\n-old\n+new"),
			},
		},
	}

	// Test with no category
	mockGemini := &mockGeminiAPI{
		result: &geminiAnalysisResult{
			AltersBehavior: false,
			NotImprovement: false,
			Category:       "", // No category
		},
	}

	config := DefaultConfig()
	config.UseGemini = true

	analyzer, err := New(mockGH, mockGemini, config)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	result, err := analyzer.AnalyzePullRequest(ctx, "owner", "repo", 1)
	if err != nil {
		t.Fatalf("Failed to analyze PR: %v", err)
	}

	if result.Approvable {
		t.Error("Expected PR to not be approvable when category is missing")
	}
	if result.Reason != "Cannot determine change category" {
		t.Errorf("Expected reason 'Cannot determine change category', got %q", result.Reason)
	}
}

func TestNonTrivialRejection(t *testing.T) {
	ctx := context.Background()

	mockGH := &mockGitHubAPI{
		pr: &github.PullRequest{
			State:             github.String("open"),
			Draft:             github.Bool(false),
			ChangedFiles:      github.Int(1),
			Additions:         github.Int(10),
			Deletions:         github.Int(5),
			UpdatedAt:         &github.Timestamp{Time: time.Now().Add(-24 * time.Hour)},
			User:              &github.User{Login: github.String("testuser")},
			AuthorAssociation: github.String("CONTRIBUTOR"),
		},
		files: []*github.CommitFile{
			{
				Filename: github.String("main.go"),
				Patch:    github.String("@@ -1 +1 @@\n-old\n+new"),
			},
		},
	}

	// Test with non-trivial flag set
	mockGemini := &mockGeminiAPI{
		result: &geminiAnalysisResult{
			AltersBehavior: false,
			NotImprovement: false,
			NonTrivial:     true, // This should cause rejection
			Category:       "refactor",
		},
	}

	config := DefaultConfig()
	config.UseGemini = true

	analyzer, err := New(mockGH, mockGemini, config)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	result, err := analyzer.AnalyzePullRequest(ctx, "owner", "repo", 1)
	if err != nil {
		t.Fatalf("Failed to analyze PR: %v", err)
	}

	if result.Approvable {
		t.Error("Expected PR to not be approvable when marked as non-trivial")
	}
	if result.Reason != "Changes are non-trivial" {
		t.Errorf("Expected reason 'Changes are non-trivial', got %q", result.Reason)
	}
}
