package analyzer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v68/github"
)

func TestDependabotBehavior(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name              string
		prUser            string
		authorAssociation string
		additions         int
		deletions         int
		nonTrivial        bool
		majorVersionBump  bool
		altersBehavior    bool
		wantApprovable    bool
		wantReason        string
	}{
		{
			name:              "dependabot with large diff is allowed",
			prUser:            "dependabot[bot]",
			authorAssociation: "CONTRIBUTOR",
			additions:         500,
			deletions:         300,
			nonTrivial:        false,
			altersBehavior:    false, // Dependabot non-major updates don't alter behavior
			wantApprovable:    true,
		},
		{
			name:              "dependabot with non-trivial changes is allowed",
			prUser:            "dependabot[bot]",
			authorAssociation: "CONTRIBUTOR",
			additions:         50,
			deletions:         30,
			nonTrivial:        true,
			altersBehavior:    false, // Dependabot non-major updates don't alter behavior
			wantApprovable:    true,
		},
		{
			name:              "dependabot with major version bump is rejected",
			prUser:            "dependabot[bot]",
			authorAssociation: "CONTRIBUTOR",
			additions:         50,
			deletions:         30,
			nonTrivial:        true,
			majorVersionBump:  true,
			altersBehavior:    true, // Major version bumps do alter behavior
			wantApprovable:    false,
			wantReason:        "Major version bump detected - requires manual review",
		},
		{
			name:              "regular user with large diff is rejected",
			prUser:            "regular-user",
			authorAssociation: "CONTRIBUTOR",
			additions:         500,
			deletions:         300,
			nonTrivial:        false,
			altersBehavior:    true,
			wantApprovable:    false,
			wantReason:        "Too many lines changed (800 > 250)",
		},
		{
			name:              "regular user with non-trivial changes is rejected",
			prUser:            "regular-user",
			authorAssociation: "CONTRIBUTOR",
			additions:         50,
			deletions:         30,
			nonTrivial:        true,
			altersBehavior:    true,
			wantApprovable:    false,
			wantReason:        "Changes alter application behavior", // AltersBehavior is checked before NonTrivial
		},
		{
			name:              "dependabot alternative name",
			prUser:            "dependabot",
			authorAssociation: "CONTRIBUTOR",
			additions:         500,
			deletions:         300,
			nonTrivial:        true,
			altersBehavior:    false, // Dependabot non-major updates don't alter behavior
			wantApprovable:    true,
		},
		{
			name:              "dependabot minor version update doesn't alter behavior",
			prUser:            "dependabot[bot]",
			authorAssociation: "CONTRIBUTOR",
			additions:         20,
			deletions:         15,
			nonTrivial:        false,
			majorVersionBump:  false,
			altersBehavior:    false, // Minor/patch updates from dependabot don't alter behavior
			wantApprovable:    true,
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
					User:              &github.User{Login: github.String(tt.prUser)},
					AuthorAssociation: github.String(tt.authorAssociation),
					Base: &github.PullRequestBranch{
						Repo: &github.Repository{
							Name:  github.String("testrepo"),
							Owner: &github.User{Login: github.String("testorg")},
						},
					},
					Number: github.Int(123),
				},
				files: []*github.CommitFile{
					{
						Filename:  github.String("go.mod"),
						Additions: github.Int(tt.additions),
						Deletions: github.Int(tt.deletions),
						Patch:     github.String("dependency update"),
					},
				},
			}

			mockGemini := &mockGeminiAPI{
				result: &geminiAnalysisResult{
					AltersBehavior:   tt.altersBehavior,
					NotImprovement:   false,
					NonTrivial:       tt.nonTrivial,
					Category:         "dependency",
					MajorVersionBump: tt.majorVersionBump,
				},
			}

			config := DefaultConfig()
			config.UseGemini = true
			config.MaxLines = 250

			analyzer, err := New(mockGH, mockGemini, config)
			if err != nil {
				t.Fatalf("Failed to create analyzer: %v", err)
			}

			result, err := analyzer.AnalyzePullRequest(ctx, "owner", "repo", 1)
			if err != nil {
				t.Fatalf("Failed to analyze PR: %v", err)
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

func TestDependabotAltersBehaviorCheck(t *testing.T) {
	ctx := context.Background()

	// Test that regular dependency updates from dependabot don't alter behavior
	mockGH := &mockGitHubAPI{
		pr: &github.PullRequest{
			State:             github.String("open"),
			Draft:             github.Bool(false),
			ChangedFiles:      github.Int(1),
			Additions:         github.Int(10),
			Deletions:         github.Int(5),
			UpdatedAt:         &github.Timestamp{Time: time.Now().Add(-24 * time.Hour)},
			User:              &github.User{Login: github.String("dependabot[bot]")},
			AuthorAssociation: github.String("CONTRIBUTOR"),
			Base: &github.PullRequestBranch{
				Repo: &github.Repository{
					Name:  github.String("testrepo"),
					Owner: &github.User{Login: github.String("testorg")},
				},
			},
			Number: github.Int(123),
		},
		files: []*github.CommitFile{
			{
				Filename: github.String("package.json"),
				Patch:    github.String(`-"react": "^17.0.2"\n+"react": "^17.0.3"`),
			},
		},
	}

	mockGemini := &mockGeminiAPI{
		result: &geminiAnalysisResult{
			AltersBehavior:   false, // Gemini should recognize dependabot minor update doesn't alter behavior
			NotImprovement:   false,
			NonTrivial:       false,
			Category:         "dependency",
			MajorVersionBump: false,
			Reason:           "Minor version update from dependabot",
		},
	}

	config := DefaultConfig()
	config.UseGemini = true

	analyzer, err := New(mockGH, mockGemini, config)
	if err != nil {
		t.Fatalf("Failed to create analyzer: %v", err)
	}

	result, err := analyzer.AnalyzePullRequest(ctx, "testorg", "testrepo", 123)
	if err != nil {
		t.Fatalf("Failed to analyze PR: %v", err)
	}

	if !result.Approvable {
		t.Errorf("Expected dependabot minor version update to be approvable, got: %s", result.Reason)
	}
}

func TestMajorVersionBumpDetection(t *testing.T) {
	ctx := context.Background()

	mockGH := &mockGitHubAPI{
		pr: &github.PullRequest{
			State:             github.String("open"),
			Draft:             github.Bool(false),
			ChangedFiles:      github.Int(1),
			Additions:         github.Int(10),
			Deletions:         github.Int(5),
			UpdatedAt:         &github.Timestamp{Time: time.Now().Add(-24 * time.Hour)},
			User:              &github.User{Login: github.String("dependabot[bot]")},
			AuthorAssociation: github.String("CONTRIBUTOR"),
			Base: &github.PullRequestBranch{
				Repo: &github.Repository{
					Name:  github.String("testrepo"),
					Owner: &github.User{Login: github.String("testorg")},
				},
			},
			Number: github.Int(123),
		},
		files: []*github.CommitFile{
			{
				Filename: github.String("package.json"),
				Patch:    github.String(`-"react": "^17.0.2"\n+"react": "^18.0.0"`),
			},
		},
	}

	mockGemini := &mockGeminiAPI{
		result: &geminiAnalysisResult{
			AltersBehavior:   false,
			NotImprovement:   false,
			NonTrivial:       false,
			Category:         "dependency",
			MajorVersionBump: true,
			Reason:           "Major version bump: react 17.x to 18.x",
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
		t.Error("Expected PR with major version bump to not be approvable")
	}

	if result.Reason != "Major version bump detected - requires manual review" {
		t.Errorf("Expected major version bump reason, got %q", result.Reason)
	}

	// Check that details mention the major version bump
	foundBump := false
	for _, detail := range result.Details {
		if strings.Contains(detail, "major version bump") {
			foundBump = true
			break
		}
	}
	if !foundBump {
		t.Error("Expected details to mention major version bump")
	}
}

func TestIsDependabotPR(t *testing.T) {
	a := &Analyzer{}

	tests := []struct {
		name string
		pr   *github.PullRequest
		want bool
	}{
		{
			name: "dependabot[bot] user",
			pr: &github.PullRequest{
				User: &github.User{Login: github.String("dependabot[bot]")},
			},
			want: true,
		},
		{
			name: "dependabot user",
			pr: &github.PullRequest{
				User: &github.User{Login: github.String("dependabot")},
			},
			want: true,
		},
		{
			name: "regular user",
			pr: &github.PullRequest{
				User: &github.User{Login: github.String("john-doe")},
			},
			want: false,
		},
		{
			name: "nil user",
			pr: &github.PullRequest{
				User: nil,
			},
			want: false,
		},
		{
			name: "user with dependabot in name",
			pr: &github.PullRequest{
				User: &github.User{Login: github.String("my-dependabot-fork")},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := a.isDependabotPR(tt.pr)
			if got != tt.want {
				t.Errorf("isDependabotPR() = %v, want %v", got, tt.want)
			}
		})
	}
}
