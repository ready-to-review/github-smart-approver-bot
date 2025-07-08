package analyzer

import (
	"testing"

	"github.com/google/go-github/v68/github"
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
			},
			want: false,
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
		},
	}
	
	failing := a.getFailingChecks(status)
	
	if len(failing) != 2 {
		t.Errorf("Expected 2 failing checks, got %d", len(failing))
	}
	
	expectedStrings := []string{
		"[failure] ci/build: Build failed (see: https://ci.example.com/build/123)",
		"[error] ci/test: Tests timed out",
	}
	
	for i, expected := range expectedStrings {
		if i >= len(failing) {
			t.Errorf("Missing expected failing check %d", i)
			continue
		}
		if failing[i] != expected {
			t.Errorf("Failing check %d = %q, want %q", i, failing[i], expected)
		}
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