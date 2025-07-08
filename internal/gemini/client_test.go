package gemini

import (
	"strings"
	"testing"
)

func TestParseAnalysisResponse(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     *AnalysisResult
	}{
		{
			name: "typical response",
			response: `ALTERS_BEHAVIOR: NO
IS_IMPROVEMENT: YES
IS_TRIVIAL: YES
CATEGORY: typo
REASON: Fixed spelling error in comment`,
			want: &AnalysisResult{
				AltersBehavior: false,
				IsImprovement:  true,
				IsTrivial:      true,
				Category:       "typo",
				Reason:         "Fixed spelling error in comment",
			},
		},
		{
			name: "behavior altering change",
			response: `ALTERS_BEHAVIOR: YES
IS_IMPROVEMENT: YES
IS_TRIVIAL: NO
CATEGORY: other
REASON: Changed algorithm logic`,
			want: &AnalysisResult{
				AltersBehavior: true,
				IsImprovement:  true,
				IsTrivial:      false,
				Category:       "other",
				Reason:         "Changed algorithm logic",
			},
		},
		{
			name: "case insensitive yes/no",
			response: `ALTERS_BEHAVIOR: yes
IS_IMPROVEMENT: Yes
IS_TRIVIAL: YES
CATEGORY: comment
REASON: Added clarifying comment`,
			want: &AnalysisResult{
				AltersBehavior: true,
				IsImprovement:  true,
				IsTrivial:      true,
				Category:       "comment",
				Reason:         "Added clarifying comment",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAnalysisResponse(tt.response)
			if err != nil {
				t.Fatalf("parseAnalysisResponse() error = %v", err)
			}

			if got.AltersBehavior != tt.want.AltersBehavior {
				t.Errorf("AltersBehavior = %v, want %v", got.AltersBehavior, tt.want.AltersBehavior)
			}
			if got.IsImprovement != tt.want.IsImprovement {
				t.Errorf("IsImprovement = %v, want %v", got.IsImprovement, tt.want.IsImprovement)
			}
			if got.IsTrivial != tt.want.IsTrivial {
				t.Errorf("IsTrivial = %v, want %v", got.IsTrivial, tt.want.IsTrivial)
			}
			if got.Category != tt.want.Category {
				t.Errorf("Category = %v, want %v", got.Category, tt.want.Category)
			}
			if got.Reason != tt.want.Reason {
				t.Errorf("Reason = %v, want %v", got.Reason, tt.want.Reason)
			}
		})
	}
}

func TestBuildAnalysisPrompt(t *testing.T) {
	files := []FileChange{
		{
			Filename:  "main.go",
			Additions: 2,
			Deletions: 1,
			Patch:     "@@ -10,3 +10,4 @@\n-// This is a test\n+// This is a test comment\n+// with more detail",
		},
	}

	prompt := buildAnalysisPrompt(files)
	
	if !strings.Contains(prompt, "main.go") {
		t.Error("prompt should contain filename")
	}
	if !strings.Contains(prompt, "Additions: 2, Deletions: 1") {
		t.Error("prompt should contain additions/deletions")
	}
	if !strings.Contains(prompt, "This is a test comment") {
		t.Error("prompt should contain patch content")
	}
	if !strings.Contains(prompt, "ALTERS_BEHAVIOR:") {
		t.Error("prompt should contain analysis instructions")
	}
}