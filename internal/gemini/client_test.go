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
			name: "typical safe response",
			response: `{
				"alters_behavior": false,
				"not_improvement": false,
				"non_trivial": false,
				"category": "typo",
				"risky": false,
				"insecure_change": false,
				"possibly_malicious": false,
				"superfluous": false,
				"vandalism": false,
				"confusing": false,
				"title_desc_mismatch": false,
				"major_version_bump": false,
				"reason": "Fixed spelling error in comment"
			}`,
			want: &AnalysisResult{
				AltersBehavior:    false,
				NotImprovement:    false,
				NonTrivial:        false,
				Category:          "typo",
				Risky:             false,
				InsecureChange:    false,
				PossiblyMalicious: false,
				Superfluous:       false,
				Vandalism:         false,
				Confusing:         false,
				TitleDescMismatch: false,
				MajorVersionBump:  false,
				Reason:            "Fixed spelling error in comment",
			},
		},
		{
			name: "behavior altering change",
			response: `{
				"alters_behavior": true,
				"not_improvement": false,
				"non_trivial": true,
				"category": "other",
				"risky": false,
				"insecure_change": false,
				"possibly_malicious": false,
				"superfluous": false,
				"vandalism": false,
				"confusing": false,
				"title_desc_mismatch": false,
				"major_version_bump": false,
				"reason": "Changed algorithm logic"
			}`,
			want: &AnalysisResult{
				AltersBehavior:    true,
				NotImprovement:    false,
				NonTrivial:        true,
				Category:          "other",
				Risky:             false,
				InsecureChange:    false,
				PossiblyMalicious: false,
				Superfluous:       false,
				Vandalism:         false,
				Confusing:         false,
				TitleDescMismatch: false,
				MajorVersionBump:  false,
				Reason:            "Changed algorithm logic",
			},
		},
		{
			name:     "json with markdown wrapper",
			response: "```json\n{\"alters_behavior\":false,\"not_improvement\":false,\"non_trivial\":false,\"category\":\"comment\",\"risky\":false,\"insecure_change\":false,\"possibly_malicious\":false,\"superfluous\":false,\"vandalism\":false,\"confusing\":false,\"title_desc_mismatch\":false,\"major_version_bump\":false,\"reason\":\"Added clarifying comment\"}\n```",
			want: &AnalysisResult{
				AltersBehavior:    false,
				NotImprovement:    false,
				NonTrivial:        false,
				Category:          "comment",
				Risky:             false,
				InsecureChange:    false,
				PossiblyMalicious: false,
				Superfluous:       false,
				Vandalism:         false,
				Confusing:         false,
				TitleDescMismatch: false,
				MajorVersionBump:  false,
				Reason:            "Added clarifying comment",
			},
		},
		{
			name: "security concerns",
			response: `{
				"alters_behavior": true,
				"not_improvement": true,
				"non_trivial": true,
				"category": "other",
				"risky": true,
				"insecure_change": true,
				"possibly_malicious": true,
				"superfluous": false,
				"vandalism": true,
				"confusing": false,
				"title_desc_mismatch": false,
				"major_version_bump": false,
				"reason": "Suspicious code that appears to add a backdoor"
			}`,
			want: &AnalysisResult{
				AltersBehavior:    true,
				NotImprovement:    true,
				NonTrivial:        true,
				Category:          "other",
				Risky:             true,
				InsecureChange:    true,
				PossiblyMalicious: true,
				Superfluous:       false,
				Vandalism:         true,
				Confusing:         false,
				TitleDescMismatch: false,
				MajorVersionBump:  false,
				Reason:            "Suspicious code that appears to add a backdoor",
			},
		},
		{
			name: "major version bump",
			response: `{
				"alters_behavior": true,
				"not_improvement": false,
				"non_trivial": true,
				"category": "dependency",
				"risky": true,
				"insecure_change": false,
				"possibly_malicious": false,
				"superfluous": false,
				"vandalism": false,
				"confusing": false,
				"title_desc_mismatch": false,
				"major_version_bump": true,
				"reason": "Updates React from v17 to v18 with breaking changes"
			}`,
			want: &AnalysisResult{
				AltersBehavior:    true,
				NotImprovement:    false,
				NonTrivial:        true,
				Category:          "dependency",
				Risky:             true,
				InsecureChange:    false,
				PossiblyMalicious: false,
				Superfluous:       false,
				Vandalism:         false,
				Confusing:         false,
				TitleDescMismatch: false,
				MajorVersionBump:  true,
				Reason:            "Updates React from v17 to v18 with breaking changes",
			},
		},
		{
			name:     "invalid JSON returns conservative defaults",
			response: "This is not valid JSON",
			want: &AnalysisResult{
				AltersBehavior:    true,
				NotImprovement:    true,
				NonTrivial:        true,
				Category:          "",
				Risky:             true,
				InsecureChange:    false,
				PossiblyMalicious: false,
				Superfluous:       true,
				Vandalism:         false,
				Confusing:         true,
				TitleDescMismatch: true,
				MajorVersionBump:  true,
				Reason:            "Failed to parse Gemini response: failed to parse Gemini JSON response: invalid character 'T' looking for beginning of value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAnalysisResponse(tt.response)
			if err != nil {
				t.Errorf("parseAnalysisResponse() error = %v", err)
				return
			}
			if got == nil {
				t.Fatal("parseAnalysisResponse() returned nil")
			}

			if got.AltersBehavior != tt.want.AltersBehavior {
				t.Errorf("AltersBehavior = %v, want %v", got.AltersBehavior, tt.want.AltersBehavior)
			}
			if got.NotImprovement != tt.want.NotImprovement {
				t.Errorf("NotImprovement = %v, want %v", got.NotImprovement, tt.want.NotImprovement)
			}
			if got.NonTrivial != tt.want.NonTrivial {
				t.Errorf("NonTrivial = %v, want %v", got.NonTrivial, tt.want.NonTrivial)
			}
			if got.Category != tt.want.Category {
				t.Errorf("Category = %v, want %v", got.Category, tt.want.Category)
			}
			if got.Risky != tt.want.Risky {
				t.Errorf("Risky = %v, want %v", got.Risky, tt.want.Risky)
			}
			if got.InsecureChange != tt.want.InsecureChange {
				t.Errorf("InsecureChange = %v, want %v", got.InsecureChange, tt.want.InsecureChange)
			}
			if got.PossiblyMalicious != tt.want.PossiblyMalicious {
				t.Errorf("PossiblyMalicious = %v, want %v", got.PossiblyMalicious, tt.want.PossiblyMalicious)
			}
			if got.Superfluous != tt.want.Superfluous {
				t.Errorf("Superfluous = %v, want %v", got.Superfluous, tt.want.Superfluous)
			}
			if got.Vandalism != tt.want.Vandalism {
				t.Errorf("Vandalism = %v, want %v", got.Vandalism, tt.want.Vandalism)
			}
			if got.Confusing != tt.want.Confusing {
				t.Errorf("Confusing = %v, want %v", got.Confusing, tt.want.Confusing)
			}
			if got.TitleDescMismatch != tt.want.TitleDescMismatch {
				t.Errorf("TitleDescMismatch = %v, want %v", got.TitleDescMismatch, tt.want.TitleDescMismatch)
			}
			if got.MajorVersionBump != tt.want.MajorVersionBump {
				t.Errorf("MajorVersionBump = %v, want %v", got.MajorVersionBump, tt.want.MajorVersionBump)
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
			Patch:     "@@ -1,5 +1,5 @@\n-func main() {\n+func Main() {\n     fmt.Println(\"Hello\")\n }",
			Additions: 1,
			Deletions: 1,
		},
	}

	prContext := PRContext{
		Title:             "Fix typo",
		Description:       "Fixed function name",
		Author:            "testuser",
		AuthorAssociation: "CONTRIBUTOR",
		Organization:      "testorg",
		Repository:        "testrepo",
		PullRequestNumber: 123,
		URL:               "https://github.com/testorg/testrepo/pull/123",
	}

	prompt := buildAnalysisPrompt(files, prContext)

	// Check that prompt contains expected elements
	if !strings.Contains(prompt, "PR Title: Fix typo") {
		t.Errorf("Prompt missing PR title")
	}
	if !strings.Contains(prompt, "PR Description: Fixed function name") {
		t.Errorf("Prompt missing PR description")
	}
	if !strings.Contains(prompt, "PR Author: testuser") {
		t.Errorf("Prompt missing PR author")
	}
	if !strings.Contains(prompt, "Author Association: CONTRIBUTOR") {
		t.Errorf("Prompt missing author association")
	}
	if !strings.Contains(prompt, "Repository: testorg/testrepo") {
		t.Errorf("Prompt missing repository")
	}
	if !strings.Contains(prompt, "PR URL: https://github.com/testorg/testrepo/pull/123") {
		t.Errorf("Prompt missing PR URL")
	}
	if !strings.Contains(prompt, "File: main.go") {
		t.Errorf("Prompt missing file name")
	}
	if !strings.Contains(prompt, "Additions: 1, Deletions: 1") {
		t.Errorf("Prompt missing additions/deletions")
	}
	if !strings.Contains(prompt, "@@ -1,5 +1,5 @@") {
		t.Errorf("Prompt missing patch content")
	}
	if !strings.Contains(prompt, "Return ONLY this JSON") || !strings.Contains(prompt, "major_version_bump") {
		t.Errorf("Prompt missing JSON format instructions with major_version_bump field")
	}
}

func TestCleanJSONResponse(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain json",
			input:    `{"key": "value"}`,
			expected: `{"key": "value"}`,
		},
		{
			name:     "json with markdown wrapper",
			input:    "```json\n{\"key\": \"value\"}\n```",
			expected: `{"key": "value"}`,
		},
		{
			name:     "json with plain code block",
			input:    "```\n{\"key\": \"value\"}\n```",
			expected: `{"key": "value"}`,
		},
		{
			name:     "json with whitespace",
			input:    "  \n  {\"key\": \"value\"}  \n  ",
			expected: `{"key": "value"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanJSONResponse(tt.input)
			if got != tt.expected {
				t.Errorf("cleanJSONResponse() = %q, want %q", got, tt.expected)
			}
		})
	}
}
