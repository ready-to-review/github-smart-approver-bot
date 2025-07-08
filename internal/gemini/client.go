package gemini

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/google/generative-ai-go/genai"
	"github.com/thegroove/trivial-auto-approve/internal/errors"
	"github.com/thegroove/trivial-auto-approve/internal/retry"
	"google.golang.org/api/option"
)

// Client implements the API interface for Gemini operations.
type Client struct {
	client *genai.Client
	model  *genai.GenerativeModel
}

// ensure Client implements API interface
var _ API = (*Client)(nil)

// NewClient creates a new Gemini client.
func NewClient(ctx context.Context) (*Client, error) {
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		return nil, errors.ErrNoGeminiKey
	}

	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return nil, &errors.APIError{
			Service: "Gemini",
			Method:  "NewClient",
			Err:     err,
		}
	}

	// Use Gemini 2.0 Flash as specified
	model := client.GenerativeModel("gemini-2.0-flash")
	
	// Configure model for code analysis
	model.SetTemperature(0.1) // Low temperature for more deterministic responses
	model.SystemInstruction = genai.NewUserContent(genai.Text(systemPrompt))

	return &Client{
		client: client,
		model:  model,
	}, nil
}

// Close closes the Gemini client.
func (c *Client) Close() error {
	return c.client.Close()
}

// AnalyzePRChanges analyzes PR changes to determine if they alter behavior.
func (c *Client) AnalyzePRChanges(ctx context.Context, files []FileChange) (*AnalysisResult, error) {
	prompt := buildAnalysisPrompt(files)
	
	var resp *genai.GenerateContentResponse
	err := retry.Do(ctx, 3, func() error {
		var err error
		resp, err = c.model.GenerateContent(ctx, genai.Text(prompt))
		if err != nil && retry.IsRetryable(err) {
			return err
		} else if err != nil {
			return &errors.APIError{
				Service: "Gemini",
				Method:  "GenerateContent",
				Err:     err,
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(resp.Candidates) == 0 {
		return nil, fmt.Errorf("no response candidates")
	}

	content := resp.Candidates[0].Content
	if content == nil || len(content.Parts) == 0 {
		return nil, fmt.Errorf("empty response content")
	}

	text := fmt.Sprintf("%v", content.Parts[0])
	return parseAnalysisResponse(text)
}

// FileChange represents a file change in a PR.
type FileChange struct {
	Filename string
	Patch    string
	Additions int
	Deletions int
}

// AnalysisResult represents the result of PR analysis.
type AnalysisResult struct {
	AltersBehavior bool
	IsImprovement  bool
	Reason         string
	IsTrivial      bool
	Category       string // "typo", "comment", "markdown", "lint", etc.
}

const systemPrompt = `You are a code review assistant analyzing pull request changes.
Your task is to determine:
1. Whether the changes alter the behavior of the application
2. Whether the changes represent an improvement
3. Whether the changes are trivial (typos, comments, markdown, lint fixes)

Analyze conservatively - if unsure, assume the change alters behavior.
Focus on semantic changes, not just syntactic ones.

Respond in a structured format.`

var analysisPromptTemplate = template.Must(template.New("analysis").Parse(`
Analyze the following pull request changes:

{{range .Files}}
File: {{.Filename}}
Additions: {{.Additions}}, Deletions: {{.Deletions}}
Patch:
` + "```" + `
{{.Patch}}
` + "```" + `

{{end}}
Please analyze these changes and respond with:
1. ALTERS_BEHAVIOR: YES/NO
2. IS_IMPROVEMENT: YES/NO
3. IS_TRIVIAL: YES/NO
4. CATEGORY: typo/comment/markdown/lint/other
5. REASON: Brief explanation of your analysis
`))

func buildAnalysisPrompt(files []FileChange) string {
	var sb strings.Builder
	data := struct {
		Files []FileChange
	}{
		Files: files,
	}
	
	if err := analysisPromptTemplate.Execute(&sb, data); err != nil {
		// Fallback to simple format if template fails
		sb.Reset()
		sb.WriteString("Analyze the following pull request changes:\n\n")
		for _, file := range files {
			sb.WriteString(fmt.Sprintf("File: %s\n", file.Filename))
			sb.WriteString(fmt.Sprintf("Additions: %d, Deletions: %d\n", file.Additions, file.Deletions))
			sb.WriteString("Patch:\n```\n")
			sb.WriteString(file.Patch)
			sb.WriteString("\n```\n\n")
		}
		sb.WriteString("\nPlease analyze these changes and respond with:\n")
		sb.WriteString("1. ALTERS_BEHAVIOR: YES/NO\n")
		sb.WriteString("2. IS_IMPROVEMENT: YES/NO\n")
		sb.WriteString("3. IS_TRIVIAL: YES/NO\n")
		sb.WriteString("4. CATEGORY: typo/comment/markdown/lint/other\n")
		sb.WriteString("5. REASON: Brief explanation of your analysis\n")
	}
	
	return sb.String()
}

func parseAnalysisResponse(response string) (*AnalysisResult, error) {
	result := &AnalysisResult{}
	
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ALTERS_BEHAVIOR:") {
			result.AltersBehavior = strings.Contains(strings.ToUpper(line), "YES")
		} else if strings.HasPrefix(line, "IS_IMPROVEMENT:") {
			result.IsImprovement = strings.Contains(strings.ToUpper(line), "YES")
		} else if strings.HasPrefix(line, "IS_TRIVIAL:") {
			result.IsTrivial = strings.Contains(strings.ToUpper(line), "YES")
		} else if strings.HasPrefix(line, "CATEGORY:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.Category = strings.TrimSpace(strings.ToLower(parts[1]))
			}
		} else if strings.HasPrefix(line, "REASON:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				result.Reason = strings.TrimSpace(parts[1])
			}
		}
	}
	
	return result, nil
}