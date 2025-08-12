package gemini

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"text/template"

	"github.com/google/generative-ai-go/genai"
	"github.com/thegroove/trivial-auto-approve/internal/constants"
	"github.com/thegroove/trivial-auto-approve/internal/errors"
	"github.com/thegroove/trivial-auto-approve/internal/retry"
	"github.com/thegroove/trivial-auto-approve/internal/security"
	"google.golang.org/api/option"
)

// Client implements the API interface for Gemini operations.
type Client struct {
	client     *genai.Client
	model      *genai.GenerativeModel
	debug      bool
	defense    *security.AIDefense
	validator  *security.ResponseValidator
}

// ensure Client implements API interface.
var _ API = (*Client)(nil)

// NewClient creates a new Gemini client with the specified model.
func NewClient(ctx context.Context, modelName string, debug bool) (*Client, error) {
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		return nil, errors.ErrNoGeminiKey
	}

	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return nil, errors.API("Gemini", "NewClient", err)
	}

	// Use the specified model
	model := client.GenerativeModel(modelName)

	// Configure model for code analysis
	model.SetTemperature(0.0) // Zero temperature for fastest, most deterministic responses
	model.SystemInstruction = genai.NewUserContent(genai.Text(systemPrompt))

	// Set generation config for faster responses
	model.GenerationConfig.MaxOutputTokens = genai.Ptr[int32](500) // Limit output size
	model.GenerationConfig.TopK = genai.Ptr[int32](1)              // Most deterministic
	model.GenerationConfig.TopP = genai.Ptr[float32](0.1)          // Narrow sampling

	return &Client{
		client:    client,
		model:     model,
		debug:     debug,
		defense:   security.NewAIDefense(true), // Enable strict mode
		validator: security.NewResponseValidator(),
	}, nil
}

// AnalyzeText analyzes raw text for behavior changes (used by multi-model)
func (c *Client) AnalyzeText(ctx context.Context, prompt string) (*AnalysisResult, error) {
	// For simple text analysis, just use the prompt directly
	// The defense mechanisms are already applied in AnalyzePRChanges
	
	// Generate content from the model
	resp, err := c.model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return nil, errors.API("Gemini", "GenerateContent", err)
	}
	
	if len(resp.Candidates) == 0 {
		return nil, fmt.Errorf("Gemini API returned no response candidates")
	}

	content := resp.Candidates[0].Content
	if content == nil || len(content.Parts) == 0 {
		return nil, fmt.Errorf("Gemini API returned empty response content")
	}

	text := fmt.Sprintf("%v", content.Parts[0])
	
	// Parse the response
	result, err := parseAnalysisResponse(text)
	if err != nil {
		return nil, err
	}
	
	// Set default confidence
	result.Confidence = 0.9 // Default high confidence
	
	return result, nil
}

// Close closes the Gemini client.
func (c *Client) Close() error {
	return c.client.Close()
}

// AnalyzePRChanges analyzes PR changes to determine if they alter behavior.
func (c *Client) AnalyzePRChanges(ctx context.Context, files []FileChange, prContext PRContext) (*AnalysisResult, error) {
	// Sanitize inputs before building prompt
	sanitizedContext := c.sanitizePRContext(prContext)
	sanitizedFiles := c.sanitizeFileChanges(files)
	
	// Check for security threats
	if c.detectThreats(sanitizedContext, sanitizedFiles) {
		log.Printf("[GEMINI] Security threat detected in PR content, returning conservative result")
		return &AnalysisResult{
			AltersBehavior:    true,
			PossiblyMalicious: true,
			Risky:            true,
			Category:         "suspicious",
			Reason:           "Security threat detected in PR content",
		}, nil
	}
	
	prompt := buildAnalysisPrompt(sanitizedFiles, sanitizedContext)

	if c.debug {
		log.Println("\n=== DEBUG: Gemini Request Summary ===")
		log.Printf("Prompt length: %d characters", len(prompt))
		log.Printf("Number of files analyzed: %d", len(sanitizedFiles))
		// Security: Don't log the full prompt in production as it contains code
		// Only log first 200 chars for debugging if needed
		if len(prompt) > 200 {
			log.Printf("Prompt preview: %s...", prompt[:200])
		} else {
			log.Printf("Prompt preview: %s", prompt)
		}
		log.Println("=== END Gemini Request Summary ===")
	}

	var resp *genai.GenerateContentResponse
	err := retry.Do(ctx, constants.MaxRetryAttempts, retry.WithRetryableCheck(
		func() error {
			var err error
			resp, err = c.model.GenerateContent(ctx, genai.Text(prompt))
			return err
		},
		func(err error) error {
			return errors.API("Gemini", "GenerateContent", err)
		},
	))
	if err != nil {
		return nil, err
	}

	if len(resp.Candidates) == 0 {
		return nil, fmt.Errorf("Gemini API returned no response candidates for PR analysis")
	}

	content := resp.Candidates[0].Content
	if content == nil || len(content.Parts) == 0 {
		return nil, fmt.Errorf("Gemini API returned empty response content for PR analysis")
	}

	text := fmt.Sprintf("%v", content.Parts[0])

	if c.debug {
		log.Println("\n=== DEBUG: Gemini Response ===")
		log.Println(text)
		log.Println("=== END Gemini Response ===")
	}

	// Validate response structure
	if err := c.validator.ValidateResponse(text); err != nil {
		log.Printf("[GEMINI] Invalid response structure: %v", err)
		return conservativeDefaults(err), nil
	}

	return parseAnalysisResponse(text)
}

// FileChange represents a file change in a PR with patch content and modification statistics.
type FileChange struct {
	Filename  string
	Patch     string
	Additions int
	Deletions int
}

// AnalysisResult represents the result of AI-powered PR analysis for behavior and triviality detection.
type AnalysisResult struct {
	Reason            string  // Analysis reason/explanation
	Category          string  // "typo", "comment", "markdown", "lint", etc.
	AltersBehavior    bool
	NotImprovement    bool    // True if change is NOT an improvement
	NonTrivial        bool    // True if change is NOT trivial
	Risky             bool    // True if change is high risk
	InsecureChange    bool    // True if may introduce security problems
	PossiblyMalicious bool    // True if change appears malicious
	Superfluous       bool    // True if change is unnecessary/redundant
	Vandalism         bool    // True if change is destructive/harmful
	Confidence        float64 // Confidence level of the analysis (0.0-1.0)
	Confusing         bool // True if change reduces clarity
	TitleDescMismatch bool // True if title/description doesn't match diff
	MajorVersionBump  bool // True if change includes major version bump
}

const systemPrompt = `You are a skeptical and critical software engineer analyzing open-source pull request changes for security and quality.
Your task is to evaluate multiple aspects of the changes:

1. Behavior: Does this alter application behavior?
2. Improvement: Is this change an improvement or just garbage?
3. Triviality: Is this a trivial change (typo, comment, formatting, minor dependency update, security fix, or version bump)?
4. Risk Level: Is this a low-risk change?
5. Security: Could this introduce security vulnerabilities?
6. Maliciousness: Could this be a malicious change?
7. Necessity: Is this change useful (not superfluous)?
8. Vandalism: Could this be vandalism or destructive?
9. Clarity: Could this introduce confusion or reduce code clarity?
10. Accuracy: Is the PR title/description useful and accurately represent the changes?
11. Major Version Bump: Does this include a major version bump in any dependency?

For dependency updates, pay special attention to version changes:
- Major version bumps (e.g., v1.x.x to v2.x.x) often include breaking changes
- Minor and patch updates are typically safer
- Check package.json, go.mod, pom.xml, requirements.txt, Gemfile, etc.

IMPORTANT: For PRs by dependabot[bot]:
- Dependency updates that are NOT major version bumps should be marked as alters_behavior: false
- Only major version bumps from dependabot[bot] should be marked as alters_behavior: true
- Minor and patch version updates from dependabot[bot] do not alter application behavior

Analyze conservatively - when in doubt:
- Assume higher risk, unless the PR is by dependabot[bot]
- Flag potential security issues
- Flag suspicious or unnecessary changes
- Minor or patch-level updates to dependencies should be considered trivial and not behavior changing
- Major version bumps should always be flagged

Focus on the actual impact and intent of changes, not just syntax.

Pull requests by dependabot[bot] are normally low risk, trivial, dependency changes that do not alter program behavior unless the major version changes.
`

var analysisPromptTemplate = template.Must(template.New("analysis").Parse(`
Analyze the following pull request:

PR URL: {{.Context.URL}}
PR Title: {{.Context.Title}}
PR Description: {{.Context.Description}}
PR Author: {{.Context.Author}}
Author Association: {{.Context.AuthorAssociation}}
Repository: {{.Context.Organization}}/{{.Context.Repository}}

Changes:
{{range .Files}}
File: {{.Filename}}
Additions: {{.Additions}}, Deletions: {{.Deletions}}
Patch:
` + "```" + `
{{.Patch}}
` + "```" + `

{{end}}
Return ONLY this JSON (set flags to true only if they apply, false is default):
{"alters_behavior":bool,"not_improvement":bool,"non_trivial":bool,"category":"typo|comment|markdown|lint|dependency|config|refactor|bugfix|feature|other","risky":bool,"insecure_change":bool,"possibly_malicious":bool,"superfluous":bool,"vandalism":bool,"confusing":bool,"title_desc_mismatch":bool,"major_version_bump":bool,"reason":"brief explanation"}
`))

func buildAnalysisPrompt(files []FileChange, prContext PRContext) string {
	var sb strings.Builder
	data := struct {
		Context PRContext
		Files   []FileChange
	}{
		Context: prContext,
		Files:   files,
	}

	if err := analysisPromptTemplate.Execute(&sb, data); err != nil {
		// Fallback to manual formatting
		return buildManualPrompt(files, prContext)
	}

	return sb.String()
}

// buildManualPrompt creates prompt without template.
func buildManualPrompt(files []FileChange, prContext PRContext) string {
	var sb strings.Builder

	sb.WriteString("Analyze the following pull request:\n\n")
	sb.WriteString(fmt.Sprintf("PR URL: %s\n", prContext.URL))
	sb.WriteString(fmt.Sprintf("PR Title: %s\n", prContext.Title))
	sb.WriteString(fmt.Sprintf("PR Description: %s\n", prContext.Description))
	sb.WriteString(fmt.Sprintf("PR Author: %s\n", prContext.Author))
	sb.WriteString(fmt.Sprintf("Author Association: %s\n", prContext.AuthorAssociation))
	sb.WriteString(fmt.Sprintf("Repository: %s/%s\n\n", prContext.Organization, prContext.Repository))
	sb.WriteString("Changes:\n")

	for _, file := range files {
		sb.WriteString(fmt.Sprintf("File: %s\n", file.Filename))
		sb.WriteString(fmt.Sprintf("Additions: %d, Deletions: %d\n", file.Additions, file.Deletions))
		sb.WriteString("Patch:\n```\n")
		sb.WriteString(file.Patch)
		sb.WriteString("\n```\n\n")
	}

	sb.WriteString("\nPlease analyze these changes and respond with a JSON object containing the following fields:\n")
	sb.WriteString(`{
  "alters_behavior": boolean,
  "not_improvement": boolean,
  "non_trivial": boolean,
  "category": string,
  "risky": boolean,
  "insecure_change": boolean,
  "possibly_malicious": boolean,
  "superfluous": boolean,
  "vandalism": boolean,
  "confusing": boolean,
  "title_desc_mismatch": boolean,
  "major_version_bump": boolean,
  "reason": string
}
Return ONLY the JSON object, no additional text.`)

	return sb.String()
}

// jsonResponse is the structure we expect from Gemini.
type jsonResponse struct {
	AltersBehavior    bool   `json:"alters_behavior"`
	NotImprovement    bool   `json:"not_improvement"`
	NonTrivial        bool   `json:"non_trivial"`
	Category          string `json:"category"`
	Risky             bool   `json:"risky"`
	InsecureChange    bool   `json:"insecure_change"`
	PossiblyMalicious bool   `json:"possibly_malicious"`
	Superfluous       bool   `json:"superfluous"`
	Vandalism         bool   `json:"vandalism"`
	Confusing         bool   `json:"confusing"`
	TitleDescMismatch bool   `json:"title_desc_mismatch"`
	MajorVersionBump  bool   `json:"major_version_bump"`
	Reason            string `json:"reason"`
}

func parseAnalysisResponse(response string) (*AnalysisResult, error) {
	// Clean up response
	response = cleanJSONResponse(response)

	// Try to parse JSON
	var jsonResp jsonResponse
	if err := json.Unmarshal([]byte(response), &jsonResp); err != nil {
		// Return conservative defaults on parse failure
		return conservativeDefaults(fmt.Errorf("failed to parse Gemini JSON response: %w", err)), nil
	}

	return jsonResponseToResult(&jsonResp), nil
}

// cleanJSONResponse removes markdown code blocks from response.
func cleanJSONResponse(response string) string {
	response = strings.TrimSpace(response)

	// Remove markdown code blocks
	if strings.HasPrefix(response, "```json") {
		response = strings.TrimPrefix(response, "```json")
		response = strings.TrimSuffix(response, "```")
	} else if strings.HasPrefix(response, "```") {
		response = strings.TrimPrefix(response, "```")
		response = strings.TrimSuffix(response, "```")
	}

	return strings.TrimSpace(response)
}

// jsonResponseToResult converts JSON response to AnalysisResult.
func jsonResponseToResult(resp *jsonResponse) *AnalysisResult {
	return &AnalysisResult{
		AltersBehavior:    resp.AltersBehavior,
		NotImprovement:    resp.NotImprovement,
		NonTrivial:        resp.NonTrivial,
		Category:          resp.Category,
		Risky:             resp.Risky,
		InsecureChange:    resp.InsecureChange,
		PossiblyMalicious: resp.PossiblyMalicious,
		Superfluous:       resp.Superfluous,
		Vandalism:         resp.Vandalism,
		Confusing:         resp.Confusing,
		TitleDescMismatch: resp.TitleDescMismatch,
		MajorVersionBump:  resp.MajorVersionBump,
		Reason:            resp.Reason,
	}
}

// conservativeDefaults returns safe defaults that will reject the PR.
func conservativeDefaults(err error) *AnalysisResult {
	return &AnalysisResult{
		AltersBehavior:    true,  // Assume it alters behavior
		NotImprovement:    true,  // Assume it's not an improvement
		NonTrivial:        true,  // Assume it's non-trivial
		Risky:             true,  // Assume it's risky
		InsecureChange:    false, // Don't falsely accuse of security issues
		PossiblyMalicious: false, // Don't falsely accuse of malicious intent
		Superfluous:       true,  // Assume it's unnecessary
		Vandalism:         false, // Don't falsely accuse of vandalism
		Confusing:         true,  // Assume it's confusing
		TitleDescMismatch: true,  // Assume mismatch
		MajorVersionBump:  true,  // Assume major version bump (safer)
		Category:          "",    // No category = will be rejected
		Reason:            fmt.Sprintf("Failed to parse Gemini response: %v", err),
	}
}

// sanitizePRContext sanitizes PR context for security
func (c *Client) sanitizePRContext(ctx PRContext) PRContext {
	titleResult := c.defense.SanitizePRTitle(ctx.Title)
	descResult := c.defense.SanitizePRDescription(ctx.Description)
	
	if titleResult.ThreatDetected || descResult.ThreatDetected {
		log.Printf("[GEMINI] Security threats detected in PR metadata")
		if titleResult.ThreatDetected {
			log.Printf("[GEMINI]   Title: %v", titleResult.ThreatDetails)
		}
		if descResult.ThreatDetected {
			log.Printf("[GEMINI]   Description: %v", descResult.ThreatDetails)
		}
	}
	
	return PRContext{
		URL:               ctx.URL,
		Title:             titleResult.Sanitized,
		Description:       descResult.Sanitized,
		Author:            ctx.Author,
		AuthorAssociation: ctx.AuthorAssociation,
		Organization:      ctx.Organization,
		Repository:        ctx.Repository,
	}
}

// sanitizeFileChanges sanitizes file changes for security
func (c *Client) sanitizeFileChanges(files []FileChange) []FileChange {
	sanitized := make([]FileChange, 0, len(files))
	
	for _, file := range files {
		patchResult := c.defense.SanitizePatch(file.Patch, file.Filename)
		
		if patchResult.ThreatDetected {
			log.Printf("[GEMINI] Security threat in patch for %s: %v", 
				file.Filename, patchResult.ThreatDetails)
		}
		
		sanitized = append(sanitized, FileChange{
			Filename:  file.Filename,
			Patch:     patchResult.Sanitized,
			Additions: file.Additions,
			Deletions: file.Deletions,
		})
	}
	
	return sanitized
}

// detectThreats checks if any sanitization detected threats
func (c *Client) detectThreats(ctx PRContext, files []FileChange) bool {
	// Re-check context for threats
	titleResult := c.defense.SanitizePRTitle(ctx.Title)
	descResult := c.defense.SanitizePRDescription(ctx.Description)
	
	if titleResult.ThreatDetected || descResult.ThreatDetected {
		return true
	}
	
	// Check patches
	for _, file := range files {
		patchResult := c.defense.SanitizePatch(file.Patch, file.Filename)
		if patchResult.ThreatDetected {
			return true
		}
	}
	
	return false
}
