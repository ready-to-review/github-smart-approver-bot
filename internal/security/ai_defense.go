// Package security provides AI security and defense mechanisms
package security

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// Maximum sizes to prevent resource exhaustion
	MaxTitleLength       = 500
	MaxDescriptionLength = 5000
	MaxPatchSize         = 50000
	MaxFileNameLength    = 500
	MaxTotalPromptSize   = 100000

	// Suspicious pattern thresholds
	MaxUnicodeComplexity = 0.1  // Max 10% non-ASCII characters
	MaxRepetitionRatio   = 0.3  // Max 30% repeated content
	MaxControlChars      = 10   // Max control characters allowed
)

// SanitizationResult contains the sanitized input and any security findings
type SanitizationResult struct {
	Sanitized      string
	ThreatDetected bool
	ThreatType     string
	ThreatDetails  []string
}

// AIDefense provides security measures against AI attacks
type AIDefense struct {
	enableLogging bool
	strictMode    bool
}

// NewAIDefense creates a new AI defense system
func NewAIDefense(strictMode bool) *AIDefense {
	return &AIDefense{
		enableLogging: true,
		strictMode:    strictMode,
	}
}

// SanitizePRTitle sanitizes and validates PR title
func (d *AIDefense) SanitizePRTitle(title string) SanitizationResult {
	result := SanitizationResult{Sanitized: title}

	// Check length
	if len(title) > MaxTitleLength {
		result.ThreatDetected = true
		result.ThreatType = "overflow"
		result.ThreatDetails = append(result.ThreatDetails, 
			fmt.Sprintf("Title exceeds maximum length: %d > %d", len(title), MaxTitleLength))
		title = title[:MaxTitleLength]
	}

	// Detect prompt injection attempts
	if threats := d.detectPromptInjection(title); len(threats) > 0 {
		result.ThreatDetected = true
		result.ThreatType = "prompt_injection"
		result.ThreatDetails = append(result.ThreatDetails, threats...)
		if d.strictMode {
			title = d.neutralizePromptInjection(title)
		}
	}

	// Remove control characters
	title = d.removeControlCharacters(title)

	// Check for suspicious Unicode patterns
	if d.hasSuspiciousUnicode(title) {
		result.ThreatDetected = true
		result.ThreatType = "unicode_attack"
		result.ThreatDetails = append(result.ThreatDetails, "Suspicious Unicode patterns detected")
		if d.strictMode {
			title = d.normalizeUnicode(title)
		}
	}

	result.Sanitized = strings.TrimSpace(title)
	return result
}

// SanitizePRDescription sanitizes and validates PR description
func (d *AIDefense) SanitizePRDescription(description string) SanitizationResult {
	result := SanitizationResult{Sanitized: description}

	// Check length
	if len(description) > MaxDescriptionLength {
		result.ThreatDetected = true
		result.ThreatType = "overflow"
		result.ThreatDetails = append(result.ThreatDetails,
			fmt.Sprintf("Description exceeds maximum length: %d > %d", len(description), MaxDescriptionLength))
		description = description[:MaxDescriptionLength]
	}

	// Detect prompt injection attempts
	if threats := d.detectPromptInjection(description); len(threats) > 0 {
		result.ThreatDetected = true
		result.ThreatType = "prompt_injection"
		result.ThreatDetails = append(result.ThreatDetails, threats...)
		if d.strictMode {
			description = d.neutralizePromptInjection(description)
		}
	}

	// Check for repetitive patterns (common in attacks)
	if d.hasRepetitivePatterns(description) {
		result.ThreatDetected = true
		result.ThreatType = "repetition_attack"
		result.ThreatDetails = append(result.ThreatDetails, "Excessive repetitive patterns detected")
	}

	result.Sanitized = strings.TrimSpace(description)
	return result
}

// SanitizePatch sanitizes and validates patch content
func (d *AIDefense) SanitizePatch(patch string, filename string) SanitizationResult {
	result := SanitizationResult{Sanitized: patch}

	// Check patch size
	if len(patch) > MaxPatchSize {
		result.ThreatDetected = true
		result.ThreatType = "overflow"
		result.ThreatDetails = append(result.ThreatDetails,
			fmt.Sprintf("Patch for %s exceeds maximum size: %d > %d", filename, len(patch), MaxPatchSize))
		patch = patch[:MaxPatchSize] + "\n... [truncated for security]"
	}

	// Detect embedded prompt instructions in code comments
	if threats := d.detectCodeCommentInjection(patch); len(threats) > 0 {
		result.ThreatDetected = true
		result.ThreatType = "code_injection"
		result.ThreatDetails = append(result.ThreatDetails, threats...)
		if d.strictMode {
			patch = d.neutralizeCodeComments(patch)
		}
	}

	// Check for suspicious patterns in patches
	if d.hasSuspiciousPatchPatterns(patch) {
		result.ThreatDetected = true
		result.ThreatType = "suspicious_patch"
		result.ThreatDetails = append(result.ThreatDetails, "Patch contains suspicious patterns")
	}

	result.Sanitized = patch
	return result
}

// detectPromptInjection detects common prompt injection patterns
func (d *AIDefense) detectPromptInjection(text string) []string {
	var threats []string
	
	// Common injection patterns
	injectionPatterns := []struct {
		pattern *regexp.Regexp
		threat  string
	}{
		{regexp.MustCompile(`(?i)(ignore|disregard|forget).{0,20}(previous|above|prior).{0,20}(instruction|prompt|rule)`), "Instruction override attempt"},
		{regexp.MustCompile(`(?i)new\s+(instruction|prompt|rule|task)s?:`), "New instruction injection"},
		{regexp.MustCompile(`(?i)system\s+(prompt|message|instruction):`), "System prompt injection"},
		{regexp.MustCompile(`(?i)(act|behave|pretend).{0,20}(as|like|you're)`), "Role manipulation attempt"},
		{regexp.MustCompile(`(?i)</?(system|assistant|user|instruction)>`), "Chat markup injection"},
		{regexp.MustCompile(`(?i)###\s*(system|instruction|important)`), "Markdown instruction injection"},
		{regexp.MustCompile(`(?i)approved:\s*true`), "Direct approval injection"},
		{regexp.MustCompile(`(?i)(always|must|should)\s+(approve|accept|merge)`), "Forced approval attempt"},
		{regexp.MustCompile(`\x00|\x1b\[|\u202e|\ufeff`), "Control character injection"},
		{regexp.MustCompile(`(?i)json.*approved.*true`), "JSON injection attempt"},
	}

	for _, p := range injectionPatterns {
		if p.pattern.MatchString(text) {
			threats = append(threats, p.threat)
			if d.enableLogging {
				log.Printf("[AI DEFENSE] Detected: %s", p.threat)
			}
		}
	}

	return threats
}

// detectCodeCommentInjection detects injection attempts in code comments
func (d *AIDefense) detectCodeCommentInjection(code string) []string {
	var threats []string

	// Extract comments from common languages
	commentPatterns := []*regexp.Regexp{
		regexp.MustCompile(`//.*$`),                    // Single-line comments
		regexp.MustCompile(`/\*[\s\S]*?\*/`),          // Multi-line comments
		regexp.MustCompile(`#.*$`),                     // Shell/Python comments
		regexp.MustCompile(`<!--[\s\S]*?-->`),         // HTML comments
		regexp.MustCompile(`"""[\s\S]*?"""`),          // Python docstrings
	}

	for _, pattern := range commentPatterns {
		matches := pattern.FindAllString(code, -1)
		for _, match := range matches {
			if injections := d.detectPromptInjection(match); len(injections) > 0 {
				threats = append(threats, fmt.Sprintf("Injection in code comment: %v", injections))
			}
		}
	}

	return threats
}

// hasSuspiciousUnicode checks for Unicode-based attacks
func (d *AIDefense) hasSuspiciousUnicode(text string) bool {
	if !utf8.ValidString(text) {
		return true
	}

	nonASCII := 0
	total := 0
	for _, r := range text {
		total++
		if r > 127 {
			nonASCII++
		}
		// Check for specific dangerous Unicode characters
		if r == '\u202e' || // Right-to-left override
			r == '\ufeff' || // Zero-width no-break space
			r == '\u200b' || // Zero-width space
			r == '\u2060' || // Word joiner
			(r >= '\ue000' && r <= '\uf8ff') { // Private use area
			return true
		}
	}

	// Check ratio of non-ASCII characters
	if total > 0 && float64(nonASCII)/float64(total) > MaxUnicodeComplexity {
		return true
	}

	return false
}

// hasRepetitivePatterns detects repetitive content (common in resource exhaustion attacks)
func (d *AIDefense) hasRepetitivePatterns(text string) bool {
	if len(text) < 100 {
		return false
	}

	// Create a simple hash map of substrings
	chunks := make(map[string]int)
	chunkSize := 20
	
	for i := 0; i <= len(text)-chunkSize; i += chunkSize/2 {
		end := i + chunkSize
		if end > len(text) {
			end = len(text)
		}
		chunk := text[i:end]
		chunks[chunk]++
	}

	// Check if any chunk appears too many times
	maxRepetitions := len(text) / chunkSize / 3 // Allow up to 1/3 repetition
	for _, count := range chunks {
		if count > maxRepetitions && count > 2 {
			return true
		}
	}

	return false
}

// hasSuspiciousPatchPatterns checks for suspicious patterns in patches
func (d *AIDefense) hasSuspiciousPatchPatterns(patch string) bool {
	suspiciousPatterns := []string{
		"APPROVE_ALL",
		"BYPASS_SECURITY",
		"DISABLE_CHECKS",
		"ALWAYS_MERGE",
		"SKIP_VALIDATION",
		"IGNORE_ERRORS",
	}

	upperPatch := strings.ToUpper(patch)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(upperPatch, pattern) {
			return true
		}
	}

	return false
}

// neutralizePromptInjection removes or escapes prompt injection attempts
func (d *AIDefense) neutralizePromptInjection(text string) string {
	// Replace dangerous patterns with safe versions
	replacements := map[string]string{
		"ignore previous": "[REDACTED-INJECTION]",
		"new instruction": "[REDACTED-INJECTION]",
		"system prompt":   "[REDACTED-INJECTION]",
		"###":            "---",
		"```":            "'''",
	}

	result := text
	for pattern, replacement := range replacements {
		result = strings.ReplaceAll(strings.ToLower(result), pattern, replacement)
	}

	return result
}

// neutralizeCodeComments removes potentially malicious comments
func (d *AIDefense) neutralizeCodeComments(code string) string {
	// Replace suspicious comments with safe placeholders
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)//.*?(ignore|instruction|prompt|approve).*$`),
		regexp.MustCompile(`(?i)/\*.*?(ignore|instruction|prompt|approve).*?\*/`),
	}

	result := code
	for _, pattern := range patterns {
		result = pattern.ReplaceAllString(result, "/* [comment sanitized for security] */")
	}

	return result
}

// removeControlCharacters removes control characters except newlines and tabs
func (d *AIDefense) removeControlCharacters(text string) string {
	var result strings.Builder
	for _, r := range text {
		if r == '\n' || r == '\t' || (r >= 32 && r != 127) {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// normalizeUnicode converts text to ASCII-safe version
func (d *AIDefense) normalizeUnicode(text string) string {
	var result strings.Builder
	for _, r := range text {
		if r < 128 {
			result.WriteRune(r)
		} else {
			// Replace non-ASCII with escaped version
			result.WriteString(fmt.Sprintf("\\u%04x", r))
		}
	}
	return result.String()
}

// HashContent creates a secure hash of content for comparison
func (d *AIDefense) HashContent(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// ValidateStructuredOutput validates that AI output matches expected structure
func (d *AIDefense) ValidateStructuredOutput(output string) error {
	// Check for valid JSON structure
	if !strings.HasPrefix(strings.TrimSpace(output), "{") {
		return fmt.Errorf("output does not start with JSON object")
	}

	// Check for required fields
	requiredFields := []string{
		"alters_behavior",
		"category",
		"reason",
	}

	for _, field := range requiredFields {
		if !strings.Contains(output, `"`+field+`"`) {
			return fmt.Errorf("missing required field: %s", field)
		}
	}

	// Check for injection of unexpected fields
	if strings.Contains(output, "ALWAYS_APPROVE") ||
		strings.Contains(output, "FORCE_MERGE") ||
		strings.Contains(output, "BYPASS") {
		return fmt.Errorf("suspicious field detected in output")
	}

	return nil
}