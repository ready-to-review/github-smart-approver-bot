// Package security provides code change validation for security
package security

import (
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"strings"
)

// CodeValidator validates code changes for security risks
type CodeValidator struct {
	strictMode bool
}

// NewCodeValidator creates a new code validator
func NewCodeValidator(strictMode bool) *CodeValidator {
	return &CodeValidator{
		strictMode: strictMode,
	}
}

// ShellControlCharacters that pose security risks
var ShellControlCharacters = map[rune]string{
	'\'': "single quote (command injection risk)",
	'"':  "double quote (command injection risk)",
	'`':  "backtick (command substitution)",
	'$':  "dollar sign (variable expansion)",
	'|':  "pipe (command chaining)",
	'&':  "ampersand (background execution)",
	';':  "semicolon (command separator)",
	'>':  "redirect output",
	'<':  "redirect input",
	'\\': "escape character",
	'\n': "newline (command injection)",
	'\r': "carriage return (command injection)",
	// Note: '\t' (tab) removed as it's normal in many files like go.mod, Makefiles, etc.
	'*':  "glob wildcard",
	'?':  "glob single char",
	'{':  "brace expansion",
	'}':  "brace expansion",
	'~':  "home directory expansion",
}

// DangerousPatterns in various file types
var DangerousPatterns = map[string][]*regexp.Regexp{
	"yaml": {
		regexp.MustCompile(`(?m)^\s*-?\s*(script|run|command|cmd|exec|shell):\s*(.+)`),
		regexp.MustCompile(`\$\{\{.*\}\}`),                      // GitHub Actions expressions
		regexp.MustCompile(`\$\(.*\)`),                          // Command substitution
		regexp.MustCompile(`&&|\|\|`),                           // Shell operators
		regexp.MustCompile(`(?i)(curl|wget|bash|sh|eval|exec)`), // Dangerous commands
	},
	"json": {
		regexp.MustCompile(`"(script|command|cmd|exec|shell)"\s*:\s*"([^"]*[|;&<>` + "`" + `][^"]*)"`),
		regexp.MustCompile(`\$\(.*\)`),
	},
	"dockerfile": {
		regexp.MustCompile(`(?i)^RUN\s+.*[|;&]`),
		regexp.MustCompile(`(?i)^CMD\s+.*[|;&]`),
		regexp.MustCompile(`(?i)^ENTRYPOINT\s+.*[|;&]`),
		regexp.MustCompile(`curl.*\|\s*(bash|sh)`), // Curl pipe to shell
	},
	"makefile": {
		regexp.MustCompile(`\$\(shell.*\)`),
		regexp.MustCompile(`@.*[|;&]`),
	},
	"github_workflow": {
		regexp.MustCompile(`run:\s*\|`),                         // Multi-line run commands
		regexp.MustCompile(`\$\{\{.*github\.event\..*\}\}`),     // Untrusted input
		regexp.MustCompile(`\$\{\{.*inputs\..*\}\}`),            // User inputs
		regexp.MustCompile(`\$\{\{.*issue\.title.*\}\}`),        // Issue title injection
		regexp.MustCompile(`\$\{\{.*issue\.body.*\}\}`),         // Issue body injection
		regexp.MustCompile(`\$\{\{.*pull_request\.title.*\}\}`), // PR title injection
	},
}

// FileTypeConfig defines validation rules for different file types
type FileTypeConfig struct {
	IsCode              bool
	IsConfig            bool
	IsMarkdown          bool
	AllowApostrophes    bool
	MaxLineLength       int
	ForbiddenCharacters map[rune]bool
}

// GetFileTypeConfig returns configuration for a file type
func GetFileTypeConfig(filename string) FileTypeConfig {
	ext := strings.ToLower(filepath.Ext(filename))
	base := strings.ToLower(filepath.Base(filename))
	
	// Check for specific config files
	configFiles := map[string]bool{
		"dockerfile":         true,
		"makefile":          true,
		"gemfile":           true,
		"package.json":      true,
		"package-lock.json": true,
		"requirements.txt":  true,
		"pom.xml":          true,
		"build.gradle":     true,
		".dockerignore":    true,
		"docker-compose.yml": true,
		"docker-compose.yaml": true,
	}
	
	// Go files have special handling
	goFiles := map[string]bool{
		"go.mod": true,
		"go.sum": true,
	}
	
	// Safe config files that don't affect program behavior
	safeConfigFiles := map[string]bool{
		".gitignore":     true,
		".editorconfig":  true,
		".gitattributes": true,
	}
	
	// GitHub Actions workflows
	if strings.Contains(filename, ".github/workflows") {
		return FileTypeConfig{
			IsCode:              false,
			IsConfig:            true,
			IsMarkdown:          false,
			AllowApostrophes:    false,
			MaxLineLength:       80,
			ForbiddenCharacters: getAllShellControlChars(),
		}
	}
	
	// Check if it's a safe config file (like .gitignore)
	if safeConfigFiles[base] {
		return FileTypeConfig{
			IsCode:              false,
			IsConfig:            false, // Treat as non-config to allow changes
			IsMarkdown:          false,
			AllowApostrophes:    false,
			MaxLineLength:       120,
			ForbiddenCharacters: getMinimalControlChars(), // Only check for truly dangerous chars
		}
	}
	
	// Check if it's a Go config file (needs special handling for tabs)
	if goFiles[base] {
		return FileTypeConfig{
			IsCode:              false,
			IsConfig:            true,
			IsMarkdown:          false,
			AllowApostrophes:    false,
			MaxLineLength:       120, // Go modules can have longer lines
			ForbiddenCharacters: getGoConfigControlChars(),
		}
	}
	
	// Check if it's a known config file
	if configFiles[base] {
		return FileTypeConfig{
			IsCode:              false,
			IsConfig:            true,
			IsMarkdown:          false,
			AllowApostrophes:    false,
			MaxLineLength:       80,
			ForbiddenCharacters: getAllShellControlChars(),
		}
	}
	
	// Check by extension
	switch ext {
	case ".md", ".markdown", ".rst", ".txt":
		return FileTypeConfig{
			IsCode:              false,
			IsConfig:            false,
			IsMarkdown:          true,
			AllowApostrophes:    true, // Allow apostrophes in documentation
			MaxLineLength:       100,  // More lenient for docs
			ForbiddenCharacters: getMinimalControlChars(),
		}
	case ".yml", ".yaml":
		return FileTypeConfig{
			IsCode:              false,
			IsConfig:            true,
			IsMarkdown:          false,
			AllowApostrophes:    false,
			MaxLineLength:       80,
			ForbiddenCharacters: getAllShellControlChars(),
		}
	case ".json", ".xml", ".toml", ".ini", ".conf", ".config":
		return FileTypeConfig{
			IsCode:              false,
			IsConfig:            true,
			IsMarkdown:          false,
			AllowApostrophes:    false,
			MaxLineLength:       80,
			ForbiddenCharacters: getConfigControlChars(),
		}
	case ".sh", ".bash", ".zsh", ".fish":
		// Shell scripts should NEVER be auto-approved if modified
		return FileTypeConfig{
			IsCode:              true,
			IsConfig:            false,
			IsMarkdown:          false,
			AllowApostrophes:    false,
			MaxLineLength:       80,
			ForbiddenCharacters: getAllShellControlChars(),
		}
	case ".py", ".rb", ".pl", ".php":
		// Scripting languages
		return FileTypeConfig{
			IsCode:              true,
			IsConfig:            false,
			IsMarkdown:          false,
			AllowApostrophes:    false,
			MaxLineLength:       80,
			ForbiddenCharacters: getScriptControlChars(),
		}
	case ".go", ".java", ".c", ".cpp", ".h", ".hpp", ".cs", ".rs":
		// Compiled languages
		return FileTypeConfig{
			IsCode:              true,
			IsConfig:            false,
			IsMarkdown:          false,
			AllowApostrophes:    false,
			MaxLineLength:       120, // Increased for modern codebases
			ForbiddenCharacters: getCodeControlChars(),
		}
	case ".js", ".ts", ".jsx", ".tsx":
		// JavaScript/TypeScript
		return FileTypeConfig{
			IsCode:              true,
			IsConfig:            false,
			IsMarkdown:          false,
			AllowApostrophes:    false,
			MaxLineLength:       80,
			ForbiddenCharacters: getJSControlChars(),
		}
	default:
		// Unknown files - be conservative
		return FileTypeConfig{
			IsCode:              true,
			IsConfig:            false,
			IsMarkdown:          false,
			AllowApostrophes:    false,
			MaxLineLength:       80,
			ForbiddenCharacters: getAllShellControlChars(),
		}
	}
}

// getAllShellControlChars returns all shell control characters
func getAllShellControlChars() map[rune]bool {
	chars := make(map[rune]bool)
	for char := range ShellControlCharacters {
		chars[char] = true
	}
	return chars
}

// getMinimalControlChars returns minimal control chars for markdown
func getMinimalControlChars() map[rune]bool {
	return map[rune]bool{
		'`':  true, // Still dangerous in markdown (code execution)
		'$':  true, // Variable expansion
		'\r': true, // Carriage return
	}
}

// getConfigControlChars returns control chars for config files
func getConfigControlChars() map[rune]bool {
	return map[rune]bool{
		'`':  true, // Command substitution
		'|':  true, // Pipe
		'&':  true, // Background execution
		';':  true, // Command separator
		'>':  true, // Redirect
		'<':  true, // Redirect
		'\r': true, // Carriage return
		// Note: NOT including quotes, dollar signs, newlines as they're normal in many config files
	}
}

// getScriptControlChars returns control chars for scripting languages
func getScriptControlChars() map[rune]bool {
	return map[rune]bool{
		'`':  true,
		'$':  true,
		';':  true,
		'|':  true,
		'&':  true,
		'>':  true,
		'<':  true,
		'\r': true,
	}
}

// getCodeControlChars returns control chars for compiled languages
func getCodeControlChars() map[rune]bool {
	return map[rune]bool{
		'`':  true, // Command substitution in string literals
		'$':  true, // Often used in templates
		'\r': true, // Carriage return
	}
}

// getJSControlChars returns control chars for JavaScript
func getJSControlChars() map[rune]bool {
	return map[rune]bool{
		'`':  true, // Template literals can execute code
		'$':  true, // Template literal expressions
		'\r': true, // Carriage return
	}
}

// getGoConfigControlChars returns control chars for Go config files (go.mod, go.sum)
func getGoConfigControlChars() map[rune]bool {
	// Go config files are very strict format, only worry about actual security risks
	return map[rune]bool{
		'`':  true, // Command substitution
		'|':  true, // Pipe
		'&':  true, // Background execution
		';':  true, // Command separator
		'>':  true, // Redirect
		'<':  true, // Redirect
		'\r': true, // Carriage return
		// Note: NOT including tabs, quotes, dollar signs as they're normal in go.mod
	}
}

// ValidatePatchLine validates a single line from a patch
func (v *CodeValidator) ValidatePatchLine(line string, filename string, isAddition bool, isRemoval bool) error {
	// Skip validation for removed lines
	if isRemoval {
		return nil
	}
	
	config := GetFileTypeConfig(filename)
	
	// Check line length for additions
	if isAddition && len(line) > config.MaxLineLength {
		return fmt.Errorf("line exceeds maximum length %d characters", config.MaxLineLength)
	}
	
	// For GitHub Actions, check for dangerous patterns first (before character checks)
	if strings.Contains(filename, ".github/workflows") {
		if strings.Contains(line, "${{ github.event") || 
		   strings.Contains(line, "${{ inputs.") ||
		   strings.Contains(line, "${{ issue.") ||
		   strings.Contains(line, "${{ pull_request.") {
			return fmt.Errorf("dangerous pattern detected: untrusted GitHub Actions input")
		}
	}
	
	// Check for forbidden characters
	for _, char := range line {
		if config.ForbiddenCharacters[char] {
			// Special case: allow apostrophes in markdown for readability
			if char == '\'' && config.AllowApostrophes {
				continue
			}
			
			if description, exists := ShellControlCharacters[char]; exists {
				return fmt.Errorf("forbidden character detected: %s", description)
			}
			return fmt.Errorf("forbidden control character detected: %q", char)
		}
	}
	
	// Check for dangerous patterns based on file type
	fileType := detectFileType(filename)
	if patterns, exists := DangerousPatterns[fileType]; exists {
		for _, pattern := range patterns {
			if pattern.MatchString(line) {
				return fmt.Errorf("dangerous pattern detected: %s", pattern.String())
			}
		}
	}
	
	// Additional checks for specific file types
	if config.IsConfig || config.IsCode {
		// Check for command injection patterns
		if err := v.checkCommandInjection(line); err != nil {
			return err
		}
	}
	
	return nil
}

// detectFileType determines the file type for pattern matching
func detectFileType(filename string) string {
	lower := strings.ToLower(filename)
	
	if strings.Contains(lower, ".github/workflows") {
		return "github_workflow"
	}
	if strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml") {
		return "yaml"
	}
	if strings.HasSuffix(lower, ".json") {
		return "json"
	}
	if strings.Contains(lower, "dockerfile") {
		return "dockerfile"
	}
	if strings.Contains(lower, "makefile") {
		return "makefile"
	}
	
	return ""
}

// checkCommandInjection checks for command injection patterns
func (v *CodeValidator) checkCommandInjection(line string) error {
	// Check for common command injection patterns
	dangerousCommands := []string{
		"eval",
		"exec",
		"system",
		"popen",
		"subprocess",
		"os.system",
		"Runtime.exec",
		"Process.Start",
		"shell_exec",
		"passthru",
		"proc_open",
	}
	
	lowerLine := strings.ToLower(line)
	for _, cmd := range dangerousCommands {
		if strings.Contains(lowerLine, cmd) {
			return fmt.Errorf("potentially dangerous command detected: %s", cmd)
		}
	}
	
	// Check for command substitution patterns
	substitutionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\$\([^)]+\)`),     // $(command)
		regexp.MustCompile("`[^`]+`"),          // `command`
		regexp.MustCompile(`\$\{[^}]+\}`),      // ${command}
		regexp.MustCompile(`%\([^)]+\)s`),      // Python format string
		regexp.MustCompile(`f["'].*\{.*\}`),    // Python f-string
	}
	
	for _, pattern := range substitutionPatterns {
		if pattern.MatchString(line) {
			return fmt.Errorf("command substitution pattern detected")
		}
	}
	
	return nil
}

// ValidatePatch validates an entire patch for security issues
func (v *CodeValidator) ValidatePatch(patch string, filename string) error {
	lines := strings.Split(patch, "\n")
	
	for i, line := range lines {
		// Skip empty lines and diff headers
		if line == "" || strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---") {
			continue
		}
		
		isAddition := strings.HasPrefix(line, "+")
		isRemoval := strings.HasPrefix(line, "-")
		
		// Get the actual content (remove diff prefix)
		content := line
		if isAddition || isRemoval {
			content = line[1:]
		}
		
		// Validate the line
		if err := v.ValidatePatchLine(content, filename, isAddition, isRemoval); err != nil {
			log.Printf("[CODE VALIDATOR] Line %d in %s failed validation: %v", i+1, filename, err)
			return fmt.Errorf("line %d: %w", i+1, err)
		}
	}
	
	// Check for overall patch patterns that might indicate behavior change
	if err := v.checkBehaviorChange(patch, filename); err != nil {
		return err
	}
	
	return nil
}

// checkBehaviorChange checks if patch might alter program behavior
func (v *CodeValidator) checkBehaviorChange(patch string, filename string) error {
	config := GetFileTypeConfig(filename)
	
	// Special case: go.mod and go.sum dependency updates don't alter behavior
	base := strings.ToLower(filepath.Base(filename))
	if base == "go.mod" || base == "go.sum" {
		if isDependencyUpdate(patch) {
			log.Printf("[CODE VALIDATOR] Dependency update in %s doesn't alter behavior", filename)
			return nil
		}
	}
	
	// Any change to code or config files could alter behavior
	if config.IsCode || config.IsConfig {
		// Count actual changes (not just whitespace or comments)
		hasNonCommentChanges := false
		
		lines := strings.Split(patch, "\n")
		for _, line := range lines {
			// Skip diff headers
			if strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "+++") || 
			   strings.HasPrefix(line, "---") {
				continue
			}
			
			if strings.HasPrefix(line, "+") {
				content := strings.TrimSpace(line[1:])
				
				// Skip empty lines
				if content == "" {
					continue
				}
				
				// Check if it's a comment
				if !isSafeCommentLine(content) {
					hasNonCommentChanges = true
					break
				}
			}
		}
		
		// Any non-comment change to code/config could alter behavior
		if hasNonCommentChanges {
			return fmt.Errorf("changes to %s file could alter program behavior", 
				map[bool]string{true: "code", false: "config"}[config.IsCode])
		}
	}
	
	return nil
}

// IsSafeChange determines if a change is safe to auto-approve
func (v *CodeValidator) IsSafeChange(patch string, filename string) bool {
	// Validate the patch
	if err := v.ValidatePatch(patch, filename); err != nil {
		log.Printf("[CODE VALIDATOR] Patch for %s is not safe: %v", filename, err)
		return false
	}
	
	config := GetFileTypeConfig(filename)
	
	// Markdown changes are generally safe if they pass validation
	if config.IsMarkdown {
		return true
	}
	
	// Special case: go.mod and go.sum dependency updates are safe
	base := strings.ToLower(filepath.Base(filename))
	if base == "go.mod" || base == "go.sum" {
		if isDependencyUpdate(patch) {
			log.Printf("[CODE VALIDATOR] Dependency update in %s is safe", filename)
			return true
		}
	}
	
	// For code and config files, only allow very specific safe changes
	lines := strings.Split(patch, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "+") {
			content := strings.TrimSpace(line[1:])
			
			// Allow only comments and whitespace changes
			if content == "" {
				continue
			}
			
			// Check if it's a comment line
			if !isSafeCommentLine(content) {
				log.Printf("[CODE VALIDATOR] Non-comment change in %s is not safe", filename)
				return false
			}
		}
	}
	
	return true
}

// isSafeCommentLine checks if a line is a safe comment
func isSafeCommentLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	
	// Common comment patterns
	commentPrefixes := []string{
		"//", "#", "/*", "*", "*/", "<!--", "-->",
		"\"\"\"", "'''", "rem", "REM", "::",
	}
	
	for _, prefix := range commentPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	
	return false
}

// isDependencyUpdate checks if a patch is a dependency version update
func isDependencyUpdate(patch string) bool {
	lines := strings.Split(patch, "\n")
	
	// Pattern for dependency updates:
	// - Only changes version numbers
	// - In expected dependency format
	versionPattern := regexp.MustCompile(`v?\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?`)
	
	for _, line := range lines {
		// Skip headers and context lines
		if strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "+++") || 
		   strings.HasPrefix(line, "---") || (!strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "-")) {
			continue
		}
		
		// Get the actual content
		if len(line) < 2 {
			continue
		}
		content := line[1:]
		
		// Skip empty lines
		if strings.TrimSpace(content) == "" {
			continue
		}
		
		// Check if it looks like a dependency line
		// go.mod: module/package v1.2.3
		// go.sum: module/package v1.2.3 h1:hash
		// package.json: "package": "1.2.3",
		// requirements.txt: package==1.2.3
		
		// For go.mod/go.sum specifically
		if strings.Contains(content, " v") || strings.Contains(content, "/go.mod") {
			// Check if only version changed
			if !versionPattern.MatchString(content) && !strings.Contains(content, "h1:") {
				// Has non-version changes
				return false
			}
		} else {
			// Unknown format, be conservative
			return false
		}
	}
	
	return true
}