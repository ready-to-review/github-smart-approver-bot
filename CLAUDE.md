# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Go CLI tool called `trivial-auto-approve` that automatically analyzes, approves, and merges trivial GitHub pull requests using AI-powered analysis (Google Gemini). The tool is designed to be safe and conservative, only approving PRs that meet strict criteria.

## Key Commands

```bash
# Build
make build           # Builds binary to ./auto-approve
go build -o auto-approve ./cmd/auto-approve

# Test
make test            # Run all tests
go test -v ./...     # Run all tests with verbose output
go test -v ./internal/analyzer/...  # Run specific package tests

# Lint
make lint            # Run golangci-lint with strict config
make fix             # Run golangci-lint with --fix

# Install
make install         # Install to $GOPATH/bin
go install ./cmd/auto-approve
```

## Architecture

### Package Structure
- `cmd/auto-approve/` - CLI entry point and command processor
  - `main.go` - Flag parsing and initialization
  - `processor.go` - Core PR processing logic
- `internal/analyzer/` - PR analysis engine (coordinates GitHub and Gemini)
  - Safety checks, contributor validation, AI prompt generation
- `internal/github/` - GitHub API client wrapper using `gh` CLI
- `internal/gemini/` - Google Gemini AI client for PR analysis
- `internal/retry/` - Retry logic with exponential backoff
- `internal/errors/` - Custom error types
- `internal/constants/` - Shared constants

### Key Design Patterns
- All API clients use interfaces for testability
- Configuration is centralized in `analyzer.Config` with validation
- Errors use custom types for better error handling
- GitHub operations go through `gh` CLI rather than direct API calls
- AI prompts are carefully structured to be conservative

### Safety Architecture
The analyzer implements multiple safety layers:
1. PR state checks (open, not draft)
2. Review state validation (no existing reviews)
3. File/line count limits
4. CI check status verification
5. Contributor history validation
6. AI analysis for non-trivial changes
7. Age requirements (min/max open time)

## Development Guidelines

### Testing
- All packages have corresponding `_test.go` files
- Tests use interfaces to mock external dependencies
- Special attention to Dependabot PR handling (see `dependabot_test.go`)

### Linting
The project uses a strict golangci-lint configuration (.golangci.yml) with:
- All linters enabled by default with specific exclusions
- Custom rules for Go best practices
- Cognitive complexity limits (55)
- Function length limits (150 lines)

### Error Handling
- Use custom error types from `internal/errors`
- Always wrap errors with context
- Return errors up the stack rather than logging internally

### GitHub Integration
- Uses `gh` CLI commands rather than direct API calls
- Supports both `owner/repo#123` and full URL formats
- Handles auto-merge and auto-rebase features

### AI Integration
- Gemini prompts are structured with clear safety instructions
- Responses are parsed for specific categories and confidence levels
- Model can be disabled with empty `--model` flag