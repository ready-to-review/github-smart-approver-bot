// Package main provides the trivial-auto-approve command-line tool.
//
// Trivial-auto-approve is a Go tool that automatically approves and merges
// trivial GitHub pull requests using AI-powered analysis. It can analyze
// individual PRs, entire projects, or organizations.
//
// Features:
//   - Flexible targeting: single PRs, projects, or organizations
//   - AI-powered analysis using Google Gemini
//   - Smart review detection
//   - Configurable safety features
//   - Dry-run mode for testing
//
// Usage:
//
//	auto-approve --pr owner/repo#123
//	auto-approve --project owner/repo --poll 1h
//	auto-approve --org myorg --dry-run
//
// The tool requires GitHub CLI (gh) to be installed and authenticated.
// For AI analysis, set the GEMINI_API_KEY environment variable.
package main
