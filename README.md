# Trivial Auto-Approve

A Go tool that automatically analyzes, approves, and optionally merges trivial GitHub pull requests using AI-powered analysis.

## Overview

Trivial Auto-Approve helps maintainers reduce the overhead of manually reviewing and approving simple, non-behavior-changing pull requests. The tool uses Google Gemini AI to analyze code changes and automatically approve PRs that contain only trivial improvements like typo fixes, comment additions, documentation updates, and lint fixes.

## Key Capabilities

- **AI-Powered Analysis**: Uses Google Gemini 2.5 Flash to detect behavior-altering changes and assess triviality
- **Flexible Targeting**: Analyze single PRs, entire repositories, or all repositories in an organization
- **Smart Safety Features**: Multiple layers of protection to prevent inappropriate approvals
- **Batch Processing**: Process multiple PRs with polling support for continuous monitoring
- **Auto-Merge Support**: Optionally enable auto-merge for approved PRs
- **Branch Management**: Automatically update PR branches before approval

## Installation

```bash
go install github.com/thegroove/trivial-auto-approve/cmd/auto-approve@latest
```

## Prerequisites

1. **GitHub CLI** (`gh`) must be installed and authenticated:
   ```bash
   gh auth login
   ```

2. **Gemini API key** (required for AI analysis):
   ```bash
   export GEMINI_API_KEY=your-api-key
   ```
   Get your API key from [Google AI Studio](https://aistudio.google.com/app/apikey)

## Usage

### Single Pull Request

```bash
# Analyze and approve a specific PR
auto-approve --pr https://github.com/owner/repo/pull/123

# Or use short format
auto-approve --pr owner/repo#123

# Dry run mode (preview only)
auto-approve --pr owner/repo#123 --dry-run

# Enable auto-merge after approval
auto-approve --pr owner/repo#123 --auto-merge
```

### Repository (Project)

```bash
# Process all open PRs in a repository once
auto-approve --project owner/repo

# Poll every hour for new PRs
auto-approve --project owner/repo --poll 1h

# With auto-rebase and auto-merge
auto-approve --project owner/repo --auto-rebase --auto-merge
```

### Organization

```bash
# Process all open PRs across all repos in an organization
auto-approve --org myorg

# Poll every 30 minutes with dry-run
auto-approve --org myorg --poll 30m --dry-run
```

## What Gets Auto-Approved?

The tool considers PRs safe for auto-approval when **ALL** of these conditions are met:

### Safety Checks
1. **PR State**: Must be open and not a draft
2. **No Existing Reviews**: No approved, changes requested, or commented reviews
3. **No Collaborator Comments**: No comments from users with write access
4. **File Count**: 5 or fewer files changed (configurable with `--max-files`)
5. **CI Status**: All required checks passing (review-required failures are allowed)
6. **Contributor Status**: Not a first-time contributor (configurable with `--skip-first-time`)
7. **PR Age**: Respects min/max age requirements (configurable)

### AI Analysis (When Enabled)
When Gemini analysis is enabled, the tool also verifies:
- **No Behavior Changes**: Code changes don't alter application behavior
- **Improvement Quality**: Changes are actual improvements, not degradations
- **Triviality**: Changes fall into safe categories like:
  - Typo fixes in comments or documentation
  - Added comments or documentation
  - Markdown formatting improvements
  - Lint fixes (whitespace, imports, etc.)
  - Dead code removal

## Configuration Options

### Target Options (choose one)
- `--pr URL`: Specific pull request URL or `owner/repo#number`
- `--project owner/repo`: All PRs in a repository
- `--org name`: All PRs across all repositories in an organization

### Behavior Options
- `--poll duration`: Polling interval (e.g., `1h`, `30m`). If not set, runs once
- `--dry-run`: Preview mode - shows what would be approved without taking action
- `--auto-merge`: Enable auto-merge after approval (requires repository settings)
- `--auto-rebase`: Update PR branches before approval

### Safety Options
- `--max-files N`: Maximum files changed for auto-approval (default: 5)
- `--skip-first-time`: Skip first-time contributors (default: true)
- `--no-gemini`: Disable AI analysis (only approves obvious safe changes)
- `--approve-message`: Custom approval message

### Advanced Options
- `--model`: Gemini model to use (default: gemini-2.0-flash-exp)
- `--min-age`: Minimum PR age before approval
- `--max-age`: Maximum PR age for approval

## Examples

```bash
# Quick check of a single PR
auto-approve --pr golang/go#12345 --dry-run

# Monitor a high-traffic repository
auto-approve --project kubernetes/kubernetes --poll 1h --auto-merge

# Process an entire organization with higher file limit
auto-approve --org google --max-files 10

# Conservative mode without AI (only obvious safe changes)
auto-approve --project myorg/myrepo --no-gemini

# Full automation with branch updates and auto-merge
auto-approve --project myorg/myrepo --poll 30m --auto-rebase --auto-merge
```

## Limitations

### What It Won't Approve
- **Code Logic Changes**: Any modification that could alter program behavior
- **Configuration Changes**: Updates to config files, CI/CD, or deployment scripts
- **Dependency Changes**: Updates to go.mod, package.json, requirements.txt, etc.
- **Large PRs**: More than 5 files changed by default
- **Reviewed PRs**: PRs that already have human reviews or comments
- **Draft PRs**: Work-in-progress pull requests
- **Failing PRs**: PRs with failing required checks

### Technical Limitations
- **API Rate Limits**: Subject to GitHub and Gemini API rate limits
- **Repository Access**: Requires appropriate permissions for target repositories
- **Network Dependent**: Requires internet connectivity for API calls
- **AI Accuracy**: Gemini analysis, while sophisticated, may occasionally misclassify changes

## Security Considerations

- **Token Security**: Uses GitHub token from `gh` CLI (never stored by the tool)
- **API Key Management**: Gemini API key should be kept secure and not logged
- **Conservative Defaults**: Default settings prioritize safety over automation
- **Audit Trail**: All approvals are logged and traceable in GitHub
- **Respect Existing Process**: Never overrides existing reviews or branch protection rules

## Best Practices

1. **Start with Dry Run**: Always test with `--dry-run` first in new repositories
2. **Monitor Initially**: Watch the tool's decisions for the first few runs
3. **Configure Appropriately**: Adjust `--max-files` and other settings based on your repository
4. **Use Polling Wisely**: Don't set polling intervals too aggressively to avoid rate limits
5. **Review Logs**: Check tool output regularly to ensure it's working as expected

## Building from Source

```bash
# Clone the repository
git clone https://github.com/thegroove/trivial-auto-approve.git
cd trivial-auto-approve

# Download dependencies
go mod download

# Build
go build -o auto-approve ./cmd/auto-approve

# Run tests
go test ./...

# Run with go
go run ./cmd/auto-approve --help
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run `go test ./...` and `go vet ./...`
6. Submit a pull request

## License

GPL v3 License - see LICENSE file for details.