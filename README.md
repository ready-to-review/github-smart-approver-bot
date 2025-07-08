# Trivial Auto-Approve

A Go tool that automatically approves and merges trivial GitHub pull requests using AI-powered analysis.

## Features

- **Flexible Targeting**: Analyze single PRs, entire projects, or organizations
- **AI-Powered Analysis**: Uses Google Gemini 2.0 Flash to detect behavior-altering changes
- **Smart Review Detection**: Skips PRs that already have reviews or collaborator comments
- **Safety Features**:
  - Skip first-time contributors by default
  - Require passing CI checks (allows review-required failures)
  - Skip PRs with existing reviews
  - Skip PRs with collaborator comments
  - Limit to 5 files changed by default
  - Dry-run mode for testing
  - Ignores signing checks for bot authors

## Installation

```bash
go install github.com/thegroove/trivial-auto-approve/cmd/auto-approve@latest
```

## Prerequisites

1. GitHub CLI (`gh`) must be installed and authenticated:
   ```bash
   gh auth login
   ```

2. Gemini API key (optional but recommended):
   ```bash
   export GEMINI_API_KEY=your-api-key
   ```

## Usage

### Single Pull Request

```bash
# Approve a specific PR
auto-approve --pr https://github.com/owner/repo/pull/123

# Or use short format
auto-approve --pr owner/repo#123

# Dry run mode
auto-approve --pr owner/repo#123 --dry-run
```

### Project (Repository)

```bash
# Process all PRs in a project once
auto-approve --project owner/repo

# Poll a project every hour
auto-approve --project owner/repo --poll 1h
```

### Organization

```bash
# Process all PRs in an organization once
auto-approve --org myorg

# Poll an organization every 30 minutes
auto-approve --org myorg --poll 30m --dry-run
```

## What Gets Auto-Approved?

The tool considers PRs trivial and safe to auto-approve when ALL of these conditions are met:

1. **No existing reviews**: PR has no approved, changes requested, or commented reviews
2. **No collaborator comments**: No comments from users with write access
3. **File count**: 5 or fewer files changed (configurable)
4. **CI status**: All checks passing (review-required failures are allowed)
5. **Contributor**: Not a first-time contributor (configurable)
6. **AI Analysis** (when enabled):
   - Changes do not alter application behavior
   - Changes are improvements
   - Categories: typo fixes, added comments, markdown improvements, lint fixes

## Configuration Options

### Target Options (use one)
- `--pr`: Pull request URL
- `--project`: GitHub project (owner/repo)
- `--org`: GitHub organization

### Behavior Options
- `--poll`: Polling interval (e.g., 1h, 30m). If not set, runs once
- `--dry-run`: Preview what would be approved without taking action
- `--max-files`: Maximum files for auto-approval (default: 5)
- `--skip-first-time`: Skip first-time contributors (default: true)
- `--no-gemini`: Disable AI analysis
- `--approve-message`: Custom approval message

## Examples

```bash
# Check a single PR
auto-approve --pr golang/go#12345 --dry-run

# Monitor a project continuously
auto-approve --project kubernetes/kubernetes --poll 1h

# Process an entire organization once
auto-approve --org google --max-files 10

# Without AI analysis (only markdown/docs changes will be approved)
auto-approve --project myorg/myrepo --no-gemini
```

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
```

## Security Considerations

- Uses GitHub token from `gh` CLI (never stored in the tool)
- Gemini API key should be kept secure
- Default settings are conservative to prevent accidental approvals
- Always test with `--dry-run` first
- Respects existing review processes by skipping reviewed PRs

## License

MIT