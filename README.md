# Trivial Auto-Approve

Automatically analyzes, approves, and merges trivial GitHub pull requests using AI-powered analysis.

## Installation

```bash
go install github.com/thegroove/trivial-auto-approve/cmd/auto-approve@latest
```

## Prerequisites

- **GitHub CLI**: `gh auth login`
- **Gemini API key**: `export GEMINI_API_KEY=your-api-key` ([Get key](https://aistudio.google.com/app/apikey))

## Usage

```bash
# Single PR
auto-approve --pr owner/repo#123

# Repository monitoring
auto-approve --project owner/repo --poll 1h

# Organization-wide
auto-approve --org myorg --dry-run

# Full automation
auto-approve --project owner/repo --poll 30m --auto-rebase --auto-merge
```

## Safety Checks

PRs are auto-approved only when **ALL** conditions are met:

- **State**: Open, not draft
- **Reviews**: No existing reviews or collaborator comments
- **Files**: ≤5 files changed (configurable)
- **CI**: All required checks passing
- **Contributor**: Not first-time (configurable)
- **AI Analysis**: No behavior changes, actual improvements, trivial categories only

## Configuration

| Flag | Description | Default |
|------|-------------|---------|
| `--pr URL` | Single PR to analyze | - |
| `--project owner/repo` | Repository to monitor | - |
| `--org name` | Organization to monitor | - |
| `--poll duration` | Polling interval | one-time |
| `--dry-run` | Preview mode only | false |
| `--auto-merge` | Enable auto-merge | false |
| `--auto-rebase` | Update branches | false |
| `--max-files N` | File limit | 5 |
| `--no-gemini` | Disable AI analysis | false |

## What Gets Approved

✅ **Safe changes**: Typo fixes, comments, documentation, lint fixes, dead code removal  
❌ **Rejected**: Code logic, config files, dependencies, large PRs, failing checks

## Limitations

- **AI Accuracy**: May occasionally misclassify changes
- **Rate Limits**: Subject to GitHub/Gemini API limits
- **Network Required**: Needs internet for API calls
- **Permissions**: Requires appropriate repository access

## Security

- Uses GitHub CLI token (never stored)
- Conservative defaults prioritize safety
- All actions logged and traceable
- Respects existing review processes

## Building

```bash
git clone https://github.com/thegroove/trivial-auto-approve.git
cd trivial-auto-approve
go build -o auto-approve ./cmd/auto-approve
```

## License

GPL v3 License - see LICENSE file for details.