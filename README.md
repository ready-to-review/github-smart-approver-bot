# Trivial Auto-Approve

Automatically analyzes, approves, and merges trivial GitHub pull requests using AI-powered analysis.

## Installation

```bash
go install github.com/thegroove/trivial-auto-approve/cmd/auto-approve@latest
```

## Prerequisites

- **Authentication** (choose one):
  - **GitHub CLI**: `gh auth login` (default)
  - **GitHub App**: Create app with PR write permissions (production)
- **Gemini API key**: `export GEMINI_API_KEY=your-api-key` ([Get key](https://aistudio.google.com/app/apikey))

## Usage

### Using GitHub CLI (default)
```bash
# Single PR
auto-approve --pr owner/repo#123

# Repository monitoring
auto-approve --project owner/repo --poll 1h

# Organization-wide
auto-approve --org myorg --dry-run
```

### Using GitHub App (production)
```bash
# Single PR with GitHub App
auto-approve \
  --app-id 123456 \
  --app-key /path/to/private-key.pem \
  --pr owner/repo#123

# Full automation with GitHub App
auto-approve \
  --app-id 123456 \
  --app-key /path/to/private-key.pem \
  --project owner/repo \
  --poll 30m --auto-rebase --auto-merge
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
| `--model ""` | Disable AI analysis | gemini-2.0-flash |
| `--app-id N` | GitHub App ID | - |
| `--app-key path` | Path to private key | - |
| `--installation-id N` | Installation ID | auto-detect |

## What Gets Approved

✅ **Safe changes**: Typo fixes, comments, documentation, lint fixes, dead code removal  
❌ **Rejected**: Code logic, config files, dependencies, large PRs, failing checks

## Limitations

- **AI Accuracy**: May occasionally misclassify changes
- **Rate Limits**: Subject to GitHub/Gemini API limits
- **Network Required**: Needs internet for API calls
- **Permissions**: Requires appropriate repository access

## Security

- **Authentication**: GitHub CLI token or GitHub App JWT (never stored)
- **GitHub App**: More secure for production with scoped permissions
- **Conservative**: Safety-first defaults, requires all checks to pass
- **Auditable**: All actions logged and traceable
- **Respectful**: Won't override existing reviews or comments

## GitHub App Setup

1. **Create a GitHub App**:
   - Go to Settings → Developer settings → GitHub Apps → New GitHub App
   - Set permissions:
     - Pull requests: Read & Write
     - Contents: Read
     - Checks: Read
     - Metadata: Read

2. **Generate private key**:
   - In your app settings, generate and download a private key
   - Save as `private-key.pem`

3. **Install the app**:
   - Install on your repository or organization
   - Note the installation ID (visible in the URL)

4. **Use with auto-approve**:
   ```bash
   auto-approve \
     --app-id YOUR_APP_ID \
     --app-key ./private-key.pem \
     --pr owner/repo#123
   ```

## Building

```bash
git clone https://github.com/thegroove/trivial-auto-approve.git
cd trivial-auto-approve
go build -o auto-approve ./cmd/auto-approve
```

## License

GPL v3 License - see LICENSE file for details.