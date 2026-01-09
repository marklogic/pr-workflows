# TruffleHog Secret Scanning Workflow

Centralized GitHub Actions workflow that automatically scans all pull requests for exposed secrets (API keys, passwords, tokens, etc.) across your organization.

## Features

- Scans only modified files in PRs (fast and efficient)
- Works with PRs from forks (public and private)
- Configurable exclusion patterns using regex
- Supports org-level defaults with repo-level overrides
- No workflow file needed in individual repos (uses org rulesets)
- Posts PR comments with detailed findings when secrets are detected
- Sets commit status to pass/fail for clear merge blocking
- Classifies secrets as verified (confirmed active) or unverified (potential match)

## Setup
### Set Default Exclusions (Optional)

Set organization-wide exclusion patterns:

1. Go to **Organization** > **Settings** > **Secrets and variables** > **Actions**
2. Click **Variables** tab > **New organization variable**
3. Configure:

| Field | Value |
|-------|-------|
| Name | `TRUFFLEHOG_EXCLUDES` |
| Value | Comma-separated regex patterns (see examples below) |
| Repository access | `All repositories` or select specific ones |

## Exclusion Patterns

### Setting Exclusions

Exclusions are configured via the `TRUFFLEHOG_EXCLUDES` variable using regex patterns.

**How it works:**
- Default exclusions are **always applied** (node_modules, lock files, etc.)
- Repository-level patterns are **added on top** of defaults
- Organization-level patterns are **added on top** of defaults
- You never lose the base coverage when adding custom patterns

### Pattern Reference

| What to Exclude | Pattern | Example Match |
|-----------------|---------|---------------|
| Exact file | `^path/to/file\.json$` | `path/to/file.json` |
| Directory | `^node_modules/` | `node_modules/package/index.js` |
| File extension | `\.lock$` | `package-lock.json`, `yarn.lock` |
| Multiple extensions | `\.(md\|txt)$` | `README.md`, `notes.txt` |
| Test files | `_test\.py$` | `user_test.py` |
| Minified files | `\.min\.(js\|css)$` | `app.min.js`, `style.min.css` |
| Multiple directories | `^(vendor\|dist\|build)/` | `vendor/lib.js`, `dist/app.js` |
| Hidden files | `^\.[^/]+$` | `.gitignore`, `.env.example` |
| Config examples | `\.example$` | `.env.example` |

### Regex Syntax Reference

| Symbol | Meaning | Example |
|--------|---------|---------|
| `^` | Start of path | `^src/` matches paths starting with `src/` |
| `$` | End of path | `\.js$` matches files ending in `.js` |
| `\.` | Literal dot | `\.json$` matches `.json` extension |
| `.*` | Any characters | `^src/.*\.js$` matches any `.js` in `src/` |
| `(a\|b)` | OR operator | `\.(js\|ts)$` matches `.js` or `.ts` |
| `[^/]` | Any char except `/` | `^\.[^/]+$` matches hidden files in root |

### Example Variable Values

**Basic exclusions:**
```
^node_modules/,^vendor/,\.lock$,\.min\.js$
```

**Development files:**
```
^test/,^tests/,^spec/,_test\.(js|py)$,\.test\.(js|ts)$
```

**Documentation and configs:**
```
^docs/,\.md$,^\.github/,\.example$
```

**Comprehensive exclusion:**
```
^node_modules/,^vendor/,^dist/,^build/,\.lock$,\.min\.(js|css)$,^docs/,_test\.py$,\.test\.(js|ts)$,\.example$
```

## Override at Repository Level

Individual repos can add additional exclusions on top of the defaults:

1. Go to **Repository** > **Settings** > **Secrets and variables** > **Actions**
2. Click **Variables** tab > **New repository variable**
3. Name: `TRUFFLEHOG_EXCLUDES`
4. Value: Your comma-separated regex patterns

**Exclusions are always additive:** Your patterns are appended to the default exclusions. You don't need to repeat common patterns like `node_modules/` or `.lock` files since they're always included.

## Default Exclusions

These default exclusions are **always applied**, regardless of whether custom patterns are defined:

```
^node_modules/
^vendor/
^\.git/
\.lock$
^package-lock\.json$
^yarn\.lock$
^pnpm-lock\.yaml$
\.min\.js$
\.min\.css$
```

Any patterns you add via `TRUFFLEHOG_EXCLUDES` are appended to this list.

## How It Works at Runtime

```
PR Created/Updated
       |
       v
pull_request_target trigger
(works for both fork and same-repo PRs)
       |
       v
Checkout Base Repository
       |
       v
Fetch PR Head Commits
(using refs/pull/{number}/head)
       |
       v
Load Default Exclusions
       |
       v
Check for TRUFFLEHOG_EXCLUDES variable
       |
       +------------------+------------------+
       |                  |                  |
       v                  v                  v
  Repo variable      Org variable        Neither set
    exists?            exists?                |
       |                  |                   v
       v                  v            Use defaults only
  Append to           Append to              |
   defaults            defaults              |
       |                  |                  |
       +------------------+------------------+
                          |
                          v
           Create .trufflehog-ignore file
           (defaults + custom patterns)
                          |
                          v
           Run TruffleHog scan on PR diff
           (only modified files between base and head)
                          |
              +-----------+-----------+
              |                       |
              v                       v
        Secrets found           No secrets found
              |                       |
              v                       v
      Post/Update PR           Check for previous
      comment with               alert comment
      scanned commit                  |
        SHA + findings       +--------+--------+
              |              |                 |
              v              v                 v
      Set commit status   Exists?           No comment
        to failure           |             (clean PR)
              |              v                 |
              v         Update to             v
        FAIL - PR       "Resolved"      Set commit status
         blocked          status          to success
                             |                 |
                             v                 v
                       Set commit        PASS - PR allowed
                       to success
```

**Scan scope:** Only files modified in the PR are scanned, not the entire repository.

## Secret Classification

TruffleHog classifies detected secrets into two categories:

| Type | Description | Action |
|------|-------------|--------|
| **Verified** | Confirmed active/valid credentials | Blocks PR, requires immediate rotation |
| **Unverified** | Potential secrets that couldn't be validated | Warning in logs, review recommended |

## PR Comments

The workflow manages PR comments to provide clear feedback throughout the remediation process:

### When Secrets Are Detected

A comment is posted with:
- **Scanned commit SHA** (short hash with link to full commit) so you can verify the scan ran on your latest changes
- Link to workflow logs for detailed findings
- Instructions for removing and rotating secrets
- Information about file paths, line numbers, and secret types

### When Secrets Are Resolved

If you fix the secrets and push again:
- The **same comment is updated** to show a "Passed" status
- Shows the new commit SHA that resolved the issue
- Includes a reminder to rotate any previously exposed credentials

### Clean PRs

If a PR never had secrets detected, no comment is posted to keep the PR clean.

## Workflow Triggers

The workflow uses `pull_request_target` to handle all PR types with a single trigger:

| Trigger | Used For | Description |
|---------|----------|-------------|
| `pull_request_target` | All PRs | Runs in base repo context, works for both same-repo and fork PRs |
| `workflow_dispatch` | Manual runs | Trigger manually from Actions tab |

**Why `pull_request_target`?**
- Works for both same-repo branches and forks
- Only one workflow run per PR (no duplicate or skipped checks)
- Runs workflow code from the base branch (more secure for secret scanning)
- PR commits are fetched via `refs/pull/{number}/head`

## Fork PR Support

The workflow fully supports PRs from forked repositories:

- Uses GitHub's `refs/pull/{number}/head` to fetch PR commits
- Works with both public and private forks
- No direct access to fork repository required
- Runs immediately without requiring maintainer approval

## Viewing Results

1. Go to the **Pull Request** > **Checks** tab
2. Look for **TruffleHog Secret Scan** commit status
3. If secrets are found:
   - A PR comment will be posted with remediation steps
   - Click the status link to view detailed logs
4. View logs for:
   - Applied exclusion patterns
   - Detected secrets (file, line, secret type)
   - Verification status (verified = confirmed active)

## Handling Detected Secrets

If the scan fails:

1. **Remove the secret** from your code
2. **Rotate the secret** immediately (assume it's compromised)
3. **Push the fix** to your PR branch
4. Scan re-runs automatically
5. PR comment updates to show "Resolved" status when fixed

**For false positives:** Add the file/pattern to repo-level `TRUFFLEHOG_EXCLUDES` (patterns are additive to defaults).

## Manual Scan

To run a scan manually:

1. Go to **Repository** > **Actions**
2. Select **TruffleHog Secret Scan**
3. Click **Run workflow**

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Workflow not triggering | Verify ruleset is Active and targets correct repos/branches |
| Can't access workflow | Enable "Accessible from repositories in the organization" in this repo's Actions settings |
| Exclusions not working | Check regex syntax; view workflow logs for applied patterns |
| Variable not found | Confirm `TRUFFLEHOG_EXCLUDES` is set at org or repo level |
| Fork PRs failing | Workflow handles forks automatically; ensure fork has access |

## Support

For issues or questions:
- Check workflow run logs for detailed error messages
- Review exclusion patterns for regex errors
- Contact your PDP Pioneers team
