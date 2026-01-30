# TruffleHog Secret Scanning Workflow

Centralized GitHub Actions workflow that automatically scans all pull requests for exposed secrets (API keys, passwords, tokens, etc.) across your organization.

## Features

- Scans only modified files in PRs (fast and efficient)
- Works with PRs from forks (public and private)
- Configurable exclusion patterns using regex
- Supports org-level defaults with repo-level overrides
- No workflow file needed in individual repos (uses org rulesets)
- **Verified secrets block the PR** - confirmed active credentials must be removed
- **Unverified secrets allow PR to proceed** - warnings shown for review
- Posts PR comments with detailed findings (updated when issues are resolved)
- Creates file-level annotations pointing to exact secret locations
- Classifies secrets as verified (confirmed active) or unverified (potential match)

## Setup

### Required Permissions

The workflow requires these GitHub token permissions:

| Permission | Access | Purpose |
|------------|--------|----------|
| `contents` | read | Checkout repository and fetch PR commits |
| `pull-requests` | write | Post and update PR comments |

These are configured in the workflow file and apply automatically.

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
Load Default Exclusions + Custom Patterns
       |
       v
Run TruffleHog scan on PR diff
(only modified files between base and head)
       |
       v
Parse results and create annotations
       |
       +------------------+------------------+
       |                  |                  |
       v                  v                  v
  Verified            Unverified          No secrets
  secrets found       secrets only          found
       |                  |                  |
       v                  v                  v
  Error annotations   Warning annotations  Check for previous
  (red) on files      (yellow) on files   CRITICAL comment
       |                  |                  |
       v                  v            +-----+-----+
  Post CRITICAL       Post Warning    |           |
  PR comment          PR comment      v           v
  (blocking)          (non-blocking)  Was         Not blocking
       |                  |           CRITICAL?    or no comment
       v                  v              |           |
  FAIL workflow       PASS workflow     v           v
  PR blocked          PR allowed     Update to   Do nothing
                                     "Passed"    (keep warning
                                         |       if exists)
                                         v
                                    PASS workflow
```

**Key behaviors:**
- **Verified secrets** → Error annotations + CRITICAL comment + workflow fails
- **Unverified only** → Warning annotations + Warning comment + workflow passes
- **Clean after CRITICAL** → Comment updated to "Passed"
- **Clean after Warning** → Warning comment stays (for visibility)
- **Always clean** → No comment posted

**Scan scope:** Only files modified in the PR are scanned, not the entire repository.

## Secret Classification

TruffleHog classifies detected secrets into two categories:

| Type | Description | Workflow Result | PR Status |
|------|-------------|-----------------|-----------|
| **Verified** | Confirmed active/valid credentials | **Fails** | Blocked until fixed |
| **Unverified** | Potential secrets that couldn't be validated | **Passes** | Can proceed (review recommended) |

### Behavior Summary

| Scenario | Workflow | PR Comment | Annotations |
|----------|----------|------------|-------------|
| Verified secrets found | Fails | Critical alert posted | Error annotations on files |
| Only unverified secrets | Passes | Warning posted | Warning annotations on files |
| No secrets detected | Passes | No comment (or updates to "Passed" if previously blocked) | None |

**Why this approach?**
- **Verified secrets** are confirmed active credentials that pose immediate risk and must be removed
- **Unverified secrets** match known patterns but couldn't be validated (may be false positives, test data, or inactive credentials)
- Blocking only on verified secrets reduces friction while still catching real exposures

## PR Comments

The workflow manages PR comments to provide clear feedback throughout the remediation process:

### When Verified Secrets Are Detected (Blocking)

A **CRITICAL** comment is posted with:
- Red alert icon
- Count of verified vs unverified secrets
- **Scanned commit SHA** (short hash with link to full commit)
- Clear message that PR is blocked
- Instructions for removing and rotating secrets
- Link to workflow logs for file paths and line numbers

### When Only Unverified Secrets Are Detected (Non-blocking)

A **Warning** comment is posted with:
- Warning icon
- Count of unverified secrets
- **Scanned commit SHA**
- Message that PR can proceed but review is recommended
- Same remediation instructions

### When Verified Secrets Are Resolved

If you fix verified secrets and push again:
- The **same comment is updated** to show a "Passed" status
- Shows the new commit SHA that resolved the issue
- Thanks the contributor for addressing security concerns

### Unverified Warnings Persist

If only unverified secrets were found and you push new commits:
- The warning comment **stays as-is** (no override)
- This ensures the warning remains visible for review
- The workflow still passes

### Clean PRs

If a PR never had secrets detected, no comment is posted to keep the PR clean.

## Annotations

The workflow creates GitHub annotations that point to exact locations in your code:

| Secret Type | Annotation Level | Appears In |
|-------------|------------------|------------|
| Verified | Error (red) | Files changed tab, Annotations panel |
| Unverified | Warning (yellow) | Files changed tab, Annotations panel |

Annotations include:
- File path
- Line number
- Secret type (e.g., AWS, Slack, Postgres)
- Verification status
- Remediation guidance

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
2. Look for **TruffleHog Secret Scan / Scan PR for Secrets**
3. Check the workflow result:
   - **Failed** = Verified secrets found (PR blocked)
   - **Passed with warnings** = Only unverified secrets (review recommended)
   - **Passed** = No secrets detected
4. If secrets are found:
   - Check the **Annotations** panel for file/line locations
   - Review the PR comment for remediation steps
   - Click the workflow link to view detailed logs
5. Logs show:
   - Applied exclusion patterns
   - Detected secrets (file, line, secret type)
   - Verification status (verified = confirmed active)

## Handling Detected Secrets

### Verified Secrets (PR Blocked)

If verified secrets are detected:

1. **PR is blocked** - cannot be merged until fixed
2. **Remove the secret** from your code
3. **Rotate the secret immediately** - assume it's compromised
4. **Push the fix** to your PR branch
5. Scan re-runs automatically
6. PR comment updates to show "Passed" status when fixed

### Unverified Secrets (PR Can Proceed)

If only unverified secrets are detected:

1. **PR can still be merged** - workflow passes
2. **Review the warnings** - check if they're real credentials
3. If real: remove and rotate as above
4. If false positive: add pattern to `TRUFFLEHOG_EXCLUDES`
5. Warning comment remains visible for awareness

### False Positives

To exclude files/patterns that trigger false positives:
- Add the pattern to repo-level `TRUFFLEHOG_EXCLUDES`
- Patterns are additive to defaults
- See [Exclusion Patterns](#exclusion-patterns) for syntax

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
