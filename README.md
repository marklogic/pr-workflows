# TruffleHog Secret Scanning Workflow

Centralized GitHub Actions workflow that automatically scans all pull requests for exposed secrets (API keys, passwords, tokens, etc.) across your organization.

## Features

- Scans only modified files in PRs (fast and efficient)
- Works with PRs from forks
- Configurable exclusion patterns using regex
- Supports org-level defaults with repo-level overrides
- No workflow file needed in individual repos (uses org rulesets)

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

**Priority order:**
1. Repository-level variable (highest priority)
2. Organization-level variable
3. Workflow defaults (if no variable set)

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

Individual repos can override org defaults:

1. Go to **Repository** > **Settings** > **Secrets and variables** > **Actions**
2. Click **Variables** tab > **New repository variable**
3. Name: `TRUFFLEHOG_EXCLUDES`
4. Value: Your comma-separated regex patterns

This completely replaces org-level patterns for that repository.

## Default Exclusions

If no `TRUFFLEHOG_EXCLUDES` variable is set, these defaults apply:

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

## How It Works at Runtime

```
PR Created/Updated
       |
       v
Ruleset Triggers Workflow
       |
       v
Checkout Repository
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
       v                  v            Use DEFAULT_EXCLUDES
    Use it             Use it          from workflow
       |                  |                  |
       +------------------+------------------+
                          |
                          v
           Create .trufflehog-ignore file
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
        FAIL - PR blocked       PASS - PR allowed
```

**Scan scope:** Only files modified in the PR are scanned, not the entire repository.

## Workflow Triggers

| Trigger | When |
|---------|------|
| `pull_request` | PR opened, updated, or reopened |
| `workflow_dispatch` | Manual run from Actions tab |

## Viewing Results

1. Go to the **Pull Request** > **Checks** tab
2. Click **Scan PR for Secrets**
3. View logs for:
   - Applied exclusion patterns
   - Detected secrets (file, line, type)

## Handling Detected Secrets

If the scan fails:

1. **Remove the secret** from your code
2. **Rotate the secret** immediately (assume it's compromised)
3. **Push the fix** to your PR branch
4. Scan re-runs automatically

**For false positives:** Add the file/pattern to repo-level `TRUFFLEHOG_EXCLUDES` or request an update to org-level patterns.

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
- Contact your PDP Pioneers's team
