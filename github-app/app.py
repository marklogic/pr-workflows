#!/usr/bin/env python3
"""
GitHub App for Copyright Validation on GHES

This app listens to PR webhooks and validates copyright headers
using direct API calls (no PyGithub dependency for GHES compatibility).
"""

import os
import logging
from logging.handlers import TimedRotatingFileHandler
import tempfile
import requests
from flask import Flask, request, jsonify
import jwt
import time
import subprocess
import shutil
import base64
import re
from datetime import datetime

LOG_DIR = '/var/log/app'
LOG_FILE = os.path.join(LOG_DIR, 'app.log')
logger = logging.getLogger()  # root logger so all modules inherit
logger.setLevel(logging.INFO)
# Clear default handlers if any (avoid duplicate logs on reload)
if logger.handlers:
    for h in list(logger.handlers):
        logger.removeHandler(h)

formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')

# Stream handler (stdout) for docker logs
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)

# Rotating file handler (daily, keep 7 backups)
try:
    os.makedirs(LOG_DIR, exist_ok=True)
    file_handler = TimedRotatingFileHandler(LOG_FILE, when='D', interval=1, backupCount=7, utc=True)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.info(f"File logging enabled: {LOG_FILE} (daily rotation, 7 backups)")
except Exception as e:
    logger.warning(f"Failed to set up file logging ({LOG_FILE}): {e}. Continuing with stdout only.")

app = Flask(__name__)

# GitHub App configuration
APP_ID = os.environ.get('GITHUB_APP_ID')
PRIVATE_KEY_FILE = os.environ.get('GITHUB_PRIVATE_KEY_FILE')  # required: path to mounted PEM file

# Load private key strictly from mounted file
PRIVATE_KEY = None
if PRIVATE_KEY_FILE:
    try:
        with open(PRIVATE_KEY_FILE, 'r') as pkf:
            PRIVATE_KEY = pkf.read()
        logger.info("Loaded private key from mounted file (GITHUB_PRIVATE_KEY_FILE)")
    except Exception as e:
        logger.error(f"Failed to read private key file '{PRIVATE_KEY_FILE}': {e}")
else:
    logger.error("GITHUB_PRIVATE_KEY_FILE environment variable is required (path to PEM key file)")

GHES_URL = os.environ.get('GITHUB_ENTERPRISE_URL', 'https://github.com').rstrip('/')  # Remove trailing slash

# Script repository configuration (defaults to GitHub.com)
SCRIPT_REPO_URL = os.environ.get('SCRIPT_REPO_URL', 'https://api.github.com')
SCRIPT_REPO_OWNER = os.environ.get('SCRIPT_REPO_OWNER', 'marklogic')
SCRIPT_REPO_NAME = os.environ.get('SCRIPT_REPO_NAME', 'pr-workflows')
SCRIPT_BRANCH = os.environ.get('SCRIPT_BRANCH', 'main')

# GHES-specific options
VERIFY_SSL = os.environ.get('VERIFY_SSL', 'true').lower() == 'true'

# Validate required environment variables
if not APP_ID:
    logger.error("GITHUB_APP_ID environment variable is required")
    raise ValueError("GITHUB_APP_ID not set")

if not PRIVATE_KEY:
    logger.error("Private key could not be loaded from file")
    raise ValueError("GITHUB_PRIVATE_KEY_FILE invalid or unreadable")

if not GHES_URL:
    logger.error("GITHUB_ENTERPRISE_URL environment variable is required")
    raise ValueError("GITHUB_ENTERPRISE_URL not set")

logger.info(f"Initializing GitHub App with ID: {APP_ID}")
logger.info(f"GitHub Enterprise URL: {GHES_URL}")
logger.info(f"SSL Verification: {VERIFY_SSL}")

# Disable SSL warnings if verification is disabled
if not VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logger.warning("SSL verification disabled - use only for testing!")

def create_jwt_token():
    """Create JWT token for GitHub App authentication"""
    try:
        payload = {
            'iat': int(time.time()),
            'exp': int(time.time()) + 600,  # 10 minutes
            'iss': APP_ID
        }
        token = jwt.encode(payload, PRIVATE_KEY, algorithm='RS256')
        return token
    except Exception as e:
        logger.error(f"Failed to create JWT token: {e}")
        return None

def get_installation_access_token(installation_id):
    """Get installation access token using direct API call"""
    try:
        jwt_token = create_jwt_token()
        if not jwt_token:
            raise Exception("Failed to create JWT token")
        
        headers = {
            'Authorization': f'Bearer {jwt_token}',
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json'
        }
        
        url = f"{GHES_URL}/api/v3/app/installations/{installation_id}/access_tokens"
        logger.info(f"Getting installation token from: {url}")
        
        response = requests.post(url, headers=headers, verify=VERIFY_SSL)
        
        if response.status_code == 201:
            token_data = response.json()
            logger.info("Installation access token obtained successfully")
            return token_data['token']
        else:
            logger.error(f"Failed to get installation token: {response.status_code} {response.text}")
            raise Exception(f"Token request failed: {response.status_code}")
            
    except Exception as e:
        logger.error(f"Failed to get installation access token: {e}")
        raise

# --- New helpers for structured block extraction (Markdown only) for summary ---
MD_START = '<<<COPYRIGHT-CHECK:MARKDOWN>>>'
MD_END = '<<<END COPYRIGHT-CHECK:MARKDOWN>>>'

def extract_block(text, start_marker, end_marker):
    try:
        start = text.index(start_marker) + len(start_marker)
        end = text.index(end_marker, start)
        return text[start:end].strip()
    except ValueError:
        return None

def parse_markdown_counts(md_block):
    """Parse counts line from markdown summary.
    Expected second line like:
    Total: X | Passed: Y | Failed: Z | Skipped: N (Skipped segment optional)
    """
    if not md_block:
        return {}
    lines = [l.strip() for l in md_block.splitlines() if l.strip()]
    if len(lines) < 2:
        return {}
    counts_line = lines[1]
    pattern = r"Total:\s*(\d+).*?Passed:\s*(\d+).*?Failed:\s*(\d+)(?:.*?Skipped:\s*(\d+))?"
    m = re.search(pattern, counts_line)
    if not m:
        return {}
    total, passed, failed, skipped = m.groups()
    return {
        'total': int(total),
        'valid': int(passed),
        'invalid': int(failed),
        'excluded': int(skipped) if skipped is not None else 0
    }

def parse_script_output_markdown(raw_stdout):
    md_block = extract_block(raw_stdout, MD_START, MD_END)
    counts = parse_markdown_counts(md_block)
    if md_block and counts:
        return {'counts': counts, 'markdown': md_block}
    if md_block:
        return {'markdown': md_block}
    return None

def build_summary_comment(structured, commit_sha):
    """Return markdown for PR comment from structured data (no header augmentation).
    The script now emits timestamp + commit when COMMIT_SHA/GITHUB_SHA is set.
    We only append the hidden marker for update detection.
    """
    if not structured:
        return "No summary available."
    md = structured.get('markdown', '').rstrip('\n')
    if not md.endswith('\n'):
        md += '\n'
    md += '<!-- COPYRIGHT-CHECK-COMMENT: v1 -->\n'
    return md

def find_existing_comment(access_token, repo_full_name, pr_number):
    try:
        api_url = f"{GHES_URL}/api/v3/repos/{repo_full_name}/issues/{pr_number}/comments"
        headers = {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github.v3+json'}
        resp = requests.get(api_url, headers=headers, verify=VERIFY_SSL)
        if resp.status_code != 200:
            return None
        for c in resp.json():
            if '<!-- COPYRIGHT-CHECK-COMMENT:' in (c.get('body','')):
                return c.get('id')
    except Exception:
        return None
    return None

def update_pr_comment(access_token, repo_full_name, comment_id, body):
    try:
        api_url = f"{GHES_URL}/api/v3/repos/{repo_full_name}/issues/comments/{comment_id}"
        headers = {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github.v3+json'}
        requests.patch(api_url, json={'body': body}, headers=headers, verify=VERIFY_SSL)
    except Exception as e:
        logger.error(f"Failed to update PR comment: {e}")

def create_pr_comment(access_token, repo_full_name, pr_number, body):
    try:
        api_url = f"{GHES_URL}/api/v3/repos/{repo_full_name}/issues/{pr_number}/comments"
        headers = {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github.v3+json'}
        requests.post(api_url, json={'body': body}, headers=headers, verify=VERIFY_SSL)
    except Exception as e:
        logger.error(f"Failed to create PR comment: {e}")

class CopyrightValidator:
    def __init__(self, access_token, repo_full_name, pr_number):
        try:
            logger.info(f"Init validator for {repo_full_name}#{pr_number}")
            self.access_token = access_token
            self.repo_full_name = repo_full_name
            self.pr_number = pr_number
            self.temp_dir = None
            self.diff_applied = False
            self.files_from_diff = []
            self.files_from_base = []
            self.headers = {'Authorization': f'token {access_token}', 'Accept': 'application/vnd.github.v3+json'}
            pr_url = f"{GHES_URL}/api/v3/repos/{repo_full_name}/pulls/{pr_number}"
            resp = requests.get(pr_url, headers=self.headers, verify=VERIFY_SSL)
            if resp.status_code != 200:
                raise Exception(f"Failed to get PR data: {resp.status_code}")
            self.pr_data = resp.json()
        except Exception as e:
            logger.error(f"Validator init failed: {e}")
            raise
    def __enter__(self):
        try:
            self.temp_dir = tempfile.mkdtemp()
            return self
        except Exception as e:
            logger.error(f"Failed to create temporary directory for validation: {e}")
            raise RuntimeError("Temporary workspace allocation failed") from e
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    def get_config_file(self):
        try:
            base_clone_dir = os.path.join(self.temp_dir, 'base_repo')
            config_path = os.path.join(base_clone_dir, '.copyrightconfig')
            if os.path.exists(config_path):
                if '.copyrightconfig' in self.files_from_diff:
                    logger.info("Using .copyrightconfig from PR changes")
                else:
                    logger.info("Using .copyrightconfig from base repository")
                return config_path
            logger.warning("No .copyrightconfig found")
            return None
        except Exception as e:
            logger.error(f"get_config_file error: {e}")
            return None
    def get_changed_files(self):
        try:
            files_url = f"{GHES_URL}/api/v3/repos/{self.repo_full_name}/pulls/{self.pr_number}/files"
            resp = requests.get(files_url, headers=self.headers, verify=VERIFY_SSL)
            if resp.status_code != 200:
                raise Exception(f"Failed to get PR files: {resp.status_code}")
            changed = []
            for fd in resp.json():
                status = fd['status']
                fn = fd['filename']
                # Skip deleted/removed files - they don't exist in PR head
                if status in ['removed', 'deleted']:
                    logger.info(f"Skipping deleted file: {fn}")
                    continue
                # For added, modified, or renamed files, use the new filename
                if status in ['added', 'modified', 'renamed']:
                    if not fn.startswith('.') or fn == '.copyrightconfig':
                        changed.append(fn)
                else:
                    logger.warning(f"Unknown file status '{status}' for {fn}")
            logger.info(f"Changed files: {len(changed)}")
            return changed
        except Exception as e:
            logger.error(f"get_changed_files error: {e}")
            return []
    def download_files(self, file_paths):
        try:
            diff_url = f"{GHES_URL}/api/v3/repos/{self.repo_full_name}/pulls/{self.pr_number}"
            diff_headers = self.headers.copy(); diff_headers['Accept'] = 'application/vnd.github.v3.diff'
            diff_resp = requests.get(diff_url, headers=diff_headers, verify=VERIFY_SSL)
            if diff_resp.status_code != 200:
                raise Exception(f"Cannot get PR diff: {diff_resp.status_code}")
            diff_path = os.path.join(self.temp_dir, 'pr.diff')
            # Use context manager for writing diff file
            with open(diff_path, 'w') as f:
                f.write(diff_resp.text)
            base_clone_dir = os.path.join(self.temp_dir, 'base_repo')
            token = self.headers['Authorization'].replace('token ','')
            auth_clone_url = f"https://x-access-token:{token}@{GHES_URL.replace('https://','')}/{self.repo_full_name}.git"
            clone_res = subprocess.run(['git','clone','--shallow-since','1 month ago','--branch', self.pr_data['base']['ref'], auth_clone_url, base_clone_dir], capture_output=True, text=True, timeout=60)
            if clone_res.returncode != 0:
                raise Exception(f"Git clone failed: {clone_res.stderr}")
            # First try apply with whitespace fix, then 3way for modifications  
            normal_apply_res = subprocess.run(['git','apply','--whitespace=fix', diff_path], cwd=base_clone_dir, capture_output=True, text=True, timeout=30)
            if normal_apply_res.returncode != 0:
                logger.info(f"Git apply failed, trying --3way: {normal_apply_res.stderr[:200]}")
                threeway_apply_res = subprocess.run(['git','apply','--3way','--ignore-whitespace', diff_path], cwd=base_clone_dir, capture_output=True, text=True, timeout=30)
                apply_res = threeway_apply_res
            else:
                apply_res = normal_apply_res
            stderr_lower = apply_res.stderr.lower()
            applied_some = stderr_lower.count('applied patch') + stderr_lower.count('cleanly')
            self.diff_applied = apply_res.returncode == 0 or applied_some > 0
            if apply_res.returncode != 0:
                logger.warning(f"Git apply stderr: {apply_res.stderr[:500]}")
            downloaded = []
            diff_content = diff_resp.text
            for fp in file_paths:
                sp = os.path.join(base_clone_dir, fp)
                if os.path.exists(sp):
                    downloaded.append(sp)
                    in_diff = f"--- a/{fp}" in diff_content or f"+++ b/{fp}" in diff_content
                    applied_clean = f"Applied patch {fp} cleanly" in apply_res.stderr
                    if in_diff and (apply_res.returncode == 0 or applied_clean):
                        self.files_from_diff.append(fp)
                    else:
                        self.files_from_base.append(fp)
                else:
                    logger.warning(f"File not found after diff apply: {fp}")
            return downloaded
        except Exception as e:
            logger.error(f"download_files error: {e}")
            return []
    def validate(self):
        try:
            changed = self.get_changed_files()
            if not changed:
                return {'success': True, 'files_checked': 0, 'message': 'No files to validate'}
            downloaded = self.download_files(changed)
            if not downloaded:
                return {'success': False, 'error': 'Failed to download files for validation'}
            config_path = self.get_config_file()
            if not config_path:
                return {'success': False, 'error': 'Config not found'}
            script_path = self.get_copyright_script()
            if not script_path:
                return {'success': False, 'error': 'Script not found'}
            base_clone_dir = os.path.join(self.temp_dir, 'base_repo')
            rel_files = [os.path.relpath(f, base_clone_dir) for f in downloaded]
            origins_path = os.path.join(self.temp_dir, 'origins.txt')
            try:
                with open(origins_path,'w') as of:
                    for f in rel_files:
                        of.write(f"{f} {'PR' if f in self.files_from_diff else 'Base'}\n")
            except Exception:
                origins_path = None
            cmd = ['python3', script_path, '--config', config_path, '--working-dir', base_clone_dir]
            if origins_path:
                cmd += ['--origins-file', origins_path]
            cmd += rel_files
            # Inject COPYRIGHT_CHECK_COMMIT_SHA for uniform script header output
            run_env = os.environ.copy()
            try:
                run_env['COPYRIGHT_CHECK_COMMIT_SHA'] = self.pr_data['head']['sha']
            except Exception:
                pass
            proc = subprocess.run(cmd, cwd=base_clone_dir, capture_output=True, text=True, timeout=300, env=run_env)
            structured = None
            try:
                structured = parse_script_output_markdown(proc.stdout)
            except Exception as e:
                logger.error(f"Parsing markdown failed: {e}")
            if proc.returncode == 0:
                return {'success': True, 'files_checked': len(downloaded), 'structured': structured}
            return {'success': False, 'files_checked': len(downloaded), 'error': proc.stdout + proc.stderr, 'structured': structured}
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Validation timed out after 5 minutes'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def get_copyright_script(self):  # moved unchanged logic earlier, keep definition here for ordering clarity
        try:
            script_url = f"{SCRIPT_REPO_URL}/repos/{SCRIPT_REPO_OWNER}/{SCRIPT_REPO_NAME}/contents/scripts/copyrightcheck.py?ref={SCRIPT_BRANCH}"
            if SCRIPT_REPO_URL == 'https://api.github.com':
                resp = requests.get(script_url, verify=True)
            else:
                resp = requests.get(script_url, headers=self.headers, verify=VERIFY_SSL)
            if resp.status_code == 200:
                data = resp.json(); content = base64.b64decode(data['content']).decode('utf-8')
                path = os.path.join(self.temp_dir, 'copyrightcheck.py')
                # Use context manager for writing fetched script
                with open(path, 'w') as f:
                    f.write(content)
                return path
            logger.error(f"Failed to fetch script: {resp.status_code}")
            return None
        except Exception as e:
            logger.error(f"Script fetch error: {e}")
            return None

def create_status_check(access_token, repo_full_name, commit_sha, state, description):
    """Create a status check on the commit using direct API call"""
    try:
        # Truncate description to GitHub's 140 character limit
        max_description_length = 140
        if len(description) > max_description_length:
            description = description[:max_description_length-3] + "..."
            
        logger.info(f"Creating status check for {repo_full_name}@{commit_sha}: {state} - {description}")
        
        # Construct the API URL
        api_url = f"{GHES_URL}/api/v3/repos/{repo_full_name}/statuses/{commit_sha}"
        
        headers = {
            'Authorization': f'token {access_token}',
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'state': state,
            'description': description,
            'context': 'copyright-validation'
        }
        
        logger.info(f"Status check API URL: {api_url}")
        logger.info(f"Status check payload: {payload}")
        
        response = requests.post(api_url, json=payload, headers=headers, verify=VERIFY_SSL)
        
        if response.status_code in [200, 201]:
            logger.info("Status check created successfully")
            logger.info(f"Response: {response.text}")
        else:
            logger.error(f"Status check failed: {response.status_code}")
            logger.error(f"Response: {response.text}")
            raise Exception(f"API returned {response.status_code}: {response.text}")
            
    except Exception as e:
        logger.error(f"Failed to create status check: {e}", exc_info=True)
        raise

@app.route('/webhook', methods=['POST'])
def webhook():
    """Handle GitHub webhook events"""
    try:
        payload = request.get_json()
        if payload is None:
            logger.error("Received webhook with no JSON payload")
            return jsonify({'error': 'No JSON payload'}), 400
            
        event_type = request.headers.get('X-GitHub-Event')
        logger.info(f"Received webhook event: {event_type}")
        
        # Only handle pull request events
        if event_type != 'pull_request':
            return jsonify({'message': 'Event type not handled'}), 200
        
        action = payload.get('action')
        logger.info(f"PR action: {action}")
        if action not in ['opened', 'synchronize', 'reopened']:
            return jsonify({'message': 'PR action not handled'}), 200
        
        # Extract PR information with error checking
        try:
            repo_full_name = payload['repository']['full_name']
            pr_number = payload['pull_request']['number']
            commit_sha = payload['pull_request']['head']['sha']
            installation_id = payload['installation']['id']
        except KeyError as e:
            logger.error(f"Missing required field in webhook payload: {e}")
            return jsonify({'error': f'Missing field: {e}'}), 400
        
        logger.info(f"Processing PR #{pr_number} in {repo_full_name}")
        
        # Get access token for this installation
        try:
            access_token = get_installation_access_token(installation_id)
        except Exception as e:
            logger.error(f"Failed to get access token: {e}")
            return jsonify({'error': 'Authentication failed'}), 500
        
        # Create pending status
        try:
            create_status_check(
                access_token,
                repo_full_name,
                commit_sha,
                'pending',
                'Copyright check running...'
            )
        except Exception as e:
            logger.error(f"Failed to create pending status: {e}")
            return jsonify({'error': 'Failed to create status check'}), 500
        
        # Run copyright validation
        try:
            with CopyrightValidator(access_token, repo_full_name, pr_number) as validator:
                result = validator.validate()
        except Exception as e:
            logger.error(f"Copyright validation failed: {e}")
            # Try to create failure status
            try:
                create_status_check(
                    access_token,
                    repo_full_name,
                    commit_sha,
                    'error',
                    f'Copyright validation error: {str(e)}'
                )
            except:
                pass  # Don't fail if we can't create status
            return jsonify({'error': f'Validation failed: {str(e)}'}), 500
        
        # Create status check based on results
        if result['success']:
            structured = result.get('structured')
            if structured:
                counts = structured.get('counts', {})
                valid_count = counts.get('valid')
                excluded_count = counts.get('excluded')
                description = f"Copyright validation passed ({valid_count} files valid"
                if excluded_count:
                    description += f", {excluded_count} excluded"
                description += ")"
            else:
                description = f"Copyright validation passed ({result.get('files_checked', 0)} files)"
            # (Old per-file count description retained above but not used in final status message)
        else:
            structured = result.get('structured')
            if structured and structured.get('counts'):
                counts = structured['counts']
                invalid_count = counts.get('invalid', 0)
                display_count = invalid_count or 1
            else:
                display_count = 1
            logger.info(f"Debug - Status check invalid file count: {display_count}")
        
        # Create / update PR comment and capture action
        comment_action = 'unavailable'
        try:
            structured = result.get('structured')
            if structured:
                body = build_summary_comment(structured, commit_sha)
                existing_id = find_existing_comment(access_token, repo_full_name, pr_number)
                if existing_id:
                    update_pr_comment(access_token, repo_full_name, existing_id, body)
                    comment_action = 'updated'
                else:
                    create_pr_comment(access_token, repo_full_name, pr_number, body)
                    comment_action = 'created'
        except Exception as e:
            logger.error(f"PR comment failure: {e}")
            comment_action = 'unavailable'
        
        # Unified final status description per template
        try:
            base_desc = f"Copyright check {'passed' if result['success'] else 'failed'}."
            if comment_action in ('updated','created'):
                final_desc = f"{base_desc} See the {comment_action} PR comment."
            else:
                final_desc = f"{base_desc} PR comment unavailable."
            create_status_check(
                access_token,
                repo_full_name,
                commit_sha,
                'success' if result['success'] else 'failure',
                final_desc
            )
        except Exception:
            pass
        
        logger.info(f"Copyright validation completed for PR #{pr_number}: {'PASSED' if result['success'] else 'FAILED'} (comment_action={comment_action})")
        
        return jsonify({'message': 'Webhook processed successfully'}), 200
        
    except Exception as e:
        logger.error(f"Webhook processing failed: {e}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    missing = [v for v in ['GITHUB_APP_ID','GITHUB_PRIVATE_KEY'] if not os.environ.get(v)]
    if missing:
        logger.error(f"Missing required environment variables: {missing}")
        exit(1)
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
