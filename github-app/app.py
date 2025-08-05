#!/usr/bin/env python3
"""
GitHub App for Copyright Validation on GHES

This app listens to PR webhooks and validates copyright headers
using direct API calls (no PyGithub dependency for GHES compatibility).
"""

import os
import json
import logging
import tempfile
import requests
from flask import Flask, request, jsonify
import jwt
import time
import subprocess
import shutil
from pathlib import Path
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# GitHub App configuration
APP_ID = os.environ.get('GITHUB_APP_ID')
PRIVATE_KEY = os.environ.get('GITHUB_PRIVATE_KEY')
WEBHOOK_SECRET = os.environ.get('GITHUB_WEBHOOK_SECRET')
GHES_URL = os.environ.get('GITHUB_ENTERPRISE_URL', 'https://github.com').rstrip('/')  # Remove trailing slash

# Script repository configuration (defaults to GitHub.com)
SCRIPT_REPO_URL = os.environ.get('SCRIPT_REPO_URL', 'https://api.github.com')
SCRIPT_REPO_OWNER = os.environ.get('SCRIPT_REPO_OWNER', 'marklogic')
SCRIPT_REPO_NAME = os.environ.get('SCRIPT_REPO_NAME', 'pr-workflows')
SCRIPT_BRANCH = os.environ.get('SCRIPT_BRANCH', 'copyright')

# GHES-specific options
VERIFY_SSL = os.environ.get('VERIFY_SSL', 'true').lower() == 'true'

# Validate required environment variables
if not APP_ID:
    logger.error("GITHUB_APP_ID environment variable is required")
    raise ValueError("GITHUB_APP_ID not set")

if not PRIVATE_KEY:
    logger.error("GITHUB_PRIVATE_KEY environment variable is required")
    raise ValueError("GITHUB_PRIVATE_KEY not set")

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
            logger.error(f"Failed to get installation token: {response.status_code}")
            logger.error(f"Response: {response.text}")
            raise Exception(f"Token request failed: {response.status_code}")
            
    except Exception as e:
        logger.error(f"Failed to get installation access token: {e}")
        raise

# Test GitHub App setup
jwt_token = create_jwt_token()
if jwt_token:
    logger.info("GitHub App JWT token created successfully")
else:
    logger.error("Failed to create GitHub App JWT token")

class CopyrightValidator:
    def __init__(self, access_token, repo_full_name, pr_number):
        try:
            logger.info(f"Initializing CopyrightValidator for {repo_full_name}#{pr_number}")
            self.access_token = access_token
            self.repo_full_name = repo_full_name
            self.pr_number = pr_number
            self.temp_dir = None
            
            # API headers
            self.headers = {
                'Authorization': f'token {access_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            # Get PR data
            pr_url = f"{GHES_URL}/api/v3/repos/{repo_full_name}/pulls/{pr_number}"
            logger.info(f"Getting PR data from: {pr_url}")
            
            response = requests.get(pr_url, headers=self.headers, verify=VERIFY_SSL)
            if response.status_code != 200:
                raise Exception(f"Failed to get PR data: {response.status_code}")
            
            self.pr_data = response.json()
            logger.info(f"PR data retrieved successfully: {self.pr_data['title']}")
            
        except Exception as e:
            logger.error(f"Failed to initialize CopyrightValidator: {e}")
            raise
        
    def __enter__(self):
        """Context manager entry - create temp directory"""
        self.temp_dir = tempfile.mkdtemp()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup temp directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def get_config_file(self):
        """Get .copyrightconfig from PR head or base repo using direct API calls"""
        config_content = None
        config_source = None
        
        try:
            logger.info("Attempting to get config from PR head...")
            # Try to get config from PR head first
            head_repo_name = self.pr_data['head']['repo']['full_name']
            head_sha = self.pr_data['head']['sha']
            
            config_url = f"{GHES_URL}/api/v3/repos/{head_repo_name}/contents/.copyrightconfig?ref={head_sha}"
            logger.info(f"Getting config from: {config_url}")
            
            response = requests.get(config_url, headers=self.headers, verify=VERIFY_SSL)
            if response.status_code == 200:
                config_data = response.json()
                config_content = base64.b64decode(config_data['content']).decode('utf-8')
                config_source = "PR head"
                logger.info(f"Found .copyrightconfig in PR head")
            else:
                raise Exception(f"Config not found in PR head: {response.status_code}")
                
        except Exception as e:
            logger.info(f"Config not found in PR head: {e}")
            
            try:
                logger.info("Attempting to get config from base repository...")
                # Fallback to base repo
                base_repo_name = self.pr_data['base']['repo']['full_name']
                base_ref = self.pr_data['base']['ref']
                
                config_url = f"{GHES_URL}/api/v3/repos/{base_repo_name}/contents/.copyrightconfig?ref={base_ref}"
                logger.info(f"Getting config from: {config_url}")
                
                response = requests.get(config_url, headers=self.headers, verify=VERIFY_SSL)
                if response.status_code == 200:
                    config_data = response.json()
                    config_content = base64.b64decode(config_data['content']).decode('utf-8')
                    config_source = "base repository"
                    logger.info(f"Found .copyrightconfig in base repository")
                else:
                    raise Exception(f"Config not found in base repo: {response.status_code}")
                    
            except Exception as e:
                logger.error(f"Config not found in base repo either: {e}")
                return None, None
        
        if config_content is None:
            logger.error("Config content is None after processing")
            return None, None
            
        # Save config to temp file
        config_path = os.path.join(self.temp_dir, '.copyrightconfig')
        try:
            with open(config_path, 'w') as f:
                f.write(config_content)
        except Exception as e:
            logger.error(f"Failed to write config file: {e}")
            return None, None
            
        logger.info(f"Config file saved to {config_path} (source: {config_source})")
        return config_path, config_source

    def get_changed_files(self):
        """Get list of changed files from PR using direct API call"""
        try:
            # Get PR files
            files_url = f"{GHES_URL}/api/v3/repos/{self.repo_full_name}/pulls/{self.pr_number}/files"
            logger.info(f"Getting changed files from: {files_url}")
            
            response = requests.get(files_url, headers=self.headers, verify=VERIFY_SSL)
            if response.status_code != 200:
                raise Exception(f"Failed to get PR files: {response.status_code}")
            
            files_data = response.json()
            changed_files = []
            
            for file_data in files_data:
                if file_data['status'] in ['added', 'modified']:
                    filename = file_data['filename']
                    # Skip dotfiles
                    if not filename.startswith('.'):
                        changed_files.append(filename)
                        logger.info(f"Changed file: {filename}")
            
            logger.info(f"Found {len(changed_files)} changed files (excluding dotfiles)")
            return changed_files
            
        except Exception as e:
            logger.error(f"Failed to get changed files: {e}")
            return []

    def download_files(self, file_paths):
        """Download files from PR head using direct API call"""
        try:
            downloaded_files = []
            head_sha = self.pr_data['head']['sha']
            head_repo_name = self.pr_data['head']['repo']['full_name']
            
            for file_path in file_paths:
                try:
                    # Get file content
                    file_url = f"{GHES_URL}/api/v3/repos/{head_repo_name}/contents/{file_path}?ref={head_sha}"
                    logger.info(f"Downloading file: {file_url}")
                    
                    response = requests.get(file_url, headers=self.headers, verify=VERIFY_SSL)
                    if response.status_code == 200:
                        file_data = response.json()
                        
                        # Decode file content
                        if file_data.get('encoding') == 'base64':
                            file_content = base64.b64decode(file_data['content']).decode('utf-8')
                        else:
                            file_content = file_data['content']
                        
                        # Save to temp directory
                        local_path = os.path.join(self.temp_dir, file_path)
                        os.makedirs(os.path.dirname(local_path), exist_ok=True)
                        
                        with open(local_path, 'w') as f:
                            f.write(file_content)
                            
                        downloaded_files.append(local_path)
                        logger.info(f"Downloaded: {file_path}")
                    else:
                        logger.warning(f"Failed to download {file_path}: {response.status_code}")
                        
                except Exception as e:
                    logger.error(f"Error downloading {file_path}: {e}")
                    continue
            
            logger.info(f"Downloaded {len(downloaded_files)} files")
            return downloaded_files
            
        except Exception as e:
            logger.error(f"Failed to download files: {e}")
            return []

    def get_copyright_script(self):
        """Download copyright validation script from pr-workflows repo"""
        try:
            # Get script from configured repository (defaults to GitHub.com)
            script_url = f"{SCRIPT_REPO_URL}/repos/{SCRIPT_REPO_OWNER}/{SCRIPT_REPO_NAME}/contents/scripts/copyrightcheck.py?ref={SCRIPT_BRANCH}"
            logger.info(f"Getting copyright script from: {script_url}")
            
            # For GitHub.com, try without authentication first (public repo)
            if SCRIPT_REPO_URL == 'https://api.github.com':
                response = requests.get(script_url, verify=True)
            else:
                # For other instances, use authentication
                response = requests.get(script_url, headers=self.headers, verify=VERIFY_SSL)
                
            if response.status_code == 200:
                script_data = response.json()
                script_content = base64.b64decode(script_data['content']).decode('utf-8')
                
                # Save script to temp directory
                script_path = os.path.join(self.temp_dir, 'copyrightcheck.py')
                with open(script_path, 'w') as f:
                    f.write(script_content)
                    
                logger.info(f"Copyright script saved to {script_path}")
                return script_path
            else:
                logger.error(f"Failed to get copyright script: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to get copyright script: {e}")
            return None

    def validate_copyright(self):
        """Run copyright validation"""
        try:
            logger.info("Starting copyright validation...")
            
            # Get configuration file
            config_path, config_source = self.get_config_file()
            if not config_path:
                return {'success': False, 'error': 'Copyright configuration file not found'}
            
            # Get changed files
            changed_files = self.get_changed_files()
            if not changed_files:
                return {'success': True, 'files_checked': 0, 'message': 'No files to validate'}
            
            # Download changed files
            downloaded_files = self.download_files(changed_files)
            if not downloaded_files:
                return {'success': False, 'error': 'Failed to download files for validation'}
            
            # Get copyright validation script
            script_path = self.get_copyright_script()
            if not script_path:
                return {'success': False, 'error': 'Copyright validation script not found'}
            
            # Run copyright validation
            logger.info(f"Running copyright validation on {len(downloaded_files)} files...")
            result = subprocess.run([
                'python3', script_path,
                '--config', config_path
            ] + downloaded_files,  # Add files as positional arguments
                cwd=self.temp_dir,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            logger.info(f"Copyright validation completed with exit code: {result.returncode}")
            logger.info(f"Stdout: {result.stdout}")
            if result.stderr:
                logger.warning(f"Stderr: {result.stderr}")
            
            if result.returncode == 0:
                return {
                    'success': True,
                    'files_checked': len(downloaded_files),
                    'config_source': config_source,
                    'output': result.stdout
                }
            else:
                return {
                    'success': False,
                    'files_checked': len(downloaded_files),
                    'config_source': config_source,
                    'error': result.stdout + result.stderr,
                    'output': result.stdout
                }
                
        except subprocess.TimeoutExpired:
            logger.error("Copyright validation timed out")
            return {'success': False, 'error': 'Validation timed out after 5 minutes'}
        except Exception as e:
            logger.error(f"Copyright validation failed: {e}")
            return {'success': False, 'error': str(e)}

def create_status_check(access_token, repo_full_name, commit_sha, state, description, details_url=None):
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
        
        if details_url:
            payload['target_url'] = details_url
            
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

def create_pr_comment(access_token, repo_full_name, pr_number, comment_body):
    """Create a comment on the PR with detailed validation results"""
    try:
        logger.info(f"Creating PR comment on {repo_full_name}#{pr_number}")
        
        # Construct the API URL for PR comments
        api_url = f"{GHES_URL}/api/v3/repos/{repo_full_name}/issues/{pr_number}/comments"
        
        headers = {
            'Authorization': f'token {access_token}',
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'body': comment_body
        }
        
        logger.info(f"PR comment API URL: {api_url}")
        
        response = requests.post(api_url, json=payload, headers=headers, verify=VERIFY_SSL)
        
        if response.status_code in [200, 201]:
            logger.info("PR comment created successfully")
            comment_data = response.json()
            return comment_data.get('html_url')
        else:
            logger.error(f"PR comment failed: {response.status_code}")
            logger.error(f"Response: {response.text}")
            # Don't raise exception - commenting is optional
            return None
            
    except Exception as e:
        logger.error(f"Failed to create PR comment: {e}")
        # Don't raise exception - commenting is optional
        return None

def format_validation_comment(result):
    """Format validation results into a GitHub markdown comment"""
    if result['success']:
        # Success comment
        files_checked = result.get('files_checked', 0)
        emoji = "✅"
        title = "Copyright Validation Passed"
        summary = f"All {files_checked} file{'s' if files_checked != 1 else ''} passed copyright validation."
        
        comment = f"""## {emoji} {title}

{summary}

<details>
<summary>Validation Details</summary>

```
{result.get('output', 'No detailed output available.')}
```

</details>
"""
    else:
        # Failure comment
        emoji = "❌"
        title = "Copyright Validation Failed"
        output = result.get('output', '')
        
        # Extract summary from output
        files_checked = result.get('files_checked', 0)
        invalid_count = output.count('❌') if output else 1
        valid_count = files_checked - invalid_count if files_checked > 0 else 0
        
        summary = f"Copyright validation failed for {invalid_count} file{'s' if invalid_count != 1 else ''}."
        if valid_count > 0:
            summary += f" {valid_count} file{'s' if valid_count != 1 else ''} passed."
        
        comment = f"""## {emoji} {title}

{summary}

<details>
<summary>Validation Results</summary>

```
{output}
```

</details>

### 🔧 How to Fix

1. **Add copyright header** to the beginning of each file
2. **Use the expected format** shown in the validation results
3. **Update year range** if needed (e.g., 2003-2025)
4. **Commit and push** your changes

The validation will run again automatically when you update the PR.
"""
    
    return comment

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
            pr_data = payload['pull_request']
            repo_full_name = payload['repository']['full_name']
            pr_number = pr_data['number']
            commit_sha = pr_data['head']['sha']
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
                'Copyright validation in progress...'
            )
        except Exception as e:
            logger.error(f"Failed to create pending status: {e}")
            return jsonify({'error': 'Failed to create status check'}), 500
        
        # Run copyright validation
        try:
            with CopyrightValidator(access_token, repo_full_name, pr_number) as validator:
                result = validator.validate_copyright()
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
            create_status_check(
                access_token,
                repo_full_name,
                commit_sha,
                'success',
                f"Copyright validation passed ({result.get('files_checked', 0)} files)"
            )
        else:
            # Count invalid files for concise message
            invalid_count = result.get('output', '').count('❌') if result.get('output') else 1
            create_status_check(
                access_token,
                repo_full_name,
                commit_sha,
                'failure',
                f"Copyright validation failed ({invalid_count} file{'s' if invalid_count != 1 else ''} invalid)"
            )
        
        # Create PR comment with detailed results
        try:
            comment_body = format_validation_comment(result)
            comment_url = create_pr_comment(access_token, repo_full_name, pr_number, comment_body)
            if comment_url:
                logger.info(f"PR comment created: {comment_url}")
            else:
                logger.warning("PR comment creation failed (check if app has 'Pull requests: Write' permission)")
        except Exception as e:
            logger.error(f"Failed to create PR comment: {e}")
            logger.warning("PR comment failed - continuing with status check only")
        
        # Create PR comment with detailed results
        try:
            comment_body = format_validation_comment(result)
            create_pr_comment(access_token, repo_full_name, pr_number, comment_body)
        except Exception as e:
            logger.error(f"Failed to create PR comment: {e}")
        
        logger.info(f"Copyright validation completed for PR #{pr_number}: {'PASSED' if result['success'] else 'FAILED'}")
        
        return jsonify({'message': 'Webhook processed successfully'}), 200
        
    except Exception as e:
        logger.error(f"Webhook processing failed: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200

@app.route('/debug/integration', methods=['GET'])
def debug_integration():
    """Debug endpoint to test GitHub integration using direct API calls"""
    try:
        logger.info("Debug: Testing GitHub integration with direct API calls...")
        
        # Check environment variables
        debug_info = {
            'app_id': APP_ID,
            'has_private_key': PRIVATE_KEY is not None,
            'private_key_length': len(PRIVATE_KEY) if PRIVATE_KEY else 0,
            'private_key_starts_with': PRIVATE_KEY[:50] if PRIVATE_KEY else None,
            'ghes_url': GHES_URL,
            'using_direct_api': True,
        }
        
        # Test JWT token creation
        try:
            jwt_token = create_jwt_token()
            if jwt_token:
                debug_info['jwt_test'] = 'success'
                debug_info['jwt_length'] = len(jwt_token)
            else:
                debug_info['jwt_test'] = 'failed'
        except Exception as e:
            debug_info['jwt_error'] = str(e)
            return jsonify(debug_info), 500
        
        # Test app info endpoint
        try:
            headers = {
                'Authorization': f'Bearer {jwt_token}',
                'Accept': 'application/vnd.github.v3+json'
            }
            
            app_url = f"{GHES_URL}/api/v3/app"
            response = requests.get(app_url, headers=headers, verify=VERIFY_SSL)
            
            if response.status_code == 200:
                app_data = response.json()
                debug_info['app_test'] = 'success'
                debug_info['app_name'] = app_data.get('name')
                debug_info['app_installations_count'] = app_data.get('installations_count', 0)
            else:
                debug_info['app_error'] = f"HTTP {response.status_code}: {response.text[:200]}"
                
        except Exception as e:
            debug_info['app_error'] = str(e)
        
        # Test installations endpoint
        try:
            install_url = f"{GHES_URL}/api/v3/app/installations"
            response = requests.get(install_url, headers=headers, verify=VERIFY_SSL)
            
            if response.status_code == 200:
                installations = response.json()
                debug_info['installations_test'] = 'success'
                debug_info['installation_count'] = len(installations)
                
                install_list = []
                for install in installations:
                    install_id = install.get('id')
                    account_login = install.get('account', {}).get('login') if install.get('account') else None
                    install_list.append((install_id, account_login))
                
                debug_info['installations'] = install_list
            else:
                debug_info['installations_error'] = f"HTTP {response.status_code}: {response.text[:200]}"
                
        except Exception as e:
            debug_info['installations_error'] = str(e)
        
        # Test installation access token (if installation ID provided)
        installation_id = request.args.get('installation_id')
        if installation_id:
            try:
                installation_id = int(installation_id)
                debug_info['testing_installation'] = installation_id
                
                access_token = get_installation_access_token(installation_id)
                debug_info['token_test'] = 'success'
                debug_info['token_length'] = len(access_token)
                
            except Exception as e:
                debug_info['token_error'] = str(e)
        
        return jsonify(debug_info), 200
        
    except Exception as e:
        logger.error(f"Debug integration failed: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Validate required environment variables
    required_vars = ['GITHUB_APP_ID', 'GITHUB_PRIVATE_KEY']
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {missing_vars}")
        exit(1)
    
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
