#!/usr/bin/env python3
"""
GitHub App for Copyright Validation on GHES

This app listens to PR webhooks and validates copyright headers
using the same copyrightcheck.py script as the GitHub Actions workflow.
"""

import os
import json
import logging
import tempfile
import requests
from flask import Flask, request, jsonify
from github import Github, GithubIntegration
import subprocess
import shutil
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# GitHub App configuration
APP_ID = os.environ.get('GITHUB_APP_ID')
PRIVATE_KEY = os.environ.get('GITHUB_PRIVATE_KEY')
WEBHOOK_SECRET = os.environ.get('GITHUB_WEBHOOK_SECRET')
GHES_URL = os.environ.get('GITHUB_ENTERPRISE_URL', 'https://github.com')

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

# Initialize GitHub Integration
def create_integration():
    """Create GitHub Integration with error handling"""
    try:
        logger.info("Creating GitHub Integration...")
        integration = GithubIntegration(APP_ID, PRIVATE_KEY, base_url=f"{GHES_URL}/api/v3")
        logger.info("GitHub Integration initialized successfully")
        return integration
    except Exception as e:
        logger.error(f"Failed to create GitHub Integration: {e}")
        return None

integration = create_integration()

if integration:
    # Test the integration by getting app info
    try:
        app_info = integration.get_app()
        if app_info:
            logger.info(f"GitHub App verified: {getattr(app_info, 'name', 'Unknown')} (ID: {getattr(app_info, 'id', 'Unknown')})")
        else:
            logger.warning("App info returned None")
    except Exception as e:
        logger.warning(f"Could not verify app info (this might be okay): {e}")
else:
    logger.error("GitHub Integration could not be created")
        
except Exception as e:
    logger.error(f"Failed to initialize GitHub Integration: {str(e)}")
    logger.error(f"APP_ID: {APP_ID}")
    logger.error(f"PRIVATE_KEY length: {len(PRIVATE_KEY) if PRIVATE_KEY else 'None'}")
    logger.error(f"GHES_URL: {GHES_URL}")
    raise

class CopyrightValidator:
    def __init__(self, github_client, repo_full_name, pr_number):
        try:
            logger.info(f"Initializing CopyrightValidator for {repo_full_name}#{pr_number}")
            self.github = github_client
            
            logger.info(f"Getting repository: {repo_full_name}")
            self.repo = self.github.get_repo(repo_full_name)
            
            logger.info(f"Getting pull request #{pr_number}")
            self.pr = self.repo.get_pull(pr_number)
            
            self.temp_dir = None
            logger.info("CopyrightValidator initialized successfully")
            
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
        """Get .copyrightconfig from PR head or base repo"""
        config_content = None
        config_source = None
        
        try:
            logger.info("Attempting to get config from PR head...")
            # Try to get config from PR head first
            head_repo_name = self.pr.head.repo.full_name
            logger.info(f"Getting repository: {head_repo_name}")
            head_repo = self.github.get_repo(head_repo_name)
            
            logger.info(f"Getting .copyrightconfig from {head_repo_name} at {self.pr.head.sha}")
            config_file = head_repo.get_contents('.copyrightconfig', ref=self.pr.head.sha)
            config_content = config_file.decoded_content.decode('utf-8')
            config_source = "PR head"
            logger.info(f"Found .copyrightconfig in PR head")
        except Exception as e:
            logger.info(f"Config not found in PR head: {e}")
            
            try:
                logger.info("Attempting to get config from base repository...")
                # Fallback to base repo
                base_repo_name = self.repo.full_name
                logger.info(f"Getting .copyrightconfig from {base_repo_name} at {self.pr.base.ref}")
                config_file = self.repo.get_contents('.copyrightconfig', ref=self.pr.base.ref)
                config_content = config_file.decoded_content.decode('utf-8')
                config_source = "base repository"
                logger.info(f"Found .copyrightconfig in base repository")
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
            
        return config_path, config_source
    
    def get_changed_files(self):
        """Get list of changed files in the PR"""
        try:
            files = []
            pr_files = self.pr.get_files()
            
            if pr_files is None:
                logger.warning("PR get_files() returned None")
                return []
                
            for file in pr_files:
                if file and file.status in ['added', 'modified']:  # Skip deleted files
                    files.append(file.filename)
            
            logger.info(f"Found {len(files)} changed files: {files}")
            return files
            
        except Exception as e:
            logger.error(f"Error getting changed files: {e}")
            return []
    
    def download_file_content(self, file_path):
        """Download file content from PR head"""
        try:
            head_repo = self.github.get_repo(self.pr.head.repo.full_name)
            file_content = head_repo.get_contents(file_path, ref=self.pr.head.sha)
            
            # Save file to temp directory
            full_path = os.path.join(self.temp_dir, 'target-repo', file_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            
            with open(full_path, 'wb') as f:
                f.write(file_content.decoded_content)
            
            return full_path
        except Exception as e:
            logger.error(f"Failed to download {file_path}: {e}")
            return None
    
    def get_copyright_script(self):
        """Get path to the local copyright validation script"""
        script_path = '/app/copyrightcheck.py'
        
        if not os.path.exists(script_path):
            logger.error(f"Copyright script not found at {script_path}")
            return None
            
        return script_path
    
    def validate_copyright(self):
        """Run copyright validation and return results"""
        try:
            # Get configuration
            logger.info("Getting configuration file...")
            config_path, config_source = self.get_config_file()
            if not config_path:
                return {
                    'success': False,
                    'error': 'No .copyrightconfig file found in PR head or base repository'
                }
            
            # Get copyright script
            logger.info("Getting copyright script...")
            script_path = self.get_copyright_script()
            if not script_path:
                return {
                    'success': False,
                    'error': 'Copyright validation script not available'
                }
            
            # Get changed files
            logger.info("Getting changed files...")
            changed_files = self.get_changed_files()
            if not changed_files:
                return {
                    'success': True,
                    'message': 'No files to validate',
                    'files_checked': 0
                }
            
            # Download changed files
            logger.info(f"Downloading {len(changed_files)} files...")
            downloaded_files = []
            for file_path in changed_files:
                logger.info(f"Downloading file: {file_path}")
                local_path = self.download_file_content(file_path)
                if local_path:
                    downloaded_files.append(local_path)
            
            if not downloaded_files:
                return {
                    'success': False,
                    'error': 'No files could be downloaded for validation'
                }
            
            # Run copyright validation
            logger.info(f"Running copyright validation on {len(downloaded_files)} files...")
            try:
                cmd = ['python3', script_path, '-c', config_path, '-v'] + downloaded_files
                logger.info(f"Running command: {' '.join(cmd)}")
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd=self.temp_dir
                )
                
                logger.info(f"Command exit code: {result.returncode}")
                if result.stdout:
                    logger.info(f"Command stdout: {result.stdout}")
                if result.stderr:
                    logger.error(f"Command stderr: {result.stderr}")
                
                return {
                    'success': result.returncode == 0,
                    'exit_code': result.returncode,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'files_checked': len(downloaded_files),
                    'config_source': config_source
                }
                
            except Exception as e:
                logger.error(f"Failed to run copyright validation subprocess: {str(e)}")
                return {
                    'success': False,
                    'error': f'Failed to run copyright validation: {str(e)}'
                }
                
        except Exception as e:
            logger.error(f"Exception in validate_copyright: {str(e)}", exc_info=True)
            return {
                'success': False,
                'error': f'Validation error: {str(e)}'
            }

def get_installation_client(installation_id):
    """Get GitHub client for a specific installation"""
    try:
        logger.info(f"Getting access token for installation ID: {installation_id}")
        
        # Debug: Check if integration object is valid
        if integration is None:
            logger.error("Integration object is None")
            raise ValueError("GitHub Integration not initialized")
        
        logger.info(f"Integration object type: {type(integration)}")
        logger.info(f"App ID: {APP_ID}, GHES URL: {GHES_URL}")
        
        # Debug: Check if private key is valid
        if PRIVATE_KEY is None:
            logger.error("Private key is None")
            raise ValueError("Private key not set")
            
        logger.info(f"Private key length: {len(PRIVATE_KEY) if PRIVATE_KEY else 'None'}")
        
        # Debug: Test if we can make a basic API call first
        try:
            logger.info("Testing basic API access by getting app info...")
            app_info = integration.get_app()
            logger.info(f"App info retrieved: {app_info.name} (ID: {app_info.id})")
        except Exception as e:
            logger.error(f"Failed to get app info: {e}")
            raise ValueError(f"Cannot access GitHub API: {e}")
        
        # Debug: List all installations first
        try:
            logger.info("Getting list of installations...")
            installations = integration.get_installations()
            install_list = [(install.id, install.account.login) for install in installations]
            logger.info(f"Available installations: {install_list}")
            
            # Check if our installation ID is in the list
            install_ids = [install.id for install in installations]
            if installation_id not in install_ids:
                logger.error(f"Installation ID {installation_id} not found in available installations: {install_ids}")
                raise ValueError(f"Installation {installation_id} not accessible")
                
        except Exception as e:
            logger.error(f"Failed to get installations: {e}")
            # Continue anyway, maybe it's a permission issue with listing
        
        # Try to get access token
        logger.info(f"Calling integration.get_access_token({installation_id})...")
        access_token = integration.get_access_token(installation_id)
        logger.info("Access token obtained successfully")
        
        if access_token is None:
            logger.error("Access token is None")
            raise ValueError("Failed to get access token")
            
        logger.info(f"Access token type: {type(access_token)}")
        
        # Create GitHub client
        base_url = f"{GHES_URL}/api/v3"
        logger.info(f"Creating GitHub client with base URL: {base_url}")
        github_client = Github(access_token.token, base_url=base_url)
        logger.info("GitHub client created successfully")
        return github_client
        
    except Exception as e:
        logger.error(f"Failed to get GitHub client for installation {installation_id}: {str(e)}", exc_info=True)
        raise

def create_status_check(github_client, repo_full_name, commit_sha, state, description, details_url=None):
    """Create a status check on the commit"""
    try:
        logger.info(f"Creating status check for {repo_full_name}@{commit_sha}: {state} - {description}")
        repo = github_client.get_repo(repo_full_name)
        repo.create_status(
            sha=commit_sha,
            state=state,  # pending, success, error, failure
            target_url=details_url,
            description=description,
            context="copyright-validation"
        )
        logger.info("Status check created successfully")
    except Exception as e:
        logger.error(f"Failed to create status check: {e}")
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
            pr_data = payload['pull_request']
            repo_full_name = payload['repository']['full_name']
            installation_id = payload['installation']['id']
            pr_number = pr_data['number']
            commit_sha = pr_data['head']['sha']
        except KeyError as e:
            logger.error(f"Missing required field in webhook payload: {e}")
            return jsonify({'error': f'Missing field: {e}'}), 400
        
        logger.info(f"Processing PR #{pr_number} in {repo_full_name}")
        
        # Get GitHub client for this installation
        try:
            github_client = get_installation_client(installation_id)
        except Exception as e:
            logger.error(f"Failed to get GitHub client: {e}")
            return jsonify({'error': 'Authentication failed'}), 500
        
        # Create pending status
        try:
            create_status_check(
                github_client,
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
            with CopyrightValidator(github_client, repo_full_name, pr_number) as validator:
                result = validator.validate_copyright()
        except Exception as e:
            logger.error(f"Copyright validation failed: {e}")
            # Try to create failure status
            try:
                create_status_check(
                    github_client,
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
                github_client,
                repo_full_name,
                commit_sha,
                'success',
                f"Copyright validation passed ({result.get('files_checked', 0)} files checked)"
            )
        else:
            create_status_check(
                github_client,
                repo_full_name,
                commit_sha,
                'failure',
                f"Copyright validation failed: {result.get('error', 'Unknown error')}"
            )
        
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
    """Debug endpoint to test GitHub integration"""
    try:
        logger.info("Debug: Testing GitHub integration...")
        
        # Check if integration was created successfully
        if not integration:
            return jsonify({'error': 'GitHub Integration not initialized'}), 500
        
        # Check environment variables
        debug_info = {
            'app_id': APP_ID,
            'has_private_key': PRIVATE_KEY is not None,
            'private_key_length': len(PRIVATE_KEY) if PRIVATE_KEY else 0,
            'private_key_starts_with': PRIVATE_KEY[:50] if PRIVATE_KEY else None,
            'ghes_url': GHES_URL,
            'integration_type': str(type(integration)),
        }
        
        logger.info(f"Debug info: {debug_info}")
        
        # Test getting app info
        try:
            app_info = integration.get_app()
            debug_info['app_name'] = getattr(app_info, 'name', None)
            debug_info['app_owner'] = getattr(app_info.owner, 'login', None) if hasattr(app_info, 'owner') and app_info.owner else None
            debug_info['app_test'] = 'success'
        except Exception as e:
            debug_info['app_error'] = str(e)
            logger.error(f"App info error: {e}", exc_info=True)
            
        # Test getting installations
        try:
            installations = integration.get_installations()
            install_list = []
            for install in installations:
                install_id = getattr(install, 'id', None)
                account_login = getattr(install.account, 'login', None) if hasattr(install, 'account') and install.account else None
                if install_id:
                    install_list.append((install_id, account_login))
            debug_info['installations'] = install_list
            debug_info['installation_count'] = len(install_list)
        except Exception as e:
            debug_info['installations_error'] = str(e)
            logger.error(f"Installations error: {e}", exc_info=True)
            
        # Test with a sample installation ID (if provided)
        installation_id = request.args.get('installation_id')
        if installation_id:
            try:
                installation_id = int(installation_id)
                debug_info['testing_installation'] = installation_id
                
                # Check if this installation is in our list
                if 'installations' in debug_info:
                    install_ids = [install[0] for install in debug_info['installations']]
                    debug_info['installation_in_list'] = installation_id in install_ids
                
                access_token = integration.get_access_token(installation_id)
                debug_info['token_test'] = 'success'
                debug_info['token_length'] = len(access_token.token)
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
