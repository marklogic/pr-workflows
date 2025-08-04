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

# Initialize GitHub Integration
integration = GithubIntegration(APP_ID, PRIVATE_KEY, base_url=f"{GHES_URL}/api/v3")

class CopyrightValidator:
    def __init__(self, github_client, repo_full_name, pr_number):
        self.github = github_client
        self.repo = self.github.get_repo(repo_full_name)
        self.pr = self.repo.get_pull(pr_number)
        self.temp_dir = None
        
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
            # Try to get config from PR head first
            head_repo = self.github.get_repo(self.pr.head.repo.full_name)
            config_file = head_repo.get_contents('.copyrightconfig', ref=self.pr.head.sha)
            config_content = config_file.decoded_content.decode('utf-8')
            config_source = "PR head"
            logger.info(f"Found .copyrightconfig in PR head")
        except Exception as e:
            logger.info(f"Config not found in PR head: {e}")
            
            try:
                # Fallback to base repo
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
    access_token = integration.get_access_token(installation_id)
    return Github(access_token.token, base_url=f"{GHES_URL}/api/v3")

def create_status_check(github_client, repo_full_name, commit_sha, state, description, details_url=None):
    """Create a status check on the commit"""
    repo = github_client.get_repo(repo_full_name)
    repo.create_status(
        sha=commit_sha,
        state=state,  # pending, success, error, failure
        target_url=details_url,
        description=description,
        context="copyright-validation"
    )

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
        create_status_check(
            github_client,
            repo_full_name,
            commit_sha,
            'pending',
            'Copyright validation in progress...'
        )
        
        # Run copyright validation
        with CopyrightValidator(github_client, repo_full_name, pr_number) as validator:
            result = validator.validate_copyright()
        
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

if __name__ == '__main__':
    # Validate required environment variables
    required_vars = ['GITHUB_APP_ID', 'GITHUB_PRIVATE_KEY']
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    if missing_vars:
        logger.error(f"Missing required environment variables: {missing_vars}")
        exit(1)
    
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port, debug=False)
