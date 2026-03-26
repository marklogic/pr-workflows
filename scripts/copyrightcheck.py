#!/usr/bin/env python3
"""
Copyright validation script for checking copyright headers in source files.

This script validates that files contain the correct copyright header format
based on configuration settings.
"""

import argparse
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Set, Dict, Any


class CopyrightValidator:
    """Validates copyright headers in source files."""
    
    # Common patterns for comment block terminators
    TRAILING_COMMENT_TERMINATORS = r'(\*/|-->|:\))\s*$'
    
    def __init__(self, config_file: str):
        """Initialize validator with configuration file."""
        self.config = self._load_config(config_file)
        self.current_year = datetime.now().year
        self.start_year = self.config.get('startyear')
        if self.start_year is None:
            print("Error: 'startyear' must be specified in the configuration file.")
            sys.exit(1)
        
        # Get excluded files from config, default to empty set if not specified
        excluded_files_list = self.config.get('filesexcluded')
        if excluded_files_list is None:
            self.excluded_files = set()
        else:
            self.excluded_files = set(excluded_files_list)
        
    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from plain text file.
        
        Supports both single-line and multiline filesexcluded values:
        
          Single-line:
            filesexcluded: README.MD,.github/*
        
          Mixed (inline value + continuation lines):
            filesexcluded: README.MD
            .github/*
            src/scripts/brijeshtest.py
        
          Multiline only (empty inline value):
            filesexcluded:
            .github/*
            src/scripts/brijeshtest.py
        
        Continuation lines are collected until an empty line or a new key: is found.
        """
        config = {}
        
        print(f"📋 Loading copyright config from: {config_file}")
        
        try:
            with open(config_file, 'r') as f:
                content = f.read()
                print("📄 Raw config file content:")
                for line_num, line in enumerate(content.split('\n'), 1):
                    print(f"     {line_num:2d}: {line}")
                print()
                
                # Reset file pointer to beginning
                f.seek(0)
                
                current_multiline_key = None
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Empty line ends any active multi-line block
                    if not line:
                        current_multiline_key = None
                        continue
                    
                    # Skip comments
                    if line.startswith('#'):
                        continue
                    
                    # Detect key:value pairs — key must be a simple word (no path chars)
                    if ':' in line:
                        key_part, value_part = line.split(':', 1)
                        key_candidate = key_part.strip().lower()
                        if re.match(r'^[a-z][a-z0-9]*$', key_candidate):
                            current_multiline_key = None
                            key = key_candidate
                            value = value_part.strip()
                            
                            if key == 'startyear':
                                try:
                                    config['startyear'] = int(value)
                                except ValueError:
                                    print(f"Error: Invalid start year '{value}'. Must be a valid integer.")
                                    sys.exit(1)
                            
                            elif key == 'filesexcluded':
                                # Always initialise the list and activate multiline mode.
                                # This supports:
                                #   - empty inline value  → purely multiline
                                #   - non-empty inline value → inline entries + optional continuation lines
                                files = [f.strip() for f in value.split(',') if f.strip()] if value else []
                                config['filesexcluded'] = files
                                current_multiline_key = 'filesexcluded'
                            continue
                    
                    # Continuation line for an active multi-line key
                    # Each line may contain one or more comma-separated entries
                    if current_multiline_key == 'filesexcluded':
                        entries = [e.strip() for e in line.split(',')]
                        config['filesexcluded'].extend([e for e in entries if e])
                
                print("✅ Parsed configuration:")
                for key, value in config.items():
                    print(f"     {key}: {value}")
                print()
                
                return config
                
        except FileNotFoundError:
            print(f"Error: Configuration file '{config_file}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading configuration file: {e}")
            sys.exit(1)
    
    def _is_excluded(self, relative_path: str) -> bool:
        """Check if file should be excluded from copyright validation.
        
        Args:
            relative_path: File path relative to repository root
        """
        relative_path = os.path.normpath(relative_path)
        
        # Always exclude dotfiles (files starting with .)
        filename = os.path.basename(relative_path)
        if filename.startswith('.'):        
            print(f"🚫 Excluding dotfile: {relative_path}")
            return True
        
        for excluded_pattern in self.excluded_files:
            excluded_pattern = os.path.normpath(excluded_pattern)
            
            # Check for exact match
            if relative_path == excluded_pattern:
                print(f"🚫 Excluding (exact match): {relative_path} matches {excluded_pattern}")
                return True
            
            # Check for pattern match (simple glob-like matching)
            if '*' in excluded_pattern:
                pattern = excluded_pattern.replace('*', '.*')
                if re.match(pattern, relative_path):
                    print(f"🚫 Excluding (pattern match): {relative_path} matches {excluded_pattern}")
                    return True
        
        print(f"✅ Including: {relative_path}")
        return False
            
    
    def _get_expected_copyright(self) -> str:
        """Generate expected copyright header."""
        year_range = f"{self.start_year}-{self.current_year}" if self.start_year != self.current_year else str(self.current_year)
        return f"Copyright (c) {year_range} Progress Software Corporation and/or its subsidiaries or affiliates. All Rights Reserved."
    
    def _extract_copyright_from_content(self, content: str) -> str:
        """Extract copyright line from file content."""
        lines = content.split('\n')
        # Look for copyright in first 20 lines
        for line in lines[:20]:
            # Remove common leading comment characters and whitespace (including HTML <!-- starts and XQuery (: )
            cleaned_line = re.sub(r'^[\s\*#\/]*(?:<!--|\(:)?', '', line).strip()
            # Trim common trailing block terminators if present on same line
            cleaned_line = re.sub(self.TRAILING_COMMENT_TERMINATORS, '', cleaned_line).strip()
            if cleaned_line.lower().startswith('copyright'):
                return cleaned_line
        return ""
    
    def _validate_copyright_format(self, copyright_line: str) -> bool:
        """Validate copyright line.
        Accepts any header of the form:
        Copyright (c) YYYY-YYYY Progress Software Corporation and/or its subsidiaries or affiliates. All Rights Reserved.
        where years are 4 digits, start <= end, and end <= current year (flexible start year per file).
        Trailing block terminator already removed in extraction.
        """
        # Normalize whitespace and remove any trailing block terminator defensively
        copyright_line = re.sub(self.TRAILING_COMMENT_TERMINATORS, '', copyright_line).strip()
        normalized_actual = re.sub(r'\s+', ' ', copyright_line)
        # Regex for pattern (case-insensitive on 'Copyright')
        pattern = re.compile(r'^copyright \(c\) (\d{4})-(\d{4}) progress software corporation and/or its subsidiaries or affiliates\. all rights reserved\.$', re.IGNORECASE)
        m = pattern.match(normalized_actual.lower())
        if not m:
            return False
        start, end = int(m.group(1)), int(m.group(2))
        # Basic sanity checks on years
        current_year = self.current_year
        if start > end:
            return False
        if end > current_year:
            return False
        if end != current_year:
            return False
        # Enforce repository configured start year
        if start != self.start_year:
            return False
        # All conditions satisfied
        return True
    
    def validate_file(self, file_path: str) -> Dict[str, Any]:
        """Validate copyright in a single file."""
        result = {
            'file': file_path,
            'valid': False,
            'excluded': False,
            'error': None,
            'found_copyright': '',
            'expected_copyright': self._get_expected_copyright()
        }
        
        # Check if file is excluded
        if self._is_excluded(file_path):
            result['excluded'] = True
            result['valid'] = True  # Excluded files are considered valid
            return result
        
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                result['error'] = f"File not found: {file_path}"
                return result
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract copyright line
            copyright_line = self._extract_copyright_from_content(content)
            result['found_copyright'] = copyright_line
            
            if not copyright_line:
                result['error'] = "No copyright header found"
                return result
            
            # Validate copyright format
            result['valid'] = self._validate_copyright_format(copyright_line)
            
            if not result['valid']:
                result['error'] = "Copyright format does not match expected format"
            
        except Exception as e:
            result['error'] = f"Error reading file: {str(e)}"
        
        return result
    
    def validate_files(self, file_paths: List[str], relative_paths: List[str] = None) -> List[Dict[str, Any]]:
        """Validate copyright in multiple files.
        
        Args:
            file_paths: Absolute paths to files for file operations
            relative_paths: Relative paths for exclusion checking (optional)
        """
        results = []
        
        # If no relative paths provided, use file_paths as-is
        if relative_paths is None:
            relative_paths = file_paths
        
        for file_path, relative_path in zip(file_paths, relative_paths):
            # Use relative path for exclusion checking
            if self._is_excluded(relative_path):
                results.append({
                    'file': file_path,
                    'relative_path': relative_path,
                    'valid': True,
                    'excluded': True,
                    'error': None,
                    'found_copyright': None
                })
            else:
                result = self.validate_file(file_path)
                result['relative_path'] = relative_path
                results.append(result)
        
        return results
