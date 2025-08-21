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
        """Load configuration from plain text file."""
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
                
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse key:value pairs
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip().lower()
                        value = value.strip()
                        
                        if key == 'startyear':
                            try:
                                config['startyear'] = int(value)
                            except ValueError:
                                print(f"Error: Invalid start year '{value}'. Must be a valid integer.")
                                sys.exit(1)
                        
                        elif key == 'filesexcluded':
                            # Parse comma-separated list or single file
                            if value:
                                files = [f.strip() for f in value.split(',')]
                                config['filesexcluded'] = [f for f in files if f]
                            else:
                                config['filesexcluded'] = []
                
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
            # Remove common comment characters and whitespace
            cleaned_line = re.sub(r'^[\s\*#//]*', '', line).strip()
            if cleaned_line.lower().startswith('copyright'):
                return cleaned_line
        
        return ""
    
    def _validate_copyright_format(self, copyright_line: str) -> bool:
        """Validate if copyright line matches expected format."""
        expected = self._get_expected_copyright()
        
        # Normalize both strings for comparison
        normalized_expected = re.sub(r'\s+', ' ', expected.strip())
        normalized_actual = re.sub(r'\s+', ' ', copyright_line.strip())
        
        return normalized_actual == normalized_expected
    
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
                continue
            
            # Use absolute path for file operations
            result = self.validate_file(file_path)
            result['relative_path'] = relative_path
            results.append(result)
        
        return results
    
    def print_results(self, results: List[Dict[str, Any]], verbose: bool = False):
        """Print validation results."""
        MARKER_START = "<<<COPYRIGHT-CHECK:MARKDOWN>>>"
        MARKER_END = "<<<END COPYRIGHT-CHECK:MARKDOWN>>>"
        total_files = len(results)
        # Fixed logical operator '&&' to 'and'
        valid_files = sum(1 for r in results if r['valid'] and not r['excluded'])
        excluded_files = sum(1 for r in results if r['excluded'])
        invalid_files = sum(1 for r in results if not r['valid'] and not r['excluded'])

        LIST_LIMIT = 200  # safety cap

        print(MARKER_START)
        print("Copyright Validation Results:")
        print(f"Total: {total_files} | Passed: {valid_files} | Failed: {invalid_files} | Skipped: {excluded_files}")
        print()

        has_invalid = invalid_files > 0
        if has_invalid:
            print("### ❌ Failed Files")
            for result in results:
                if result['valid'] or result['excluded']:
                    continue
                # Prefer relative path for display
                display_path = result.get('relative_path') or result['file']
                print(f"- {display_path}")
                print()  # blank line for visual spacing before error details
                err_msg = result.get('error') or 'Invalid header'
                # Error label small + bold
                print("  <small><strong>Error:</strong></small>")
                print("  ```diff")
                print(f"  - {err_msg}")
                print("  ```")
                expected_line = result['expected_copyright']
                # Expected header label small + bold
                print("  <small><strong>Expected header:</strong></small>")
                print("  ```")
                print(f"  {expected_line}")
                print("  ```")
            print()

        excluded_list = [r for r in results if r['excluded']]
        if excluded_list:
            print("### ⏭️ Skipped (Excluded) Files")
            for r in excluded_list[:LIST_LIMIT]:
                display_path = r.get('relative_path') or r['file']
                print(f"- {display_path}")
            if len(excluded_list) > LIST_LIMIT:
                print(f"- … ({len(excluded_list) - LIST_LIMIT} more omitted)")
            print()

        valid_list = [r for r in results if r['valid'] and not r['excluded']]
        if valid_list:
            print("### ✅ Valid Files")
            for r in valid_list[:LIST_LIMIT]:
                display_path = r.get('relative_path') or r['file']
                print(f"- {display_path}")
            if len(valid_list) > LIST_LIMIT:
                print(f"- … ({len(valid_list) - LIST_LIMIT} more omitted)")
            print()

        if not has_invalid:
            print("✅ All files have valid copyright headers!\n")

        print(MARKER_END)


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Validate copyright headers in source files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python copyrightcheck.py -c config.yml file1.py file2.js
  python copyrightcheck.py -c config.yml --files-from-stdin
  echo "file1.py\nfile2.js" | python copyrightcheck.py -c config.yml --files-from-stdin
        """
    )
    
    parser.add_argument(
        '-c', '--config',
        required=True,
        help='Path to copyright configuration file'
    )
    
    parser.add_argument(
        '-w', '--working-dir',
        help='Working directory for resolving relative file paths (default: current directory)'
    )
    
    parser.add_argument(
        'files',
        nargs='*',
        help='Files to check for copyright headers (relative to working-dir if specified)'
    )
    
    parser.add_argument(
        '--files-from-stdin',
        action='store_true',
        help='Read file paths from standard input (one per line)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed output including valid and excluded files'
    )
    
    parser.add_argument(
        '--origins-file',
        help='Optional file containing origin metadata for each file (ignored by validator)',
        required=False
    )
    
    args = parser.parse_args()
    
    # Get file paths
    file_paths = []
    
    if args.files_from_stdin:
        # Read file paths from stdin
        for line in sys.stdin:
            file_path = line.strip()
            if file_path:
                file_paths.append(file_path)
    else:
        file_paths = args.files
    
    if not file_paths:
        print("Error: No files specified. Use positional arguments or --files-from-stdin.")
        sys.exit(1)
    
    # Initialize validator
    validator = CopyrightValidator(args.config)
    
    # Set working directory if specified
    working_dir = args.working_dir or os.getcwd()
    if args.working_dir:
        print(f"📂 Working directory: {working_dir}")
    
    # Convert file paths to absolute paths for file operations
    # but keep relative paths for exclusion checking
    absolute_file_paths = []
    relative_file_paths = []
    
    for file_path in file_paths:
        if os.path.isabs(file_path):
            # Already absolute - convert to relative for exclusion checking
            try:
                relative_path = os.path.relpath(file_path, working_dir)
                absolute_file_paths.append(file_path)
                relative_file_paths.append(relative_path)
            except ValueError:
                # If relpath fails, use as-is
                absolute_file_paths.append(file_path)
                relative_file_paths.append(file_path)
        else:
            # Relative path - resolve to absolute for file operations
            absolute_path = os.path.join(working_dir, file_path)
            absolute_file_paths.append(absolute_path)
            relative_file_paths.append(file_path)
    
    # Validate files using absolute paths for file ops, relative for exclusion
    results = validator.validate_files(absolute_file_paths, relative_file_paths)
    
    # Print results
    validator.print_results(results, verbose=args.verbose)
    
    # Exit with error code if any files are invalid
    invalid_count = sum(1 for r in results if not r['valid'] and not r['excluded'])
    if invalid_count > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()