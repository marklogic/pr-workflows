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
        
        try:
            with open(config_file, 'r') as f:
                for line in f:
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
                
                return config
                
        except FileNotFoundError:
            print(f"Error: Configuration file '{config_file}' not found.")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading configuration file: {e}")
            sys.exit(1)
    
    def _is_excluded(self, file_path: str) -> bool:
        """Check if file should be excluded from copyright validation."""
        file_path = os.path.normpath(file_path)
        
        # Strip common prefixes that might be added by the workflow
        # This handles cases where files are passed as "target-repo/filename"
        base_file_path = file_path
        for prefix in ['target-repo/', 'target-repo\\']:
            if file_path.startswith(prefix):
                base_file_path = file_path[len(prefix):]
                break
        
        for excluded_pattern in self.excluded_files:
            excluded_pattern = os.path.normpath(excluded_pattern)
            
            # Check for exact match against both full path and base path
            if file_path == excluded_pattern or base_file_path == excluded_pattern:
                return True
            
            # Check for pattern match (simple glob-like matching)
            if '*' in excluded_pattern:
                pattern = excluded_pattern.replace('*', '.*')
                if re.match(pattern, file_path) or re.match(pattern, base_file_path):
                    return True
            
            # Check if file is within excluded directory
            if (file_path.startswith(excluded_pattern + os.sep) or 
                base_file_path.startswith(excluded_pattern + os.sep)):
                return True
                
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
    
    def validate_files(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """Validate copyright in multiple files."""
        results = []
        
        for file_path in file_paths:
            result = self.validate_file(file_path)
            results.append(result)
        
        return results
    
    def print_results(self, results: List[Dict[str, Any]], verbose: bool = False):
        """Print validation results."""
        total_files = len(results)
        valid_files = sum(1 for r in results if r['valid'])
        excluded_files = sum(1 for r in results if r['excluded'])
        invalid_files = total_files - valid_files
        
        print(f"\nCopyright Validation Results:")
        print(f"{'=' * 50}")
        print(f"Total files checked: {total_files}")
        print(f"Valid files: {valid_files}")
        print(f"Invalid files: {invalid_files}")
        print(f"Excluded files: {excluded_files}")
        print()
        
        # Print details for invalid files
        has_invalid = False
        for result in results:
            if not result['valid'] and not result['excluded']:
                has_invalid = True
                print(f"❌ {result['file']}")
                if result['error']:
                    print(f"   Error: {result['error']}")
                if result['found_copyright']:
                    print(f"   Found: {result['found_copyright']}")
                print(f"   Expected: {result['expected_copyright']}")
                print()
        
        # Print excluded files if verbose
        if verbose and excluded_files > 0:
            print("Excluded files:")
            for result in results:
                if result['excluded']:
                    print(f"⏭️  {result['file']}")
            print()
        
        # Print valid files if verbose
        if verbose:
            print("Valid files:")
            for result in results:
                if result['valid'] and not result['excluded']:
                    print(f"✅ {result['file']}")
            print()
        
        if not has_invalid:
            print("✅ All files have valid copyright headers!")


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
        'files',
        nargs='*',
        help='Files to check for copyright headers'
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
    
    # Validate files
    results = validator.validate_files(file_paths)
    
    # Print results
    validator.print_results(results, verbose=args.verbose)
    
    # Exit with error code if any files are invalid
    invalid_count = sum(1 for r in results if not r['valid'] and not r['excluded'])
    if invalid_count > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()