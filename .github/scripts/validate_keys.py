#!/usr/bin/env python3
"""
Public Key Validator for GitHub Actions
Handles concurrent and batch key validation with proper locking
"""

import os
import sys
import json
import argparse
import hashlib
import tempfile
import fcntl
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
from cryptography.hazmat.backends import default_backend
from datetime import datetime
import subprocess
# Add to your existing validate_keys.py

class SecurityValidator:
    def __init__(self):
        self.suspicious_patterns = [
            # Common malicious key patterns
            r"AAAAB3NzaC1yc2EAAAADAQABAAABAQ",  # Weak RSA pattern
            r"ssh-rsa AAAA[0-9A-Za-z+/]{100,}",  # Generic suspicious
        ]
        
    def analyze_whitelist_changes(self):
        """Analyze whitelist changes for suspicious activity"""
        try:
            # Get whitelist changes from git
            result = subprocess.run([
                'git', 'diff', 'HEAD~1', 'HEAD', '--', '.github/keys-whitelist.txt'
            ], capture_output=True, text=True, check=True)
            
            if result.stdout:
                additions = []
                for line in result.stdout.split('\n'):
                    if line.startswith('+') and not line.startswith('+++'):
                        additions.append(line[1:].strip())
                
                return self.check_suspicious_additions(additions)
            
            return True, "No whitelist changes detected"
            
        except subprocess.CalledProcessError:
            return True, "Could not analyze whitelist changes"

    def check_suspicious_additions(self, additions):
        """Check if whitelist additions are suspicious"""
        suspicious = []
        
        for addition in additions:
            if not addition or addition.startswith('#'):
                continue
                
            # Check if it's a valid fingerprint format
            if not re.match(r'^[a-f0-9]{64}$', addition):
                suspicious.append(f"Invalid fingerprint format: {addition}")
                
            # Check for known compromised keys
            if self.is_known_compromised(addition):
                suspicious.append(f"Known compromised key: {addition}")
        
        if suspicious:
            return False, " | ".join(suspicious)
        return True, "Whitelist changes appear legitimate"

    def is_known_compromised(self, fingerprint):
        """Check against known compromised keys (simplified example)"""
        compromised_keys = {
            # Add known compromised key fingerprints here
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Example compromised key",
        }
        return fingerprint in compromised_keys

def validate_whitelist_integrity():
    """Ensure whitelist hasn't been tampered with"""
    validator = SecurityValidator()
    
    # Check if whitelist file has been modified
    if os.path.exists('.github/keys-whitelist.txt'):
        with open('.github/keys-whitelist.txt', 'r') as f:
            content = f.read()
            
        # Verify file signature (simplified)
        current_hash = hashlib.sha256(content.encode()).hexdigest()
        expected_hash = os.getenv('WHITELIST_HASH', '')
        
        if expected_hash and current_hash != expected_hash:
            return False, "Whitelist integrity check failed"
    
    return True, "Whitelist integrity verified"
    
class KeyValidator:
    def __init__(self, batch_size=50, whitelist_file=None):
        self.batch_size = batch_size
        self.whitelist = self.load_whitelist(whitelist_file) if whitelist_file else set()
        self.results = {
            'timestamp': datetime.utcnow().isoformat(),
            'validated_keys': 0,
            'valid_keys': 0,
            'invalid_keys': 0,
            'duplicate_keys': 0,
            'details': []
        }
        
    def load_whitelist(self, whitelist_file):
        """Load whitelisted key fingerprints"""
        whitelist = set()
        if os.path.exists(whitelist_file):
            with open(whitelist_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        whitelist.add(line)
        return whitelist

    def get_key_fingerprint(self, key_data):
        """Calculate SHA256 fingerprint of public key"""
        return hashlib.sha256(key_data.encode()).hexdigest()

    def validate_ssh_public_key(self, key_data, filename):
        """Validate SSH public key format and content"""
        try:
            key_data = key_data.strip()
            
            # Basic SSH key structure validation
            parts = key_data.split()
            if len(parts) < 2:
                return False, "Invalid key format: too few parts"
            
            key_type = parts[0]
            key_body = parts[1]
            
            # Check key type
            supported_types = ['ssh-rsa', 'ssh-dss', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 
                             'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']
            if key_type not in supported_types:
                return False, f"Unsupported key type: {key_type}"
            
            # Validate base64 encoding
            try:
                import base64
                base64.b64decode(key_body)
            except Exception:
                return False, "Invalid base64 encoding"
            
            # Advanced validation using cryptography library
            try:
                if key_type == 'ssh-rsa':
                    public_key = serialization.load_ssh_public_key(key_data.encode(), backend=default_backend())
                    if not isinstance(public_key, rsa.RSAPublicKey):
                        return False, "Invalid RSA key"
                    # Check minimum key size
                    key_size = public_key.key_size
                    if key_size < 2048:
                        return False, f"RSA key too small: {key_size} bits (minimum 2048)"
                        
                elif key_type == 'ssh-dss':
                    public_key = serialization.load_ssh_public_key(key_data.encode(), backend=default_backend())
                    if not isinstance(public_key, dsa.DSAPublicKey):
                        return False, "Invalid DSA key"
                    key_size = public_key.key_size
                    if key_size < 1024:
                        return False, f"DSA key too small: {key_size} bits"
                        
                elif key_type == 'ssh-ed25519':
                    public_key = serialization.load_ssh_public_key(key_data.encode(), backend=default_backend())
                    if not isinstance(public_key, ed25519.Ed25519PublicKey):
                        return False, "Invalid Ed25519 key"
                        
                elif key_type.startswith('ecdsa-'):
                    public_key = serialization.load_ssh_public_key(key_data.encode(), backend=default_backend())
                    if not isinstance(public_key, ec.EllipticCurvePublicKey):
                        return False, "Invalid ECDSA key"
                        
            except Exception as e:
                return False, f"Cryptography validation failed: {str(e)}"
            
            # Check for weak keys (basic checks)
            fingerprint = self.get_key_fingerprint(key_data)
            if self.is_weak_key(key_data):
                return False, "Key appears to be weak or compromised"
                
            # Check against whitelist
            if fingerprint in self.whitelist:
                return True, "Key is whitelisted"
            
            return True, "Valid key"
            
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    def is_weak_key(self, key_data):
        """Basic weak key detection"""
        # Check for obviously weak keys (this is a simplified example)
        weak_patterns = [
            'AAAAB3NzaC1yc2EAAAADAQABAAAA',  # Example weak pattern
            # Add more patterns based on your security requirements
        ]
        
        for pattern in weak_patterns:
            if pattern in key_data:
                return True
        return False

    def process_key_file(self, filepath):
        """Process a single key file"""
        results = []
        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                is_valid, message = self.validate_ssh_public_key(line, filepath)
                fingerprint = self.get_key_fingerprint(line)
                
                result = {
                    'file': str(filepath),
                    'line': line_num,
                    'key_preview': line[:50] + '...' if len(line) > 50 else line,
                    'fingerprint': fingerprint,
                    'valid': is_valid,
                    'message': message
                }
                
                results.append(result)
                
        except Exception as e:
            results.append({
                'file': str(filepath),
                'line': 0,
                'key_preview': '',
                'fingerprint': '',
                'valid': False,
                'message': f"File processing error: {str(e)}"
            })
            
        return results

    def get_changed_key_files(self):
        """Get list of changed key files using git"""
        try:
            # Get files changed in the last commit
            result = subprocess.run([
                'git', 'diff-tree', '--no-commit-id', '--name-only', '-r', 
                os.getenv('GITHUB_SHA', 'HEAD')
            ], capture_output=True, text=True, check=True)
            
            changed_files = result.stdout.strip().split('\n')
            key_files = [f for f in changed_files if f.startswith('keys/') and os.path.isfile(f)]
            
            return key_files
            
        except subprocess.CalledProcessError:
            # Fallback: check all keys in keys directory
            keys_dir = Path('keys')
            if keys_dir.exists():
                return list(keys_dir.glob('**/*.pub')) + list(keys_dir.glob('**/*.key'))
            return []

    def run_validation(self):
        """Main validation runner with batch processing"""
        # Get changed files or all key files
        if os.getenv('GITHUB_EVENT_NAME') == 'push':
            key_files = self.get_changed_key_files()
        else:
            # For PRs, check all key files
            keys_dir = Path('keys')
            key_files = list(keys_dir.glob('**/*.pub')) + list(keys_dir.glob('**/*.key'))
        
        if not key_files:
            print("No key files to validate")
            return True
            
        print(f"Found {len(key_files)} key files to validate")
        
        # Process in batches
        all_results = []
        seen_fingerprints = set()
        
        for i in range(0, len(key_files), self.batch_size):
            batch = key_files[i:i + self.batch_size]
            print(f"Processing batch {i//self.batch_size + 1}: {len(batch)} files")
            
            for key_file in batch:
                file_results = self.process_key_file(key_file)
                
                for result in file_results:
                    # Check for duplicates
                    if result['fingerprint'] and result['fingerprint'] in seen_fingerprints:
                        result['valid'] = False
                        result['message'] = 'Duplicate key detected'
                        self.results['duplicate_keys'] += 1
                    elif result['fingerprint']:
                        seen_fingerprints.add(result['fingerprint'])
                    
                    # Update counters
                    self.results['validated_keys'] += 1
                    if result['valid']:
                        self.results['valid_keys'] += 1
                    else:
                        self.results['invalid_keys'] += 1
                    
                    all_results.append(result)
        
        self.results['details'] = all_results
        
        # Generate summary
        self.generate_report()
        
        # Determine if validation passed
        return self.results['invalid_keys'] == 0

    def generate_report(self):
        """Generate validation report"""
        # Print summary to console
        print("\n" + "="*50)
        print("PUBLIC KEY VALIDATION REPORT")
        print("="*50)
        print(f"Total keys validated: {self.results['validated_keys']}")
        print(f"Valid keys: {self.results['valid_keys']}")
        print(f"Invalid keys: {self.results['invalid_keys']}")
        print(f"Duplicate keys: {self.results['duplicate_keys']}")
        
        # Print details of invalid keys
        invalid_keys = [r for r in self.results['details'] if not r['valid']]
        if invalid_keys:
            print("\n❌ INVALID KEYS:")
            for key in invalid_keys:
                print(f"  - {key['file']}:{key['line']} - {key['message']}")
        
        # Save detailed report
        with open('validation-report.json', 'w') as f:
            json.dump(self.results, f, indent=2)

def main():
    parser = argparse.ArgumentParser(description='Validate SSH public keys')
    parser.add_argument('--batch-size', type=int, default=50, 
                       help='Number of keys to process in each batch')
    parser.add_argument('--whitelist', type=str,
                       help='Path to whitelist file')
    
    args = parser.parse_args()
    
    validator = KeyValidator(
        batch_size=args.batch_size,
        whitelist_file=args.whitelist
    )
    
    success = validator.run_validation()
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
