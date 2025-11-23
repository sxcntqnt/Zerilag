# Zeklag
SSH-KEYS DEPO
keys/
├── users/
│   ├── alice.pub
│   ├── bob.pub
│   └── carol.pub
├── servers/
│   ├── web-server.pub
│   └── db-server.pub
└── ci/
    └── deployment.pub

Key Features
1. Concurrency Handling

    Uses GitHub's concurrency group to cancel in-progress runs

    File-based locking for batch processing

    Atomic operations for duplicate detection

2. Batch Processing

    Configurable batch sizes via matrix strategy

    Memory-efficient processing of large key sets

    Progress reporting for large batches

3. Comprehensive Validation

    Multiple key type support (RSA, DSA, Ed25519, ECDSA)

    Weak key detection

    Duplicate key prevention

    Whitelist support for trusted keys

4. Security Features

    Cryptographic validation using industry-standard libraries

    Fingerprint-based duplicate detection

    Minimum key size enforcement

    Weak pattern detection

5. Reporting

    Detailed JSON reports

    Console output with clear error messages

    Artifact upload for historical tracking

Usage

    Push keys to the keys/ directory

    The workflow automatically validates:

    Key format and structure

    Cryptographic integrity

    Duplicates across the entire repository

    Security requirements (key sizes, weak keys)

    Validation fails if any invalid keys are detected, preventing security issues from being introduced.

Organization-level Security Settings
In GitHub Organization Settings:

    Required Two-factor Authentication

        Settings → Security → Two-factor authentication required

    Base Permissions

        Settings → Member privileges → Base permissions: "Read"

    Repository Creation

        Settings → Member privileges → Repository creation: "Disable"
        
Revoke all deployment keys

    Settings → Deploy keys → Remove all

Rollback suspicious commits
bash

git revert <suspicious-commit>

    Rotate all secrets

        Update GitHub secrets

        Rotate deployment keys

        Update CI/CD tokens

Investigation

    Check audit log: Settings → Security & analysis → Audit log

    Review recent workflow runs

    Check branch protection history

Implementation Checklist

    ✅ Enable branch protection with required reviews

    ✅ Configure CODEOWNERS for sensitive files

    ✅ Require signed commits for all changes

    ✅ Set up required status checks for key validation

    ✅ Restrict push access to trusted teams only

    ✅ Enable 2FA for all organization members

    ✅ Create emergency response procedures

    ✅ Set up monitoring for suspicious activities

    Security Manager Role

        Create custom "Security Manager" role with limited permissions


This multi-layered approach ensures that even if a malicious actor gains some access, they cannot modify the whitelist without going through proper security reviews and validations.







