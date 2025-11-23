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

This solution efficiently handles both small concurrent pushes and large batch operations while maintaining security and performance.
