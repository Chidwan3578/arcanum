# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the Arcanum cryptographic library.

## What is an ADR?

An ADR is a document that captures an important architectural decision made along with its context and consequences.

## ADR Index

| ID | Title | Status | Date |
|----|-------|--------|------|
| [ADR-0001](0001-rustcrypto-ecosystem.md) | Use RustCrypto Ecosystem | Accepted | 2024-01 |
| [ADR-0002](0002-error-handling.md) | Error Handling Strategy | Accepted | 2024-01 |
| [ADR-0003](0003-feature-flags.md) | Feature Flag Design | Accepted | 2024-01 |
| [ADR-0004](0004-nonce-management.md) | Nonce Management Strategy | Accepted | 2024-12 |
| [ADR-0005](0005-key-zeroization.md) | Key Zeroization on Drop | Accepted | 2024-12 |

## ADR Template

```markdown
# ADR-XXXX: Title

## Status
Proposed | Accepted | Deprecated | Superseded

## Context
What is the issue that we're seeing that is motivating this decision?

## Decision
What is the change that we're proposing and/or doing?

## Consequences
What becomes easier or more difficult because of this change?
```
