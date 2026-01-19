# ADR-0002: Error Handling Strategy

## Status
Accepted

## Context

Cryptographic libraries need robust error handling that:
1. Provides enough context for debugging
2. Doesn't leak sensitive information
3. Allows callers to handle errors appropriately
4. Is consistent across all crates

Options considered:
1. **Single error enum** - One `Error` type for all crates
2. **Per-crate errors** - Each crate has its own error type
3. **Anyhow-style** - Dynamic error types with context
4. **Hybrid** - Core error type with crate-specific extensions

## Decision

Use a **single comprehensive error enum** in `arcanum-core` with contextual variants.

```rust
pub enum Error {
    // Key errors
    InvalidKeyLength { expected: usize, actual: usize },

    // Encryption errors
    EncryptionFailed,
    DecryptionFailed,

    // With algorithm context
    EncryptionFailedContext { algorithm: String, reason: String },

    // ...
}
```

### Design principles

1. **Contextual variants**: Errors include algorithm names and reasons
2. **Suggestion method**: `error.suggestion()` provides recovery advice
3. **Recoverability**: `error.is_recoverable()` indicates transient failures
4. **thiserror**: Use `thiserror` for `Display` and `Error` implementations
5. **No sensitive data**: Never include keys, plaintext, or secrets in errors

## Consequences

### Positive
- Single import for error handling across all arcanum crates
- Consistent error messages and patterns
- Easy to add new error variants without breaking changes
- `suggestion()` helps users fix common mistakes

### Negative
- Error enum grows large over time
- Some variants may not apply to all crates
- Breaking changes require careful migration

### Examples

```rust
// Contextual error with suggestion
let err = Error::InvalidKeyLength { expected: 32, actual: 16 };
assert_eq!(err.suggestion(), Some("Use a 32-byte key for AES-256"));

// Algorithm context
let err = Error::EncryptionFailedContext {
    algorithm: "AES-256-GCM".into(),
    reason: "nonce reuse detected".into(),
};
```
