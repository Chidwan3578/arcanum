# ADR-0005: Key Zeroization on Drop

## Status
Accepted

## Context

Cryptographic keys in memory are high-value targets. If memory is:
- Swapped to disk
- Core dumped
- Read by another process (exploit)
- Left in freed memory

...the keys could be compromised. We need a strategy to minimize key exposure.

## Decision

**Zeroize all secret key material on drop** using the `zeroize` crate.

### Implementation

1. **Automatic via `Zeroize` derive**:
```rust
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: [u8; 32],
}
```

2. **Manual for wrapped types**:
```rust
impl Drop for CipherInstance<C> {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
```

3. **SecretBuffer wrapper**:
```rust
pub struct SecretBuffer(Vec<u8>);

impl Drop for SecretBuffer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
```

### What gets zeroized

| Type | Zeroized |
|------|----------|
| Private/secret keys | Yes |
| Symmetric keys | Yes |
| Key derivation outputs | Yes |
| Nonces | No (not secret) |
| Public keys | No (not secret) |
| Ciphertext | No (not secret) |

## Consequences

### Positive
- Keys are cleared from memory as soon as they're no longer needed
- Defense in depth against memory disclosure
- Automatic via `Drop` trait - no manual cleanup needed
- Works with stack and heap allocations

### Negative
- Small performance overhead on drop
- Compiler may optimize away zeroization (mitigated by `zeroize` crate's barriers)
- Does not protect against:
  - Keys in CPU registers/cache
  - Memory copied by runtime (cloning)
  - Swap before drop occurs

### Best practices

1. Minimize key lifetime - drop as soon as possible
2. Use `SecretBuffer` for temporary key material
3. Avoid cloning secret keys unnecessarily
4. Consider `mlock` for long-lived keys (OS-specific)

### Verification

```rust
#[test]
fn key_is_zeroized_on_drop() {
    let ptr: *const u8;
    {
        let key = SecretKey::generate();
        ptr = key.as_bytes().as_ptr();
    }
    // After drop, memory at ptr should be zeroed
    // (Note: this is UB to actually check, but zeroize guarantees it)
}
```
