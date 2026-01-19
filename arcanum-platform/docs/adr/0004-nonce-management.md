# ADR-0004: Nonce Management Strategy

## Status
Accepted

## Context

AEAD ciphers (AES-GCM, ChaCha20-Poly1305) require unique nonces for each encryption. Nonce reuse is a critical security vulnerability that can lead to:
- Plaintext recovery
- Forgery attacks
- Complete key compromise (for GCM)

We need an API that makes correct nonce usage easy and incorrect usage hard.

## Decision

Provide **three levels of nonce management**:

### Level 1: Automatic (seal/open)
```rust
let sealed = Aes256Gcm::seal(&key, plaintext)?;
let opened = Aes256Gcm::open(&key, &sealed)?;
```
- Generates random nonce automatically
- Prepends nonce to ciphertext
- Recommended for most use cases

### Level 2: Strategy-based (CipherInstance)
```rust
let cipher = CipherBuilder::<Aes256Gcm>::new()
    .key(&key)
    .nonce_strategy(NonceStrategy::Counter)
    .build()?;

let ct1 = cipher.encrypt(b"message1")?;
let ct2 = cipher.encrypt(b"message2")?;
```
- Supports `Random`, `Counter`, `CounterFrom(n)` strategies
- Counter uses `AtomicU64` for thread safety
- Nonce embedded in output

### Level 3: Explicit (advanced)
```rust
let ct = Aes256Gcm::encrypt(&key, &nonce, plaintext, None)?;
```
- User provides nonce directly
- Documented as hazardous
- Required for some protocols

## Consequences

### Positive
- Default API (seal/open) is safe by design
- Counter strategy enables high-performance scenarios
- Advanced users can still use explicit nonces
- Thread-safe counter via `AtomicU64`

### Negative
- Counter strategy requires careful initialization
- Multiple abstraction levels may confuse users
- Explicit nonce API can be misused

### NonceStrategy enum

```rust
pub enum NonceStrategy {
    Random,           // Generate random nonce each time
    Counter,          // Start at 0, increment atomically
    CounterFrom(u64), // Start at specified value
}
```

### Thread safety

Counter-based nonces use `AtomicU64::fetch_add` with `SeqCst` ordering, ensuring unique nonces even under concurrent access.
