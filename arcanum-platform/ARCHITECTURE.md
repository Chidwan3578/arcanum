# Arcanum Platform Architecture

## Quick Reference: Which Crate Do I Need?

| Task | Crate | Example |
|------|-------|---------|
| Hash data (SHA, Blake) | `arcanum-hash` | `Sha256::hash(data)` |
| Derive key from password | `arcanum-hash` | `Argon2::hash_password(...)` |
| Encrypt with shared key | `arcanum-symmetric` | `Aes256Gcm::encrypt(...)` |
| RSA/ECDH key exchange | `arcanum-asymmetric` | `X25519SecretKey::generate()` |
| Sign/verify messages | `arcanum-signatures` | `Ed25519SigningKey::sign(...)` |
| Post-quantum crypto | `arcanum-pqc` | `MlKem768::generate_keypair()` |
| Zero-knowledge proofs | `arcanum-zkp` | `RangeProof::prove(...)` |
| Store keys securely | `arcanum-keystore` | `EncryptedKeyStore::new(...)` |
| Build secure channels | `arcanum-protocols` | `SecureChannel::new(...)` |
| Encode/decode data | `arcanum-formats` | `Hex::encode(...)` |

## Crate Dependency Graph

```
                    ┌─────────────────┐
                    │  arcanum-core   │  Foundation: errors, traits, types
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│ arcanum-hash  │   │arcanum-formats│   │ arcanum-core  │
│  SHA, Blake,  │   │  Hex, Base64, │   │   (traits)    │
│  Argon2, HKDF │   │     PEM       │   └───────┬───────┘
└───────┬───────┘   └───────────────┘           │
        │                                       │
        ▼                    ┌──────────────────┼──────────────────┐
┌───────────────┐            │                  │                  │
│arcanum-symmet │            ▼                  ▼                  ▼
│ AES, ChaCha   │   ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
└───────┬───────┘   │arcanum-asymm  │  │arcanum-signat │  │  arcanum-pqc  │
        │           │ X25519, RSA   │  │ Ed25519, ECDSA│  │ ML-KEM, ML-DSA│
        │           └───────┬───────┘  └───────────────┘  └───────────────┘
        │                   │
        ▼                   ▼
┌─────────────────────────────────────┐
│        arcanum-protocols            │  High-level: key exchange,
│   SecureChannel, SessionKeys        │  session management, channels
└─────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────┐
│        arcanum-keystore             │  Persistent key storage
└─────────────────────────────────────┘
```

## Algorithm Selection Guide

### Symmetric Encryption

| Algorithm | Use When | Avoid When |
|-----------|----------|------------|
| **AES-256-GCM** | Default choice, hardware acceleration available | Nonce management is difficult |
| **ChaCha20-Poly1305** | Embedded systems, no AES-NI, constant-time needed | You need AES for compliance |
| **XChaCha20-Poly1305** | Random nonces, long-lived keys | Absolute maximum performance needed |

```rust
use arcanum_symmetric::prelude::*;

// Default choice for most applications
let ciphertext = Aes256Gcm::encrypt(&key, &nonce, &plaintext, None)?;

// For embedded or when constant-time is critical
let ciphertext = ChaCha20Poly1305::encrypt(&key, &nonce, &plaintext, None)?;

// When you can't guarantee unique nonces
let ciphertext = XChaCha20Poly1305::encrypt(&key, &nonce, &plaintext, None)?;
```

### Hash Functions

| Algorithm | Use When | Output Size |
|-----------|----------|-------------|
| **SHA-256** | General hashing, compatibility needed | 32 bytes |
| **SHA-512** | Need larger output, 64-bit systems | 64 bytes |
| **Blake3** | Maximum speed, modern applications | Variable |
| **SHA3-256** | Post-quantum margin, NIST compliance | 32 bytes |

```rust
use arcanum_hash::prelude::*;

// General purpose
let hash = Sha256::hash(data);

// Maximum performance
let hash = Blake3::hash(data);

// Post-quantum security margin
let hash = Sha3_256::hash(data);
```

### Password Hashing

| Algorithm | Use When |
|-----------|----------|
| **Argon2id** | Default for passwords (PHC winner) |
| **scrypt** | Legacy compatibility |
| **PBKDF2** | FIPS compliance required |

```rust
use arcanum_hash::prelude::*;

// Always use Argon2id for new applications
let hash = Argon2::hash_password(password, &Argon2Params::default())?;
let valid = Argon2::verify_password(password, &hash)?;
```

### Digital Signatures

| Algorithm | Use When | Key Size |
|-----------|----------|----------|
| **Ed25519** | Default choice, fast, small signatures | 32 bytes |
| **ECDSA P-256** | Compatibility with existing systems | 32 bytes |
| **ECDSA P-384** | Higher security margin needed | 48 bytes |
| **RSA-PSS** | Legacy compatibility, large key OK | 256+ bytes |

```rust
use arcanum_signatures::prelude::*;

// Modern applications - fast and secure
let signing_key = Ed25519SigningKey::generate();
let signature = signing_key.sign(message);

// When compatibility matters
let signing_key = P256SigningKey::generate();
```

### Key Exchange

| Algorithm | Use When |
|-----------|----------|
| **X25519** | Default for key agreement |
| **X448** | Need 224-bit security level |
| **ECDH P-256** | Compatibility requirements |

```rust
use arcanum_protocols::prelude::*;

// Recommended for most use cases
let (secret, public) = KeyExchangeProtocol::generate_keypair();
let shared = KeyExchangeProtocol::derive_shared_secret(&secret, &peer_public)?;
```

### Post-Quantum Cryptography

| Algorithm | Type | Use When |
|-----------|------|----------|
| **ML-KEM-768** | KEM | Default PQ key encapsulation |
| **ML-KEM-1024** | KEM | Maximum security needed |
| **ML-DSA-65** | Signature | Default PQ signatures |
| **ML-DSA-87** | Signature | Maximum security needed |

```rust
use arcanum_pqc::prelude::*;

// Key encapsulation (for key exchange)
let (dk, ek) = MlKem768::generate_keypair()?;
let (ciphertext, shared_secret) = ek.encapsulate()?;
let shared_secret = dk.decapsulate(&ciphertext)?;

// Digital signatures
let (signing_key, verifying_key) = MlDsa65::generate_keypair()?;
let signature = signing_key.sign(message)?;
```

## Common Workflows

### 1. Encrypt Data with a Password

```rust
use arcanum_hash::prelude::*;
use arcanum_symmetric::prelude::*;

fn encrypt_with_password(password: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    // Derive a key from the password
    let salt = arcanum_core::random::random_bytes::<16>();
    let key = Argon2::derive_key(password, &salt, &Argon2Params::default(), 32)?;

    // Encrypt the data
    let nonce = Aes256Gcm::generate_nonce();
    let ciphertext = Aes256Gcm::encrypt(&key, &nonce, data, None)?;

    // Return salt + nonce + ciphertext
    let mut result = Vec::new();
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}
```

### 2. Establish a Secure Channel

```rust
use arcanum_protocols::prelude::*;

// Alice's side
let (alice_secret, alice_public) = KeyExchangeProtocol::generate_keypair();

// ... send alice_public to Bob, receive bob_public ...

let shared = KeyExchangeProtocol::derive_shared_secret(&alice_secret, &bob_public)?;
let keys = SessionKeys::derive_with_roles(&shared, b"my-app-v1", true)?; // true = initiator
let mut channel = SecureChannel::new(keys);

// Send encrypted messages
let encrypted = channel.encrypt(b"Hello, Bob!")?;

// Receive and decrypt
let plaintext = channel.decrypt(&received_message)?;
```

### 3. Sign and Verify with Hybrid PQ/Classical

```rust
use arcanum_signatures::prelude::*;
use arcanum_pqc::prelude::*;

// Generate both key types
let ed_key = Ed25519SigningKey::generate();
let (ml_dsa_sk, ml_dsa_vk) = MlDsa65::generate_keypair()?;

// Sign with both (defense in depth)
let ed_sig = ed_key.sign(message);
let pq_sig = ml_dsa_sk.sign(message)?;

// Verify both signatures
ed_key.verifying_key().verify(message, &ed_sig)?;
ml_dsa_vk.verify(message, &pq_sig)?;
```

### 4. Store Keys Securely

```rust
use arcanum_keystore::prelude::*;

// Create encrypted keystore
let master_key = MasterKey::from_password(b"user-password", b"app-salt")?;
let backing = FileKeyStore::new("/path/to/keys").await?;
let store = EncryptedKeyStore::new(backing, master_key);

// Store a key with metadata
let metadata = KeyMetadata::new("aes-256-gcm")
    .with_expiry(Duration::from_secs(86400 * 30)); // 30 days
store.store("encryption-key", &key_bytes, Some(&metadata)).await?;

// Retrieve later
let key = store.get("encryption-key").await?.expect("key not found");
```

## Security Best Practices

### DO:
- Use `Aes256Gcm` or `ChaCha20Poly1305` for symmetric encryption
- Use `Argon2id` for password hashing (never SHA-256!)
- Use `Ed25519` for new signature systems
- Derive separate keys for encryption and authentication
- Use random nonces with sufficient length
- Zeroize sensitive data after use (automatic with our types)

### DON'T:
- Reuse nonces with the same key (catastrophic for GCM!)
- Use ECB mode (we don't even provide it)
- Roll your own crypto - use `arcanum-protocols` for channels
- Store raw keys - use `arcanum-keystore`
- Mix algorithms without understanding implications

## Feature Flags

Each crate uses feature flags to minimize binary size:

```toml
[dependencies]
arcanum-hash = { version = "0.1", features = ["sha2", "blake3", "argon2"] }
arcanum-symmetric = { version = "0.1", features = ["aes-gcm", "chacha20poly1305"] }
arcanum-signatures = { version = "0.1", features = ["ed25519"] }
```

Default features provide the most common algorithms. Enable only what you need for smaller binaries.
