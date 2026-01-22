#!/bin/bash
#
# Generate "Good First Issues" for Arcanum
# Usage: ./scripts/generate-good-first-issues.sh [--dry-run] [--category CATEGORY]
#
# Categories: test-vectors, examples, benchmarks, docs
#

set -e

DRY_RUN=false
CATEGORY="all"
REPO="Daemoniorum-LLC/arcanum"

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --category)
            CATEGORY="$2"
            shift 2
            ;;
        --repo)
            REPO="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

create_issue() {
    local title="$1"
    local body="$2"
    local labels="$3"

    if $DRY_RUN; then
        echo "Would create: $title"
        echo "  Labels: $labels"
        echo ""
    else
        echo "Creating: $title"
        gh issue create \
            --repo "$REPO" \
            --title "$title" \
            --body "$body" \
            --label "$labels"
        sleep 1  # Rate limiting
    fi
}

# ============================================================================
# WYCHEPROOF TEST VECTORS
# ============================================================================

generate_wycheproof_issues() {
    echo "=== Generating Wycheproof Test Vector Issues ==="

    # AES-GCM
    for i in {1..5}; do
        start=$(( (i-1)*5 + 1 ))
        end=$(( i*5 ))
        create_issue \
            "[Test Vector] Wycheproof AES-GCM tcId $start-$end" \
"## Add Wycheproof AES-GCM Test Vectors

**Difficulty**: Beginner (no Rust experience required)
**Time**: 5-10 minutes

### What to do

1. Open [aes_gcm_test.json](https://github.com/google/wycheproof/blob/master/testvectors/aes_gcm_test.json)
2. Find test cases with \`tcId\` $start through $end
3. Add them to \`crates/arcanum-symmetric/src/aes_ciphers.rs\` in the tests module

### Template

\`\`\`rust
#[test]
fn test_wycheproof_aes_gcm_tcid_$start() {
    // tcId: $start
    // Comment from Wycheproof: <copy the comment field>
    let key = hex!(\"<key>\");
    let iv = hex!(\"<iv>\");
    let aad = hex!(\"<aad>\");
    let msg = hex!(\"<msg>\");
    let ct = hex!(\"<ct>\");
    let tag = hex!(\"<tag>\");
    let result = hex!(\"<result>\");  // \"valid\", \"invalid\", or \"acceptable\"

    // Test encryption
    let ciphertext = Aes256Gcm::encrypt(&key, &iv, &msg, Some(&aad)).unwrap();
    assert_eq!(&ciphertext[..ct.len()], &ct[..]);
}
\`\`\`

### Resources
- [Wycheproof AES-GCM vectors](https://github.com/google/wycheproof/blob/master/testvectors/aes_gcm_test.json)
- [Existing tests for reference](../../crates/arcanum-symmetric/src/aes_ciphers.rs)" \
            "good first issue,test,help wanted,aes-gcm"
    done

    # ChaCha20-Poly1305
    for i in {1..5}; do
        start=$(( (i-1)*5 + 1 ))
        end=$(( i*5 ))
        create_issue \
            "[Test Vector] Wycheproof ChaCha20-Poly1305 tcId $start-$end" \
"## Add Wycheproof ChaCha20-Poly1305 Test Vectors

**Difficulty**: Beginner (no Rust experience required)
**Time**: 5-10 minutes

### What to do

1. Open [chacha20_poly1305_test.json](https://github.com/google/wycheproof/blob/master/testvectors/chacha20_poly1305_test.json)
2. Find test cases with \`tcId\` $start through $end
3. Add them to \`crates/arcanum-symmetric/src/chacha_ciphers.rs\` in the tests module

### Template

\`\`\`rust
#[test]
fn test_wycheproof_chacha20poly1305_tcid_$start() {
    // tcId: $start
    let key = hex!(\"<key>\");
    let iv = hex!(\"<iv>\");
    let aad = hex!(\"<aad>\");
    let msg = hex!(\"<msg>\");
    let ct = hex!(\"<ct>\");
    let tag = hex!(\"<tag>\");

    let ciphertext = ChaCha20Poly1305Cipher::encrypt(&key, &iv, &msg, Some(&aad)).unwrap();
    assert_eq!(&ciphertext[..ct.len()], &ct[..]);
}
\`\`\`

### Resources
- [Wycheproof ChaCha20-Poly1305 vectors](https://github.com/google/wycheproof/blob/master/testvectors/chacha20_poly1305_test.json)" \
            "good first issue,test,help wanted,chacha20"
    done

    # Ed25519
    for i in {1..5}; do
        start=$(( (i-1)*5 + 1 ))
        end=$(( i*5 ))
        create_issue \
            "[Test Vector] Wycheproof Ed25519 tcId $start-$end" \
"## Add Wycheproof Ed25519 Test Vectors

**Difficulty**: Beginner (no Rust experience required)
**Time**: 5-10 minutes

### What to do

1. Open [ed25519_test.json](https://github.com/google/wycheproof/blob/master/testvectors/ed25519_test.json)
2. Find test cases with \`tcId\` $start through $end
3. Add them to \`crates/arcanum-signatures/src/ed25519.rs\` in the tests module

### Resources
- [Wycheproof Ed25519 vectors](https://github.com/google/wycheproof/blob/master/testvectors/ed25519_test.json)" \
            "good first issue,test,help wanted,ed25519"
    done

    # X25519
    for i in {1..4}; do
        start=$(( (i-1)*5 + 1 ))
        end=$(( i*5 ))
        create_issue \
            "[Test Vector] Wycheproof X25519 tcId $start-$end" \
"## Add Wycheproof X25519 Test Vectors

**Difficulty**: Beginner (no Rust experience required)
**Time**: 5-10 minutes

### What to do

1. Open [x25519_test.json](https://github.com/google/wycheproof/blob/master/testvectors/x25519_test.json)
2. Find test cases with \`tcId\` $start through $end
3. Add them to \`crates/arcanum-asymmetric/src/x25519.rs\` in the tests module

**Note**: Some test cases include low-order points that should be rejected. Check the \`result\` field!

### Resources
- [Wycheproof X25519 vectors](https://github.com/google/wycheproof/blob/master/testvectors/x25519_test.json)" \
            "good first issue,test,help wanted,x25519"
    done
}

# ============================================================================
# DOCUMENTATION EXAMPLES
# ============================================================================

generate_example_issues() {
    echo "=== Generating Documentation Example Issues ==="

    create_issue \
        "[Docs] Add ML-KEM key exchange example" \
"## Add Usage Example for ML-KEM Key Exchange

**Difficulty**: Beginner (basic Rust)
**Time**: 10-15 minutes

### What to do

Add a complete example showing how to perform a key exchange using ML-KEM-768.

### Where to add it

\`crates/arcanum-pqc/src/ml_kem.rs\` - in the module-level doc comment

### Example structure

\`\`\`rust
//! ## Example: Key Exchange
//!
//! \`\`\`rust
//! use arcanum_pqc::ml_kem::{MlKem768, Kem};
//!
//! // Alice generates a keypair
//! let (encapsulation_key, decapsulation_key) = MlKem768::generate();
//!
//! // Alice sends encapsulation_key to Bob...
//!
//! // Bob encapsulates a shared secret
//! let (ciphertext, shared_secret_bob) = MlKem768::encapsulate(&encapsulation_key);
//!
//! // Bob sends ciphertext to Alice...
//!
//! // Alice decapsulates to get the same shared secret
//! let shared_secret_alice = MlKem768::decapsulate(&decapsulation_key, &ciphertext);
//!
//! assert_eq!(shared_secret_alice, shared_secret_bob);
//! \`\`\`
\`\`\`

### Tips
- Make sure the example compiles (run \`cargo test --doc\`)
- Keep it simple and focused on the happy path" \
        "good first issue,documentation,help wanted,pqc"

    create_issue \
        "[Docs] Add hybrid X25519 + ML-KEM example" \
"## Add Usage Example for Hybrid Key Exchange

**Difficulty**: Beginner (basic Rust)
**Time**: 10-15 minutes

### What to do

Add an example showing how to combine X25519 (classical) with ML-KEM (post-quantum) for defense-in-depth key exchange.

### Where to add it

\`crates/arcanum-pqc/src/hybrid.rs\` or create \`examples/hybrid_key_exchange.rs\`

### Why hybrid?

Hybrid combines the battle-tested security of X25519 with the quantum resistance of ML-KEM. If either algorithm is broken, the other still protects the key exchange." \
        "good first issue,documentation,help wanted,pqc"

    create_issue \
        "[Docs] Add HoloCrypt selective disclosure example" \
"## Add Usage Example for Selective Disclosure

**Difficulty**: Beginner-Intermediate (basic Rust)
**Time**: 15-20 minutes

### What to do

Add an example showing how to:
1. Create a HoloCrypt container with multiple data chunks
2. Generate a Merkle proof for one chunk
3. Verify the proof without revealing other chunks

### Where to add it

\`crates/arcanum-holocrypt/src/selective.rs\` or \`examples/selective_disclosure.rs\`

### Use case

Imagine proving you have a valid credential without revealing all your personal data - selective disclosure makes this possible." \
        "good first issue,documentation,help wanted,holocrypt"

    create_issue \
        "[Docs] Add Argon2 password hashing example" \
"## Add Usage Example for Password Hashing

**Difficulty**: Beginner (basic Rust)
**Time**: 10 minutes

### What to do

Add a simple example showing secure password hashing with Argon2id.

### Key points to cover
- Generating a random salt
- Choosing appropriate parameters (memory, iterations, parallelism)
- Hashing a password
- Verifying a password

### Where to add it

\`crates/arcanum-hash/src/argon2.rs\`" \
        "good first issue,documentation,help wanted,hash"

    create_issue \
        "[Docs] Add HKDF key derivation example" \
"## Add Usage Example for HKDF

**Difficulty**: Beginner (basic Rust)
**Time**: 10 minutes

### What to do

Add an example showing how to derive multiple keys from a single shared secret using HKDF.

### Use case

After a key exchange, you often need multiple keys (encryption key, MAC key, IV, etc.). HKDF lets you safely derive all of them from one shared secret." \
        "good first issue,documentation,help wanted,hash"
}

# ============================================================================
# BENCHMARK SCENARIOS
# ============================================================================

generate_benchmark_issues() {
    echo "=== Generating Benchmark Issues ==="

    create_issue \
        "[Benchmark] Add ML-DSA signing throughput benchmark" \
"## Add ML-DSA Signing Throughput Benchmark

**Difficulty**: Beginner (copy existing pattern)
**Time**: 10-15 minutes

### What to do

Add a benchmark measuring how many signatures per second ML-DSA can produce.

### Where to add it

\`crates/arcanum-pqc/benches/pqc_bench.rs\`

### Template

Copy the existing ML-KEM benchmark pattern and adapt for ML-DSA signing." \
        "good first issue,performance,help wanted,pqc"

    create_issue \
        "[Benchmark] Add large message encryption benchmark (1MB, 10MB, 100MB)" \
"## Add Large Message Encryption Benchmarks

**Difficulty**: Beginner (copy existing pattern)
**Time**: 10-15 minutes

### What to do

Add benchmarks for encrypting large messages with AES-GCM and ChaCha20-Poly1305.

### Sizes to benchmark
- 1 MB
- 10 MB
- 100 MB

### Where to add it

\`crates/arcanum-symmetric/benches/\` or \`crates/arcanum-primitives/benches/primitives_bench.rs\`" \
        "good first issue,performance,help wanted"

    create_issue \
        "[Benchmark] Add batch signature verification benchmark" \
"## Add Batch Signature Verification Benchmark

**Difficulty**: Beginner (copy existing pattern)
**Time**: 10-15 minutes

### What to do

Benchmark verifying 100, 1000, and 10000 Ed25519 signatures to show batch performance characteristics." \
        "good first issue,performance,help wanted,ed25519"
}

# ============================================================================
# ERROR MESSAGE IMPROVEMENTS
# ============================================================================

generate_error_message_issues() {
    echo "=== Generating Error Message Issues ==="

    create_issue \
        "[DX] Improve error message for invalid key length" \
"## Improve Invalid Key Length Error Message

**Difficulty**: Beginner
**Time**: 5-10 minutes

### Current message
\`InvalidKeyLength { expected: 32, actual: 16 }\`

### Better message
\`Invalid key length: expected 32 bytes (256 bits) for AES-256, got 16 bytes. Did you mean to use AES-128?\`

### What to do

1. Find \`InvalidKeyLength\` in \`crates/arcanum-symmetric/src/error.rs\`
2. Improve the Display implementation
3. Add algorithm context where possible" \
        "good first issue,help wanted,dx"

    create_issue \
        "[DX] Improve error message for authentication failure" \
"## Improve Authentication Failure Error Message

**Difficulty**: Beginner
**Time**: 5-10 minutes

### Current message
\`AuthenticationFailed\`

### Better message
\`Authentication failed: the ciphertext may have been tampered with, or the wrong key/nonce was used\`

### What to do

Make the error message more helpful for debugging without leaking security-sensitive information." \
        "good first issue,help wanted,dx"
}

# ============================================================================
# MAIN
# ============================================================================

echo "Arcanum Good First Issues Generator"
echo "===================================="
echo "Repository: $REPO"
echo "Dry run: $DRY_RUN"
echo "Category: $CATEGORY"
echo ""

case $CATEGORY in
    test-vectors)
        generate_wycheproof_issues
        ;;
    examples)
        generate_example_issues
        ;;
    benchmarks)
        generate_benchmark_issues
        ;;
    errors)
        generate_error_message_issues
        ;;
    all)
        generate_wycheproof_issues
        generate_example_issues
        generate_benchmark_issues
        generate_error_message_issues
        ;;
    *)
        echo "Unknown category: $CATEGORY"
        echo "Valid categories: test-vectors, examples, benchmarks, errors, all"
        exit 1
        ;;
esac

echo ""
echo "Done!"
if $DRY_RUN; then
    echo "(This was a dry run - no issues were created)"
fi
