//! Known Answer Tests (KAT) for digital signatures.
//!
//! These tests verify our implementations match official test vectors
//! from RFC 8032 (Ed25519), NIST FIPS 186-4 (ECDSA), and other standards.

use arcanum_signatures::{SigningKey, VerifyingKey, Signature};
use arcanum_signatures::{Ed25519SigningKey, Ed25519VerifyingKey, Ed25519Signature};
use arcanum_signatures::{
    P256SigningKey, P256VerifyingKey, P256Signature,
    P384SigningKey, P384VerifyingKey, P384Signature,
    Secp256k1SigningKey, Secp256k1VerifyingKey, Secp256k1Signature,
};

// ═══════════════════════════════════════════════════════════════════════════════
// Ed25519 Test Vectors (RFC 8032 Section 7.1)
// ═══════════════════════════════════════════════════════════════════════════════

/// RFC 8032 Section 7.1 - Test 1 (empty message)
#[test]
fn ed25519_rfc8032_test1_empty() {
    // Secret key (seed)
    let secret = hex::decode(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    ).unwrap();

    // Expected public key
    let expected_public = hex::decode(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    ).unwrap();

    // Empty message
    let message: &[u8] = b"";

    // Expected signature
    let expected_signature = hex::decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ).unwrap();

    // Create signing key from seed
    let signing_key = Ed25519SigningKey::from_bytes(&secret).unwrap();
    let verifying_key = signing_key.verifying_key();

    // Verify public key matches
    assert_eq!(
        verifying_key.to_bytes(),
        expected_public,
        "Public key mismatch"
    );

    // Sign and verify signature
    let signature = signing_key.sign(message);
    assert_eq!(
        signature.to_bytes(),
        expected_signature,
        "Signature mismatch"
    );

    // Verify signature is valid
    assert!(
        verifying_key.verify(message, &signature).is_ok(),
        "Signature verification failed"
    );
}

/// RFC 8032 Section 7.1 - Test 2 (one byte message)
#[test]
fn ed25519_rfc8032_test2_one_byte() {
    let secret = hex::decode(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    ).unwrap();

    let expected_public = hex::decode(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    ).unwrap();

    let message = hex::decode("72").unwrap();  // 0x72 = 'r'

    let expected_signature = hex::decode(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    ).unwrap();

    let signing_key = Ed25519SigningKey::from_bytes(&secret).unwrap();
    let verifying_key = signing_key.verifying_key();

    assert_eq!(verifying_key.to_bytes(), expected_public, "Public key mismatch");

    let signature = signing_key.sign(&message);
    assert_eq!(signature.to_bytes(), expected_signature, "Signature mismatch");

    assert!(verifying_key.verify(&message, &signature).is_ok(), "Verification failed");
}

/// RFC 8032 Section 7.1 - Test 3 (two byte message)
#[test]
fn ed25519_rfc8032_test3_two_bytes() {
    let secret = hex::decode(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
    ).unwrap();

    let expected_public = hex::decode(
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
    ).unwrap();

    let message = hex::decode("af82").unwrap();

    let expected_signature = hex::decode(
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
         18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    ).unwrap();

    let signing_key = Ed25519SigningKey::from_bytes(&secret).unwrap();
    let verifying_key = signing_key.verifying_key();

    assert_eq!(verifying_key.to_bytes(), expected_public, "Public key mismatch");

    let signature = signing_key.sign(&message);
    assert_eq!(signature.to_bytes(), expected_signature, "Signature mismatch");

    assert!(verifying_key.verify(&message, &signature).is_ok(), "Verification failed");
}

/// RFC 8032 Section 7.1 - Test 1024 (longer message)
#[test]
fn ed25519_rfc8032_test_1024() {
    let secret = hex::decode(
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"
    ).unwrap();

    let expected_public = hex::decode(
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"
    ).unwrap();

    // 1023 bytes: 0x08, 0xb8, 0xb2, ...
    let message = hex::decode(
        "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98\
         fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8\
         79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d\
         658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc\
         1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe\
         ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e\
         06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef\
         efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7\
         aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1\
         85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2\
         d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24\
         554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270\
         88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc\
         2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07\
         07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba\
         b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a\
         ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e\
         c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7\
         51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c\
         42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8\
         ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df\
         f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08\
         d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649\
         de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4\
         88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3\
         2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e\
         6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f\
         b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5\
         0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1\
         369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d\
         b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c\
         0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"
    ).unwrap();

    let expected_signature = hex::decode(
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350\
         aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
    ).unwrap();

    let signing_key = Ed25519SigningKey::from_bytes(&secret).unwrap();
    let verifying_key = signing_key.verifying_key();

    assert_eq!(verifying_key.to_bytes(), expected_public, "Public key mismatch");

    let signature = signing_key.sign(&message);
    assert_eq!(signature.to_bytes(), expected_signature, "Signature mismatch");

    assert!(verifying_key.verify(&message, &signature).is_ok(), "Verification failed");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Ed25519 Error Handling Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test that verification fails with wrong message
#[test]
fn ed25519_wrong_message_fails() {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let message = b"Original message";
    let wrong_message = b"Wrong message";

    let signature = signing_key.sign(message);

    assert!(
        verifying_key.verify(wrong_message, &signature).is_err(),
        "Verification should fail with wrong message"
    );
}

/// Test that verification fails with wrong signature
#[test]
fn ed25519_wrong_signature_fails() {
    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let message = b"Test message";
    let signature = signing_key.sign(message);

    // Tamper with signature
    let mut sig_bytes = signature.to_bytes();
    sig_bytes[0] ^= 0xFF;
    let tampered_signature = Ed25519Signature::from_bytes(&sig_bytes).unwrap();

    assert!(
        verifying_key.verify(message, &tampered_signature).is_err(),
        "Verification should fail with tampered signature"
    );
}

/// Test that verification fails with wrong public key
#[test]
fn ed25519_wrong_key_fails() {
    let signing_key1 = Ed25519SigningKey::generate();
    let signing_key2 = Ed25519SigningKey::generate();

    let verifying_key2 = signing_key2.verifying_key();

    let message = b"Test message";
    let signature = signing_key1.sign(message);

    assert!(
        verifying_key2.verify(message, &signature).is_err(),
        "Verification should fail with wrong key"
    );
}

/// Test invalid key length rejection
#[test]
fn ed25519_invalid_key_length() {
    let short_key = hex::decode("0102030405060708").unwrap();
    let result = Ed25519SigningKey::from_bytes(&short_key);
    assert!(result.is_err(), "Should reject invalid key length");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Ed25519 Property Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Ed25519 signatures are deterministic
#[test]
fn ed25519_deterministic() {
    let signing_key = Ed25519SigningKey::generate();
    let message = b"The quick brown fox jumps over the lazy dog";

    let sig1 = signing_key.sign(message);
    let sig2 = signing_key.sign(message);

    assert_eq!(sig1.to_bytes(), sig2.to_bytes(), "Ed25519 should be deterministic");
}

/// Ed25519 signature length is always 64 bytes
#[test]
fn ed25519_signature_length() {
    let signing_key = Ed25519SigningKey::generate();

    for size in [0, 1, 10, 100, 1000] {
        let message = vec![0u8; size];
        let signature = signing_key.sign(&message);
        assert_eq!(signature.to_bytes().len(), 64, "Signature should be 64 bytes");
    }
}

/// Ed25519 key serialization roundtrip
#[test]
fn ed25519_key_roundtrip() {
    let signing_key = Ed25519SigningKey::generate();
    let bytes = signing_key.to_bytes();

    let restored = Ed25519SigningKey::from_bytes(&bytes).unwrap();
    assert_eq!(
        signing_key.verifying_key().to_bytes(),
        restored.verifying_key().to_bytes(),
        "Key roundtrip failed"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ECDSA P-256 Test Vectors (NIST FIPS 186-4 / Wycheproof)
// ═══════════════════════════════════════════════════════════════════════════════

/// ECDSA P-256 test vector from NIST FIPS 186-4 / Wycheproof
/// This tests basic sign/verify functionality with a known good key pair.
#[test]
fn ecdsa_p256_basic_sign_verify() {
    // Well-known test private key (from Wycheproof test vectors)
    let private_key = hex::decode(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
    ).unwrap();

    let signing_key = P256SigningKey::from_bytes(&private_key).unwrap();
    let verifying_key = signing_key.verifying_key();

    // Message to sign
    let message = b"sample";

    // Sign the message
    let signature = signing_key.sign(message);

    // Verify the signature
    assert!(
        verifying_key.verify(message, &signature).is_ok(),
        "P-256 signature verification failed"
    );

    // Signature should be 64 bytes (32 bytes r + 32 bytes s)
    assert_eq!(
        signature.to_bytes().len(),
        64,
        "P-256 signature should be 64 bytes"
    );
}

/// ECDSA P-256: Verify known public key derivation
#[test]
fn ecdsa_p256_key_derivation() {
    // RFC 6979 test vector - deterministic ECDSA
    // Private key
    let private_key = hex::decode(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
    ).unwrap();

    // Expected public key (uncompressed point, 65 bytes: 04 || x || y)
    // We expect compressed format from our API (33 bytes: 02/03 || x)
    let expected_x = hex::decode(
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
    ).unwrap();

    let signing_key = P256SigningKey::from_bytes(&private_key).unwrap();
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_bytes();

    // First byte is the compression prefix (02 or 03)
    assert!(
        pubkey_bytes[0] == 0x02 || pubkey_bytes[0] == 0x03,
        "Invalid compression prefix"
    );

    // X coordinate should match
    assert_eq!(
        &pubkey_bytes[1..33],
        &expected_x[..],
        "Public key X coordinate mismatch"
    );
}

/// ECDSA P-256: Signature verification with prehashed message
#[test]
fn ecdsa_p256_prehashed_signature() {
    use sha2::{Sha256, Digest};

    let signing_key = P256SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let message = b"Test message for prehashed ECDSA";

    // Hash the message
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize();

    // Sign the prehashed message
    let signature = signing_key.sign_prehashed(&hash).unwrap();

    // Verify with prehashed
    assert!(
        verifying_key.verify_prehashed(&hash, &signature).is_ok(),
        "Prehashed signature verification failed"
    );
}

/// ECDSA P-256: Wrong message fails verification
#[test]
fn ecdsa_p256_wrong_message_fails() {
    let signing_key = P256SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let message = b"Original message";
    let wrong_message = b"Wrong message";

    let signature = signing_key.sign(message);

    assert!(
        verifying_key.verify(wrong_message, &signature).is_err(),
        "Verification should fail with wrong message"
    );
}

/// ECDSA P-256: Tampered signature fails verification
#[test]
fn ecdsa_p256_tampered_signature_fails() {
    let signing_key = P256SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let message = b"Test message";
    let signature = signing_key.sign(message);

    // Tamper with the signature
    let mut sig_bytes = signature.to_bytes();
    sig_bytes[0] ^= 0xFF;
    let tampered = P256Signature::from_bytes(&sig_bytes).unwrap();

    assert!(
        verifying_key.verify(message, &tampered).is_err(),
        "Verification should fail with tampered signature"
    );
}

/// ECDSA P-256: Wrong key fails verification
#[test]
fn ecdsa_p256_wrong_key_fails() {
    let signing_key1 = P256SigningKey::generate();
    let signing_key2 = P256SigningKey::generate();
    let verifying_key2 = signing_key2.verifying_key();

    let message = b"Test message";
    let signature = signing_key1.sign(message);

    assert!(
        verifying_key2.verify(message, &signature).is_err(),
        "Verification should fail with wrong key"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// ECDSA P-384 Test Vectors (NIST FIPS 186-4)
// ═══════════════════════════════════════════════════════════════════════════════

/// ECDSA P-384: Basic sign/verify test
#[test]
fn ecdsa_p384_basic_sign_verify() {
    // Generate a key pair (P-384 keys are 48 bytes)
    let signing_key = P384SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let message = b"Test message for P-384 ECDSA";

    let signature = signing_key.sign(message);

    assert!(
        verifying_key.verify(message, &signature).is_ok(),
        "P-384 signature verification failed"
    );

    // P-384 signature should be 96 bytes (48 bytes r + 48 bytes s)
    assert_eq!(
        signature.to_bytes().len(),
        96,
        "P-384 signature should be 96 bytes"
    );
}

/// ECDSA P-384: Key size validation
#[test]
fn ecdsa_p384_key_sizes() {
    let signing_key = P384SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    // Private key should be 48 bytes
    assert_eq!(
        signing_key.to_bytes().len(),
        48,
        "P-384 private key should be 48 bytes"
    );

    // Compressed public key should be 49 bytes (1 prefix + 48 x-coord)
    assert_eq!(
        verifying_key.to_bytes().len(),
        49,
        "P-384 compressed public key should be 49 bytes"
    );
}

/// ECDSA P-384: Prehashed signature with SHA-384
#[test]
fn ecdsa_p384_prehashed_signature() {
    use sha2::{Sha384, Digest};

    let signing_key = P384SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let message = b"Test message for prehashed P-384 ECDSA";

    // Hash with SHA-384
    let mut hasher = Sha384::new();
    hasher.update(message);
    let hash = hasher.finalize();

    let signature = signing_key.sign_prehashed(&hash).unwrap();

    assert!(
        verifying_key.verify_prehashed(&hash, &signature).is_ok(),
        "P-384 prehashed signature verification failed"
    );
}

/// ECDSA P-384: Wrong message fails verification
#[test]
fn ecdsa_p384_wrong_message_fails() {
    let signing_key = P384SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let message = b"Original";
    let wrong_message = b"Wrong";

    let signature = signing_key.sign(message);

    assert!(
        verifying_key.verify(wrong_message, &signature).is_err(),
        "P-384 verification should fail with wrong message"
    );
}

/// ECDSA P-384: Key roundtrip serialization
#[test]
fn ecdsa_p384_key_roundtrip() {
    let signing_key = P384SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    // Serialize and deserialize verifying key
    let bytes = verifying_key.to_bytes();
    let restored = P384VerifyingKey::from_bytes(&bytes).unwrap();

    assert_eq!(
        verifying_key.to_bytes(),
        restored.to_bytes(),
        "P-384 verifying key roundtrip failed"
    );

    // Test signing key roundtrip
    let sk_bytes = signing_key.to_bytes();
    let restored_sk = P384SigningKey::from_bytes(&sk_bytes).unwrap();

    // Sign with restored key
    let message = b"Roundtrip test";
    let sig = restored_sk.sign(message);
    assert!(verifying_key.verify(message, &sig).is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════════
// ECDSA secp256k1 Test Vectors (Bitcoin/Ethereum)
// ═══════════════════════════════════════════════════════════════════════════════

/// secp256k1: Basic sign/verify test
#[test]
fn ecdsa_secp256k1_basic_sign_verify() {
    let signing_key = Secp256k1SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let message = b"Bitcoin message signing test";

    let signature = signing_key.sign(message);

    assert!(
        verifying_key.verify(message, &signature).is_ok(),
        "secp256k1 signature verification failed"
    );

    // secp256k1 signature should be 64 bytes
    assert_eq!(
        signature.to_bytes().len(),
        64,
        "secp256k1 signature should be 64 bytes"
    );
}

/// secp256k1: Known test vector (from Bitcoin/Wycheproof)
#[test]
fn ecdsa_secp256k1_known_key() {
    // Well-known test private key
    let private_key = hex::decode(
        "0000000000000000000000000000000000000000000000000000000000000001"
    ).unwrap();

    let signing_key = Secp256k1SigningKey::from_bytes(&private_key).unwrap();
    let verifying_key = signing_key.verifying_key();

    // The generator point G as public key (compressed)
    // For private key = 1, public key = G
    let expected_pubkey_compressed = hex::decode(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    ).unwrap();

    assert_eq!(
        verifying_key.to_bytes(),
        expected_pubkey_compressed,
        "secp256k1 public key for private key 1 should be generator point G"
    );
}

/// secp256k1: Ethereum-style message signing
#[test]
fn ecdsa_secp256k1_ethereum_style() {
    use sha3::{Keccak256, Digest};

    let signing_key = Secp256k1SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    // Ethereum uses Keccak-256 for message hashing
    let message = b"Hello Ethereum!";
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());

    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message);
    let hash = hasher.finalize();

    // Sign the prehashed message
    let signature = signing_key.sign_prehashed(&hash).unwrap();

    // Verify with prehashed
    assert!(
        verifying_key.verify_prehashed(&hash, &signature).is_ok(),
        "Ethereum-style signature verification failed"
    );
}

/// secp256k1: Wrong message fails verification
#[test]
fn ecdsa_secp256k1_wrong_message_fails() {
    let signing_key = Secp256k1SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let message = b"Original";
    let wrong_message = b"Wrong";

    let signature = signing_key.sign(message);

    assert!(
        verifying_key.verify(wrong_message, &signature).is_err(),
        "secp256k1 verification should fail with wrong message"
    );
}

/// secp256k1: Key sizes are correct
#[test]
fn ecdsa_secp256k1_key_sizes() {
    let signing_key = Secp256k1SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    // Private key should be 32 bytes
    assert_eq!(
        signing_key.to_bytes().len(),
        32,
        "secp256k1 private key should be 32 bytes"
    );

    // Compressed public key should be 33 bytes
    assert_eq!(
        verifying_key.to_bytes().len(),
        33,
        "secp256k1 compressed public key should be 33 bytes"
    );
}

/// secp256k1: Key roundtrip serialization
#[test]
fn ecdsa_secp256k1_key_roundtrip() {
    let signing_key = Secp256k1SigningKey::generate();

    // Signing key roundtrip
    let sk_bytes = signing_key.to_bytes();
    let restored = Secp256k1SigningKey::from_bytes(&sk_bytes).unwrap();

    assert_eq!(
        signing_key.verifying_key().to_bytes(),
        restored.verifying_key().to_bytes(),
        "secp256k1 key roundtrip failed"
    );
}

/// secp256k1: Signature roundtrip serialization
#[test]
fn ecdsa_secp256k1_signature_roundtrip() {
    let signing_key = Secp256k1SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    let message = b"Signature roundtrip test";
    let signature = signing_key.sign(message);

    // Serialize and deserialize
    let sig_bytes = signature.to_bytes();
    let restored_sig = Secp256k1Signature::from_bytes(&sig_bytes).unwrap();

    // Should still verify
    assert!(
        verifying_key.verify(message, &restored_sig).is_ok(),
        "Restored signature should verify"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cross-Curve Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that different curves produce different signature formats
#[test]
fn cross_curve_signature_sizes() {
    let message = b"Test message";

    // Ed25519: 64-byte signatures
    let ed_key = Ed25519SigningKey::generate();
    let ed_sig = ed_key.sign(message);
    assert_eq!(ed_sig.to_bytes().len(), 64);

    // P-256: 64-byte signatures
    let p256_key = P256SigningKey::generate();
    let p256_sig = p256_key.sign(message);
    assert_eq!(p256_sig.to_bytes().len(), 64);

    // P-384: 96-byte signatures
    let p384_key = P384SigningKey::generate();
    let p384_sig = p384_key.sign(message);
    assert_eq!(p384_sig.to_bytes().len(), 96);

    // secp256k1: 64-byte signatures
    let secp_key = Secp256k1SigningKey::generate();
    let secp_sig = secp_key.sign(message);
    assert_eq!(secp_sig.to_bytes().len(), 64);
}

/// Verify signatures from one curve don't verify with another curve's key
#[test]
fn cross_curve_no_confusion() {
    let message = b"Cross-curve test";

    // Sign with P-256
    let p256_key = P256SigningKey::generate();
    let p256_sig = p256_key.sign(message);

    // Create secp256k1 key
    let secp_key = Secp256k1SigningKey::generate();
    let secp_vk = secp_key.verifying_key();

    // Try to create a secp256k1 signature from P-256 bytes
    // This may fail at parsing or verification
    let p256_sig_bytes = p256_sig.to_bytes();
    if let Ok(fake_sig) = Secp256k1Signature::from_bytes(&p256_sig_bytes) {
        // If parsing succeeds, verification should fail
        assert!(
            secp_vk.verify(message, &fake_sig).is_err(),
            "Cross-curve signature should not verify"
        );
    }
    // If parsing fails, that's also correct behavior
}
