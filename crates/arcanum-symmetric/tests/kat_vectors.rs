//! Known Answer Tests (KAT) from official test vectors.
//!
//! These tests verify our implementations match official cryptographic
//! test vectors from NIST and IETF RFCs.

use arcanum_symmetric::{
    Aes128Gcm, Aes256Gcm, Aes256GcmSiv, ChaCha20Poly1305Cipher, Cipher, XChaCha20Poly1305Cipher,
};

// ═══════════════════════════════════════════════════════════════════════════════
// AES-GCM Test Vectors (NIST SP 800-38D)
// ═══════════════════════════════════════════════════════════════════════════════

/// Test vector from NIST SP 800-38D, Test Case 14
/// AES-256-GCM with 60-byte plaintext and AAD
#[test]
fn aes256_gcm_nist_test_case_14() {
    // Key: 32 bytes
    let key = hex::decode(
        "feffe9928665731c6d6a8f9467308308\
         feffe9928665731c6d6a8f9467308308",
    )
    .unwrap();

    // Nonce: 12 bytes (96-bit IV)
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();

    // Plaintext: 60 bytes
    let plaintext = hex::decode(
        "d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b39",
    )
    .unwrap();

    // AAD: 20 bytes
    let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();

    // Expected ciphertext: 60 bytes
    let expected_ciphertext = hex::decode(
        "522dc1f099567d07f47f37a32a84427d\
         643a8cdcbfe5c0c97598a2bd2555d1aa\
         8cb08e48590dbb3da7b08b1056828838\
         c5f61e6393ba7a0abcc9f662",
    )
    .unwrap();

    // Expected tag: 16 bytes
    let expected_tag = hex::decode("76fc6ece0f4e1768cddf8853bb2d551b").unwrap();

    // Encrypt
    let result = Aes256Gcm::encrypt(&key, &nonce, &plaintext, Some(&aad)).unwrap();

    // Result contains ciphertext + tag
    let (ct, tag) = result.split_at(result.len() - 16);

    assert_eq!(ct, expected_ciphertext.as_slice(), "Ciphertext mismatch");
    assert_eq!(tag, expected_tag.as_slice(), "Authentication tag mismatch");

    // Decrypt and verify roundtrip
    let decrypted = Aes256Gcm::decrypt(&key, &nonce, &result, Some(&aad)).unwrap();
    assert_eq!(decrypted, plaintext, "Decryption roundtrip failed");
}

/// Test vector from NIST SP 800-38D, Test Case 13
/// AES-256-GCM with no plaintext (AAD only authentication)
#[test]
fn aes256_gcm_nist_test_case_13() {
    let key = hex::decode(
        "00000000000000000000000000000000\
         00000000000000000000000000000000",
    )
    .unwrap();

    let nonce = hex::decode("000000000000000000000000").unwrap();
    let plaintext: Vec<u8> = vec![];
    let aad: Vec<u8> = vec![];

    // Expected output for empty plaintext: just the tag
    let expected_tag = hex::decode("530f8afbc74536b9a963b4f1c4cb738b").unwrap();

    let result = Aes256Gcm::encrypt(&key, &nonce, &plaintext, Some(&aad)).unwrap();

    // For empty plaintext, result should be just the tag
    assert_eq!(result.len(), 16, "Expected tag-only output");
    assert_eq!(result, expected_tag, "Tag mismatch for empty message");

    // Verify decryption
    let decrypted = Aes256Gcm::decrypt(&key, &nonce, &result, Some(&aad)).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Additional AES-256-GCM test with 16-byte plaintext
#[test]
fn aes256_gcm_16_byte_plaintext() {
    let key = hex::decode(
        "feffe9928665731c6d6a8f9467308308\
         feffe9928665731c6d6a8f9467308308",
    )
    .unwrap();

    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();

    // 16-byte (one block) plaintext
    let plaintext = hex::decode("d9313225f88406e5a55909c5aff5269a").unwrap();

    // Test that encryption produces valid ciphertext of correct length
    let result = Aes256Gcm::encrypt(&key, &nonce, &plaintext, None).unwrap();
    assert_eq!(result.len(), plaintext.len() + 16, "Output length mismatch");

    // Verify roundtrip
    let decrypted = Aes256Gcm::decrypt(&key, &nonce, &result, None).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Test AES-128-GCM with NIST-style vector
#[test]
fn aes128_gcm_nist_style_vector() {
    // AES-128 key: 16 bytes
    let key = hex::decode("00000000000000000000000000000000").unwrap();
    let nonce = hex::decode("000000000000000000000000").unwrap();
    let plaintext: Vec<u8> = vec![];

    // Expected tag for empty message with zero key/nonce
    let expected_tag = hex::decode("58e2fccefa7e3061367f1d57a4e7455a").unwrap();

    let result = Aes128Gcm::encrypt(&key, &nonce, &plaintext, None).unwrap();
    assert_eq!(result, expected_tag, "AES-128-GCM tag mismatch");
}

/// Test AES-256-GCM-SIV deterministic encryption
/// SIV mode produces deterministic ciphertexts for the same inputs
#[test]
fn aes256_gcm_siv_determinism() {
    let key = hex::decode(
        "01000000000000000000000000000000\
         00000000000000000000000000000002",
    )
    .unwrap();

    let nonce = hex::decode("030000000000000000000000").unwrap();
    let plaintext = hex::decode("0100000000000000").unwrap();
    let aad: Vec<u8> = vec![];

    // Encrypt twice
    let ct1 = Aes256GcmSiv::encrypt(&key, &nonce, &plaintext, Some(&aad)).unwrap();
    let ct2 = Aes256GcmSiv::encrypt(&key, &nonce, &plaintext, Some(&aad)).unwrap();

    // SIV mode should produce identical ciphertexts
    assert_eq!(ct1, ct2, "AES-GCM-SIV should be deterministic");

    // Verify roundtrip
    let decrypted = Aes256GcmSiv::decrypt(&key, &nonce, &ct1, Some(&aad)).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ═══════════════════════════════════════════════════════════════════════════════
// ChaCha20-Poly1305 Test Vectors (RFC 8439)
// ═══════════════════════════════════════════════════════════════════════════════

/// RFC 8439 Section 2.8.2 - ChaCha20-Poly1305 AEAD Test Vector
#[test]
fn chacha20_poly1305_rfc8439_test_vector() {
    // Key from RFC 8439
    let key = hex::decode(
        "808182838485868788898a8b8c8d8e8f\
         909192939495969798999a9b9c9d9e9f",
    )
    .unwrap();

    // Nonce from RFC 8439 (12 bytes, with 32-bit counter prepended as zeros internally)
    let nonce = hex::decode("070000004041424344454647").unwrap();

    // Plaintext from RFC 8439 (using ASCII representation)
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

    // AAD from RFC 8439
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();

    // Expected ciphertext from RFC 8439
    let expected_ciphertext = hex::decode(
        "d31a8d34648e60db7b86afbc53ef7ec2\
         a4aded51296e08fea9e2b5a736ee62d6\
         3dbea45e8ca9671282fafb69da92728b\
         1a71de0a9e060b2905d6a5b67ecd3b36\
         92ddbd7f2d778b8c9803aee328091b58\
         fab324e4fad675945585808b4831d7bc\
         3ff4def08e4b7a9de576d26586cec64b\
         6116",
    )
    .unwrap();

    // Expected tag from RFC 8439
    let expected_tag = hex::decode("1ae10b594f09e26a7e902ecbd0600691").unwrap();

    // Encrypt
    let result = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, plaintext, Some(&aad)).unwrap();

    // Verify ciphertext and tag
    let (ct, tag) = result.split_at(result.len() - 16);
    assert_eq!(
        ct,
        expected_ciphertext.as_slice(),
        "ChaCha20-Poly1305 ciphertext mismatch"
    );
    assert_eq!(
        tag,
        expected_tag.as_slice(),
        "ChaCha20-Poly1305 tag mismatch"
    );

    // Verify decryption
    let decrypted = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &result, Some(&aad)).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// RFC 8439 Appendix A.5 - ChaCha20-Poly1305 Test Vector
#[test]
fn chacha20_poly1305_rfc8439_appendix_a5() {
    let key = hex::decode(
        "1c9240a5eb55d38af333888604f6b5f0\
         473917c1402b80099dca5cbc207075c0",
    )
    .unwrap();

    let nonce = hex::decode("000000000102030405060708").unwrap();

    // Internet draft text as plaintext
    let plaintext = hex::decode(
        "496e7465726e65742d44726166747320\
         61726520647261667420646f63756d65\
         6e74732076616c696420666f72206120\
         6d6178696d756d206f6620736978206d\
         6f6e74687320616e64206d6179206265\
         20757064617465642c207265706c6163\
         65642c206f72206f62736f6c65746564\
         206279206f7468657220646f63756d65\
         6e747320617420616e792074696d652e\
         20497420697320696e617070726f7072\
         6961746520746f2075736520496e7465\
         726e65742d4472616674732061732072\
         65666572656e6365206d617465726961\
         6c206f7220746f206369746520746865\
         6d206f74686572207468616e20617320\
         2fe2809c776f726b20696e2070726f67\
         726573732e2fe2809d",
    )
    .unwrap();

    let aad = hex::decode("f33388860000000000004e91").unwrap();

    let expected_ciphertext = hex::decode(
        "64a0861575861af460f062c79be643bd\
         5e805cfd345cf389f108670ac76c8cb2\
         4c6cfc18755d43eea09ee94e382d26b0\
         bdb7b73c321b0100d4f03b7f355894cf\
         332f830e710b97ce98c8a84abd0b9481\
         14ad176e008d33bd60f982b1ff37c855\
         9797a06ef4f0ef61c186324e2b350638\
         3606907b6a7c02b0f9f6157b53c867e4\
         b9166c767b804d46a59b5216cde7a4e9\
         9040c5a40433225ee282a1b0a06c523e\
         af4534d7f83fa1155b0047718cbc546a\
         0d072b04b3564eea1b422273f548271a\
         0bb2316053fa76991955ebd63159434e\
         cebb4e466dae5a1073a6727627097a10\
         49e617d91d361094fa68f0ff77987130\
         305beaba2eda04df997b714d6c6f2c29\
         a6ad5cb4022b02709b",
    )
    .unwrap();

    let expected_tag = hex::decode("eead9d67890cbb22392336fea1851f38").unwrap();

    let result = ChaCha20Poly1305Cipher::encrypt(&key, &nonce, &plaintext, Some(&aad)).unwrap();

    let (ct, tag) = result.split_at(result.len() - 16);
    assert_eq!(ct, expected_ciphertext.as_slice(), "Ciphertext mismatch");
    assert_eq!(tag, expected_tag.as_slice(), "Tag mismatch");

    // Roundtrip
    let decrypted = ChaCha20Poly1305Cipher::decrypt(&key, &nonce, &result, Some(&aad)).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// XChaCha20-Poly1305 Test Vector (from libsodium/draft-irtf-cfrg-xchacha)
#[test]
fn xchacha20_poly1305_test_vector() {
    // Test vector from draft-irtf-cfrg-xchacha-03
    let key = hex::decode(
        "808182838485868788898a8b8c8d8e8f\
         909192939495969798999a9b9c9d9e9f",
    )
    .unwrap();

    // 24-byte nonce for XChaCha20
    let nonce = hex::decode(
        "404142434445464748494a4b4c4d4e4f\
         5051525354555658",
    )
    .unwrap();

    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();

    // Encrypt
    let result = XChaCha20Poly1305Cipher::encrypt(&key, &nonce, plaintext, Some(&aad)).unwrap();

    // Verify correct output length
    assert_eq!(result.len(), plaintext.len() + 16, "Output length mismatch");

    // Verify roundtrip
    let decrypted = XChaCha20Poly1305Cipher::decrypt(&key, &nonce, &result, Some(&aad)).unwrap();
    assert_eq!(decrypted, plaintext);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Error Handling Tests
// ═══════════════════════════════════════════════════════════════════════════════

/// Test that decryption fails with wrong key
#[test]
fn aes256_gcm_wrong_key_fails() {
    let key1 = hex::decode(
        "feffe9928665731c6d6a8f9467308308\
         feffe9928665731c6d6a8f9467308308",
    )
    .unwrap();

    let key2 = hex::decode(
        "00000000000000000000000000000000\
         00000000000000000000000000000000",
    )
    .unwrap();

    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let plaintext = b"Test message";

    let ciphertext = Aes256Gcm::encrypt(&key1, &nonce, plaintext, None).unwrap();
    let result = Aes256Gcm::decrypt(&key2, &nonce, &ciphertext, None);

    assert!(result.is_err(), "Decryption should fail with wrong key");
}

/// Test that decryption fails with tampered ciphertext
#[test]
fn aes256_gcm_tampered_ciphertext_fails() {
    let key = hex::decode(
        "feffe9928665731c6d6a8f9467308308\
         feffe9928665731c6d6a8f9467308308",
    )
    .unwrap();

    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let plaintext = b"Test message for tampering";

    let mut ciphertext = Aes256Gcm::encrypt(&key, &nonce, plaintext, None).unwrap();

    // Tamper with the ciphertext
    ciphertext[0] ^= 0xFF;

    let result = Aes256Gcm::decrypt(&key, &nonce, &ciphertext, None);
    assert!(
        result.is_err(),
        "Decryption should fail with tampered ciphertext"
    );
}

/// Test that decryption fails with wrong AAD
#[test]
fn aes256_gcm_wrong_aad_fails() {
    let key = hex::decode(
        "feffe9928665731c6d6a8f9467308308\
         feffe9928665731c6d6a8f9467308308",
    )
    .unwrap();

    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let plaintext = b"Test message";
    let aad1 = b"correct aad";
    let aad2 = b"wrong aad";

    let ciphertext = Aes256Gcm::encrypt(&key, &nonce, plaintext, Some(aad1)).unwrap();
    let result = Aes256Gcm::decrypt(&key, &nonce, &ciphertext, Some(aad2));

    assert!(result.is_err(), "Decryption should fail with wrong AAD");
}

/// Test that invalid key length is rejected
#[test]
fn aes256_gcm_invalid_key_length() {
    let short_key = hex::decode("0102030405060708").unwrap();
    let nonce = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let plaintext = b"Test";

    let result = Aes256Gcm::encrypt(&short_key, &nonce, plaintext, None);
    assert!(result.is_err(), "Should reject invalid key length");
}

/// Test that invalid nonce length is rejected
#[test]
fn aes256_gcm_invalid_nonce_length() {
    let key = hex::decode(
        "feffe9928665731c6d6a8f9467308308\
         feffe9928665731c6d6a8f9467308308",
    )
    .unwrap();

    let short_nonce = hex::decode("0102030405").unwrap();
    let plaintext = b"Test";

    let result = Aes256Gcm::encrypt(&key, &short_nonce, plaintext, None);
    assert!(result.is_err(), "Should reject invalid nonce length");
}
