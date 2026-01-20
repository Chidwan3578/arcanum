//! SLH-DSA Hash Function Abstractions
//!
//! FIPS 205 Section 10 defines the hash functions used in SLH-DSA.
//! This module provides implementations for SHA-256 based variants.
//!
//! Hash functions:
//! - H_msg: Message hash (variable output length via MGF1)
//! - PRF: Pseudorandom function for key generation
//! - PRF_msg: Message randomness generation (HMAC-based)
//! - F: Chaining function for WOTS+
//! - H: Tree hash (two n-byte inputs to n-byte output)
//! - T_l: WOTS+ public key compression

#![allow(dead_code)]

use super::address::Address;
use super::params::SlhDsaParams;
use alloc::vec::Vec;
use arcanum_primitives::sha2::Sha256;
use core::marker::PhantomData;

/// Hash function trait for SLH-DSA
///
/// This trait abstracts over SHA-256 and SHAKE256 based variants.
pub trait SlhDsaHash<P: SlhDsaParams> {
    /// H_msg: Hash message to get FORS indices and tree index
    ///
    /// Inputs:
    /// - r: Randomness (n bytes)
    /// - pk_seed: Public seed (n bytes)
    /// - pk_root: Root of the top tree (n bytes)
    /// - m: Message (arbitrary length)
    ///
    /// Output: Variable length for FORS message indices
    fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8], out_len: usize) -> Vec<u8>;

    /// PRF: Pseudorandom function for secret key generation
    ///
    /// Inputs:
    /// - pk_seed: Public seed (n bytes)
    /// - sk_seed: Secret seed (n bytes)
    /// - adrs: Address (32 bytes)
    ///
    /// Output: n bytes
    fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Address) -> Vec<u8>;

    /// PRF_msg: Generate message randomness
    ///
    /// Inputs:
    /// - sk_prf: Secret PRF key (n bytes)
    /// - opt_rand: Optional randomness (n bytes, or pk_seed for deterministic)
    /// - m: Message (arbitrary length)
    ///
    /// Output: n bytes
    fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8>;

    /// F: Chaining function for WOTS+
    ///
    /// Inputs:
    /// - pk_seed: Public seed (n bytes)
    /// - adrs: Address (32 bytes)
    /// - m: Input (n bytes)
    ///
    /// Output: n bytes
    fn f(pk_seed: &[u8], adrs: &Address, m: &[u8]) -> Vec<u8>;

    /// H: Tree hash function
    ///
    /// Inputs:
    /// - pk_seed: Public seed (n bytes)
    /// - adrs: Address (32 bytes)
    /// - m1: Left child (n bytes)
    /// - m2: Right child (n bytes)
    ///
    /// Output: n bytes
    fn h(pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]) -> Vec<u8>;

    /// T_l: WOTS+ public key compression
    ///
    /// Inputs:
    /// - pk_seed: Public seed (n bytes)
    /// - adrs: Address (32 bytes)
    /// - m: Concatenated WOTS+ chain endpoints (len * n bytes)
    ///
    /// Output: n bytes
    fn t_l(pk_seed: &[u8], adrs: &Address, m: &[u8]) -> Vec<u8>;
}

// ============================================================================
// SHA-256 Based Implementation (FIPS 205 Section 10.1)
// ============================================================================

/// SHA-256 based hash functions for SLH-DSA
///
/// Implements FIPS 205 Section 10.1 instantiation.
pub struct Sha2Hash<P: SlhDsaParams> {
    _params: PhantomData<P>,
}

impl<P: SlhDsaParams> Sha2Hash<P> {
    /// MGF1 with SHA-256 (RFC 8017 Appendix B.2.1)
    ///
    /// Mask generation function used for H_msg.
    fn mgf1_sha256(seed: &[u8], length: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(length);
        let mut counter: u32 = 0;

        while output.len() < length {
            // Hash seed || counter
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(&counter.to_be_bytes());
            let hash = hasher.finalize();

            let remaining = length - output.len();
            let to_copy = remaining.min(32);
            output.extend_from_slice(&hash[..to_copy]);

            counter += 1;
        }

        output.truncate(length);
        output
    }

    /// HMAC-SHA-256 implementation for PRF_msg
    ///
    /// RFC 2104 compliant HMAC using native SHA-256.
    fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        const BLOCK_SIZE: usize = 64;
        const IPAD: u8 = 0x36;
        const OPAD: u8 = 0x5c;

        // Step 1: Prepare key (hash if longer than block size, pad if shorter)
        let mut k = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            let h = Sha256::hash(key);
            k[..32].copy_from_slice(&h);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        // Step 2: XOR key with ipad
        let mut k_ipad = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            k_ipad[i] = k[i] ^ IPAD;
        }

        // Step 3: XOR key with opad
        let mut k_opad = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            k_opad[i] = k[i] ^ OPAD;
        }

        // Step 4: Inner hash: H(k_ipad || data)
        let mut inner_hasher = Sha256::new();
        inner_hasher.update(&k_ipad);
        inner_hasher.update(data);
        let inner_hash = inner_hasher.finalize();

        // Step 5: Outer hash: H(k_opad || inner_hash)
        let mut outer_hasher = Sha256::new();
        outer_hasher.update(&k_opad);
        outer_hasher.update(&inner_hash);
        outer_hasher.finalize()
    }

    /// Truncate hash output to n bytes
    #[inline]
    fn truncate(hash: &[u8; 32]) -> Vec<u8> {
        hash[..P::N].to_vec()
    }
}

impl<P: SlhDsaParams> SlhDsaHash<P> for Sha2Hash<P> {
    /// H_msg: Hash message for FORS indices
    ///
    /// FIPS 205 Section 10.1:
    /// H_msg(R, PK.seed, PK.root, M) = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M), m)
    fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8], out_len: usize) -> Vec<u8> {
        // First compute inner hash: SHA-256(R || PK.seed || PK.root || M)
        let mut inner_hasher = Sha256::new();
        inner_hasher.update(r);
        inner_hasher.update(pk_seed);
        inner_hasher.update(pk_root);
        inner_hasher.update(m);
        let inner_hash = inner_hasher.finalize();

        // MGF1 seed: R || PK.seed || inner_hash
        let mut mgf_seed = Vec::with_capacity(r.len() + pk_seed.len() + 32);
        mgf_seed.extend_from_slice(r);
        mgf_seed.extend_from_slice(pk_seed);
        mgf_seed.extend_from_slice(&inner_hash);

        // Generate output via MGF1
        Self::mgf1_sha256(&mgf_seed, out_len)
    }

    /// PRF: Pseudorandom function
    ///
    /// FIPS 205 Section 10.1:
    /// n=16: PRF(PK.seed, SK.seed, ADRS) = Trunc_n(SHA-256(PK.seed || ADRSc || SK.seed))
    /// n>16: PRF(PK.seed, SK.seed, ADRS) = Trunc_n(SHA-256(PK.seed || toByte(0,64-n) || ADRSc || SK.seed))
    fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Address) -> Vec<u8> {
        let adrs_c = adrs.to_compressed();
        let mut hasher = Sha256::new();
        hasher.update(pk_seed);
        // Add padding for n > 16
        if P::N > 16 {
            let padding = [0u8; 64];
            hasher.update(&padding[..(64 - P::N)]);
        }
        hasher.update(&adrs_c);
        hasher.update(sk_seed);
        let hash = hasher.finalize();
        Self::truncate(&hash)
    }

    /// PRF_msg: Message randomness generation
    ///
    /// FIPS 205 Section 10.1:
    /// PRF_msg(SK.prf, opt_rand, M) = Trunc_n(HMAC-SHA-256(SK.prf, opt_rand || M))
    fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8> {
        // Concatenate opt_rand || M
        let mut data = Vec::with_capacity(opt_rand.len() + m.len());
        data.extend_from_slice(opt_rand);
        data.extend_from_slice(m);

        // HMAC-SHA-256
        let mac = Self::hmac_sha256(sk_prf, &data);
        mac[..P::N].to_vec()
    }

    /// F: Chaining function for WOTS+
    ///
    /// FIPS 205 Section 10.1:
    /// n=16: F(PK.seed, ADRS, M₁) = Trunc_n(SHA-256(PK.seed || ADRSc || M₁))
    /// n>16: F(PK.seed, ADRS, M₁) = Trunc_n(SHA-256(PK.seed || toByte(0,64-n) || ADRSc || M₁))
    fn f(pk_seed: &[u8], adrs: &Address, m: &[u8]) -> Vec<u8> {
        let adrs_c = adrs.to_compressed();
        let mut hasher = Sha256::new();
        hasher.update(pk_seed);
        if P::N > 16 {
            let padding = [0u8; 64];
            hasher.update(&padding[..(64 - P::N)]);
        }
        hasher.update(&adrs_c);
        hasher.update(m);
        let hash = hasher.finalize();
        Self::truncate(&hash)
    }

    /// H: Tree hash function
    ///
    /// FIPS 205 Section 10.1:
    /// n=16: H(PK.seed, ADRS, M₁ || M₂) = Trunc_n(SHA-256(PK.seed || ADRSc || M₁ || M₂))
    /// n>16: H(PK.seed, ADRS, M₁ || M₂) = Trunc_n(SHA-256(PK.seed || toByte(0,64-n) || ADRSc || M₁ || M₂))
    fn h(pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]) -> Vec<u8> {
        let adrs_c = adrs.to_compressed();
        let mut hasher = Sha256::new();
        hasher.update(pk_seed);
        if P::N > 16 {
            let padding = [0u8; 64];
            hasher.update(&padding[..(64 - P::N)]);
        }
        hasher.update(&adrs_c);
        hasher.update(m1);
        hasher.update(m2);
        let hash = hasher.finalize();
        Self::truncate(&hash)
    }

    /// T_l: WOTS+ public key compression
    ///
    /// FIPS 205 Section 10.1:
    /// n=16: T_l(PK.seed, ADRS, M) = Trunc_n(SHA-256(PK.seed || ADRSc || M))
    /// n>16: T_l(PK.seed, ADRS, M) = Trunc_n(SHA-256(PK.seed || toByte(0,64-n) || ADRSc || M))
    fn t_l(pk_seed: &[u8], adrs: &Address, m: &[u8]) -> Vec<u8> {
        let adrs_c = adrs.to_compressed();
        let mut hasher = Sha256::new();
        hasher.update(pk_seed);
        if P::N > 16 {
            let padding = [0u8; 64];
            hasher.update(&padding[..(64 - P::N)]);
        }
        hasher.update(&adrs_c);
        hasher.update(m);
        let hash = hasher.finalize();
        Self::truncate(&hash)
    }
}

// ============================================================================
// SHAKE256 Based Implementation (FIPS 205 Section 10.2) - Phase 2
// ============================================================================

/// SHAKE256 based hash functions for SLH-DSA (Phase 2)
pub struct ShakeHash<P: SlhDsaParams> {
    _params: PhantomData<P>,
}

impl<P: SlhDsaParams> SlhDsaHash<P> for ShakeHash<P> {
    fn h_msg(r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8], out_len: usize) -> Vec<u8> {
        let _ = (r, pk_seed, pk_root, m, out_len);
        unimplemented!("SHAKE H_msg not yet implemented - requires SHAKE256 in arcanum-primitives")
    }

    fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Address) -> Vec<u8> {
        let _ = (pk_seed, sk_seed, adrs);
        unimplemented!("SHAKE PRF not yet implemented")
    }

    fn prf_msg(sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8> {
        let _ = (sk_prf, opt_rand, m);
        unimplemented!("SHAKE PRF_msg not yet implemented")
    }

    fn f(pk_seed: &[u8], adrs: &Address, m: &[u8]) -> Vec<u8> {
        let _ = (pk_seed, adrs, m);
        unimplemented!("SHAKE F not yet implemented")
    }

    fn h(pk_seed: &[u8], adrs: &Address, m1: &[u8], m2: &[u8]) -> Vec<u8> {
        let _ = (pk_seed, adrs, m1, m2);
        unimplemented!("SHAKE H not yet implemented")
    }

    fn t_l(pk_seed: &[u8], adrs: &Address, m: &[u8]) -> Vec<u8> {
        let _ = (pk_seed, adrs, m);
        unimplemented!("SHAKE T_l not yet implemented")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::params::Sha2_128f;

    // ========================================================================
    // PRF Tests
    // ========================================================================

    #[test]
    fn test_prf_returns_n_bytes() {
        let pk_seed = [0u8; 16];
        let sk_seed = [1u8; 16];
        let adrs = Address::new();

        let result = Sha2Hash::<Sha2_128f>::prf(&pk_seed, &sk_seed, &adrs);
        assert_eq!(result.len(), Sha2_128f::N);
    }

    #[test]
    fn test_prf_is_deterministic() {
        let pk_seed = [0u8; 16];
        let sk_seed = [1u8; 16];
        let adrs = Address::wots_hash(0, 0, 0, 0, 0);

        let result1 = Sha2Hash::<Sha2_128f>::prf(&pk_seed, &sk_seed, &adrs);
        let result2 = Sha2Hash::<Sha2_128f>::prf(&pk_seed, &sk_seed, &adrs);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_prf_different_address_different_output() {
        let pk_seed = [0u8; 16];
        let sk_seed = [1u8; 16];
        let adrs1 = Address::wots_hash(0, 0, 0, 0, 0);
        let adrs2 = Address::wots_hash(0, 0, 0, 0, 1);

        let result1 = Sha2Hash::<Sha2_128f>::prf(&pk_seed, &sk_seed, &adrs1);
        let result2 = Sha2Hash::<Sha2_128f>::prf(&pk_seed, &sk_seed, &adrs2);
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_prf_different_seed_different_output() {
        let pk_seed = [0u8; 16];
        let sk_seed1 = [1u8; 16];
        let sk_seed2 = [2u8; 16];
        let adrs = Address::new();

        let result1 = Sha2Hash::<Sha2_128f>::prf(&pk_seed, &sk_seed1, &adrs);
        let result2 = Sha2Hash::<Sha2_128f>::prf(&pk_seed, &sk_seed2, &adrs);
        assert_ne!(result1, result2);
    }

    // ========================================================================
    // PRF_msg Tests
    // ========================================================================

    #[test]
    fn test_prf_msg_returns_n_bytes() {
        let sk_prf = [0u8; 16];
        let opt_rand = [1u8; 16];
        let message = b"test message";

        let result = Sha2Hash::<Sha2_128f>::prf_msg(&sk_prf, &opt_rand, message);
        assert_eq!(result.len(), Sha2_128f::N);
    }

    #[test]
    fn test_prf_msg_deterministic() {
        let sk_prf = [0u8; 16];
        let opt_rand = [1u8; 16];
        let message = b"test message";

        let result1 = Sha2Hash::<Sha2_128f>::prf_msg(&sk_prf, &opt_rand, message);
        let result2 = Sha2Hash::<Sha2_128f>::prf_msg(&sk_prf, &opt_rand, message);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_prf_msg_different_message_different_output() {
        let sk_prf = [0u8; 16];
        let opt_rand = [1u8; 16];

        let result1 = Sha2Hash::<Sha2_128f>::prf_msg(&sk_prf, &opt_rand, b"message 1");
        let result2 = Sha2Hash::<Sha2_128f>::prf_msg(&sk_prf, &opt_rand, b"message 2");
        assert_ne!(result1, result2);
    }

    // ========================================================================
    // F Function Tests
    // ========================================================================

    #[test]
    fn test_f_returns_n_bytes() {
        let pk_seed = [0u8; 16];
        let adrs = Address::new();
        let m = [2u8; 16];

        let result = Sha2Hash::<Sha2_128f>::f(&pk_seed, &adrs, &m);
        assert_eq!(result.len(), Sha2_128f::N);
    }

    #[test]
    fn test_f_deterministic() {
        let pk_seed = [0u8; 16];
        let adrs = Address::wots_hash(0, 0, 0, 5, 0);
        let m = [2u8; 16];

        let result1 = Sha2Hash::<Sha2_128f>::f(&pk_seed, &adrs, &m);
        let result2 = Sha2Hash::<Sha2_128f>::f(&pk_seed, &adrs, &m);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_f_different_input_different_output() {
        let pk_seed = [0u8; 16];
        let adrs = Address::new();
        let m1 = [1u8; 16];
        let m2 = [2u8; 16];

        let result1 = Sha2Hash::<Sha2_128f>::f(&pk_seed, &adrs, &m1);
        let result2 = Sha2Hash::<Sha2_128f>::f(&pk_seed, &adrs, &m2);
        assert_ne!(result1, result2);
    }

    // ========================================================================
    // H Function Tests
    // ========================================================================

    #[test]
    fn test_h_returns_n_bytes() {
        let pk_seed = [0u8; 16];
        let adrs = Address::new();
        let m1 = [1u8; 16];
        let m2 = [2u8; 16];

        let result = Sha2Hash::<Sha2_128f>::h(&pk_seed, &adrs, &m1, &m2);
        assert_eq!(result.len(), Sha2_128f::N);
    }

    #[test]
    fn test_h_not_commutative() {
        let pk_seed = [0u8; 16];
        let adrs = Address::tree(0, 0, 1, 0);
        let m1 = [1u8; 16];
        let m2 = [2u8; 16];

        let result1 = Sha2Hash::<Sha2_128f>::h(&pk_seed, &adrs, &m1, &m2);
        let result2 = Sha2Hash::<Sha2_128f>::h(&pk_seed, &adrs, &m2, &m1);
        assert_ne!(result1, result2);
    }

    // ========================================================================
    // T_l Function Tests
    // ========================================================================

    #[test]
    fn test_t_l_returns_n_bytes() {
        let pk_seed = [0u8; 16];
        let adrs = Address::wots_pk(0, 0, 0);
        let m = vec![0u8; 35 * 16]; // WOTS_LEN * N for Sha2_128f

        let result = Sha2Hash::<Sha2_128f>::t_l(&pk_seed, &adrs, &m);
        assert_eq!(result.len(), Sha2_128f::N);
    }

    // ========================================================================
    // H_msg Function Tests
    // ========================================================================

    #[test]
    fn test_h_msg_returns_requested_length() {
        let r = [0u8; 16];
        let pk_seed = [1u8; 16];
        let pk_root = [2u8; 16];
        let m = b"test message";

        let result = Sha2Hash::<Sha2_128f>::h_msg(&r, &pk_seed, &pk_root, m, 50);
        assert_eq!(result.len(), 50);
    }

    #[test]
    fn test_h_msg_deterministic() {
        let r = [0u8; 16];
        let pk_seed = [1u8; 16];
        let pk_root = [2u8; 16];
        let m = b"test message";

        let result1 = Sha2Hash::<Sha2_128f>::h_msg(&r, &pk_seed, &pk_root, m, 32);
        let result2 = Sha2Hash::<Sha2_128f>::h_msg(&r, &pk_seed, &pk_root, m, 32);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_h_msg_different_r_different_output() {
        let r1 = [0u8; 16];
        let r2 = [1u8; 16];
        let pk_seed = [1u8; 16];
        let pk_root = [2u8; 16];
        let m = b"test message";

        let result1 = Sha2Hash::<Sha2_128f>::h_msg(&r1, &pk_seed, &pk_root, m, 32);
        let result2 = Sha2Hash::<Sha2_128f>::h_msg(&r2, &pk_seed, &pk_root, m, 32);
        assert_ne!(result1, result2);
    }

    // ========================================================================
    // HMAC Tests
    // ========================================================================

    #[test]
    fn test_hmac_sha256_known_vector() {
        // RFC 4231 Test Case 1
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];

        let result = Sha2Hash::<Sha2_128f>::hmac_sha256(&key, data);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_mgf1_output_length() {
        let seed = b"test seed";

        let out1 = Sha2Hash::<Sha2_128f>::mgf1_sha256(seed, 10);
        assert_eq!(out1.len(), 10);

        let out2 = Sha2Hash::<Sha2_128f>::mgf1_sha256(seed, 100);
        assert_eq!(out2.len(), 100);

        let out3 = Sha2Hash::<Sha2_128f>::mgf1_sha256(seed, 0);
        assert_eq!(out3.len(), 0);
    }

    #[test]
    fn test_mgf1_deterministic() {
        let seed = b"test seed";

        let out1 = Sha2Hash::<Sha2_128f>::mgf1_sha256(seed, 64);
        let out2 = Sha2Hash::<Sha2_128f>::mgf1_sha256(seed, 64);
        assert_eq!(out1, out2);
    }
}
