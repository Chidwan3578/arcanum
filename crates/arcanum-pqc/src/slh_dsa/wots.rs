//! WOTS+ (Winternitz One-Time Signature Plus)
//!
//! FIPS 205 Section 5 defines the WOTS+ one-time signature scheme.
//! WOTS+ is the fundamental building block for the Merkle tree leaves.
//!
//! Key properties:
//! - One-time use only (security degrades with reuse)
//! - Signature size: len * n bytes (where len = len1 + len2)
//! - Public key: n bytes (compressed via T_l)

#![allow(dead_code)]

use super::address::{Address, AddressType};
use super::hash::SlhDsaHash;
use super::params::SlhDsaParams;
use core::marker::PhantomData;
use std::vec::Vec;

/// WOTS+ signature
#[derive(Clone)]
pub struct WotsSignature<P: SlhDsaParams> {
    /// Signature data: len * n bytes
    data: Vec<u8>,
    _params: PhantomData<P>,
}

impl<P: SlhDsaParams> WotsSignature<P> {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let expected_len = P::WOTS_LEN * P::N;
        if bytes.len() != expected_len {
            return None;
        }
        Some(Self {
            data: bytes.to_vec(),
            _params: PhantomData,
        })
    }

    /// Get raw signature bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the i-th chain value (n bytes)
    pub fn chain_value(&self, i: usize) -> Option<&[u8]> {
        if i >= P::WOTS_LEN {
            return None;
        }
        let start = i * P::N;
        let end = start + P::N;
        Some(&self.data[start..end])
    }
}

/// WOTS+ implementation
pub struct Wots<P: SlhDsaParams, H: SlhDsaHash<P>> {
    _params: PhantomData<P>,
    _hash: PhantomData<H>,
}

impl<P: SlhDsaParams, H: SlhDsaHash<P>> Wots<P, H> {
    /// Compute base-w representation of a message
    ///
    /// Converts a byte array to base-w digits for WOTS+ chain selection.
    /// FIPS 205 Algorithm 1: base_2b
    ///
    /// # Arguments
    /// * `x` - Input bytes
    /// * `out_len` - Number of base-w digits to produce
    ///
    /// # Returns
    /// Vector of base-w digits (each in range 0..w)
    pub fn base_w(x: &[u8], out_len: usize) -> Vec<u32> {
        let w = P::W as u32;
        let log_w = match w {
            4 => 2,
            16 => 4,
            256 => 8,
            _ => panic!("Invalid Winternitz parameter"),
        };

        let mut result = Vec::with_capacity(out_len);
        let mut total = 0u32;
        let mut bits = 0u32;
        let mut byte_idx = 0;

        for _ in 0..out_len {
            // Load more bits if needed
            while bits < log_w && byte_idx < x.len() {
                total = (total << 8) | (x[byte_idx] as u32);
                bits += 8;
                byte_idx += 1;
            }

            // Extract log_w bits
            bits -= log_w;
            let digit = (total >> bits) & (w - 1);
            result.push(digit);
        }

        result
    }

    /// Compute checksum for WOTS+ message
    ///
    /// FIPS 205 Algorithm 2
    ///
    /// # Arguments
    /// * `msg_digits` - Base-w representation of message (len1 digits)
    ///
    /// # Returns
    /// Checksum as base-w digits (len2 digits)
    pub fn checksum(msg_digits: &[u32]) -> Vec<u32> {
        let w = P::W as u32;
        let len1 = P::N * 8 / 4; // For w=16, log_w=4

        // Compute sum of (w-1) - msg[i]
        let mut csum: u32 = 0;
        for &digit in msg_digits.iter().take(len1) {
            csum += (w - 1) - digit;
        }

        // Convert checksum to base-w
        // csum is at most len1 * (w-1), which fits in ceil(len1 * log_w / log_w) = len2 digits
        let len2 = 3; // For standard FIPS 205 parameters

        // Shift checksum left by (8 - ((len2 * log_w) % 8)) % 8
        let log_w = 4u32; // For w=16
        let total_bits = len2 * log_w as usize;
        let shift = (8 - (total_bits % 8)) % 8;
        csum <<= shift;

        // Convert to bytes then to base-w
        let csum_bytes = csum.to_be_bytes();
        Self::base_w(&csum_bytes[4 - (total_bits + 7) / 8..], len2)
    }

    /// WOTS+ chain function
    ///
    /// FIPS 205 Algorithm 3: Iteratively applies F function
    ///
    /// # Arguments
    /// * `x` - Starting value (n bytes)
    /// * `start` - Starting index in chain
    /// * `steps` - Number of iterations
    /// * `pk_seed` - Public seed
    /// * `adrs` - Address (will be modified)
    ///
    /// # Returns
    /// Final chain value (n bytes)
    pub fn chain(x: &[u8], start: u32, steps: u32, pk_seed: &[u8], adrs: &mut Address) -> Vec<u8> {
        if steps == 0 {
            return x.to_vec();
        }

        let mut result = x.to_vec();

        for i in start..(start + steps) {
            adrs.set_hash_address(i);
            result = H::f(pk_seed, adrs, &result);
        }

        result
    }

    /// Generate WOTS+ public key from secret seed
    ///
    /// FIPS 205 Algorithm 4: wots_PKgen
    ///
    /// # Arguments
    /// * `sk_seed` - Secret seed
    /// * `pk_seed` - Public seed
    /// * `adrs` - Address (must have type set appropriately)
    ///
    /// # Returns
    /// WOTS+ public key (n bytes, compressed)
    pub fn keygen(sk_seed: &[u8], pk_seed: &[u8], adrs: &Address) -> Vec<u8> {
        // Preserve keypair address before type change clears it
        let keypair = adrs.keypair_address();

        let mut sk_adrs = *adrs;
        sk_adrs.set_type(AddressType::WotsPrf);
        sk_adrs.set_keypair_address(keypair);

        let mut wots_pk_adrs = *adrs;
        wots_pk_adrs.set_type(AddressType::WotsPk);
        wots_pk_adrs.set_keypair_address(keypair);

        let mut tmp = Vec::with_capacity(P::WOTS_LEN * P::N);

        for i in 0..P::WOTS_LEN {
            sk_adrs.set_chain_address(i as u32);

            // Generate secret key element
            let sk_i = H::prf(pk_seed, sk_seed, &sk_adrs);

            // Chain to get public key element
            let mut chain_adrs = *adrs;
            chain_adrs.set_type(AddressType::WotsHash);
            chain_adrs.set_keypair_address(keypair);
            chain_adrs.set_chain_address(i as u32);

            let pk_i = Self::chain(&sk_i, 0, (P::W - 1) as u32, pk_seed, &mut chain_adrs);
            tmp.extend_from_slice(&pk_i);
        }

        // Compress public key
        H::t_l(pk_seed, &wots_pk_adrs, &tmp)
    }

    /// Generate WOTS+ signature
    ///
    /// FIPS 205 Algorithm 5: wots_sign
    ///
    /// # Arguments
    /// * `msg` - Message hash (n bytes)
    /// * `sk_seed` - Secret seed
    /// * `pk_seed` - Public seed
    /// * `adrs` - Address
    ///
    /// # Returns
    /// WOTS+ signature
    pub fn sign(msg: &[u8], sk_seed: &[u8], pk_seed: &[u8], adrs: &Address) -> WotsSignature<P> {
        // Preserve keypair address before type change clears it
        let keypair = adrs.keypair_address();

        // Convert message to base-w
        let len1 = P::N * 8 / 4; // For w=16
        let msg_digits = Self::base_w(msg, len1);

        // Compute and append checksum
        let csum_digits = Self::checksum(&msg_digits);

        let mut all_digits = msg_digits;
        all_digits.extend(csum_digits);

        // Generate signature
        let mut sk_adrs = *adrs;
        sk_adrs.set_type(AddressType::WotsPrf);
        sk_adrs.set_keypair_address(keypair);

        let mut sig_data = Vec::with_capacity(P::WOTS_LEN * P::N);

        for (i, &digit) in all_digits.iter().enumerate() {
            sk_adrs.set_chain_address(i as u32);
            let sk_i = H::prf(pk_seed, sk_seed, &sk_adrs);

            let mut chain_adrs = *adrs;
            chain_adrs.set_type(AddressType::WotsHash);
            chain_adrs.set_keypair_address(keypair);
            chain_adrs.set_chain_address(i as u32);

            let sig_i = Self::chain(&sk_i, 0, digit, pk_seed, &mut chain_adrs);
            sig_data.extend_from_slice(&sig_i);
        }

        WotsSignature {
            data: sig_data,
            _params: PhantomData,
        }
    }

    /// Compute WOTS+ public key from signature
    ///
    /// FIPS 205 Algorithm 6: wots_PKFromSig
    ///
    /// # Arguments
    /// * `sig` - WOTS+ signature
    /// * `msg` - Message hash (n bytes)
    /// * `pk_seed` - Public seed
    /// * `adrs` - Address
    ///
    /// # Returns
    /// Computed public key (n bytes)
    pub fn pk_from_sig(
        sig: &WotsSignature<P>,
        msg: &[u8],
        pk_seed: &[u8],
        adrs: &Address,
    ) -> Vec<u8> {
        // Preserve keypair address before type change clears it
        let keypair = adrs.keypair_address();

        // Convert message to base-w
        let len1 = P::N * 8 / 4;
        let msg_digits = Self::base_w(msg, len1);

        // Compute and append checksum
        let csum_digits = Self::checksum(&msg_digits);

        let mut all_digits = msg_digits;
        all_digits.extend(csum_digits);

        // Compute public key from signature
        let mut wots_pk_adrs = *adrs;
        wots_pk_adrs.set_type(AddressType::WotsPk);
        wots_pk_adrs.set_keypair_address(keypair);

        let mut tmp = Vec::with_capacity(P::WOTS_LEN * P::N);

        for (i, &digit) in all_digits.iter().enumerate() {
            let sig_i = sig.chain_value(i).expect("Invalid signature length");

            let mut chain_adrs = *adrs;
            chain_adrs.set_type(AddressType::WotsHash);
            chain_adrs.set_keypair_address(keypair);
            chain_adrs.set_chain_address(i as u32);

            // Chain from signature value to public key value
            let steps = (P::W - 1) as u32 - digit;
            let pk_i = Self::chain(sig_i, digit, steps, pk_seed, &mut chain_adrs);
            tmp.extend_from_slice(&pk_i);
        }

        // Compress to get public key
        H::t_l(pk_seed, &wots_pk_adrs, &tmp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::hash::Sha2Hash;
    use crate::slh_dsa::params::Sha2_128f;

    type TestWots = Wots<Sha2_128f, Sha2Hash<Sha2_128f>>;

    // ========================================================================
    // Base-W Conversion Tests
    // ========================================================================

    #[test]
    fn test_base_w_zero_input() {
        let input = [0u8; 4];
        let digits = TestWots::base_w(&input, 8);
        assert_eq!(digits.len(), 8);
        assert!(digits.iter().all(|&d| d == 0));
    }

    #[test]
    fn test_base_w_all_ones() {
        let input = [0xFF, 0xFF];
        let digits = TestWots::base_w(&input, 4);
        // 0xFFFF in base-16 = [15, 15, 15, 15]
        assert_eq!(digits, vec![15, 15, 15, 15]);
    }

    #[test]
    fn test_base_w_mixed() {
        let input = [0x12, 0x34];
        let digits = TestWots::base_w(&input, 4);
        // 0x1234 in base-16 = [1, 2, 3, 4]
        assert_eq!(digits, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_base_w_output_length() {
        let input = [0xAB; 16];
        let digits = TestWots::base_w(&input, 32);
        assert_eq!(digits.len(), 32);
    }

    // ========================================================================
    // Checksum Tests
    // ========================================================================

    #[test]
    fn test_checksum_zero_message() {
        // All zeros means max checksum (all (w-1) values)
        let msg_digits = vec![0u32; 32]; // len1 = 32 for n=16, w=16
        let csum = TestWots::checksum(&msg_digits);
        assert_eq!(csum.len(), 3); // len2 = 3

        // Sum should be 32 * 15 = 480
        // Verify checksum digits reconstruct to this
    }

    #[test]
    fn test_checksum_max_message() {
        // All 15s means zero checksum
        let msg_digits = vec![15u32; 32];
        let csum = TestWots::checksum(&msg_digits);
        assert_eq!(csum.len(), 3);
        // Checksum should be 0
        assert!(csum.iter().all(|&d| d == 0));
    }

    // ========================================================================
    // WOTS+ Signature Tests (will fail until hash is implemented)
    // ========================================================================

    #[test]
    fn test_wots_keygen_output_size() {
        let sk_seed = [0u8; 16];
        let pk_seed = [1u8; 16];
        let adrs = Address::wots_hash(0, 0, 0, 0, 0);

        let pk = TestWots::keygen(&sk_seed, &pk_seed, &adrs);
        assert_eq!(pk.len(), Sha2_128f::N);
    }

    #[test]
    fn test_wots_sign_output_size() {
        let msg = [0u8; 16];
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::wots_hash(0, 0, 0, 0, 0);

        let sig = TestWots::sign(&msg, &sk_seed, &pk_seed, &adrs);
        assert_eq!(sig.as_bytes().len(), Sha2_128f::WOTS_LEN * Sha2_128f::N);
    }

    #[test]
    fn test_wots_sign_verify_roundtrip() {
        let msg = [42u8; 16];
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::wots_hash(0, 0, 5, 0, 0);

        // Generate public key
        let pk = TestWots::keygen(&sk_seed, &pk_seed, &adrs);

        // Sign message
        let sig = TestWots::sign(&msg, &sk_seed, &pk_seed, &adrs);

        // Verify: pk_from_sig should return the same public key
        let computed_pk = TestWots::pk_from_sig(&sig, &msg, &pk_seed, &adrs);

        assert_eq!(pk, computed_pk);
    }

    #[test]
    fn test_wots_wrong_message_fails() {
        let msg1 = [1u8; 16];
        let msg2 = [2u8; 16];
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::wots_hash(0, 0, 0, 0, 0);

        // Generate public key
        let pk = TestWots::keygen(&sk_seed, &pk_seed, &adrs);

        // Sign msg1
        let sig = TestWots::sign(&msg1, &sk_seed, &pk_seed, &adrs);

        // Try to verify with msg2 - should produce different public key
        let computed_pk = TestWots::pk_from_sig(&sig, &msg2, &pk_seed, &adrs);

        assert_ne!(pk, computed_pk);
    }

    #[test]
    fn test_wots_different_keypairs_different_keys() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];

        let adrs1 = Address::wots_hash(0, 0, 0, 0, 0);
        let adrs2 = Address::wots_hash(0, 0, 1, 0, 0);

        let pk1 = TestWots::keygen(&sk_seed, &pk_seed, &adrs1);
        let pk2 = TestWots::keygen(&sk_seed, &pk_seed, &adrs2);

        assert_ne!(pk1, pk2);
    }

    // ========================================================================
    // Chain Function Tests
    // ========================================================================

    #[test]
    fn test_chain_zero_steps_returns_input() {
        let x = vec![42u8; 16];
        let pk_seed = [0u8; 16];
        let mut adrs = Address::wots_hash(0, 0, 0, 0, 0);

        let result = TestWots::chain(&x, 0, 0, &pk_seed, &mut adrs);
        assert_eq!(result, x);
    }

    #[test]
    fn test_chain_deterministic() {
        let x = vec![1u8; 16];
        let pk_seed = [2u8; 16];
        let mut adrs1 = Address::wots_hash(0, 0, 0, 5, 0);
        let mut adrs2 = Address::wots_hash(0, 0, 0, 5, 0);

        let result1 = TestWots::chain(&x, 0, 3, &pk_seed, &mut adrs1);
        let result2 = TestWots::chain(&x, 0, 3, &pk_seed, &mut adrs2);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_chain_composition() {
        // chain(x, 0, a+b) == chain(chain(x, 0, a), a, b)
        let x = vec![1u8; 16];
        let pk_seed = [2u8; 16];

        let mut adrs1 = Address::wots_hash(0, 0, 0, 0, 0);
        let direct = TestWots::chain(&x, 0, 5, &pk_seed, &mut adrs1);

        let mut adrs2 = Address::wots_hash(0, 0, 0, 0, 0);
        let step1 = TestWots::chain(&x, 0, 3, &pk_seed, &mut adrs2);
        let mut adrs3 = Address::wots_hash(0, 0, 0, 0, 0);
        let step2 = TestWots::chain(&step1, 3, 2, &pk_seed, &mut adrs3);

        assert_eq!(direct, step2);
    }
}
