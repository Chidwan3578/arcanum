//! Hypertree Signature
//!
//! FIPS 205 Section 8 defines the hypertree, a tree of XMSS trees with d layers.
//! The hypertree is used to sign the FORS public key during SLH-DSA signing.
//!
//! Structure:
//! - d layers of XMSS trees
//! - Each XMSS tree has 2^h' leaves
//! - Total height H = d * h'
//! - Tree addresses identify position in the hypertree

#![allow(dead_code)]

use super::address::Address;
use super::hash::SlhDsaHash;
use super::params::SlhDsaParams;
use super::xmss::{Xmss, XmssSignature};
use core::marker::PhantomData;
use std::vec::Vec;
use subtle::ConstantTimeEq;

/// Hypertree signature containing d XMSS signatures
#[derive(Clone)]
pub struct HypertreeSignature<P: SlhDsaParams> {
    /// d XMSS signatures, one per layer
    xmss_sigs: Vec<XmssSignature<P>>,
    _params: PhantomData<P>,
}

impl<P: SlhDsaParams> HypertreeSignature<P> {
    /// Create from XMSS signatures
    pub fn new(xmss_sigs: Vec<XmssSignature<P>>) -> Self {
        Self {
            xmss_sigs,
            _params: PhantomData,
        }
    }

    /// Get XMSS signatures
    pub fn xmss_sigs(&self) -> &[XmssSignature<P>] {
        &self.xmss_sigs
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let xmss_size = XmssSignature::<P>::size();
        let mut bytes = Vec::with_capacity(P::D * xmss_size);

        for sig in &self.xmss_sigs {
            bytes.extend_from_slice(&sig.to_bytes());
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let xmss_size = XmssSignature::<P>::size();
        if bytes.len() != P::D * xmss_size {
            return None;
        }

        let mut xmss_sigs = Vec::with_capacity(P::D);
        for i in 0..P::D {
            let start = i * xmss_size;
            let sig = XmssSignature::<P>::from_bytes(&bytes[start..start + xmss_size])?;
            xmss_sigs.push(sig);
        }

        Some(Self {
            xmss_sigs,
            _params: PhantomData,
        })
    }

    /// Get size in bytes
    pub fn size() -> usize {
        P::D * XmssSignature::<P>::size()
    }
}

/// Hypertree implementation
pub struct Hypertree<P: SlhDsaParams, H: SlhDsaHash<P>> {
    _params: PhantomData<P>,
    _hash: PhantomData<H>,
}

impl<P: SlhDsaParams, H: SlhDsaHash<P>> Hypertree<P, H> {
    /// Generate hypertree signature
    ///
    /// FIPS 205 Algorithm 14: ht_sign
    ///
    /// # Arguments
    /// * `msg` - Message to sign (n bytes, typically FORS public key)
    /// * `sk_seed` - Secret seed
    /// * `pk_seed` - Public seed
    /// * `idx_tree` - Tree index (identifies which XMSS leaf)
    /// * `idx_leaf` - Leaf index within the bottom tree
    ///
    /// # Returns
    /// Hypertree signature (d XMSS signatures)
    pub fn ht_sign(
        msg: &[u8],
        sk_seed: &[u8],
        pk_seed: &[u8],
        idx_tree: u64,
        idx_leaf: u32,
    ) -> HypertreeSignature<P> {
        let mut xmss_sigs = Vec::with_capacity(P::D);
        let mut current_msg = msg.to_vec();
        let mut tree_addr = idx_tree;
        let mut leaf_idx = idx_leaf;

        for layer in 0..P::D {
            // Set up address for this layer
            let mut adrs = Address::new();
            adrs.set_layer_address(layer as u32);
            adrs.set_tree_address(tree_addr);

            // Sign current message
            let xmss_sig = Xmss::<P, H>::xmss_sign(&current_msg, sk_seed, pk_seed, leaf_idx, &adrs);
            xmss_sigs.push(xmss_sig.clone());

            // Compute the root for the next layer's message
            current_msg = Xmss::<P, H>::xmss_root(sk_seed, pk_seed, &adrs);

            // Update indices for next layer
            // The leaf index in the next layer is derived from the current tree address
            leaf_idx = (tree_addr & ((1 << P::H_PRIME) - 1)) as u32;
            tree_addr >>= P::H_PRIME;
        }

        HypertreeSignature::new(xmss_sigs)
    }

    /// Verify hypertree signature
    ///
    /// FIPS 205 Algorithm 15: ht_verify
    ///
    /// # Arguments
    /// * `msg` - Message that was signed (n bytes)
    /// * `sig` - Hypertree signature
    /// * `pk_seed` - Public seed
    /// * `idx_tree` - Tree index
    /// * `idx_leaf` - Leaf index
    /// * `pk_root` - Expected root (from public key)
    ///
    /// # Returns
    /// True if signature is valid, false otherwise
    pub fn ht_verify(
        msg: &[u8],
        sig: &HypertreeSignature<P>,
        pk_seed: &[u8],
        idx_tree: u64,
        idx_leaf: u32,
        pk_root: &[u8],
    ) -> bool {
        let mut current_msg = msg.to_vec();
        let mut tree_addr = idx_tree;
        let mut leaf_idx = idx_leaf;

        for layer in 0..P::D {
            // Set up address for this layer
            let mut adrs = Address::new();
            adrs.set_layer_address(layer as u32);
            adrs.set_tree_address(tree_addr);

            // Compute root from this XMSS signature
            let xmss_sig = &sig.xmss_sigs[layer];
            current_msg =
                Xmss::<P, H>::xmss_pk_from_sig(leaf_idx, xmss_sig, &current_msg, pk_seed, &adrs);

            // Update indices for next layer
            leaf_idx = (tree_addr & ((1 << P::H_PRIME) - 1)) as u32;
            tree_addr >>= P::H_PRIME;
        }

        // Final computed root should match pk_root (constant-time comparison)
        bool::from(current_msg.ct_eq(pk_root))
    }

    /// Compute the hypertree root (for key generation)
    ///
    /// # Arguments
    /// * `sk_seed` - Secret seed
    /// * `pk_seed` - Public seed
    ///
    /// # Returns
    /// Root of the hypertree (n bytes)
    pub fn ht_root(sk_seed: &[u8], pk_seed: &[u8]) -> Vec<u8> {
        // The hypertree root is the root of the top XMSS tree (layer d-1, tree 0)
        let mut adrs = Address::new();
        adrs.set_layer_address((P::D - 1) as u32);
        adrs.set_tree_address(0);

        Xmss::<P, H>::xmss_root(sk_seed, pk_seed, &adrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::hash::Sha2Hash;
    use crate::slh_dsa::params::Sha2_128f;

    type TestHt = Hypertree<Sha2_128f, Sha2Hash<Sha2_128f>>;

    #[test]
    fn test_ht_root_deterministic() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];

        let root1 = TestHt::ht_root(&sk_seed, &pk_seed);
        let root2 = TestHt::ht_root(&sk_seed, &pk_seed);

        assert_eq!(root1, root2);
        assert_eq!(root1.len(), Sha2_128f::N);
    }

    #[test]
    fn test_ht_sign_verify_roundtrip() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let msg = [42u8; 16];
        let idx_tree = 0u64;
        let idx_leaf = 0u32;

        // Compute root
        let pk_root = TestHt::ht_root(&sk_seed, &pk_seed);

        // Sign
        let sig = TestHt::ht_sign(&msg, &sk_seed, &pk_seed, idx_tree, idx_leaf);

        // Verify
        let result = TestHt::ht_verify(&msg, &sig, &pk_seed, idx_tree, idx_leaf, &pk_root);
        assert!(result, "Hypertree verification failed");
    }

    #[test]
    fn test_ht_sign_verify_different_indices() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let msg = [42u8; 16];
        let pk_root = TestHt::ht_root(&sk_seed, &pk_seed);

        // Test with different tree/leaf indices
        let test_cases = [(0u64, 0u32), (0u64, 1u32), (1u64, 0u32), (0u64, 3u32)];

        for (idx_tree, idx_leaf) in test_cases {
            let sig = TestHt::ht_sign(&msg, &sk_seed, &pk_seed, idx_tree, idx_leaf);
            let result = TestHt::ht_verify(&msg, &sig, &pk_seed, idx_tree, idx_leaf, &pk_root);
            assert!(
                result,
                "Failed for idx_tree={}, idx_leaf={}",
                idx_tree, idx_leaf
            );
        }
    }

    #[test]
    fn test_ht_wrong_message_fails() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let msg1 = [1u8; 16];
        let msg2 = [2u8; 16];
        let pk_root = TestHt::ht_root(&sk_seed, &pk_seed);

        let sig = TestHt::ht_sign(&msg1, &sk_seed, &pk_seed, 0, 0);
        let result = TestHt::ht_verify(&msg2, &sig, &pk_seed, 0, 0, &pk_root);

        assert!(!result, "Should fail with wrong message");
    }

    #[test]
    fn test_ht_wrong_indices_fails() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let msg = [42u8; 16];
        let pk_root = TestHt::ht_root(&sk_seed, &pk_seed);

        let sig = TestHt::ht_sign(&msg, &sk_seed, &pk_seed, 0, 0);

        // Verify with wrong leaf index
        let result = TestHt::ht_verify(&msg, &sig, &pk_seed, 0, 1, &pk_root);
        assert!(!result, "Should fail with wrong leaf index");
    }

    #[test]
    fn test_ht_signature_size() {
        let expected_size = Sha2_128f::D * XmssSignature::<Sha2_128f>::size();
        assert_eq!(HypertreeSignature::<Sha2_128f>::size(), expected_size);
    }

    #[test]
    fn test_ht_signature_serialization() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let msg = [42u8; 16];

        let sig = TestHt::ht_sign(&msg, &sk_seed, &pk_seed, 0, 0);
        let bytes = sig.to_bytes();

        assert_eq!(bytes.len(), HypertreeSignature::<Sha2_128f>::size());

        let restored = HypertreeSignature::<Sha2_128f>::from_bytes(&bytes).unwrap();
        assert_eq!(sig.xmss_sigs().len(), restored.xmss_sigs().len());
    }
}
