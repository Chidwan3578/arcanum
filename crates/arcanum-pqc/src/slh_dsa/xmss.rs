//! XMSS (eXtended Merkle Signature Scheme)
//!
//! FIPS 205 Section 6 defines XMSS trees used in the hypertree structure.
//! Each XMSS tree has 2^h' leaves, where each leaf is a WOTS+ public key.
//!
//! Key functions:
//! - `xmss_node`: Compute tree node at given height and index
//! - `xmss_sign`: Generate XMSS signature (WOTS+ sig + authentication path)
//! - `xmss_pk_from_sig`: Compute root from signature for verification

#![allow(dead_code)]

use super::address::{Address, AddressType};
use super::hash::SlhDsaHash;
use super::params::SlhDsaParams;
use super::wots::{Wots, WotsSignature};
use alloc::vec::Vec;
use core::marker::PhantomData;

/// XMSS signature containing WOTS+ signature and authentication path
#[derive(Clone)]
pub struct XmssSignature<P: SlhDsaParams> {
    /// WOTS+ signature (WOTS_LEN * N bytes)
    wots_sig: Vec<u8>,
    /// Authentication path (H' nodes of N bytes each)
    auth_path: Vec<Vec<u8>>,
    _params: PhantomData<P>,
}

impl<P: SlhDsaParams> XmssSignature<P> {
    /// Create from components
    pub fn new(wots_sig: Vec<u8>, auth_path: Vec<Vec<u8>>) -> Self {
        Self {
            wots_sig,
            auth_path,
            _params: PhantomData,
        }
    }

    /// Get WOTS+ signature bytes
    pub fn wots_sig(&self) -> &[u8] {
        &self.wots_sig
    }

    /// Get authentication path
    pub fn auth_path(&self) -> &[Vec<u8>] {
        &self.auth_path
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(P::WOTS_LEN * P::N + P::H_PRIME * P::N);
        bytes.extend_from_slice(&self.wots_sig);
        for node in &self.auth_path {
            bytes.extend_from_slice(node);
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let wots_size = P::WOTS_LEN * P::N;
        let auth_size = P::H_PRIME * P::N;
        if bytes.len() != wots_size + auth_size {
            return None;
        }

        let wots_sig = bytes[0..wots_size].to_vec();
        let mut auth_path = Vec::with_capacity(P::H_PRIME);
        for i in 0..P::H_PRIME {
            let start = wots_size + i * P::N;
            auth_path.push(bytes[start..start + P::N].to_vec());
        }

        Some(Self {
            wots_sig,
            auth_path,
            _params: PhantomData,
        })
    }

    /// Get size in bytes
    pub fn size() -> usize {
        P::WOTS_LEN * P::N + P::H_PRIME * P::N
    }
}

/// XMSS tree implementation
pub struct Xmss<P: SlhDsaParams, H: SlhDsaHash<P>> {
    _params: PhantomData<P>,
    _hash: PhantomData<H>,
}

impl<P: SlhDsaParams, H: SlhDsaHash<P>> Xmss<P, H> {
    /// Compute a node in the XMSS tree
    ///
    /// FIPS 205 Algorithm 7: xmss_node
    ///
    /// # Arguments
    /// * `sk_seed` - Secret seed
    /// * `pk_seed` - Public seed
    /// * `i` - Node index (0 to 2^(h'-height) - 1)
    /// * `height` - Node height (0 = leaves, h' = root)
    /// * `adrs` - Address (layer and tree address set)
    ///
    /// # Returns
    /// Node value (n bytes)
    pub fn xmss_node(
        sk_seed: &[u8],
        pk_seed: &[u8],
        i: u32,
        height: u32,
        adrs: &Address,
    ) -> Vec<u8> {
        if height == 0 {
            // Leaf node: compute WOTS+ public key
            let mut wots_adrs = *adrs;
            wots_adrs.set_type(AddressType::WotsHash);
            wots_adrs.set_keypair_address(i);

            Wots::<P, H>::keygen(sk_seed, pk_seed, &wots_adrs)
        } else {
            // Internal node: hash children
            let left = Self::xmss_node(sk_seed, pk_seed, 2 * i, height - 1, adrs);
            let right = Self::xmss_node(sk_seed, pk_seed, 2 * i + 1, height - 1, adrs);

            let mut tree_adrs = *adrs;
            tree_adrs.set_type(AddressType::Tree);
            tree_adrs.set_tree_height(height);
            tree_adrs.set_tree_index(i);

            H::h(pk_seed, &tree_adrs, &left, &right)
        }
    }

    /// Generate XMSS signature
    ///
    /// FIPS 205 Algorithm 8: xmss_sign
    ///
    /// # Arguments
    /// * `msg` - Message to sign (n bytes, typically a hash)
    /// * `sk_seed` - Secret seed
    /// * `pk_seed` - Public seed
    /// * `idx` - Index of WOTS+ keypair to use (0 to 2^h' - 1)
    /// * `adrs` - Address (layer and tree address set)
    ///
    /// # Returns
    /// XMSS signature
    pub fn xmss_sign(
        msg: &[u8],
        sk_seed: &[u8],
        pk_seed: &[u8],
        idx: u32,
        adrs: &Address,
    ) -> XmssSignature<P> {
        // Generate WOTS+ signature
        let mut wots_adrs = *adrs;
        wots_adrs.set_type(AddressType::WotsHash);
        wots_adrs.set_keypair_address(idx);

        let wots_sig = Wots::<P, H>::sign(msg, sk_seed, pk_seed, &wots_adrs);

        // Build authentication path
        let mut auth_path = Vec::with_capacity(P::H_PRIME);
        let mut k = idx;

        for j in 0..P::H_PRIME as u32 {
            // Sibling index: if k is even, sibling is k+1; if odd, sibling is k-1
            let sibling_idx = k ^ 1;
            let node = Self::xmss_node(sk_seed, pk_seed, sibling_idx, j, adrs);
            auth_path.push(node);
            k /= 2;
        }

        XmssSignature::new(wots_sig.as_bytes().to_vec(), auth_path)
    }

    /// Compute XMSS public key (root) from signature
    ///
    /// FIPS 205 Algorithm 9: xmss_PKFromSig
    ///
    /// # Arguments
    /// * `idx` - WOTS+ key index used for signing
    /// * `sig` - XMSS signature
    /// * `msg` - Message that was signed (n bytes)
    /// * `pk_seed` - Public seed
    /// * `adrs` - Address (layer and tree address set)
    ///
    /// # Returns
    /// Computed root (n bytes)
    pub fn xmss_pk_from_sig(
        idx: u32,
        sig: &XmssSignature<P>,
        msg: &[u8],
        pk_seed: &[u8],
        adrs: &Address,
    ) -> Vec<u8> {
        // Compute WOTS+ public key from signature
        let mut wots_adrs = *adrs;
        wots_adrs.set_type(AddressType::WotsHash);
        wots_adrs.set_keypair_address(idx);

        let wots_sig = WotsSignature::<P>::from_bytes(sig.wots_sig())
            .expect("Invalid WOTS+ signature length");
        let mut node = Wots::<P, H>::pk_from_sig(&wots_sig, msg, pk_seed, &wots_adrs);

        // Climb the tree using authentication path
        let mut k = idx;
        for j in 0..P::H_PRIME {
            let mut tree_adrs = *adrs;
            tree_adrs.set_type(AddressType::Tree);
            tree_adrs.set_tree_height(j as u32 + 1);
            tree_adrs.set_tree_index(k / 2);

            let sibling = &sig.auth_path()[j];

            // Order depends on whether k is even or odd
            if k % 2 == 0 {
                // node is left child
                node = H::h(pk_seed, &tree_adrs, &node, sibling);
            } else {
                // node is right child
                node = H::h(pk_seed, &tree_adrs, sibling, &node);
            }
            k /= 2;
        }

        node
    }

    /// Compute XMSS root directly (for key generation)
    ///
    /// # Arguments
    /// * `sk_seed` - Secret seed
    /// * `pk_seed` - Public seed
    /// * `adrs` - Address (layer and tree address set)
    ///
    /// # Returns
    /// Root of the XMSS tree (n bytes)
    pub fn xmss_root(sk_seed: &[u8], pk_seed: &[u8], adrs: &Address) -> Vec<u8> {
        Self::xmss_node(sk_seed, pk_seed, 0, P::H_PRIME as u32, adrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::hash::Sha2Hash;
    use crate::slh_dsa::params::Sha2_128f;

    type TestXmss = Xmss<Sha2_128f, Sha2Hash<Sha2_128f>>;

    #[test]
    fn test_xmss_leaf_is_wots_pk() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::tree(0, 0, 0, 0);

        // Compute leaf node (height 0)
        let leaf = TestXmss::xmss_node(&sk_seed, &pk_seed, 0, 0, &adrs);
        assert_eq!(leaf.len(), Sha2_128f::N);

        // Should match WOTS+ keygen
        let mut wots_adrs = adrs;
        wots_adrs.set_type(AddressType::WotsHash);
        wots_adrs.set_keypair_address(0);

        let wots_pk =
            Wots::<Sha2_128f, Sha2Hash<Sha2_128f>>::keygen(&sk_seed, &pk_seed, &wots_adrs);
        assert_eq!(leaf, wots_pk);
    }

    #[test]
    fn test_xmss_node_deterministic() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::tree(0, 0, 0, 0);

        let node1 = TestXmss::xmss_node(&sk_seed, &pk_seed, 0, 2, &adrs);
        let node2 = TestXmss::xmss_node(&sk_seed, &pk_seed, 0, 2, &adrs);

        assert_eq!(node1, node2);
    }

    #[test]
    fn test_xmss_different_indices_different_leaves() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::tree(0, 0, 0, 0);

        let leaf0 = TestXmss::xmss_node(&sk_seed, &pk_seed, 0, 0, &adrs);
        let leaf1 = TestXmss::xmss_node(&sk_seed, &pk_seed, 1, 0, &adrs);

        assert_ne!(leaf0, leaf1);
    }

    #[test]
    fn test_xmss_sign_verify_roundtrip() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::tree(0, 0, 0, 0);
        let msg = [42u8; 16];
        let idx = 0u32;

        // Compute the root directly
        let root = TestXmss::xmss_root(&sk_seed, &pk_seed, &adrs);

        // Sign and verify
        let sig = TestXmss::xmss_sign(&msg, &sk_seed, &pk_seed, idx, &adrs);
        let computed_root = TestXmss::xmss_pk_from_sig(idx, &sig, &msg, &pk_seed, &adrs);

        assert_eq!(root, computed_root);
    }

    #[test]
    fn test_xmss_sign_verify_different_indices() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::tree(0, 0, 0, 0);
        let msg = [42u8; 16];

        // Compute the root
        let root = TestXmss::xmss_root(&sk_seed, &pk_seed, &adrs);

        // Sign with different indices (all should produce same root)
        for idx in [0, 1, 2, 3] {
            let sig = TestXmss::xmss_sign(&msg, &sk_seed, &pk_seed, idx, &adrs);
            let computed_root = TestXmss::xmss_pk_from_sig(idx, &sig, &msg, &pk_seed, &adrs);
            assert_eq!(root, computed_root, "Failed for idx={}", idx);
        }
    }

    #[test]
    fn test_xmss_wrong_message_fails() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::tree(0, 0, 0, 0);
        let msg1 = [1u8; 16];
        let msg2 = [2u8; 16];
        let idx = 0u32;

        let root = TestXmss::xmss_root(&sk_seed, &pk_seed, &adrs);
        let sig = TestXmss::xmss_sign(&msg1, &sk_seed, &pk_seed, idx, &adrs);

        // Verify with wrong message should produce different root
        let computed_root = TestXmss::xmss_pk_from_sig(idx, &sig, &msg2, &pk_seed, &adrs);
        assert_ne!(root, computed_root);
    }

    #[test]
    fn test_xmss_wrong_index_fails() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::tree(0, 0, 0, 0);
        let msg = [42u8; 16];

        let root = TestXmss::xmss_root(&sk_seed, &pk_seed, &adrs);
        let sig = TestXmss::xmss_sign(&msg, &sk_seed, &pk_seed, 0, &adrs);

        // Verify with wrong index should produce different root
        let computed_root = TestXmss::xmss_pk_from_sig(1, &sig, &msg, &pk_seed, &adrs);
        assert_ne!(root, computed_root);
    }

    #[test]
    fn test_xmss_signature_serialization() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::tree(0, 0, 0, 0);
        let msg = [42u8; 16];

        let sig = TestXmss::xmss_sign(&msg, &sk_seed, &pk_seed, 0, &adrs);
        let bytes = sig.to_bytes();

        assert_eq!(bytes.len(), XmssSignature::<Sha2_128f>::size());

        let restored = XmssSignature::<Sha2_128f>::from_bytes(&bytes).unwrap();
        assert_eq!(sig.wots_sig(), restored.wots_sig());
        assert_eq!(sig.auth_path().len(), restored.auth_path().len());
    }

    #[test]
    fn test_xmss_root_deterministic() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::tree(0, 0, 0, 0);

        let root1 = TestXmss::xmss_root(&sk_seed, &pk_seed, &adrs);
        let root2 = TestXmss::xmss_root(&sk_seed, &pk_seed, &adrs);

        assert_eq!(root1, root2);
    }
}
