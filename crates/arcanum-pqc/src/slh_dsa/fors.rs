//! FORS (Forest of Random Subsets)
//!
//! FIPS 205 Section 7 defines FORS, a few-time signature scheme used in SLH-DSA.
//! FORS consists of k binary trees, each with 2^a leaves.
//!
//! Key functions:
//! - `fors_sk_gen`: Generate FORS secret key values
//! - `fors_node`: Compute tree node at given height and index
//! - `fors_sign`: Generate FORS signature (k secret values + k auth paths)
//! - `fors_pk_from_sig`: Compute FORS public key from signature

#![allow(dead_code)]

use super::address::{Address, AddressType};
use super::hash::SlhDsaHash;
use super::params::SlhDsaParams;
use core::marker::PhantomData;
use std::vec::Vec;

/// FORS signature containing k secret values and k authentication paths
#[derive(Clone)]
pub struct ForsSignature<P: SlhDsaParams> {
    /// k secret values (each n bytes)
    sk_values: Vec<Vec<u8>>,
    /// k authentication paths (each with a nodes of n bytes)
    auth_paths: Vec<Vec<Vec<u8>>>,
    _params: PhantomData<P>,
}

impl<P: SlhDsaParams> ForsSignature<P> {
    /// Create from components
    pub fn new(sk_values: Vec<Vec<u8>>, auth_paths: Vec<Vec<Vec<u8>>>) -> Self {
        Self {
            sk_values,
            auth_paths,
            _params: PhantomData,
        }
    }

    /// Get secret values
    pub fn sk_values(&self) -> &[Vec<u8>] {
        &self.sk_values
    }

    /// Get authentication paths
    pub fn auth_paths(&self) -> &[Vec<Vec<u8>>] {
        &self.auth_paths
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        // Size: k * n (sk_values) + k * a * n (auth_paths)
        let size = P::K * P::N + P::K * P::A * P::N;
        let mut bytes = Vec::with_capacity(size);

        for i in 0..P::K {
            bytes.extend_from_slice(&self.sk_values[i]);
            for j in 0..P::A {
                bytes.extend_from_slice(&self.auth_paths[i][j]);
            }
        }
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let expected_size = P::K * P::N + P::K * P::A * P::N;
        if bytes.len() != expected_size {
            return None;
        }

        let mut sk_values = Vec::with_capacity(P::K);
        let mut auth_paths = Vec::with_capacity(P::K);
        let tree_size = P::N + P::A * P::N; // sk_value + auth_path per tree

        for i in 0..P::K {
            let tree_start = i * tree_size;
            sk_values.push(bytes[tree_start..tree_start + P::N].to_vec());

            let mut auth_path = Vec::with_capacity(P::A);
            for j in 0..P::A {
                let node_start = tree_start + P::N + j * P::N;
                auth_path.push(bytes[node_start..node_start + P::N].to_vec());
            }
            auth_paths.push(auth_path);
        }

        Some(Self {
            sk_values,
            auth_paths,
            _params: PhantomData,
        })
    }

    /// Get size in bytes
    pub fn size() -> usize {
        P::K * P::N + P::K * P::A * P::N
    }
}

/// FORS implementation
pub struct Fors<P: SlhDsaParams, H: SlhDsaHash<P>> {
    _params: PhantomData<P>,
    _hash: PhantomData<H>,
}

impl<P: SlhDsaParams, H: SlhDsaHash<P>> Fors<P, H> {
    /// Generate FORS secret key value
    ///
    /// FIPS 205 Algorithm 10: fors_SKgen
    ///
    /// # Arguments
    /// * `sk_seed` - Secret seed
    /// * `pk_seed` - Public seed
    /// * `adrs` - Address (with keypair address set)
    /// * `tree_idx` - Which FORS tree (0 to k-1)
    /// * `leaf_idx` - Which leaf in tree (0 to 2^a - 1)
    ///
    /// # Returns
    /// Secret key value (n bytes)
    pub fn fors_sk_gen(
        sk_seed: &[u8],
        pk_seed: &[u8],
        adrs: &Address,
        tree_idx: u32,
        leaf_idx: u32,
    ) -> Vec<u8> {
        let mut sk_adrs = *adrs;
        sk_adrs.set_type(AddressType::ForsPrf);
        sk_adrs.set_tree_height(0);
        sk_adrs.set_tree_index(tree_idx * (1 << P::A) + leaf_idx);

        H::prf(pk_seed, sk_seed, &sk_adrs)
    }

    /// Compute a node in a FORS tree
    ///
    /// FIPS 205 Algorithm 11: fors_node
    ///
    /// # Arguments
    /// * `sk_seed` - Secret seed
    /// * `pk_seed` - Public seed
    /// * `tree_idx` - Which FORS tree (0 to k-1)
    /// * `node_idx` - Node index at this height
    /// * `height` - Node height (0 = leaves, a = root)
    /// * `adrs` - Address (with keypair address set)
    ///
    /// # Returns
    /// Node value (n bytes)
    pub fn fors_node(
        sk_seed: &[u8],
        pk_seed: &[u8],
        tree_idx: u32,
        node_idx: u32,
        height: u32,
        adrs: &Address,
    ) -> Vec<u8> {
        if height == 0 {
            // Leaf node: F(pk_seed, adrs, sk_value)
            let sk = Self::fors_sk_gen(sk_seed, pk_seed, adrs, tree_idx, node_idx);

            let mut leaf_adrs = *adrs;
            leaf_adrs.set_type(AddressType::ForsTree);
            leaf_adrs.set_tree_height(0);
            leaf_adrs.set_tree_index(tree_idx * (1 << P::A) + node_idx);

            H::f(pk_seed, &leaf_adrs, &sk)
        } else {
            // Internal node: H(pk_seed, adrs, left || right)
            let left = Self::fors_node(sk_seed, pk_seed, tree_idx, 2 * node_idx, height - 1, adrs);
            let right = Self::fors_node(
                sk_seed,
                pk_seed,
                tree_idx,
                2 * node_idx + 1,
                height - 1,
                adrs,
            );

            let mut tree_adrs = *adrs;
            tree_adrs.set_type(AddressType::ForsTree);
            tree_adrs.set_tree_height(height);
            tree_adrs.set_tree_index(tree_idx * (1 << (P::A - height as usize)) + node_idx);

            H::h(pk_seed, &tree_adrs, &left, &right)
        }
    }

    /// Compute root of a single FORS tree
    pub fn fors_tree_root(
        sk_seed: &[u8],
        pk_seed: &[u8],
        tree_idx: u32,
        adrs: &Address,
    ) -> Vec<u8> {
        Self::fors_node(sk_seed, pk_seed, tree_idx, 0, P::A as u32, adrs)
    }

    /// Generate FORS signature
    ///
    /// FIPS 205 Algorithm 12: fors_sign
    ///
    /// # Arguments
    /// * `md` - Message digest (determines which leaves to reveal)
    /// * `sk_seed` - Secret seed
    /// * `pk_seed` - Public seed
    /// * `adrs` - Address (with keypair address set)
    ///
    /// # Returns
    /// FORS signature
    pub fn fors_sign(
        md: &[u8],
        sk_seed: &[u8],
        pk_seed: &[u8],
        adrs: &Address,
    ) -> ForsSignature<P> {
        // Extract indices from message digest
        let indices = Self::message_to_indices(md);

        let mut sk_values = Vec::with_capacity(P::K);
        let mut auth_paths = Vec::with_capacity(P::K);

        for (tree_idx, &leaf_idx) in indices.iter().enumerate() {
            // Get secret key value for this leaf
            let sk = Self::fors_sk_gen(sk_seed, pk_seed, adrs, tree_idx as u32, leaf_idx);
            sk_values.push(sk);

            // Build authentication path
            let mut auth_path = Vec::with_capacity(P::A);
            let mut k = leaf_idx;

            for height in 0..P::A as u32 {
                // Sibling index
                let sibling_idx = k ^ 1;
                let node =
                    Self::fors_node(sk_seed, pk_seed, tree_idx as u32, sibling_idx, height, adrs);
                auth_path.push(node);
                k /= 2;
            }

            auth_paths.push(auth_path);
        }

        ForsSignature::new(sk_values, auth_paths)
    }

    /// Compute FORS public key from signature
    ///
    /// FIPS 205 Algorithm 13: fors_PKFromSig
    ///
    /// # Arguments
    /// * `md` - Message digest
    /// * `sig` - FORS signature
    /// * `pk_seed` - Public seed
    /// * `adrs` - Address (with keypair address set)
    ///
    /// # Returns
    /// FORS public key (n bytes)
    pub fn fors_pk_from_sig(
        md: &[u8],
        sig: &ForsSignature<P>,
        pk_seed: &[u8],
        adrs: &Address,
    ) -> Vec<u8> {
        let indices = Self::message_to_indices(md);
        let mut roots = Vec::with_capacity(P::K);

        for (tree_idx, &leaf_idx) in indices.iter().enumerate() {
            // Compute leaf from secret key value
            let mut leaf_adrs = *adrs;
            leaf_adrs.set_type(AddressType::ForsTree);
            leaf_adrs.set_tree_height(0);
            leaf_adrs.set_tree_index(tree_idx as u32 * (1 << P::A) + leaf_idx);

            let mut node = H::f(pk_seed, &leaf_adrs, &sig.sk_values[tree_idx]);

            // Climb tree using authentication path
            let mut k = leaf_idx;
            for height in 0..P::A {
                let mut tree_adrs = *adrs;
                tree_adrs.set_type(AddressType::ForsTree);
                tree_adrs.set_tree_height(height as u32 + 1);
                tree_adrs.set_tree_index(tree_idx as u32 * (1 << (P::A - height - 1)) + k / 2);

                let sibling = &sig.auth_paths[tree_idx][height];

                if k % 2 == 0 {
                    node = H::h(pk_seed, &tree_adrs, &node, sibling);
                } else {
                    node = H::h(pk_seed, &tree_adrs, sibling, &node);
                }
                k /= 2;
            }

            roots.push(node);
        }

        // Compress all roots into final public key
        let mut fors_roots_adrs = *adrs;
        fors_roots_adrs.set_type(AddressType::ForsRoots);

        let all_roots: Vec<u8> = roots.into_iter().flatten().collect();
        H::t_l(pk_seed, &fors_roots_adrs, &all_roots)
    }

    /// Compute FORS public key directly (for key generation)
    pub fn fors_pk(sk_seed: &[u8], pk_seed: &[u8], adrs: &Address) -> Vec<u8> {
        let mut roots = Vec::with_capacity(P::K);

        for tree_idx in 0..P::K as u32 {
            let root = Self::fors_tree_root(sk_seed, pk_seed, tree_idx, adrs);
            roots.push(root);
        }

        let mut fors_roots_adrs = *adrs;
        fors_roots_adrs.set_type(AddressType::ForsRoots);

        let all_roots: Vec<u8> = roots.into_iter().flatten().collect();
        H::t_l(pk_seed, &fors_roots_adrs, &all_roots)
    }

    /// Convert message digest to FORS indices
    ///
    /// Extracts k indices (each in range 0 to 2^a - 1) from the message digest.
    fn message_to_indices(md: &[u8]) -> Vec<u32> {
        let a = P::A;
        let k = P::K;
        let mut indices = Vec::with_capacity(k);

        // Total bits needed: k * a
        let mut bit_offset = 0;

        for _ in 0..k {
            let mut index: u32 = 0;
            for bit in 0..a {
                let byte_idx = (bit_offset + bit) / 8;
                let bit_idx = 7 - ((bit_offset + bit) % 8);

                if byte_idx < md.len() {
                    let bit_val = (md[byte_idx] >> bit_idx) & 1;
                    index |= (bit_val as u32) << (a - 1 - bit);
                }
            }
            indices.push(index);
            bit_offset += a;
        }

        indices
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slh_dsa::hash::Sha2Hash;
    use crate::slh_dsa::params::Sha2_128f;

    type TestFors = Fors<Sha2_128f, Sha2Hash<Sha2_128f>>;

    #[test]
    fn test_fors_sk_gen_deterministic() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::fors_tree(0, 0, 5, 0, 0);

        let sk1 = TestFors::fors_sk_gen(&sk_seed, &pk_seed, &adrs, 0, 0);
        let sk2 = TestFors::fors_sk_gen(&sk_seed, &pk_seed, &adrs, 0, 0);

        assert_eq!(sk1.len(), Sha2_128f::N);
        assert_eq!(sk1, sk2);
    }

    #[test]
    fn test_fors_sk_gen_different_indices() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::fors_tree(0, 0, 5, 0, 0);

        let sk1 = TestFors::fors_sk_gen(&sk_seed, &pk_seed, &adrs, 0, 0);
        let sk2 = TestFors::fors_sk_gen(&sk_seed, &pk_seed, &adrs, 0, 1);
        let sk3 = TestFors::fors_sk_gen(&sk_seed, &pk_seed, &adrs, 1, 0);

        assert_ne!(sk1, sk2);
        assert_ne!(sk1, sk3);
        assert_ne!(sk2, sk3);
    }

    #[test]
    fn test_fors_node_leaf() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::fors_tree(0, 0, 5, 0, 0);

        let leaf = TestFors::fors_node(&sk_seed, &pk_seed, 0, 0, 0, &adrs);
        assert_eq!(leaf.len(), Sha2_128f::N);
    }

    #[test]
    fn test_fors_tree_root_deterministic() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::fors_tree(0, 0, 5, 0, 0);

        let root1 = TestFors::fors_tree_root(&sk_seed, &pk_seed, 0, &adrs);
        let root2 = TestFors::fors_tree_root(&sk_seed, &pk_seed, 0, &adrs);

        assert_eq!(root1, root2);
    }

    #[test]
    fn test_message_to_indices() {
        // For SHA2-128f: A=12, K=14
        // Total bits needed: 14 * 12 = 168 bits = 21 bytes
        let md = vec![0xFF; 32]; // All ones

        let indices = TestFors::message_to_indices(&md);
        assert_eq!(indices.len(), Sha2_128f::K);

        // All bits are 1, so each index should be 2^A - 1 = 4095
        for &idx in &indices {
            assert_eq!(idx, (1 << Sha2_128f::A) - 1);
        }
    }

    #[test]
    fn test_message_to_indices_zero() {
        let md = vec![0u8; 32]; // All zeros

        let indices = TestFors::message_to_indices(&md);
        assert_eq!(indices.len(), Sha2_128f::K);

        // All bits are 0, so each index should be 0
        for &idx in &indices {
            assert_eq!(idx, 0);
        }
    }

    #[test]
    fn test_fors_sign_verify_roundtrip() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::fors_tree(0, 0, 5, 0, 0);
        let md = [42u8; 32];

        // Compute public key directly
        let pk = TestFors::fors_pk(&sk_seed, &pk_seed, &adrs);

        // Sign and verify
        let sig = TestFors::fors_sign(&md, &sk_seed, &pk_seed, &adrs);
        let computed_pk = TestFors::fors_pk_from_sig(&md, &sig, &pk_seed, &adrs);

        assert_eq!(pk, computed_pk);
    }

    #[test]
    fn test_fors_wrong_message_fails() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::fors_tree(0, 0, 5, 0, 0);
        let md1 = [1u8; 32];
        let md2 = [2u8; 32];

        let pk = TestFors::fors_pk(&sk_seed, &pk_seed, &adrs);
        let sig = TestFors::fors_sign(&md1, &sk_seed, &pk_seed, &adrs);

        // Verify with wrong message should produce different public key
        let computed_pk = TestFors::fors_pk_from_sig(&md2, &sig, &pk_seed, &adrs);
        assert_ne!(pk, computed_pk);
    }

    #[test]
    fn test_fors_signature_size() {
        // Size should be: k * n + k * a * n = k * n * (1 + a)
        let expected_size =
            Sha2_128f::K * Sha2_128f::N + Sha2_128f::K * Sha2_128f::A * Sha2_128f::N;
        assert_eq!(ForsSignature::<Sha2_128f>::size(), expected_size);
    }

    #[test]
    fn test_fors_signature_serialization() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::fors_tree(0, 0, 5, 0, 0);
        let md = [42u8; 32];

        let sig = TestFors::fors_sign(&md, &sk_seed, &pk_seed, &adrs);
        let bytes = sig.to_bytes();

        assert_eq!(bytes.len(), ForsSignature::<Sha2_128f>::size());

        let restored = ForsSignature::<Sha2_128f>::from_bytes(&bytes).unwrap();
        assert_eq!(sig.sk_values().len(), restored.sk_values().len());
        assert_eq!(sig.auth_paths().len(), restored.auth_paths().len());
    }

    #[test]
    fn test_fors_pk_deterministic() {
        let sk_seed = [1u8; 16];
        let pk_seed = [2u8; 16];
        let adrs = Address::fors_tree(0, 0, 5, 0, 0);

        let pk1 = TestFors::fors_pk(&sk_seed, &pk_seed, &adrs);
        let pk2 = TestFors::fors_pk(&sk_seed, &pk_seed, &adrs);

        assert_eq!(pk1, pk2);
        assert_eq!(pk1.len(), Sha2_128f::N);
    }
}
