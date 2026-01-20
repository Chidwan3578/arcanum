//! SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
//!
//! Native implementation of FIPS 205 for post-quantum digital signatures.
//!
//! # Overview
//!
//! SLH-DSA provides digital signatures whose security relies solely on the
//! security of the underlying hash function. This makes it a conservative
//! choice for post-quantum cryptography.
//!
//! # Supported Variants
//!
//! ## SHA-2 Based (using SHA-256)
//!
//! | Variant | Security | Signature Size | Sign Speed |
//! |---------|----------|----------------|------------|
//! | `SlhDsaSha2_128s` | 128-bit | 7,856 bytes | Slow |
//! | `SlhDsaSha2_128f` | 128-bit | 17,088 bytes | Fast |
//! | `SlhDsaSha2_192s` | 192-bit | 16,224 bytes | Slow |
//! | `SlhDsaSha2_192f` | 192-bit | 35,664 bytes | Fast |
//! | `SlhDsaSha2_256s` | 256-bit | 29,792 bytes | Slow |
//! | `SlhDsaSha2_256f` | 256-bit | 49,856 bytes | Fast |
//!
//! The "s" variants have smaller signatures but slower signing.
//! The "f" variants have faster signing but larger signatures.
//!
//! # Example
//!
//! ```ignore
//! use arcanum_pqc::slh_dsa::{SlhDsaSha2_128f, SlhDsa};
//!
//! // Generate keypair
//! let (signing_key, verifying_key) = SlhDsaSha2_128f::generate_keypair();
//!
//! // Sign a message (randomized by default)
//! let message = b"Hello, post-quantum world!";
//! let signature = SlhDsaSha2_128f::sign(&signing_key, message);
//!
//! // Verify the signature
//! assert!(SlhDsaSha2_128f::verify(&verifying_key, message, &signature).is_ok());
//!
//! // Deterministic signing for testing
//! let det_sig = SlhDsaSha2_128f::sign_deterministic(&signing_key, message);
//! ```
//!
//! # Security Considerations
//!
//! - **Randomized signing is the default** and recommended for production
//! - Deterministic signing is available for testing and debugging
//! - Signing keys must be kept secret and securely erased after use
//! - The security relies entirely on SHA-256 (or SHAKE256) security

#![allow(dead_code)]

extern crate alloc;

pub mod address;
pub mod fors;
pub mod hash;
pub mod hypertree;
pub mod params;
pub mod wots;
pub mod xmss;

use alloc::vec::Vec;
use core::marker::PhantomData;

pub use address::{Address, AddressType};
pub use fors::Fors;
pub use hash::{Sha2Hash, ShakeHash, SlhDsaHash};
pub use hypertree::Hypertree;
pub use params::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    SlhDsaParams,
};

use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// Key Types
// ============================================================================

/// SLH-DSA signing (secret) key
///
/// Contains:
/// - `sk_seed`: Secret seed for key generation (n bytes)
/// - `sk_prf`: Secret key for PRF_msg (n bytes)
/// - `pk_seed`: Public seed (n bytes)
/// - `pk_root`: Root of the top XMSS tree (n bytes)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SlhDsaSigningKey<P: SlhDsaParams> {
    /// Secret seed (n bytes)
    sk_seed: Vec<u8>,
    /// PRF key for message randomness (n bytes)
    sk_prf: Vec<u8>,
    /// Public seed (n bytes) - also in public key
    pk_seed: Vec<u8>,
    /// Root hash (n bytes) - also in public key
    pk_root: Vec<u8>,
    #[zeroize(skip)]
    _params: PhantomData<P>,
}

impl<P: SlhDsaParams> SlhDsaSigningKey<P> {
    /// Create a signing key from components
    pub fn from_components(
        sk_seed: Vec<u8>,
        sk_prf: Vec<u8>,
        pk_seed: Vec<u8>,
        pk_root: Vec<u8>,
    ) -> Option<Self> {
        if sk_seed.len() != P::N
            || sk_prf.len() != P::N
            || pk_seed.len() != P::N
            || pk_root.len() != P::N
        {
            return None;
        }
        Some(Self {
            sk_seed,
            sk_prf,
            pk_seed,
            pk_root,
            _params: PhantomData,
        })
    }

    /// Create from serialized bytes (4n bytes)
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != P::SK_SIZE {
            return None;
        }
        let n = P::N;
        Some(Self {
            sk_seed: bytes[0..n].to_vec(),
            sk_prf: bytes[n..2 * n].to_vec(),
            pk_seed: bytes[2 * n..3 * n].to_vec(),
            pk_root: bytes[3 * n..4 * n].to_vec(),
            _params: PhantomData,
        })
    }

    /// Serialize to bytes (4n bytes)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(P::SK_SIZE);
        bytes.extend_from_slice(&self.sk_seed);
        bytes.extend_from_slice(&self.sk_prf);
        bytes.extend_from_slice(&self.pk_seed);
        bytes.extend_from_slice(&self.pk_root);
        bytes
    }

    /// Get the corresponding verifying key
    pub fn verifying_key(&self) -> SlhDsaVerifyingKey<P> {
        SlhDsaVerifyingKey {
            pk_seed: self.pk_seed.clone(),
            pk_root: self.pk_root.clone(),
            _params: PhantomData,
        }
    }

    /// Access secret seed (for internal use)
    pub(crate) fn sk_seed(&self) -> &[u8] {
        &self.sk_seed
    }

    /// Access PRF key (for internal use)
    pub(crate) fn sk_prf(&self) -> &[u8] {
        &self.sk_prf
    }

    /// Access public seed
    pub fn pk_seed(&self) -> &[u8] {
        &self.pk_seed
    }

    /// Access root hash
    pub fn pk_root(&self) -> &[u8] {
        &self.pk_root
    }
}

impl<P: SlhDsaParams> core::fmt::Debug for SlhDsaSigningKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SlhDsaSigningKey")
            .field("algorithm", &P::ALGORITHM)
            .field("sk_seed", &"[REDACTED]")
            .field("sk_prf", &"[REDACTED]")
            .finish()
    }
}

/// SLH-DSA verifying (public) key
///
/// Contains:
/// - `pk_seed`: Public seed (n bytes)
/// - `pk_root`: Root of the top XMSS tree (n bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct SlhDsaVerifyingKey<P: SlhDsaParams> {
    /// Public seed (n bytes)
    pk_seed: Vec<u8>,
    /// Root hash (n bytes)
    pk_root: Vec<u8>,
    _params: PhantomData<P>,
}

impl<P: SlhDsaParams> SlhDsaVerifyingKey<P> {
    /// Create from components
    pub fn from_components(pk_seed: Vec<u8>, pk_root: Vec<u8>) -> Option<Self> {
        if pk_seed.len() != P::N || pk_root.len() != P::N {
            return None;
        }
        Some(Self {
            pk_seed,
            pk_root,
            _params: PhantomData,
        })
    }

    /// Create from serialized bytes (2n bytes)
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != P::PK_SIZE {
            return None;
        }
        let n = P::N;
        Some(Self {
            pk_seed: bytes[0..n].to_vec(),
            pk_root: bytes[n..2 * n].to_vec(),
            _params: PhantomData,
        })
    }

    /// Serialize to bytes (2n bytes)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(P::PK_SIZE);
        bytes.extend_from_slice(&self.pk_seed);
        bytes.extend_from_slice(&self.pk_root);
        bytes
    }

    /// Access public seed
    pub fn pk_seed(&self) -> &[u8] {
        &self.pk_seed
    }

    /// Access root hash
    pub fn pk_root(&self) -> &[u8] {
        &self.pk_root
    }
}

impl<P: SlhDsaParams> core::fmt::Debug for SlhDsaVerifyingKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SlhDsaVerifyingKey")
            .field("algorithm", &P::ALGORITHM)
            .field("pk_seed", &hex::encode(&self.pk_seed))
            .field("pk_root", &hex::encode(&self.pk_root))
            .finish()
    }
}

// ============================================================================
// Signature Type
// ============================================================================

/// SLH-DSA signature
///
/// Contains:
/// - `randomness`: R value (n bytes)
/// - `fors_sig`: FORS signature
/// - `ht_sig`: Hypertree signature (d XMSS signatures)
#[derive(Clone)]
pub struct SlhDsaSignature<P: SlhDsaParams> {
    /// Signature data
    data: Vec<u8>,
    _params: PhantomData<P>,
}

impl<P: SlhDsaParams> SlhDsaSignature<P> {
    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != P::SIG_SIZE {
            return None;
        }
        Some(Self {
            data: bytes.to_vec(),
            _params: PhantomData,
        })
    }

    /// Get raw signature bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    /// Get signature size
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if signature is empty (should never be true for valid signatures)
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the randomness R (first n bytes)
    pub fn randomness(&self) -> &[u8] {
        &self.data[0..P::N]
    }
}

impl<P: SlhDsaParams> core::fmt::Debug for SlhDsaSignature<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SlhDsaSignature")
            .field("algorithm", &P::ALGORITHM)
            .field("size", &self.data.len())
            .finish()
    }
}

// ============================================================================
// Main Algorithm Implementation
// ============================================================================

/// SLH-DSA signature scheme
///
/// Generic over parameter set P and hash function H.
pub struct SlhDsa<P: SlhDsaParams, H: SlhDsaHash<P> = Sha2Hash<P>> {
    _params: PhantomData<P>,
    _hash: PhantomData<H>,
}

impl<P: SlhDsaParams, H: SlhDsaHash<P>> SlhDsa<P, H> {
    /// Generate a new keypair
    ///
    /// Uses secure random number generation for seed creation.
    pub fn generate_keypair() -> (SlhDsaSigningKey<P>, SlhDsaVerifyingKey<P>) {
        // Generate random seeds
        let mut sk_seed = vec![0u8; P::N];
        let mut sk_prf = vec![0u8; P::N];
        let mut pk_seed = vec![0u8; P::N];

        getrandom::getrandom(&mut sk_seed).expect("Failed to generate random sk_seed");
        getrandom::getrandom(&mut sk_prf).expect("Failed to generate random sk_prf");
        getrandom::getrandom(&mut pk_seed).expect("Failed to generate random pk_seed");

        Self::generate_keypair_from_seed(&sk_seed, &sk_prf, &pk_seed)
    }

    /// Generate keypair from specific seeds (for testing/KAT vectors)
    pub fn generate_keypair_from_seed(
        sk_seed: &[u8],
        sk_prf: &[u8],
        pk_seed: &[u8],
    ) -> (SlhDsaSigningKey<P>, SlhDsaVerifyingKey<P>) {
        // Compute pk_root by building the hypertree root
        let pk_root = Hypertree::<P, H>::ht_root(sk_seed, pk_seed);

        let sk = SlhDsaSigningKey::from_components(
            sk_seed.to_vec(),
            sk_prf.to_vec(),
            pk_seed.to_vec(),
            pk_root.clone(),
        )
        .expect("Invalid seed lengths");

        let vk =
            SlhDsaVerifyingKey::from_components(pk_seed.to_vec(), pk_root).expect("Invalid lengths");

        (sk, vk)
    }

    /// Sign a message (randomized - recommended for production)
    ///
    /// Uses fresh randomness for each signature to provide hedged security.
    pub fn sign(sk: &SlhDsaSigningKey<P>, message: &[u8]) -> SlhDsaSignature<P> {
        // Generate random opt_rand
        let mut opt_rand = vec![0u8; P::N];
        getrandom::getrandom(&mut opt_rand).expect("Failed to generate randomness");

        Self::sign_internal(sk, message, &opt_rand)
    }

    /// Sign a message (deterministic - for testing only)
    ///
    /// Uses pk_seed as opt_rand, producing deterministic signatures.
    /// **Warning**: Use randomized signing in production!
    pub fn sign_deterministic(sk: &SlhDsaSigningKey<P>, message: &[u8]) -> SlhDsaSignature<P> {
        Self::sign_internal(sk, message, sk.pk_seed())
    }

    /// Internal signing function
    fn sign_internal(
        sk: &SlhDsaSigningKey<P>,
        message: &[u8],
        opt_rand: &[u8],
    ) -> SlhDsaSignature<P> {
        // Step 1: Generate randomness R
        let r = H::prf_msg(sk.sk_prf(), opt_rand, message);

        // Step 2: Hash message to get digest for FORS and tree indices
        // digest = H_msg(R, PK.seed, PK.root, M)
        // digest length = (k*a + h + 7) / 8 bits
        let digest_len = (P::K * P::A + P::H + 7) / 8;
        let digest = H::h_msg(&r, sk.pk_seed(), sk.pk_root(), message, digest_len);

        // Step 3: Extract FORS message digest (k*a bits) and tree/leaf indices
        let fors_bits = P::K * P::A;
        let fors_bytes = (fors_bits + 7) / 8;
        let md = &digest[0..fors_bytes];

        // Extract tree index (h - h' bits) and leaf index (h' bits)
        let tree_bits = P::H - P::H_PRIME;
        let (idx_tree, idx_leaf) = Self::extract_indices(&digest[fors_bytes..], tree_bits, P::H_PRIME);

        // Step 4: Set up FORS address
        let mut fors_adrs = Address::new();
        fors_adrs.set_layer_address(0);
        fors_adrs.set_tree_address(idx_tree);
        fors_adrs.set_type(AddressType::ForsTree);
        fors_adrs.set_keypair_address(idx_leaf);

        // Step 5: Generate FORS signature
        let fors_sig = Fors::<P, H>::fors_sign(md, sk.sk_seed(), sk.pk_seed(), &fors_adrs);

        // Step 6: Compute FORS public key (to be signed by hypertree)
        let fors_pk = Fors::<P, H>::fors_pk_from_sig(md, &fors_sig, sk.pk_seed(), &fors_adrs);

        // Step 7: Generate hypertree signature
        let ht_sig = Hypertree::<P, H>::ht_sign(
            &fors_pk,
            sk.sk_seed(),
            sk.pk_seed(),
            idx_tree,
            idx_leaf,
        );

        // Step 8: Assemble signature: R || FORS_SIG || HT_SIG
        let mut data = Vec::with_capacity(P::SIG_SIZE);
        data.extend_from_slice(&r);
        data.extend_from_slice(&fors_sig.to_bytes());
        data.extend_from_slice(&ht_sig.to_bytes());

        SlhDsaSignature {
            data,
            _params: PhantomData,
        }
    }

    /// Extract tree and leaf indices from digest bytes
    fn extract_indices(bytes: &[u8], tree_bits: usize, leaf_bits: usize) -> (u64, u32) {
        let mut idx_tree: u64 = 0;
        let mut idx_leaf: u32 = 0;

        // Extract tree index (tree_bits bits)
        let mut bit_offset = 0;
        for i in 0..tree_bits {
            let byte_idx = (bit_offset + i) / 8;
            let bit_idx = 7 - ((bit_offset + i) % 8);
            if byte_idx < bytes.len() {
                let bit_val = ((bytes[byte_idx] >> bit_idx) & 1) as u64;
                idx_tree |= bit_val << (tree_bits - 1 - i);
            }
        }

        // Extract leaf index (leaf_bits bits)
        bit_offset = tree_bits;
        for i in 0..leaf_bits {
            let byte_idx = (bit_offset + i) / 8;
            let bit_idx = 7 - ((bit_offset + i) % 8);
            if byte_idx < bytes.len() {
                let bit_val = ((bytes[byte_idx] >> bit_idx) & 1) as u32;
                idx_leaf |= bit_val << (leaf_bits - 1 - i);
            }
        }

        (idx_tree, idx_leaf)
    }

    /// Verify a signature
    pub fn verify(
        vk: &SlhDsaVerifyingKey<P>,
        message: &[u8],
        sig: &SlhDsaSignature<P>,
    ) -> Result<(), SignatureError> {
        if sig.len() != P::SIG_SIZE {
            return Err(SignatureError::InvalidLength);
        }

        // Step 1: Extract R from signature
        let r = sig.randomness();

        // Step 2: Hash message to get digest
        let digest_len = (P::K * P::A + P::H + 7) / 8;
        let digest = H::h_msg(r, vk.pk_seed(), vk.pk_root(), message, digest_len);

        // Step 3: Extract FORS message digest and indices
        let fors_bits = P::K * P::A;
        let fors_bytes = (fors_bits + 7) / 8;
        let md = &digest[0..fors_bytes];

        let tree_bits = P::H - P::H_PRIME;
        let (idx_tree, idx_leaf) = Self::extract_indices(&digest[fors_bytes..], tree_bits, P::H_PRIME);

        // Step 4: Parse FORS and HT signatures from sig
        let fors_sig_start = P::N; // After R
        let fors_sig_size = fors::ForsSignature::<P>::size();
        let ht_sig_start = fors_sig_start + fors_sig_size;

        let fors_sig = match fors::ForsSignature::<P>::from_bytes(
            &sig.data[fors_sig_start..fors_sig_start + fors_sig_size],
        ) {
            Some(s) => s,
            None => return Err(SignatureError::InvalidSignature),
        };

        let ht_sig = match hypertree::HypertreeSignature::<P>::from_bytes(&sig.data[ht_sig_start..])
        {
            Some(s) => s,
            None => return Err(SignatureError::InvalidSignature),
        };

        // Step 5: Set up FORS address
        let mut fors_adrs = Address::new();
        fors_adrs.set_layer_address(0);
        fors_adrs.set_tree_address(idx_tree);
        fors_adrs.set_type(AddressType::ForsTree);
        fors_adrs.set_keypair_address(idx_leaf);

        // Step 6: Compute FORS public key from signature
        let fors_pk = Fors::<P, H>::fors_pk_from_sig(md, &fors_sig, vk.pk_seed(), &fors_adrs);

        // Step 7: Verify hypertree signature
        let ht_valid = Hypertree::<P, H>::ht_verify(
            &fors_pk,
            &ht_sig,
            vk.pk_seed(),
            idx_tree,
            idx_leaf,
            vk.pk_root(),
        );

        if !ht_valid {
            return Err(SignatureError::InvalidSignature);
        }

        Ok(())
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Signature verification error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// Signature has invalid length
    InvalidLength,
    /// Signature verification failed
    InvalidSignature,
    /// Public key is malformed
    InvalidPublicKey,
}

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignatureError::InvalidLength => write!(f, "invalid signature length"),
            SignatureError::InvalidSignature => write!(f, "signature verification failed"),
            SignatureError::InvalidPublicKey => write!(f, "invalid public key"),
        }
    }
}

// ============================================================================
// Type Aliases for Convenience
// ============================================================================

/// SLH-DSA with SHA2-128s parameters (small signatures)
pub type SlhDsaSha2_128s = SlhDsa<Sha2_128s, Sha2Hash<Sha2_128s>>;

/// SLH-DSA with SHA2-128f parameters (fast signing)
pub type SlhDsaSha2_128f = SlhDsa<Sha2_128f, Sha2Hash<Sha2_128f>>;

/// SLH-DSA with SHA2-192s parameters
pub type SlhDsaSha2_192s = SlhDsa<Sha2_192s, Sha2Hash<Sha2_192s>>;

/// SLH-DSA with SHA2-192f parameters
pub type SlhDsaSha2_192f = SlhDsa<Sha2_192f, Sha2Hash<Sha2_192f>>;

/// SLH-DSA with SHA2-256s parameters
pub type SlhDsaSha2_256s = SlhDsa<Sha2_256s, Sha2Hash<Sha2_256s>>;

/// SLH-DSA with SHA2-256f parameters
pub type SlhDsaSha2_256f = SlhDsa<Sha2_256f, Sha2Hash<Sha2_256f>>;

// Convenience aliases
/// Recommended 128-bit security variant (fast)
pub type SlhDsa128f = SlhDsaSha2_128f;
/// Recommended 128-bit security variant (small signatures)
pub type SlhDsa128s = SlhDsaSha2_128s;

#[cfg(test)]
mod tests;
