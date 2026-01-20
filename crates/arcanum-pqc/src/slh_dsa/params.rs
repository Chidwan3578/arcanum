//! SLH-DSA Parameter Sets (FIPS 205)
//!
//! This module defines the parameter sets for all SLH-DSA variants.
//! Parameters are compile-time constants using the `SlhDsaParams` trait.

#![allow(dead_code)]

/// Trait defining SLH-DSA parameter sets.
///
/// Each parameter set is a zero-sized type implementing this trait,
/// providing compile-time constants for the algorithm configuration.
pub trait SlhDsaParams: Clone + Copy + Default + 'static {
    /// Security parameter in bytes (n): 16, 24, or 32
    const N: usize;

    /// Total tree height (h)
    const H: usize;

    /// Number of hypertree layers (d)
    const D: usize;

    /// Height of each XMSS tree (h' = h/d)
    const H_PRIME: usize;

    /// FORS tree height (a)
    const A: usize;

    /// Number of FORS trees (k)
    const K: usize;

    /// Winternitz parameter (w) - always 16 for FIPS 205
    const W: usize = 16;

    /// WOTS+ signature length (len = len1 + len2)
    const WOTS_LEN: usize;

    /// Algorithm identifier string
    const ALGORITHM: &'static str;

    /// Security level in bits
    const SECURITY_LEVEL: usize;

    /// Signature size in bytes
    const SIG_SIZE: usize;

    /// Public key size in bytes (2n)
    const PK_SIZE: usize;

    /// Secret key size in bytes (4n)
    const SK_SIZE: usize;

    /// Whether this variant uses SHA-2 (true) or SHAKE (false)
    const USE_SHA2: bool;
}

// ============================================================================
// SHA-2 Based Parameter Sets
// ============================================================================

/// SLH-DSA-SHA2-128s: Small signatures, 128-bit security
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Sha2_128s;

impl SlhDsaParams for Sha2_128s {
    const N: usize = 16;
    const H: usize = 63;
    const D: usize = 7;
    const H_PRIME: usize = 9;
    const A: usize = 12;
    const K: usize = 14;
    const WOTS_LEN: usize = 35; // len1=32, len2=3
    const ALGORITHM: &'static str = "SLH-DSA-SHA2-128s";
    const SECURITY_LEVEL: usize = 128;
    const SIG_SIZE: usize = 7_856;
    const PK_SIZE: usize = 32;
    const SK_SIZE: usize = 64;
    const USE_SHA2: bool = true;
}

/// SLH-DSA-SHA2-128f: Fast signing, 128-bit security
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Sha2_128f;

impl SlhDsaParams for Sha2_128f {
    const N: usize = 16;
    const H: usize = 66;
    const D: usize = 22;
    const H_PRIME: usize = 3;
    const A: usize = 6;
    const K: usize = 33;
    const WOTS_LEN: usize = 35;
    const ALGORITHM: &'static str = "SLH-DSA-SHA2-128f";
    const SECURITY_LEVEL: usize = 128;
    const SIG_SIZE: usize = 17_088;
    const PK_SIZE: usize = 32;
    const SK_SIZE: usize = 64;
    const USE_SHA2: bool = true;
}

/// SLH-DSA-SHA2-192s: Small signatures, 192-bit security
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Sha2_192s;

impl SlhDsaParams for Sha2_192s {
    const N: usize = 24;
    const H: usize = 63;
    const D: usize = 7;
    const H_PRIME: usize = 9;
    const A: usize = 14;
    const K: usize = 17;
    const WOTS_LEN: usize = 51; // len1=48, len2=3
    const ALGORITHM: &'static str = "SLH-DSA-SHA2-192s";
    const SECURITY_LEVEL: usize = 192;
    const SIG_SIZE: usize = 16_224;
    const PK_SIZE: usize = 48;
    const SK_SIZE: usize = 96;
    const USE_SHA2: bool = true;
}

/// SLH-DSA-SHA2-192f: Fast signing, 192-bit security
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Sha2_192f;

impl SlhDsaParams for Sha2_192f {
    const N: usize = 24;
    const H: usize = 66;
    const D: usize = 22;
    const H_PRIME: usize = 3;
    const A: usize = 8;
    const K: usize = 33;
    const WOTS_LEN: usize = 51;
    const ALGORITHM: &'static str = "SLH-DSA-SHA2-192f";
    const SECURITY_LEVEL: usize = 192;
    const SIG_SIZE: usize = 35_664;
    const PK_SIZE: usize = 48;
    const SK_SIZE: usize = 96;
    const USE_SHA2: bool = true;
}

/// SLH-DSA-SHA2-256s: Small signatures, 256-bit security
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Sha2_256s;

impl SlhDsaParams for Sha2_256s {
    const N: usize = 32;
    const H: usize = 64;
    const D: usize = 8;
    const H_PRIME: usize = 8;
    const A: usize = 14;
    const K: usize = 22;
    const WOTS_LEN: usize = 67; // len1=64, len2=3
    const ALGORITHM: &'static str = "SLH-DSA-SHA2-256s";
    const SECURITY_LEVEL: usize = 256;
    const SIG_SIZE: usize = 29_792;
    const PK_SIZE: usize = 64;
    const SK_SIZE: usize = 128;
    const USE_SHA2: bool = true;
}

/// SLH-DSA-SHA2-256f: Fast signing, 256-bit security
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Sha2_256f;

impl SlhDsaParams for Sha2_256f {
    const N: usize = 32;
    const H: usize = 68;
    const D: usize = 17;
    const H_PRIME: usize = 4;
    const A: usize = 9;
    const K: usize = 35;
    const WOTS_LEN: usize = 67;
    const ALGORITHM: &'static str = "SLH-DSA-SHA2-256f";
    const SECURITY_LEVEL: usize = 256;
    const SIG_SIZE: usize = 49_856;
    const PK_SIZE: usize = 64;
    const SK_SIZE: usize = 128;
    const USE_SHA2: bool = true;
}

// ============================================================================
// SHAKE Based Parameter Sets (Phase 2)
// ============================================================================

/// SLH-DSA-SHAKE-128s: Small signatures, 128-bit security, SHAKE256
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Shake_128s;

impl SlhDsaParams for Shake_128s {
    const N: usize = 16;
    const H: usize = 63;
    const D: usize = 7;
    const H_PRIME: usize = 9;
    const A: usize = 12;
    const K: usize = 14;
    const WOTS_LEN: usize = 35;
    const ALGORITHM: &'static str = "SLH-DSA-SHAKE-128s";
    const SECURITY_LEVEL: usize = 128;
    const SIG_SIZE: usize = 7_856;
    const PK_SIZE: usize = 32;
    const SK_SIZE: usize = 64;
    const USE_SHA2: bool = false;
}

/// SLH-DSA-SHAKE-128f: Fast signing, 128-bit security, SHAKE256
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Shake_128f;

impl SlhDsaParams for Shake_128f {
    const N: usize = 16;
    const H: usize = 66;
    const D: usize = 22;
    const H_PRIME: usize = 3;
    const A: usize = 6;
    const K: usize = 33;
    const WOTS_LEN: usize = 35;
    const ALGORITHM: &'static str = "SLH-DSA-SHAKE-128f";
    const SECURITY_LEVEL: usize = 128;
    const SIG_SIZE: usize = 17_088;
    const PK_SIZE: usize = 32;
    const SK_SIZE: usize = 64;
    const USE_SHA2: bool = false;
}

// Additional SHAKE variants follow the same pattern...
// (Shake_192s, Shake_192f, Shake_256s, Shake_256f)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha2_128s_params() {
        assert_eq!(Sha2_128s::N, 16);
        assert_eq!(Sha2_128s::H, 63);
        assert_eq!(Sha2_128s::D, 7);
        assert_eq!(Sha2_128s::H_PRIME, 9);
        assert_eq!(Sha2_128s::H, Sha2_128s::D * Sha2_128s::H_PRIME);
        assert_eq!(Sha2_128s::PK_SIZE, 2 * Sha2_128s::N);
        assert_eq!(Sha2_128s::SK_SIZE, 4 * Sha2_128s::N);
    }

    #[test]
    fn test_sha2_128f_params() {
        assert_eq!(Sha2_128f::N, 16);
        assert_eq!(Sha2_128f::H, 66);
        assert_eq!(Sha2_128f::D, 22);
        assert_eq!(Sha2_128f::H_PRIME, 3);
        assert_eq!(Sha2_128f::H, Sha2_128f::D * Sha2_128f::H_PRIME);
    }

    #[test]
    fn test_sha2_192s_params() {
        assert_eq!(Sha2_192s::N, 24);
        assert_eq!(Sha2_192s::SECURITY_LEVEL, 192);
        assert_eq!(Sha2_192s::PK_SIZE, 48);
    }

    #[test]
    fn test_sha2_256s_params() {
        assert_eq!(Sha2_256s::N, 32);
        assert_eq!(Sha2_256s::SECURITY_LEVEL, 256);
        assert_eq!(Sha2_256s::PK_SIZE, 64);
    }

    #[test]
    fn test_all_variants_have_w_16() {
        assert_eq!(Sha2_128s::W, 16);
        assert_eq!(Sha2_128f::W, 16);
        assert_eq!(Sha2_192s::W, 16);
        assert_eq!(Sha2_192f::W, 16);
        assert_eq!(Sha2_256s::W, 16);
        assert_eq!(Sha2_256f::W, 16);
    }
}
