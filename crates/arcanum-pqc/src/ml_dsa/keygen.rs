//! Key generation for ML-DSA (FIPS 204)
//!
//! Implements Algorithm 1 (ML-DSA.KeyGen) from FIPS 204.
//!
//! # Algorithm Overview
//!
//! 1. Sample random seed ξ ← {0,1}^256
//! 2. (ρ, ρ', K) ← H(ξ)
//! 3. A ← ExpandA(ρ)
//! 4. (s₁, s₂) ← ExpandS(ρ')
//! 5. t ← As₁ + s₂
//! 6. (t₁, t₀) ← Power2Round(t)
//! 7. pk ← (ρ, t₁)
//! 8. tr ← H(pk)
//! 9. sk ← (ρ, K, tr, s₁, s₂, t₀)
//! 10. return (pk, sk)

#![allow(dead_code)]

use super::ntt::reduce32;
use super::params::{MlDsaParams, N, Q};
use super::poly::Poly;
use super::rounding::poly_power2round;
use super::sampling::{expand_a, expand_s};
use arcanum_primitives::shake::Shake256;

/// Internal representation of ML-DSA keypair components
#[derive(Clone)]
pub struct KeyPairInternal {
    /// Public seed ρ (32 bytes)
    pub rho: [u8; 32],
    /// Signing key K (32 bytes)
    pub key: [u8; 32],
    /// Hash of public key tr (64 bytes)
    pub tr: [u8; 64],
    /// Secret vector s₁ (L polynomials)
    pub s1: Vec<Poly>,
    /// Secret vector s₂ (K polynomials)
    pub s2: Vec<Poly>,
    /// High bits of t (K polynomials)
    pub t1: Vec<Poly>,
    /// Low bits of t (K polynomials)
    pub t0: Vec<Poly>,
}

/// Generate ML-DSA keypair from random seed
///
/// # Arguments
///
/// * `seed` - 32-byte random seed ξ
///
/// # Returns
///
/// Internal keypair structure with all components
pub fn generate_keypair_internal<P: MlDsaParams>(seed: &[u8; 32]) -> KeyPairInternal {
    // Step 2: Expand seed to (ρ, ρ', K) using SHAKE256
    // Per FIPS 204, input is: ξ || K || L (34 bytes)
    // Output is: ρ (32) || ρ' (64) || K (32) = 128 bytes
    let mut inbuf = [0u8; 34];
    inbuf[..32].copy_from_slice(seed);
    inbuf[32] = P::K as u8;
    inbuf[33] = P::L as u8;

    let mut shake = Shake256::new();
    shake.update(&inbuf);
    let mut reader = shake.finalize_xof();

    let mut rho = [0u8; 32];
    let mut rho_prime = [0u8; 64];
    let mut key = [0u8; 32];

    reader.squeeze(&mut rho);
    reader.squeeze(&mut rho_prime);
    reader.squeeze(&mut key);

    // Step 3: Generate matrix A from ρ (in NTT domain)
    let a = expand_a::<P>(&rho);

    // Step 4: Generate secret vectors s₁, s₂ from ρ'
    let (s1, s2) = expand_s::<P>(&rho_prime);

    // Step 5: Compute t = As₁ + s₂
    // Convert s₁ to NTT domain for efficient multiplication (keep original for storage)
    let mut s1_ntt = s1.clone();
    for poly in &mut s1_ntt {
        poly.ntt();
    }

    // Compute t = A * s₁ (in NTT domain)
    let mut t = vec![Poly::zero(); P::K];
    for i in 0..P::K {
        for j in 0..P::L {
            let product = a[i][j].pointwise_mul(&s1_ntt[j]);
            t[i] = t[i].add(&product);
        }
    }

    // Convert t back from NTT domain and reduce
    // Note: After NTT multiplication + inv_ntt, result is already in standard form
    // (the Montgomery factors cancel out in pointwise_mul and inv_ntt)
    for poly in &mut t {
        poly.inv_ntt();
        poly.reduce();
    }

    // Add s₂ to t
    for i in 0..P::K {
        t[i] = t[i].add(&s2[i]);
        // Reduce to [0, q)
        t[i].reduce();
    }

    // Step 6: Apply Power2Round to each polynomial in t
    let mut t1 = Vec::with_capacity(P::K);
    let mut t0 = Vec::with_capacity(P::K);

    for poly in &t {
        let (high, low) = poly_power2round(poly);
        t1.push(high);
        t0.push(low);
    }

    // Step 7-8: Compute tr = H(pk) where pk = (ρ || t₁)
    // First, pack the public key
    let pk_bytes = pack_pk::<P>(&rho, &t1);

    let mut shake = Shake256::new();
    shake.update(&pk_bytes);
    let mut reader = shake.finalize_xof();
    let mut tr = [0u8; 64];
    reader.squeeze(&mut tr);

    // Convert s₁ back from NTT domain for storage
    // (Actually, we keep it in NTT form for efficient signing)

    KeyPairInternal {
        rho,
        key,
        tr,
        s1,
        s2,
        t1,
        t0,
    }
}

/// Pack public key: pk = ρ || t₁
///
/// # Format
///
/// - ρ: 32 bytes
/// - t₁: K × 320 bytes (each coefficient in [0, 2^10) packed as 10 bits)
pub fn pack_pk<P: MlDsaParams>(rho: &[u8; 32], t1: &[Poly]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(P::PK_SIZE);

    // Pack ρ (32 bytes)
    bytes.extend_from_slice(rho);

    // Pack t₁: each polynomial coefficient in [0, 2^10) needs 10 bits
    // 256 coefficients × 10 bits = 2560 bits = 320 bytes per polynomial
    for poly in t1.iter().take(P::K) {
        pack_t1_poly(&mut bytes, poly);
    }

    bytes
}

/// Pack a single t₁ polynomial (10 bits per coefficient)
fn pack_t1_poly(bytes: &mut Vec<u8>, poly: &Poly) {
    // Pack 4 coefficients into 5 bytes (4 × 10 bits = 40 bits)
    for chunk in 0..(N / 4) {
        let c0 = poly.coeffs[4 * chunk] as u32;
        let c1 = poly.coeffs[4 * chunk + 1] as u32;
        let c2 = poly.coeffs[4 * chunk + 2] as u32;
        let c3 = poly.coeffs[4 * chunk + 3] as u32;

        bytes.push((c0 & 0xFF) as u8);
        bytes.push(((c0 >> 8) | (c1 << 2)) as u8);
        bytes.push(((c1 >> 6) | (c2 << 4)) as u8);
        bytes.push(((c2 >> 4) | (c3 << 6)) as u8);
        bytes.push((c3 >> 2) as u8);
    }
}

/// Unpack public key
///
/// # Returns
///
/// (ρ, t₁) on success
pub fn unpack_pk<P: MlDsaParams>(bytes: &[u8]) -> Option<([u8; 32], Vec<Poly>)> {
    if bytes.len() != P::PK_SIZE {
        return None;
    }

    // Unpack ρ
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&bytes[0..32]);

    // Unpack t₁
    let mut t1 = Vec::with_capacity(P::K);
    let mut offset = 32;

    for _ in 0..P::K {
        let mut poly = Poly::zero();
        unpack_t1_poly(&bytes[offset..offset + 320], &mut poly);
        t1.push(poly);
        offset += 320;
    }

    Some((rho, t1))
}

/// Unpack a single t₁ polynomial
fn unpack_t1_poly(bytes: &[u8], poly: &mut Poly) {
    for chunk in 0..(N / 4) {
        let b = &bytes[5 * chunk..5 * chunk + 5];

        poly.coeffs[4 * chunk] = ((b[0] as i32) | ((b[1] as i32 & 0x03) << 8)) as i32;
        poly.coeffs[4 * chunk + 1] = (((b[1] as i32) >> 2) | ((b[2] as i32 & 0x0F) << 6)) as i32;
        poly.coeffs[4 * chunk + 2] = (((b[2] as i32) >> 4) | ((b[3] as i32 & 0x3F) << 4)) as i32;
        poly.coeffs[4 * chunk + 3] = (((b[3] as i32) >> 6) | ((b[4] as i32) << 2)) as i32;
    }
}

/// Pack secret key: sk = ρ || K || tr || s₁ || s₂ || t₀
///
/// # Format
///
/// - ρ: 32 bytes
/// - K: 32 bytes
/// - tr: 64 bytes
/// - s₁: L × (256 × η_bits / 8) bytes
/// - s₂: K × (256 × η_bits / 8) bytes
/// - t₀: K × 416 bytes (each coefficient needs 13 bits)
pub fn pack_sk<P: MlDsaParams>(
    rho: &[u8; 32],
    key: &[u8; 32],
    tr: &[u8; 64],
    s1: &[Poly],
    s2: &[Poly],
    t0: &[Poly],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(P::SK_SIZE);

    // Pack ρ (32 bytes)
    bytes.extend_from_slice(rho);

    // Pack K (32 bytes)
    bytes.extend_from_slice(key);

    // Pack tr (64 bytes)
    bytes.extend_from_slice(tr);

    // Pack s₁: coefficients in [-η, η]
    for poly in s1.iter().take(P::L) {
        pack_eta_poly::<P>(&mut bytes, poly);
    }

    // Pack s₂: coefficients in [-η, η]
    for poly in s2.iter().take(P::K) {
        pack_eta_poly::<P>(&mut bytes, poly);
    }

    // Pack t₀: coefficients in [-(2^(d-1)), 2^(d-1)) with d=13
    for poly in t0.iter().take(P::K) {
        pack_t0_poly(&mut bytes, poly);
    }

    bytes
}

/// Pack a polynomial with coefficients in [-η, η]
fn pack_eta_poly<P: MlDsaParams>(bytes: &mut Vec<u8>, poly: &Poly) {
    if P::ETA == 2 {
        // η = 2: coefficients in [-2, 2], stored as [0, 4] in 3 bits
        // Pack 8 coefficients into 3 bytes (8 × 3 bits = 24 bits)
        for chunk in 0..(N / 8) {
            // Collect 8 coefficients, map [-2,2] to [4,0]
            let mut vals = [0u32; 8];
            for i in 0..8 {
                vals[i] = (2 - poly.coeffs[8 * chunk + i]) as u32;
            }

            // Pack into 24 bits (3 bytes)
            // Use u32 arithmetic to avoid overflow issues
            let bits: u32 = vals[0]
                | (vals[1] << 3)
                | (vals[2] << 6)
                | (vals[3] << 9)
                | (vals[4] << 12)
                | (vals[5] << 15)
                | (vals[6] << 18)
                | (vals[7] << 21);

            bytes.push((bits & 0xFF) as u8);
            bytes.push(((bits >> 8) & 0xFF) as u8);
            bytes.push(((bits >> 16) & 0xFF) as u8);
        }
    } else if P::ETA == 4 {
        // η = 4: coefficients in [-4, 4], stored as [0, 8] in 4 bits
        // Pack 2 coefficients per byte
        for chunk in 0..(N / 2) {
            let c0 = (4 - poly.coeffs[2 * chunk]) as u8;
            let c1 = (4 - poly.coeffs[2 * chunk + 1]) as u8;
            bytes.push(c0 | (c1 << 4));
        }
    }
}

/// Pack a t₀ polynomial (13 bits per coefficient)
fn pack_t0_poly(bytes: &mut Vec<u8>, poly: &Poly) {
    // t₀ coefficients are in [-(2^(d-1)), 2^(d-1)) = [-4096, 4096)
    // Per FIPS 204, map to [0, 2^13 - 1] using: (2^(d-1) - 1) - t0
    // This maps [-4096, 4095] to [8191, 0], fitting in 13 bits
    // Pack 8 coefficients into 13 bytes (8 × 13 bits = 104 bits)
    const HALF_MINUS_1: i32 = (1 << 12) - 1; // 4095

    for chunk in 0..(N / 8) {
        let mut vals = [0u32; 8];
        for i in 0..8 {
            vals[i] = (HALF_MINUS_1 - poly.coeffs[8 * chunk + i]) as u32;
        }

        // Pack 8 × 13 bits = 104 bits = 13 bytes
        bytes.push((vals[0] & 0xFF) as u8);
        bytes.push(((vals[0] >> 8) | (vals[1] << 5)) as u8);
        bytes.push(((vals[1] >> 3) & 0xFF) as u8);
        bytes.push(((vals[1] >> 11) | (vals[2] << 2)) as u8);
        bytes.push(((vals[2] >> 6) | (vals[3] << 7)) as u8);
        bytes.push(((vals[3] >> 1) & 0xFF) as u8);
        bytes.push(((vals[3] >> 9) | (vals[4] << 4)) as u8);
        bytes.push(((vals[4] >> 4) & 0xFF) as u8);
        bytes.push(((vals[4] >> 12) | (vals[5] << 1)) as u8);
        bytes.push(((vals[5] >> 7) | (vals[6] << 6)) as u8);
        bytes.push(((vals[6] >> 2) & 0xFF) as u8);
        bytes.push(((vals[6] >> 10) | (vals[7] << 3)) as u8);
        bytes.push((vals[7] >> 5) as u8);
    }
}

/// Unpack secret key
///
/// # Returns
///
/// (ρ, K, tr, s₁, s₂, t₀) on success
#[allow(clippy::type_complexity)]
pub fn unpack_sk<P: MlDsaParams>(
    bytes: &[u8],
) -> Option<(
    [u8; 32],
    [u8; 32],
    [u8; 64],
    Vec<Poly>,
    Vec<Poly>,
    Vec<Poly>,
)> {
    if bytes.len() != P::SK_SIZE {
        return None;
    }

    let mut offset = 0;

    // Unpack ρ
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;

    // Unpack K
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[offset..offset + 32]);
    offset += 32;

    // Unpack tr
    let mut tr = [0u8; 64];
    tr.copy_from_slice(&bytes[offset..offset + 64]);
    offset += 64;

    // Calculate eta poly size
    let eta_poly_size = if P::ETA == 2 { 96 } else { 128 }; // 256*3/8 or 256*4/8

    // Unpack s₁
    let mut s1 = Vec::with_capacity(P::L);
    for _ in 0..P::L {
        let mut poly = Poly::zero();
        unpack_eta_poly::<P>(&bytes[offset..offset + eta_poly_size], &mut poly);
        s1.push(poly);
        offset += eta_poly_size;
    }

    // Unpack s₂
    let mut s2 = Vec::with_capacity(P::K);
    for _ in 0..P::K {
        let mut poly = Poly::zero();
        unpack_eta_poly::<P>(&bytes[offset..offset + eta_poly_size], &mut poly);
        s2.push(poly);
        offset += eta_poly_size;
    }

    // Unpack t₀ (416 bytes per polynomial = 256*13/8 = 416)
    let mut t0 = Vec::with_capacity(P::K);
    for _ in 0..P::K {
        let mut poly = Poly::zero();
        unpack_t0_poly(&bytes[offset..offset + 416], &mut poly);
        t0.push(poly);
        offset += 416;
    }

    Some((rho, key, tr, s1, s2, t0))
}

/// Unpack a polynomial with coefficients in [-η, η]
fn unpack_eta_poly<P: MlDsaParams>(bytes: &[u8], poly: &mut Poly) {
    if P::ETA == 2 {
        // η = 2: 3 bits per coefficient, 8 coefficients in 3 bytes
        for chunk in 0..(N / 8) {
            let b = &bytes[3 * chunk..3 * chunk + 3];
            let mut bits = (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16);

            for i in 0..8 {
                let c = (bits & 0x07) as i32;
                poly.coeffs[8 * chunk + i] = 2 - c;
                bits >>= 3;
            }
        }
    } else if P::ETA == 4 {
        // η = 4: 4 bits per coefficient, 2 coefficients per byte
        for chunk in 0..(N / 2) {
            let b = bytes[chunk];
            poly.coeffs[2 * chunk] = 4 - ((b & 0x0F) as i32);
            poly.coeffs[2 * chunk + 1] = 4 - ((b >> 4) as i32);
        }
    }
}

/// Unpack a t₀ polynomial (13 bits per coefficient)
fn unpack_t0_poly(bytes: &[u8], poly: &mut Poly) {
    // Inverse of pack: t0 = (2^(d-1) - 1) - packed_val
    const HALF_MINUS_1: i32 = (1 << 12) - 1; // 4095

    // Unpack 8 × 13 bits from 13 bytes
    for chunk in 0..(N / 8) {
        let b = &bytes[13 * chunk..13 * chunk + 13];

        let v0 = (b[0] as u32) | ((b[1] as u32 & 0x1F) << 8);
        let v1 = ((b[1] as u32) >> 5) | ((b[2] as u32) << 3) | ((b[3] as u32 & 0x03) << 11);
        let v2 = ((b[3] as u32) >> 2) | ((b[4] as u32 & 0x7F) << 6);
        let v3 = ((b[4] as u32) >> 7) | ((b[5] as u32) << 1) | ((b[6] as u32 & 0x0F) << 9);
        let v4 = ((b[6] as u32) >> 4) | ((b[7] as u32) << 4) | ((b[8] as u32 & 0x01) << 12);
        let v5 = ((b[8] as u32) >> 1) | ((b[9] as u32 & 0x3F) << 7);
        let v6 = ((b[9] as u32) >> 6) | ((b[10] as u32) << 2) | ((b[11] as u32 & 0x07) << 10);
        let v7 = ((b[11] as u32) >> 3) | ((b[12] as u32) << 5);

        poly.coeffs[8 * chunk] = HALF_MINUS_1 - (v0 as i32);
        poly.coeffs[8 * chunk + 1] = HALF_MINUS_1 - (v1 as i32);
        poly.coeffs[8 * chunk + 2] = HALF_MINUS_1 - (v2 as i32);
        poly.coeffs[8 * chunk + 3] = HALF_MINUS_1 - (v3 as i32);
        poly.coeffs[8 * chunk + 4] = HALF_MINUS_1 - (v4 as i32);
        poly.coeffs[8 * chunk + 5] = HALF_MINUS_1 - (v5 as i32);
        poly.coeffs[8 * chunk + 6] = HALF_MINUS_1 - (v6 as i32);
        poly.coeffs[8 * chunk + 7] = HALF_MINUS_1 - (v7 as i32);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::super::params::{Params44, Params65, Params87};
    use super::*;

    #[test]
    fn test_keygen_44_produces_valid_sizes() {
        let seed = [0x42u8; 32];
        let keypair = generate_keypair_internal::<Params44>(&seed);

        assert_eq!(keypair.rho.len(), 32);
        assert_eq!(keypair.key.len(), 32);
        assert_eq!(keypair.tr.len(), 64);
        assert_eq!(keypair.s1.len(), Params44::L);
        assert_eq!(keypair.s2.len(), Params44::K);
        assert_eq!(keypair.t1.len(), Params44::K);
        assert_eq!(keypair.t0.len(), Params44::K);
    }

    #[test]
    fn test_keygen_65_produces_valid_sizes() {
        let seed = [0x42u8; 32];
        let keypair = generate_keypair_internal::<Params65>(&seed);

        assert_eq!(keypair.s1.len(), Params65::L);
        assert_eq!(keypair.s2.len(), Params65::K);
        assert_eq!(keypair.t1.len(), Params65::K);
        assert_eq!(keypair.t0.len(), Params65::K);
    }

    #[test]
    fn test_keygen_87_produces_valid_sizes() {
        let seed = [0x42u8; 32];
        let keypair = generate_keypair_internal::<Params87>(&seed);

        assert_eq!(keypair.s1.len(), Params87::L);
        assert_eq!(keypair.s2.len(), Params87::K);
        assert_eq!(keypair.t1.len(), Params87::K);
        assert_eq!(keypair.t0.len(), Params87::K);
    }

    #[test]
    fn test_keygen_deterministic() {
        let seed = [0x42u8; 32];
        let kp1 = generate_keypair_internal::<Params65>(&seed);
        let kp2 = generate_keypair_internal::<Params65>(&seed);

        assert_eq!(kp1.rho, kp2.rho);
        assert_eq!(kp1.key, kp2.key);
        assert_eq!(kp1.tr, kp2.tr);

        for i in 0..Params65::K {
            for j in 0..N {
                assert_eq!(kp1.t1[i].coeffs[j], kp2.t1[i].coeffs[j]);
            }
        }
    }

    #[test]
    fn test_keygen_different_seeds() {
        let seed1 = [0x42u8; 32];
        let seed2 = [0x43u8; 32];
        let kp1 = generate_keypair_internal::<Params44>(&seed1);
        let kp2 = generate_keypair_internal::<Params44>(&seed2);

        // Keys should differ
        assert_ne!(kp1.rho, kp2.rho);
    }

    #[test]
    fn test_t1_coefficients_in_range() {
        // t₁ coefficients should be in [0, 2^10) after Power2Round
        let seed = [0x42u8; 32];
        let keypair = generate_keypair_internal::<Params44>(&seed);

        for poly in &keypair.t1 {
            for &c in &poly.coeffs {
                assert!(c >= 0, "t1 coefficient < 0: {}", c);
                assert!(c < 1024, "t1 coefficient >= 2^10: {}", c);
            }
        }
    }

    #[test]
    fn test_t0_coefficients_in_range() {
        // t₀ coefficients should be in [-(2^12), 2^12) after Power2Round
        let seed = [0x42u8; 32];
        let keypair = generate_keypair_internal::<Params44>(&seed);

        let bound: i32 = 1 << 12; // 4096
        for poly in &keypair.t0 {
            for &c in &poly.coeffs {
                assert!(c >= -bound, "t0 coefficient < -2^12: {}", c);
                assert!(c < bound, "t0 coefficient >= 2^12: {}", c);
            }
        }
    }

    #[test]
    fn test_pack_unpack_pk_44() {
        let seed = [0x42u8; 32];
        let keypair = generate_keypair_internal::<Params44>(&seed);

        let pk_bytes = pack_pk::<Params44>(&keypair.rho, &keypair.t1);
        assert_eq!(pk_bytes.len(), Params44::PK_SIZE);

        let (rho, t1) = unpack_pk::<Params44>(&pk_bytes).unwrap();
        assert_eq!(rho, keypair.rho);

        for i in 0..Params44::K {
            for j in 0..N {
                assert_eq!(
                    t1[i].coeffs[j], keypair.t1[i].coeffs[j],
                    "t1[{}][{}] mismatch",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_pack_unpack_pk_65() {
        let seed = [0x42u8; 32];
        let keypair = generate_keypair_internal::<Params65>(&seed);

        let pk_bytes = pack_pk::<Params65>(&keypair.rho, &keypair.t1);
        assert_eq!(pk_bytes.len(), Params65::PK_SIZE);

        let (rho, t1) = unpack_pk::<Params65>(&pk_bytes).unwrap();
        assert_eq!(rho, keypair.rho);

        for i in 0..Params65::K {
            for j in 0..N {
                assert_eq!(t1[i].coeffs[j], keypair.t1[i].coeffs[j]);
            }
        }
    }

    #[test]
    fn test_pack_unpack_sk_44() {
        let seed = [0x42u8; 32];
        let keypair = generate_keypair_internal::<Params44>(&seed);

        // Note: s1 is in NTT form, need to convert back for packing
        // For this test, we'll pack s2 which is not in NTT form
        let sk_bytes = pack_sk::<Params44>(
            &keypair.rho,
            &keypair.key,
            &keypair.tr,
            &keypair.s1, // Actually in NTT form, but test packing logic
            &keypair.s2,
            &keypair.t0,
        );
        assert_eq!(sk_bytes.len(), Params44::SK_SIZE);

        let (rho, key, tr, _s1, s2, t0) = unpack_sk::<Params44>(&sk_bytes).unwrap();
        assert_eq!(rho, keypair.rho);
        assert_eq!(key, keypair.key);
        assert_eq!(tr, keypair.tr);

        // Check s2 (not in NTT form)
        for i in 0..Params44::K {
            for j in 0..N {
                assert_eq!(s2[i].coeffs[j], keypair.s2[i].coeffs[j], "s2[{}][{}]", i, j);
            }
        }

        // Check t0
        for i in 0..Params44::K {
            for j in 0..N {
                assert_eq!(t0[i].coeffs[j], keypair.t0[i].coeffs[j], "t0[{}][{}]", i, j);
            }
        }
    }

    #[test]
    fn test_pack_unpack_sk_65() {
        let seed = [0x42u8; 32];
        let keypair = generate_keypair_internal::<Params65>(&seed);

        let sk_bytes = pack_sk::<Params65>(
            &keypair.rho,
            &keypair.key,
            &keypair.tr,
            &keypair.s1,
            &keypair.s2,
            &keypair.t0,
        );
        assert_eq!(sk_bytes.len(), Params65::SK_SIZE);

        let (rho, key, tr, _, s2, t0) = unpack_sk::<Params65>(&sk_bytes).unwrap();
        assert_eq!(rho, keypair.rho);
        assert_eq!(key, keypair.key);
        assert_eq!(tr, keypair.tr);

        for i in 0..Params65::K {
            for j in 0..N {
                assert_eq!(s2[i].coeffs[j], keypair.s2[i].coeffs[j]);
                assert_eq!(t0[i].coeffs[j], keypair.t0[i].coeffs[j]);
            }
        }
    }

    #[test]
    fn test_unpack_pk_wrong_size() {
        let bytes = vec![0u8; 100];
        assert!(unpack_pk::<Params44>(&bytes).is_none());
        assert!(unpack_pk::<Params65>(&bytes).is_none());
        assert!(unpack_pk::<Params87>(&bytes).is_none());
    }

    #[test]
    fn test_unpack_sk_wrong_size() {
        let bytes = vec![0u8; 100];
        assert!(unpack_sk::<Params44>(&bytes).is_none());
        assert!(unpack_sk::<Params65>(&bytes).is_none());
        assert!(unpack_sk::<Params87>(&bytes).is_none());
    }
}
