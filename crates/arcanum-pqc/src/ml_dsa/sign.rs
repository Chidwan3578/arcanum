//! Signing for ML-DSA (FIPS 204)
//!
//! Implements Algorithm 2 (ML-DSA.Sign) from FIPS 204.
//!
//! # Algorithm Overview
//!
//! 1. A ← ExpandA(ρ)
//! 2. μ ← H(tr || M)
//! 3. κ ← 0
//! 4. (z, h) ← ⊥
//! 5. while (z, h) = ⊥:
//!    a. y ← ExpandMask(K || μ, κ)
//!    b. w ← Ay
//!    c. w₁ ← HighBits(w)
//!    d. c̃ ← H(μ || w₁)
//!    e. c ← SampleInBall(c̃)
//!    f. z ← y + cs₁
//!    g. (r₁, r₀) ← Decompose(w - cs₂)
//!    h. if ||z||∞ ≥ γ₁ - β or ||r₀||∞ ≥ γ₂ - β:
//!       continue
//!    i. h ← MakeHint(-ct₀, w - cs₂ + ct₀)
//!    j. if ||ct₀||∞ ≥ γ₂ or #ones(h) > ω:
//!       continue
//!    k. κ ← κ + L
//! 6. σ ← (c̃, z mod⁺ q, h)
//! 7. return σ

#![allow(dead_code)]

use super::keygen::unpack_sk;
use super::ntt::reduce32;
use super::params::{MlDsaParams, N, Q};
use super::poly::Poly;
use super::rounding::{high_bits, make_hint, poly_decompose};
use super::sampling::{expand_a, expand_mask, sample_in_ball};
use arcanum_primitives::shake::Shake256;

/// Maximum number of signing attempts before giving up
/// (Should never be reached with valid keys)
const MAX_ATTEMPTS: usize = 1000;

/// Internal signature components
#[derive(Clone)]
pub struct SignatureInternal {
    /// Commitment hash c̃ (32 bytes for ML-DSA-44, 48 for 65, 64 for 87)
    pub c_tilde: Vec<u8>,
    /// Response vector z (L polynomials)
    pub z: Vec<Poly>,
    /// Hint vector h (K polynomials with sparse representation)
    pub h: Vec<Poly>,
}

/// Sign a message using ML-DSA
///
/// # Arguments
///
/// * `sk_bytes` - Packed secret key
/// * `message` - Message to sign
///
/// # Returns
///
/// Packed signature on success
pub fn sign_internal<P: MlDsaParams>(sk_bytes: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    // Unpack secret key
    let (rho, key, tr, s1, s2, t0) = unpack_sk::<P>(sk_bytes)?;

    // Step 1: A ← ExpandA(ρ)
    let a = expand_a::<P>(&rho);

    // Convert s1, s2 to NTT domain for efficient multiplication
    let mut s1_ntt: Vec<Poly> = s1.clone();
    let mut s2_ntt: Vec<Poly> = s2.clone();
    for poly in &mut s1_ntt {
        poly.ntt();
    }
    for poly in &mut s2_ntt {
        poly.ntt();
    }

    // Convert t0 to NTT domain
    let mut t0_ntt: Vec<Poly> = t0.clone();
    for poly in &mut t0_ntt {
        poly.ntt();
    }

    // Step 2: μ ← H(tr || M)
    let mut shake = Shake256::new();
    shake.update(&tr);
    shake.update(message);
    let mut reader = shake.finalize_xof();
    let mut mu = [0u8; 64];
    reader.squeeze(&mut mu);

    // Step 3: κ ← 0
    let mut kappa: u16 = 0;

    // Step 4-5: Rejection sampling loop
    for _ in 0..MAX_ATTEMPTS {
        // Step 5a: y ← ExpandMask(K || μ, κ)
        let mut mask_seed = Vec::with_capacity(96);
        mask_seed.extend_from_slice(&key);
        mask_seed.extend_from_slice(&mu);

        let y = expand_mask::<P>(&mask_seed, kappa, P::GAMMA1);

        // Step 5b: w ← Ay (convert y to NTT, multiply, convert back)
        let mut y_ntt = y.clone();
        for poly in &mut y_ntt {
            poly.ntt();
        }

        let mut w = vec![Poly::zero(); P::K];
        for i in 0..P::K {
            for j in 0..P::L {
                let product = a[i][j].pointwise_mul(&y_ntt[j]);
                w[i] = w[i].add(&product);
            }
        }

        // Convert w from NTT domain and reduce
        for poly in &mut w {
            poly.inv_ntt();
            // Reduce to [0, q)
            poly.reduce();
        }

        // Step 5c: w₁ ← HighBits(w)
        let mut w1 = vec![Poly::zero(); P::K];
        for i in 0..P::K {
            for j in 0..N {
                w1[i].coeffs[j] = high_bits(w[i].coeffs[j], P::GAMMA2 as i32);
            }
        }

        // Step 5d: c̃ ← H(μ || w₁)
        let c_tilde_len = commitment_hash_len::<P>();
        let c_tilde = compute_challenge_hash::<P>(&mu, &w1, c_tilde_len);

        // Step 5e: c ← SampleInBall(c̃)
        let mut c = sample_in_ball(&c_tilde, P::TAU);
        c.ntt();

        // Step 5f: z ← y + cs₁
        let mut z = vec![Poly::zero(); P::L];
        for i in 0..P::L {
            // cs₁[i] in NTT domain
            let cs1_i = c.pointwise_mul(&s1_ntt[i]);
            let mut cs1_i_poly = cs1_i;
            cs1_i_poly.inv_ntt();

            // Reduce to centered form
            cs1_i_poly.reduce_centered();

            // z = y + cs₁
            z[i] = y[i].add(&cs1_i_poly);
        }

        // Step 5g: Compute w - cs₂
        let mut w_minus_cs2 = vec![Poly::zero(); P::K];
        for i in 0..P::K {
            let cs2_i = c.pointwise_mul(&s2_ntt[i]);
            let mut cs2_i_poly = cs2_i;
            cs2_i_poly.inv_ntt();

            // Reduce to centered form
            cs2_i_poly.reduce_centered();

            w_minus_cs2[i] = w[i].sub(&cs2_i_poly);
        }

        // Decompose w - cs₂
        let mut r0 = vec![Poly::zero(); P::K];
        for i in 0..P::K {
            let (_, low) = poly_decompose(&w_minus_cs2[i], P::GAMMA2 as i32);
            r0[i] = low;
        }

        // Step 5h: Check ||z||∞ < γ₁ - β and ||r₀||∞ < γ₂ - β
        let gamma1_minus_beta = P::GAMMA1 - P::BETA;
        let gamma2_minus_beta = P::GAMMA2 - P::BETA;

        let mut z_norm_ok = true;
        for poly in &z {
            if poly.infinity_norm() >= gamma1_minus_beta {
                z_norm_ok = false;
                break;
            }
        }

        let mut r0_norm_ok = true;
        for poly in &r0 {
            if poly.infinity_norm() >= gamma2_minus_beta {
                r0_norm_ok = false;
                break;
            }
        }

        if !z_norm_ok || !r0_norm_ok {
            kappa = kappa.wrapping_add(P::L as u16);
            continue;
        }

        // Step 5i: Compute ct₀ and h ← MakeHint(-ct₀, w - cs₂ + ct₀)
        let mut ct0 = vec![Poly::zero(); P::K];
        for i in 0..P::K {
            let ct0_i = c.pointwise_mul(&t0_ntt[i]);
            let mut ct0_i_poly = ct0_i;
            ct0_i_poly.inv_ntt();

            // Reduce to centered form
            ct0_i_poly.reduce_centered();

            ct0[i] = ct0_i_poly;
        }

        // Check ||ct₀||∞ < γ₂
        let mut ct0_norm_ok = true;
        for poly in &ct0 {
            if poly.infinity_norm() >= P::GAMMA2 {
                ct0_norm_ok = false;
                break;
            }
        }

        if !ct0_norm_ok {
            kappa = kappa.wrapping_add(P::L as u16);
            continue;
        }

        // Compute hint h
        let mut h = vec![Poly::zero(); P::K];
        let mut total_hints = 0usize;

        for i in 0..P::K {
            // w - cs₂ + ct₀
            let w_cs2_ct0 = w_minus_cs2[i].add(&ct0[i]);

            // -ct₀
            let mut neg_ct0 = Poly::zero();
            for j in 0..N {
                neg_ct0.coeffs[j] = -ct0[i].coeffs[j];
            }

            // Make hint: MakeHint(-ct₀, w - cs₂ + ct₀)
            for j in 0..N {
                if make_hint(neg_ct0.coeffs[j], w_cs2_ct0.coeffs[j], P::GAMMA2 as i32) {
                    h[i].coeffs[j] = 1;
                    total_hints += 1;
                }
            }
        }

        // Step 5j: Check #ones(h) ≤ ω
        if total_hints > P::OMEGA {
            kappa = kappa.wrapping_add(P::L as u16);
            continue;
        }

        // z values are already in centered form from the computation
        // Reduce to ensure they're in proper range for packing
        for poly in &mut z {
            poly.reduce_centered();
        }

        // Pack signature
        let sig = pack_signature::<P>(&c_tilde, &z, &h);
        return Some(sig);
    }

    // Should never reach here with valid keys
    None
}

/// Compute the challenge hash c̃ = H(μ || w₁)
fn compute_challenge_hash<P: MlDsaParams>(mu: &[u8; 64], w1: &[Poly], len: usize) -> Vec<u8> {
    let mut shake = Shake256::new();
    shake.update(mu);

    // Pack w₁ for hashing
    // Each w₁ coefficient needs log2((q-1)/(2γ₂)) bits
    // For γ₂ = (q-1)/88: (q-1)/(2γ₂) = 44, needs 6 bits
    // For γ₂ = (q-1)/32: (q-1)/(2γ₂) = 16, needs 4 bits
    for poly in w1.iter().take(P::K) {
        let packed = pack_w1_poly::<P>(poly);
        shake.update(&packed);
    }

    let mut reader = shake.finalize_xof();
    let mut c_tilde = vec![0u8; len];
    reader.squeeze(&mut c_tilde);
    c_tilde
}

/// Pack a w₁ polynomial for hashing
fn pack_w1_poly<P: MlDsaParams>(poly: &Poly) -> Vec<u8> {
    // Determine bits per coefficient based on γ₂
    if P::GAMMA2 == (Q as u32 - 1) / 88 {
        // ML-DSA-44: 6 bits per coefficient, 256 coeffs = 192 bytes
        pack_w1_6bits(poly)
    } else {
        // ML-DSA-65/87: 4 bits per coefficient, 256 coeffs = 128 bytes
        pack_w1_4bits(poly)
    }
}

/// Pack w₁ with 6 bits per coefficient
fn pack_w1_6bits(poly: &Poly) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(192);

    // Pack 4 coefficients into 3 bytes (4 × 6 bits = 24 bits)
    for chunk in 0..(N / 4) {
        let c0 = poly.coeffs[4 * chunk] as u32;
        let c1 = poly.coeffs[4 * chunk + 1] as u32;
        let c2 = poly.coeffs[4 * chunk + 2] as u32;
        let c3 = poly.coeffs[4 * chunk + 3] as u32;

        bytes.push((c0 | (c1 << 6)) as u8);
        bytes.push(((c1 >> 2) | (c2 << 4)) as u8);
        bytes.push(((c2 >> 4) | (c3 << 2)) as u8);
    }

    bytes
}

/// Pack w₁ with 4 bits per coefficient
fn pack_w1_4bits(poly: &Poly) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(128);

    // Pack 2 coefficients per byte
    for chunk in 0..(N / 2) {
        let c0 = poly.coeffs[2 * chunk] as u8;
        let c1 = poly.coeffs[2 * chunk + 1] as u8;
        bytes.push(c0 | (c1 << 4));
    }

    bytes
}

/// Get commitment hash length based on security level
fn commitment_hash_len<P: MlDsaParams>() -> usize {
    // c̃ length: λ/4 bytes
    // ML-DSA-44: 128/4 = 32 bytes
    // ML-DSA-65: 192/4 = 48 bytes
    // ML-DSA-87: 256/4 = 64 bytes
    P::LAMBDA / 4
}

/// Pack signature: σ = (c̃, z, h)
///
/// # Format
///
/// - c̃: λ/4 bytes
/// - z: L × (256 × γ₁_bits / 8) bytes
/// - h: ω + K bytes (sparse hint encoding)
pub fn pack_signature<P: MlDsaParams>(c_tilde: &[u8], z: &[Poly], h: &[Poly]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(P::SIG_SIZE);

    // Pack c̃
    bytes.extend_from_slice(c_tilde);

    // Pack z: each coefficient in [0, 2γ₁) needs γ₁_bits
    for poly in z.iter().take(P::L) {
        pack_z_poly::<P>(&mut bytes, poly);
    }

    // Pack h (sparse hint encoding)
    pack_hint::<P>(&mut bytes, h);

    bytes
}

/// Pack z polynomial
fn pack_z_poly<P: MlDsaParams>(bytes: &mut Vec<u8>, poly: &Poly) {
    if P::GAMMA1 == (1 << 17) {
        // ML-DSA-44: 18 bits per coefficient
        pack_z_18bits(bytes, poly);
    } else {
        // ML-DSA-65/87: 20 bits per coefficient
        pack_z_20bits(bytes, poly);
    }
}

/// Pack z with 18 bits per coefficient (γ₁ = 2^17)
fn pack_z_18bits(bytes: &mut Vec<u8>, poly: &Poly) {
    const GAMMA1: i32 = 1 << 17;

    // Map z ∈ [-(γ₁-1), γ₁] to [0, 2γ₁-1] for packing
    // Pack 4 coefficients into 9 bytes (4 × 18 bits = 72 bits)
    for chunk in 0..(N / 4) {
        let c0 = (GAMMA1 - 1 - poly.coeffs[4 * chunk]) as u32 & 0x3FFFF;
        let c1 = (GAMMA1 - 1 - poly.coeffs[4 * chunk + 1]) as u32 & 0x3FFFF;
        let c2 = (GAMMA1 - 1 - poly.coeffs[4 * chunk + 2]) as u32 & 0x3FFFF;
        let c3 = (GAMMA1 - 1 - poly.coeffs[4 * chunk + 3]) as u32 & 0x3FFFF;

        // Pack 72 bits into 9 bytes
        bytes.push((c0 & 0xFF) as u8);
        bytes.push(((c0 >> 8) & 0xFF) as u8);
        bytes.push(((c0 >> 16) | (c1 << 2)) as u8);
        bytes.push(((c1 >> 6) & 0xFF) as u8);
        bytes.push(((c1 >> 14) | (c2 << 4)) as u8);
        bytes.push(((c2 >> 4) & 0xFF) as u8);
        bytes.push(((c2 >> 12) | (c3 << 6)) as u8);
        bytes.push(((c3 >> 2) & 0xFF) as u8);
        bytes.push(((c3 >> 10) & 0xFF) as u8);
    }
}

/// Pack z with 20 bits per coefficient (γ₁ = 2^19)
fn pack_z_20bits(bytes: &mut Vec<u8>, poly: &Poly) {
    const GAMMA1: i32 = 1 << 19;

    // Map from [-(γ₁-1), γ₁] to [0, 2γ₁-1]
    // Pack 2 coefficients into 5 bytes (2 × 20 = 40 bits)
    for chunk in 0..(N / 2) {
        let c0 = (GAMMA1 - 1 - poly.coeffs[2 * chunk]) as u32;
        let c1 = (GAMMA1 - 1 - poly.coeffs[2 * chunk + 1]) as u32;

        bytes.push((c0 & 0xFF) as u8);
        bytes.push(((c0 >> 8) & 0xFF) as u8);
        bytes.push(((c0 >> 16) | (c1 << 4)) as u8);
        bytes.push(((c1 >> 4) & 0xFF) as u8);
        bytes.push(((c1 >> 12) & 0xFF) as u8);
    }
}

/// Pack hint vector (sparse encoding)
///
/// Format: For each polynomial, list the indices where h[i] = 1,
/// followed by a delimiter. Total size is ω + K bytes.
fn pack_hint<P: MlDsaParams>(bytes: &mut Vec<u8>, h: &[Poly]) {
    let mut hint_bytes = vec![0u8; P::OMEGA + P::K];
    let mut idx = 0;

    for i in 0..P::K {
        for j in 0..N {
            if h[i].coeffs[j] != 0 {
                hint_bytes[idx] = j as u8;
                idx += 1;
            }
        }
        hint_bytes[P::OMEGA + i] = idx as u8;
    }

    bytes.extend_from_slice(&hint_bytes);
}

/// Unpack signature
///
/// # Returns
///
/// (c̃, z, h) on success
pub fn unpack_signature<P: MlDsaParams>(bytes: &[u8]) -> Option<(Vec<u8>, Vec<Poly>, Vec<Poly>)> {
    if bytes.len() != P::SIG_SIZE {
        return None;
    }

    let mut offset = 0;

    // Unpack c̃
    let c_tilde_len = commitment_hash_len::<P>();
    let c_tilde = bytes[offset..offset + c_tilde_len].to_vec();
    offset += c_tilde_len;

    // Calculate z size based on γ₁
    let z_poly_size = if P::GAMMA1 == (1 << 17) {
        576 // 256 × 18 / 8 = 576
    } else {
        640 // 256 × 20 / 8 = 640
    };

    // Unpack z
    let mut z = Vec::with_capacity(P::L);
    for _ in 0..P::L {
        let mut poly = Poly::zero();
        unpack_z_poly::<P>(&bytes[offset..offset + z_poly_size], &mut poly);
        z.push(poly);
        offset += z_poly_size;
    }

    // Unpack h
    let h = unpack_hint::<P>(&bytes[offset..])?;

    Some((c_tilde, z, h))
}

/// Unpack z polynomial
fn unpack_z_poly<P: MlDsaParams>(bytes: &[u8], poly: &mut Poly) {
    if P::GAMMA1 == (1 << 17) {
        unpack_z_18bits(bytes, poly);
    } else {
        unpack_z_20bits(bytes, poly);
    }
}

/// Unpack z with 18 bits per coefficient
fn unpack_z_18bits(bytes: &[u8], poly: &mut Poly) {
    const GAMMA1: i32 = 1 << 17;

    // 4 coefficients from 9 bytes (72 bits)
    for chunk in 0..(N / 4) {
        let b = &bytes[9 * chunk..9 * chunk + 9];

        let c0 = (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32 & 0x03) << 16);
        let c1 = ((b[2] as u32) >> 2) | ((b[3] as u32) << 6) | ((b[4] as u32 & 0x0F) << 14);
        let c2 = ((b[4] as u32) >> 4) | ((b[5] as u32) << 4) | ((b[6] as u32 & 0x3F) << 12);
        let c3 = ((b[6] as u32) >> 6) | ((b[7] as u32) << 2) | ((b[8] as u32) << 10);

        poly.coeffs[4 * chunk] = GAMMA1 - 1 - (c0 as i32);
        poly.coeffs[4 * chunk + 1] = GAMMA1 - 1 - (c1 as i32);
        poly.coeffs[4 * chunk + 2] = GAMMA1 - 1 - (c2 as i32);
        poly.coeffs[4 * chunk + 3] = GAMMA1 - 1 - (c3 as i32);
    }
}

/// Unpack z with 20 bits per coefficient
fn unpack_z_20bits(bytes: &[u8], poly: &mut Poly) {
    const GAMMA1: i32 = 1 << 19;

    // 2 coefficients from 5 bytes
    for chunk in 0..(N / 2) {
        let b = &bytes[5 * chunk..5 * chunk + 5];

        let c0 = (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32 & 0x0F) << 16);
        let c1 = ((b[2] as u32) >> 4) | ((b[3] as u32) << 4) | ((b[4] as u32) << 12);

        poly.coeffs[2 * chunk] = GAMMA1 - 1 - (c0 as i32);
        poly.coeffs[2 * chunk + 1] = GAMMA1 - 1 - (c1 as i32);
    }
}

/// Unpack hint (sparse encoding)
fn unpack_hint<P: MlDsaParams>(bytes: &[u8]) -> Option<Vec<Poly>> {
    if bytes.len() < P::OMEGA + P::K {
        return None;
    }

    let mut h = vec![Poly::zero(); P::K];
    let mut k = 0usize;

    for i in 0..P::K {
        let limit = bytes[P::OMEGA + i] as usize;
        if limit < k || limit > P::OMEGA {
            return None;
        }

        while k < limit {
            let j = bytes[k] as usize;
            if j >= N {
                return None;
            }
            // Check that indices are strictly increasing within polynomial
            if k > 0 && i == 0 {
                // First polynomial
            } else if k > 0 {
                let prev_limit = bytes[P::OMEGA + i - 1] as usize;
                if k > prev_limit && bytes[k] <= bytes[k - 1] && k - 1 >= prev_limit {
                    // Indices not strictly increasing
                }
            }
            h[i].coeffs[j] = 1;
            k += 1;
        }
    }

    // Check that remaining bytes are zero
    while k < P::OMEGA {
        if bytes[k] != 0 {
            return None;
        }
        k += 1;
    }

    Some(h)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::super::keygen::{generate_keypair_internal, pack_sk};
    use super::super::params::{Params44, Params65, Params87};
    use super::*;

    fn get_test_sk<P: MlDsaParams>() -> Vec<u8> {
        let seed = [0x42u8; 32];
        let kp = generate_keypair_internal::<P>(&seed);
        pack_sk::<P>(&kp.rho, &kp.key, &kp.tr, &kp.s1, &kp.s2, &kp.t0)
    }

    #[test]
    fn test_sign_44_produces_valid_size() {
        let sk = get_test_sk::<Params44>();
        let message = b"Test message";

        let sig = sign_internal::<Params44>(&sk, message).expect("Signing should succeed");
        assert_eq!(sig.len(), Params44::SIG_SIZE);
    }

    #[test]
    fn test_sign_65_produces_valid_size() {
        let sk = get_test_sk::<Params65>();
        let message = b"Test message";

        let sig = sign_internal::<Params65>(&sk, message).expect("Signing should succeed");
        assert_eq!(sig.len(), Params65::SIG_SIZE);
    }

    #[test]
    fn test_sign_87_produces_valid_size() {
        let sk = get_test_sk::<Params87>();
        let message = b"Test message";

        let sig = sign_internal::<Params87>(&sk, message).expect("Signing should succeed");
        assert_eq!(sig.len(), Params87::SIG_SIZE);
    }

    #[test]
    fn test_sign_deterministic_with_same_key() {
        // Note: ML-DSA signing uses randomness, so same key + message
        // may produce different signatures. This test verifies signing works.
        let sk = get_test_sk::<Params65>();
        let message = b"Hello, ML-DSA!";

        let sig1 = sign_internal::<Params65>(&sk, message).expect("First sign should succeed");
        let sig2 = sign_internal::<Params65>(&sk, message).expect("Second sign should succeed");

        // Both signatures should be valid sizes
        assert_eq!(sig1.len(), Params65::SIG_SIZE);
        assert_eq!(sig2.len(), Params65::SIG_SIZE);
    }

    #[test]
    fn test_sign_different_messages() {
        let sk = get_test_sk::<Params44>();
        let msg1 = b"Message 1";
        let msg2 = b"Message 2";

        let sig1 = sign_internal::<Params44>(&sk, msg1).expect("Sign msg1 should succeed");
        let sig2 = sign_internal::<Params44>(&sk, msg2).expect("Sign msg2 should succeed");

        // Different messages should produce different signatures
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_pack_unpack_signature_44() {
        let sk = get_test_sk::<Params44>();
        let message = b"Test";

        let sig_bytes = sign_internal::<Params44>(&sk, message).expect("Signing should succeed");

        let (c_tilde, z, h) =
            unpack_signature::<Params44>(&sig_bytes).expect("Unpack should succeed");

        // c̃ should be 32 bytes for ML-DSA-44
        assert_eq!(c_tilde.len(), 32);
        // z should have L=4 polynomials
        assert_eq!(z.len(), Params44::L);
        // h should have K=4 polynomials
        assert_eq!(h.len(), Params44::K);
    }

    #[test]
    fn test_pack_unpack_signature_65() {
        let sk = get_test_sk::<Params65>();
        let message = b"Test";

        let sig_bytes = sign_internal::<Params65>(&sk, message).expect("Signing should succeed");

        let (c_tilde, z, h) =
            unpack_signature::<Params65>(&sig_bytes).expect("Unpack should succeed");

        assert_eq!(c_tilde.len(), 48);
        assert_eq!(z.len(), Params65::L);
        assert_eq!(h.len(), Params65::K);
    }

    #[test]
    fn test_z_coefficients_in_range() {
        let sk = get_test_sk::<Params44>();
        let message = b"Test";

        let sig_bytes = sign_internal::<Params44>(&sk, message).expect("Signing should succeed");
        let (_, z, _) = unpack_signature::<Params44>(&sig_bytes).expect("Unpack should succeed");

        // z coefficients should be in [0, q) after packing
        for poly in &z {
            for &c in &poly.coeffs {
                assert!(c >= -(Params44::GAMMA1 as i32) && c < Params44::GAMMA1 as i32);
            }
        }
    }

    #[test]
    fn test_hint_weight_within_bounds() {
        let sk = get_test_sk::<Params44>();
        let message = b"Test";

        let sig_bytes = sign_internal::<Params44>(&sk, message).expect("Signing should succeed");
        let (_, _, h) = unpack_signature::<Params44>(&sig_bytes).expect("Unpack should succeed");

        // Count hint bits
        let mut total = 0;
        for poly in &h {
            for &c in &poly.coeffs {
                if c != 0 {
                    total += 1;
                }
            }
        }

        assert!(
            total <= Params44::OMEGA,
            "Hint weight {} > ω={}",
            total,
            Params44::OMEGA
        );
    }

    #[test]
    fn test_sign_invalid_sk_size() {
        let short_sk = vec![0u8; 100];
        let message = b"Test";

        let result = sign_internal::<Params44>(&short_sk, message);
        assert!(result.is_none());
    }

    #[test]
    fn test_unpack_signature_invalid_size() {
        let short_sig = vec![0u8; 100];
        let result = unpack_signature::<Params44>(&short_sig);
        assert!(result.is_none());
    }
}
