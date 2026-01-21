//! Arcanum-DSA: SIMD-Optimized Digital Signature Algorithm
//!
//! # Overview
//!
//! Arcanum-DSA is a variant of ML-DSA (FIPS 204) with parameters optimized for
//! modern SIMD architectures. It maintains equivalent or stronger security while
//! enabling efficient 4-way and 8-way parallel processing.
//!
//! # Design Rationale
//!
//! ML-DSA's L parameter (number of secret polynomials in s₁/y) determines the
//! batch size for ExpandMask sampling. Standard ML-DSA uses:
//! - ML-DSA-44: L=4 (optimal for 4-way SIMD)
//! - ML-DSA-65: L=5 (1 leftover in 4-way batch)
//! - ML-DSA-87: L=7 (3 leftover in 4-way batch)
//!
//! Arcanum-DSA adjusts parameters to make L a multiple of 4:
//! - Arcanum-44: K=4, L=4 (identical to ML-DSA-44)
//! - Arcanum-65: K=4, L=8 (dimension 3072 vs 2816, ~9% stronger)
//! - Arcanum-87: K=8, L=8 (dimension 4096 vs 3840, ~7% stronger)
//!
//! # Security Equivalence
//!
//! Security is primarily determined by:
//! 1. Lattice dimension: N×(K+L) where N=256
//! 2. Secret coefficient bound η
//! 3. Challenge weight τ
//!
//! Arcanum variants maintain *at least* the security of their ML-DSA counterparts
//! by ensuring dimension ≥ ML-DSA dimension. The slight over-provisioning provides
//! additional security margin.
//!
//! # Trade-offs
//!
//! | Aspect | Impact |
//! |--------|--------|
//! | Security | Equal or stronger (larger dimension) |
//! | Key size | Larger (more polynomials in s₁) |
//! | Signature size | Larger (L polynomials in z) |
//! | Performance | Better (perfect SIMD batching) |
//!
//! # When to Use
//!
//! - **Use Arcanum-DSA** when: Performance is critical, FIPS compliance not required
//! - **Use ML-DSA** when: FIPS 204 compliance required, interoperability needed
//!
//! # Agent-Optimized TDD Methodology
//!
//! This module follows agent-optimized TDD where tests serve as:
//! 1. **Executable specifications** - Tests define behavior unambiguously
//! 2. **Property invariants** - Mathematical properties that must hold
//! 3. **Boundary conditions** - Edge cases agents might miss
//! 4. **Regression guards** - Prevent breaking working code
//!
//! Tests are written BEFORE implementation and serve as the source of truth.

#![allow(dead_code)]

pub mod params;

#[cfg(test)]
mod tests;

// Re-export main types
pub use params::{ArcanumDsaParams, Params44, Params65, Params87};
