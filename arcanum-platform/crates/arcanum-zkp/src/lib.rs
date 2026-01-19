//! # Arcanum Zero-Knowledge Proofs
//!
//! Zero-knowledge proof systems for proving statements without revealing secrets.
//!
//! ## Bulletproofs
//!
//! Efficient range proofs without trusted setup:
//! - Prove a committed value is within a range [0, 2^n)
//! - Logarithmic proof size
//! - Aggregatable for multiple proofs
//!
//! ## Schnorr Proofs
//!
//! Interactive proofs of knowledge:
//! - Proof of discrete log knowledge
//! - Proof of equality of discrete logs
//! - Made non-interactive via Fiat-Shamir
//!
//! ## Pedersen Commitments
//!
//! Information-theoretically hiding commitments:
//! - Perfectly hiding: reveals nothing about the value
//! - Computationally binding: cannot open to different value
//! - Homomorphic: C(a) + C(b) = C(a + b)
//!
//! ## Example
//!
//! ```rust
//! use arcanum_zkp::prelude::*;
//!
//! // Create a Pedersen commitment
//! let value = 42u64;
//! let opening = PedersenOpening::random();
//! let commitment = PedersenCommitment::commit(value, &opening);
//!
//! // Verify the commitment opens correctly
//! assert!(commitment.verify(value, &opening));
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod traits;
mod commitment;

#[cfg(feature = "bulletproofs")]
pub mod range_proof;

#[cfg(feature = "schnorr-proofs")]
pub mod schnorr_proof;

pub use traits::*;
pub use commitment::{PedersenCommitment, PedersenOpening};

#[cfg(feature = "bulletproofs")]
pub use range_proof::{RangeProof, RangeProofBatch};

#[cfg(feature = "schnorr-proofs")]
pub use schnorr_proof::{
    SchnorrProof, SchnorrProofBuilder,
    DiscreteLogProof, EqualityProof,
};

/// Prelude for convenient imports.
pub mod prelude {
    pub use crate::traits::*;
    pub use crate::commitment::{PedersenCommitment, PedersenOpening};

    #[cfg(feature = "bulletproofs")]
    pub use crate::range_proof::{RangeProof, RangeProofBatch};

    #[cfg(feature = "schnorr-proofs")]
    pub use crate::schnorr_proof::{SchnorrProof, DiscreteLogProof, EqualityProof};
}

/// Re-export curve25519-dalek-ng types for convenience (compatible with bulletproofs).
pub mod curve {
    pub use curve25519_dalek_ng::scalar::Scalar;
    pub use curve25519_dalek_ng::ristretto::{RistrettoPoint, CompressedRistretto};
    pub use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT;
}
