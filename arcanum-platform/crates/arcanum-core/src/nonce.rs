//! Nonce generation and management.
//!
//! Proper nonce handling is critical for cryptographic security.
//! This module provides utilities for generating and tracking nonces
//! to prevent catastrophic nonce reuse.

use crate::error::{Error, Result};
use crate::random::OsRng;
use parking_lot::Mutex;
use rand::RngCore;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

// ═══════════════════════════════════════════════════════════════════════════════
// NONCE TYPE
// ═══════════════════════════════════════════════════════════════════════════════

/// A cryptographic nonce (number used once).
///
/// This type ensures compile-time sizing and provides various
/// generation strategies.
#[derive(Clone, Zeroize)]
pub struct Nonce<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Nonce<N> {
    /// Create a nonce from bytes.
    pub fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    /// Create from a slice, returning error if length doesn't match.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(Error::InvalidNonceLength {
                expected: N,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    /// Generate a random nonce.
    pub fn random() -> Self {
        let mut bytes = [0u8; N];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Create a zero nonce (use with counter-based schemes).
    pub fn zero() -> Self {
        Self { bytes: [0u8; N] }
    }

    /// Access the nonce bytes.
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    /// Access as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the nonce size in bytes.
    pub const fn len() -> usize {
        N
    }

    /// Increment the nonce (for counter-based nonces).
    ///
    /// Returns `Err` if overflow would occur.
    pub fn increment(&mut self) -> Result<()> {
        for byte in self.bytes.iter_mut().rev() {
            if *byte == 255 {
                *byte = 0;
            } else {
                *byte += 1;
                return Ok(());
            }
        }
        Err(Error::NonceExhausted)
    }

    /// Create from a u64 counter (for nonces >= 8 bytes).
    ///
    /// The counter is placed in the last 8 bytes.
    /// Panics if N < 8.
    pub fn from_counter(counter: u64) -> Self {
        assert!(N >= 8, "Nonce must be at least 8 bytes for counter mode");
        let mut bytes = [0u8; N];
        bytes[N - 8..].copy_from_slice(&counter.to_be_bytes());
        Self { bytes }
    }
}

impl<const N: usize> AsRef<[u8]> for Nonce<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl<const N: usize> std::fmt::Debug for Nonce<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Nonce<{}>({})", N, hex::encode(self.bytes))
    }
}

impl<const N: usize> std::fmt::Display for Nonce<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.bytes))
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NONCE GENERATOR
// ═══════════════════════════════════════════════════════════════════════════════

/// Strategy for generating nonces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceStrategy {
    /// Purely random nonces (recommended for most use cases).
    Random,
    /// Counter-based nonces (for high-volume encryption).
    Counter,
    /// Hybrid: random prefix + counter suffix.
    Hybrid,
}

/// Thread-safe nonce generator.
///
/// Tracks nonce generation to help prevent reuse.
pub struct NonceGenerator<const N: usize> {
    strategy: NonceStrategy,
    counter: AtomicU64,
    random_prefix: [u8; 4],
    generated_count: AtomicU64,
    max_nonces: Option<u64>,
}

impl<const N: usize> NonceGenerator<N> {
    /// Create a new random nonce generator.
    pub fn random() -> Self {
        Self {
            strategy: NonceStrategy::Random,
            counter: AtomicU64::new(0),
            random_prefix: [0; 4],
            generated_count: AtomicU64::new(0),
            max_nonces: None,
        }
    }

    /// Create a counter-based nonce generator.
    ///
    /// Useful when you need deterministic nonces or very high throughput.
    pub fn counter(start: u64) -> Self {
        Self {
            strategy: NonceStrategy::Counter,
            counter: AtomicU64::new(start),
            random_prefix: [0; 4],
            generated_count: AtomicU64::new(0),
            max_nonces: None,
        }
    }

    /// Create a hybrid nonce generator.
    ///
    /// Combines a random prefix with a counter for the best of both worlds.
    pub fn hybrid() -> Self {
        let mut prefix = [0u8; 4];
        OsRng.fill_bytes(&mut prefix);

        Self {
            strategy: NonceStrategy::Hybrid,
            counter: AtomicU64::new(0),
            random_prefix: prefix,
            generated_count: AtomicU64::new(0),
            max_nonces: None,
        }
    }

    /// Set a maximum number of nonces that can be generated.
    ///
    /// After this limit, `generate` will return an error.
    pub fn with_limit(mut self, max: u64) -> Self {
        self.max_nonces = Some(max);
        self
    }

    /// Generate the next nonce.
    pub fn generate(&self) -> Result<Nonce<N>> {
        // Increment generated count
        let count = self.generated_count.fetch_add(1, Ordering::SeqCst);

        // Check limit
        if let Some(max) = self.max_nonces {
            if count >= max {
                return Err(Error::NonceExhausted);
            }
        }

        match self.strategy {
            NonceStrategy::Random => Ok(Nonce::random()),

            NonceStrategy::Counter => {
                let counter = self.counter.fetch_add(1, Ordering::SeqCst);
                if counter == u64::MAX {
                    return Err(Error::NonceExhausted);
                }

                let mut bytes = [0u8; N];
                let counter_bytes = counter.to_be_bytes();
                let start = N.saturating_sub(8);
                bytes[start..].copy_from_slice(&counter_bytes[8 - (N - start)..]);
                Ok(Nonce::new(bytes))
            }

            NonceStrategy::Hybrid => {
                let counter = self.counter.fetch_add(1, Ordering::SeqCst);
                if counter == u64::MAX {
                    return Err(Error::NonceExhausted);
                }

                let mut bytes = [0u8; N];
                // First 4 bytes: random prefix
                let prefix_len = 4.min(N);
                bytes[..prefix_len].copy_from_slice(&self.random_prefix[..prefix_len]);

                // Remaining bytes: counter
                if N > 4 {
                    let counter_bytes = counter.to_be_bytes();
                    let counter_space = N - 4;
                    let counter_start = 8usize.saturating_sub(counter_space);
                    bytes[4..].copy_from_slice(&counter_bytes[counter_start..]);
                }

                Ok(Nonce::new(bytes))
            }
        }
    }

    /// Get the number of nonces generated.
    pub fn count(&self) -> u64 {
        self.generated_count.load(Ordering::SeqCst)
    }

    /// Get the current counter value.
    pub fn current_counter(&self) -> u64 {
        self.counter.load(Ordering::SeqCst)
    }

    /// Reset the generator (use with extreme caution).
    ///
    /// **Warning**: Resetting can lead to nonce reuse if the same key is still in use.
    /// This is not memory-unsafe but is cryptographically dangerous.
    ///
    /// # Safety
    ///
    /// This function is marked unsafe because resetting a nonce generator while
    /// the associated key is still in use can lead to catastrophic nonce reuse,
    /// which breaks the security guarantees of authenticated encryption schemes.
    #[allow(unsafe_code)]
    pub unsafe fn reset(&self) {
        self.counter.store(0, Ordering::SeqCst);
        self.generated_count.store(0, Ordering::SeqCst);
    }
}

impl<const N: usize> Default for NonceGenerator<N> {
    fn default() -> Self {
        Self::random()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NONCE TRACKER
// ═══════════════════════════════════════════════════════════════════════════════

/// Tracks used nonces to detect reuse.
///
/// Useful for receiving encrypted messages where you need to
/// ensure an attacker isn't replaying old messages.
pub struct NonceTracker<const N: usize> {
    seen: Mutex<std::collections::HashSet<[u8; N]>>,
    max_entries: usize,
}

impl<const N: usize> NonceTracker<N> {
    /// Create a new nonce tracker.
    pub fn new(max_entries: usize) -> Self {
        Self {
            seen: Mutex::new(std::collections::HashSet::new()),
            max_entries,
        }
    }

    /// Check and record a nonce.
    ///
    /// Returns `Ok(())` if this is a new nonce, `Err(NonceReuse)` if seen before.
    pub fn check(&self, nonce: &Nonce<N>) -> Result<()> {
        let mut seen = self.seen.lock();

        // Check for reuse
        if seen.contains(nonce.as_bytes()) {
            return Err(Error::NonceReuse);
        }

        // Evict old entries if at capacity
        if seen.len() >= self.max_entries {
            // In a real implementation, you'd want LRU eviction
            // For now, just clear half
            let to_remove: Vec<_> = seen.iter().take(self.max_entries / 2).cloned().collect();
            for nonce in to_remove {
                seen.remove(&nonce);
            }
        }

        seen.insert(*nonce.as_bytes());
        Ok(())
    }

    /// Clear all tracked nonces.
    pub fn clear(&self) {
        self.seen.lock().clear();
    }

    /// Get the number of tracked nonces.
    pub fn len(&self) -> usize {
        self.seen.lock().len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.seen.lock().is_empty()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMMON NONCE SIZES
// ═══════════════════════════════════════════════════════════════════════════════

/// 96-bit nonce (12 bytes) - used by AES-GCM, ChaCha20-Poly1305
pub type Nonce96 = Nonce<12>;

/// 192-bit nonce (24 bytes) - used by XChaCha20-Poly1305, XSalsa20
pub type Nonce192 = Nonce<24>;

/// 128-bit nonce (16 bytes) - used by AES-SIV
pub type Nonce128 = Nonce<16>;

/// 64-bit nonce (8 bytes) - used by Salsa20, ChaCha20 (original)
pub type Nonce64 = Nonce<8>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_random() {
        let n1 = Nonce96::random();
        let n2 = Nonce96::random();
        assert_ne!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn test_nonce_increment() {
        let mut nonce = Nonce96::zero();
        for i in 1..=256 {
            nonce.increment().unwrap();
            assert_eq!(nonce.as_bytes()[11], (i & 0xFF) as u8);
        }
    }

    #[test]
    fn test_nonce_generator_counter() {
        let generator = NonceGenerator::<12>::counter(0);
        let n1 = generator.generate().unwrap();
        let n2 = generator.generate().unwrap();
        assert_ne!(n1.as_bytes(), n2.as_bytes());
        assert_eq!(generator.count(), 2);
    }

    #[test]
    fn test_nonce_generator_limit() {
        let generator = NonceGenerator::<12>::counter(0).with_limit(2);
        assert!(generator.generate().is_ok());
        assert!(generator.generate().is_ok());
        assert!(generator.generate().is_err()); // Should fail
    }

    #[test]
    fn test_nonce_tracker() {
        let tracker = NonceTracker::<12>::new(100);
        let nonce = Nonce96::random();

        // First use should succeed
        assert!(tracker.check(&nonce).is_ok());

        // Second use should fail (replay)
        assert!(tracker.check(&nonce).is_err());

        // Different nonce should succeed
        let nonce2 = Nonce96::random();
        assert!(tracker.check(&nonce2).is_ok());
    }
}
