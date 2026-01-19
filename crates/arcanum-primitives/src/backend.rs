//! Backend selection system for cryptographic implementations.
//!
//! This module provides a trait-based system for selecting between
//! different implementation backends at compile-time or runtime.
//!
//! # Backend Types
//!
//! - [`NativeBackend`]: Pure Rust portable implementation
//! - [`SimdBackend`]: SIMD-accelerated implementation (AVX2, NEON)
//! - [`HardwareBackend`]: Hardware instruction implementation (SHA-NI, AES-NI)
//!
//! # Example
//!
//! ```ignore
//! use arcanum_primitives::backend::{Backend, NativeBackend, detect_best_backend};
//!
//! // Compile-time backend selection
//! type Sha256 = Sha256Impl<NativeBackend>;
//!
//! // Runtime detection
//! let backend = detect_best_backend();
//! ```

use core::fmt;

/// Marker trait for cryptographic implementation backends.
///
/// Backends provide different implementation strategies for cryptographic
/// algorithms, trading off between portability, performance, and features.
pub trait Backend: Sized + Clone + Copy + 'static {
    /// Human-readable name for this backend.
    const NAME: &'static str;

    /// Whether this backend uses hardware acceleration.
    const HW_ACCELERATED: bool;

    /// Whether this backend is available on the current platform.
    fn is_available() -> bool;
}

/// Pure Rust portable backend.
///
/// This backend works on all platforms and uses no platform-specific
/// optimizations. It serves as the fallback when other backends are
/// not available.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeBackend;

impl Backend for NativeBackend {
    const NAME: &'static str = "native";
    const HW_ACCELERATED: bool = false;

    #[inline]
    fn is_available() -> bool {
        true // Always available
    }
}

/// SIMD-accelerated backend.
///
/// Uses SIMD instructions (AVX2, AVX-512, NEON) for parallel processing.
/// Falls back to native implementation on unsupported platforms.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SimdBackend;

impl Backend for SimdBackend {
    const NAME: &'static str = "simd";
    const HW_ACCELERATED: bool = true;

    #[inline]
    fn is_available() -> bool {
        // Runtime CPU detection requires std
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        {
            std::is_x86_feature_detected!("avx2")
        }

        #[cfg(all(feature = "std", target_arch = "aarch64"))]
        {
            // NEON is always available on AArch64
            true
        }

        // No runtime detection available without std
        #[cfg(not(feature = "std"))]
        {
            false
        }

        #[cfg(all(feature = "std", not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
        {
            false
        }
    }
}

/// Hardware cryptographic instruction backend.
///
/// Uses dedicated CPU instructions for cryptographic operations:
/// - x86_64: SHA-NI, AES-NI, CLMUL
/// - AArch64: SHA, AES instructions
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HardwareBackend;

impl Backend for HardwareBackend {
    const NAME: &'static str = "hardware";
    const HW_ACCELERATED: bool = true;

    #[inline]
    fn is_available() -> bool {
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        {
            std::is_x86_feature_detected!("sha") && std::is_x86_feature_detected!("aes")
        }

        #[cfg(all(feature = "std", target_arch = "aarch64"))]
        {
            // Check for crypto extensions
            #[cfg(target_feature = "sha2")]
            {
                true
            }
            #[cfg(not(target_feature = "sha2"))]
            {
                false
            }
        }

        // No runtime detection available without std
        #[cfg(not(feature = "std"))]
        {
            false
        }

        #[cfg(all(feature = "std", not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
        {
            false
        }
    }
}

/// Runtime backend selection.
///
/// Allows selecting the best available backend at runtime based on
/// CPU feature detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DynamicBackend {
    /// Pure Rust portable implementation
    Native,
    /// SIMD-accelerated implementation
    Simd,
    /// Hardware cryptographic instructions
    Hardware,
}

impl DynamicBackend {
    /// Detect and return the best available backend for the current CPU.
    #[inline]
    pub fn detect() -> Self {
        if HardwareBackend::is_available() {
            Self::Hardware
        } else if SimdBackend::is_available() {
            Self::Simd
        } else {
            Self::Native
        }
    }

    /// Get the name of this backend.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Native => NativeBackend::NAME,
            Self::Simd => SimdBackend::NAME,
            Self::Hardware => HardwareBackend::NAME,
        }
    }

    /// Check if this backend uses hardware acceleration.
    pub const fn is_hw_accelerated(&self) -> bool {
        match self {
            Self::Native => false,
            Self::Simd | Self::Hardware => true,
        }
    }
}

impl Default for DynamicBackend {
    fn default() -> Self {
        Self::detect()
    }
}

impl fmt::Display for DynamicBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Detect the best available backend for the current platform.
///
/// Returns the most optimized backend that is available:
/// 1. Hardware (SHA-NI, AES-NI) if available
/// 2. SIMD (AVX2, NEON) if available
/// 3. Native (pure Rust) as fallback
#[inline]
pub fn detect_best_backend() -> DynamicBackend {
    DynamicBackend::detect()
}

/// CPU feature detection utilities (requires std feature)
#[cfg(feature = "std")]
pub mod cpu {
    /// Check if AVX2 is available (x86_64 only)
    #[cfg(target_arch = "x86_64")]
    #[inline]
    pub fn has_avx2() -> bool {
        std::is_x86_feature_detected!("avx2")
    }

    /// Check if AVX-512 is available (x86_64 only)
    #[cfg(target_arch = "x86_64")]
    #[inline]
    pub fn has_avx512() -> bool {
        std::is_x86_feature_detected!("avx512f")
    }

    /// Check if SHA-NI is available (x86_64 only)
    #[cfg(target_arch = "x86_64")]
    #[inline]
    pub fn has_sha_ni() -> bool {
        std::is_x86_feature_detected!("sha")
    }

    /// Check if AES-NI is available (x86_64 only)
    #[cfg(target_arch = "x86_64")]
    #[inline]
    pub fn has_aes_ni() -> bool {
        std::is_x86_feature_detected!("aes")
    }

    /// Check if CLMUL is available (x86_64 only)
    #[cfg(target_arch = "x86_64")]
    #[inline]
    pub fn has_clmul() -> bool {
        std::is_x86_feature_detected!("pclmulqdq")
    }

    /// Get a summary of available CPU features
    #[cfg(target_arch = "x86_64")]
    pub fn feature_summary() -> FeatureSummary {
        FeatureSummary {
            avx2: has_avx2(),
            avx512: has_avx512(),
            sha_ni: has_sha_ni(),
            aes_ni: has_aes_ni(),
            clmul: has_clmul(),
        }
    }

    /// Summary of available CPU features
    #[cfg(target_arch = "x86_64")]
    #[derive(Debug, Clone, Copy)]
    pub struct FeatureSummary {
        /// AVX2 available
        pub avx2: bool,
        /// AVX-512 available
        pub avx512: bool,
        /// SHA-NI available
        pub sha_ni: bool,
        /// AES-NI available
        pub aes_ni: bool,
        /// CLMUL available
        pub clmul: bool,
    }

    #[cfg(target_arch = "x86_64")]
    impl core::fmt::Display for FeatureSummary {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "AVX2:{} AVX512:{} SHA-NI:{} AES-NI:{} CLMUL:{}",
                if self.avx2 { "✓" } else { "✗" },
                if self.avx512 { "✓" } else { "✗" },
                if self.sha_ni { "✓" } else { "✗" },
                if self.aes_ni { "✓" } else { "✗" },
                if self.clmul { "✓" } else { "✗" },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_backend_always_available() {
        assert!(NativeBackend::is_available());
        assert_eq!(NativeBackend::NAME, "native");
        assert!(!NativeBackend::HW_ACCELERATED);
    }

    #[test]
    fn test_dynamic_backend_detect() {
        let backend = DynamicBackend::detect();
        // Should always succeed
        assert!(!backend.name().is_empty());
    }

    #[test]
    fn test_dynamic_backend_display() {
        let backend = DynamicBackend::Native;
        assert_eq!(format!("{}", backend), "native");
    }

    #[test]
    fn test_detect_best_backend() {
        let backend = detect_best_backend();
        // Native should always be available as fallback
        assert!(matches!(
            backend,
            DynamicBackend::Native | DynamicBackend::Simd | DynamicBackend::Hardware
        ));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_cpu_features() {
        // These just shouldn't panic
        let _ = cpu::has_avx2();
        let _ = cpu::has_avx512();
        let _ = cpu::has_sha_ni();
        let _ = cpu::has_aes_ni();
        let _ = cpu::has_clmul();

        let summary = cpu::feature_summary();
        let display = format!("{}", summary);
        assert!(display.contains("AVX2:"));
    }
}
