//! SLH-DSA Address Scheme (ADRS)
//!
//! FIPS 205 Section 4.2 defines the address structure used to domain-separate
//! hash function calls throughout the algorithm.
//!
//! The address is a 32-byte structure with the following layout:
//! - Bytes 0-3:   Layer address (which hypertree layer)
//! - Bytes 4-11:  Tree address (which tree in the layer)
//! - Bytes 12-15: Type (address type identifier)
//! - Bytes 16-31: Type-specific fields

#![allow(dead_code)]

use core::fmt;

/// Address types as defined in FIPS 205
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AddressType {
    /// WOTS+ hash address
    WotsHash = 0,
    /// WOTS+ public key compression
    WotsPk = 1,
    /// Hash tree address
    Tree = 2,
    /// FORS tree address
    ForsTree = 3,
    /// FORS roots address
    ForsRoots = 4,
    /// WOTS+ PRF address
    WotsPrf = 5,
    /// FORS PRF address
    ForsPrf = 6,
}

/// 32-byte address structure for SLH-DSA
///
/// This structure is used to domain-separate all hash function calls
/// in the algorithm, preventing related-key attacks.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Address {
    /// Raw 32-byte address data
    data: [u8; 32],
}

impl Address {
    /// Create a new zeroed address
    pub const fn new() -> Self {
        Self { data: [0u8; 32] }
    }

    /// Create address from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { data: bytes }
    }

    /// Get the raw address bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data
    }

    /// Get mutable reference to raw bytes
    pub fn as_bytes_mut(&mut self) -> &mut [u8; 32] {
        &mut self.data
    }

    // ========================================================================
    // Common Fields (all address types)
    // ========================================================================

    /// Set the layer address (bytes 0-3)
    pub fn set_layer_address(&mut self, layer: u32) {
        self.data[0..4].copy_from_slice(&layer.to_be_bytes());
    }

    /// Get the layer address
    pub fn layer_address(&self) -> u32 {
        u32::from_be_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
    }

    /// Set the tree address (bytes 4-11)
    pub fn set_tree_address(&mut self, tree: u64) {
        self.data[4..12].copy_from_slice(&tree.to_be_bytes());
    }

    /// Get the tree address
    pub fn tree_address(&self) -> u64 {
        u64::from_be_bytes([
            self.data[4],
            self.data[5],
            self.data[6],
            self.data[7],
            self.data[8],
            self.data[9],
            self.data[10],
            self.data[11],
        ])
    }

    /// Set the address type (bytes 12-15)
    pub fn set_type(&mut self, addr_type: AddressType) {
        self.data[12..16].copy_from_slice(&(addr_type as u32).to_be_bytes());
        // Clear type-specific fields when type changes
        self.data[16..32].fill(0);
    }

    /// Get the address type
    pub fn get_type(&self) -> Option<AddressType> {
        let type_val =
            u32::from_be_bytes([self.data[12], self.data[13], self.data[14], self.data[15]]);
        match type_val {
            0 => Some(AddressType::WotsHash),
            1 => Some(AddressType::WotsPk),
            2 => Some(AddressType::Tree),
            3 => Some(AddressType::ForsTree),
            4 => Some(AddressType::ForsRoots),
            5 => Some(AddressType::WotsPrf),
            6 => Some(AddressType::ForsPrf),
            _ => None,
        }
    }

    // ========================================================================
    // WOTS+ Hash Address Fields (Type 0)
    // ========================================================================

    /// Set keypair address (bytes 16-19) - which WOTS+ keypair
    pub fn set_keypair_address(&mut self, keypair: u32) {
        self.data[16..20].copy_from_slice(&keypair.to_be_bytes());
    }

    /// Get keypair address
    pub fn keypair_address(&self) -> u32 {
        u32::from_be_bytes([self.data[16], self.data[17], self.data[18], self.data[19]])
    }

    /// Set chain address (bytes 20-23) - which chain in WOTS+
    pub fn set_chain_address(&mut self, chain: u32) {
        self.data[20..24].copy_from_slice(&chain.to_be_bytes());
    }

    /// Get chain address
    pub fn chain_address(&self) -> u32 {
        u32::from_be_bytes([self.data[20], self.data[21], self.data[22], self.data[23]])
    }

    /// Set hash address (bytes 24-27) - position in chain
    pub fn set_hash_address(&mut self, hash: u32) {
        self.data[24..28].copy_from_slice(&hash.to_be_bytes());
    }

    /// Get hash address
    pub fn hash_address(&self) -> u32 {
        u32::from_be_bytes([self.data[24], self.data[25], self.data[26], self.data[27]])
    }

    // ========================================================================
    // Tree Address Fields (Type 2)
    // ========================================================================

    /// Set tree height (bytes 20-23)
    pub fn set_tree_height(&mut self, height: u32) {
        self.data[20..24].copy_from_slice(&height.to_be_bytes());
    }

    /// Get tree height
    pub fn tree_height(&self) -> u32 {
        u32::from_be_bytes([self.data[20], self.data[21], self.data[22], self.data[23]])
    }

    /// Set tree index (bytes 24-27)
    pub fn set_tree_index(&mut self, index: u32) {
        self.data[24..28].copy_from_slice(&index.to_be_bytes());
    }

    /// Get tree index
    pub fn tree_index(&self) -> u32 {
        u32::from_be_bytes([self.data[24], self.data[25], self.data[26], self.data[27]])
    }

    // ========================================================================
    // Convenience constructors
    // ========================================================================

    /// Create a WOTS+ hash address
    pub fn wots_hash(layer: u32, tree: u64, keypair: u32, chain: u32, hash: u32) -> Self {
        let mut addr = Self::new();
        addr.set_layer_address(layer);
        addr.set_tree_address(tree);
        addr.set_type(AddressType::WotsHash);
        addr.set_keypair_address(keypair);
        addr.set_chain_address(chain);
        addr.set_hash_address(hash);
        addr
    }

    /// Create a WOTS+ public key address
    pub fn wots_pk(layer: u32, tree: u64, keypair: u32) -> Self {
        let mut addr = Self::new();
        addr.set_layer_address(layer);
        addr.set_tree_address(tree);
        addr.set_type(AddressType::WotsPk);
        addr.set_keypair_address(keypair);
        addr
    }

    /// Create a tree address
    pub fn tree(layer: u32, tree: u64, height: u32, index: u32) -> Self {
        let mut addr = Self::new();
        addr.set_layer_address(layer);
        addr.set_tree_address(tree);
        addr.set_type(AddressType::Tree);
        addr.set_tree_height(height);
        addr.set_tree_index(index);
        addr
    }

    /// Create a FORS tree address
    pub fn fors_tree(layer: u32, tree: u64, keypair: u32, height: u32, index: u32) -> Self {
        let mut addr = Self::new();
        addr.set_layer_address(layer);
        addr.set_tree_address(tree);
        addr.set_type(AddressType::ForsTree);
        addr.set_keypair_address(keypair);
        addr.set_tree_height(height);
        addr.set_tree_index(index);
        addr
    }

    /// Create a FORS roots address
    pub fn fors_roots(layer: u32, tree: u64, keypair: u32) -> Self {
        let mut addr = Self::new();
        addr.set_layer_address(layer);
        addr.set_tree_address(tree);
        addr.set_type(AddressType::ForsRoots);
        addr.set_keypair_address(keypair);
        addr
    }

    /// Copy layer and tree address from another address
    pub fn copy_subtree_address(&mut self, other: &Address) {
        self.data[0..12].copy_from_slice(&other.data[0..12]);
    }

    /// Copy keypair address from another address
    pub fn copy_keypair_address(&mut self, other: &Address) {
        self.data[16..20].copy_from_slice(&other.data[16..20]);
    }

    /// Get compressed address (ADRSc) for SHA-2 variants
    ///
    /// FIPS 205 Section 10.1: ADRSc is a 22-byte compressed form:
    /// ADRSc = ADRS[3] || ADRS[8:16] || ADRS[19] || ADRS[20:32]
    ///
    /// Layout:
    /// - Byte 0: Layer address (LSB of bytes 0-3)
    /// - Bytes 1-8: Tree address overlap (bytes 8-15: last 4 of tree + type)
    /// - Byte 9: Keypair address (LSB of bytes 16-19)
    /// - Bytes 10-21: Type-specific tail (bytes 20-31)
    ///
    /// Note: FIPS 205 uses this specific compression to reduce bandwidth
    /// while preserving necessary domain separation.
    pub fn to_compressed(&self) -> [u8; 22] {
        let mut adrs_c = [0u8; 22];
        adrs_c[0] = self.data[3]; // ADRS[3]: Layer LSB
        adrs_c[1..9].copy_from_slice(&self.data[8..16]); // ADRS[8:16]
        adrs_c[9] = self.data[19]; // ADRS[19]: Keypair LSB
        adrs_c[10..22].copy_from_slice(&self.data[20..32]); // ADRS[20:32]
        adrs_c
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Address")
            .field("layer", &self.layer_address())
            .field("tree", &self.tree_address())
            .field("type", &self.get_type())
            .finish()
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_new_is_zeroed() {
        let addr = Address::new();
        assert_eq!(addr.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_layer_address_encoding() {
        let mut addr = Address::new();
        addr.set_layer_address(0x12345678);
        assert_eq!(addr.layer_address(), 0x12345678);
        assert_eq!(&addr.data[0..4], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_tree_address_encoding() {
        let mut addr = Address::new();
        addr.set_tree_address(0x123456789ABCDEF0);
        assert_eq!(addr.tree_address(), 0x123456789ABCDEF0);
    }

    #[test]
    fn test_address_type_encoding() {
        let mut addr = Address::new();

        addr.set_type(AddressType::WotsHash);
        assert_eq!(addr.get_type(), Some(AddressType::WotsHash));

        addr.set_type(AddressType::ForsTree);
        assert_eq!(addr.get_type(), Some(AddressType::ForsTree));
    }

    #[test]
    fn test_type_change_clears_fields() {
        let mut addr = Address::new();
        addr.set_type(AddressType::WotsHash);
        addr.set_keypair_address(42);
        addr.set_chain_address(7);

        // Change type should clear type-specific fields
        addr.set_type(AddressType::Tree);
        assert_eq!(addr.keypair_address(), 0);
    }

    #[test]
    fn test_wots_hash_constructor() {
        let addr = Address::wots_hash(3, 100, 5, 12, 8);
        assert_eq!(addr.layer_address(), 3);
        assert_eq!(addr.tree_address(), 100);
        assert_eq!(addr.get_type(), Some(AddressType::WotsHash));
        assert_eq!(addr.keypair_address(), 5);
        assert_eq!(addr.chain_address(), 12);
        assert_eq!(addr.hash_address(), 8);
    }

    #[test]
    fn test_tree_constructor() {
        let addr = Address::tree(2, 50, 4, 15);
        assert_eq!(addr.layer_address(), 2);
        assert_eq!(addr.tree_address(), 50);
        assert_eq!(addr.get_type(), Some(AddressType::Tree));
        assert_eq!(addr.tree_height(), 4);
        assert_eq!(addr.tree_index(), 15);
    }

    #[test]
    fn test_fors_tree_constructor() {
        let addr = Address::fors_tree(0, 0, 10, 5, 20);
        assert_eq!(addr.get_type(), Some(AddressType::ForsTree));
        assert_eq!(addr.keypair_address(), 10);
        assert_eq!(addr.tree_height(), 5);
        assert_eq!(addr.tree_index(), 20);
    }

    #[test]
    fn test_copy_subtree_address() {
        let src = Address::wots_hash(5, 1000, 0, 0, 0);
        let mut dst = Address::new();
        dst.copy_subtree_address(&src);

        assert_eq!(dst.layer_address(), 5);
        assert_eq!(dst.tree_address(), 1000);
    }

    #[test]
    fn test_address_roundtrip() {
        let original = Address::wots_hash(7, 0xDEADBEEF, 42, 13, 99);
        let bytes = *original.as_bytes();
        let restored = Address::from_bytes(bytes);
        assert_eq!(original, restored);
    }

    #[test]
    fn test_compressed_address_format() {
        // Create an address with known values
        let addr = Address::wots_hash(3, 0x123456789ABCDEF0, 42, 7, 99);

        let adrs_c = addr.to_compressed();

        // Verify 22-byte output
        assert_eq!(adrs_c.len(), 22);

        // Byte 0: Layer LSB (layer=3, so LSB is 3)
        assert_eq!(adrs_c[0], 3);

        // Byte 9: Keypair LSB (keypair=42, so LSB is 42)
        assert_eq!(adrs_c[9], 42);
    }

    #[test]
    fn test_compressed_address_different_keypairs() {
        let addr1 = Address::wots_hash(0, 0, 0, 0, 0);
        let addr2 = Address::wots_hash(0, 0, 1, 0, 0);

        let adrs_c1 = addr1.to_compressed();
        let adrs_c2 = addr2.to_compressed();

        // Different keypairs should produce different compressed addresses
        assert_ne!(adrs_c1, adrs_c2);
    }
}
