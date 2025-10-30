use crate::common::{
    Bytes32,
    Prefix,
    empty_sum_blake3,
};

// Merkle Tree hash of an empty list
// MTH({}) = Hash()
pub const fn empty_sum() -> &'static Bytes32 {
    empty_sum_blake3()
}

// Merkle tree hash of an n-element list D[n]
// MTH(D[n]) = Hash(0x01 || MTH(D[0:k]) || MTH(D[k:n])
pub fn node_sum(lhs_data: &Bytes32, rhs_data: &Bytes32) -> Bytes32 {
    let mut hasher = blake3::Hasher::new();

    hasher.update(Prefix::Node.as_ref());
    hasher.update(lhs_data);
    hasher.update(rhs_data);

    (*hasher.finalize().as_bytes()).into()
}

// Merkle tree hash of a list with one entry
// MTH({d(0)}) = Hash(0x00 || d(0))
pub fn leaf_sum(data: &[u8]) -> Bytes32 {
    let mut hasher = blake3::Hasher::new();

    hasher.update(Prefix::Leaf.as_ref());
    hasher.update(data);

    (*hasher.finalize().as_bytes()).into()
}
