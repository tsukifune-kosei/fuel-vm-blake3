pub type Data = [u8; 32];

const NODE: u8 = 0x01;
const LEAF: u8 = 0x00;

// Merkle Tree hash of an empty list
// MTH({}) = Hash()
pub fn empty_sum() -> &'static Data {
    const EMPTY_SUM: Data = [
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36,
        0xdc, 0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a,
        0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
    ];

    &EMPTY_SUM
}

// Merkle tree hash of an n-element list D[n]
// MTH(D[n]) = Hash(0x01 || MTH(D[0:k]) || MTH(D[k:n])
pub fn node_sum(lhs_data: &[u8], rhs_data: &[u8]) -> Data {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[NODE]);
    hasher.update(lhs_data);
    hasher.update(rhs_data);
    (*hasher.finalize().as_bytes()).into()
}

// Merkle tree hash of a list with one entry
// MTH({d(0)}) = Hash(0x00 || d(0))
pub fn leaf_sum(data: &[u8]) -> Data {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[LEAF]);
    hasher.update(data);
    (*hasher.finalize().as_bytes()).into()
}
