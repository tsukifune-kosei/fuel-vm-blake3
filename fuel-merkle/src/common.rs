mod hash;
mod msb;
mod path_iterator;
mod position;
mod position_path;
mod prefix;
mod storage_map;

pub(crate) mod error;
pub(crate) mod node;
pub(crate) mod path;

pub use path_iterator::AsPathIterator;
pub use position::Position;
pub use storage_map::StorageMap;

pub(crate) use msb::Msb;
pub(crate) use position_path::PositionPath;
pub(crate) use prefix::{
    Prefix,
    PrefixError,
};

pub type Bytes1 = [u8; 1];
pub type Bytes2 = [u8; 2];
pub type Bytes4 = [u8; 4];
pub type Bytes8 = [u8; 8];
pub type Bytes16 = [u8; 16];
pub type Bytes32 = [u8; 32];

use alloc::vec::Vec;
pub type ProofSet = Vec<Bytes32>;

pub use hash::{
    sum,
    sum_iter,
};

// Merkle Tree hash of an empty list
// MTH({}) = Hash()
pub const fn empty_sum_blake3() -> &'static Bytes32 {
    const EMPTY_SUM: Bytes32 = [
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36,
        0xdc, 0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a,
        0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
    ];

    &EMPTY_SUM
}

#[test]
fn empty_sum_blake3_is_empty_hash() {
    let sum = empty_sum_blake3();
    let empty = *blake3::hash(b"").as_bytes();

    assert_eq!(&empty, sum);
}
