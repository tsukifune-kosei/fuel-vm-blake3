use super::Bytes32;

pub fn sum<T: AsRef<[u8]>>(data: T) -> Bytes32 {
    let hash = blake3::hash(data.as_ref());
    (*hash.as_bytes()).into()
}

pub fn sum_iter<I: IntoIterator<Item = T>, T: AsRef<[u8]>>(iterator: I) -> Bytes32 {
    let mut hasher = blake3::Hasher::new();
    for data in iterator {
        hasher.update(data.as_ref());
    }
    let hash = hasher.finalize();
    (*hash.as_bytes()).into()
}
