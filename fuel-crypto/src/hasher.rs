use fuel_types::Bytes32;
use blake3;

use core::iter;

/// Standard hasher
#[derive(Debug, Default, Clone)]
pub struct Hasher(blake3::Hasher);

impl Hasher {
    /// Length of the output
    pub const OUTPUT_LEN: usize = Bytes32::LEN;

    /// Append data to the hasher
    pub fn input<B>(&mut self, data: B)
    where
        B: AsRef<[u8]>,
    {
        self.0.update(data.as_ref());
    }

    /// Consume, append data and return the hasher
    pub fn chain<B>(mut self, data: B) -> Self
    where
        B: AsRef<[u8]>,
    {
        self.0.update(data.as_ref());
        self
    }

    /// Consume, append the items of the iterator and return the hasher
    pub fn extend_chain<B, I>(mut self, iter: I) -> Self
    where
        B: AsRef<[u8]>,
        I: IntoIterator<Item = B>,
    {
        self.extend(iter);

        self
    }

    /// Reset the hasher to the default state
    pub fn reset(&mut self) {
        self.0 = blake3::Hasher::new();
    }

    /// Hash the provided data, returning its digest
    pub fn hash<B>(data: B) -> Bytes32
    where
        B: AsRef<[u8]>,
    {
        let hash = blake3::hash(data.as_ref());
        (*hash.as_bytes()).into()
    }

    /// Consume the hasher, returning the digest
    pub fn finalize(self) -> Bytes32 {
        let hash = self.0.finalize();
        (*hash.as_bytes()).into()
    }

    /// Return the digest without consuming the hasher
    pub fn digest(&self) -> Bytes32 {
        let hash = self.0.clone().finalize();
        (*hash.as_bytes()).into()
    }
}

impl<B> iter::FromIterator<B> for Hasher
where
    B: AsRef<[u8]>,
{
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = B>,
    {
        iter.into_iter().fold(Hasher::default(), Hasher::chain)
    }
}

impl<B> Extend<B> for Hasher
where
    B: AsRef<[u8]>,
{
    fn extend<T: IntoIterator<Item = B>>(&mut self, iter: T) {
        iter.into_iter().for_each(|b| self.input(b))
    }
}
