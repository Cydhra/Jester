#![allow(clippy::unreadable_literal)]

use std::mem;
use std::mem::size_of;

use crate::{align_to_u32a_be, HashFunction};

const BLOCK_LENGTH_BYTES: usize = 128;

/// The initial state for any blake2 hash. From here, all blocks are applied.
pub const INITIAL: Blake2bHash = Blake2bHash([
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
]);

/// A SHA1 hash state. It consists mainly out of 5 double-words named `a`, `b`, `c`, `d` and `e`.
#[derive(Debug, Copy, Clone)]
pub struct Blake2bHash([u64; 8]);

impl Blake2bHash {
    /// SHA-1 round function that corresponds to the digestion of exactly one block of data. This block must be
    /// exactly `BLOCK_LENGTH_BYTES` long.
    /// # Parameters
    /// - `input_block` a block of data to be digested
    pub fn round_function(&mut self, input_block: &[u8]) {
        assert_eq!(input_block.len(), BLOCK_LENGTH_BYTES);

        unimplemented!()
    }

    /// Digest the last (partial) block of input data.
    #[allow(clippy::cast_possible_truncation)]
    pub fn digest_last_block(&mut self, input: &[u8]) {
        unimplemented!()
    }
}

impl HashFunction for Blake2bHash {
    const BLOCK_SIZE: usize = BLOCK_LENGTH_BYTES;

    const OUTPUT_SIZE: usize = mem::size_of::<Self>();

    /// Digest a full message of arbitrary size.
    /// # Parameters
    /// - `input` a slice containing a (possibly large) chunk of byte data that is to be digested.
    ///
    /// # Returns
    /// Returns the hash state of the digested input data. It cannot be used to append more data, as the message
    /// length was appended to the input data for digestion.
    fn digest_message(input: &[u8]) -> Self {
        let mut hash_state = INITIAL;
        unimplemented!()
    }

    /// Generates a raw `[u8; 64]` array from the current hash state.
    fn raw(&self) -> Box<[u8]> {
        unsafe {
            mem::transmute::<[u64; 8], [u8; 64]>(self.0)
        }
        .to_vec()
        .into()
    }
}
