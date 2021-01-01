#![allow(clippy::unreadable_literal)]

use std::convert::TryInto;
use std::mem;

use num::traits::WrappingAdd;
use num::PrimInt;

use crate::HashFunction;

const BLOCK_LENGTH_BYTES: usize = 128;

/// The initial state for any blake2b hash. From here, all blocks are applied.
pub const INITIAL_2B: Blake2bHash = Blake2bHash([
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
]);

pub const INITIAL_2S: Blake2sHash = Blake2sHash([
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]);

/// A Blake2b hash state. It consists out of 8 quad-words
#[derive(Debug, Copy, Clone)]
pub struct Blake2bHash([u64; 8]);

/// A Blake2s hash state. It consists out of 8 double-words.
#[derive(Debug, Copy, Clone)]
pub struct Blake2sHash([u32; 8]);

fn blake2_mix_function<
    N: WrappingAdd + PrimInt,
    const R1: u8,
    const R2: u8,
    const R3: u8,
    const R4: u8,
>(
    vector: &mut [N; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: N,
    y: N,
) {
    vector[a] = vector[a].wrapping_add(&vector[b]).wrapping_add(&x);
    vector[d] = (vector[d] ^ vector[a]).rotate_right(R1.try_into().unwrap());
    vector[c] = vector[c].wrapping_add(&vector[b]);
    vector[b] = (vector[b] ^ vector[c]).rotate_right(R2.try_into().unwrap());

    vector[a] = vector[a].wrapping_add(&vector[b]).wrapping_add(&y);
    vector[d] = (vector[d] ^ vector[a]).rotate_right(R3.try_into().unwrap());
    vector[c] = vector[c].wrapping_add(&vector[d]);
    vector[b] = (vector[b] ^ vector[c]).rotate_right(R4.try_into().unwrap());
}

impl Blake2bHash {
    pub fn mix_function(&mut self) {}

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
        unimplemented!()
    }

    /// Generates a raw `[u8; 64]` array from the current hash state.
    fn raw(&self) -> Box<[u8]> {
        unsafe { mem::transmute::<[u64; 8], [u8; 64]>(self.0) }
            .to_vec()
            .into()
    }
}
