#![allow(clippy::unreadable_literal)]

use std::convert::TryInto;
use std::mem;

use num::PrimInt;
use num::traits::WrappingAdd;

const BLOCK_LENGTH_BYTES: usize = 128;

/// Blake2 round permutation matrix. In round i row i mod 10 is used to permute the input block.
/// Column j denotes which input word is to be used as word j for the mixing function.
pub const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

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

pub const BLAKE_2B_WORD_LENGTH: usize = 64;
pub const BLAKE_2B_ROUND_COUNT: usize = 12;
pub const BLAKE_2B_BLOCK_SIZE: usize = 128;

pub const INITIAL_2S: Blake2sHash = Blake2sHash([
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]);

pub const BLAKE_2S_WORD_LENGTH: usize = 32;
pub const BLAKE_2S_ROUND_COUNT: usize = 10;
pub const BLAKE_2S_BLOCK_SIZE: usize = 64;

/// A Blake2b hash state. It consists out of 8 quad-words
#[derive(Debug, Copy, Clone)]
pub struct Blake2bHash([u64; 8]);

/// A Blake2s hash state. It consists out of 8 double-words.
#[derive(Debug, Copy, Clone)]
pub struct Blake2sHash([u32; 8]);

/// The Blake2 mix function as defined by RFC 7693. It operates upon a mutable array of 16 words
/// (word length depends on the algorithm subtype). No values is returned, as the working vector
/// is changed in-place. The mixing constants R1 to R4 are given as constant generics.
fn blake2_mix<N: WrappingAdd + PrimInt, const R1: u8, const R2: u8, const R3: u8, const R4: u8>(
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

fn blake2b_mix(vector: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    blake2_mix::<u64, 32, 24, 16, 63>(vector, a, b, c, d, x, y)
}

fn blake2s_mix(vector: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    blake2_mix::<u32, 16, 12, 8, 7>(vector, a, b, c, d, x, y)
}

fn blake2b_compress(state: &mut [u64; 8], iv: &[u64; 8], input_block: &[u64; 16], byte_count: u128,
                    last_block: bool) {
    // initialize local working vector
    let mut vector: [u64; 16] = [0; 16];
    vector[0..=7].copy_from_slice(&state[..]);
    vector[8..=15].copy_from_slice(&iv[..]);

    vector[12] ^= byte_count as u64;
    vector[13] ^= (byte_count >> BLAKE_2B_WORD_LENGTH) as u64;

    if last_block {
        vector[14] ^= u64::MAX
    }

    for i in 0..BLAKE_2B_ROUND_COUNT {
        let permutation = &SIGMA[i % 10][0..16];

        blake2b_mix(&mut vector, 0, 4, 8, 12,
                                          input_block[permutation[0]],
                                          input_block[permutation[1]]);
        blake2b_mix(&mut vector, 1, 5, 9, 13,
                                          input_block[permutation[2]],
                                          input_block[permutation[3]]);
        blake2b_mix(&mut vector, 2, 6, 10, 14,
                                          input_block[permutation[4]],
                                          input_block[permutation[5]]);
        blake2b_mix(&mut vector, 3, 7, 11, 15,
                                          input_block[permutation[6]],
                                          input_block[permutation[7]]);

        blake2b_mix(&mut vector, 0, 5, 10, 15,
                                          input_block[permutation[8]],
                                          input_block[permutation[9]]);
        blake2b_mix(&mut vector, 1, 6, 11, 12,
                                          input_block[permutation[10]],
                                          input_block[permutation[11]]);
        blake2b_mix(&mut vector, 2, 7, 8, 13,
                                          input_block[permutation[12]],
                                          input_block[permutation[13]]);
        blake2b_mix(&mut vector, 3, 4, 9, 14,
                                          input_block[permutation[14]],
                                          input_block[permutation[15]]);
    }

    for i in 0..8 {
        state[i] ^= vector[i] ^ vector[i + 8];
    }
}

fn blake2s_compress(state: &mut [u32; 8], iv: &[u32; 8], input_block: &[u32; 16], byte_count: u64,
                    last_block: bool) {
    // initialize local working vector
    let mut vector: [u32; 16] = [0; 16];
    vector[0..=7].copy_from_slice(&state[..]);
    vector[8..=15].copy_from_slice(&iv[..]);

    vector[12] ^= byte_count as u32;
    vector[13] ^= (byte_count >> BLAKE_2S_WORD_LENGTH) as u32;

    if last_block {
        vector[14] ^= u32::MAX
    }

    for i in 0..BLAKE_2S_ROUND_COUNT {
        let permutation = &SIGMA[i % 10][0..16];

        blake2s_mix(&mut vector, 0, 4, 8, 12,
                                        input_block[permutation[0]],
                                        input_block[permutation[1]]);
        blake2s_mix(&mut vector, 1, 5, 9, 13,
                                        input_block[permutation[2]],
                                        input_block[permutation[3]]);
        blake2s_mix(&mut vector, 2, 6, 10, 14,
                                        input_block[permutation[4]],
                                        input_block[permutation[5]]);
        blake2s_mix(&mut vector, 3, 7, 11, 15,
                                        input_block[permutation[6]],
                                        input_block[permutation[7]]);

        blake2s_mix(&mut vector, 0, 5, 10, 15,
                                        input_block[permutation[8]],
                                        input_block[permutation[9]]);
        blake2s_mix(&mut vector, 1, 6, 11, 12,
                                        input_block[permutation[10]],
                                        input_block[permutation[11]]);
        blake2s_mix(&mut vector, 2, 7, 8, 13,
                                        input_block[permutation[12]],
                                        input_block[permutation[13]]);
        blake2s_mix(&mut vector, 3, 4, 9, 14,
                                        input_block[permutation[14]],
                                        input_block[permutation[15]]);
    }

    for i in 0..8 {
        state[i] ^= vector[i] ^ vector[i + 8];
    }
}

impl Blake2bHash {
    pub fn mix_function(&mut self) {}

    pub fn round_function(&mut self, input_block: &[u8]) {
        assert_eq!(input_block.len(), BLOCK_LENGTH_BYTES);

        unimplemented!()
    }

    /// Digest the last (partial) block of input data.
    pub fn digest_last_block(&mut self, input: &[u8]) {
        unimplemented!()
    }
}