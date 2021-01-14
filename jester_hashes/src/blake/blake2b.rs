use std::convert::TryInto;
use std::mem;
use std::ptr::hash;

use crate::{HashFunction, HashValue};
use crate::blake::{blake2_mix, SIGMA};

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

/// A Blake2b hash state. It consists out of 8 quad-words
#[derive(Debug, Copy, Clone)]
pub struct Blake2bHash([u64; 8]);

pub struct Blake2bContext {
    pub output_len: usize,
    pub key: Vec<u8>,
}

pub struct Blake2bState {
    hash: Blake2bHash,
    message_length: u128,
    remaining_data_buffer: [u8; BLAKE_2B_BLOCK_SIZE],
    remaining_data_length: usize,
}

impl HashFunction for Blake2bHash {
    type Context = Blake2bContext;
    type HashState = Blake2bState;
    type HashData = Blake2bHash;

    fn init_hash(ctx: &Self::Context) -> Self::HashState {
        let mut state = Blake2bState {
            hash: INITIAL_2B,
            message_length: 0,
            remaining_data_buffer: [0_u8; BLAKE_2B_BLOCK_SIZE],
            remaining_data_length: 0,
        };

        // parameter block
        state.hash.0[0] ^= 0x0101_0000 ^ ((ctx.key.len() as u64) << 8) ^ ctx.output_len as u64;

        // copy the key into the remaining data buffer and set the buffer to full. However, do
        // not compress yet: If no further data is hashed, this is considered the last block,
        // thus we cannot know whether the last block flag must be set.
        if !ctx.key.is_empty() {
            state.remaining_data_buffer[..ctx.key.len()].copy_from_slice(&ctx.key);
            state.remaining_data_length = BLAKE_2B_BLOCK_SIZE;
        }

        state
    }

    fn update_hash(hash: &mut Self::HashState, ctx: &Self::Context, input: &[u8]) {
        // offset where to begin reading input data
        let mut input_data_offset = 0;

        // check whether at least one block can be compressed
        if hash.remaining_data_length + input.len() > BLAKE_2B_BLOCK_SIZE {
            // if there is remaining data in the buffer, compress it with the new input appended.
            // If none is present, just copy the first block of input data anyway and set the
            // input_data_offset to an entire block length
            input_data_offset = BLAKE_2B_BLOCK_SIZE - hash.remaining_data_length;

            let mut block = [0_u8; BLAKE_2B_BLOCK_SIZE];
            block[..hash.remaining_data_length]
                .copy_from_slice(&hash.remaining_data_buffer[..hash.remaining_data_length]);
            block[hash.remaining_data_length..]
                .copy_from_slice(&input[..input_data_offset]);

            // update message length by a block
            hash.message_length += BLAKE_2B_BLOCK_SIZE as u128;

            // compress the new block
            blake2b_compress(hash, &block, false);

            // reset the remaining data buffer
            hash.remaining_data_length = 0;
        } else { // else just add the input to the buffer and return from the function
            hash.remaining_data_buffer[hash.remaining_data_length..
                hash.remaining_data_length + input.len()]
                .copy_from_slice(&input[..]);
            hash.remaining_data_length += input.len();
            return;
        }

        // compress full blocks from the input buffer except the last one
        let block_count = (input.len() - input_data_offset) / BLAKE_2B_BLOCK_SIZE;
        for i in 0..block_count - 1 {
            // update message length by a block
            hash.message_length += BLAKE_2B_BLOCK_SIZE as u128;

            // compress the next block
            blake2b_compress(
                hash,
                &input[input_data_offset + i * BLAKE_2B_BLOCK_SIZE..
                    input_data_offset + (i + 1) * BLAKE_2B_BLOCK_SIZE].try_into().unwrap(),
                false,
            )
        }

        // if there is more data in the input buffer, the last full block is not the last block
        // of the algorithm and can therefore be compressed safely
        if input_data_offset + block_count * BLAKE_2B_BLOCK_SIZE < input.len() {
            // update message length by a block
            hash.message_length += BLAKE_2B_BLOCK_SIZE as u128;

            // compress the last block
            blake2b_compress(
                hash,
                &input[input_data_offset + (block_count - 1) * BLAKE_2B_BLOCK_SIZE..
                    input_data_offset + block_count * BLAKE_2B_BLOCK_SIZE].try_into().unwrap(),
                false,
            );

            hash.remaining_data_length = input.len() -
                (input_data_offset + block_count * BLAKE_2B_BLOCK_SIZE);
            hash.remaining_data_buffer[..hash.remaining_data_length]
                .copy_from_slice(&input[input_data_offset + block_count * BLAKE_2B_BLOCK_SIZE..]);
        }
        // otherwise this could potentially be the last block, therefore only add it to the buffer
        else {
            hash.remaining_data_length = BLAKE_2B_BLOCK_SIZE;
            hash.remaining_data_buffer[..].copy_from_slice(&input[input_data_offset
                + (block_count - 1) * BLAKE_2B_BLOCK_SIZE..]);
        }
    }

    fn finish_hash(hash: &mut Self::HashState, ctx: &Self::Context) -> Self::HashData {
        if hash.message_length.wrapping_add(hash.remaining_data_length as u128) <
            hash.message_length {
            panic!("blake2b cannot hash more than 2**128-1 bytes")
        } else {
            hash.message_length += hash.remaining_data_length as u128;
        }

        // pad last block with zeros
        let mut last_block = [0_u8; BLAKE_2B_BLOCK_SIZE];
        last_block[..hash.remaining_data_length]
            .copy_from_slice(&hash.remaining_data_buffer[..hash.remaining_data_length]);

        blake2b_compress(hash, &last_block, true);

        // TODO change output length according to context
        hash.hash
    }

    fn digest_message(ctx: &Self::Context, input: &[u8]) -> Self::HashData {
        let mut hash_state = Self::init_hash(ctx);

        Self::update_hash(&mut hash_state, ctx, input);
        Self::finish_hash(&mut hash_state, ctx)
    }
}

impl HashValue for Blake2bHash {
    fn raw(&self) -> Box<[u8]> {
        unsafe {
            // TODO: do this properly
            mem::transmute::<[u64; 8], [u8; 64]>([
                u64::from_le(self.0[0]),
                u64::from_le(self.0[1]),
                u64::from_le(self.0[2]),
                u64::from_le(self.0[3]),
                u64::from_le(self.0[4]),
                u64::from_le(self.0[5]),
                u64::from_le(self.0[6]),
                u64::from_le(self.0[7]),
            ])
        }
            .to_vec()
            .into()
    }
}


fn blake2b_mix(vector: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    blake2_mix::<u64, 32, 24, 16, 63>(vector, a, b, c, d, x, y)
}

fn blake2b_compress(state: &mut Blake2bState, input: &[u8; 128], last_block: bool) {
    // initialize local working vector
    let mut vector: [u64; 16] = [0; 16];
    vector[0..=7].copy_from_slice(&state.hash.0[..]);
    vector[8..=15].copy_from_slice(&INITIAL_2B.0[..]);

    vector[12] ^= state.message_length as u64;
    vector[13] ^= (state.message_length >> 64) as u64;

    if last_block {
        vector[14] ^= u64::MAX
    }

    // transform the input block into an u64 array interpreting the input as little endian words
    let input_block = transform_block(input);

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
        state.hash.0[i] ^= vector[i] ^ vector[i + 8];
    }
}

fn transform_block(bytes: &[u8; 128]) -> [u64; 16] {
    let mut block = [0_u64; 16];
    for i in 0..16 {
        block[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    block
}