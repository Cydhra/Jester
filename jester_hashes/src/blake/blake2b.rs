use std::convert::TryInto;

use crate::{HashFunction, HashValue, BlockHashFunction};
use crate::blake::{blake2_mix, SIGMA};
use byteorder::{LittleEndian, WriteBytesExt};

/// The initial state for any blake2b hash. From here, all blocks are applied.
pub const INITIAL_2B: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

pub const BLAKE_2B_WORD_LENGTH: usize = 64;
pub const BLAKE_2B_ROUND_COUNT: usize = 12;
pub const BLAKE_2B_BLOCK_SIZE: usize = 128;

/// A type for the Blake2b hash function. It does not carry actual data and exists solely for
/// access to the function.
pub struct Blake2b;

/// A Blake2b hash output. It varies in length depending on the desired output length
#[derive(Debug, Clone)]
pub struct Blake2bHash {
    pub hash: Vec<u8>,
}

pub struct Blake2bContext {
    pub output_len: usize,
    pub key: Vec<u8>,
}

pub struct Blake2bState {
    hash: [u64; 8],
    message_length: u128,
    remaining_data_buffer: [u8; BLAKE_2B_BLOCK_SIZE],
    remaining_data_length: usize,
}

impl HashFunction for Blake2b {
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
        state.hash[0] ^= 0x0101_0000 ^ ((ctx.key.len() as u64) << 8) ^ ctx.output_len as u64;

        // copy the key into the remaining data buffer and set the buffer to full. However, do
        // not compress yet: If no further data is hashed, this is considered the last block,
        // thus we cannot know whether the last block flag must be set.
        if !ctx.key.is_empty() {
            state.remaining_data_buffer[..ctx.key.len()].copy_from_slice(&ctx.key);
            state.remaining_data_length = BLAKE_2B_BLOCK_SIZE;
        }

        state
    }

    fn update_hash(hash: &mut Self::HashState, _ctx: &Self::Context, input: &[u8]) {
        // offset where to begin reading input data
        let mut input_data_offset;

        // check whether at least one block can be compressed. This is the case if the remaining
        // data buffer plus all input data is strictly longer than one block size (If the sum is
        // equal to exactly one block, we cannot compress it because it might be the last block
        // to compress, in which case the last_block flag must be set).
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
        } else { // if not enough data is present, just add the input to the remaining data buffer
            // and return  from the function
            hash.remaining_data_buffer[hash.remaining_data_length..
                hash.remaining_data_length + input.len()]
                .copy_from_slice(&input[..]);
            hash.remaining_data_length += input.len();
            return;
        }

        // now compress blocks until at most one block is present in the input buffer. Again, if
        // exactly one block is present, we cannot compress it until we know if more data will
        // arrive.
        while input.len() - input_data_offset > BLAKE_2B_BLOCK_SIZE {
            // increase message length by one block
            hash.message_length += BLAKE_2B_BLOCK_SIZE as u128;

            // compress the next block
            blake2b_compress(
                hash,
                &input[input_data_offset..input_data_offset + BLAKE_2B_BLOCK_SIZE]
                    .try_into().unwrap(),
                false,
            );

            // advance the offset by the compressed block length
            input_data_offset += BLAKE_2B_BLOCK_SIZE;
        }

        // store any left over data in the remaining data buffer
        hash.remaining_data_length = input.len() - input_data_offset;
        hash.remaining_data_buffer[..hash.remaining_data_length].copy_from_slice(&input[input_data_offset..]);
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

        Blake2bHash { hash: hash.raw().into_iter().take(ctx.output_len).collect() }
    }

    fn digest_message(ctx: &Self::Context, input: &[u8]) -> Self::HashData {
        let mut hash_state = Self::init_hash(ctx);

        Self::update_hash(&mut hash_state, ctx, input);
        Self::finish_hash(&mut hash_state, ctx)
    }
}

impl BlockHashFunction for Blake2b {
    fn block_size(ctx: &Self::Context) -> usize {
        BLAKE_2B_BLOCK_SIZE
    }

    fn output_size(ctx: &Self::Context) -> usize {
        ctx.output_len
    }
}

impl HashValue for Blake2bState {
    fn raw(&self) -> Vec<u8> {
        let mut b = vec![];
        for i in 0..8 {
            b.write_u64::<LittleEndian>(self.hash[i]).unwrap();
        }
        b
    }
}

impl HashValue for Blake2bHash {
    fn raw(&self) -> Vec<u8> {
        self.hash.clone()
    }
}


fn blake2b_mix(vector: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    blake2_mix::<u64, 32, 24, 16, 63>(vector, a, b, c, d, x, y)
}

fn blake2b_compress(state: &mut Blake2bState, input: &[u8; 128], last_block: bool) {
    // initialize local working vector
    let mut vector: [u64; 16] = [0; 16];
    vector[0..=7].copy_from_slice(&state.hash[..]);
    vector[8..=15].copy_from_slice(&INITIAL_2B[..]);

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
        state.hash[i] ^= vector[i] ^ vector[i + 8];
    }
}

fn transform_block(bytes: &[u8; 128]) -> [u64; 16] {
    let mut block = [0_u64; 16];
    for i in 0..16 {
        block[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    block
}