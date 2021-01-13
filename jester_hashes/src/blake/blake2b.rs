use crate::blake::{blake2_mix, SIGMA};
use crate::{HashValue, HashFunction};

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

pub struct Blake2bContext {}

pub struct Blake2bState {
    hash: Blake2bHash,
    message_length: u128,
}

impl HashFunction for Blake2bHash {
    type Context = Blake2bContext;
    type HashState = Blake2bState;
    type HashData = Blake2bState;

    fn init_hash(ctx: &Self::Context) -> Self::HashState {
        // TODO keyed hashing using context
        Blake2bState { hash: INITIAL_2B, message_length: 0 }
    }

    fn update_hash(hash: &mut Self::HashState, ctx: &Self::Context, input: &[u8]) {
        unimplemented!()
    }

    fn finish_hash(hash: &mut Self::HashState, ctx: &Self::Context) -> Self::HashData {
        unimplemented!()
    }

    fn digest_message(ctx: &Self::Context, input: &[u8]) -> Self::HashData {
        let mut hash_state = Self::init_hash(ctx);
        Self::update_hash(&mut hash_state, ctx, input);
        Self::finish_hash(&mut hash_state, ctx)
    }
}

impl HashValue for Blake2bState {
    fn raw(&self) -> Box<[u8]> {
        unimplemented!()
    }
}


fn blake2b_mix(vector: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    blake2_mix::<u64, 32, 24, 16, 63>(vector, a, b, c, d, x, y)
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

