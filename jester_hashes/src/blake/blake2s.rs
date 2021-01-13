use crate::blake::{blake2_mix, SIGMA};

pub const INITIAL_2S: Blake2sHash = Blake2sHash([
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]);

pub const BLAKE_2S_WORD_LENGTH: usize = 32;
pub const BLAKE_2S_ROUND_COUNT: usize = 10;
pub const BLAKE_2S_BLOCK_SIZE: usize = 64;

/// A Blake2s hash state. It consists out of 8 double-words.
#[derive(Debug, Copy, Clone)]
pub struct Blake2sHash([u32; 8]);

fn blake2s_mix(vector: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    blake2_mix::<u32, 16, 12, 8, 7>(vector, a, b, c, d, x, y)
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