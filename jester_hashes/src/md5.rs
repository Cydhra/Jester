#![allow(clippy::unreadable_literal)]
#![allow(clippy::zero_prefixed_literal)]

use std::mem;
use std::mem::size_of;

use crate::{align_to_u32a_le, BlockHashFunction, HashFunction, HashValue};
use std::convert::TryInto;

/// the hash block length in bytes
const BLOCK_LENGTH_BYTES: usize = 64;

/// the hash block length in 32 bit integers
const BLOCK_LENGTH_DOUBLE_WORDS: usize = BLOCK_LENGTH_BYTES / 4;

/// The initial state for any MD5 hash. From here, all blocks are applied.
pub const INITIAL: MD5Hash = MD5Hash(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476);

/// A tuple struct containing all four bytes of an MD5 Hash.
#[derive(Debug, Copy, Clone)]
pub struct MD5Hash(pub u32, pub u32, pub u32, pub u32);

pub struct MD5HashState {
    hash: MD5Hash,
    message_length: u64,
    remaining_data: Vec<u8>,
}

/// bits rotated per round
static ROUND_ROTATION_COUNT: [u32; 64] = [
    07, 12, 17, 22, 07, 12, 17, 22, 07, 12, 17, 22, 07, 12, 17, 22, 05, 09, 14, 20, 05, 09, 14, 20,
    05, 09, 14, 20, 05, 09, 14, 20, 04, 11, 16, 23, 04, 11, 16, 23, 04, 11, 16, 23, 04, 11, 16, 23,
    06, 10, 15, 21, 06, 10, 15, 21, 06, 10, 15, 21, 06, 10, 15, 21,
];

/// binary floored values of sin(i + 1) * 2^32 where i is the array index
static MAGIC_SINUS_SCALARS: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

fn round_function(hash: &mut MD5HashState, input: &[u8; BLOCK_LENGTH_BYTES]) {
    let mut input_block = [0_u32; BLOCK_LENGTH_DOUBLE_WORDS];
    unsafe { align_to_u32a_le(&mut input_block, input) };

    let mut round_state = hash.hash;

    for i in 0..BLOCK_LENGTH_BYTES {
        let (scrambled_data, message_index) = match i {
            0..=15 => (
                round_state.3 ^ (round_state.1 & (round_state.2 ^ round_state.3)),
                i,
            ),
            16..=31 => (
                round_state.2 ^ (round_state.3 & (round_state.1 ^ round_state.2)),
                (5 * i + 1) % BLOCK_LENGTH_DOUBLE_WORDS,
            ),
            32..=47 => (
                (round_state.1 ^ round_state.2 ^ round_state.3),
                (3 * i + 5) % BLOCK_LENGTH_DOUBLE_WORDS,
            ),
            48..=63 => (
                (round_state.2 ^ (round_state.1 | !round_state.3)),
                (7 * i) % BLOCK_LENGTH_DOUBLE_WORDS,
            ),
            _ => unreachable!(),
        };

        let temp = round_state.3;
        round_state.3 = round_state.2;
        round_state.2 = round_state.1;
        round_state.1 = round_state.1.wrapping_add(u32::rotate_left(
            round_state
                .0
                .wrapping_add(scrambled_data)
                .wrapping_add(MAGIC_SINUS_SCALARS[i])
                .wrapping_add(input_block[message_index]),
            ROUND_ROTATION_COUNT[i],
        ));
        round_state.0 = temp;
    }

    hash.hash.0 = hash.hash.0.wrapping_add(round_state.0);
    hash.hash.1 = hash.hash.1.wrapping_add(round_state.1);
    hash.hash.2 = hash.hash.2.wrapping_add(round_state.2);
    hash.hash.3 = hash.hash.3.wrapping_add(round_state.3);

    if hash.message_length as u128 + 64_u128 * 8 > u64::MAX as u128 {
        // todo maybe throw an error here?
        panic!("cannot hash more than 2**64 - 1 bits.")
    } else {
        hash.message_length += 64 * 8
    }
}

impl HashFunction for MD5Hash {
    type Context = ();
    type HashState = MD5HashState;
    type HashData = MD5Hash;

    fn init_hash(_ctx: &Self::Context) -> Self::HashState {
        MD5HashState { hash: INITIAL, message_length: 0, remaining_data: vec![] }
    }

    /// Compute one round of the MD5 hash function.
    ///
    /// # Parameters
    /// `input` a 16 byte array containing one block of input data that gets digested.
    /// TODO: this may be more or less data, store excess in the state
    ///
    /// # Returns
    /// A new `MD5HashState` computed from the input state and the input data block.
    fn update_hash(hash: &mut Self::HashState, _ctx: &Self::Context, input: &[u8]) {
        // offset of input data that is already processed during the use of the remaining data
        // stored in the state
        let mut input_data_offset = 0;

        // digest remaining data from the state, if any and copy a prefix from input data that
        if !hash.remaining_data.is_empty() {
            // fills one block of data
            if hash.remaining_data.len() + input.len() >= BLOCK_LENGTH_BYTES {
                // move the remaining data outside the buffer and append new input data to fill
                // first block
                input_data_offset = hash.remaining_data.len();

                let mut first_block = [0u8; BLOCK_LENGTH_BYTES];
                first_block[..input_data_offset].copy_from_slice(&hash.remaining_data);
                first_block[input_data_offset..].copy_from_slice(&input[..input_data_offset]);

                // hash first block
                round_function(hash, &first_block);
            } else { // else copy the input data into the vec and wait for more data
                hash.remaining_data.append(&mut input.to_vec());
                return;
            }
        }

        // calculate how many full blocks remain in the input buffer
        let message_blocks_count = (input.len() - input_data_offset) / BLOCK_LENGTH_BYTES;

        // digest full blocks
        for i in 0..message_blocks_count {
            round_function(hash, &input[input_data_offset + i * BLOCK_LENGTH_BYTES..
                input_data_offset + (i + 1) * BLOCK_LENGTH_BYTES].try_into().unwrap())
        }

        // copy remaining data into hash state
        let remaining_data = &input[message_blocks_count * BLOCK_LENGTH_BYTES..];
        hash.remaining_data = remaining_data.to_vec();
    }

    /// Apply padding to the last incomplete block and digest it. May digest two blocks, if the
    /// `input` must be the complete message that is being hashed.
    ///
    /// # Parameters
    /// `input` the input array that shall be padded and applied. It can be longer than one block,
    /// all full blocks prefixing the array will be omitted.
    #[allow(clippy::cast_possible_truncation)]
    fn finish_hash(hash: &mut Self::HashState, _ctx: &Self::Context) -> Self::HashData {
        let remaining_data = &hash.remaining_data;

        let mut last_block = [0_u8; BLOCK_LENGTH_BYTES];
        last_block[..remaining_data.len()].copy_from_slice(&remaining_data[..]);

        let message_length_bits =
            if hash.message_length as u128 +
                remaining_data.len() as u128 * 8_u128 > u64::MAX as u128 {
                // todo maybe throw an error here?
                panic!("cannot hash more than 2**64 - 1 bits.")
            } else {
                hash.message_length + (remaining_data.len() * 8) as u64
            };

        // append a single 1-bit to the end of the message
        last_block[remaining_data.len()] = 0x80_u8;

        // if there is not enough space for the message length to be appended, a new block must be
        // created
        if remaining_data.len() + 1 + size_of::<u64>() > BLOCK_LENGTH_BYTES {
            let mut overflow_block = [0_u8; BLOCK_LENGTH_BYTES];
            // append the message length in bits
            for i in 0..8 {
                overflow_block[BLOCK_LENGTH_BYTES - 8 + i] =
                    (message_length_bits >> (i * 8) as u64) as u8;
            }

            round_function(hash, &last_block);
            round_function(hash, &overflow_block);
        } else {
            // append the message length in bits
            for i in 0..8 {
                last_block[56 + i] = (message_length_bits >> (i * 8) as u64) as u8;
            }

            round_function(hash, &last_block);
        }

        hash.hash
    }

    fn digest_message(ctx: &Self::Context, input: &[u8]) -> Self::HashData {
        let mut hash_state = Self::init_hash(ctx);
        Self::update_hash(&mut hash_state, ctx, &input);

        // pad and digest last block
        Self::finish_hash(&mut hash_state, ctx)
    }
}

impl BlockHashFunction for MD5Hash {
    fn block_size(_ctx: &Self::Context) -> usize {
        BLOCK_LENGTH_BYTES
    }

    fn output_size(_ctx: &Self::Context) -> usize {
        size_of::<MD5Hash>()
    }
}

impl HashValue for MD5Hash {
    /// Generates a raw `[u8; 16]` array from the current hash state.
    fn raw(&self) -> Box<[u8]> {
        unsafe {
            mem::transmute::<[u32; 4], [u8; 16]>([
                u32::from_le(self.0),
                u32::from_le(self.1),
                u32::from_le(self.2),
                u32::from_le(self.3),
            ])
        }
            .to_vec()
            .into()
    }
}
