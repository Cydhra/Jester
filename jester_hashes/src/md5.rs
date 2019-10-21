#![allow(clippy::unreadable_literal)]
#![allow(clippy::zero_prefixed_literal)]

use std::mem;
use std::mem::size_of;

use jester_util;

use crate::HashFunction;

/// the hash block length in bytes
const BLOCK_LENGTH_BYTES: usize = 64;

/// the hash block length in 32 bit integers
const BLOCK_LENGTH_DOUBLE_WORDS: usize = BLOCK_LENGTH_BYTES / 4;

/// The initial state for any MD5 hash. From here, all blocks are applied.
pub const INITIAL: MD5Hash = MD5Hash(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476);

/// A tuple struct containing all four bytes of an MD5 Hash.
#[derive(Debug, Copy, Clone)]
pub struct MD5Hash(pub u32, pub u32, pub u32, pub u32);

/// bits rotated per round
static ROUND_ROTATION_COUNT: [u32; 64] = [
    07, 12, 17, 22, 07, 12, 17, 22, 07, 12, 17, 22, 07, 12, 17, 22,
    05, 09, 14, 20, 05, 09, 14, 20, 05, 09, 14, 20, 05, 09, 14, 20,
    04, 11, 16, 23, 04, 11, 16, 23, 04, 11, 16, 23, 04, 11, 16, 23,
    06, 10, 15, 21, 06, 10, 15, 21, 06, 10, 15, 21, 06, 10, 15, 21];

/// binary floored values of sin(i + 1) * 2^32 where i is the array index
static MAGIC_SINUS_SCALARS: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391];

impl MD5Hash {
    /// compute one round of MD5
    ///
    /// # Parameters
    /// ``input_block`` a 16 byte array containing one block of input data that shall be hashed
    ///
    /// # Returns
    /// A new ``MD5HashState`` computed from the input state and the input data block.
    pub fn round_function(&mut self, input: &[u8]) {
        assert_eq!(input.len(), BLOCK_LENGTH_BYTES);

        let mut input_block = [0u32; BLOCK_LENGTH_DOUBLE_WORDS];
        unsafe { jester_util::align_to_u32a_le(&mut input_block, input) };

        let mut round_state = *self;

        for i in 0..BLOCK_LENGTH_BYTES {
            let (scrambled_data, message_index) = match i {
                0..=15 =>
                    (round_state.3 ^ (round_state.1 & (round_state.2 ^ round_state.3)), i),
                16..=31 =>
                    (round_state.2 ^ (round_state.3 & (round_state.1 ^ round_state.2)), (5 * i + 1) %
                        BLOCK_LENGTH_DOUBLE_WORDS),
                32..=47 =>
                    ((round_state.1 ^ round_state.2 ^ round_state.3), (3 * i + 5) % BLOCK_LENGTH_DOUBLE_WORDS),
                48..=63 =>
                    ((round_state.2 ^ (round_state.1 | !round_state.3)), (7 * i) % BLOCK_LENGTH_DOUBLE_WORDS),
                _ => unreachable!()
            };

            let temp = round_state.3;
            round_state.3 = round_state.2;
            round_state.2 = round_state.1;
            round_state.1 = round_state.1.wrapping_add(
                u32::rotate_left(round_state.0.wrapping_add(scrambled_data)
                                     .wrapping_add(MAGIC_SINUS_SCALARS[i])
                                     .wrapping_add(input_block[message_index]),
                                 ROUND_ROTATION_COUNT[i])
            );
            round_state.0 = temp;
        }

        self.0 = self.0.wrapping_add(round_state.0);
        self.1 = self.1.wrapping_add(round_state.1);
        self.2 = self.2.wrapping_add(round_state.2);
        self.3 = self.3.wrapping_add(round_state.3);
    }

    /// Apply padding to the last incomplete block and digest it. May digest two blocks, if the
    /// padding itself overflows into a new block. The last block is automatically retrieved from ``input``.
    /// ``input`` must be the complete message that is being hashed.
    ///
    /// # Parameters
    /// ``input`` the input array that shall be padded and applied. It can be longer than one block,
    /// all full blocks prefixing the array will be omitted.
    pub fn digest_last_block(&mut self, input: &[u8]) {
        let message_length_bits: u64 = (input.len() as u64) * 8u64;
        let message_blocks_count = input.len() / BLOCK_LENGTH_BYTES;

        let relevant_data = &input[message_blocks_count * BLOCK_LENGTH_BYTES..];

        let mut last_block = [0u8; BLOCK_LENGTH_BYTES];
        // append the last part of message to the block
        for (dst, src) in last_block.iter_mut().zip(relevant_data.iter()) {
            *dst = *src
        }

        // append a single 1-bit to the end of the message
        last_block[relevant_data.len()] = 0x80u8;

        // if there is not enough space for the message length to be appended, a new block must be
        // created
        if relevant_data.len() + 1 + size_of::<u64>() > BLOCK_LENGTH_BYTES {
            let mut overflow_block = [0u8; BLOCK_LENGTH_BYTES];
            // append the message length in bits
            for i in 0..8 {
                overflow_block[BLOCK_LENGTH_BYTES - 8 + i] = (message_length_bits >> (i * 8) as u64) as u8;
            }

            self.round_function(&last_block);
            self.round_function(&overflow_block);
        } else {
            // append the message length in bits
            for i in 0..8 {
                last_block[56 + i] = (message_length_bits >> (i * 8) as u64) as u8;
            }

            self.round_function(&last_block);
        }
    }
}

impl HashFunction for MD5Hash {
    const BLOCK_SIZE: usize = BLOCK_LENGTH_BYTES;

    const OUTPUT_SIZE: usize = mem::size_of::<MD5Hash>();

    /// Digest a full message of arbitrary size.
    /// #Parameters
    /// - `input` a slice containing a (possibly large) chunk of byte data that is to be digested.
    ///
    /// #Output
    /// Returns the hash state of the digested input data. It cannot be used to append more data, as the message
    /// length was appended to the input data for digestion.
    fn digest_message(input: &[u8]) -> Self {
        let mut hash_state = INITIAL;
        let message_blocks_count = input.len() / BLOCK_LENGTH_BYTES;

        // digest full blocks
        for block_index in 0..message_blocks_count {
            hash_state.round_function(&input[block_index * BLOCK_LENGTH_BYTES..(block_index + 1) * BLOCK_LENGTH_BYTES]);
        }

        // pad and digest last block
        hash_state.digest_last_block(input);

        hash_state
    }


    /// Generates a raw ``[u8; 16]`` array from the current hash state.
    fn raw(&self) -> Box<[u8]> {
        unsafe {
            mem::transmute::<[u32; 4], [u8; 16]>([
                u32::from_le(self.0),
                u32::from_le(self.1),
                u32::from_le(self.2),
                u32::from_le(self.3)])
        }.to_vec().into()
    }
}