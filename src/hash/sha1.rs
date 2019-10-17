use std::mem;
use std::mem::size_of;

use crate::array_util;

const BLOCK_LENGTH_BYTES: usize = 64;

#[derive(Debug, Copy, Clone)]
pub struct SHA1Hash {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub e: u32,
}

impl SHA1Hash {
    const INITIAL: Self = SHA1Hash { a: 0x67452301, b: 0xEFCDAB89, c: 0x98BADCFE, d: 0x10325476, e: 0xC3D2E1F0 };

    /// Digest a full message of arbitrary size.
    pub fn digest_message(input: &[u8]) -> Self {
        let mut hash_state = Self::INITIAL;
        let message_blocks_count = input.len() / BLOCK_LENGTH_BYTES;

        // digest full blocks
        for block_index in 0..message_blocks_count {
            hash_state.round_function(&input[block_index * BLOCK_LENGTH_BYTES..(block_index + 1) * BLOCK_LENGTH_BYTES]);
        }

        // pad and digest last block
        hash_state.digest_last_block(input);

        return hash_state;
    }

    pub fn round_function(&mut self, input_block: &[u8]) {
        assert_eq!(input_block.len(), BLOCK_LENGTH_BYTES);

        let mut extended_block = [0u32; 80];
        unsafe { array_util::align_to_u32a_be(&mut extended_block[0..16], input_block) };

        for i in 16..80 {
            extended_block[i] = u32::rotate_left(
                extended_block[i - 3] ^ extended_block[i - 8] ^ extended_block[i - 14] ^ extended_block[i - 16], 1)
        }

        let mut round_state = *self;

        for i in 0..80 {
            let (scrambled_data, magic_constant) = match i {
                0..=19 => {
                    ((round_state.b & round_state.c) | ((!round_state.b) & round_state.d), 0x5A827999)
                }
                20..=39 => {
                    (round_state.b ^ round_state.c ^ round_state.d, 0x6ED9EBA1)
                }
                40..=59 => {
                    ((round_state.b & round_state.c) | (round_state.b & round_state.d)
                         | (round_state.c & round_state.d), 0x8F1BBCDC)
                }
                60..=79 => {
                    (round_state.b ^ round_state.c ^ round_state.d, 0xCA62C1D6)
                }
                _ => unreachable!()
            };

            let temp = u32::rotate_left(round_state.a, 5)
                .wrapping_add(scrambled_data)
                .wrapping_add(round_state.e)
                .wrapping_add(magic_constant)
                .wrapping_add(extended_block[i]);
            round_state.e = round_state.d;
            round_state.d = round_state.c;
            round_state.c = u32::rotate_left(round_state.b, 30);
            round_state.b = round_state.a;
            round_state.a = temp;
        }

        self.a = self.a.wrapping_add(round_state.a);
        self.b = self.b.wrapping_add(round_state.b);
        self.c = self.c.wrapping_add(round_state.c);
        self.d = self.d.wrapping_add(round_state.d);
        self.e = self.e.wrapping_add(round_state.e);
    }

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
                // note, that the number is appended backwards because it must be handled as a big endian number
                overflow_block[BLOCK_LENGTH_BYTES - i] = (message_length_bits >> (i * 8) as u64) as u8;
            }

            self.round_function(&last_block);
            self.round_function(&overflow_block);
        } else {
            // append the message length in bits
            for i in 0..8 {
                // note, that the number is appended backwards because it must be handled as a big endian number
                last_block[63 - i] = (message_length_bits >> (i * 8) as u64) as u8;
            }

            self.round_function(&last_block);
        }
    }

    /// Generates a raw ``[u8; 16]`` array from the current hash state.
    pub fn to_raw(&self) -> [u8; 20] {
        unsafe {
            mem::transmute::<[u32; 5], [u8; 20]>([
                u32::from_be(self.a),
                u32::from_be(self.b),
                u32::from_be(self.c),
                u32::from_be(self.d),
                u32::from_be(self.e)])
        }
    }
}
