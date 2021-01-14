#![allow(clippy::unreadable_literal)]

use std::mem;
use std::mem::size_of;
use std::mem::take;

use crate::{align_to_u32a_be, HashFunction, HashValue, BlockHashFunction};
use std::convert::TryInto;

const BLOCK_LENGTH_BYTES: usize = 64;

/// The initial state for any SHA1 hash. From here, all blocks are applied.
pub const INITIAL: SHA1Hash = SHA1Hash {
    a: 0x67452301,
    b: 0xEFCDAB89,
    c: 0x98BADCFE,
    d: 0x10325476,
    e: 0xC3D2E1F0,
};

/// A SHA1 hash state. It consists mainly out of 5 double-words named `a`, `b`, `c`, `d` and `e`.
#[derive(Debug, Copy, Clone)]
pub struct SHA1Hash {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub e: u32,
}

pub struct SHA1HashState {
    hash: SHA1Hash,
    message_length: u64,
    remaining_data: Vec<u8>,
}

fn round_function(hash: &mut SHA1HashState, block: &[u8; 64]) {
    let mut extended_block = [0_u32; 80];
    unsafe { align_to_u32a_be(&mut extended_block[0..16], block) };

    for i in 16..80 {
        extended_block[i] = u32::rotate_left(
            extended_block[i - 3]
                ^ extended_block[i - 8]
                ^ extended_block[i - 14]
                ^ extended_block[i - 16],
            1,
        )
    }

    let mut round_state = hash.hash;

    for (i, data_word) in extended_block.iter().enumerate() {
        let (scrambled_data, magic_constant) = match i {
            0..=19 => (
                (round_state.b & round_state.c) | ((!round_state.b) & round_state.d),
                0x5A827999,
            ),
            20..=39 => (round_state.b ^ round_state.c ^ round_state.d, 0x6ED9EBA1),
            40..=59 => (
                (round_state.b & round_state.c)
                    | (round_state.b & round_state.d)
                    | (round_state.c & round_state.d),
                0x8F1BBCDC,
            ),
            60..=79 => (round_state.b ^ round_state.c ^ round_state.d, 0xCA62C1D6),
            _ => unreachable!(),
        };

        let temp = u32::rotate_left(round_state.a, 5)
            .wrapping_add(scrambled_data)
            .wrapping_add(round_state.e)
            .wrapping_add(magic_constant)
            .wrapping_add(*data_word);
        round_state.e = round_state.d;
        round_state.d = round_state.c;
        round_state.c = u32::rotate_left(round_state.b, 30);
        round_state.b = round_state.a;
        round_state.a = temp;
    }

    hash.hash.a = hash.hash.a.wrapping_add(round_state.a);
    hash.hash.b = hash.hash.b.wrapping_add(round_state.b);
    hash.hash.c = hash.hash.c.wrapping_add(round_state.c);
    hash.hash.d = hash.hash.d.wrapping_add(round_state.d);
    hash.hash.e = hash.hash.e.wrapping_add(round_state.e);

    if hash.message_length as u128 + 64_u128 * 8 > u64::MAX as u128 {
        // todo maybe throw an error here?
        panic!("cannot hash more than 2**64 - 1 bits.")
    } else {
        hash.message_length += 64 * 8
    }
}

impl HashFunction for SHA1Hash {
    type Context = ();
    type HashState = SHA1HashState;
    type HashData = SHA1Hash;

    fn init_hash(_ctx: &Self::Context) -> Self::HashState {
        SHA1HashState { hash: INITIAL, message_length: 0, remaining_data: vec![] }
    }

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
                input_data_offset = BLOCK_LENGTH_BYTES  - hash.remaining_data.len();

                let mut first_block = [0u8; BLOCK_LENGTH_BYTES];
                first_block[..hash.remaining_data.len()].copy_from_slice(&hash.remaining_data);
                first_block[hash.remaining_data.len()..]
                    .copy_from_slice(&input[..input_data_offset]);

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
        let remaining_data = &input[input_data_offset + message_blocks_count * BLOCK_LENGTH_BYTES..];
        hash.remaining_data = remaining_data.to_vec();
    }

    fn finish_hash(hash: &mut Self::HashState, _ctx: &Self::Context) ->
                                                                                   Self::HashData {
        // TODO: remove the input parameter from this function. It does not make sense
        let remaining_data = take(&mut hash.remaining_data);

        // prepare a zero-padded full-length block
        let mut last_block = [0_u8; BLOCK_LENGTH_BYTES];

        // append the last part of message to the block
        last_block[..remaining_data.len()].copy_from_slice(&remaining_data);

        // append a single 1-bit to the end of the message
        last_block[remaining_data.len()] = 0x80_u8;

        let message_length_bits =
            if hash.message_length as u128 +
                remaining_data.len() as u128 * 8_u128 > u64::MAX as u128 {
                // todo maybe throw an error here?
                panic!("cannot hash more than 2**64 - 1 bits.")
            } else {
                hash.message_length + (remaining_data.len() * 8) as u64
            };

        // if there is not enough space for the message length to be appended, a new block must be
        // created
        if remaining_data.len() + 1 + size_of::<u64>() > BLOCK_LENGTH_BYTES {
            let mut overflow_block = [0_u8; BLOCK_LENGTH_BYTES];
            // append the message length in bits
            for i in 0..8 {
                // note, that the number is appended backwards because it must be handled as a big endian number
                overflow_block[BLOCK_LENGTH_BYTES - i - 1] =
                    (message_length_bits >> (i * 8) as u64) as u8;
            }

            round_function(hash, &last_block);
            round_function(hash, &overflow_block);
        } else {
            // append the message length in bits
            for i in 0..8 {
                // note, that the number is appended backwards because it must be handled as a big endian number
                last_block[63 - i] = (message_length_bits >> (i * 8) as u64) as u8;
            }

            round_function(hash, &last_block);
        }

        hash.hash
    }

    fn digest_message(ctx: &Self::Context, input: &[u8]) -> Self::HashData {
        let mut hash_state = Self::init_hash(ctx);

        // digest all data
        Self::update_hash(&mut hash_state, ctx, &input);

        // finish hashing by padding the remaining data within the hash state and digesting it
        Self::finish_hash(&mut hash_state, ctx);

        hash_state.hash
    }
}

impl HashValue for SHA1Hash {
    /// Generates a raw `[u8; 20]` array from the current hash state.
    fn raw(&self) -> Vec<u8> {
        unsafe {
            mem::transmute::<[u32; 5], [u8; 20]>([
                u32::from_be(self.a),
                u32::from_be(self.b),
                u32::from_be(self.c),
                u32::from_be(self.d),
                u32::from_be(self.e),
            ])
        }
            .to_vec()
    }
}

impl BlockHashFunction for SHA1Hash {
    fn block_size(_ctx: &Self::Context) -> usize {
        BLOCK_LENGTH_BYTES
    }

    fn output_size(_ctx: &Self::Context) -> usize {
        mem::size_of::<Self>()
    }
}
