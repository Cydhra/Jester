use num::traits::WrappingAdd;
use num::PrimInt;
use std::convert::TryInto;

pub mod blake2b;
pub mod blake2s;

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
    vector[c] = vector[c].wrapping_add(&vector[d]);
    vector[b] = (vector[b] ^ vector[c]).rotate_right(R2.try_into().unwrap());

    vector[a] = vector[a].wrapping_add(&vector[b]).wrapping_add(&y);
    vector[d] = (vector[d] ^ vector[a]).rotate_right(R3.try_into().unwrap());
    vector[c] = vector[c].wrapping_add(&vector[d]);
    vector[b] = (vector[b] ^ vector[c]).rotate_right(R4.try_into().unwrap());
}

#[cfg(test)]
pub(crate) mod blake2_tests {
    use crate::blake::blake2b::{Blake2bHash, Blake2bContext};
    use crate::{HashFunction, HashValue};
    use crate::tests::{EMPTY_MESSAGE, SOME_TEXT, LONG_TEXT};

    #[test]
    fn blake2b_tests() {
        let ctx = Blake2bContext {
            output_len: 64,
            key: vec![]
        };

        assert_eq!(
            hex::encode(&Blake2bHash::digest_message(&ctx, EMPTY_MESSAGE.as_bytes()).raw()),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );

        assert_eq!(
            hex::encode(&Blake2bHash::digest_message(&ctx, SOME_TEXT.as_bytes()).raw()),
            "fc918cde2b169d192d19438620f2a9b1d1d4cce16dc8b8e8600377a577a74ace2a65a21f1cb3d3f0e3abf97e88d804e8aa4d674df143e7070976018e2ae9060f"
        );

        assert_eq!(
            hex::encode(&Blake2bHash::digest_message(&ctx, LONG_TEXT.as_bytes()).raw()),
            "ef403f8bd8f4f821376cf108e5004c78df3b7a99d198c166c7b8d1e6a409e10312bc273e3299a755b2cf75a5db85222266dd77215f80340363359656c621bf69"
        );
    }
}