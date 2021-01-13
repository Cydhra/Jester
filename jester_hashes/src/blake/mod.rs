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
    vector[c] = vector[c].wrapping_add(&vector[b]);
    vector[b] = (vector[b] ^ vector[c]).rotate_right(R2.try_into().unwrap());

    vector[a] = vector[a].wrapping_add(&vector[b]).wrapping_add(&y);
    vector[d] = (vector[d] ^ vector[a]).rotate_right(R3.try_into().unwrap());
    vector[c] = vector[c].wrapping_add(&vector[d]);
    vector[b] = (vector[b] ^ vector[c]).rotate_right(R4.try_into().unwrap());
}