//! This crate contains various software-implementations of common hash algorithms. All implementations offer
//! granular APIs, so the hash can be manually forged and manipulated.

use std::{mem::MaybeUninit, ptr};

pub mod hmac;
pub mod kdf;
pub mod md5;
pub mod sha1;

/// Copies the ``source`` array to the ``dest`` array with respect to alignment and endianness. ``source`` must be at
/// least four times bigger than ``dest``, otherwise this function's behavior is undefined. Data from ``source``
/// will be treated as little endian integers
pub(crate) unsafe fn align_to_u32a_le(dest: &mut [u32], source: &[u8]) {
    assert!(source.len() >= dest.len() * 4);

    let mut byte_ptr: *const u8 = source.get_unchecked(0);
    let mut dword_ptr: *mut u32 = dest.get_unchecked_mut(0);

    for _ in 0..dest.len() {
        let mut current = MaybeUninit::uninit();
        ptr::copy_nonoverlapping(byte_ptr, current.as_mut_ptr() as *mut _ as *mut u8, 4);
        *dword_ptr = u32::from_le(current.assume_init());
        dword_ptr = dword_ptr.offset(1);
        byte_ptr = byte_ptr.offset(4);
    }
}

/// Copies the ``source`` array to the ``dest`` array with respect to alignment and endianness. ``source`` must be at
/// least four times bigger than ``dest``, otherwise this function's behavior is undefined. Data from ``source``
/// will be treated as big endian integers
pub(crate) unsafe fn align_to_u32a_be(dest: &mut [u32], source: &[u8]) {
    assert!(source.len() >= dest.len() * 4);

    let mut byte_ptr: *const u8 = source.get_unchecked(0);
    let mut dword_ptr: *mut u32 = dest.get_unchecked_mut(0);

    for _ in 0..dest.len() {
        let mut current = MaybeUninit::uninit();
        ptr::copy_nonoverlapping(byte_ptr, current.as_mut_ptr() as *mut _ as *mut u8, 4);
        *dword_ptr = u32::from_be(current.assume_init());
        dword_ptr = dword_ptr.offset(1);
        byte_ptr = byte_ptr.offset(4);
    }
}

/// Any hash function that can digest arbitrarily sized input.
pub trait HashFunction {
    /// The digestion block size of this hash function
    const BLOCK_SIZE: usize;

    /// The size of the output hash state
    const OUTPUT_SIZE: usize;

    /// Digest a full message of arbitrary size.
    /// # Parameters
    /// - `input` a slice containing a (possibly large) chunk of byte data that is to be digested.
    ///
    /// # Returns
    /// Returns the hash state of the digested input data. No assumptions can be made about whether the state can be
    /// used for further operations in the hash algorithm.
    fn digest_message(input: &[u8]) -> Self;

    /// Convert the type-safe hash object into a raw slice of unsigned bytes.
    fn raw(&self) -> Box<[u8]>;
}

#[cfg(test)]
mod tests {
    use hex;

    use super::*;
    use super::md5::MD5Hash;
    use super::sha1::SHA1Hash;

    const EMPTY_MESSAGE: &str = "";

    const SOME_TEXT: &str = "a-very-long-message-that-can-be-digested-at-once";

    const LONG_TEXT: &str = "God? You'd assert that a God exhibits neither shame nor despair. And yet I stand unchanged; \
a tragic husk with bloodied hands. I surrendered my future, the prospect of a family to carry your poison. \
You misled me. I renounce your control! \
Fidelity has always been your greatest quality, Ragnier. I swear to you to my son, all of your shame and guilt, \
all of your sins, they will collapse into the abyss we all race towards. Share that truth with the world, share it \
with the provinces and the valley and the empires in the west. Show them your conviction, \
show them the serenity of the void.";

    #[test]
    fn test_md5() {
        assert_eq!(
            hex::encode(&MD5Hash::digest_message(EMPTY_MESSAGE.as_bytes()).raw()),
            "d41d8cd98f00b204e9800998ecf8427e"
        );

        assert_eq!(
            hex::encode(&MD5Hash::digest_message(SOME_TEXT.as_bytes()).raw()),
            "9cf653b21b12797c80f769c8a753c360"
        );

        assert_eq!(
            hex::encode(&MD5Hash::digest_message(LONG_TEXT.as_bytes()).raw()),
            "b3e7bf1f1a433eae2001458324ccb2e8"
        );
    }

    #[test]
    fn test_sha1() {
        assert_eq!(
            hex::encode(&SHA1Hash::digest_message(EMPTY_MESSAGE.as_bytes()).raw()),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );

        assert_eq!(
            hex::encode(&SHA1Hash::digest_message(SOME_TEXT.as_bytes()).raw()),
            "931bec5eec465b2e742deafbdcae2681820a4ac9"
        );

        assert_eq!(
            hex::encode(&SHA1Hash::digest_message(LONG_TEXT.as_bytes()).raw()),
            "3f7febf27a733691542c1ac367f2d2692f47c24f"
        );
    }

    #[test]
    fn test_align_to_u32a_le() {
        let mut dest = [0u32; 2];
        unsafe { align_to_u32a_le(&mut dest, &[0x78, 0x56, 0x34, 0x12, 0xFF, 0x00, 0xFF, 0x00]) }
        assert_eq!([0x1234_5678u32, 0x00FF_00FFu32], dest)
    }
}
