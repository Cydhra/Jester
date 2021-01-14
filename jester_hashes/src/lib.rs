//! This crate contains various software-implementations of common hash algorithms. All implementations offer
//! granular APIs, so the hash can be manually forged and manipulated.

use std::{mem::MaybeUninit, ptr};

pub mod hmac;
pub mod kdf;
pub mod md5;
pub mod sha1;
pub mod blake;

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

/// Output of a `HashFunction`.
pub trait HashValue {
    /// Obtain the hash as a raw byte array.
    fn raw(&self) -> Vec<u8>;
}

/// An implementation of a hashing algorithm. It defines three implementation dependent types,
/// one of which is the output hash type.
pub trait HashFunction {
    /// Implementation dependent context during hashing. May contain parameters specific to the
    /// algorithm.
    type Context;

    /// Contains the current unfinished hash value. It is constructed using `init_hash` and then
    /// used by this function as the target vector where all data is compressed into.
    type HashState;

    /// Final hash value that is obtained through completion of the hashing function. It may be
    /// the same type as `Self::HashState` though it is treated as a separate type to ensure
    /// correct usage.
    type HashData: HashValue;

    /// Obtain an initial hash value (usually the IV) conforming to the parameters set by the
    /// given `Self::Context`. The given `ctx` value may not be changed or
    fn init_hash(ctx: &Self::Context) -> Self::HashState;

    /// Update the hash with more data. If not all data can be consumed, the remaining buffer
    /// will be stored within the given context structure.
    fn update_hash(hash: &mut Self::HashState, ctx: &Self::Context, input: &[u8]);

    /// Finish the hash using the last bit of input data. The resulting hash is returned. The
    /// given `ctx` is then in a final state and may not be used for further hashing without a
    /// previous call of `init_hash`.
    fn finish_hash(hash: &mut Self::HashState, ctx: &Self::Context) -> Self::HashData;

    /// Convenience method to initialize a hash state and completely compress the given `input`
    /// into it. Then the final hash is returned.
    fn digest_message(ctx: &Self::Context, input: &[u8]) -> Self::HashData;
}

/// A special hash function that consumes input in blocks of uniform size.
pub trait BlockHashFunction: HashFunction {
    /// Obtain the block size this hash consumes given the specified context.
    fn block_size(ctx: &Self::Context) -> usize;

    /// Obtain the output size this hash will produce given the specified context.
    fn output_size(ctx: &Self::Context) -> usize;
}

#[cfg(test)]
pub(crate) mod tests {
    use hex;

    use super::*;
    use super::md5::MD5Hash;
    use super::sha1::SHA1Hash;
    use std::ptr::hash;

    pub const EMPTY_MESSAGE: &str = "";

    pub const SOME_TEXT: &str = "a-very-long-message-that-can-be-digested-at-once";

    pub const LONG_TEXT: &str = "And Ion held six fingers aloft and upon their spears did the \
soldiers impale themselves. \"For you!\" they cried before the blood drowned their tongues. \
And Ion said, \"Now do you see?\" And Nadox wept, as more did skewer themselves in Ion's name, \
for he had seen and now knew the truth of his words.";

    pub const STREAM_TEXT: [&str; 3] = [
        "Then Ion called the Klavigar to Him, and together they sat for a time within the heart \
of the Leviathan. They spoke of many things, of the darkness to come, and of the Fall. For the \
Ozirmok knew of what would befall them all at Kythera. ",
        "And, in turn, He bade each of them to go forth and set in motion the beginning of the \
Great Plan. To Orok and to his disciple Halyna Ieva, He bade them to create the \
beginnings of a great force, one to rival that of the halkostana, but to do so in secret. \
To Lovataar and her disciple Kalakaran, to study the root of small things, to understand \
unto even the base of life itself. To learn all there was to know of how to spread the \
Flesh. ",
        "To Saarn and her disciple Naman, He bade to study life itself, how to consume more than \
merely the flesh, but to study the vitality of the soul. And finally, onto Nadox and his \
disciple Zhizao, He laid the heaviest burden. To carry the weight of the Nalmasak, that \
which was His Holy Word. To bring forth His vision, to make it manifest in the world \
after He was gone."
    ];

    #[test]
    fn test_md5() {
        assert_eq!(
            hex::encode(&MD5Hash::digest_message(&(), EMPTY_MESSAGE.as_bytes()).raw()),
            "d41d8cd98f00b204e9800998ecf8427e"
        );

        assert_eq!(
            hex::encode(&MD5Hash::digest_message(&(), SOME_TEXT.as_bytes()).raw()),
            "9cf653b21b12797c80f769c8a753c360"
        );

        assert_eq!(
            hex::encode(&MD5Hash::digest_message(&(), LONG_TEXT.as_bytes()).raw()),
            "fd87f4b9821fe2223f006c3495324541"
        );
    }

    #[test]
    fn test_md5_stream() {
        let ctx = ();
        let mut hash_state = MD5Hash::init_hash(&ctx);
        MD5Hash::update_hash(&mut hash_state, &ctx, STREAM_TEXT[0].as_bytes());
        MD5Hash::update_hash(&mut hash_state, &ctx, STREAM_TEXT[1].as_bytes());
        MD5Hash::update_hash(&mut hash_state, &ctx, STREAM_TEXT[2].as_bytes());

        let hash = MD5Hash::finish_hash(&mut hash_state, &ctx);
        assert_eq!(hex::encode(hash.raw()), "4ede84ae4c00b7c8f1683ca6bbacd3b1");
    }

    #[test]
    fn test_sha1() {
        assert_eq!(
            hex::encode(&SHA1Hash::digest_message(&(), EMPTY_MESSAGE.as_bytes()).raw()),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );

        assert_eq!(
            hex::encode(&SHA1Hash::digest_message(&(), SOME_TEXT.as_bytes()).raw()),
            "931bec5eec465b2e742deafbdcae2681820a4ac9"
        );

        assert_eq!(
            hex::encode(&SHA1Hash::digest_message(&(), LONG_TEXT.as_bytes()).raw()),
            "ae410e98987c6543498833540e93dd7129fc8e0b"
        );
    }

    #[test]
    fn test_sha1_stream() {
        let ctx = ();
        let mut hash_state = SHA1Hash::init_hash(&ctx);
        SHA1Hash::update_hash(&mut hash_state, &ctx, STREAM_TEXT[0].as_bytes());
        SHA1Hash::update_hash(&mut hash_state, &ctx, STREAM_TEXT[1].as_bytes());
        SHA1Hash::update_hash(&mut hash_state, &ctx, STREAM_TEXT[2].as_bytes());

        let hash = SHA1Hash::finish_hash(&mut hash_state, &ctx);
        assert_eq!(hex::encode(hash.raw()), "c11280314809ce63f5d17a92b9a858317141f747");
    }

    #[test]
    fn test_align_to_u32a_le() {
        let mut dest = [0u32; 2];
        unsafe { align_to_u32a_le(&mut dest, &[0x78, 0x56, 0x34, 0x12, 0xFF, 0x00, 0xFF, 0x00]) }
        assert_eq!([0x1234_5678u32, 0x00FF_00FFu32], dest)
    }
}
