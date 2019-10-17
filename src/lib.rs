#![allow(clippy::needless_return)]

#[cfg(test)]
mod tests {
    use hex;

    use crate::hash::merkle_damgard::md5::MD5Hash;
    use crate::hash::merkle_damgard::MerkleDamagardHash;
    use crate::hash::merkle_damgard::sha1::SHA1Hash;

    #[test]
    fn test_md5() {
        assert_eq!(hex::encode(MD5Hash::digest_message(&"".as_bytes()).to_raw()),
                   "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex::encode(MD5Hash::digest_message(
                       &"a-very-long-message-that-cannot-be-digested-at-once".as_bytes()).to_raw()),
                   "5748be477f8cab2e6d785cd2412b823c")
    }

    #[test]
    fn test_sha1() {
        assert_eq!(hex::encode(SHA1Hash::digest_message(&"".as_bytes()).to_raw()),
                   "da39a3ee5e6b4b0d3255bfef95601890afd80709",);
        assert_eq!(hex::encode(SHA1Hash::digest_message(
                       &"a-very-long-message-that-cannot-be-digested-at-once".as_bytes()).to_raw()),
                   "fc0557cb580c6cc1949f126d0020ef6e7eadba7d")
    }
}

pub mod array_util;
pub mod hash;


