#![allow(clippy::needless_return)]

#[cfg(test)]
mod tests {
    use hex;

    use crate::hash::merkle_damgard::md5::MD5Hash;
    use crate::hash::merkle_damgard::MerkleDamagardHash;

    #[test]
    fn test_md5() {
        assert_eq!("d41d8cd98f00b204e9800998ecf8427e",
                   hex::encode(MD5Hash::digest_message(&"".as_bytes()).to_raw()));
        assert_eq!("5748be477f8cab2e6d785cd2412b823c",
                   hex::encode(MD5Hash::digest_message(
                       &"a-very-long-message-that-cannot-be-digested-at-once".as_bytes()).to_raw()))
    }
}

pub mod array_util;
pub mod hash;


