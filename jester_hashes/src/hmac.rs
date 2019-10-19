use crate::HashFunction;

/// Generate a keyed-hash message authentication code from a `HashFunction` and a given key using the HMAC protocol
/// of RFC 2104.
/// #Parameters
/// - `key` a secret key for the authentication code
/// - `message` an arbitrary-sized message to authenticate
/// - `H` an arbitrary hash function
///
/// #Outputs
/// Returns a boxed slice containing the raw authentication code
pub fn hmac<H>(key: &[u8], message: &[u8]) -> Box<[u8]>
    where H: HashFunction {
    let shortened_key = if key.len() > H::BLOCK_SIZE {
        H::digest_message(key).raw()
    } else {
        key.into()
    };

    let padded_key = if shortened_key.len() < H::BLOCK_SIZE {
        pad(key, H::BLOCK_SIZE)
    } else {
        shortened_key
    };

    let mut outer_message = padded_key.clone().iter().map(|v| v ^ 0x5C).collect::<Vec<_>>();
    let mut inner_message = padded_key.clone().iter().map(|v| v ^ 0x36).collect::<Vec<_>>();

    inner_message.append(&mut message.to_vec());
    outer_message.append(&mut H::digest_message(&inner_message).raw().into());

    H::digest_message(&outer_message).raw()
}

fn pad(key: &[u8], length: usize) -> Box<[u8]> {
    let mut padded_vec = key.to_vec();
    padded_vec.extend_from_slice(&vec![0u8; length - key.len()]);
    padded_vec.into_boxed_slice()
}

#[cfg(test)]
mod tests {
    use crate::md5::MD5Hash;
    use crate::sha1::SHA1Hash;

    use super::hmac;

    const HMAC_EXAMPLE: &[u8] = b"The quick brown fox jumps over the lazy dog";

    #[test]
    fn test_hmac_md5() {
        assert_eq!(hex::encode(hmac::<MD5Hash>(b"key", HMAC_EXAMPLE)),
                   "80070713463e7749b90c2dc24911e275");
    }

    #[test]
    fn test_hmac_sha1() {
        assert_eq!(hex::encode(hmac::<SHA1Hash>(b"key", HMAC_EXAMPLE)),
                   "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
    }
}