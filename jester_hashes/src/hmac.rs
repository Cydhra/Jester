use crate::{BlockHashFunction, HashValue};

/// Generate a keyed-hash message authentication code from a `HashFunction` and a given key using the HMAC protocol
/// of RFC 2104.
/// #Parameters
/// - `key` a secret key for the authentication code
/// - `message` an arbitrary-sized message to authenticate
/// - `H` an arbitrary hash function
///
/// #Outputs
/// Returns a boxed slice containing the raw authentication code
pub fn hmac<Hash, Context>(ctx: &Context, key: &[u8], message: &[u8]) -> Vec<u8>
    where Hash: BlockHashFunction<Context=Context>,
{
    let block_size = Hash::block_size(ctx);

    let shortened_key = if key.len() > block_size {
        Hash::digest_message(ctx, key).raw()
    } else {
        key.into()
    };

    let padded_key = if shortened_key.len() < block_size {
        pad(key, block_size)
    } else {
        shortened_key
    };

    let mut outer_message = padded_key
        .clone()
        .iter()
        .map(|v| v ^ 0x5C)
        .collect::<Vec<_>>();
    let mut inner_message = padded_key.iter().map(|v| v ^ 0x36).collect::<Vec<_>>();

    inner_message.append(&mut message.to_vec());
    outer_message.append(&mut Hash::digest_message(ctx,&inner_message).raw().into());

    Hash::digest_message(ctx, &outer_message).raw()
}

fn pad(key: &[u8], length: usize) -> Vec<u8> {
    let mut padded_vec = key.to_vec();
    padded_vec.extend_from_slice(&vec![0_u8; length - key.len()]);
    padded_vec
}

#[cfg(test)]
mod tests {
    use crate::md5::MD5Hash;

    use super::hmac;

    const HMAC_EXAMPLE: &[u8] = b"The quick brown fox jumps over the lazy dog";

    #[test]
    fn test_hmac_md5() {
        assert_eq!(
            hex::encode(hmac::<MD5Hash, ()>(&(),b"key", HMAC_EXAMPLE)),
            "80070713463e7749b90c2dc24911e275"
        );
    }

    #[test]
    fn test_hmac_sha1() {
        // assert_eq!(
        //     hex::encode(hmac::<SHA1Hash, ()>(&(),b"key", HMAC_EXAMPLE)),
        //     "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
        // );
    }
}
