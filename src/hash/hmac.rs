use crate::hash::HashFunction;

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
        H::raw(&H::digest_message(key))
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
    outer_message.append(&mut H::raw(&H::digest_message(&inner_message)).into());

    H::raw(&H::digest_message(&outer_message)).into()
}

fn pad(key: &[u8], length: usize) -> Box<[u8]> {
    let mut padded_vec = key.to_vec();
    padded_vec.extend_from_slice(&vec![0u8; length - key.len()]);
    padded_vec.into_boxed_slice()
}