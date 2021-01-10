//! Traits and implementations for key derivation functions

use std::f64;
use std::ops::Deref;

use crate::{HashContext, HashFunction, HashFunctionObsolete, BlockHashFunction};
use crate::hmac::hmac;

/// HMAC based key derivation function. A key of length `output_length` is generated.
pub fn hkdf_derive_key<Hash, Context>(ctx: &Context, salt: &[u8], ikm: &[u8], output_length: usize, info: &[u8]) -> Box<[u8]>
    where
        Context: HashContext,
        Hash: BlockHashFunction<Context=Context>
{
    let pseudo_random_key = hmac::<Hash, Context>(ctx, salt, ikm);
    let partials: usize = f64::ceil(output_length as f64 / Hash::output_size(ctx) as f64) as usize;
    let mut parts: Vec<Box<[u8]>> = vec![Box::from([]); partials + 1];

    for i in 1..=partials {
        parts[i] = hmac::<Hash, Context>(ctx, &*pseudo_random_key,
                        &vec![parts[i - 1].deref(), info, &[(i & 0xFF) as u8]].concat())
    }

    Box::from(parts.concat())
}


#[cfg(test)]
mod tests {
    #[test]
    fn test_hdkf() {
        // TODO
    }
}