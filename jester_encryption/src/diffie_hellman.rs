use rand::{CryptoRng, RngCore};

use jester_algebra::prime::PrimeField;

/// A trait representing the symmetric key exchange scheme proposed by Diffie, Hellman and Merkle. It can be used
/// between two or more parties, according to the proposal.
/// # Associated Types
/// - `PublicKey` the public values exchanged during the protocol.
/// - `PrivateKey` the private value that must not be shared with anyone
/// - `SharedKey` the shared secret generated by the protocol
/// Those types might be all the same, however the protocol still differentiates, to avoid parameter confusion by
/// implementors.
pub trait DiffieHellmanKeyExchangeScheme {
    type PublicKey;
    type PrivateKey;
    type SharedKey;

    /// Generate a random number a and raise the `generator` to the power of `a`. This number is the private key part
    /// and the calculated power is the public part of the Diffie-Hellman-Key-Exchange.
    /// #Parameters
    /// - `rng` cryptographically secure random number generator
    /// - `generator` a publicly known, common generator for `T`
    fn generate_asymmetrical_key_pair<R>(
        rng: &mut R,
        generator: &Self::PublicKey,
    ) -> (Self::PrivateKey, Self::PublicKey)
    where
        R: RngCore + CryptoRng;

    /// Generate the shared secret from the public key received by the other party.
    /// #Parameters
    /// - `private_key` the private key that was generated by `generate_public_key`
    /// - `partner_key` the other party's public key
    fn generate_shared_secret(
        private_key: &Self::PrivateKey,
        partner_key: &Self::PublicKey,
    ) -> Self::SharedKey;
}

/// Implementation of the `DiffieHellmanKeyExchangeScheme` for all `PrimeField` types
/// #Type Parameters
/// - `T` the numerical type the protocol is implemented for
impl<T> DiffieHellmanKeyExchangeScheme for T
where
    T: PrimeField,
{
    type PublicKey = T;
    type PrivateKey = T;
    type SharedKey = T;

    fn generate_asymmetrical_key_pair<R>(
        rng: &mut R,
        generator: &Self::PublicKey,
    ) -> (Self::PrivateKey, Self::PublicKey)
    where
        R: RngCore + CryptoRng,
    {
        let a = Self::PublicKey::generate_random_member(rng);
        (
            a.clone(),
            generator
                .as_uint()
                .modpow(&a.as_uint(), &T::field_prime().as_uint())
                .into(),
        )
    }

    fn generate_shared_secret(
        private_key: &Self::PrivateKey,
        partner_key: &Self::PublicKey,
    ) -> Self::SharedKey {
        partner_key
            .as_uint()
            .modpow(&private_key.as_uint(), &T::field_prime().as_uint())
            .into()
    }
}
