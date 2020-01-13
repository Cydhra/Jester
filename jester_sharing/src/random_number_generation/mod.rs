use crate::{
    CliqueCommunicationScheme, CryptoRng, Delegate, LinearSharingScheme, PrimeField, RngCore,
    ThresholdSecretSharingScheme,
};
use futures::Future;
use jester_sharing_proc::delegatable_protocol;
use std::pin::Pin;

pub mod root_random_bit_generation;
pub mod sum_random_number_generation;

pub(crate) mod sum_non_zero_random_number_generation;

/// A scheme that can be used to randomly generate a share of a number that is unknown to all participants.
/// # Type Parameters
/// - `T` the secret type
/// - `S` the share type
/// - `P` the protocol this scheme requires. It requires at least a linear threshold scheme with clique communication.
#[delegatable_protocol]
pub trait RandomNumberGenerationScheme<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>,
    T: PrimeField,
    S: 'static,
{
    /// Generate a random number and obtain a share of it, without learning the random number.
    ///
    /// # Parameters
    /// - `rng` a cryptographically secure random number generator
    /// - `protocol` the protocol instance this scheme is used within.
    fn generate_random_number_sharing<R>(
        rng: &mut R,
        protocol: &mut P,
    ) -> Pin<Box<dyn Future<Output = S> + Send>>
    where
        R: RngCore + CryptoRng;
}

/// A scheme that can be used to randomly generate a share of a bit that is unknown to all participants.
#[delegatable_protocol]
pub trait RandomBitGenerationScheme<T, S, P>
where
    T: PrimeField,
{
    /// Generate a random number and obtain a share of it, without learning the random number.
    ///
    /// # Parameters
    /// - `rng` a cryptographically secure random number generator
    /// - `protocol` the protocol instance this scheme is used within.
    fn generate_random_bit<'a, R>(
        rng: &mut R,
        protocol: &'a mut P,
    ) -> Pin<Box<dyn Future<Output = S> + Send + 'a>>
    where
        R: RngCore + CryptoRng;
}
