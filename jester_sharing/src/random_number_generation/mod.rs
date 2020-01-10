use crate::{
    CliqueCommunicationScheme, CryptoRng, Delegate, LinearSharingScheme, PrimeField, RngCore,
    ThresholdSecretSharingScheme,
};
use jester_sharing_proc::delegatable_protocol;
use futures::Future;
use std::pin::Pin;

//pub mod sum_not_zero_random_number_generation;
pub mod sum_non_zero_random_number_generation;
pub mod sum_random_number_generation;

/// A scheme that can be used to randomly generate a share of a number that is unknown to all participants. This
/// trait is not to be implemented on protocols, instead it will be used as a proxy for the actual implementations.
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
    ) -> Pin<Box<dyn Future<Output = S>>>
    where
        R: RngCore + CryptoRng;
}