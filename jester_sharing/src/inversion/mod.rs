use crate::{Delegate, LinearSharingScheme, PrimeField, ThresholdSecretSharingScheme};
use futures::Future;
use rand::{CryptoRng, RngCore};
use std::pin::Pin;

use jester_sharing_proc::delegatable_protocol;

pub mod unbounded_inversion;

/// A trait to generate the multiplicative inverse of a secret shared among the participants.
/// # Type Parameters
/// - `T` the secret type
/// - `S` the share type
/// - `P` the protocol this scheme operates in. It provides required primitives.
#[delegatable_protocol]
pub trait InversionScheme<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S> + LinearSharingScheme<T, S>,
    T: PrimeField,
    S: Clone + 'static,
{
    /// Asynchronously calculate the multiplicative inverse of the secret shared by `share`. If the secret evaluates
    /// to zero, the output of this function is undefined. Given the nature of secret sharing, it is impossible for
    /// the function to deterministically detect zero as input.
    /// # Parameters
    /// - `rng` a cryptographically secure random number generator
    /// - `protocol` the primitives required for this scheme
    /// - `share` a share of the secret to invert
    fn inverse<'a, R>(
        rng: &'a mut R,
        protocol: &'a mut P,
        share: &S,
    ) -> Pin<Box<dyn Future<Output = S> + 'a>>
    where
        R: RngCore + CryptoRng;
}

/// A trait to generate the multiplicative inverse of a set of secrets shared among the participants. Can be used to
/// invert multiple values in parallel.
/// # Type Parameters
/// - `T` the secret type
/// - `S` the share type
/// - `P` the protocol this scheme operates in. It provides required primitives.
#[delegatable_protocol]
pub trait UnboundedInversionScheme<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S> + LinearSharingScheme<T, S>,
    T: PrimeField,
    S: Clone + 'static,
{
    /// Asynchronously calculate the multiplicative inverse of the secrets shared by `shares`. If a secret evaluates
    /// to zero, the result of its inverse is undefined. Given the nature of secret sharing, it is impossible for
    /// the function to deterministically detect zero as input.
    /// # Parameters
    /// - `rng` a cryptographically secure random number generator
    /// - `protocol` the primitives required for this scheme
    /// - `shares` shares of the secrets to invert
    fn unbounded_inverse<'a, R>(
        rng: &'a mut R,
        protocol: &'a mut P,
        shares: &[S],
    ) -> Pin<Box<dyn Future<Output = Vec<S>> + 'a>>
    where
        R: RngCore + CryptoRng;
}
