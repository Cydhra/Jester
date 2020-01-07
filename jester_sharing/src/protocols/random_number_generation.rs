use std::future::Future;

use crate::{CliqueCommunicationScheme, LinearSharingScheme, ThresholdSecretSharingScheme};

use crate::protocols::{CryptoRng, PrimeField, RngCore};

/// A protocol to generate a secret random number where every participant has a share on that number, but no
/// participant learns the actual value of that number.
///
/// # Parameters
/// - `rng` a cryptographically secure random number generator
/// - `protocol` an instance of the protocol to be used. It must be a linear `ThresholdSecretSharingScheme` with
/// `PeerToPeerPartyScheme` communication style
///
/// # Returns
/// Returns a future on the value that is to be generated. The future does not hold references to `rng` and
/// `protocol` so this method can be called multiple times in parallel.
pub fn joint_random_number_sharing<R, T, S, P>(
    rng: &mut R,
    protocol: &mut P,
) -> impl Future<Output = S>
where
    R: RngCore + CryptoRng,
    T: PrimeField,
    S: 'static,
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>,
{
    let rand_partial = T::generate_random_member(rng);
    let all_shares_future = protocol.distribute_secret(rand_partial);

    async move { P::sum_shares(&all_shares_future.await).unwrap() }
}

/// A protocol to generate a secret random number where every participant has a share on that number, but no
/// participant learns the actual value of that number. This protocol involves that every party
/// member generates a private random element. To avoid generating zero, this protocol will be
/// regenerating the private random element until it is not zero. Since this does not guarantee
/// that the random shared value is not actually zero and, moreover, could alter the
/// probabilistic distribution of generated values, this method is not public.
///
/// # Parameters
/// - `rng` a cryptographically secure random number generator
/// - `protocol` an instance of the protocol to be used. It must be a linear `ThresholdSecretSharingScheme` with
/// `PeerToPeerPartyScheme` communication style
///
/// # Returns
/// Returns a future on the value that is to be generated. The future does not hold references to `rng` and
/// `protocol` so this method can be called multiple times in parallel.
pub(crate) fn joint_random_non_zero_number_sharing<R, T, S, P>(
    rng: &mut R,
    protocol: &mut P,
) -> impl Future<Output = S>
where
    R: RngCore + CryptoRng,
    T: PrimeField,
    S: 'static,
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>,
{
    let mut rand_partial = T::generate_random_member(rng);
    while rand_partial.is_zero() {
        rand_partial = T::generate_random_member(rng);
    }

    let all_shares_future = protocol.distribute_secret(rand_partial);

    async move { P::sum_shares(&all_shares_future.await).unwrap() }
}
