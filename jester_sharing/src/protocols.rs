use std::future::Future;

use rand::{CryptoRng, RngCore};

use jester_algebra::PrimeField;

use crate::{LinearSharingScheme, PeerToPeerPartyScheme, ThresholdSecretSharingScheme};

/// A protocol to generate a secret random number where every participant has a share on that number, but no
/// participant learns the actual value of that number.
/// #Parameters
/// - `rng` a cryptographically secure random number generator
/// - `protocol` an instance of the protocol to be used. It must be a linear `ThresholdSecretSharingScheme` with
/// `PeerToPeerPartyScheme` communication style
///
/// #Output
/// Returns a future on the value that is to be generated. The future does not hold references to `rng` and
/// `protocol` so this method can be called multiple times in parallel.
pub fn joint_random_number_sharing<R, T, S, P>(rng: &mut R, protocol: &mut P) -> impl Future<Output=S>
    where R: RngCore + CryptoRng,
          T: PrimeField,
          S: 'static,
          P: ThresholdSecretSharingScheme<T, S> + LinearSharingScheme<S> + PeerToPeerPartyScheme<T, S, P> {
    let rand_partial = T::generate_random_member(rng);
    let all_shares_future = protocol.distribute_secret(rand_partial);

    async move {
        P::sum_shares(&all_shares_future.await).unwrap()
    }
}