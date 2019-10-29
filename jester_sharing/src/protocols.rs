use std::future::Future;

use rand::{CryptoRng, RngCore};

use jester_algebra::PrimeField;

use crate::{CliqueCommunicationScheme, LinearSharingScheme, MultiplicationScheme, ThresholdSecretSharingScheme};

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
          P: ThresholdSecretSharingScheme<T, S> + LinearSharingScheme<S> + CliqueCommunicationScheme<T, S> {
    let rand_partial = T::generate_random_member(rng);
    let all_shares_future = protocol.distribute_secret(rand_partial);

    async move {
        P::sum_shares(&all_shares_future.await).unwrap()
    }
}

/// A protocol for the joint selection of either side of a ternary expression `condition ? lhs : rhs` without
/// any participant learning the value of `condition` or the expression chosen by the protocol.
/// #Parameters
/// - `protocol` an instance of the sub-protocols used. It must be a `ThresholdSecretSharingScheme` with additive
/// linear shares and communication between all participants. Furthermore multiplication by communication must be
/// supported.
/// - `condition` a share on a value that resolves either to `0` or to `1`. Any other value will produce undefined
/// behaviour. Since this protocol does not leak information about `condition`, such an undefined result is
/// undetectable (at least until the result is evaluated)
/// - `lhs` the left hand side of the if-else expression that is taken, if `condition` evaluates to `1`
/// - `rhs` the right hand side of the if-else expression that is taken, if `condition` evaluates to `0`
///
/// #Output
/// Returns a future on either `lhs` or `rhs`, but in a rerandomized share, so a participant cannot learn which one
/// was taken.
pub fn joint_conditional_selection<T, S, P>(protocol: &mut P, condition: &S, lhs: &S, rhs: &S) -> impl Future<Output=S>
    where T: PrimeField,
          S: Clone,
          P: ThresholdSecretSharingScheme<T, S> + LinearSharingScheme<S> + CliqueCommunicationScheme<T, S> + MultiplicationScheme<T, S> {
    let operands_difference = P::sub_shares(lhs, rhs);

    // copy rhs to move a copy into the future
    let right_copy = rhs.clone();
    let product = protocol.mul(condition, &operands_difference);

    async move {
        P::add_shares(&product.await, &right_copy)
    }
}