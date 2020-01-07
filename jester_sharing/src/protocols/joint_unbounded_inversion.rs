use futures::future::join_all;

use crate::{
    CliqueCommunicationScheme, LinearSharingScheme, ParallelMultiplicationScheme,
    ThresholdSecretSharingScheme,
};

use crate::protocols::{joint_random_non_zero_number_sharing, CryptoRng, PrimeField, RngCore};

/// A protocol inverting an unbounded amount of shares in parallel. The protocol requires two round-trip-times in a
/// `CliqueCommunicationScheme`. This protocol relies on the fact, tht the input parameters are not zero. If one
/// input parameter is a share on the value zero, the protocol will output random garbage. Since the garbage might not
/// lead to a successful calculation, participants could learn that the input had at least one zero in it.
///
/// # Parameters
/// - `rng` a cryptographically secure random number generator
/// - `protocol` an instance of the sub-protocols used. It must be a `ThresholdSecretSharingScheme` with additive
/// linear shares and communication between all participants. Furthermore, parallel multiplication by communication
/// must be supported.
/// - `elements` the shares that shall be inverted
///
/// # Returns
/// Returns a `Vec` of shares that are the inverted input elements in the same order.
pub async fn joint_unbounded_inversion<R, T, S, P>(
    rng: &mut R,
    protocol: &mut P,
    elements: &[S],
) -> Vec<S>
where
    R: RngCore + CryptoRng,
    T: PrimeField,
    S: Clone + 'static,
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + ParallelMultiplicationScheme<T, S>,
{
    let bound = elements.len();
    let helpers: Vec<_> = (0..bound)
        .map(|_| joint_random_non_zero_number_sharing(rng, protocol))
        .collect();
    let helpers = join_all(helpers).await;

    let rerandomized_elements = protocol
        .parallel_multiply(
            &elements
                .iter()
                .cloned()
                .zip(helpers.clone())
                .collect::<Vec<_>>(),
        )
        .await;

    let revealed_elements = rerandomized_elements
        .into_iter()
        .map(|e| protocol.reveal_shares(e));
    let revealed_elements = join_all(revealed_elements).await;

    revealed_elements
        .into_iter()
        .zip(helpers)
        .map(|(hidden_element, helper)| P::multiply_scalar(&helper, &hidden_element.inverse()))
        .collect()
}
