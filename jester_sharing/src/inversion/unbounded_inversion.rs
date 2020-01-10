use futures::future::join_all;

use crate::{
    CliqueCommunicationScheme, InversionScheme, LinearSharingScheme, ParallelMultiplicationScheme,
    RandomNumberGenerationScheme, ThresholdSecretSharingScheme, UnboundedInversionScheme,
};

use crate::{CryptoRng, PrimeField, RngCore};
use futures::Future;
use std::marker::PhantomData;
use std::pin::Pin;

/// A protocol inverting an unbounded amount of shares in parallel. The protocol requires two round-trip-times in a
/// `CliqueCommunicationScheme`. This protocol relies on the fact, tht the input parameters are not zero. If one
/// input parameter is a share on the value zero, the protocol will output random garbage. Since the garbage might not
/// lead to a successful calculation, participants could learn that the input had at least one zero in it.
pub struct JointUnboundedInversion<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + ParallelMultiplicationScheme<T, S>
        + RandomNumberGenerationScheme<T, S, P>,
    T: PrimeField,
    S: Clone + 'static,
{
    data: PhantomData<T>,
    share: PhantomData<S>,
    protocol: PhantomData<P>,
}

impl<T, S, P> InversionScheme<T, S, P> for JointUnboundedInversion<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + ParallelMultiplicationScheme<T, S>
        + RandomNumberGenerationScheme<T, S, P>
        + Send,
    T: PrimeField,
    S: Clone + 'static,
{
    fn inverse<'a, R>(
        rng: &'a mut R,
        protocol: &'a mut P,
        share: &S,
    ) -> Pin<Box<dyn Future<Output = S> + 'a>>
    where
        R: RngCore + CryptoRng,
    {
        let share_clone = share.clone();
        Box::pin(async move {
            let mut inverse_vec = Self::unbounded_inverse(rng, protocol, &[share_clone]).await;
            inverse_vec.pop().unwrap()
        })
    }
}

impl<T, S, P> UnboundedInversionScheme<T, S, P> for JointUnboundedInversion<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + ParallelMultiplicationScheme<T, S>
        + RandomNumberGenerationScheme<T, S, P>,
    T: PrimeField,
    S: Clone + 'static,
{
    fn unbounded_inverse<'a, R>(
        rng: &'a mut R,
        protocol: &'a mut P,
        shares: &[S],
    ) -> Pin<Box<dyn Future<Output = Vec<S>> + 'a>>
    where
        R: RngCore + CryptoRng,
    {
        let bound = shares.len();
        let helpers: Vec<_> = (0..bound)
            .map(|_| P::generate_random_number_sharing(rng, protocol))
            .collect();
        let shares_iter = shares.to_vec();

        Box::pin(async move {
            let helpers = join_all(helpers).await;

            let rerandomized_elements = protocol
                .parallel_multiply(
                    &shares_iter
                        .into_iter()
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
                .map(|(hidden_element, helper)| {
                    P::multiply_scalar(&helper, &hidden_element.inverse())
                })
                .collect()
        })
    }
}
