use std::future::Future;
use std::pin::Pin;

use futures::{future::join_all, join};

use jester_maths::prime::PrimeField;

use crate::{
    CliqueCommunicationScheme, LinearSharingScheme, MultiplicationScheme,
    ThresholdSecretSharingScheme, UnboundedMultiplicationScheme,
};
use std::marker::PhantomData;

/// This trait models a communication scheme between parties to generate or otherwise obtain random share triples
/// `([a], [b], [c])` where `c = a * b` holds. Those triples are required for the beaver multiplication scheme.
pub trait BeaverCommunicationScheme<S> {
    /// Get the reconstruction threshold of the threshold secret sharing scheme used beneath this scheme.
    fn get_reconstruction_threshold(&self) -> usize;

    /// Obtain random triples of shares `([a], [b], [c])` where `c = a * b` holds. Every participant must use shares
    /// of the same triple during the same multiplication. This function cannot be called in parallel.
    fn obtain_beaver_triples<'a>(
        &'a mut self,
        count: usize,
    ) -> Pin<Box<dyn Future<Output = Vec<(S, S, S)>> + Send + 'a>>;
}

pub struct BeaverRerandomizationMultiplication<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + BeaverCommunicationScheme<S>,
    T: PrimeField + Send + Sync,
    S: Send + Sync + 'static,
{
    data: PhantomData<T>,
    share: PhantomData<S>,
    protocol: PhantomData<P>,
}

impl<P, T, S> UnboundedMultiplicationScheme<T, S, P>
    for BeaverRerandomizationMultiplication<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + BeaverCommunicationScheme<S>
        + CliqueCommunicationScheme<T, S>
        + Send
        + Sync,
    T: PrimeField + Send + Sync,
    S: Clone + Send + Sync + 'static,
{
    fn unbounded_multiply<'a>(
        protocol: &'a mut P,
        pairs: &[(S, S)],
    ) -> Pin<Box<dyn Future<Output = Vec<S>> + Send + 'a>> {
        let pairs_clone: Vec<_> = pairs.to_vec();

        Box::pin(async move {
            let beaver_triples = protocol.obtain_beaver_triples(pairs_clone.len()).await;

            let multiplications = pairs_clone
                .into_iter()
                .zip(beaver_triples.clone())
                .map(|((lhs, rhs), (a, b, _))| {
                    let epsilon_share = P::sub_shares(&lhs, &a);
                    let delta_share = P::sub_shares(&rhs, &b);

                    let delta = protocol.reveal_shares(delta_share);
                    let epsilon = protocol.reveal_shares(epsilon_share);

                    async { join!(delta, epsilon) }
                })
                .collect::<Vec<_>>();

            join_all(multiplications)
                .await
                .into_iter()
                .zip(beaver_triples)
                .map(|((delta, epsilon), (a, b, c))| {
                    P::add_scalar(
                        &P::add_shares(
                            &P::add_shares(&c, &P::multiply_scalar(&b, &epsilon)),
                            &P::multiply_scalar(&a, &delta),
                        ),
                        &(epsilon.clone() * delta.clone()),
                    )
                })
                .collect()
        })
    }
}

impl<P, T, S> MultiplicationScheme<T, S, P> for BeaverRerandomizationMultiplication<T, S, P>
where
    P: BeaverCommunicationScheme<S>
        + ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + BeaverCommunicationScheme<S>
        + Send
        + Sync,
    T: PrimeField + Send + Sync,
    S: Clone + Send + Sync + 'static,
{
    fn multiply<'a>(
        protocol: &'a mut P,
        lhs: &S,
        rhs: &S,
    ) -> Pin<Box<dyn Future<Output = S> + Send + 'a>> {
        let lhs = lhs.clone();
        let rhs = rhs.clone();

        Box::pin(async move {
            let (a, b, c) = protocol.obtain_beaver_triples(1).await.pop().unwrap();

            let epsilon_share = P::sub_shares(&lhs, &a);
            let delta_share = P::sub_shares(&rhs, &b);

            let (delta, epsilon) = join!(
                protocol.reveal_shares(delta_share),
                protocol.reveal_shares(epsilon_share)
            );

            P::add_scalar(
                &P::add_shares(
                    &P::add_shares(&c, &P::multiply_scalar(&b, &epsilon)),
                    &P::multiply_scalar(&a, &delta),
                ),
                &(epsilon.clone() * delta.clone()),
            )
        })
    }
}
