use crate::{
    CliqueCommunicationScheme, CryptoRng, LinearSharingScheme, PrimeField,
    RandomNumberGenerationScheme, RngCore, ThresholdSecretSharingScheme,
};
use futures::Future;
use std::marker::PhantomData;
use std::pin::Pin;

/// A marker struct that delegates to a non-zero random number generation scheme. This does not actually guarantee
/// that zero is not generated, it just works for test-cases with a singular participant. Therefore this protocol is
/// not within the public API (as it does not provide any advantages). It is only used for internal test cases.
pub(crate) struct SumNonZeroRandomNumberGeneration<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>,
    T: PrimeField,
    S: 'static,
{
    data: PhantomData<T>,
    share: PhantomData<S>,
    protocol: PhantomData<P>,
}

impl<T, S, P> RandomNumberGenerationScheme<T, S, P> for SumNonZeroRandomNumberGeneration<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>,
    T: PrimeField,
    S: 'static,
{
    fn generate_random_number_sharing<R>(
        rng: &mut R,
        protocol: &mut P,
    ) -> Pin<Box<dyn Future<Output = S>>>
    where
        R: RngCore + CryptoRng,
    {
        let mut rand_partial = T::generate_random_member(rng);
        while rand_partial.is_zero() {
            rand_partial = T::generate_random_member(rng);
        }

        let all_shares_future = protocol.distribute_secret(rand_partial);

        Box::pin(async move { P::sum_shares(&all_shares_future.await).unwrap() })
    }
}
