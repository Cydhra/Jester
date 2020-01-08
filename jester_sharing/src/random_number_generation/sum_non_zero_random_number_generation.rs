use crate::{
    CliqueCommunicationScheme, CryptoRng, LinearSharingScheme, PrimeField,
    RandomNumberGenerationScheme, RngCore, ThresholdSecretSharingScheme,
};
use futures::Future;
use std::marker::PhantomData;
use std::pin::Pin;

/// A marker struct that delegates to a non-zero random number generation scheme.
/// # Usage
/// ```
/// use jester_sharing::{RandomNumberGenerationDelegate, ProtocolMarker, Delegate, ThresholdSecretSharingScheme, LinearSharingScheme, CliqueCommunicationScheme, PrimeField};
/// use jester_sharing::random_number_generation::sum_non_zero_random_number_generation
/// ::SumNonZeroRandomNumberGeneration;
///
/// struct ExampleProtocol;
///
/// // snip: implementations for ThresholdSecretSharingScheme, LinearSharingScheme and CliqueCommunicationScheme for
/// // ExampleProtocol
///
/// impl ProtocolMarker for ExampleProtocol {
///     type Marker = Delegate;
/// }
///
/// impl<T, S, P> RandomNumberGenerationDelegate<T, S, P> for ExampleProtocol
/// where
///     P: ThresholdSecretSharingScheme<T, S>
///         + LinearSharingScheme<T, S>
///         + CliqueCommunicationScheme<T, S>,
///     T: PrimeField,
///     S: 'static, {
///     type Delegate = SumNonZeroRandomNumberGeneration<T, S, P>;
/// }
/// ```
pub struct SumNonZeroRandomNumberGeneration<T, S, P>
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
