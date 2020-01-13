use crate::{
    CliqueCommunicationScheme, CryptoRng, LinearSharingScheme, MultiplicationScheme, PrimeField,
    RandomBitGenerationScheme, RandomNumberGenerationScheme, RngCore, ThresholdSecretSharingScheme,
};
use futures::Future;
use std::marker::PhantomData;
use std::pin::Pin;

/// A marker struct that delegates to a default random number generation scheme.
/// # Usage
/// ```
/// use jester_sharing::{RandomBitGenerationSchemeDelegate, RandomBitGenerationSchemeMarker, Delegate,
///  ThresholdSecretSharingScheme, LinearSharingScheme, CliqueCommunicationScheme, PrimeField, MultiplicationScheme, RandomNumberGenerationScheme};
/// use jester_sharing::root_random_bit_generation::RootRandomBitGeneration;
///
/// struct ExampleProtocol;
///
/// // snip: implementations for ThresholdSecretSharingScheme, LinearSharingScheme and CliqueCommunicationScheme for
/// // ExampleProtocol
///
/// impl RandomBitGenerationSchemeMarker for ExampleProtocol {
///     type Marker = Delegate;
/// }
///
/// impl<T, S, P> RandomBitGenerationSchemeDelegate<T, S, P> for ExampleProtocol
/// where
///     P: ThresholdSecretSharingScheme<T, S>
///         + LinearSharingScheme<T, S>
///         + CliqueCommunicationScheme<T, S>
///         + MultiplicationScheme<T, S, P>
///         + RandomNumberGenerationScheme<T, S, P>
///         + Send
///         + Sync,
///     T: PrimeField + Sync + Send,
///     S: Sync + Send + 'static,
/// {
///     type Delegate = RootRandomBitGeneration<T, S, P>;
/// }
/// ```
pub struct RootRandomBitGeneration<T, S, P>(PhantomData<T>, PhantomData<S>, PhantomData<P>)
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + MultiplicationScheme<T, S, P>
        + RandomNumberGenerationScheme<T, S, P>
        + Send
        + Sync,
    T: PrimeField + Sync + Send,
    S: Sync + Send + 'static;

impl<T, S, P> RandomBitGenerationScheme<T, S, P> for RootRandomBitGeneration<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + MultiplicationScheme<T, S, P>
        + RandomNumberGenerationScheme<T, S, P>
        + Send
        + Sync,
    T: PrimeField + Sync + Send,
    S: Sync + Send + 'static,
{
    fn generate_random_bit<'a, R>(
        rng: &mut R,
        protocol: &'a mut P,
    ) -> Pin<Box<dyn Future<Output = S> + Send + 'a>>
    where
        R: RngCore + CryptoRng,
    {
        let r = P::generate_random_number_sharing(rng, protocol);

        Box::pin(async move {
            let r = r.await;
            let square = P::multiply(protocol, &r, &r).await;
            let square_revealed = protocol.reveal_shares(square).await;
            let square_root: T = unimplemented!(); // calculate the root of the revealed number
            P::multiply_scalar(
                &P::add_scalar(&P::multiply_scalar(&r, &square_root.inverse()), &T::one()),
                &T::from_u32(2).unwrap().inverse(),
            )
        })
    }
}
