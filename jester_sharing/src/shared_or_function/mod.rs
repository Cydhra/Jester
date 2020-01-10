use crate::{
    CliqueCommunicationScheme, CryptoRng, Delegate, LinearSharingScheme,
    ParallelMultiplicationScheme, PrimeField, RandomNumberGenerationScheme, RngCore,
    ThresholdSecretSharingScheme, UnboundedInversionScheme,
};
use futures::Future;
use jester_sharing_proc::delegatable_protocol;
use std::pin::Pin;

pub mod joint_unbounded_or;

#[delegatable_protocol]
pub trait OrFunctionScheme<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + ParallelMultiplicationScheme<T, S>
        + RandomNumberGenerationScheme<T, S, P>
        + UnboundedInversionScheme<T, S, P>,
    T: PrimeField + Send + Sync + 'static,
    S: Clone + 'static,
{
    fn shared_or<'a, R>(
        rng: &'a mut R,
        protocol: &'a mut P,
        bits: &S,
    ) -> Pin<Box<dyn Future<Output = S> + 'a>>
    where
        R: RngCore + CryptoRng;
}

#[delegatable_protocol]
pub trait UnboundedOrFunctionScheme<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + ParallelMultiplicationScheme<T, S>
        + RandomNumberGenerationScheme<T, S, P>
        + UnboundedInversionScheme<T, S, P>,
    T: PrimeField + Send + Sync + 'static,
    S: Clone + 'static,
{
    fn unbounded_shared_or<'a, R>(
        rng: &'a mut R,
        protocol: &'a mut P,
        bits: &[S],
    ) -> Pin<Box<dyn Future<Output = S> + 'a>>
    where
        R: RngCore + CryptoRng;
}
