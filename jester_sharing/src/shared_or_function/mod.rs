use crate::{
    CliqueCommunicationScheme, CryptoRng, Delegate, LinearSharingScheme, PrimeField,
    RandomNumberGenerationScheme, RngCore, ThresholdSecretSharingScheme, UnboundedInversionScheme,
    UnboundedMultiplicationScheme,
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
        + UnboundedMultiplicationScheme<T, S, P>
        + RandomNumberGenerationScheme<T, S, P>
        + UnboundedInversionScheme<T, S, P>
        + Send
        + Sync,
    T: PrimeField + Send + Sync + 'static,
    S: Send + Sync + Clone + 'static,
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
        + UnboundedMultiplicationScheme<T, S, P>
        + RandomNumberGenerationScheme<T, S, P>
        + UnboundedInversionScheme<T, S, P>
        + Send
        + Sync,
    T: PrimeField + Send + Sync + 'static,
    S: Send + Sync + Clone + 'static,
{
    fn unbounded_shared_or<'a, R>(
        rng: &'a mut R,
        protocol: &'a mut P,
        bits: &[S],
    ) -> Pin<Box<dyn Future<Output = S> + 'a>>
    where
        R: RngCore + CryptoRng;
}
