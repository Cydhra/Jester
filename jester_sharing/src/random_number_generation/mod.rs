use crate::{
    CliqueCommunicationScheme, CryptoRng, Delegate, LinearSharingScheme, PrimeField, RngCore,
    ThresholdSecretSharingScheme,
};
use futures::Future;
use std::pin::Pin;

//pub mod sum_not_zero_random_number_generation;
pub mod sum_non_zero_random_number_generation;
pub mod sum_random_number_generation;

/// A scheme that can be used to randomly generate a share of a number that is unknown to all participants. This
/// trait is not to be implemented on protocols, instead it will be used as a proxy for the actual implementations.
/// # Type Parameters
/// - `T` the secret type
/// - `S` the share type
/// - `P` the protocol this scheme requires. It requires at least a linear threshold scheme with clique communication.
pub trait RandomNumberGenerationScheme<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>,
    T: PrimeField,
    S: 'static,
{
    /// Generate a random number and obtain a share of it, without learning the random number.
    ///
    /// # Parameters
    /// - `rng` a cryptographically secure random number generator
    /// - `protocol` the protocol instance this scheme is used within.
    fn generate_random_number_sharing<R>(
        rng: &mut R,
        protocol: &mut P,
    ) -> Pin<Box<dyn Future<Output = S>>>
    where
        R: RngCore + CryptoRng;
}

/// Type-safe marker for protocol delegation and composition. This marker has to be implemented by any type that is a
/// `RandomNumberGenerationScheme`.
pub trait ProtocolMarker {
    type Marker;
}

/// An implementation of random number generation. This trait is used to actually implement
/// `RandomNumberGenerationScheme`, which itself should never be implemented on any type.
/// # Type Parameters
/// - `T` the secret type
/// - `S` the share type
/// - `P` the protocol this scheme is implemented in.
/// - `Marker` a marker used for type-safe delegation. Each implementation must use a unique marker.
pub trait RandomNumberGenerationImpl<T, S, P, Marker>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>,
    T: PrimeField,
    S: 'static,
{
    /// Generate a random number and obtain a share of it, without learning the random number
    ///
    /// # Parameters
    /// - `rng` a cryptographically secure random number generator
    /// - `protocol` the protocol this scheme uses as primitives
    fn do_generate_random_number_sharing<R>(
        rng: &mut R,
        protocol: &mut P,
    ) -> Pin<Box<dyn Future<Output = S>>>
    where
        R: RngCore + CryptoRng;
}

/// Implement the proxy protocol scheme for all protocols that implement a `RandomNumberGenerationImpl` and its
/// respective `ProtocolMarker`
impl<T, S, P, M> RandomNumberGenerationScheme<T, S, P> for P
where
    P: ProtocolMarker<Marker = M>
        + RandomNumberGenerationImpl<T, S, P, M>
        + ThresholdSecretSharingScheme<T, S>
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
        <P as RandomNumberGenerationImpl<T, S, P, M>>::do_generate_random_number_sharing(
            rng, protocol,
        )
    }
}

/// A delegate type for the `RandomNumberGenerationScheme` that can be implemented by the user, if they want to
/// delegate to a default implementation.
/// # Usage
/// ```
/// use jester_sharing::{
///     ProtocolMarker, Delegate, RandomNumberGenerationDelegate, ThresholdSecretSharingScheme,
///     LinearSharingScheme, CliqueCommunicationScheme, PrimeField
/// };
/// use jester_sharing::sum_random_number_generation::SumRandomNumberGeneration;
///
/// // Marker struct for an exemplary protocol implementation
/// struct ExampleProtocol;
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
///     type Delegate = SumRandomNumberGeneration<T, S, P>;
/// }
/// ```
pub trait RandomNumberGenerationDelegate<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>,
    T: PrimeField,
    S: 'static,
{
    type Delegate: RandomNumberGenerationScheme<T, S, P>;
}

/// Every type that uses `RandomNumberGenerationDelegate` is automatically a `RandomNumberGenerationImpl` that will
/// simply delegate to the implementation given by `RandomNumberGenerationDelegate::Delegate`. This implementation is
/// marked with the `Delegate` marker, so the protocol that implements `RandomNumberGenerationDelegate` has to mark
/// itself as `Delegate` using `ProtocolMarker` as well.
impl<T, S, P> RandomNumberGenerationImpl<T, S, P, Delegate> for P
where
    P: RandomNumberGenerationDelegate<T, S, P>
        + ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>,
    T: PrimeField,
    S: 'static,
{
    fn do_generate_random_number_sharing<R>(
        rng: &mut R,
        protocol: &mut P,
    ) -> Pin<Box<dyn Future<Output = S>>>
    where
        R: RngCore + CryptoRng,
    {
        P::Delegate::generate_random_number_sharing(rng, protocol)
    }
}
