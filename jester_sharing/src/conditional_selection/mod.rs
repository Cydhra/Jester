use crate::{
    CliqueCommunicationScheme, Delegate, LinearSharingScheme, MultiplicationScheme, PrimeField,
    ThresholdSecretSharingScheme,
};
use futures::Future;
use jester_sharing_proc::delegatable_protocol;
use std::pin::Pin;

pub mod joint_conditional_selection;

/// A protocol for the joint selection of either side of a ternary expression `condition ? lhs : rhs` without
/// any participant learning the value of `condition` or the expression chosen by the protocol. This protocol cannot
/// be invoked in parallel, as it uses a two-stage multiplication protocol.
#[delegatable_protocol]
pub trait ConditionalSelectionScheme<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + MultiplicationScheme<T, S>,
    T: PrimeField,
    S: 'static,
{
    /// Select either `lhs` or `rhs` depending on the `condition`.
    /// # Parameters
    /// - `protocol` an instance of the sub-protocols used. It must be a `ThresholdSecretSharingScheme` with additive
    /// linear shares and communication between all participants. Furthermore multiplication by communication must be
    /// supported.
    /// - `condition` a share on a value that resolves either to `0` or to `1`. Any other value will produce undefined
    /// behaviour. Since this protocol does not leak information about `condition`, such an undefined result is
    /// undetectable (at least until the result is evaluated)
    /// - `lhs` the left hand side of the if-else expression that is taken, if `condition` evaluates to `1`
    /// - `rhs` the right hand side of the if-else expression that is taken, if `condition` evaluates to `0`
    fn joint_conditional_selection<'a>(
        protocol: &'a mut P,
        condition: &S,
        lhs: &S,
        rhs: &S,
    ) -> Pin<Box<dyn Future<Output = S> + 'a>>;
}
