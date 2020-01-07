use crate::{
    CliqueCommunicationScheme, LinearSharingScheme, MultiplicationScheme,
    ThresholdSecretSharingScheme,
};

use crate::protocols::PrimeField;

/// A protocol for the joint selection of either side of a ternary expression `condition ? lhs : rhs` without
/// any participant learning the value of `condition` or the expression chosen by the protocol. This protocol cannot
/// be invoked in parallel, as it uses a two-stage multiplication protocol.
///
/// # Parameters
/// - `protocol` an instance of the sub-protocols used. It must be a `ThresholdSecretSharingScheme` with additive
/// linear shares and communication between all participants. Furthermore multiplication by communication must be
/// supported.
/// - `condition` a share on a value that resolves either to `0` or to `1`. Any other value will produce undefined
/// behaviour. Since this protocol does not leak information about `condition`, such an undefined result is
/// undetectable (at least until the result is evaluated)
/// - `lhs` the left hand side of the if-else expression that is taken, if `condition` evaluates to `1`
/// - `rhs` the right hand side of the if-else expression that is taken, if `condition` evaluates to `0`
///
/// # Returns
/// Returns a future on either `lhs` or `rhs`, but in a rerandomized share, so a participant cannot learn which one
/// was taken.
pub async fn joint_conditional_selection<T, S, P>(
    protocol: &mut P,
    condition: &S,
    lhs: &S,
    rhs: &S,
) -> S
where
    T: PrimeField,
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + MultiplicationScheme<T, S>,
{
    let operands_difference = P::sub_shares(lhs, rhs);

    // copy rhs to move a copy into the future
    let product = protocol.multiply(condition, &operands_difference).await;
    P::add_shares(&product, rhs)
}
