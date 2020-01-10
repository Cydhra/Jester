use crate::{
    CliqueCommunicationScheme, ConditionalSelectionScheme, LinearSharingScheme,
    MultiplicationScheme, PrimeField, ThresholdSecretSharingScheme,
};
use futures::Future;
use std::marker::PhantomData;
use std::pin::Pin;

pub struct JointConditionalSelection<T, S, P>(PhantomData<T>, PhantomData<S>, PhantomData<P>)
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + MultiplicationScheme<T, S>,
    T: PrimeField,
    S: Clone + 'static;

impl<T, S, P> ConditionalSelectionScheme<T, S, P> for JointConditionalSelection<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + MultiplicationScheme<T, S>,
    T: PrimeField,
    S: Clone + 'static,
{
    fn joint_conditional_selection<'a>(
        protocol: &'a mut P,
        condition: &S,
        lhs: &S,
        rhs: &S,
    ) -> Pin<Box<dyn Future<Output = S> + 'a>> {
        let operands_difference = P::sub_shares(lhs, rhs);
        let rhs = rhs.clone();
        let condition = condition.clone();

        Box::pin(
            async move {
                let product = protocol.multiply(&condition, &operands_difference).await;
                P::add_shares(&product, &rhs)
            }
        )
    }
}
