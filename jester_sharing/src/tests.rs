//! This module contains unit tests for the sharing protocols. It is within an extra file to increase readability.

use crate::beaver_randomization_multiplication::BeaverCommunicationScheme;
use crate::shamir_secret_sharing::ShamirSecretSharingScheme;
use crate::{
    BigUint, CliqueCommunicationScheme, Delegate, LinearSharingScheme, PrimeField,
    RandomNumberGenerationScheme, RandomNumberGenerationSchemeDelegate,
    RandomNumberGenerationSchemeMarker, ThresholdSecretSharingScheme, UnboundedInversionScheme,
    UnboundedInversionSchemeDelegate, UnboundedInversionSchemeMarker,
    UnboundedMultiplicationScheme, UnboundedMultiplicationSchemeDelegate,
    UnboundedMultiplicationSchemeMarker, UnboundedOrFunctionScheme,
    UnboundedOrFunctionSchemeDelegate, UnboundedOrFunctionSchemeMarker,
};

use futures::executor::block_on;
use num::traits::{One, Zero};
use rand::thread_rng;

use jester_maths::prime_fields;

use mashup::*;
use std::iter::repeat;
use std::pin::Pin;

use crate::inversion::unbounded_inversion::JointUnboundedInversion;
use crate::multiplication::beaver_randomization_multiplication::BeaverRerandomizationMultiplication;
use crate::random_number_generation::sum_non_zero_random_number_generation::SumNonZeroRandomNumberGeneration;
use crate::shared_or_function::joint_unbounded_or::JointUnboundedOrFunction;
use futures::Future;

// Define a prime field for testing with p = 7
prime_fields!(pub(super) TestPrimeField("7", 10));

/// A testing protocol that is carried out between two participants that do not randomize their inputs and do no
/// communicate as all values are deterministic anyways.
pub(super) struct TestProtocol {
    pub(super) participant_id: usize,
}

impl ShamirSecretSharingScheme<TestPrimeField> for TestProtocol {}

impl RandomNumberGenerationSchemeMarker for TestProtocol {
    type Marker = Delegate;
}

impl<T, S, P> RandomNumberGenerationSchemeDelegate<T, S, P> for TestProtocol
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>,
    T: PrimeField,
    S: 'static,
{
    type Delegate = SumNonZeroRandomNumberGeneration<T, S, P>;
}

impl UnboundedInversionSchemeMarker for TestProtocol {
    type Marker = Delegate;
}

impl<T, S, P> UnboundedInversionSchemeDelegate<T, S, P> for TestProtocol
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + UnboundedMultiplicationScheme<T, S, P>
        + RandomNumberGenerationScheme<T, S, P>
        + Send
        + Sync,
    T: Send + Sync + PrimeField,
    S: Send + Sync + Clone + 'static,
{
    type Delegate = JointUnboundedInversion<T, S, P>;
}

impl UnboundedOrFunctionSchemeMarker for TestProtocol {
    type Marker = Delegate;
}

impl<T, S, P> UnboundedOrFunctionSchemeDelegate<T, S, P> for TestProtocol
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + UnboundedMultiplicationScheme<T, S, P>
        + RandomNumberGenerationScheme<T, S, P>
        + UnboundedInversionScheme<T, S, P>
        + Send
        + Sync,
    T: Send + Sync + PrimeField + 'static,
    S: Send + Sync + Clone + 'static,
{
    type Delegate = JointUnboundedOrFunction<T, S, P>;
}

/// All shares are considered to be carried out on polynomials where all coefficients are zero. Thus
/// communication is unnecessary and the secret is always the share
impl CliqueCommunicationScheme<TestPrimeField, (usize, TestPrimeField)> for TestProtocol
where
    TestProtocol: ShamirSecretSharingScheme<TestPrimeField>,
{
    fn reveal_shares(
        &mut self,
        share: (usize, TestPrimeField),
    ) -> Pin<Box<dyn Future<Output = TestPrimeField> + Send>> {
        Box::pin(async move { share.1 })
    }

    fn distribute_secret(
        &mut self,
        secret: TestPrimeField,
    ) -> Pin<Box<dyn Future<Output = Vec<(usize, TestPrimeField)>> + Send>> {
        let id = self.participant_id;
        Box::pin(async move { vec![(id, secret.clone()), (id, secret)] })
    }
}

impl BeaverCommunicationScheme<(usize, TestPrimeField)> for TestProtocol {
    fn get_reconstruction_threshold(&self) -> usize {
        2
    }

    fn obtain_beaver_triples<'a>(
        &'a mut self,
        count: usize,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Vec<(
                        (usize, TestPrimeField),
                        (usize, TestPrimeField),
                        (usize, TestPrimeField),
                    )>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            repeat((
                (self.participant_id, TestPrimeField::one()),
                (self.participant_id, TestPrimeField::one()),
                (self.participant_id, TestPrimeField::one()),
            ))
            .take(count)
            .collect()
        })
    }
}

impl<T, S, P> UnboundedMultiplicationSchemeDelegate<T, S, P> for TestProtocol
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + BeaverCommunicationScheme<S>
        + Send
        + Sync,
    T: PrimeField + Send + Sync,
    S: Send + Sync + Clone + 'static,
{
    type Delegate = BeaverRerandomizationMultiplication<T, S, P>;
}

impl UnboundedMultiplicationSchemeMarker for TestProtocol {
    type Marker = Delegate;
}

#[test]
fn test_unbounded_or_one() {
    let mut protocol = TestProtocol { participant_id: 1 };

    block_on(async {
        let bits = vec![
            (1, TestPrimeField::one()),
            (1, TestPrimeField::zero()),
            (1, TestPrimeField::one()),
        ];

        let or = TestProtocol::unbounded_shared_or(&mut thread_rng(), &mut protocol, &bits).await;
        let revealed = protocol.reveal_shares(or).await;
        assert_eq!(revealed, TestPrimeField::one());
    })
}

#[test]
fn test_unbounded_or_zero() {
    let mut protocol = TestProtocol { participant_id: 1 };

    block_on(async {
        let bits = vec![
            (1, TestPrimeField::zero()),
            (1, TestPrimeField::zero()),
            (1, TestPrimeField::zero()),
        ];

        let or = TestProtocol::unbounded_shared_or(&mut thread_rng(), &mut protocol, &bits).await;
        let revealed = protocol.reveal_shares(or).await;
        assert_eq!(revealed, TestPrimeField::zero());
    })
}

#[test]
fn test_unbounded_inversion() {
    let mut protocol = TestProtocol { participant_id: 1 };
    let mut rng = thread_rng();

    block_on(async {
        let elements: Vec<(usize, TestPrimeField)> = vec![
            (1, BigUint::from(1u32).into()),
            (1, BigUint::from(4u32).into()),
            (1, BigUint::from(6u32).into()),
        ];
        let inverses =
            TestProtocol::unbounded_inverse(&mut rng, &mut protocol, &elements[..]).await;

        assert_eq!(inverses[0].1, TestPrimeField::from(BigUint::from(1u32)));
        assert_eq!(inverses[1].1, TestPrimeField::from(BigUint::from(2u32)));
        assert_eq!(inverses[2].1, TestPrimeField::from(BigUint::from(6u32)));
    })
}

#[test]
fn test_double_inversion() {
    let mut protocol = TestProtocol { participant_id: 1 };
    let mut rng = thread_rng();

    block_on(async {
        let shares = protocol.distribute_secret(BigUint::from(2u32).into()).await;
        let inverse = TestProtocol::unbounded_inverse(&mut rng, &mut protocol, &shares).await;
        let doubly_inverse =
            TestProtocol::unbounded_inverse(&mut rng, &mut protocol, &inverse).await;
        let revealed = protocol.reveal_shares(doubly_inverse[0].clone()).await;

        assert_eq!(revealed, BigUint::from(2u32).into());
    })
}
