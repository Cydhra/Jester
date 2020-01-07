//! This is a module that defines a protocol implementation for test cases. It is by no means cryptographically
//! secure, as it openly shares all secrets. It is merely a mathematically correct implementation that eases unit
//! tests, as only one party is required and thus no communication must be implemented.

use jester_maths::prime_fields;

use crate::beaver_randomization_multiplication::BeaverRandomizationMultiplication;
use crate::protocols::PrimeField;
use crate::shamir_secret_sharing::ShamirSecretSharingScheme;
use crate::CliqueCommunicationScheme;
use mashup::*;
use std::iter::repeat;
use std::pin::Pin;

use futures::Future;

use num::traits::One;

prime_fields!(pub(super) TestPrimeField("7", 10));

/// A testing protocol that is carried out between two participants that do not randomize their inputs and do no
/// communicate as all values are deterministic anyways.
pub(super) struct TestProtocol {
    pub(super) participant_id: usize,
}

impl ShamirSecretSharingScheme<TestPrimeField> for TestProtocol {}

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

impl BeaverRandomizationMultiplication<TestPrimeField, (usize, TestPrimeField)> for TestProtocol {
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
