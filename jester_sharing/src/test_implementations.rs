//! This module defines a protocol common to multiple tests, saving each test from redefining it.

#![cfg(test)]

use crate::CliqueCommunicationScheme;
use futures::Future;
use jester_maths::prime::PrimeField;
use jester_maths::prime_fields;
use mashup::*;
use std::pin::Pin;

/// A struct placeholder that is the common protocol for all tests.
pub(crate) struct TestProtocol {
    pub participant_id: usize,
}

// define a prime field for testing
prime_fields!(pub(crate) TestPrimeField("7", 10));

/// All shares are considered to be carried out on polynomials where all coefficients are zero. Thus
/// communication is unnecessary and the secret is always the share. This is obviously stupid to do, but useful for
/// testing whether protocols calculate their stuff correctly.
impl CliqueCommunicationScheme<TestPrimeField, (usize, TestPrimeField)> for TestProtocol {
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
