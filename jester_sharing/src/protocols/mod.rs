pub use self::conditional_selection::*;
pub use self::joint_unbounded_inversion::*;
pub use self::joint_unbounded_or::*;
pub use self::random_number_generation::*;

pub use jester_maths::prime::PrimeField;
pub use num_bigint::BigUint;
pub use rand::{CryptoRng, RngCore};

mod conditional_selection;
mod joint_unbounded_inversion;
mod joint_unbounded_or;
mod random_number_generation;

#[cfg(test)]
mod tests {
    use super::*;

    use std::iter::repeat;
    use std::pin::Pin;

    use futures::executor::block_on;
    use futures::Future;
    use mashup::*;
    use num::traits::{One, Zero};
    use rand::thread_rng;

    use jester_maths::prime_fields;

    use crate::beaver_randomization_multiplication::BeaverRandomizationMultiplication;
    use crate::shamir_secret_sharing::ShamirSecretSharingScheme;
    use crate::CliqueCommunicationScheme;

    prime_fields!(TestPrimeField("7", 10));

    /// A testing protocol that is carried out between two participants that do not randomize their inputs and do no
    /// communicate as all values are deterministic anyways.
    struct TestProtocol {
        participant_id: usize,
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

    #[test]
    fn test_protocol() {
        let mut protocol = TestProtocol { participant_id: 1 };
        let mut rng = thread_rng();

        block_on(async {
            let shares = protocol
                .distribute_secret(TestPrimeField::one() + TestPrimeField::one())
                .await;
            let inverse = joint_unbounded_inversion(&mut rng, &mut protocol, &shares).await;
            let doubly_inverse = joint_unbounded_inversion(&mut rng, &mut protocol, &inverse).await;
            let revealed = protocol.reveal_shares(doubly_inverse[0].clone()).await;

            assert_eq!(TestPrimeField::one() + TestPrimeField::one(), revealed);
        })
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

            let or = joint_unbounded_or(&mut thread_rng(), &mut protocol, &bits).await;
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

            let or = joint_unbounded_or(&mut thread_rng(), &mut protocol, &bits).await;
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
            let inverses = joint_unbounded_inversion(&mut rng, &mut protocol, &elements[..]).await;

            assert_eq!(inverses[0].1, TestPrimeField::from(BigUint::from(1u32)));
            assert_eq!(inverses[1].1, TestPrimeField::from(BigUint::from(2u32)));
            assert_eq!(inverses[2].1, TestPrimeField::from(BigUint::from(6u32)));
        })
    }
}
