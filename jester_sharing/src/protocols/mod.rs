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
    use crate::CliqueCommunicationScheme;
    use test_implementations::*;

    use futures::executor::block_on;
    use num::traits::{One, Zero};
    use rand::thread_rng;

    mod test_implementations;

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

    #[test]
    fn test_double_inversion() {
        let mut protocol = TestProtocol { participant_id: 1 };
        let mut rng = thread_rng();

        block_on(async {
            let shares = protocol
                .distribute_secret(BigUint::from(2u32).into())
                .await;
            let inverse = joint_unbounded_inversion(&mut rng, &mut protocol, &shares).await;
            let doubly_inverse = joint_unbounded_inversion(&mut rng, &mut protocol, &inverse).await;
            let revealed = protocol.reveal_shares(doubly_inverse[0].clone()).await;

            assert_eq!(revealed, BigUint::from(2u32).into());
        })
    }
}
