use crate::{CryptoRng, RngCore};
use num::pow::pow;
use num::{BigUint, FromPrimitive};
use num_bigint::RandBigInt;

use crate::PrimeField;

use crate::{LinearSharingScheme, ThresholdSecretSharingScheme};

/// A trait marking a special instance of a additive linear threshold secret sharing scheme invented by Adi Shamir. A
/// protocol implementing this trait does not have to provide implementations for `ThresholdSecretSharingScheme` nor
/// `LinearSharingScheme` as they are provided by this module.
pub trait ShamirSecretSharingScheme<T>:
    ThresholdSecretSharingScheme<T, (usize, T)> + LinearSharingScheme<T, (usize, T)>
{
    // this is a marker trait
}

/// Shamir's secret sharing scheme is linear for addition. Addition implemented by simply delegating the calls to `T`
impl<T, P> LinearSharingScheme<T, (usize, T)> for P
where
    T: PrimeField,
    P: ShamirSecretSharingScheme<T>,
{
    fn add_shares(lhs: &(usize, T), rhs: &(usize, T)) -> (usize, T) {
        assert_eq!(lhs.0.clone(), rhs.0.clone());
        (lhs.0, lhs.1.clone() + rhs.1.clone())
    }

    fn sub_shares(lhs: &(usize, T), rhs: &(usize, T)) -> (usize, T) {
        assert_eq!(lhs.0.clone(), rhs.0.clone());
        (lhs.0, lhs.1.clone() - rhs.1.clone())
    }

    fn add_scalar(share: &(usize, T), scalar: &T) -> (usize, T) {
        (share.0, share.1.clone() + scalar.clone())
    }

    fn sub_scalar(share: &(usize, T), scalar: &T) -> (usize, T) {
        (share.0, share.1.clone() - scalar.clone())
    }

    fn multiply_scalar(share: &(usize, T), scalar: &T) -> (usize, T) {
        (share.0, share.1.clone() * scalar.clone())
    }

    fn sum_shares(shares: &[(usize, T)]) -> Option<(usize, T)> {
        if shares.is_empty() {
            None
        } else {
            // assert that all shares are of the same x value
            assert!(shares
                .iter()
                .fold(shares.get(0).map(|x| x.0), |acc, val| {
                    if acc == Some(val.0) {
                        acc
                    } else {
                        None
                    }
                })
                .is_some());

            Some((
                shares.get(0).unwrap().0,
                shares.iter().map(|(_, y)| y.clone()).sum(),
            ))
        }
    }
}

impl<T, P> ThresholdSecretSharingScheme<T, (usize, T)> for P
where
    T: PrimeField,
    P: ShamirSecretSharingScheme<T>,
{
    /// Generate a random polynomial `f` and `count` solutions `sn = f(n)` where `n != 0` as shares. The secret is
    /// the solution `secret = f(0)` of the polynomial and each share is the solution of `f(i)` where `i - 1` is the
    /// index within the returned vector.
    /// # Parameters
    /// - `rng` a cryptographically secure random number generator.
    /// - `secret` an instance of `T`
    /// - `count` how many shares to generate
    /// - `threshold` how many shares are required to reconstruct the secret
    ///
    /// # Returns
    /// Returns a vector of `count` shares
    fn generate_shares<R>(
        rng: &mut R,
        secret: &T,
        count: usize,
        threshold: usize,
    ) -> Vec<(usize, T)>
    where
        R: RngCore + CryptoRng + RandBigInt,
    {
        assert!(threshold > 1);

        let polynomial = (1..threshold)
            .map(|i| (i, T::generate_random_member(rng)))
            .collect::<Vec<_>>();

        (1..=count)
            .map(|x| {
                (
                    x,
                    polynomial
                        .clone()
                        .iter()
                        .fold(secret.clone(), |akk, (index, val)| {
                            akk + val.clone() * BigUint::from_usize(pow(x, *index)).unwrap().into()
                        }),
                )
            })
            .collect()
    }

    /// Interpolates the secret using the Lagrange interpolation method.
    /// # Parameters
    /// - `shares` a collection of at least `threshold` shares
    /// - `threshold` the original threshold the shares were generated upon. This may be less than the actual number
    /// of shares given, but it must be the same value as during generation
    ///
    /// # Returns
    /// Given that `threshold` matches the threshold at generation and enough shares are present, it will return an
    /// instance of `T` that is reconstructed from the shares
    fn reconstruct_secret(shares: &[(usize, T)], threshold: usize) -> T {
        shares
            .iter()
            .take(threshold)
            .map(|(i, share)| {
                share.clone().mul(
                    shares
                        .iter()
                        .filter(|(j, _)| *i != *j)
                        .map(|(j, _)| {
                            T::from_isize(-(*j as isize))
                                .unwrap()
                                .mul(T::from_isize(*i as isize - *j as isize).unwrap().inverse())
                        })
                        .product(),
                )
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use num::{FromPrimitive, One};
    use rand::thread_rng;

    use super::*;
    use crate::test_implementations::*;

    impl ShamirSecretSharingScheme<TestPrimeField> for TestProtocol {}

    #[test]
    fn test_generator() {
        let shares = TestProtocol::generate_shares(&mut thread_rng(), &TestPrimeField::one(), 5, 5);
        assert_eq!(shares.len(), 5)
    }

    #[test]
    fn test_reconstruction() {
        let shares = TestProtocol::generate_shares(
            &mut thread_rng(),
            &TestPrimeField::from_usize(3).unwrap(),
            5,
            5,
        );
        assert_eq!(
            TestProtocol::reconstruct_secret(&shares, 5),
            TestPrimeField::from_usize(3).unwrap()
        );
    }

    #[test]
    fn test_linearity() {
        let shares = TestProtocol::generate_shares(
            &mut thread_rng(),
            &TestPrimeField::from_usize(2).unwrap(),
            2,
            2,
        );
        let shares_2 = TestProtocol::generate_shares(
            &mut thread_rng(),
            &TestPrimeField::from_usize(3).unwrap(),
            2,
            2,
        );

        let addition: Vec<_> = shares
            .into_iter()
            .zip(shares_2)
            .map(|((x1, y1), (_, y2))| (x1, y1 + y2))
            .collect();

        assert_eq!(
            TestProtocol::reconstruct_secret(&addition, 2),
            TestPrimeField::from_usize(5).unwrap()
        );
    }
}
