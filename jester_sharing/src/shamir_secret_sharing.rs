use num::{BigUint, FromPrimitive};
use num::pow::pow;
use num_bigint::RandBigInt;
use rand::{CryptoRng, RngCore};

use jester_algebra::PrimeField;

use crate::{LinearSharingScheme, ThresholdSecretSharingScheme};

/// Shamir's secret sharing scheme that uses polynomials of `threshold` degree and solutions of it as shares.
pub struct ShamirSecretSharing;

/// Shamir's secret sharing scheme is linear for addition. Implement this as a marker
impl LinearSharingScheme for ShamirSecretSharing {}

impl<T> ThresholdSecretSharingScheme<T, (usize, T)> for ShamirSecretSharing
    where T: PrimeField {
    /// Generate a random polynomial `f` and `count` solutions `sn = f(n)` where `n != 0` as shares. The secret is
    /// the solution `secret = f(0)` of the polynomial and each share is the solution of `f(i)` where `i - 1` is the
    /// index within the returned vector.
    /// #Parameters:
    /// - `rng` a cryptographically secure random number generator.
    /// - `secret` an instance of `T`
    /// - `count` how many shares to generate
    /// - `threshold` how many shares are required to reconstruct the secret
    ///
    /// #Output
    /// Returns a vector of `count` shares
    fn generate_shares<R>(rng: &mut R, secret: &T, count: usize, threshold: usize) -> Vec<(usize, T)>
        where R: RngCore + CryptoRng + RandBigInt {
        assert!(threshold > 1);

        let polynomial = (1..threshold)
            .map(|i| (i, T::generate_random_member(rng)))
            .collect::<Vec<_>>();

        (1..=count)
            .map(|x| (x, polynomial.clone().iter()
                .fold(secret.clone(), |akk, (index, val)|
                    akk + val.clone() * BigUint::from_usize(pow(x, *index)).unwrap().into())))
            .collect()
    }

    /// Interpolates the secret using the Lagrange interpolation method.
    /// #Parameters:
    /// - `shares` a collection of at least `threshold` shares
    /// - `threshold` the original threshold the shares were generated upon. This may be less than the actual number
    /// of shares given, but it must be the same value as during generation
    ///
    /// #Output:
    /// Given that `threshold` matches the threshold at generation and enough shares are present, it will return an
    /// instance of `T` that is reconstructed from the shares
    fn reconstruct_secret(shares: &[(usize, T)], threshold: usize) -> T {
        shares.iter()
            .take(threshold)
            .map(|(i, share)|
                share.clone().mul(shares.iter()
                    .filter(|(j, _)| *i != *j)
                    .map(|(j, _)| {
                        T::from_isize(-(*j as isize)).unwrap().mul(T::from_isize(*i as isize - *j as isize).unwrap()
                            .inverse())
                    })
                    .product()))
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use num::{FromPrimitive, One};
    use rand::thread_rng;

    use jester_algebra::Mersenne89;

    use crate::ThresholdSecretSharingScheme;

    use super::ShamirSecretSharing;

    #[test]
    fn test_generator() {
        let shares = ShamirSecretSharing::generate_shares(&mut thread_rng(), &Mersenne89::one(), 5, 5);
        assert_eq!(shares.len(), 5)
    }

    #[test]
    fn test_reconstruction() {
        let shares = ShamirSecretSharing::generate_shares(&mut thread_rng(),
                                                          &Mersenne89::from_usize(20).unwrap(), 5, 5);
        assert_eq!(ShamirSecretSharing::reconstruct_secret(&shares, 5), Mersenne89::from_usize(20).unwrap());
    }

    #[test]
    fn test_linearity() {
        let shares = ShamirSecretSharing::generate_shares(&mut thread_rng(),
                                                          &Mersenne89::from_usize(20).unwrap(), 2, 2);
        let shares_2 = ShamirSecretSharing::generate_shares(&mut thread_rng(),
                                                          &Mersenne89::from_usize(40).unwrap(), 2, 2);

        let addition: Vec<_> = shares.into_iter()
            .zip(shares_2)
            .map(|((x1, y1), (_, y2))| (x1, y1.clone() + y2.clone()))
            .collect();

        assert_eq!(ShamirSecretSharing::reconstruct_secret(&addition, 2), Mersenne89::from_usize(60).unwrap());
    }
}