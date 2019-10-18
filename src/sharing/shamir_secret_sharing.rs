use num::Num;
use rand::{CryptoRng, RngCore};

use crate::sharing::ThresholdSecretSharingScheme;

/// Shamir's secret sharing scheme that uses polynomials of `threshold` degree and solutions of it as shares.
struct ShamirSecretSharing;

impl<T> ThresholdSecretSharingScheme<T, T> for ShamirSecretSharing
    where T: Num + Clone {
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
    fn generate_shares<R>(rng: &mut R, secret: &T, count: usize, threshold: usize) -> Vec<T>
        where R: RngCore + CryptoRng {
        unimplemented!()
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
    fn reconstruct_secret(shares: &[T], threshold: usize) -> T {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use num::Num;

    use crate::sharing::shamir_secret_sharing::ShamirSecretSharing;
    use crate::sharing::ThresholdSecretSharingScheme;

    #[test]
    fn test() {

    }
}