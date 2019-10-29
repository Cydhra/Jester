use rand::{CryptoRng, RngCore};

pub mod shamir_secret_sharing;

/// A threshold secret sharing scheme that generates n shares of a given secret and requires t <= n of those shares
/// to reconstruct the secret. The secret is of type `T` and shares are a `Vec<S>`.
pub trait ThresholdSecretSharingScheme<T, S> {
    /// Generate shares of a secret demanding that at least `threshold` shares must be available to reconstruct the
    /// secret.
    /// #Parameters:
    /// - `rng` a cryptographically secure random number generator.
    /// - `secret` an instance of `T`
    /// - `count` how many shares to generate
    /// - `threshold` how many shares are required to reconstruct the secret
    ///
    /// #Output
    /// Returns a vector of `count` shares
    fn generate_shares<R>(rng: &mut R, secret: &T, count: usize, threshold: usize) -> Vec<S>
        where R: RngCore + CryptoRng;

    /// Take a vector of shares and reconstruct the secret from them. At least `threshold` shares must be present,
    /// otherwise the secret cannot be reconstructed
    /// #Parameters:
    /// - `shares` a collection of at least `threshold` shares
    /// - `threshold` the original threshold the shares were generated upon. This may be less than the actual number
    /// of shares given, but it must be the same value as during generation
    ///
    /// #Output:
    /// Given that `threshold` matches the threshold at generation and enough shares are present, it will return an
    /// instance of `T` that is reconstructed from the shares
    fn reconstruct_secret(shares: &[S], threshold: usize) -> T;
}

/// A trait for sharing schemes whose shares addition is linear thus enabling the addition of shares of this
/// scheme without further protocol state required.
pub trait LinearSharingScheme<S> {

    /// Sum two shares resulting in a new share of their secrets' sum.
    fn add_shares(lhs: &S, rhs: &S) -> S;

    /// Subtract `rhs` from `lhs` resulting in a new share of their secrets' difference.
    fn sub_shares(lhs: &S, rhs: &S) -> S;

    /// Sum a slice of shares resulting in a `Some` with a new share of their secrets' sum or `None` if the slice was
    /// empty.
    fn sum_shares(shares: &[S]) -> Option<S>;
}