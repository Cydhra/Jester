use num::Num;

/// A threshold secret sharing scheme that generates n shares of a given secret and requires t <= n of those shares
/// to reconstruct the secret. The secret is of type `T` and shares are a `Vec<S>`.
trait ThresholdSecretSharingScheme<T, S> {

    /// Generate shares of a secret demanding that at least `threshold` shares must be available to reconstruct the
    /// secret.
    /// #Parameters:
    /// - `secret` an instance of `T`
    /// - `count` how many shares to generate
    /// - `threshold` how many shares are required to reconstruct the secret
    ///
    /// #Output
    /// Returns a vector of `count` shares
    fn generate_shares(secret: &T, count: usize, threshold: usize) -> Vec<S>;

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