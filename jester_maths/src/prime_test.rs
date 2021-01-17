/// Trait for algorithms to test whether a specified number is prime.
pub trait PrimeTest<P> {

    /// Test whether the given numeral is a prime number
    fn is_prime(number: &P) -> bool;
}