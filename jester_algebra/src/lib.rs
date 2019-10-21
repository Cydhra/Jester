use std::iter::{Product, Sum};

use num::{BigUint, Num};
use num_bigint::RandBigInt;
use rand::{CryptoRng, RngCore};

macro_rules! gen_prime_field {
    ($name:ident, $prime:literal) => {
        static PRIME_NUMBER: once_cell::sync::Lazy<$name> = once_cell::sync::Lazy::new(|| {
            // do not parse this to a struct instance directly, because parsing that actually requires
            // this constant to be already present. Parse the big integer from string instead.
            $name(std::str::FromStr::from_str($prime).unwrap())
        });

        impl std::ops::Add<$name> for $name {
            type Output = $name;

            fn add(self, rhs: $name) -> Self::Output {
                let mut sum = self.0.clone().add(&rhs.0);
                std::ops::RemAssign::rem_assign(&mut sum, PRIME_NUMBER.0.clone());
                $name(sum)
            }
        }

        impl std::ops::Sub<$name> for $name {
            type Output = $name;

            fn sub(self, rhs: $name) -> Self::Output {
                let mut sum = ::std::ops::Sub::sub(&self.0.clone(), &rhs.0);
                ::std::ops::RemAssign::rem_assign(&mut sum, PRIME_NUMBER.0.clone());
                $name(sum)
            }
        }

        impl std::ops::Div<$name> for $name {
            type Output = $name;

            fn div(self, rhs: $name) -> Self::Output {
                let mut tmp = ::std::ops::Div::div(&self.0.clone(), &rhs.0);
                ::std::ops::RemAssign::rem_assign(&mut tmp, PRIME_NUMBER.0.clone());
                $name(tmp)
            }
        }

        impl std::ops::Mul<$name> for $name {
            type Output = $name;

            fn mul(self, rhs: $name) -> Self::Output {
                let mut tmp = ::std::ops::Mul::mul(&self.0.clone(), &rhs.0);
                ::std::ops::RemAssign::rem_assign(&mut tmp, PRIME_NUMBER.0.clone());
                $name(tmp)
            }
        }

        impl std::ops::Rem<$name> for $name {
            type Output = Self;

            fn rem(self, rhs: $name) -> $name {
                let mut tmp = self.0.clone();
                ::std::ops::RemAssign::rem_assign(&mut tmp, &rhs.0);
                $name(tmp)
            }
        }

        impl num::Zero for $name {
            fn zero() -> Self {
                $name(num_bigint::BigUint::zero())
            }

            fn is_zero(&self) -> bool {
                self.0.is_zero()
            }
        }

        impl num::One for $name {
            fn one() -> Self {
                $name(num_bigint::BigUint::one())
            }

            fn is_one(&self) -> bool
                where Self: PartialEq, {
                self.0.is_one()
            }
        }

        impl num::Num for $name {
            type FromStrRadixErr = num::bigint::ParseBigIntError;

            fn from_str_radix(str: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
                num_bigint::BigUint::from_str_radix(str, radix).map(|i| {
                    let n = i.modpow(&::num::One::one(), &PRIME_NUMBER.0);
                    $name(n)
                })
            }
        }

        impl std::iter::Sum for $name {
            fn sum<I: Iterator<Item=Self>>(iter: I) -> Self {
                let mut tmp: $name = ::num::Zero::zero();
                for x in iter {
                    tmp = tmp + x;
                }
                tmp
            }
        }

        impl std::iter::Product for $name {
            fn product<I: Iterator<Item=Self>>(iter: I) -> Self {
                let mut tmp: $name = ::num::One::one();
                for x in iter {
                    tmp = tmp * x;
                }
                tmp
            }
        }

        impl From<$name> for BigUint {
            fn from(v: $name) -> Self {
                v.0
            }
        }

        impl From<BigUint> for $name {
            fn from(v: BigUint) -> Self {
                let mut g = v;
                ::std::ops::RemAssign::rem_assign(&mut g, &PRIME_NUMBER.0);
                $name(g)
            }
        }

        impl PrimeField for $name {
            fn field_prime() -> Self {
                PRIME_NUMBER.clone()
            }
        }
    }
}

#[macro_export]
macro_rules! prime_field {
    ($name:ident, $prime:literal) => {
        #[derive(Debug, Clone, PartialEq, PartialOrd)]
        struct $name(num_bigint::BigUint);

        gen_prime_field!($name, $prime);
    };
    (pub $name:ident, $prime:literal) => {
        #[derive(Debug, Clone, PartialEq, PartialOrd)]
        pub struct $name(num_bigint::BigUint);

        gen_prime_field!($name, $prime);
    }
}

/// This trait describes an integer type for large prime field arithmetic.
trait PrimeField: Num + Sum + Product + From<BigUint> {
    /// Returns the prime number that is base to this numeric field and its operations.
    fn field_prime() -> Self;

    /// Generate a random member of this field. This method must ensure that guarantees for the distribution of
    /// generated field elements is not worse than guarantees by the underlying random number generator.
    /// #Parameters
    /// - `rng` a random number generator to be used for generating the element
    fn generate_random_member<R: RngCore + CryptoRng + RandBigInt>(rng: &mut R) -> Self
        where num::BigUint: std::convert::From<Self> {
        rng.gen_biguint_below(&Self::field_prime().into()).into()
    }
}

// generate an example prime field struct
prime_field!(pub Mersenne89, "618970019642690137449562111");

#[cfg(test)]
mod tests {
    use num::{Num, One};

    use super::*;

    #[test]
    fn test_addition() {
        let result = Mersenne89::from_str_radix("618970019642690137449561873", 10).unwrap()
            + Mersenne89::from_str_radix("618970019642690137449560877", 10).unwrap();
        assert_eq!(Mersenne89::from_str_radix("618970019642690137449560639", 10).unwrap(), result)
    }

    /// Test, whether an overflowing subtraction correctly wraps around the mersenne number 2^89-1
    #[test]
    fn test_subtraction() {
        let result = Mersenne89::one() - Mersenne89::from_str_radix("645784", 10).unwrap();
        assert_eq!(Mersenne89::from_str_radix("618970019642690137448916328", 10).unwrap(), result)
    }
}