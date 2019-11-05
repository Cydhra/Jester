use std::iter::{Product, Sum};

use num::{BigUint, FromPrimitive, Num};
use num_bigint::RandBigInt;
use rand::{CryptoRng, RngCore};

#[macro_export]
macro_rules! prime_fields {
    ($($v:vis $name:ident($prime:literal)),*) => {

        mashup! {
            $(
                m["prime" $name] = PRIME_NUMBER_ $name;
            )*
        }

        $(
            m! {
                static "prime" $name: once_cell::sync::Lazy<$name> = once_cell::sync::Lazy::new(|| {
                    // do not parse this to a struct instance directly, because parsing that actually requires
                    // this constant to be already present. Parse the big integer from string instead.
                    $name(std::str::FromStr::from_str(stringify!($prime)).unwrap())
                });
            }

            m! {
                #[derive(Clone, Debug, PartialEq, PartialOrd)]
                $v struct $name(num_bigint::BigUint);

                impl std::ops::Add<$name> for $name {
                    type Output = $name;

                    fn add(self, rhs: $name) -> Self::Output {
                        let mut sum = self.0.clone().add(&rhs.0);
                        std::ops::RemAssign::rem_assign(&mut sum, "prime" $name.0.clone());
                        $name(sum)
                    }
                }
            }

            m! {
                impl std::ops::Sub<$name> for $name {
                    type Output = $name;

                    fn sub(self, rhs: $name) -> Self::Output {
                        let mut sum = if self >= rhs {
                            ::std::ops::Sub::sub(&self.0.clone(), &rhs.0)
                        } else {
                            let inverse = ::std::ops::Sub::sub("prime" $name.clone(), rhs.clone());
                            ::std::ops::Add::add(&self.0.clone(), &inverse.0)
                        };

                        ::std::ops::RemAssign::rem_assign(&mut sum, "prime" $name.0.clone());
                        $name(sum)
                    }
                }
            }
            m! {
                impl std::ops::Div<$name> for $name {
                    type Output = $name;

                    fn div(self, rhs: $name) -> Self::Output {
                        let mut tmp = ::std::ops::Div::div(&self.0.clone(), &rhs.0);
                        ::std::ops::RemAssign::rem_assign(&mut tmp, "prime" $name.0.clone());
                        $name(tmp)
                    }
                }
            }
            m! {
                impl std::ops::Mul<$name> for $name {
                    type Output = $name;

                    fn mul(self, rhs: $name) -> Self::Output {
                        let mut tmp = ::std::ops::Mul::mul(&self.0.clone(), &rhs.0);
                        ::std::ops::RemAssign::rem_assign(&mut tmp, "prime" $name.0.clone());
                        $name(tmp)
                    }
                }
            }
            m! {
                impl std::ops::Rem<$name> for $name {
                    type Output = Self;

                    fn rem(self, rhs: $name) -> $name {
                        let mut tmp = self.0.clone();
                        ::std::ops::RemAssign::rem_assign(&mut tmp, &rhs.0);
                        $name(tmp)
                    }
                }
            }
            m! {
                impl num::Zero for $name {
                    fn zero() -> Self {
                        $name(num_bigint::BigUint::zero())
                    }

                    fn is_zero(&self) -> bool {
                        self.0.is_zero()
                    }
                }
            }
            m! {
                impl num::One for $name {
                    fn one() -> Self {
                        $name(num_bigint::BigUint::one())
                    }

                    fn is_one(&self) -> bool
                        where Self: PartialEq, {
                        self.0.is_one()
                    }
                }
            }
            m! {
                impl num::Num for $name {
                    type FromStrRadixErr = num::bigint::ParseBigIntError;

                    fn from_str_radix(str: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
                        num_bigint::BigUint::from_str_radix(str, radix).map(|i| {
                            let n = i.modpow(&::num::One::one(), &"prime" $name.0);
                            $name(n)
                        })
                    }
                }
            }
            m! {
                impl std::iter::Sum for $name {
                    fn sum<I: Iterator<Item=Self>>(iter: I) -> Self {
                        let mut tmp: $name = ::num::Zero::zero();
                        for x in iter {
                            tmp = tmp + x;
                        }
                        tmp
                    }
                }
            }
            m! {
                impl std::iter::Product for $name {
                    fn product<I: Iterator<Item=Self>>(iter: I) -> Self {
                        let mut tmp: $name = ::num::One::one();
                        for x in iter {
                            tmp = tmp * x;
                        }
                        tmp
                    }
                }
            }
            m! {
                impl From<$name> for BigUint {
                    fn from(v: $name) -> Self {
                        v.0
                    }
                }
            }
            m! {
                impl From<BigUint> for $name {
                    fn from(v: BigUint) -> Self {
                        let mut g = v;
                        ::std::ops::RemAssign::rem_assign(&mut g, &"prime" $name.0);
                        $name(g)
                    }
                }
            }
            m! {
                impl num::FromPrimitive for $name {
                    fn from_i64(n: i64) -> Option<Self> {
                        if n < 0 {
                            BigUint::from_i64(-n).map(|a| ::std::ops::Sub::sub("prime" $name.clone(), a.into()))
                        } else {
                            num_bigint::BigUint::from_i64(n).map(|o| o.into())
                        }
                    }

                    fn from_u64(n: u64) -> Option<Self> {
                        num_bigint::BigUint::from_u64(n).map(|o| o.into())
                    }
                }
            }
            m! {
                impl PrimeField for $name {
                    fn field_prime() -> Self {
                        "prime" $name.clone()
                    }

                    fn as_uint(&self) -> BigUint {
                        self.0.clone()
                    }
                }
            }
        )*
    }
}

/// This trait describes an integer type for large prime field arithmetic.
pub trait PrimeField: Num + Clone + Sum + Product + From<BigUint> + FromPrimitive {
    /// Returns the prime number that is base to this numeric field and its operations.
    fn field_prime() -> Self;

    /// Returns the prime as a `BigUint` instance
    fn as_uint(&self) -> BigUint;

    /// Calculate the multiplicative inverse of this element.
    fn inverse(&self) -> Self {
        let (_, _, inverse) = Self::extended_greatest_common_divisor(&Self::field_prime(), self);
        inverse
    }

    /// The extended euclidean algorithm within this integer prime field.
    fn extended_greatest_common_divisor(a: &Self, b: &Self) -> (Self, Self, Self) {
        if b.is_zero() {
            (a.clone(), Self::one(), Self::zero())
        } else {
            let (d, s, t) = Self::extended_greatest_common_divisor(b, &a.clone().rem(b.clone()));
            let delta = (a.clone().div(b.clone())).mul(t.clone());
            (d, t, s - delta)
        }
    }


    /// Generate a random member of this field. This method must ensure that guarantees for the distribution of
    /// generated field elements is not worse than guarantees by the underlying random number generator.
    /// #Parameters
    /// - `rng` a random number generator to be used for generating the element
    fn generate_random_member<R: RngCore + CryptoRng + RandBigInt>(rng: &mut R) -> Self {
        rng.gen_biguint_below(&Self::field_prime().as_uint()).into()
    }
}

// generate an example prime field structs
prime_fields!(
    pub Mersenne2(3),
    pub Mersenne3(7),
    pub Mersenne5(31),
    pub Mersenne13(8191),
    pub Mersenne17(131071),
    pub Mersenne19(524287),
    pub Mersenne31(2147483647),
    pub Mersenne61(2305843009213693951),
    pub Mersenne89(618970019642690137449562111),
    pub Mersenne107(162259276829213363391578010288127),
    pub Mersenne127(170141183460469231731687303715884105727));

/// This trait defines a function to randomly generate a prime number of a given size
pub trait PrimeGenerator {
    fn generate_random_prime<R>(rng: &mut R, bit_size: usize) -> BigUint
        where R: RngCore + CryptoRng;
}

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