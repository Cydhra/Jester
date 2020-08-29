//! This module defines the trait `PrimeField` to be used as a numerical data type for large-prime-field algebra.
//! It also defines macros for defining such types and provides implementations for common operations on such.
//! Furthermore, it provides types for prime fields built from Mersenne numbers.

use std::fmt::Debug;
use std::iter::{Product, Sum};

use mashup::*;
use num::{BigUint, FromPrimitive, Num};
pub use num_bigint;
use num_bigint::RandBigInt;
pub use once_cell;
use rand::{CryptoRng, RngCore};

/// A macro to the define one or multiple data types for large-prime-field algebra. It generates a data type from a
/// given identifier and a string literal, that is then converted into a `BigUint` instance.
/// # Examples
/// ```
/// // this macro requires a higher recursion limit
/// #![recursion_limit="256"]
///
/// // sadly mashup cannot be re-exported and thus must be manually added to to dependencies by the implementor
/// use mashup::*;
/// use num::BigUint;
/// use jester_maths::prime::PrimeField;
/// use jester_maths::prime_fields;
///
/// // the first argument "7" is a string representation of the prime, the second is its radix.
/// prime_fields!(pub MersenneTest("7", 10));
///
/// // the type `MersenneTest` is generated and implements `PrimeField`
/// assert_eq!(BigUint::from(7u64), MersenneTest::field_prime().as_uint());
/// ```
#[macro_export]
macro_rules! prime_fields {
    ($($v:vis $name:ident($prime:literal, $radix:literal)),*) => {

        mashup! {
            $(
                $name["prime" $name] = PRIME_NUMBER_ $name;
            )*
        }

        $(
            $name! {
                static "prime" $name: $crate::prime::once_cell::sync::Lazy<$name> =
                    $crate::prime::once_cell::sync::Lazy::new (|| {
                        // do not parse this to a struct instance directly, because parsing that actually requires
                        // this constant to be already present. Parse the big integer from string instead.
                        $name(num::Num::from_str_radix($prime, $radix).unwrap())
                    });
            }

            $name! {
                #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Hash)]
                $v struct $name($crate::prime::num_bigint::BigUint);

                impl std::ops::Add<$name> for $name {
                    type Output = Self;

                    fn add(self, rhs: $name) -> Self::Output {
                        let mut sum = self.0.clone().add(&rhs.0);
                        std::ops::RemAssign::rem_assign(&mut sum, "prime" $name.0.clone());
                        $name(sum)
                    }
                }
            }

            $name! {
                impl std::ops::Sub<$name> for $name {
                    type Output = Self;

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
            $name! {
                impl std::ops::Div<$name> for $name {
                    type Output = Self;

                    fn div(self, rhs: $name) -> Self::Output {
                        let mut tmp = ::std::ops::Div::div(&self.0.clone(), &rhs.0);
                        ::std::ops::RemAssign::rem_assign(&mut tmp, "prime" $name.0.clone());
                        $name(tmp)
                    }
                }
            }
            $name! {
                impl std::ops::Mul<$name> for $name {
                    type Output = Self;

                    fn mul(self, rhs: $name) -> Self::Output {
                        let mut tmp = ::std::ops::Mul::mul(&self.0.clone(), &rhs.0);
                        ::std::ops::RemAssign::rem_assign(&mut tmp, "prime" $name.0.clone());
                        $name(tmp)
                    }
                }
            }
            $name! {
                impl std::ops::Rem<$name> for $name {
                    type Output = Self;

                    fn rem(self, rhs: $name) -> $name {
                        let mut tmp = self.0.clone();
                        ::std::ops::RemAssign::rem_assign(&mut tmp, &rhs.0);
                        $name(tmp)
                    }
                }
            }
            $name! {
                impl num::Zero for $name {
                    fn zero() -> Self {
                        $name($crate::prime::num_bigint::BigUint::zero())
                    }

                    fn is_zero(&self) -> bool {
                        self.0.is_zero()
                    }
                }
            }
            $name! {
                impl num::One for $name {
                    fn one() -> Self {
                        $name($crate::prime::num_bigint::BigUint::one())
                    }

                    fn is_one(&self) -> bool
                        where Self: PartialEq, {
                        self.0.is_one()
                    }
                }
            }
            $name! {
                impl num::Num for $name {
                    type FromStrRadixErr = num::bigint::ParseBigIntError;

                    fn from_str_radix(str: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
                        $crate::prime::num_bigint::BigUint::from_str_radix(str, radix).map(|i| {
                            let n = i.modpow(&::num::One::one(), &"prime" $name.0);
                            $name(n)
                        })
                    }
                }
            }
            $name! {
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
            $name! {
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
            $name! {
                impl From<$name> for $crate::prime::num_bigint::BigUint {
                    fn from(v: $name) -> Self {
                        v.0
                    }
                }
            }
            $name! {
                impl From<$crate::prime::num_bigint::BigUint> for $name {
                    fn from(v: $crate::prime::num_bigint::BigUint) -> Self {
                        let mut g = v;
                        ::std::ops::RemAssign::rem_assign(&mut g, &"prime" $name.0);
                        $name(g)
                    }
                }
            }
            $name! {
                impl num::FromPrimitive for $name {
                    fn from_i64(n: i64) -> Option<Self> {
                        if n < 0 {
                            $crate::prime::num_bigint::BigUint::from_i64(-n).map(|a| ::std::ops::Sub::sub("prime" $name.clone(), a.into()))
                        } else {
                            $crate::prime::num_bigint::BigUint::from_i64(n).map(|o| o.into())
                        }
                    }

                    fn from_u64(n: u64) -> Option<Self> {
                        $crate::prime::num_bigint::BigUint::from_u64(n).map(|o| o.into())
                    }
                }
            }
            $name! {
                impl PrimeField for $name {
                    fn field_prime() -> Self {
                        "prime" $name.clone()
                    }

                    fn as_uint(&self) -> $crate::prime::num_bigint::BigUint {
                        self.0.clone()
                    }
                }
            }
        )*
    }
}

/// This trait describes an integer type for large prime field arithmetic.
pub trait PrimeField: Num + Clone + Sum + Product + From<BigUint> + FromPrimitive + Debug {
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
    /// generated field elements is not worse than guarantees by the underlying random number generator, however this
    /// method might invoke the `rng` multiple times to achieve that. It is assumed that `rng` is well-seeded and
    /// cryptographically secure.
    fn generate_random_member<R: RngCore + CryptoRng + RandBigInt>(rng: &mut R) -> Self {
        rng.gen_biguint_below(&Self::field_prime().as_uint()).into()
    }
}

// generate mersenne prime field structs
prime_fields!(
    // generate prime groups from the first 11 mersenne numbers
    pub Mersenne2("3", 10),
    pub Mersenne3("7", 10),
    pub Mersenne5("31", 10),
    pub Mersenne13("8191", 10),
    pub Mersenne17("131071", 10),
    pub Mersenne19("524287", 10),
    pub Mersenne31("2147483647", 10),
    pub Mersenne61("2305843009213693951", 10),
    pub Mersenne89("618970019642690137449562111", 10),
    pub Mersenne107("162259276829213363391578010288127", 10),
    pub Mersenne127("170141183460469231731687303715884105727", 10),
    // generate the three prime groups defined in RFC 5114
    pub IetfGroup1
    ("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16),
    pub IetfGroup2
    ("AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F", 16),
    pub IetfGroup3
    ("87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597", 16)
);

/// This trait defines a function to randomly generate a prime number of a given size
pub trait PrimeGenerator {
    fn generate_random_prime<R>(rng: &mut R, bit_size: usize) -> BigUint
    where
        R: RngCore + CryptoRng;
}

#[cfg(test)]
mod tests {
    use num::{Num, One};

    use super::*;

    #[test]
    fn test_addition() {
        let result = Mersenne89::from_str_radix("618970019642690137449561873", 10).unwrap()
            + Mersenne89::from_str_radix("618970019642690137449560877", 10).unwrap();
        assert_eq!(
            Mersenne89::from_str_radix("618970019642690137449560639", 10).unwrap(),
            result
        )
    }

    /// Test, whether an overflowing subtraction correctly wraps around the mersenne number 2^89-1
    #[test]
    fn test_subtraction() {
        let result = Mersenne89::one() - Mersenne89::from_str_radix("645784", 10).unwrap();
        assert_eq!(
            Mersenne89::from_str_radix("618970019642690137448916328", 10).unwrap(),
            result
        )
    }
}
