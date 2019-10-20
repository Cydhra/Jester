use num::{BigInt, One, Zero};

#[macro_export]
macro_rules! prime_field {
    ($name:ident, $prime:literal) => {
        static PRIME_NUMBER: once_cell::sync::Lazy<$name> = once_cell::sync::Lazy::new(|| {
            // do not parse this to a struct instance directly, because parsing that actually requires
            // this constant to be already present. Parse the big integer from string instead.
            $name(std::str::FromStr::from_str($prime).unwrap())
        });

        #[derive(Debug, Clone, PartialEq, PartialOrd)]
        pub struct $name(num_bigint::BigInt);

        impl std::ops::Add<$name> for $name {
            type Output = $name;

            fn add(self, rhs: $name) -> Self::Output {
                let mut sum = self.0.clone().add(&rhs.0);
                std::ops::RemAssign::rem_assign(&mut sum, PRIME_NUMBER.0.clone());
                if num::Signed::is_negative(&sum) {
                    std::ops::AddAssign::add_assign(&mut sum, &PRIME_NUMBER.0)
                }
                $name(sum)
            }
        }

        impl std::ops::Sub<$name> for $name {
            type Output = $name;

            fn sub(self, rhs: $name) -> Self::Output {
                let mut sum = ::std::ops::Sub::sub(&self.0.clone(), &rhs.0);
                ::std::ops::RemAssign::rem_assign(&mut sum, PRIME_NUMBER.0.clone());
                if ::num::Signed::is_negative(&sum) {
                    ::std::ops::AddAssign::add_assign(&mut sum, &PRIME_NUMBER.0);
                }
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
                $name(num_bigint::BigInt::zero())
            }

            fn is_zero(&self) -> bool {
                self.0.is_zero()
            }
        }

        impl num::One for $name {
            fn one() -> Self {
                $name(num_bigint::BigInt::one())
            }

            fn is_one(&self) -> bool
                where Self: PartialEq, {
                self.0.is_one()
            }
        }

        impl num::Num for $name {
            type FromStrRadixErr = num::bigint::ParseBigIntError;

            fn from_str_radix(str: &str, radix: u32) -> Result<Self, Self::FromStrRadixErr> {
                num_bigint::BigInt::from_str_radix(str, radix).map(|i| {
                    let n = i.modpow(&BigInt::one(), &PRIME_NUMBER.0);
                    $name(n)
                })
            }
        }

        impl std::iter::Sum for $name {
            fn sum<I: Iterator<Item=Self>>(iter: I) -> Self {
                let mut tmp = $name::zero();
                for x in iter {
                    tmp = tmp + x;
                }
                tmp
            }
        }

        impl std::iter::Product for $name {
            fn product<I: Iterator<Item=Self>>(iter: I) -> Self {
                let mut tmp = $name::one();
                for x in iter {
                    tmp = tmp * x;
                }
                tmp
            }
        }
    }
}

trait PrimeField {}

prime_field!(Mersenne89, "618970019642690137449562111");


#[cfg(test)]
mod tests {
    use num::Num;

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