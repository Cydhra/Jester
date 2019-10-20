use std::iter::{Product, Sum};
use std::ops::{Add, Div, Mul, Rem, Sub};

use num::{Integer, Num, One, pow::pow, Signed, Zero};
use num_bigint::ParseBigIntError;
use num_bigint::BigInt;

use jester_algebra_derive::PrimeField;

#[derive(PrimeField, Debug, Clone, PartialEq, PartialOrd)]
struct Mersenne89(BigInt);

trait PrimeField {}
