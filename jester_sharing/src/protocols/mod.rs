//! This module contains a lot of protocols that are not modelled by their own traits. Those are divided in their own
//! submodules, but are reexported here for convenient access. All those protocols are simple functions with a type
//! contract that requires implementations of all primitives necessary.

pub use self::conditional_selection::*;
pub use self::joint_unbounded_inversion::*;
pub use self::joint_unbounded_or::*;
pub use self::random_number_generation::*;

pub use jester_maths::prime::PrimeField;
pub use num_bigint::BigUint;
pub use rand::{CryptoRng, RngCore};

mod conditional_selection;
mod joint_unbounded_inversion;
mod joint_unbounded_or;
mod random_number_generation;

#[cfg(test)]
mod tests;
