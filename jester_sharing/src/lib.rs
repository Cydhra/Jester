//! This crate holds a set of protocols and protocol traits for secret sharing. They all aim to provide a toolset
//! useful for calculations on shared secrets.

#![recursion_limit = "256"]

pub use communication::*;
pub use conditional_selection::*;
pub use inversion::*;
pub use multiplication::*;
pub use random_number_generation::*;
pub use shared_or_function::*;
pub use threshold_sharing::*;

pub use jester_maths::prime::PrimeField;
pub use num_bigint::BigUint;
pub use rand::{CryptoRng, RngCore};

pub mod communication;
pub mod conditional_selection;
pub mod inversion;
pub mod multiplication;
pub mod prefix_or_function;
pub mod random_number_generation;
pub mod shared_or_function;
pub mod threshold_sharing;

/// Protocol marker for delegated protocol implementations
pub struct Delegate;

#[cfg(test)]
mod tests;
