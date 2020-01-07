//! This crate holds a set of protocols and protocol traits for secret sharing. They all aim to provide a toolset
//! useful for calculations on shared secrets.

#![recursion_limit = "256"]

pub use communication::*;
pub use multiplication::*;
pub use threshold_sharing::*;

pub use jester_maths::prime::PrimeField;
pub use num_bigint::BigUint;
pub use rand::{CryptoRng, RngCore};

pub mod communication;
pub mod multiplication;
pub mod protocols;
pub mod threshold_sharing;
