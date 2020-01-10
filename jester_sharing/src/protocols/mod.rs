//! This module contains a lot of protocols that are not modelled by their own traits. Those are divided in their own
//! submodules, but are reexported here for convenient access. All those protocols are simple functions with a type
//! contract that requires implementations of all primitives necessary.

pub use self::conditional_selection::*;
pub use self::joint_unbounded_or::*;

mod conditional_selection;
mod joint_unbounded_or;

#[cfg(test)]
mod tests;
