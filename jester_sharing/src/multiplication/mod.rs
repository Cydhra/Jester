//! This module defines common traits for multiplication protocols, allowing secret multiplication of shares.
//! This module also provides common implementations of such multiplication schemes.

use crate::Delegate;
use jester_sharing_proc::delegatable_protocol;
use std::future::Future;
use std::pin::Pin;

pub mod beaver_randomization_multiplication;

/// A multiplication scheme. This multiplication scheme is potentially very complex and requires at least one round
/// of communication which in turn requires it to capture a mutable reference to protocol it is defined on. This in
/// turn makes it impossible to parallelize the multiplication. However, there is an extension to this scheme
/// (`ParallelMultiplicationScheme`) which takes multiple parameters and performs all multiplications in parallel.
#[delegatable_protocol]
pub trait MultiplicationScheme<T, S, P>
where
    P: Send + Sync,
    T: Send + Sync,
    S: Send + Sync,
{
    /// Multiply two shares `lhs * rhs` asynchronously. This method cannot be used in parallel, because it moves the
    /// mutable reference to `self` into the future returned.
    fn multiply<'a>(
        protocol: &'a mut P,
        lhs: &S,
        rhs: &S,
    ) -> Pin<Box<dyn Future<Output = S> + Send + 'a>>;
}

/// An extension to `MultiplicationScheme` that overcomes its limitation by simply taking multiple pairs of shares
/// that are to be multiplied at once and multiplying them in parallel.
#[delegatable_protocol]
pub trait UnboundedMultiplicationScheme<T, S, P>
where
    P: Send + Sync,
    T: Send + Sync,
    S: Send + Sync,
{
    /// Multiply a set of pairs of shares in parallel. This method cannot be called in parallel, which is why it
    /// takes a slice of pairs as argument. Simply call this method once with all pairs of values that are to be
    /// multiplied.
    fn unbounded_multiply<'a>(
        protocol: &'a mut P,
        pairs: &[(S, S)],
    ) -> Pin<Box<dyn Future<Output = Vec<S>> + Send + 'a>>;
}
