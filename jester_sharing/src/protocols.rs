use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::RwLock;

use futures::join;
use futures::lock::Mutex;
use num::{FromPrimitive, One, Zero};
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use rand::{CryptoRng, RngCore};

use jester_algebra::prime::PrimeField;

use crate::{CliqueCommunicationScheme, LinearSharingScheme, MultiplicationScheme, ThresholdSecretSharingScheme};

/// A protocol to generate a secret random number where every participant has a share on that number, but no
/// participant learns the actual value of that number.
/// #Parameters
/// - `rng` a cryptographically secure random number generator
/// - `protocol` an instance of the protocol to be used. It must be a linear `ThresholdSecretSharingScheme` with
/// `PeerToPeerPartyScheme` communication style
///
/// #Output
/// Returns a future on the value that is to be generated. The future does not hold references to `rng` and
/// `protocol` so this method can be called multiple times in parallel.
pub fn joint_random_number_sharing<R, T, S, P>(rng: &mut R, protocol: &mut P) -> impl Future<Output=S>
    where R: RngCore + CryptoRng,
          T: PrimeField,
          S: 'static,
          P: ThresholdSecretSharingScheme<T, S> + LinearSharingScheme<T, S> + CliqueCommunicationScheme<T, S> {
    let rand_partial = T::generate_random_member(rng);
    let all_shares_future = protocol.distribute_secret(rand_partial);

    async move {
        P::sum_shares(&all_shares_future.await).unwrap()
    }
}

/// A protocol for the joint selection of either side of a ternary expression `condition ? lhs : rhs` without
/// any participant learning the value of `condition` or the expression chosen by the protocol. This protocol cannot
/// be invoked in parallel, as it uses a two-stage multiplication protocol.
///
/// #Parameters
/// - `protocol` an instance of the sub-protocols used. It must be a `ThresholdSecretSharingScheme` with additive
/// linear shares and communication between all participants. Furthermore multiplication by communication must be
/// supported.
/// - `condition` a share on a value that resolves either to `0` or to `1`. Any other value will produce undefined
/// behaviour. Since this protocol does not leak information about `condition`, such an undefined result is
/// undetectable (at least until the result is evaluated)
/// - `lhs` the left hand side of the if-else expression that is taken, if `condition` evaluates to `1`
/// - `rhs` the right hand side of the if-else expression that is taken, if `condition` evaluates to `0`
///
/// #Output
/// Returns a future on either `lhs` or `rhs`, but in a rerandomized share, so a participant cannot learn which one
/// was taken.
pub async fn joint_conditional_selection<T, S, P>(protocol: &mut P, condition: &S, lhs: &S, rhs: &S) -> S
    where T: PrimeField,
          P: ThresholdSecretSharingScheme<T, S> + LinearSharingScheme<T, S> + CliqueCommunicationScheme<T, S> +
          MultiplicationScheme<T, S> {
    let operands_difference = P::sub_shares(lhs, rhs);

    // copy rhs to move a copy into the future
    let product = protocol.multiply(condition, &operands_difference).await;
    P::add_shares(&product, rhs)
}

/// A function generating the upper triangular matrix U that is defined by V = U * L, where V is the inverted
/// Vandermonde matrix. The function generates the matrix recursively and caches results to be used later on.
/// Asynchronicity is used to wait on a lock onto the global cache it uses for pre-calculated entries.
/// # Parameters
/// - `row` row of requested entry. Starts at zero. Negative entries might lead to undefined behaviour.
/// - `column` column of requested entry. Starts at zero. Negative entries might lead to undefined behaviour.
fn get_inverted_vandermonde_upper<T>(row: isize, column: isize) -> Pin<Box<dyn Future<Output=T> + Sync + Send>>
    where T: PrimeField + Send + Sync + 'static {
    Box::pin(async move {
        // a wrapper struct wrapping a marker used as a key in a typemap
        struct TypeKey<T: 'static>(PhantomData<T>);
        impl<T: 'static> typemap::Key for TypeKey<T> {
            type Value = HashMap<(isize, isize), T>;
        }

        lazy_static! {
        static ref INVERTED_VANDERMONDE_MATRIX_UPPER: Mutex<typemap::ShareMap> =
            Mutex::new(typemap::TypeMap::custom());
    }

        if let Some(v) = INVERTED_VANDERMONDE_MATRIX_UPPER
            .lock()
            .await
            .get::<TypeKey<T>>()
            .and_then(|matrix| matrix.get(&(row, column))) {
            v.clone().into()
        } else {
            let v = if row == column {
                T::one()
            } else if column == 0 {
                T::zero()
            } else if row == -1 {
                T::zero()
            } else {
                assert!(column >= 0);
                assert!(row >= 0);

                let x = (BigUint::from_isize(column).unwrap() + BigUint::one()).into();

                let (a, b) = join!(get_inverted_vandermonde_upper::<T>(row - 1, column - 1),
                get_inverted_vandermonde_upper::<T>(row, column - 1));

                a - b * x
            };

            INVERTED_VANDERMONDE_MATRIX_UPPER
                .lock()
                .await
                .entry::<TypeKey<T>>()
                .or_insert_with(|| HashMap::new())
                .insert((row, column), v.clone());
            v
        }
    })
}

/// A function generating the lower triangular matrix L that is defined by V = U * L, where V is the inverted
/// Vandermonde matrix. The function generates the matrix recursively and caches results to be used later on.
/// Asynchronicity is used to wait on a lock onto the global cache it uses for pre-calculated entries.
/// # Parameters
/// - `row` row of requested entry. Starts at zero. Negative entries might lead to undefined behaviour.
/// - `column` column of requested entry. Starts at zero. Negative entries might lead to undefined behaviour.
async fn get_inverted_vandermonde_lower<T>(row: isize, column: isize) -> T
    where T: PrimeField + Send + Sync + 'static {
    // use a wrapper to a marker type that can be used as a key to the typemap
    struct TypeKey<T: 'static>(PhantomData<T>);
    impl<T: 'static> typemap::Key for TypeKey<T> {
        type Value = HashMap<(isize, isize), T>;
    }

    lazy_static! {
        static ref INVERTED_VANDERMONDE_MATRIX_LOWER: Mutex<typemap::ShareMap> =
            Mutex::new(typemap::TypeMap::custom());
    }

    if let Some(v) = INVERTED_VANDERMONDE_MATRIX_LOWER
        .lock()
        .await
        .get::<TypeKey<T>>()
        .and_then(|matrix| matrix.get(&(row, column))) {
        v.clone().into()
    } else {
        let v = if row < column {
            T::zero()
        } else if row == 0 && column == 0 {
            T::one()
        } else {
            (0..=row)
                .filter(|k| *k != column)
                .map(|k| (BigUint::from_isize(column).unwrap() - BigUint::from_isize(k).unwrap()).into())
                .product::<T>()
                .inverse()
        };

        INVERTED_VANDERMONDE_MATRIX_LOWER
            .lock()
            .await
            .entry::<TypeKey<T>>()
            .or_insert_with(|| HashMap::new())
            .insert((row, column), v.clone());
        v
    }
}

/// Asynchronously get the entries of an inverted vandermonde matrix of given size. This function does not cache
/// results, as results change on different matrix sizes.
/// # Parameters
/// - `row` row of requested entry. Starts at zero. Negative entries will result in unexpected behaviour.
/// - `column` column of requested entry. Starts at zero. Negative entries will result in unexpected behaviour.
/// - `matrix_size` size of the square vandermonde matrix. Depends on the amount of sample points that this matrix
/// transforms.
async fn get_inverted_vandermonde_entry<T>(row: isize, column: isize, matrix_size: usize) -> T
    where T: PrimeField + Sync + Send + 'static {
    assert!(matrix_size > 0);

    let mut acc = T::zero();

    for index in 0..matrix_size {
        let (u, l) = join!(get_inverted_vandermonde_upper::<T>(row, index as isize),
                                get_inverted_vandermonde_lower::<T>(index as isize, column));
        acc = acc + u * l
    }

    acc
}

pub async fn unbounded_or<T, S, P>(protocol: &mut P, bits: &[S]) -> S
    where T: PrimeField,
          P: ThresholdSecretSharingScheme<T, S> + LinearSharingScheme<T, S> + CliqueCommunicationScheme<T, S> +
          MultiplicationScheme<T, S> {
    unimplemented!()
}