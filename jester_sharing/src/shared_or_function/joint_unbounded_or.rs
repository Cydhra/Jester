use crate::{
    BigUint, CliqueCommunicationScheme, CryptoRng, LinearSharingScheme, OrFunctionScheme,
    PrimeField, RandomNumberGenerationScheme, RngCore, ThresholdSecretSharingScheme,
    UnboundedInversionScheme, UnboundedMultiplicationScheme, UnboundedOrFunctionScheme,
};

use futures::Future;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::pin::Pin;

use futures::lock::Mutex;
use futures::{future::join_all, join};
use lazy_static::*;
use num::FromPrimitive;

pub struct JointUnboundedOrFunction<T, S, P>(PhantomData<T>, PhantomData<S>, PhantomData<P>)
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + UnboundedMultiplicationScheme<T, S>
        + RandomNumberGenerationScheme<T, S, P>
        + UnboundedInversionScheme<T, S, P>,
    T: PrimeField + Send + Sync + 'static,
    S: Clone + 'static;

impl<T, S, P> OrFunctionScheme<T, S, P> for JointUnboundedOrFunction<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + UnboundedMultiplicationScheme<T, S>
        + RandomNumberGenerationScheme<T, S, P>
        + UnboundedInversionScheme<T, S, P>,
    T: PrimeField + Send + Sync + 'static,
    S: Clone + 'static,
{
    fn shared_or<'a, R>(
        rng: &'a mut R,
        protocol: &'a mut P,
        bits: &S,
    ) -> Pin<Box<dyn Future<Output = S> + 'a>>
    where
        R: RngCore + CryptoRng,
    {
        let bits_vec = vec![bits.clone()];
        Self::unbounded_shared_or(rng, protocol, &bits_vec)
    }
}

impl<T, S, P> UnboundedOrFunctionScheme<T, S, P> for JointUnboundedOrFunction<T, S, P>
where
    P: ThresholdSecretSharingScheme<T, S>
        + LinearSharingScheme<T, S>
        + CliqueCommunicationScheme<T, S>
        + UnboundedMultiplicationScheme<T, S>
        + RandomNumberGenerationScheme<T, S, P>
        + UnboundedInversionScheme<T, S, P>,
    T: PrimeField + Send + Sync + 'static,
    S: Clone + 'static,
{
    fn unbounded_shared_or<'a, R>(
        rng: &'a mut R,
        protocol: &'a mut P,
        bits: &[S],
    ) -> Pin<Box<dyn Future<Output = S> + 'a>>
    where
        R: RngCore + CryptoRng,
    {
        assert!(!bits.is_empty());

        // compute a polynomial share of the sum of all `l` bits plus one.
        let sum = P::add_scalar(&P::sum_shares(bits).unwrap(), &T::one());

        let degree = bits.len(); // `l`

        Box::pin(async move {
            // now define an `l`-degree polynomial f(x) such that `f(1) = 0, f(2) = f(3) = ... = f(l + 1) = 1`. Note that
            // f(sum) = bits[0] | bits[1] | ... | bits[l]. Choose `l + 1` samples from the polynomial. Conveniently, the
            // samples at points `(1..l+1)` are chosen. Those samples are the lagrange-coefficients of the polynomial and can
            // be transformed to monomial-coefficients by multiplication with the inverse vandermonde-matrix
            let lagrange_coefficients: Vec<_> = (1..=degree + 1)
                .map(|a| if a == 1 { 0_usize } else { 1_usize })
                .collect();

            let monomial_coefficients: Vec<T> = join_all((0..=degree).map(|i| {
                let iter_clone = lagrange_coefficients.iter();
                async move {
                    join_all(iter_clone.enumerate().map(|(j, c)| {
                        async move {
                            get_inverted_vandermonde_entry::<T>(i as isize, j as isize, degree + 1)
                                .await
                                * BigUint::from(*c).into()
                        }
                    }))
                    .await
                    .into_iter()
                    .sum()
                }
            }))
            .await;

            // generate `l` helper used for an unbounded multiplication. Those helpers will be inverted using an
            // unbounded inversion and then multiplied with the elements that are used in the unbounded multiplication such
            // that helper[i - 1] * inverse_helper[i] are multiplied with one element. Then all elements that are rerandomized
            // this way are revealed and multiplied together by all parties. This way, all helpers except for one cancel each
            // other out and the last (inverse) helper remaining will be cancelled by all parties independently by
            // multiplying their share of that helper. This way, all parties obtain a share of the unbounded multiplication
            // result, but cannot learn the reconstructed result without learning the reconstructed last helper.
            let helpers: Vec<_> = (1..=degree)
                .map(|_| P::generate_random_number_sharing(rng, protocol))
                .collect();
            let helpers = join_all(helpers).await;

            let inverted_helpers = P::unbounded_inverse(rng, protocol, &helpers).await;

            // multiply the `i`'th inverted helper (except the first one) with the `(i - 1)'th` helper
            let mut cancellation_factors = vec![];
            cancellation_factors.push(inverted_helpers[0].clone());
            cancellation_factors.append(
                &mut protocol
                    .unbounded_multiply(
                        &helpers[..degree - 1]
                            .iter()
                            .cloned()
                            .zip(inverted_helpers[1..].iter().cloned())
                            .collect::<Vec<_>>(),
                    )
                    .await,
            );

            // unbounded multiplication keeping all factors
            let factors = protocol
                .unbounded_multiply(
                    &cancellation_factors
                        .into_iter()
                        .map(|f| (sum.clone(), f))
                        .collect::<Vec<_>>(),
                )
                .await;

            // reveal factors
            let revealed_factors: Vec<_> = factors
                .iter()
                .map(|c| protocol.reveal_shares(c.clone()))
                .collect();
            let revealed_factors = join_all(revealed_factors).await;

            // calculate all powers of `sum` between `1` and `degree` and add their respective monomials
            let powers_for_polynomial: Vec<_> = (1..=degree)
                .map(|power| {
                    P::multiply_scalar(
                        &P::multiply_scalar(
                            &helpers[power - 1],
                            &revealed_factors[..power].iter().cloned().product(),
                        ),
                        &monomial_coefficients[power],
                    )
                })
                .collect();

            // add the constant monomial coefficient to the polynomial and sum it up
            powers_for_polynomial[1..].iter().fold(
                P::add_scalar(&powers_for_polynomial[0], &monomial_coefficients[0]),
                |acc, monomial| P::add_shares(&acc, monomial),
            )
        })
    }
}

/// A function generating the upper triangular matrix U that is defined by V = U * L, where V is the inverted
/// Vandermonde matrix. The function generates the matrix recursively and caches results to be used later on.
/// Asynchronicity is used to wait on a lock onto the global cache it uses for pre-calculated entries.
///
/// # Parameters
/// - `row` row of requested entry. Starts at zero. Negative entries might lead to undefined behaviour.
/// - `column` column of requested entry. Starts at zero. Negative entries might lead to undefined behaviour.
fn get_inverted_vandermonde_upper<T>(
    row: isize,
    column: isize,
) -> Pin<Box<dyn Future<Output = T> + Sync + Send>>
where
    T: PrimeField + Send + Sync + 'static,
{
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

        let mutex_guard = INVERTED_VANDERMONDE_MATRIX_UPPER.lock().await;

        if let Some(v) = mutex_guard
            .get::<TypeKey<T>>()
            .and_then(|matrix| matrix.get(&(row, column)))
        {
            v.clone()
        } else {
            drop(mutex_guard);

            let v = if row == column {
                T::one()
            } else if column == 0 || row == -1 {
                T::zero()
            } else {
                assert!(column >= 0);
                assert!(row >= 0);

                let x = BigUint::from_isize(column).unwrap().into();

                let (a, b) = join!(
                    get_inverted_vandermonde_upper::<T>(row - 1, column - 1),
                    get_inverted_vandermonde_upper::<T>(row, column - 1)
                );

                a - b * x
            };

            let mut mutex_guard = INVERTED_VANDERMONDE_MATRIX_UPPER.lock().await;
            mutex_guard
                .entry::<TypeKey<T>>()
                .or_insert_with(HashMap::new)
                .insert((row, column), v.clone());
            v
        }
    })
}

/// A function generating the lower triangular matrix L that is defined by V = U * L, where V is the inverted
/// Vandermonde matrix. The function generates the matrix recursively and caches results to be used later on.
/// Asynchronicity is used to wait on a lock onto the global cache it uses for pre-calculated entries.
///
/// # Parameters
/// - `row` row of requested entry. Starts at zero. Negative entries might lead to undefined behaviour.
/// - `column` column of requested entry. Starts at zero. Negative entries might lead to undefined behaviour.
async fn get_inverted_vandermonde_lower<T>(row: isize, column: isize) -> T
where
    T: PrimeField + Send + Sync + 'static,
{
    // use a wrapper to a marker type that can be used as a key to the typemap
    struct TypeKey<T: 'static>(PhantomData<T>);
    impl<T: 'static> typemap::Key for TypeKey<T> {
        type Value = HashMap<(isize, isize), T>;
    }

    lazy_static! {
        static ref INVERTED_VANDERMONDE_MATRIX_LOWER: Mutex<typemap::ShareMap> =
            Mutex::new(typemap::TypeMap::custom());
    }

    let mut mutex_guard = INVERTED_VANDERMONDE_MATRIX_LOWER.lock().await;

    if let Some(v) = mutex_guard
        .get::<TypeKey<T>>()
        .and_then(|matrix| matrix.get(&(row, column)))
    {
        v.clone()
    } else {
        let v = if row < column {
            T::zero()
        } else if row == 0 && column == 0 {
            T::one()
        } else {
            (0..=row)
                .filter(|k| *k != column)
                .map(|k| T::from_isize(column).unwrap() - T::from_isize(k).unwrap())
                .product::<T>()
                .inverse()
        };

        mutex_guard
            .entry::<TypeKey<T>>()
            .or_insert_with(HashMap::new)
            .insert((row, column), v.clone());
        v
    }
}

/// Asynchronously get the entries of an inverted vandermonde matrix of given size. This function does not cache
/// results, as results change on different matrix sizes.
///
/// # Parameters
/// - `row` row of requested entry. Starts at zero. Negative entries will result in unexpected behaviour.
/// - `column` column of requested entry. Starts at zero. Negative entries will result in unexpected behaviour.
/// - `matrix_size` size of the square vandermonde matrix. Depends on the amount of sample points that this matrix
/// transforms.
async fn get_inverted_vandermonde_entry<T>(row: isize, column: isize, matrix_size: usize) -> T
where
    T: PrimeField + Sync + Send + 'static,
{
    assert!(matrix_size > 0);

    let mut acc = T::zero();

    for index in 0..matrix_size {
        let (u, l) = join!(
            get_inverted_vandermonde_upper::<T>(row, index as isize),
            get_inverted_vandermonde_lower::<T>(index as isize, column)
        );
        acc = acc + u * l;
    }

    acc
}
