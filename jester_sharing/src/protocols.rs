use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;

use futures::{future::join_all, join};
use futures::lock::Mutex;
use num::{FromPrimitive, One};
use num_bigint::BigUint;
use rand::{CryptoRng, RngCore};

use jester_maths::prime::PrimeField;

use crate::{CliqueCommunicationScheme, LinearSharingScheme, MultiplicationScheme, ParallelMultiplicationScheme, ThresholdSecretSharingScheme};

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

/// A protocol inverting an unbounded amount of shares in parallel. The protocol requires two round-trip-times in a
/// `CliqueCommunicationScheme`.
/// # Parameters
/// - `rng` a cryptographically secure random number generator
/// - `protocol` an instance of the sub-protocols used. It must be a `ThresholdSecretSharingScheme` with additive
/// linear shares and communication between all participants. Furthermore, parallel multiplication by communication
/// must be supported.
/// - `elements` the shares that shall be inverted
///
/// # Output
/// Returns a `Vec` of shares that are the inverted input elements in the same order.
pub async fn joint_unbounded_inversion<R, T, S, P>(rng: &mut R, protocol: &mut P, elements: &[S]) -> Vec<S>
    where R: RngCore + CryptoRng,
          T: PrimeField,
          S: Clone + 'static,
          P: ThresholdSecretSharingScheme<T, S> + LinearSharingScheme<T, S> + CliqueCommunicationScheme<T, S> +
          ParallelMultiplicationScheme<T, S> {
    let bound = elements.len();
    let helpers: Vec<_> = (0..bound)
        .map(|_| joint_random_number_sharing(rng, protocol))
        .collect();
    let helpers = join_all(helpers).await;

    let rerandomized_elements = protocol.parallel_multiply(&elements.iter()
        .cloned()
        .zip(helpers.clone())
        .collect::<Vec<_>>())
        .await;

    let revealed_elements = rerandomized_elements.into_iter()
        .map(|e| protocol.reveal_shares(e));
    let revealed_elements = join_all(revealed_elements).await;

    revealed_elements.into_iter()
        .zip(helpers)
        .map(|(hidden_element, helper)| P::multiply_scalar(&helper, &hidden_element.inverse()))
        .collect()
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

        let mutex_guard = INVERTED_VANDERMONDE_MATRIX_UPPER.lock().await;

        if let Some(v) = mutex_guard
            .get::<TypeKey<T>>()
            .and_then(|matrix| matrix.get(&(row, column))) {
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

                let x = (BigUint::from_isize(column).unwrap() + BigUint::one()).into();

                let (a, b) = join!(get_inverted_vandermonde_upper::<T>(row - 1, column - 1),
                get_inverted_vandermonde_upper::<T>(row, column - 1));

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

    let mut mutex_guard = INVERTED_VANDERMONDE_MATRIX_LOWER.lock().await;

    if let Some(v) = mutex_guard
        .get::<TypeKey<T>>()
        .and_then(|matrix| matrix.get(&(row, column))) {
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
        acc = acc + u * l;
    }

    acc
}

pub async fn joint_unbounded_or<R, T, S, P>(rng: &mut R, protocol: &mut P, bits: &[S]) -> S
    where R: RngCore + CryptoRng,
          T: PrimeField + Send + Sync + 'static,
          S: Clone + 'static,
          P: ThresholdSecretSharingScheme<T, S> + LinearSharingScheme<T, S> + CliqueCommunicationScheme<T, S> +
          ParallelMultiplicationScheme<T, S> {
    assert!(!bits.is_empty());

    // compute a polynomial share of the sum of all `l` bits plus one.
    let sum = P::add_scalar(&P::sum_shares(bits).unwrap(), &T::one());

    // now define an `l`-degree polynomial f(x) such that `f(1) = 0, f(2) = f(3) = ... = f(l + 1) = 1`. Note that
    // f(sum) = bits[0] | bits[1] | ... | bits[l]. Choose `l + 1` samples from the polynomial. Conveniently, the
    // samples at points `(1..l+1)` are chosen. Those samples are the lagrange-coefficients of the polynomial and can
    // be transformed to monomial-coefficients by multiplication with the inverse vandermonde-matrix
    let degree = bits.len(); // `l`
    let lagrange_coefficients: Vec<_> = (1..=degree + 1)
        .map(|a| if a == 1 { 0_usize } else { 1_usize })
        .collect();

    let monomial_coefficients: Vec<T> = join_all((0..=degree)
        .map(|i| {
            let iter_clone = lagrange_coefficients.iter();
            async move {
                join_all(iter_clone
                    .enumerate()
                    .map(|(j, c)| async move {
                        get_inverted_vandermonde_entry::<T>(i as isize, j as isize, degree + 1).await
                            * BigUint::from(*c).into()
                    }))
                    .await
                    .into_iter()
                    .sum()
            }
        })).await;

    // generate `l` helper used for an unbounded multiplication. Those helpers will be inverted using an
    // unbounded inversion and then multiplied with the elements that are used in the unbounded multiplication such
    // that helper[i - 1] * inverse_helper[i] are multiplied with one element. Then all elements that are rerandomized
    // this way are revealed and multiplied together by all parties. This way, all helpers except for one cancel each
    // other out and the last (inverse) helper remaining will be cancelled by all parties independently by
    // multiplying their share of that helper. This way, all parties obtain a share of the unbounded multiplication
    // result, but cannot learn the reconstructed result without learning the reconstructed last helper.
    let helpers: Vec<_> = (1..=degree)
        .map(|_| joint_random_number_sharing(rng, protocol))
        .collect();
    let helpers = join_all(helpers).await;

    let inverted_helpers = joint_unbounded_inversion(rng, protocol, &helpers).await;

    // multiply the `i`'th inverted helper (except the first one) with the `(i - 1)'th` helper
    let mut cancellation_factors = vec![];
    cancellation_factors.push(inverted_helpers[0].clone());
    cancellation_factors.append(&mut protocol.parallel_multiply(
        &helpers[..degree - 1]
            .iter()
            .cloned()
            .zip(inverted_helpers[1..].iter().cloned())
            .collect::<Vec<_>>()).await);

    // unbounded multiplication keeping all factors
    let factors = protocol.parallel_multiply(
        &cancellation_factors.into_iter()
            .map(|f| (sum.clone(), f))
            .collect::<Vec<_>>()
    ).await;

    // reveal factors
    let revealed_factors: Vec<_> = factors.iter().map(|c| protocol.reveal_shares(c.clone())).collect();
    let revealed_factors = join_all(revealed_factors).await;

    // calculate all powers of `sum` between `1` and `degree` and add their respective monomials
    let powers_for_polynomial: Vec<_> = (1..=degree)
        .map(|power|
            P::multiply_scalar(
                &P::multiply_scalar(&helpers[power - 1], &revealed_factors[..power].iter().cloned().product()),
                &monomial_coefficients[power]))
        .collect();

    // add the constant monomial coefficient to the polynomial and sum it up
    powers_for_polynomial[1..]
        .iter()
        .fold(P::add_scalar(&powers_for_polynomial[0], &monomial_coefficients[0]), |acc, monomial|
            P::add_shares(&acc, monomial))
}

#[cfg(test)]
mod tests {
    use std::iter::repeat;
    use std::pin::Pin;

    use futures::executor::block_on;
    use futures::Future;
    use mashup::*;
    use num::traits::{One, Zero};
    use num_bigint::BigUint;
    use rand::thread_rng;

    use jester_maths::prime::PrimeField;
    use jester_maths::prime_fields;

    use crate::beaver_randomization_multiplication::BeaverRandomizationMultiplication;
    use crate::CliqueCommunicationScheme;
    use crate::protocols::{joint_unbounded_inversion, joint_unbounded_or};
    use crate::shamir_secret_sharing::ShamirSecretSharingScheme;

    prime_fields!(TestPrimeField("7", 10));

    /// A testing protocol that is carried out between two participants that do not randomize their inputs and do no
                        /// communicate as all values are deterministic anyways.
    struct TestProtocol {
        participant_id: usize,
    }

    impl ShamirSecretSharingScheme<TestPrimeField> for TestProtocol {}

    /// All shares are considered to be carried out on polynomials where all coefficients are zero. Thus
    /// communication is unnecessary and the secret is always the share
    impl CliqueCommunicationScheme<TestPrimeField, (usize, TestPrimeField)> for TestProtocol
        where TestProtocol: ShamirSecretSharingScheme<TestPrimeField> {
        fn reveal_shares(&mut self, share: (usize, TestPrimeField)) -> Pin<Box<dyn Future<Output=TestPrimeField> + Send>> {
            Box::pin(
                async move {
                    share.1
                }
            )
        }

        fn distribute_secret(&mut self, secret: TestPrimeField)
                             -> Pin<Box<dyn Future<Output=Vec<(usize, TestPrimeField)>> + Send>> {
            let id = self.participant_id;
            Box::pin(async move {
                vec![(id, secret.clone()), (id, secret)]
            })
        }
    }

    impl BeaverRandomizationMultiplication<TestPrimeField, (usize, TestPrimeField)> for TestProtocol {
        fn get_reconstruction_threshold(&self) -> usize {
            2
        }

        fn obtain_beaver_triples<'a>(&'a mut self, count: usize)
                                     -> Pin<Box<dyn Future<Output=Vec<((usize, TestPrimeField), (usize, TestPrimeField),
                                                                       (usize, TestPrimeField))>> + Send + 'a>> {
            Box::pin(
                async move {
                    repeat(((self.participant_id, TestPrimeField::one()),
                            (self.participant_id, TestPrimeField::one()),
                            (self.participant_id, TestPrimeField::one())))
                        .take(count)
                        .collect()
                }
            )
        }
    }

    #[test]
    fn test_protocol() {
        let mut protocol = TestProtocol { participant_id: 1 };
        let mut rng = thread_rng();

        block_on(
            async {
//                let shares = protocol.distribute_secret(TestPrimeField::one() + TestPrimeField::one()).await;
//                let inverse = joint_unbounded_inversion(&mut rng, &mut protocol, &shares).await;
//                let doubly_inverse = joint_unbounded_inversion(&mut rng, &mut protocol, &inverse).await;
//                let revealed = protocol.reveal_shares(doubly_inverse[0].clone()).await;
//
//                assert_eq!(TestPrimeField::one() + TestPrimeField::one(), revealed);
            }
        )
    }

    #[test]
    fn test_unbounded_or() {
        let mut protocol = TestProtocol { participant_id: 1 };

        block_on(async {
            let bits = vec![(1, TestPrimeField::one()), (1, TestPrimeField::one()), (1, TestPrimeField::zero())];

            let or = joint_unbounded_or(&mut thread_rng(), &mut protocol, &bits).await;
            let revealed = protocol.reveal_shares(or).await;
            assert_eq!(revealed, TestPrimeField::one());
        })
    }

    #[test]
    fn test_unbounded_inversion() {
        let mut protocol = TestProtocol { participant_id: 1 };
        let mut rng = thread_rng();

        block_on(async {
            let elements: Vec<(usize, TestPrimeField)> = vec![(1, BigUint::from(1u32).into()),
                                                              (1, BigUint::from(4u32).into()),
                                                              (1, BigUint::from(6u32).into())];
            let inverses = joint_unbounded_inversion(&mut rng, &mut protocol, &elements[..]).await;

            assert_eq!(inverses[0].1, TestPrimeField::from(BigUint::from(1u32)));
            assert_eq!(inverses[1].1, TestPrimeField::from(BigUint::from(2u32)));
            assert_eq!(inverses[2].1, TestPrimeField::from(BigUint::from(6u32)));
        })
    }
}
