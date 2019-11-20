use std::future::Future;
use std::pin::Pin;

use futures::{future::join_all, join};

use jester_algebra::prime::PrimeField;

use crate::{CliqueCommunicationScheme, LinearSharingScheme, MultiplicationScheme, ParallelMultiplicationScheme, ThresholdSecretSharingScheme};

/// A trait marking a special instance of a parallel two-stage multiplication scheme using Donald Beaver's
/// rerandomization technique.
pub trait BeaverRandomizationMultiplication<T, S>: ParallelMultiplicationScheme<T, S>
    where T: PrimeField,
          Self: ThresholdSecretSharingScheme<T, S> {
    /// Get the reconstruction threshold of the threshold secret sharing scheme used beneath this scheme.
    fn get_reconstruction_threshold(&self) -> usize;

    /// Obtain random triples of shares `([a], [b], [c])` where `c = a * b` holds. Every participant must use shares
    /// of the same triple during the same multiplication. This function cannot be called in parallel.
    fn obtain_beaver_triples<'a>(&'a mut self, count: usize) -> Pin<Box<dyn Future<Output=Vec<(S, S, S)>> + Send + 'a>>;
}

impl<P, T, S> ParallelMultiplicationScheme<T, S> for P
    where T: PrimeField + Send + 'static,
          S: Clone + Send + Sync + 'static,
          P: BeaverRandomizationMultiplication<T, S> + ThresholdSecretSharingScheme<T, S> + LinearSharingScheme<T, S> +
          CliqueCommunicationScheme<T, S> + MultiplicationScheme<T, S> + Send {
    fn parallel_multiply<'a>(&'a mut self, pairs: &[(S, S)]) -> Pin<Box<dyn Future<Output=Vec<S>> + Send + 'a>> {
        let pairs_clone: Vec<_> = pairs.iter().cloned().collect();

        Box::pin(
            async move {
                let beaver_triples = self.obtain_beaver_triples(pairs_clone.len()).await;

                let multiplications = pairs_clone
                    .into_iter()
                    .zip(beaver_triples.clone())
                    .map(|((lhs, rhs), (a, b, _))| {
                        let epsilon_share = Self::sub_shares(&lhs, &a);
                        let delta_share = Self::sub_shares(&rhs, &b);

                        let delta = self.reveal_shares(delta_share);
                        let epsilon = self.reveal_shares(epsilon_share);

                        async {
                            join!(delta, epsilon)
                        }
                    })
                    .collect::<Vec<_>>();

                join_all(multiplications).await
                    .into_iter()
                    .zip(beaver_triples)
                    .map(|((delta, epsilon), (a, b, c))|
                        Self::sub_scalar(
                            &Self::add_shares(
                                &Self::add_shares(&c, &Self::multiply_scalar(&b, &epsilon)),
                                &Self::multiply_scalar(&a, &delta),
                            ),
                            &(epsilon.clone() * delta.clone()),
                        )
                    )
                    .collect()
            }
        )
    }
}

impl<P, T, S> MultiplicationScheme<T, S> for P
    where T: PrimeField + Send,
          S: Clone + Send + Sync + 'static,
          P: BeaverRandomizationMultiplication<T, S> + ThresholdSecretSharingScheme<T, S> + LinearSharingScheme<T, S> +
          CliqueCommunicationScheme<T, S> + Send {
    fn multiply<'a>(&'a mut self, lhs: &S, rhs: &S) -> Pin<Box<dyn Future<Output=S> + Send + 'a>> {
        let lhs = lhs.clone();
        let rhs = rhs.clone();

        Box::pin(
            async move {
                let (a, b, c) = self.obtain_beaver_triples(1).await.pop().unwrap();

                let epsilon_share = Self::sub_shares(&lhs, &a);
                let delta_share = Self::sub_shares(&rhs, &b);

                let (delta, epsilon) = join!(
                    self.reveal_shares(delta_share),
                    self.reveal_shares(epsilon_share)
                );

                Self::sub_scalar(
                    &Self::add_shares(
                        &Self::add_shares(&c, &Self::multiply_scalar(&b, &epsilon)),
                        &Self::multiply_scalar(&a, &delta),
                    ),
                    &(epsilon.clone() * delta.clone()),
                )
            }
        )
    }
}