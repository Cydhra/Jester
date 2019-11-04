use std::future::Future;
use std::pin::Pin;

use num::traits::NumOps;

use jester_algebra::PrimeField;

use crate::{CliqueCommunicationScheme, LinearSharingScheme, MultiplicationScheme, ParallelMultiplicationScheme, ThresholdSecretSharingScheme};

/// A trait marking a special instance of a parallel two-stage multiplication scheme using Donald Beaver's
/// rerandomization technique.
pub trait BeaverRandomizationMultiplication<T, S>: ParallelMultiplicationScheme<T, S>
    where T: PrimeField,
          S: NumOps<T, S>,
          Self: ThresholdSecretSharingScheme<T, S> {
    /// Get the reconstruction threshold of the threshold secret sharing scheme used beneath this scheme.
    fn get_reconstruction_threshold(&self) -> usize;

    /// Obtain random triples of shares `([a], [b], [c])` where `c = a * b` holds. Every participant must use shares
    /// of the same triple during the same multiplication. This function cannot be called in parallel.
    fn obtain_beaver_triples<'a>(&'a mut self, count: usize) -> Pin<Box<dyn Future<Output=(S, S, S)> + Send + 'a>>;
}

impl<P, T, S> ParallelMultiplicationScheme<T, S> for P
    where T: PrimeField + 'static,
          S: NumOps<T, S> + Clone + Send + Sync + 'static,
          P: BeaverRandomizationMultiplication<T, S> + ThresholdSecretSharingScheme<T, S> + LinearSharingScheme<S> +
          CliqueCommunicationScheme<T, S> + MultiplicationScheme<T, S> {
    fn parallel_multiply<'a>(&'a mut self, pairs: &[(S, S)]) -> Pin<Box<dyn Future<Output=Vec<S>> + Send + 'a>> {
        let _pairs_clone = pairs.iter().map(|(l, r)| (l.clone(), r.clone())).collect::<Vec<(S, S)>>();

        unimplemented!()
    }
}

impl<P, T, S> MultiplicationScheme<T, S> for P
    where T: PrimeField + Send,
          S: NumOps<T, S> + NumOps + Clone + Send + Sync + 'static,
          P: BeaverRandomizationMultiplication<T, S> + ThresholdSecretSharingScheme<T, S> + LinearSharingScheme<S> +
          CliqueCommunicationScheme<T, S> + Send {
    fn multiply<'a>(&'a mut self, lhs: &S, rhs: &S) -> Pin<Box<dyn Future<Output=S> + Send + 'a>> {
        let lhs = lhs.clone();
        let rhs = rhs.clone();

        Box::pin(
            async move {
                let (a, b, c) = self.obtain_beaver_triples(1).await;

                let epsilon_share = Self::sub_shares(&lhs, &a);
                let delta_share = Self::sub_shares(&rhs, &b);

                let delta = self.reveal_shares(delta_share);
                let epsilon = self.reveal_shares(epsilon_share);

                let delta = delta.await;
                let epsilon = epsilon.await;

                c + b * epsilon.clone() + a * delta.clone() - epsilon.clone() * delta.clone()
            }
        )
    }
}