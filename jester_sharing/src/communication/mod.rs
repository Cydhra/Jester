//! This module defines traits modeling client communication during protocol evaluation. Different protocols require
//! different models of communication. This module does not provide implementations, as network implementation is out
//! of this crate's scope.

use crate::ThresholdSecretSharingScheme;
use futures::Future;
use std::pin::Pin;

/// A trait marking a scheme where `N` party members communicate to each other via a broadcast or a peer to peer network
/// thus every client knows every other client. Secrets can be revealed by sending the own share to all participants
/// and new secrets can be distributed by sending one share of it to all members
pub trait CliqueCommunicationScheme<T, S>: ThresholdSecretSharingScheme<T, S> {
    /// All parties reveal their shares of a secret so it can be reconstructed as soon as all shares were
    /// received.
    ///
    /// # Returns
    /// Returns a future on the reconstructed secret
    fn reveal_shares(&mut self, share: S) -> Pin<Box<dyn Future<Output = T> + Send>>;

    /// A secret is created with exactly `N` shares and one is sent to each participant. Shares of other participants
    /// are collected and returned.
    ///
    /// # Parameters
    /// - `secret` a secret compatible to a `ThresholdSecretSharingScheme` that shall be shared
    ///
    /// # Returns
    /// Returns a future on the shares that other participants sent in return
    fn distribute_secret(&mut self, secret: T) -> Pin<Box<dyn Future<Output = Vec<S>> + Send>>;
}
