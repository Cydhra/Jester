//! A crate containing traits and protocols for creating and using encrypted channels. Specific implementations of
//! encryption algorithms are not in scope of this crate, however a default implementation for the prime-field-based
//! Diffie-Hellman-key-exchange protocol is provided.

#![recursion_limit = "256"]

use rand::{CryptoRng, RngCore};

pub mod rsa;
pub mod diffie_hellman;

/// A trait representing a symmetrical encryption scheme. It offers methods for generating a random key (though one
/// might use a different scheme to generate a key) and encrypting and decrypting messages. No attempts are made to
/// secure the key, it is the caller's responsibility to properly protect the keys from attacker's attempts to
/// retrieve them from memory according to the caller's threat model.
pub trait SymmetricalEncryptionScheme {
    type Key;

    /// Randomly generate a random key from the key space of this algorithm. For this purpose, `rng` is assumed to be
    /// an instance of a well-seeded, cryptographically secure random number generator.
    fn generate_key<R>(rng: &mut R) -> Self::Key
    where
        R: RngCore + CryptoRng;

    /// Encrypt a message using the provided shared key. The cipher text will be returned inside a `Box`.
    fn encrypt_message(key: &Self::Key, message: &[u8]) -> Vec<u8>;

    /// Decrypt a cipher text using the provided shared key. The clear text will be returned inside a `Box`.
    fn decrypt_message(key: &Self::Key, message: &[u8]) -> Vec<u8>;
}

/// A trait representing an asymmetrical encryption scheme. It offers methods for generating a random key pair and
/// encrypting and decrypting messages. NNo attempts are made to secure the key, it is the caller's responsibility to
/// properly protect the keys from attacker's attempts to retrieve them from memory according to the caller's threat
/// model.
pub trait AsymmetricalEncryptionScheme {
    type PrivateKey;
    type PublicKey;

    /// Generate a key pair for this scheme by using a secure random generator. It is assumed that the generator is
    /// properly seeded.
    fn generate_keypair<R>(rng: &mut R) -> (Self::PrivateKey, Self::PublicKey)
    where
        R: RngCore + CryptoRng;

    /// Encrypt a message using the provided public key. The cipher text will be returned inside a `Box`.
    fn encrypt_message(key: &Self::PublicKey, message: &[u8]) -> Vec<u8>;

    /// Decrypt a cipher text using the provided private key. The clear text will be returned inside a `Box`.
    fn decrypt_message(key: &Self::PrivateKey, cipher: &[u8]) -> Vec<u8>;
}
