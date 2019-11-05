use rand::{RngCore, CryptoRng};

pub mod rsa;

/// A trait representing an asymmetrical encryption scheme. It offers methods for generating a random key pair and
/// encrypting and decrypting messages. No attempts for securing the keys are made, it is the caller's responsibility
/// to properly protect the keys from attacker's attempts to retrieve them from memory according to the caller's
/// thread model.
pub trait AsymmetricalEncryptionScheme {
    type PrivateKey;
    type PublicKey;

    /// Generate a key pair for this scheme by using a secure random generator. It is assumed that the generator is
    /// properly seeded.
    fn generate_keypair<R>(rng: &mut R) -> (Self::PrivateKey, Self::PublicKey)
        where R: RngCore + CryptoRng;

    /// Encrypt a message using the given public key. The cipher text will be returned inside a `Box`.
    fn encrypt_message(key: &Self::PublicKey, message: &[u8]) -> Box<&[u8]>;

    /// Decrypt a cipher text using the given private key. The clear text will be returned inside a `Box`
    fn decrypt_message(key: &Self::PrivateKey, cipher: &[u8]) -> Box<&[u8]>;
}