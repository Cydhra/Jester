/// An scheme to digitally sign messages using means of asymmetrical cryptography. Exposes a way to obtain a key pair
/// for use in the signature scheme.
pub trait SignatureScheme {
    /// Type of messages that can be signed by this algorithm
    type Message;

    /// Generated signature type
    type SignatureType;

    /// Public key type
    type PublicKey;

    /// Secret key type
    type PrivateKey;

    /// Generate an asymmetrical key pair.
    ///
    /// # Parameters
    /// - `rng` a cryptographically secure random number generator
    fn generate_key_pair<R>(rng: &mut R) -> (Self::PublicKey, Self::PrivateKey)
        where R: RngCore + CryptRng;

    /// Generate a signature from a message
    ///
    /// # Parameters
    /// - `rng` a cryptographically secure random number generator. The algorithm may not use this reference.
    /// - `message` the message to which a signature shall be generated
    /// - `private_key` the secret key used to obtain the signature
    fn sign<R>(rng: &mut R, message: Self::Message, private_key: Self::PrivateKey) -> Self::SignatureType
        where R: RngCore + CryptRng;

    /// Verify for a message if a given signature is valid. Returns true, if the given signature is a valid signature
    /// of the given message.
    ///
    /// # Parameters
    /// - `message` the message that is supposedly signed by the given signature
    /// - `signature` the signature in question
    /// - `public_key` the public key of the signer
    fn verify(message: Self::Message, signature: Self::SignatureType, public_key: Self::PublicKey) -> bool;
}