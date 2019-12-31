use std::marker::PhantomData;

use rand::{CryptoRng, RngCore};

use jester_encryption::diffie_hellman::DiffieHellmanKeyExchangeScheme;
use jester_encryption::SymmetricalEncryptionScheme;

/// A trait modelling a key-derivation-function as defined by the specification of the Double
/// Ratchet Algorithm by Trevor Perrin and Moxie Marlinspike.
///
/// #Associated Types
/// - `ChainKey` the derivation key type
/// - `Input` the data type of input to the derivation function
/// - `OutputKey` the output key type
pub trait KeyDerivationFunction {
    type ChainKey;
    type Input;
    type OutputKey;

    /// Consume the current `chain_key` and `input` to generate a new derivation key and an output key.
    fn derive_key(chain_key: Self::ChainKey, input: Self::Input) -> (Self::ChainKey, Self::OutputKey);
}

/// A symmetric key ratchet is a special case of an `KeyDerivationFunction` where the input is
/// constant. It is therefore not a parameter to the `derive_key_without_input` function.
pub trait ConstantInputKeyRatchet: KeyDerivationFunction {
    /// The constant input to the `KeyDerivationFunction`
    const INPUT: Self::Input;

    /// Consume the current `derivation_key` to generate a new chain key and an output key.
    fn derive_key_without_input(derivation_key: Self::ChainKey) -> (Self::ChainKey, Self::OutputKey) {
        Self::derive_key(derivation_key, Self::INPUT)
    }
}

/// A message sent between parties within the double-ratchet-algorithm. It contains the cipher, (except in
/// the very first message of the protocol initiator) and the public key to the diffie-hellman ratchet.
/// #Type Parameters
/// - `K` the diffie-hellman key type
/// - `C` the cipher text type
pub struct DoubleRatchetAlgorithmMessage<K, C> {
    public_key: K,
    message: Option<C>,
}

/// The three states the double ratchet protocol can be in. The `Initiator` is the party that is trying to establish
/// a communication. The `Addressee` is the party that is approached by the `Initiator` and both parties switch to
/// `Established`, as soon as both sending and receiving ratchets are initialized.
pub mod state {
    pub trait ProtocolState {}

    pub struct Initiator;

    pub struct Addressee;

    pub struct Established;

    impl ProtocolState for Initiator {}

    impl ProtocolState for Addressee {}

    impl ProtocolState for Established {}
}

///
/// #Type Parameters
/// - `DHScheme` diffie-hellman key exchange scheme for the DH-ratchet
/// - `EncryptionScheme` symmetrical encryption scheme for message encryption
/// - `RootKdf` root key derivation function
/// - `MessageKdf` sending and receiving key derivation function
/// - `DHKey` output key type of diffie-hellman function and input for root KDF
/// - `RootChainKey` root KDF key type
/// - `MessageChainKey` root KDF output key type and message KDFs' key type
/// - `MessageKey` encryption key type and output key of message KDFs
pub struct DoubleRatchetProtocol<
    DHScheme,
    EncryptionScheme,
    RootKdf,
    MessageKdf,
    DHKey,
    RootChainKey,
    MessageChainKey,
    MessageKey,
    State
> where
    DHScheme: DiffieHellmanKeyExchangeScheme<Key=DHKey>,
    EncryptionScheme: SymmetricalEncryptionScheme<Key=MessageKey>,
    RootKdf: KeyDerivationFunction<ChainKey=RootChainKey, Input=DHKey, OutputKey=MessageChainKey>,
    MessageKdf: ConstantInputKeyRatchet<ChainKey=MessageChainKey, OutputKey=MessageKey>,
    State: state::ProtocolState,
{
    state: PhantomData<State>,
    diffie_hellman_scheme: PhantomData<DHScheme>,
    encryption_scheme: PhantomData<EncryptionScheme>,
    root_chain: PhantomData<RootKdf>,
    message_chains: PhantomData<MessageKdf>,
    diffie_hellman_generator: DHKey,
    diffie_hellman_public_key: DHKey,
    root_chain_key: RootChainKey,
    sending_chain_key: Option<MessageChainKey>,
    receiving_chain_key: Option<MessageChainKey>,
}

impl<
    DHScheme,
    EncryptionScheme,
    RootKdf,
    MessageKdf,
    DHKey,
    RootChainKey,
    MessageChainKey,
    MessageKey,
> DoubleRatchetProtocol<
    DHScheme,
    EncryptionScheme,
    RootKdf,
    MessageKdf,
    DHKey,
    RootChainKey,
    MessageChainKey,
    MessageKey,
    state::Initiator,
> where
    DHScheme: DiffieHellmanKeyExchangeScheme<Key=DHKey>,
    EncryptionScheme: SymmetricalEncryptionScheme<Key=MessageKey>,
    RootKdf: KeyDerivationFunction<ChainKey=RootChainKey, Input=DHKey, OutputKey=MessageChainKey>,
    MessageKdf: ConstantInputKeyRatchet<ChainKey=MessageChainKey, OutputKey=MessageKey>,
{
    //noinspection RsFieldInitShorthand
    /// Initialize the double ratchet protocol for the sending side, that starts by sending the other side an empty
    /// message containing only a Diffie-Hellman public key.
    /// #Parameters
    /// - `rng` a cryptographically secure random number generator
    /// - `dh_generator` a pre-shared publicly known value of the Diffie-Hellman-Scheme key space used as generator
    /// - `initial_root_chain_key` the initial common root key of both parties, agreed upon OTR
    fn initialize_sending<R>(rng: &mut R, dh_generator: DHKey, initial_root_chain_key: RootChainKey) -> Self
        where R: RngCore + CryptoRng {
        // generate diffie-hellman public key
        let public_dh_key = DHScheme::generate_public_key(rng, &dh_generator);

        Self {
            state: PhantomData,
            diffie_hellman_scheme: PhantomData,
            encryption_scheme: PhantomData,
            root_chain: PhantomData,
            message_chains: PhantomData,
            diffie_hellman_generator: dh_generator,
            diffie_hellman_public_key: public_dh_key,
            root_chain_key: initial_root_chain_key,
            sending_chain_key: None,
            receiving_chain_key: None,
        }
    }
}

impl<
    DHScheme,
    EncryptionScheme,
    RootKdf,
    MessageKdf,
    DHKey,
    RootChainKey,
    MessageChainKey,
    MessageKey,
> DoubleRatchetProtocol<
    DHScheme,
    EncryptionScheme,
    RootKdf,
    MessageKdf,
    DHKey,
    RootChainKey,
    MessageChainKey,
    MessageKey,
    state::Addressee,
> where
    DHScheme: DiffieHellmanKeyExchangeScheme<Key=DHKey>,
    EncryptionScheme: SymmetricalEncryptionScheme<Key=MessageKey>,
    RootKdf: KeyDerivationFunction<ChainKey=RootChainKey, Input=DHKey, OutputKey=MessageChainKey>,
    MessageKdf: ConstantInputKeyRatchet<ChainKey=MessageChainKey, OutputKey=MessageKey>,
{
    //noinspection RsFieldInitShorthand
    /// Initialize the double ratchet protocol for the receiving side, that gets the public key of the other party
    /// and can respond with an encrypted message and its own public key, kicking off the ratchet protocol and the
    /// key chains.
    /// #Parameters
    /// - `rng` a cryptographically secure random number generator
    /// - `dh_generator` a pre-shared publicly known value of the Diffie-Hellman-Scheme key space used as generator
    /// - `received_dh_public_key` the other party's Diffie-Hellman public key, that kicks off the DH-Ratchet
    /// - `initial_root_chain_key` the initial common root key of both parties, agreed upon OTR
    fn initialize_receiving<R>(rng: &mut R, dh_generator: DHKey, received_dh_public_key: DHKey, initial_root_chain_key: RootChainKey) -> Self
        where R: RngCore + CryptoRng {
        // diffie hellman key exchange
        let generated_dh_public_key = DHScheme::generate_public_key(rng, &dh_generator);
        let dh_private_key = DHScheme::generate_shared_secret(&generated_dh_public_key, &received_dh_public_key);

        // root KDF initialization
        let (new_root_key, sending_key) = RootKdf::derive_key(initial_root_chain_key, dh_private_key);

        Self {
            state: PhantomData,
            diffie_hellman_scheme: PhantomData,
            encryption_scheme: PhantomData,
            root_chain: PhantomData,
            message_chains: PhantomData,
            diffie_hellman_generator: dh_generator,
            diffie_hellman_public_key: generated_dh_public_key,
            root_chain_key: new_root_key,
            sending_chain_key: Some(sending_key),
            receiving_chain_key: None,
        }
    }
}
