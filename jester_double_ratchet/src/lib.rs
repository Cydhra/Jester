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
    fn derive_key(
        chain_key: Self::ChainKey,
        input: Self::Input,
    ) -> (Self::ChainKey, Self::OutputKey);
}

/// A symmetric key ratchet is a special case of an `KeyDerivationFunction` where the input is
/// constant. It is therefore not a parameter to the `derive_key_without_input` function.
pub trait ConstantInputKeyRatchet: KeyDerivationFunction {
    /// The constant input to the `KeyDerivationFunction`
    const INPUT: Self::Input;

    /// Consume the current `derivation_key` to generate a new chain key and an output key.
    fn derive_key_without_input(
        derivation_key: Self::ChainKey,
    ) -> (Self::ChainKey, Self::OutputKey) {
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
/// a communication. The addressee can establish the protocol instantly, because it does not need an initialized
/// receiving chain until it gets another message by the `Initiator`, and that will contain any information necessary
/// to initialize it. The `Initiator`, however, has to wait for a response before it can switch to `Established`.
pub mod state {
    pub trait ProtocolState {}

    pub struct Initiator;

    pub struct Established;

    impl ProtocolState for Initiator {}

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
    State,
> where
    DHScheme: DiffieHellmanKeyExchangeScheme<Key = DHKey>,
    EncryptionScheme: SymmetricalEncryptionScheme<Key = MessageKey>,
    RootKdf:
        KeyDerivationFunction<ChainKey = RootChainKey, Input = DHKey, OutputKey = MessageChainKey>,
    MessageKdf: ConstantInputKeyRatchet<ChainKey = MessageChainKey, OutputKey = MessageKey>,
    DHKey: Clone + PartialEq,
    RootChainKey: Clone,
    State: state::ProtocolState,
{
    state: PhantomData<State>,
    diffie_hellman_scheme: PhantomData<DHScheme>,
    encryption_scheme: PhantomData<EncryptionScheme>,
    root_chain: PhantomData<RootKdf>,
    message_chains: PhantomData<MessageKdf>,
    diffie_hellman_generator: DHKey,
    diffie_hellman_public_key: DHKey,
    diffie_hellman_private_key: Option<DHKey>,
    diffie_hellman_received_key: Option<DHKey>,
    root_chain_key: RootChainKey,
    sending_chain_key: Option<MessageChainKey>,
    receiving_chain_key: Option<MessageChainKey>,
    sending_chain_length: usize,
    receiving_chain_length: usize,
    previous_sending_chain_length: usize,
    previous_receiving_chain_length: usize,
    // TODO: dictionary of skipped messages
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
    >
    DoubleRatchetProtocol<
        DHScheme,
        EncryptionScheme,
        RootKdf,
        MessageKdf,
        DHKey,
        RootChainKey,
        MessageChainKey,
        MessageKey,
        state::Initiator,
    >
where
    DHScheme: DiffieHellmanKeyExchangeScheme<Key = DHKey>,
    EncryptionScheme: SymmetricalEncryptionScheme<Key = MessageKey>,
    RootKdf:
        KeyDerivationFunction<ChainKey = RootChainKey, Input = DHKey, OutputKey = MessageChainKey>,
    MessageKdf: ConstantInputKeyRatchet<ChainKey = MessageChainKey, OutputKey = MessageKey>,
    RootChainKey: Clone,
    DHKey: Clone + PartialEq,
{
    //noinspection RsFieldInitShorthand
    /// Initialize the double ratchet protocol for the sending side, that starts by sending the other side an empty
    /// message containing only a Diffie-Hellman public key. Also generates one initial message that must be sent to
    /// the other party, so the first Diffie-Hellman handshake can be established.
    /// #Parameters
    /// - `rng` a cryptographically secure random number generator
    /// - `dh_generator` a pre-shared publicly known value of the Diffie-Hellman-Scheme key space used as generator
    /// - `initial_root_chain_key` the initial common root key of both parties, agreed upon OTR
    pub fn initialize_sending<R>(
        rng: &mut R,
        dh_generator: DHKey,
        initial_root_chain_key: RootChainKey,
    ) -> (Self, DoubleRatchetAlgorithmMessage<DHKey, Box<[u8]>>)
    where
        R: RngCore + CryptoRng,
    {
        // generate diffie-hellman public key
        let public_dh_key = DHScheme::generate_public_key(rng, &dh_generator);

        (
            Self {
                state: PhantomData,
                diffie_hellman_scheme: PhantomData,
                encryption_scheme: PhantomData,
                root_chain: PhantomData,
                message_chains: PhantomData,
                diffie_hellman_generator: dh_generator,
                diffie_hellman_public_key: public_dh_key.clone(),
                diffie_hellman_private_key: None,
                diffie_hellman_received_key: None,
                root_chain_key: initial_root_chain_key,
                sending_chain_key: None,
                receiving_chain_key: None,
                sending_chain_length: 0,
                receiving_chain_length: 0,
                previous_sending_chain_length: 0,
                previous_receiving_chain_length: 0,
            },
            DoubleRatchetAlgorithmMessage {
                public_key: public_dh_key,
                message: None,
            },
        )
    }

    /// Decrypt the first message received from the addressee of the protocol exchange. It may contain user data,
    /// which is returned, alongside an updated protocol instance containing ready-to-use KDF chains.
    /// #Parameters
    /// - `message` a `DoubleRatchetAlgorithmMessage` that is decrypted and used to advance the protocol state
    pub fn decrypt_first_message<R>(
        self,
        rng: &mut R,
        message: DoubleRatchetAlgorithmMessage<DHKey, Box<[u8]>>,
    ) -> (
        DoubleRatchetProtocol<
            DHScheme,
            EncryptionScheme,
            RootKdf,
            MessageKdf,
            DHKey,
            RootChainKey,
            MessageChainKey,
            MessageKey,
            state::Established,
        >,
        Box<[u8]>,
    )
    where
        R: RngCore + CryptoRng,
    {
        // update diffie-hellman-ratchet
        let generated_dh_private_key =
            DHScheme::generate_shared_secret(&self.diffie_hellman_public_key, &message.public_key);

        // update receiving chain
        let (updated_root_key, receiving_key) =
            RootKdf::derive_key(self.root_chain_key, generated_dh_private_key);
        let (receiving_chain_key, message_key) =
            MessageKdf::derive_key_without_input(receiving_key);

        // decrypt message
        let clear_text = EncryptionScheme::decrypt_message(&message_key, &message.message.unwrap());

        // update sending chain
        let new_dh_public_key = DHScheme::generate_public_key(rng, &self.diffie_hellman_generator);
        let new_dh_private_key =
            DHScheme::generate_shared_secret(&new_dh_public_key, &message.public_key);
        let (updated_root_key, sending_key) =
            RootKdf::derive_key(updated_root_key, new_dh_private_key.clone());

        (
            DoubleRatchetProtocol {
                state: PhantomData,
                diffie_hellman_scheme: PhantomData,
                encryption_scheme: PhantomData,
                root_chain: PhantomData,
                message_chains: PhantomData,
                diffie_hellman_generator: self.diffie_hellman_generator,
                diffie_hellman_public_key: self.diffie_hellman_public_key,
                diffie_hellman_private_key: Some(new_dh_private_key),
                diffie_hellman_received_key: Some(message.public_key),
                root_chain_key: updated_root_key,
                sending_chain_key: Some(sending_key),
                receiving_chain_key: Some(receiving_chain_key),
                sending_chain_length: 0,
                receiving_chain_length: 1,
                previous_sending_chain_length: 0,
                previous_receiving_chain_length: 0,
            },
            clear_text,
        )
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
    >
    DoubleRatchetProtocol<
        DHScheme,
        EncryptionScheme,
        RootKdf,
        MessageKdf,
        DHKey,
        RootChainKey,
        MessageChainKey,
        MessageKey,
        state::Established,
    >
where
    DHScheme: DiffieHellmanKeyExchangeScheme<Key = DHKey>,
    EncryptionScheme: SymmetricalEncryptionScheme<Key = MessageKey>,
    RootKdf:
        KeyDerivationFunction<ChainKey = RootChainKey, Input = DHKey, OutputKey = MessageChainKey>,
    MessageKdf: ConstantInputKeyRatchet<ChainKey = MessageChainKey, OutputKey = MessageKey>,
    RootChainKey: Clone,
    DHKey: Clone + PartialEq,
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
    pub fn initialize_receiving<R>(
        rng: &mut R,
        dh_generator: DHKey,
        received_dh_public_key: DHKey,
        initial_root_chain_key: RootChainKey,
    ) -> Self
    where
        R: RngCore + CryptoRng,
    {
        // diffie hellman key exchange
        let generated_dh_public_key = DHScheme::generate_public_key(rng, &dh_generator);
        let dh_private_key =
            DHScheme::generate_shared_secret(&generated_dh_public_key, &received_dh_public_key);

        // root KDF initialization
        let (new_root_key, sending_key) =
            RootKdf::derive_key(initial_root_chain_key, dh_private_key.clone());

        Self {
            state: PhantomData,
            diffie_hellman_scheme: PhantomData,
            encryption_scheme: PhantomData,
            root_chain: PhantomData,
            message_chains: PhantomData,
            diffie_hellman_generator: dh_generator,
            diffie_hellman_public_key: generated_dh_public_key,
            diffie_hellman_private_key: Some(dh_private_key),
            diffie_hellman_received_key: Some(received_dh_public_key),
            root_chain_key: new_root_key,
            sending_chain_key: Some(sending_key),
            receiving_chain_key: None,
            sending_chain_length: 0,
            receiving_chain_length: 0,
            previous_sending_chain_length: 0,
            previous_receiving_chain_length: 0,
        }
    }

    /// Send a message to the other protocol party. This must be done at least once to allow the other party to
    /// establish their ratchets.
    /// #Parameters
    /// - `rng` a cryptographically secure random number generator
    /// - `message` the message clear text that gets encrypted and sent
    pub fn encrypt_message(
        &mut self,
        message: &[u8],
    ) -> DoubleRatchetAlgorithmMessage<DHKey, Box<[u8]>> {
        // update sending ratchet
        let (updated_sending_chain_key, message_key) =
            MessageKdf::derive_key_without_input(self.sending_chain_key.take().unwrap());
        self.sending_chain_key = Some(updated_sending_chain_key);

        // update statistics
        self.sending_chain_length += 1;

        // encrypt message
        let cipher_text = EncryptionScheme::encrypt_message(&message_key, message);

        DoubleRatchetAlgorithmMessage {
            public_key: self.diffie_hellman_public_key.clone(),
            message: Some(cipher_text),
        }
    }

    /// Decrypt a message from the other party that has actual user content. It will fully establish the
    /// protocol by initializing the receiving chain.
    pub fn decrypt_message<R>(
        &mut self,
        rng: &mut R,
        message: DoubleRatchetAlgorithmMessage<DHKey, Box<[u8]>>,
    ) -> Box<[u8]>
    where
        R: RngCore + CryptoRng,
    {
        // if this message contains a new public key
        let message_key = if self.diffie_hellman_received_key.is_none()
            || !message
                .public_key
                .eq(self.diffie_hellman_received_key.as_ref().unwrap())
        {
            // update diffie-hellman-ratchet
            let generated_dh_private_key = DHScheme::generate_shared_secret(
                &self.diffie_hellman_public_key,
                &message.public_key,
            );

            // update receiving chain
            let (updated_root_key, receiving_chain_key) =
                RootKdf::derive_key(self.root_chain_key.clone(), generated_dh_private_key);
            let (updated_receiving_chain_key, message_key) =
                MessageKdf::derive_key_without_input(receiving_chain_key);
            self.receiving_chain_key = Some(updated_receiving_chain_key);

            // update sending chain
            let new_dh_public_key =
                DHScheme::generate_public_key(rng, &self.diffie_hellman_generator);
            let new_dh_private_key =
                DHScheme::generate_shared_secret(&new_dh_public_key, &message.public_key);
            let (updated_root_key, sending_chain_key) =
                RootKdf::derive_key(updated_root_key, new_dh_private_key.clone());
            self.sending_chain_key = Some(sending_chain_key);

            // update root chain
            self.root_chain_key = updated_root_key;

            // update stats
            self.previous_receiving_chain_length = self.receiving_chain_length;
            self.previous_sending_chain_length = self.sending_chain_length;
            self.sending_chain_length = 0;
            self.receiving_chain_length = 1;

            message_key
        } else {
            // if this message does contain a known public key
            // update receiving chain
            let (updated_receiving_chain_key, message_key) =
                MessageKdf::derive_key_without_input(self.receiving_chain_key.take().unwrap());
            self.receiving_chain_key = Some(updated_receiving_chain_key);

            // update stats
            self.receiving_chain_length += 1;

            message_key
        };

        // decrypt message
        EncryptionScheme::decrypt_message(&message_key, &message.message.unwrap())
    }
}
