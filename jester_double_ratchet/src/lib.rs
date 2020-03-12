use std::marker::PhantomData;

use rand::{CryptoRng, RngCore};

use crate::DecryptionException::OutOfOrderMessage;
use jester_encryption::diffie_hellman::DiffieHellmanKeyExchangeScheme;
use jester_encryption::SymmetricalEncryptionScheme;
use std::collections::HashMap;
use std::hash::Hash;

#[cfg(test)]
mod tests;

/// A trait modelling a key-derivation-function as defined by the specification of the Double
/// Ratchet Algorithm by Trevor Perrin and Moxie Marlinspike.
pub trait KeyDerivationFunction {
    /// The root key for the key derivation function. Each derivation generates a new root key, but it is not
    /// intended for use outside of the function.
    type ChainKey;

    /// The type of input data that is used to add further entropy to the KDF, providing break-in recovery.
    type Input;

    /// The type of keys derived by this KDF. Those are meant for outside use.
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
/// the very first message of the protocol initiator) and the public key to the diffie-hellman ratchet. For handling
/// of out-of-order messages the `message_number` and the `previous_chain_length` (both of the sending chain) are
/// sent within the header. They can be used by the recipient to detect missing messages.
/// # Type Parameters
/// - `K` the diffie-hellman key type
/// - `C` the cipher text type
pub struct DoubleRatchetAlgorithmMessage<K, C> {
    public_key: K,
    message_number: usize,
    previous_chain_length: usize,
    message: Option<C>,
}

/// The two states the double ratchet protocol can be in. The `Initiator` is the party that is trying to establish
/// a communication. The addressee can establish the protocol instantly, because it does not need an initialized
/// receiving chain until it gets another message by the `Initiator`, and that will contain any information necessary
/// to initialize it. The `Initiator`, however, has to wait for a response before it can switch to `Established`.
pub mod state {
    /// Common trait for all protocol states. It is just a marker trait.
    pub trait ProtocolState {}

    /// The protocol is in this state, until the addressee of the channel responds for the first time, sending its
    /// Diffie-Hellman public key
    pub struct Initiator;

    /// This state is reached when the protocol is fully established.
    pub struct Established;

    impl ProtocolState for Initiator {}

    impl ProtocolState for Established {}
}

/// Exceptions that can happen during protocol execution. Those are handled within the protocol, not by the library
/// user.
enum ProtocolException<DHPublicKey> {
    OutOfOrderMessage {
        public_key: DHPublicKey,
        message_number: usize,
    },
    IllegalMessageHeader {
        message: &'static str,
    },
}

/// Exceptions that can arise during decryption of messages. Some can be recovered, like simple out of order
/// handling, some end the protocol exchange.
pub enum DecryptionException {
    /// The message that was decrypted had an invalid header, rendering its decryption impossible
    InvalidMessageHeader {},

    /// The message was received out of order and that should be reflected to the user appropriately
    OutOfOrderMessage { decrypted_message: Box<[u8]> },

    /// The message header identified the message as an out-of-order message but no message key for this out-of-order
    /// arrival could be generated, rendering its decryption impossible
    UnknownMessageHeader {},
}

/// Double-Ratchet-Algorithm protocol state. It has some phantom markers for the used primitives and keeps track of
/// all state required during protocol execution-
///
/// # Type Parameters
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
    DHPublicKey,
    DHPrivateKey,
    DHSharedKey,
    RootChainKey,
    MessageChainKey,
    MessageKey,
    State,
> where
    DHScheme: DiffieHellmanKeyExchangeScheme<
        PublicKey = DHPublicKey,
        PrivateKey = DHPrivateKey,
        SharedKey = DHSharedKey,
    >,
    EncryptionScheme: SymmetricalEncryptionScheme<Key = MessageKey>,
    RootKdf: KeyDerivationFunction<
        ChainKey = RootChainKey,
        Input = DHSharedKey,
        OutputKey = MessageChainKey,
    >,
    MessageKdf: ConstantInputKeyRatchet<ChainKey = MessageChainKey, OutputKey = MessageKey>,
    DHPublicKey: Clone + Eq + Hash,
    State: state::ProtocolState,
{
    state: PhantomData<State>,
    diffie_hellman_scheme: PhantomData<DHScheme>,
    encryption_scheme: PhantomData<EncryptionScheme>,
    root_chain: PhantomData<RootKdf>,
    message_chains: PhantomData<MessageKdf>,
    diffie_hellman_generator: DHPublicKey,
    diffie_hellman_public_key: DHPublicKey,
    diffie_hellman_private_key: Option<DHPrivateKey>,
    diffie_hellman_received_key: Option<DHPublicKey>,
    root_chain_key: Option<RootChainKey>,
    sending_chain_key: Option<MessageChainKey>,
    receiving_chain_key: Option<MessageChainKey>,
    sending_chain_length: usize,
    receiving_chain_length: usize,
    previous_sending_chain_length: usize,
    previous_receiving_chain_length: usize,
    missed_messages: HashMap<(DHPublicKey, usize), MessageKey>,
}

impl<
        DHScheme,
        EncryptionScheme,
        RootKdf,
        MessageKdf,
        DHPublicKey,
        DHPrivateKey,
        DHSharedKey,
        RootChainKey,
        MessageChainKey,
        MessageKey,
    >
    DoubleRatchetProtocol<
        DHScheme,
        EncryptionScheme,
        RootKdf,
        MessageKdf,
        DHPublicKey,
        DHPrivateKey,
        DHSharedKey,
        RootChainKey,
        MessageChainKey,
        MessageKey,
        state::Initiator,
    >
where
    DHScheme: DiffieHellmanKeyExchangeScheme<
        PublicKey = DHPublicKey,
        PrivateKey = DHPrivateKey,
        SharedKey = DHSharedKey,
    >,
    EncryptionScheme: SymmetricalEncryptionScheme<Key = MessageKey>,
    RootKdf: KeyDerivationFunction<
        ChainKey = RootChainKey,
        Input = DHSharedKey,
        OutputKey = MessageChainKey,
    >,
    MessageKdf: ConstantInputKeyRatchet<ChainKey = MessageChainKey, OutputKey = MessageKey>,
    DHPublicKey: Clone + Eq + Hash,
{
    //noinspection RsFieldInitShorthand
    /// Initialize the double ratchet protocol for the sending side, that starts by sending the other side an empty
    /// message containing only a Diffie-Hellman public key. Also generates one initial message that must be sent to
    /// the other party, so the first Diffie-Hellman handshake can be established.
    /// # Parameters
    /// - `rng` a cryptographically secure random number generator
    /// - `dh_generator` a pre-shared publicly known value of the Diffie-Hellman-Scheme key space used as generator
    /// - `initial_root_chain_key` the initial common root key of both parties, agreed upon OTR
    pub fn initialize_sending<R>(
        rng: &mut R,
        dh_generator: DHPublicKey,
        initial_root_chain_key: RootChainKey,
    ) -> (Self, DoubleRatchetAlgorithmMessage<DHPublicKey, Box<[u8]>>)
    where
        R: RngCore + CryptoRng,
    {
        // generate diffie-hellman public key
        let (private_dh_key, public_dh_key) =
            DHScheme::generate_asymmetrical_key_pair(rng, &dh_generator);

        (
            Self {
                state: PhantomData,
                diffie_hellman_scheme: PhantomData,
                encryption_scheme: PhantomData,
                root_chain: PhantomData,
                message_chains: PhantomData,
                diffie_hellman_generator: dh_generator,
                diffie_hellman_public_key: public_dh_key.clone(),
                diffie_hellman_private_key: Some(private_dh_key),
                diffie_hellman_received_key: None,
                root_chain_key: Some(initial_root_chain_key),
                sending_chain_key: None,
                receiving_chain_key: None,
                sending_chain_length: 0,
                receiving_chain_length: 0,
                previous_sending_chain_length: 0,
                previous_receiving_chain_length: 0,
                missed_messages: HashMap::new(),
            },
            DoubleRatchetAlgorithmMessage {
                public_key: public_dh_key,
                message_number: 0,
                previous_chain_length: 0,
                message: None,
            },
        )
    }

    /// Decrypt the first message received from the addressee of the protocol exchange. It may contain user data,
    /// which is returned, alongside an updated protocol instance containing ready-to-use KDF chains.
    /// # Parameters
    /// - `message` a `DoubleRatchetAlgorithmMessage` that is decrypted and used to advance the protocol state
    pub fn decrypt_first_message<R>(
        mut self,
        rng: &mut R,
        message: DoubleRatchetAlgorithmMessage<DHPublicKey, Box<[u8]>>,
    ) -> (
        DoubleRatchetProtocol<
            DHScheme,
            EncryptionScheme,
            RootKdf,
            MessageKdf,
            DHPublicKey,
            DHPrivateKey,
            DHSharedKey,
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
        let generated_dh_shared_key = DHScheme::generate_shared_secret(
            &self.diffie_hellman_private_key.unwrap(),
            &message.public_key,
        );

        // update receiving chain
        let (updated_root_key, receiving_key) =
            RootKdf::derive_key(self.root_chain_key.take().unwrap(), generated_dh_shared_key);
        let (receiving_chain_key, message_key) =
            MessageKdf::derive_key_without_input(receiving_key);

        // decrypt message
        let clear_text = EncryptionScheme::decrypt_message(&message_key, &message.message.unwrap());

        // update sending chain
        let (new_dh_private_key, new_dh_public_key) =
            DHScheme::generate_asymmetrical_key_pair(rng, &self.diffie_hellman_generator);
        let new_dh_shared_key =
            DHScheme::generate_shared_secret(&new_dh_private_key, &message.public_key);
        let (updated_root_key, sending_key) =
            RootKdf::derive_key(updated_root_key, new_dh_shared_key);

        (
            DoubleRatchetProtocol {
                state: PhantomData,
                diffie_hellman_scheme: PhantomData,
                encryption_scheme: PhantomData,
                root_chain: PhantomData,
                message_chains: PhantomData,
                diffie_hellman_generator: self.diffie_hellman_generator,
                diffie_hellman_public_key: new_dh_public_key,
                diffie_hellman_private_key: Some(new_dh_private_key),
                diffie_hellman_received_key: Some(message.public_key),
                root_chain_key: Some(updated_root_key),
                sending_chain_key: Some(sending_key),
                receiving_chain_key: Some(receiving_chain_key),
                sending_chain_length: 0,
                receiving_chain_length: 1,
                previous_sending_chain_length: 0,
                previous_receiving_chain_length: 0,
                missed_messages: HashMap::new(),
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
        DHPublicKey,
        DHPrivateKey,
        DHSharedKey,
        RootChainKey,
        MessageChainKey,
        MessageKey,
    >
    DoubleRatchetProtocol<
        DHScheme,
        EncryptionScheme,
        RootKdf,
        MessageKdf,
        DHPublicKey,
        DHPrivateKey,
        DHSharedKey,
        RootChainKey,
        MessageChainKey,
        MessageKey,
        state::Established,
    >
where
    DHScheme: DiffieHellmanKeyExchangeScheme<
        PublicKey = DHPublicKey,
        PrivateKey = DHPrivateKey,
        SharedKey = DHSharedKey,
    >,
    EncryptionScheme: SymmetricalEncryptionScheme<Key = MessageKey>,
    RootKdf: KeyDerivationFunction<
        ChainKey = RootChainKey,
        Input = DHSharedKey,
        OutputKey = MessageChainKey,
    >,
    MessageKdf: ConstantInputKeyRatchet<ChainKey = MessageChainKey, OutputKey = MessageKey>,
    DHPublicKey: Clone + Eq + Hash,
{
    //noinspection RsFieldInitShorthand
    /// Initialize the double ratchet protocol for the receiving side, that gets the public key of the other party
    /// and can respond with an encrypted message and its own public key, kicking off the ratchet protocol and the
    /// key chains.
    /// # Parameters
    /// - `rng` a cryptographically secure random number generator
    /// - `dh_generator` a pre-shared publicly known value of the Diffie-Hellman-Scheme key space used as generator
    /// - `received_dh_public_key` the other party's Diffie-Hellman public key, that kicks off the DH-Ratchet
    /// - `initial_root_chain_key` the initial common root key of both parties, that was agreed upon off the record.
    pub fn initialize_receiving<R>(
        rng: &mut R,
        dh_generator: DHPublicKey,
        received_dh_public_key: DHPublicKey,
        initial_root_chain_key: RootChainKey,
    ) -> Self
    where
        R: RngCore + CryptoRng,
    {
        // diffie hellman key exchange
        let (generated_dh_private_key, generated_dh_public_key) =
            DHScheme::generate_asymmetrical_key_pair(rng, &dh_generator);
        let dh_shared_key =
            DHScheme::generate_shared_secret(&generated_dh_private_key, &received_dh_public_key);

        // root KDF initialization
        let (new_root_key, sending_key) =
            RootKdf::derive_key(initial_root_chain_key, dh_shared_key);

        Self {
            state: PhantomData,
            diffie_hellman_scheme: PhantomData,
            encryption_scheme: PhantomData,
            root_chain: PhantomData,
            message_chains: PhantomData,
            diffie_hellman_generator: dh_generator,
            diffie_hellman_public_key: generated_dh_public_key,
            diffie_hellman_private_key: Some(generated_dh_private_key),
            diffie_hellman_received_key: Some(received_dh_public_key),
            root_chain_key: Some(new_root_key),
            sending_chain_key: Some(sending_key),
            receiving_chain_key: None,
            sending_chain_length: 0,
            receiving_chain_length: 0,
            previous_sending_chain_length: 0,
            previous_receiving_chain_length: 0,
            missed_messages: HashMap::new(),
        }
    }

    /// Send a message to the other protocol party. This must be done at least once to allow the other party to
    /// establish their ratchets.
    /// # Parameters
    /// - `rng` a cryptographically secure random number generator
    /// - `message` the message clear text that gets encrypted and sent
    pub fn encrypt_message(
        &mut self,
        message: &[u8],
    ) -> DoubleRatchetAlgorithmMessage<DHPublicKey, Box<[u8]>> {
        // update sending ratchet
        let (updated_sending_chain_key, message_key) =
            MessageKdf::derive_key_without_input(self.sending_chain_key.take().unwrap());
        self.sending_chain_key = Some(updated_sending_chain_key);

        let current_message_number = self.sending_chain_length;

        // update statistics
        self.sending_chain_length += 1;

        // encrypt message
        let cipher_text = EncryptionScheme::encrypt_message(&message_key, message);

        DoubleRatchetAlgorithmMessage {
            public_key: self.diffie_hellman_public_key.clone(),
            message_number: current_message_number,
            previous_chain_length: self.previous_sending_chain_length,
            message: Some(cipher_text),
        }
    }

    /// Decrypt a message from the other party that has actual user content. It will fully establish the
    /// protocol by initializing the receiving chain.
    pub fn decrypt_message<R>(
        &mut self,
        rng: &mut R,
        message: DoubleRatchetAlgorithmMessage<DHPublicKey, Box<[u8]>>,
    ) -> Result<Box<[u8]>, DecryptionException>
    where
        R: RngCore + CryptoRng,
    {
        let (mut current_chain_missed_messages, mut next_chain_missed_messages) =
            match detect_missing_messages(self, &message) {
                Ok(v) => v,
                Err(ProtocolException::IllegalMessageHeader { message }) => {
                    return Err(DecryptionException::InvalidMessageHeader {})
                }
                Err(ProtocolException::OutOfOrderMessage {
                    public_key,
                    message_number,
                }) => {
                    let dictionary_key = (public_key, message_number);
                    if !self.missed_messages.contains_key(&dictionary_key) {
                        return Err(UnknownMessage);
                    }

                    let message_key = self.missed_messages.remove(&dictionary_key).unwrap();
                    let decrypted_message =
                        EncryptionScheme::decrypt_message(&message_key, &message.message.unwrap());
                    return Err(OutOfOrderMessage { decrypted_message });
                }
            };

        // insert missing message keys into missed_messages dictionary
        while current_chain_missed_messages > 0 {
            let (new_chain_key, output_key) =
                MessageKdf::derive_key_without_input(self.receiving_chain_key.take().unwrap());
            self.receiving_chain_key = Some(new_chain_key);
            self.receiving_chain_length += 1;
            self.missed_messages.insert(
                (
                    self.diffie_hellman_received_key.clone().unwrap(),
                    self.receiving_chain_length,
                ),
                output_key,
            );
            current_chain_missed_messages -= 1;
        }

        // if this message contains a new public key
        let message_key = if self.diffie_hellman_received_key.is_none()
            || !message
                .public_key
                .eq(self.diffie_hellman_received_key.as_ref().unwrap())
        {
            // update diffie-hellman-ratchet
            let generated_dh_private_key = DHScheme::generate_shared_secret(
                &self.diffie_hellman_private_key.take().unwrap(),
                &message.public_key,
            );

            // update receiving chain
            let (updated_root_key, mut receiving_chain_key) = RootKdf::derive_key(
                self.root_chain_key.take().unwrap(),
                generated_dh_private_key,
            );
            self.receiving_chain_length = 0;

            // if messages of this new chain were missed:
            while next_chain_missed_messages > 0 {
                self.receiving_chain_length += 1;
                let (updated_receiving_chain_key, message_key) =
                    MessageKdf::derive_key_without_input(receiving_chain_key);
                receiving_chain_key = updated_receiving_chain_key;
                self.missed_messages.insert(
                    (message.public_key.clone(), self.receiving_chain_length),
                    message_key,
                );
                next_chain_missed_messages -= 1;
            }

            let (updated_receiving_chain_key, message_key) =
                MessageKdf::derive_key_without_input(receiving_chain_key);
            self.receiving_chain_key = Some(updated_receiving_chain_key);

            // update sending chain
            let (new_dh_private_key, new_dh_public_key) =
                DHScheme::generate_asymmetrical_key_pair(rng, &self.diffie_hellman_generator);
            let new_dh_shared_key =
                DHScheme::generate_shared_secret(&new_dh_private_key, &message.public_key);
            let (updated_root_key, sending_chain_key) =
                RootKdf::derive_key(updated_root_key, new_dh_shared_key);
            self.sending_chain_key = Some(sending_chain_key);

            // update dh keys
            self.diffie_hellman_public_key = new_dh_public_key;
            self.diffie_hellman_private_key = Some(new_dh_private_key);

            // update root chain
            self.root_chain_key = Some(updated_root_key);

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
        Ok(EncryptionScheme::decrypt_message(
            &message_key,
            &message.message.unwrap(),
        ))
    }
}

/// Using an incoming message and the current protocol state, detect, whether any messages have been missed. This is
/// important for multiple reasons: the message keys of the missed messages must be stored, in case they arrive
/// out-of-order. Furthermore, the message chain must be advanced sufficiently, so that the same key for decryption is
/// used that was used for encryption.
/// # Parameters
/// - `protocol` an immutable reference to the current protocol state. no changes to the message chains are actually
/// performed
/// - `message` a reference to the latest message
///
/// # Returns
/// A result of a tuple is returned, that contains the missed messages of the current receiving chain in its first
/// parameter, and the missed messages of the next receiving chain, if a new one would be created by this message.
/// Both parameters are simply zero, if no messages are missed. The result returns a `ProtocolException` if a message
/// is received out-of-order or has an invalid message header.
fn detect_missing_messages<
    DHScheme,
    EncryptionScheme,
    RootKdf,
    MessageKdf,
    DHPublicKey,
    DHPrivateKey,
    DHSharedKey,
    RootChainKey,
    MessageChainKey,
    MessageKey,
    State,
>(
    protocol: &DoubleRatchetProtocol<
        DHScheme,
        EncryptionScheme,
        RootKdf,
        MessageKdf,
        DHPublicKey,
        DHPrivateKey,
        DHSharedKey,
        RootChainKey,
        MessageChainKey,
        MessageKey,
        State,
    >,
    message: &DoubleRatchetAlgorithmMessage<DHPublicKey, Box<[u8]>>,
) -> Result<(usize, usize), ProtocolException<DHPublicKey>>
where
    DHScheme: DiffieHellmanKeyExchangeScheme<
        PublicKey = DHPublicKey,
        PrivateKey = DHPrivateKey,
        SharedKey = DHSharedKey,
    >,
    EncryptionScheme: SymmetricalEncryptionScheme<Key = MessageKey>,
    RootKdf: KeyDerivationFunction<
        ChainKey = RootChainKey,
        Input = DHSharedKey,
        OutputKey = MessageChainKey,
    >,
    MessageKdf: ConstantInputKeyRatchet<ChainKey = MessageChainKey, OutputKey = MessageKey>,
    DHPublicKey: Clone + Eq + Hash,
    State: state::ProtocolState,
{
    if protocol.diffie_hellman_received_key.is_none() {
        // this is the first ever message received
        // the message number tells how many messages came before that were missed
        Ok((0, message.message_number))
    } else if message
        .public_key
        .eq(protocol.diffie_hellman_received_key.as_ref().unwrap())
    {
        if message.message_number >= protocol.receiving_chain_length {
            // this message belongs to the current chain, return the difference to the receiving chain length
            return Ok((message.message_number - protocol.receiving_chain_length, 0));
        } else {
            // this message is received out of order and must be handled specially
            Err(ProtocolException::OutOfOrderMessage {
                public_key: message.public_key.clone(),
                message_number: message.message_number,
            })
        }
    } else {
        if message.previous_chain_length >= protocol.receiving_chain_length {
            // this message starts a new chain
            // return the number of missed messages from the currently active chain and the number of messages missed
            // in the new chain
            Ok((
                message.previous_chain_length - protocol.receiving_chain_length,
                message.message_number,
            ))
        } else {
            // the message reports less messages sent than received. Clearly something is wrong here!
            Err(ProtocolException::IllegalMessageHeader {
                message: "the message reports less messages sent in the last chain, than messages were received."
            })
        }
    }
}
