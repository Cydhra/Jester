/// A trait modelling a key-derivation-function as defined by the specification of the Double
/// Ratchet Algorithm by Trevor Perrin and Moxie Marlinspike.
///
/// #Associated Types
/// - `ChainKey` the derivation key type
/// - `Input` the data type of input to the derivation function
/// - `OutputKey` the output key type
trait KeyDerivationFunction {
    type ChainKey;
    type Input;
    type OutputKey;

    /// Consume the current `chain_key` and `input` to generate a new derivation key and an output key.
    fn derive_key(chain_key: Self::ChainKey, input: Self::Input) -> (Self::ChainKey, Self::OutputKey);
}

/// A symmetric key ratchet is a special case of an `KeyDerivationFunction` where the input is
/// constant. It is therefore not a parameter to the `derive_key_without_input` function.
trait ConstantInputKeyRatchet: KeyDerivationFunction {
    /// The constant input to the `KeyDerivationFunction`
    const INPUT: Self::Input;

    /// Consume the current `derivation_key` to generate a new chain key and an output key.
    fn derive_key_without_input(derivation_key: Self::ChainKey) -> (Self::ChainKey, Self::OutputKey) {
        Self::derive_key(derivation_key, Self::INPUT)
    }
}