/// A trait modelling a key-derivation-function as defined by the specification of the Double
/// Ratchet Algorithm by Trevor Perrin and Moxie Marlinspike.
///
/// #Type Parameters
/// - `K` the derivation key type
/// - `I` the data type of input to the derivation function
/// - `O` the output key type
trait KeyDerivationFunction<K, I, O> {
    /// Consume the current `derivation_key` and `input` to generate a new derivation key and an
    /// output key.
    fn derive_key(derivation_key: K, input: I) -> (K, O);
}

/// A symmetric key ratchet is a special case of an `KeyDerivationFunction` where the input is
/// constant. It is therefore not a parameter to the `derive_key_inputless` function.
/// - `K` the derivation key type
/// - `I` the data type of input to the derivation function
/// - `O` the output key type
trait ConstantInputKeyRatchet<K, I, O>: KeyDerivationFunction<K, I, O> {
    /// The constant input to the `KeyDerivationFunction`
    const INPUT: I;

    /// Consume the current `derivation_key` to generate a new chain key and an output key.
    fn derive_key_inputless(derivation_key: K) -> (K, O) {
        Self::derive_key(derivation_key, Self::INPUT)
    }
}