//! This module contains a trait for a Diffie-Hellman-key-exchange protocol and a default implementation for all
//! implementors of `PrimeField` as defined in `jester_maths`.

use rand::{CryptoRng, RngCore};

use jester_maths::prime::PrimeField;

/// A trait representing the symmetric key exchange scheme proposed by Diffie, Hellman and Merkle. Each party
/// generates an asymmetrical key pair using `generate_asymmetrical_key_pair` and then exchanges public keys. Then
/// all parties can generate the shared key using `generate_shared_secret`. If more than two parties are involved,
/// multiple rounds of sharing are required. The trait defines three associated types for its keys. In most
/// implementations they will be the same type, however it enforces the correct use of keys through type safety.
pub trait DiffieHellmanKeyExchangeScheme {
    /// The type of publicly known values exchanged before or during the protocol, like the generator and its powers.
    type PublicKey;

    /// The private values that shall not be shared during the protocol.
    type PrivateKey;

    /// The shared key this protocol generates. It is the common secret of all parties involved.
    type SharedKey;

    /// Generate a random number a and raise the `generator` to the power of `a`. This number is the private key part
    /// and the calculated power is the public part of the Diffie-Hellman-Key-Exchange.
    /// # Parameters
    /// - `rng`: a cryptographically secure random number generator.
    /// - `generator`: the domain parameters used during the protocol. In case of original Diffie-Hellman-Exchange,
    /// it is a generator for the prime field used.
    fn generate_asymmetrical_key_pair<R>(
        rng: &mut R,
        generator: &Self::PublicKey,
    ) -> (Self::PrivateKey, Self::PublicKey)
    where
        R: RngCore + CryptoRng;

    /// Generate the shared secret from the public key received by the other party.
    /// # Parameters
    /// - `private_key` the private key that was generated by `generate_public_key`.
    /// - `partner_key` the public key received by the other party.
    fn generate_shared_secret(
        private_key: &Self::PrivateKey,
        partner_key: &Self::PublicKey,
    ) -> Self::SharedKey;
}

/// Implementation of the `DiffieHellmanKeyExchangeScheme` for all `PrimeField` types.
impl<T> DiffieHellmanKeyExchangeScheme for T
where
    T: PrimeField,
{
    type PublicKey = T;
    type PrivateKey = T;
    type SharedKey = T;

    fn generate_asymmetrical_key_pair<R>(
        rng: &mut R,
        generator: &Self::PublicKey,
    ) -> (Self::PrivateKey, Self::PublicKey)
    where
        R: RngCore + CryptoRng,
    {
        let a = Self::PublicKey::generate_random_member(rng);
        (
            a.clone(),
            generator
                .as_uint()
                .modpow(&a.as_uint(), &T::field_prime().as_uint())
                .into(),
        )
    }

    fn generate_shared_secret(
        private_key: &Self::PrivateKey,
        partner_key: &Self::PublicKey,
    ) -> Self::SharedKey {
        partner_key
            .as_uint()
            .modpow(&private_key.as_uint(), &T::field_prime().as_uint())
            .into()
    }
}

#[cfg(test)]
mod tests {
    use num::Num;
    use rand::thread_rng;

    use jester_maths::prime::IetfGroup3;

    use super::*;

    #[test]
    fn test_key_exchange() {
        let mut rng = thread_rng();

        let generator = IetfGroup3::from_str_radix
                 ("AC4032EF_4F2D9AE3_9DF30B5C_8FFDAC50_6CDEBE7B_89998CAF_74866A08_CFE4FFE3_A6824A4E_10B9A6F0_DD921F01_A70C4AFA_AB739D77_00C29F52_C57DB17C_620A8652_BE5E9001_A8D66AD7_C1766910_1999024A_F4D02727_5AC1348B_B8A762D0_521BC98A_E2471504_22EA1ED4_09939D54_DA7460CD_B5F6C6B2_50717CBE_F180EB34_118E98D1_19529A45_D6F83456_6E3025E3_16A330EF_BB77A86F_0C1AB15B_051AE3D4_28C8F8AC_B70A8137_150B8EEB_10E183ED_D19963DD_D9E263E4_770589EF_6AA21E7F_5F2FF381_B539CCE3_409D13CD_566AFBB4_8D6C0191_81E1BCFE_94B30269_EDFE72FE_9B6AA4BD_7B5A0F1C_71CFFF4C_19C418E1_F6EC0179_81BC087F_2A7065B3_84B890D3_191F2BFA", 16).unwrap();

        let (private_dh_key_1, public_dh_key_1) =
            IetfGroup3::generate_asymmetrical_key_pair(&mut rng, &generator);
        let (private_dh_key_2, public_dh_key_2) =
            IetfGroup3::generate_asymmetrical_key_pair(&mut rng, &generator);

        let shared_key_1 = IetfGroup3::generate_shared_secret(&private_dh_key_1, &public_dh_key_2);
        let shared_key_2 = IetfGroup3::generate_shared_secret(&private_dh_key_2, &public_dh_key_1);

        assert_eq!(shared_key_1, shared_key_2)
    }
}
