use rand::{CryptoRng, RngCore, thread_rng};

use jester_encryption::diffie_hellman::DiffieHellmanKeyExchangeScheme;
use jester_encryption::SymmetricalEncryptionScheme;
use jester_maths::prime::{IetfGroup3, PrimeField};
use num::Num;

use crate::{DoubleRatchetProtocol, KeyDerivationFunction};
use jester_hashes::kdf::hkdf_derive_key;
use jester_hashes::sha1::SHA1Hash;


// An encryption scheme for testing, that simply appends the clear text to the password and panics, if the password
// is wrong in decryption.
struct TestEncryption {

}

impl SymmetricalEncryptionScheme for TestEncryption {
    type Key = &'static str;

    fn generate_key<R>(_: &mut R) -> Self::Key where
        R: RngCore + CryptoRng {
        "super_secure_password"
    }

    fn encrypt_message(key: &Self::Key, message: &[u8]) -> Box<[u8]> {
        Box::from([key.as_bytes(), message].concat())
    }

    fn decrypt_message(key: &Self::Key, message: &[u8]) -> Box<[u8]> {
        if message.starts_with(key.as_bytes()) {
            Box::from(&message[key.as_bytes().len()..])
        } else {
            panic!("wrong key")
        }
    }
}

struct RootKeyDerivationFunction;

impl KeyDerivationFunction for RootKeyDerivationFunction {
    type ChainKey = Box<[u8]>;
    type Input = Box<[u8]>;
    type OutputKey = Box<[u8]>;

    fn derive_key(chain_key: Self::ChainKey, input: Self::Input) -> (Self::ChainKey, Self::OutputKey) {
        // let key_material = hkdf_derive_key(&chain_key, &input, SHA1Hash::OUTPUT_SIZE, &Box::from([0x0, 0x1, 0x2, 0x3]));
        // TODO figure out how to split the material
        unimplemented!()
    }
}

const DH_GENERATOR: &str =
    "AC4032EF_4F2D9AE3_9DF30B5C_8FFDAC50_6CDEBE7B_89998CAF_74866A08_CFE4FFE3_A6824A4E_10B9A6F0_DD921F01_A70C4AFA_AB739D77_00C29F52_C57DB17C_620A8652_BE5E9001_A8D66AD7_C1766910_1999024A_F4D02727_5AC1348B_B8A762D0_521BC98A_E2471504_22EA1ED4_09939D54_DA7460CD_B5F6C6B2_50717CBE_F180EB34_118E98D1_19529A45_D6F83456_6E3025E3_16A330EF_BB77A86F_0C1AB15B_051AE3D4_28C8F8AC_B70A8137_150B8EEB_10E183ED_D19963DD_D9E263E4_770589EF_6AA21E7F_5F2FF381_B539CCE3_409D13CD_566AFBB4_8D6C0191_81E1BCFE_94B30269_EDFE72FE_9B6AA4BD_7B5A0F1C_71CFFF4C_19C418E1_F6EC0179_81BC087F_2A7065B3_84B890D3_191F2BFA";

#[test]
fn test_connect() {
    // let mut rng = thread_rng();
    // let generator = IetfGroup3::from_str_radix(DH_GENERATOR, 16).unwrap();
    //
    //
    // // generate a pre-shared root key. This is done by simulating a diffie-hellman exchange:
    // let (sender_temp_private, _) = IetfGroup3::generate_asymmetrical_key_pair(&mut rng, &generator);
    // let (_, recv_temp_public) = IetfGroup3::generate_asymmetrical_key_pair(&mut rng, &generator);
    // let pre_shared_root_key = IetfGroup3::generate_shared_secret(&sender_temp_private, &recv_temp_public);
    //
    //
    // let (sender_dh_private, sender_dh_public) = IetfGroup3::generate_asymmetrical_key_pair(&mut rng, &generator);
    // DoubleRatchetProtocol::<
    //     IetfGroup3,
    //     TestEncryption,
    //     _, _, _, _, _, _, _, _, _>::initialize_sending(&mut rng, sender_dh_public, pre_shared_root_key);

    // let (receiver_dh_private, receiver_dh_public) = IetfGroup3::generate_asymmetrical_key_pair(&mut rng, &generator);
    // DoubleRatchetProtocol::initialize_receiving(&mut rng, receiver_dh_public, )
    unimplemented!()
}