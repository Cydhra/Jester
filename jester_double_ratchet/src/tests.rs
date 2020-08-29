#![cfg(test)]

use rand::thread_rng;

use jester_encryption::diffie_hellman::DiffieHellmanKeyExchangeScheme;
use jester_maths::prime::IetfGroup3;
use num::Num;

use crate::DoubleRatchetProtocol;

#[test]
fn test_first_exchange() {
    let mut rng = thread_rng();
    let generator = IetfGroup3::from_str_radix
        ("AC4032EF_4F2D9AE3_9DF30B5C_8FFDAC50_6CDEBE7B_89998CAF_74866A08_CFE4FFE3_A6824A4E_10B9A6F0_DD921F01_A70C4AFA_AB739D77_00C29F52_C57DB17C_620A8652_BE5E9001_A8D66AD7_C1766910_1999024A_F4D02727_5AC1348B_B8A762D0_521BC98A_E2471504_22EA1ED4_09939D54_DA7460CD_B5F6C6B2_50717CBE_F180EB34_118E98D1_19529A45_D6F83456_6E3025E3_16A330EF_BB77A86F_0C1AB15B_051AE3D4_28C8F8AC_B70A8137_150B8EEB_10E183ED_D19963DD_D9E263E4_770589EF_6AA21E7F_5F2FF381_B539CCE3_409D13CD_566AFBB4_8D6C0191_81E1BCFE_94B30269_EDFE72FE_9B6AA4BD_7B5A0F1C_71CFFF4C_19C418E1_F6EC0179_81BC087F_2A7065B3_84B890D3_191F2BFA", 16).unwrap();

    let (private_dh_key, public_dh_key) =
        IetfGroup3::generate_asymmetrical_key_pair(&mut rng, &generator);

    // let initiator_instance = DoubleRatchetProtocol::initialize_sending(&mut rng, public_dh_key, todo!());
}