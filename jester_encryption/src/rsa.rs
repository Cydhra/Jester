use crate::AsymmetricalEncryptionScheme;
use jester_maths::prime::PrimeField;
use rand::{RngCore, CryptoRng};
use num::{BigUint, Num};
use std::marker::PhantomData;

pub struct RSACryptoSystem<P> where P: Num {
    marker: PhantomData<P>,
}

pub struct RSAPrivateKey<P> {
    pub d: P,
    pub n: P,
}

pub struct RSAPublicKey<P> {
    pub e: P,
    pub n: P,
}

impl<P> AsymmetricalEncryptionScheme for RSACryptoSystem<P>
    where P: PrimeField {
    type PrivateKey = RSAPrivateKey<P>;
    type PublicKey = RSAPublicKey<P>;

    fn generate_keypair<R>(rng: &mut R) -> (Self::PrivateKey, Self::PublicKey) where
        R: RngCore + CryptoRng {
        unimplemented!()
    }

    /// Performs the RSA encryption on the message interpreted as an integer from `P` in little
    /// endian byte order
    fn encrypt_message(key: &Self::PublicKey, message: &[u8]) -> Vec<u8> {
        let n = P::from_bytes_le(message);
        if let Some(msg) = n {
            msg.modpow(&key.e, &key.n).to_bytes_le()
        } else {
            panic!("message length exceeds group cardinality")
        }
    }

    /// Performs the RSA decryption on the cipher interpreted as an integer from `P` in little
    /// endian byte order
    fn decrypt_message(key: &Self::PrivateKey, cipher: &[u8]) -> Vec<u8> {
        let n = P::from_bytes_le(cipher);
        if let Some(c) = n {
            c.modpow(&key.d, &key.n).to_bytes_le()
        } else {
            panic!("cipher length exceeds group cardinality")
        }
    }
}