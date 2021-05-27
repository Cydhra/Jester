use crate::AsymmetricalEncryptionScheme;
use jester_maths::prime::PrimeField;
use rand::{RngCore, CryptoRng};
use num::{BigUint, Num};
use std::marker::PhantomData;
use jester_maths::prime_test::PrimeTest;

pub struct RSACryptoSystem<P, PTest>
    where P: Num, PTest: PrimeTest<P> {
    marker: PhantomData<P>,
    test: PhantomData<PTest>,
}

pub struct RSAPrivateKey<P> {
    pub d: P,
    pub n: P,
}

pub struct RSAPublicKey<P> {
    pub e: P,
    pub n: P,
}

impl<P, PTest> AsymmetricalEncryptionScheme for RSACryptoSystem<P, PTest>
    where
        P: PrimeField,
        PTest: PrimeTest<P>,
{
    type PrivateKey = RSAPrivateKey<P>;
    type PublicKey = RSAPublicKey<P>;

    fn generate_keypair<R>(rng: &mut R) -> (Self::PrivateKey, Self::PublicKey) where
        R: RngCore + CryptoRng {

        // TODO: which length of p is to be rejected for being too small?
        //  Answer: R, S and A recommend at least 100 (decimal) digits
        let mut p = P::generate_random_member(rng);
        while !PTest::is_prime(p) {
            p = P::generate_random_member(rng)
        }

        let mut q = P::generate_random_member(rng);
        let mut bits = (q.as_uint().bits() - q.as_uint().bits());
        while !PTest::is_prime(q) || !(bits > 0 && bits < 30) {
            q = P::generate_random_member(rng);
            bits = (q.as_uint().bits() - q.as_uint().bits());
        }

        let module = p.mul(&q);
        let phi = (p.sub(1)).mul(&(q.sub(1)));

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