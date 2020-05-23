use jester_encryption::SymmetricalEncryptionScheme;
use rand::{RngCore, CryptoRng};
use std::fmt::Error;

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
