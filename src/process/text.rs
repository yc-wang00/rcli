use std::{fs, io::Read, path::Path};

use crate::{cli::TextSignFormat, get_reader, process_genpass};

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key,
};

pub trait TextSign {
    /// Sign the data from the reader and return the signature
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerify {
    fn verify(&self, reader: &mut dyn Read, signature: &[u8]) -> Result<bool>;
}

pub trait KeyLoader {
    fn load(path: impl AsRef<Path>) -> Result<Self>
    where
        Self: Sized;
}

pub trait KeyGenerator {
    fn generate() -> Result<Vec<Vec<u8>>>;
}

impl KeyGenerator for Blake3 {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let key = key.as_bytes().to_vec();
        Ok(vec![key])
    }
}

impl KeyGenerator for Ed25519Signer {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let mut csprng = OsRng;
        let sk: SigningKey = SigningKey::generate(&mut csprng);

        let pk = sk.verifying_key().to_bytes().to_vec();
        let sk = sk.to_bytes().to_vec();

        Ok(vec![sk, pk])
    }
}

impl KeyGenerator for ChaCha20Poly1305 {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);

        // convert key to Vec<u8>
        let key = key.as_slice().to_vec();
        Ok(vec![key])
    }
}

impl KeyLoader for Blake3 {
    fn load(path: impl AsRef<Path>) -> Result<Self> {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyLoader for Ed25519Signer {
    fn load(path: impl AsRef<Path>) -> Result<Self> {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyLoader for Ed25519Verifier {
    fn load(path: impl AsRef<Path>) -> Result<Self> {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

impl KeyLoader for ChaCha20Poly1305Signer {
    fn load(path: impl AsRef<Path>) -> Result<Self> {
        let key = fs::read(path)?;
        Self::try_new(&key)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Blake3 {
    key: [u8; 32],
}

impl TextSign for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        //TODO: improve perf by reading in chunks
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        let hash = blake3::keyed_hash(&self.key, &buf);
        Ok(hash.as_bytes().to_vec())
    }
}

impl TextVerify for Blake3 {
    fn verify(&self, reader: &mut dyn Read, signature: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        let hash = blake3::keyed_hash(&self.key, &buf);
        let hash = hash.as_bytes();
        Ok(hash == signature)
    }
}

pub struct Ed25519Signer {
    key: SigningKey,
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

#[derive(Debug, Clone, Copy)]
pub struct ChaCha20Poly1305Signer {
    key: [u8; 32],
}

impl TextSign for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        let signature = self.key.sign(&buf).to_bytes().to_vec();
        Ok(signature)
    }
}

impl TextVerify for Ed25519Verifier {
    fn verify(&self, reader: &mut dyn Read, signature: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        let sig = Signature::from_bytes(signature.try_into()?);

        let res = self.key.verify(&buf, &sig).is_ok();
        Ok(res)
    }
}

impl Blake3 {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = &key[..32];
        let key = key.try_into()?;
        Ok(Self::new(key))
    }
}

impl Ed25519Signer {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = SigningKey::from_bytes(key.try_into()?);
        Ok(Self::new(key))
    }
}

impl Ed25519Verifier {
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = VerifyingKey::from_bytes(key.try_into()?)?;
        let verifier = Ed25519Verifier::new(key);
        Ok(verifier)
    }
}

impl ChaCha20Poly1305Signer {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn try_new(key: &[u8]) -> Result<Self> {
        let key = &key[..32];
        let key = key.try_into()?;
        Ok(Self::new(key))
    }
}

pub fn process_text_sign(input: &str, key: &str, format: TextSignFormat) -> Result<String> {
    let mut reader = get_reader(input)?;
    let signed = match format {
        TextSignFormat::Blake3 => {
            let signer: Blake3 = Blake3::load(key)?;
            signer.sign(&mut reader)?
        }
        TextSignFormat::Ed25519 => {
            let signer: Ed25519Signer = Ed25519Signer::load(key)?;
            signer.sign(&mut reader)?
        }
        TextSignFormat::ChaCha20Poly1305 => {
            // not implemented
            Vec::new()
        }
    };
    let signed = URL_SAFE_NO_PAD.encode(signed);
    Ok(signed)
}

pub fn process_text_verify(
    input: &str,
    key: &str,
    sig: &str,
    format: TextSignFormat,
) -> Result<bool> {
    let mut reader = get_reader(input)?;
    let signature = URL_SAFE_NO_PAD.decode(sig.as_bytes())?;

    let verified = match format {
        TextSignFormat::Blake3 => {
            let verifier: Blake3 = Blake3::load(key)?;
            verifier.verify(&mut reader, &signature)?
        }
        TextSignFormat::Ed25519 => {
            let verifier: Ed25519Verifier = Ed25519Verifier::load(key)?;
            verifier.verify(&mut reader, &signature)?
        }
        TextSignFormat::ChaCha20Poly1305 => {
            // not implemented
            false
        }
    };
    Ok(verified)
}

pub fn process_text_generate(format: TextSignFormat) -> Result<Vec<Vec<u8>>> {
    match format {
        TextSignFormat::Blake3 => Blake3::generate(),
        TextSignFormat::Ed25519 => Ed25519Signer::generate(),
        TextSignFormat::ChaCha20Poly1305 => ChaCha20Poly1305::generate(),
    }
}

pub fn process_text_encrypt(input: &str, key: &str) -> Result<String> {
    let mut reader = get_reader(input)?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    // convert key from &str to &[u8]
    let key = ChaCha20Poly1305Signer::load(key)?;

    // // convert key to GenericArray
    let key = Key::from_slice(&key.key);

    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    // encrypt here
    let ciphertext = cipher.encrypt(&nonce, buf.as_ref()).unwrap();

    // encode to base64
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);
    let ciphertext_b64 = URL_SAFE_NO_PAD.encode(ciphertext);

    // concatenate nonce and ciphertext
    Ok(format!("{}:{}", nonce_b64, ciphertext_b64))
}

pub fn process_text_decrypt(input: &str, key: &str) -> Result<String> {
    let mut reader = get_reader(input)?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    let buf = String::from_utf8(buf).unwrap();
    // split nonce and ciphertext
    let parts: Vec<&str> = buf.split(':').collect();
    let nonce = URL_SAFE_NO_PAD.decode(parts[0].as_bytes())?;
    let ciphertext = URL_SAFE_NO_PAD.decode(parts[1].as_bytes())?;

    // Load key
    let key = ChaCha20Poly1305Signer::load(key)?;

    // convert key to GenericArray
    let key = Key::from_slice(&key.key);

    let cipher = ChaCha20Poly1305::new(key);
    let nonce = GenericArray::from_slice(&nonce);

    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();

    // convert plaintext to String
    let plaintext = String::from_utf8(plaintext).unwrap();
    Ok(plaintext)
}

// #[cfg(test)]
// mod tests {
// use super::*;
// use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

// const KEY: &[u8] = include_bytes!("../../fixtures/blake3.txt");

// #[test]
// fn test_process_text_sign() -> Result<()> {
//     let mut reader = "hello".as_bytes();
//     let mut reader1 = "hello".as_bytes();
//     let format = TextSignFormat::Blake3;
//     let sig = process_text_sign(&mut reader, KEY, format)?;
//     let ret = process_text_verify(&mut reader1, KEY, &sig, format)?;
//     assert!(ret);
//     Ok(())
// }

// #[test]
// fn test_process_text_verify() -> Result<()> {
//     let sk = Ed25519Signer::load("fixtures/ed25519.private")?;
//     let pk = Ed25519Verifier::load("fixtures/ed25519.public")?;

//     let data = b"hello";
//     let signature = sk.sign(&mut &data[..])?;
//     assert!(pk.verify(&mut &data[..], &signature)?);
//     Ok(())
// }
// }
