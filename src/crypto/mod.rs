use serde::{Deserialize, Serialize};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use sha2::{Sha256, Digest};
use rand::{RngCore, rngs::OsRng};

/// Cryptographic Engine Module
/// Responsibilities:
/// - Ed25519 digital signatures
/// - AES-GCM encryption/decryption
/// - Key generation

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
}

pub struct CryptoEngine;

impl CryptoEngine {
    /// Generate an Ed25519 keypair
    pub fn generate_ed25519_keypair() -> Result<KeyPair, String> {
        let mut seed = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        Ok(KeyPair {
            public_key: verifying_key.to_bytes().to_vec(),
            private_key: signing_key.to_bytes().to_vec(),
        })
    }

    /// Sign data using Ed25519 private key
    pub fn sign_data(private_key: &[u8], data: &[u8]) -> Result<Signature, String> {
        if private_key.len() != 32 {
            return Err("Invalid private key length. Expected 32 bytes for Ed25519".to_string());
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(private_key);

        let signing_key = SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(data);

        Ok(Signature {
            data: signature.to_bytes().to_vec(),
        })
    }

    /// Verify Ed25519 signature
    pub fn verify_signature(
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, String> {
        if public_key.len() != 32 {
            return Err("Invalid public key length. Expected 32 bytes for Ed25519".to_string());
        }

        if signature.len() != 64 {
            return Err("Invalid signature length. Expected 64 bytes for Ed25519".to_string());
        }

        let verifying_key = VerifyingKey::from_bytes(
            &(public_key
                .try_into()
                .map_err(|_| "Failed to convert public key".to_string())?),
        )
        .map_err(|_| "Invalid public key format".to_string())?;

        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| "Failed to convert signature to fixed array".to_string())?;

        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        match verifying_key.verify(data, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Encrypt data using AES-256-GCM
    pub fn encrypt_aes_gcm(
        key: &[u8],
        plaintext: &[u8],
        nonce: &[u8],
    ) -> Result<EncryptedPayload, String> {
        if key.len() != 32 {
            return Err("Invalid key length. Expected 32 bytes for AES-256".to_string());
        }

        if nonce.len() != 12 {
            return Err("Invalid nonce length. Expected 12 bytes for GCM".to_string());
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| "Failed to initialize cipher".to_string())?;

        let nonce_ref = Nonce::from_slice(nonce);
        let ciphertext = cipher
            .encrypt(
                nonce_ref,
                Payload {
                    msg: plaintext,
                    aad: b"",
                },
            )
            .map_err(|_| "Encryption failed".to_string())?;

        // In AES-GCM, the tag is appended to the ciphertext
        if ciphertext.len() < 16 {
            return Err("Invalid ciphertext length".to_string());
        }

        let actual_ciphertext = ciphertext[..ciphertext.len() - 16].to_vec();
        let tag = ciphertext[ciphertext.len() - 16..].to_vec();

        Ok(EncryptedPayload {
            ciphertext: actual_ciphertext,
            nonce: nonce.to_vec(),
            tag,
        })
    }

    /// Decrypt data using AES-256-GCM
    pub fn decrypt_aes_gcm(key: &[u8], encrypted: &EncryptedPayload) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("Invalid key length. Expected 32 bytes for AES-256".to_string());
        }

        if encrypted.nonce.len() != 12 {
            return Err("Invalid nonce length. Expected 12 bytes for GCM".to_string());
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|_| "Failed to initialize cipher".to_string())?;

        let mut full_ciphertext = encrypted.ciphertext.clone();
        full_ciphertext.extend_from_slice(&encrypted.tag);

        let nonce_ref = Nonce::from_slice(&encrypted.nonce);
        let plaintext = cipher
            .decrypt(
                nonce_ref,
                Payload {
                    msg: full_ciphertext.as_slice(),
                    aad: b"",
                },
            )
            .map_err(|_| "Decryption failed - authentication tag mismatch".to_string())?;

        Ok(plaintext)
    }

    /// Generate a random nonce of specified size
    pub fn generate_random_nonce(size: usize) -> Result<Vec<u8>, String> {
        let mut nonce = vec![0u8; size];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce);
        Ok(nonce)
    }

    /// Compute SHA-256 hash
    pub fn sha256_hash(data: &[u8]) -> Result<Vec<u8>, String> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Ok(hasher.finalize().to_vec())
    }
}
