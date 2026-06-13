use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Cryptographic Engine Module
/// Responsibilities:
/// - Ed25519 digital signatures
/// - AES-GCM encryption/decryption
/// - Key generation

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &format!("{} bytes", self.public_key.len()))
            .field("private_key", &"[REDACTED]")
            .finish()
    }
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

    /// Derive the Ed25519 public key from a 32-byte private signing seed.
    pub fn derive_ed25519_public_key(private_key: &[u8]) -> Result<Vec<u8>, String> {
        if private_key.len() != 32 {
            return Err("Invalid private key length. Expected 32 bytes for Ed25519".to_string());
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(private_key);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        Ok(signing_key.verifying_key().to_bytes().to_vec())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_keypair_generation() {
        let kp1 = CryptoEngine::generate_ed25519_keypair();
        assert!(kp1.is_ok(), "Keypair generation failed");

        let kp1 = kp1.unwrap();
        assert_eq!(kp1.public_key.len(), 32, "Public key should be 32 bytes");
        assert_eq!(kp1.private_key.len(), 32, "Private key should be 32 bytes");

        // Generate second keypair and verify they're different
        let kp2 = CryptoEngine::generate_ed25519_keypair().unwrap();
        assert_ne!(
            kp1.public_key, kp2.public_key,
            "Generated keypairs should be different"
        );
        assert_ne!(
            kp1.private_key, kp2.private_key,
            "Generated private keys should be different"
        );
    }

    #[test]
    fn test_keypair_debug_redacts_private_key() {
        let keypair = CryptoEngine::generate_ed25519_keypair().expect("Keypair gen failed");
        let private_key_debug = format!("{:?}", keypair.private_key);
        let debug_output = format!("{:?}", keypair);

        assert!(debug_output.contains("private_key"));
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains(&private_key_debug));
    }

    #[test]
    fn test_signing_and_verification() {
        let kp = CryptoEngine::generate_ed25519_keypair().unwrap();
        let data = b"Test message for signing";

        // Sign data
        let sig_result = CryptoEngine::sign_data(&kp.private_key, data);
        assert!(sig_result.is_ok(), "Signing should succeed");

        let sig = sig_result.unwrap();
        assert_eq!(sig.data.len(), 64, "Ed25519 signature should be 64 bytes");

        // Verify with correct public key
        let verify_result = CryptoEngine::verify_signature(&kp.public_key, data, &sig.data);
        assert!(verify_result.is_ok(), "Verification should succeed");
        assert!(verify_result.unwrap(), "Signature should be valid");
    }

    #[test]
    fn test_public_key_derivation_from_private_seed() {
        let kp = CryptoEngine::generate_ed25519_keypair().unwrap();
        let derived = CryptoEngine::derive_ed25519_public_key(&kp.private_key)
            .expect("public key derivation should succeed");

        assert_eq!(derived, kp.public_key);
    }

    #[test]
    fn test_verification_fails_with_tampered_data() {
        let kp = CryptoEngine::generate_ed25519_keypair().unwrap();
        let data = b"Original message";
        let tampered = b"Tampered message";

        let sig = CryptoEngine::sign_data(&kp.private_key, data).unwrap();

        // Verification should fail when data is different
        let result = CryptoEngine::verify_signature(&kp.public_key, tampered, &sig.data).unwrap();
        assert!(!result, "Tampered data should fail verification");
    }

    #[test]
    fn test_verification_fails_with_wrong_key() {
        let kp1 = CryptoEngine::generate_ed25519_keypair().unwrap();
        let kp2 = CryptoEngine::generate_ed25519_keypair().unwrap();
        let data = b"Test message";

        let sig = CryptoEngine::sign_data(&kp1.private_key, data).unwrap();

        // Verification should fail with different public key
        let result = CryptoEngine::verify_signature(&kp2.public_key, data, &sig.data).unwrap();
        assert!(!result, "Different CA should fail verification");
    }

    #[test]
    fn test_verification_fails_with_tampered_signature() {
        let kp = CryptoEngine::generate_ed25519_keypair().unwrap();
        let data = b"Test message";

        let mut sig = CryptoEngine::sign_data(&kp.private_key, data).unwrap();
        // Tamper with signature
        sig.data[0] ^= 0xFF;

        let result = CryptoEngine::verify_signature(&kp.public_key, data, &sig.data).unwrap();
        assert!(!result, "Tampered signature should fail verification");
    }

    #[test]
    fn test_invalid_private_key_length() {
        let short_key = vec![1u8; 16];
        let data = b"test";

        let result = CryptoEngine::sign_data(&short_key, data);
        assert!(result.is_err(), "Should reject invalid key length");
        assert!(
            result.unwrap_err().contains("32 bytes"),
            "Error should mention key length"
        );
    }

    #[test]
    fn test_invalid_public_key_length() {
        let short_key = vec![1u8; 16];
        let data = b"test";
        let sig = vec![0u8; 64];

        let result = CryptoEngine::verify_signature(&short_key, data, &sig);
        assert!(result.is_err(), "Should reject invalid public key length");
    }

    #[test]
    fn test_invalid_signature_length() {
        let kp = CryptoEngine::generate_ed25519_keypair().unwrap();
        let data = b"test";
        let short_sig = vec![0u8; 32];

        let result = CryptoEngine::verify_signature(&kp.public_key, data, &short_sig);
        assert!(result.is_err(), "Should reject invalid signature length");
    }

    #[test]
    fn test_aes_gcm_encryption_decryption() {
        let key = CryptoEngine::generate_random_nonce(32).unwrap(); // Use random data as key
        let plaintext = b"Secret message";
        let nonce = CryptoEngine::generate_random_nonce(12).unwrap();

        // Encrypt
        let encrypted = CryptoEngine::encrypt_aes_gcm(&key, plaintext, &nonce);
        assert!(encrypted.is_ok(), "Encryption should succeed");

        let encrypted_payload = encrypted.unwrap();
        assert_ne!(
            &encrypted_payload.ciphertext, plaintext,
            "Ciphertext should differ from plaintext"
        );
        assert_eq!(
            encrypted_payload.nonce.len(),
            12,
            "Nonce should be 12 bytes"
        );
        assert_eq!(
            encrypted_payload.tag.len(),
            16,
            "GCM tag should be 16 bytes"
        );

        // Decrypt
        let decrypted = CryptoEngine::decrypt_aes_gcm(&key, &encrypted_payload);
        assert!(decrypted.is_ok(), "Decryption should succeed");
        assert_eq!(
            decrypted.unwrap(),
            plaintext,
            "Decrypted data should match plaintext"
        );
    }

    #[test]
    fn test_aes_gcm_fails_with_wrong_key() {
        let key1 = CryptoEngine::generate_random_nonce(32).unwrap();
        let key2 = CryptoEngine::generate_random_nonce(32).unwrap();
        let plaintext = b"Secret";
        let nonce = CryptoEngine::generate_random_nonce(12).unwrap();

        let encrypted = CryptoEngine::encrypt_aes_gcm(&key1, plaintext, &nonce).unwrap();

        // Decryption with wrong key should fail
        let result = CryptoEngine::decrypt_aes_gcm(&key2, &encrypted);
        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[test]
    fn test_aes_gcm_rejects_invalid_key_size() {
        let short_key = vec![1u8; 16];
        let plaintext = b"test";
        let nonce = CryptoEngine::generate_random_nonce(12).unwrap();

        let result = CryptoEngine::encrypt_aes_gcm(&short_key, plaintext, &nonce);
        assert!(result.is_err(), "Should reject invalid key size");
    }

    #[test]
    fn test_aes_gcm_rejects_invalid_nonce_size() {
        let key = CryptoEngine::generate_random_nonce(32).unwrap();
        let plaintext = b"test";
        let short_nonce = vec![1u8; 8];

        let result = CryptoEngine::encrypt_aes_gcm(&key, plaintext, &short_nonce);
        assert!(result.is_err(), "Should reject invalid nonce size");
    }

    #[test]
    fn test_random_nonce_generation() {
        let nonce1 = CryptoEngine::generate_random_nonce(12).unwrap();
        assert_eq!(nonce1.len(), 12);

        // Generate second nonce and verify they're different
        let nonce2 = CryptoEngine::generate_random_nonce(12).unwrap();
        assert_ne!(nonce1, nonce2, "Random nonces should be different");
    }

    #[test]
    fn test_sha256_hash() {
        let data = b"test data";
        let hash = CryptoEngine::sha256_hash(data).unwrap();
        assert_eq!(hash.len(), 32, "SHA-256 hash should be 32 bytes");

        // Same data should produce same hash
        let hash2 = CryptoEngine::sha256_hash(data).unwrap();
        assert_eq!(hash, hash2, "Same data should produce same hash");

        // Different data should produce different hash
        let hash3 = CryptoEngine::sha256_hash(b"different").unwrap();
        assert_ne!(hash, hash3, "Different data should produce different hash");
    }
}
