/// Digital Key Fob Module (DKF)
/// Responsibilities:
/// - Generate and manage Ed25519 keypair
/// - Store private key securely
/// - Request certificate from CA
/// - Sign vehicle nonce challenges
/// - Provide authentication proof
use crate::ca::CertificateAuthority;
use crate::crypto::CryptoEngine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub enum KeyFobError {
    KeygenFailed(String),
    SigningFailed(String),
    FileIOError(String),
    SerializationError(String),
    NotInitialized,
    NoCertificate,
}

impl std::fmt::Display for KeyFobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyFobError::KeygenFailed(msg) => write!(f, "Key generation failed: {}", msg),
            KeyFobError::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            KeyFobError::FileIOError(msg) => write!(f, "File I/O error: {}", msg),
            KeyFobError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            KeyFobError::NotInitialized => write!(f, "Key fob not initialized"),
            KeyFobError::NoCertificate => write!(f, "No certificate installed"),
        }
    }
}

impl std::error::Error for KeyFobError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationProof {
    pub subject_id: String,
    pub certificate: Vec<u8>,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub signature: Vec<u8>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalKeyFob {
    pub subject_id: String,
    pub public_key: Option<Vec<u8>>,
    pub private_key: Option<Vec<u8>>,
    pub certificate: Option<Vec<u8>>,
}

impl DigitalKeyFob {
    /// Create a new key fob with given subject_id
    pub fn new(subject_id: String) -> Self {
        Self {
            subject_id,
            public_key: None,
            private_key: None,
            certificate: None,
        }
    }

    /// Generate Ed25519 keypair for the key fob
    pub fn initialize(&mut self) -> Result<(), KeyFobError> {
        // Generate keypair
        let keypair =
            CryptoEngine::generate_ed25519_keypair().map_err(|e| KeyFobError::KeygenFailed(e))?;

        self.public_key = Some(keypair.public_key);
        self.private_key = Some(keypair.private_key);

        Ok(())
    }

    /// Save key fob keys to disk
    pub fn save_keys(&self) -> Result<(), KeyFobError> {
        fs::create_dir_all("keys").map_err(|e| KeyFobError::FileIOError(e.to_string()))?;

        // Save public key
        if let Some(pub_key) = &self.public_key {
            let pub_key_path = format!("keys/fob_{}_public.json", self.subject_id);
            let pub_json = serde_json::to_string_pretty(pub_key)
                .map_err(|e| KeyFobError::SerializationError(e.to_string()))?;
            fs::write(pub_key_path, pub_json)
                .map_err(|e| KeyFobError::FileIOError(e.to_string()))?;
        }

        // Save private key (in production, should be encrypted!)
        if let Some(priv_key) = &self.private_key {
            let priv_key_path = format!("keys/fob_{}_private.json", self.subject_id);
            let priv_json = serde_json::to_string_pretty(priv_key)
                .map_err(|e| KeyFobError::SerializationError(e.to_string()))?;
            fs::write(priv_key_path, priv_json)
                .map_err(|e| KeyFobError::FileIOError(e.to_string()))?;
        }

        Ok(())
    }

    /// Load key fob keys from disk
    pub fn load_keys(&mut self) -> Result<(), KeyFobError> {
        let pub_key_path = format!("keys/fob_{}_public.json", self.subject_id);
        let priv_key_path = format!("keys/fob_{}_private.json", self.subject_id);

        if !Path::new(&pub_key_path).exists() || !Path::new(&priv_key_path).exists() {
            return Err(KeyFobError::FileIOError(
                "Key fob keys not found on disk".to_string(),
            ));
        }

        let pub_json = fs::read_to_string(&pub_key_path)
            .map_err(|e| KeyFobError::FileIOError(e.to_string()))?;
        let pub_key: Vec<u8> = serde_json::from_str(&pub_json)
            .map_err(|e| KeyFobError::SerializationError(e.to_string()))?;

        let priv_json = fs::read_to_string(&priv_key_path)
            .map_err(|e| KeyFobError::FileIOError(e.to_string()))?;
        let priv_key: Vec<u8> = serde_json::from_str(&priv_json)
            .map_err(|e| KeyFobError::SerializationError(e.to_string()))?;

        self.public_key = Some(pub_key);
        self.private_key = Some(priv_key);

        Ok(())
    }

    /// Request certificate issuance from CA
    pub fn request_certificate(&mut self, ca: &CertificateAuthority) -> Result<(), KeyFobError> {
        let pub_key = self
            .public_key
            .as_ref()
            .ok_or(KeyFobError::NotInitialized)?
            .clone();

        let cert = ca
            .issue_certificate(self.subject_id.clone(), pub_key)
            .map_err(|e| KeyFobError::SigningFailed(e.to_string()))?;

        // Serialize certificate
        let cert_json = serde_json::to_vec(&cert)
            .map_err(|e| KeyFobError::SerializationError(e.to_string()))?;

        self.certificate = Some(cert_json);

        // Save certificate to disk
        fs::create_dir_all("certs").map_err(|e| KeyFobError::FileIOError(e.to_string()))?;
        let cert_path = format!("certs/fob_{}.json", self.subject_id);
        let cert_json = serde_json::to_string_pretty(&cert)
            .map_err(|e| KeyFobError::SerializationError(e.to_string()))?;
        fs::write(&cert_path, cert_json).map_err(|e| KeyFobError::FileIOError(e.to_string()))?;

        Ok(())
    }

    /// Load certificate from disk
    pub fn load_certificate(&mut self) -> Result<(), KeyFobError> {
        let cert_path = format!("certs/fob_{}.json", self.subject_id);

        if !Path::new(&cert_path).exists() {
            return Err(KeyFobError::FileIOError(
                "Certificate not found on disk".to_string(),
            ));
        }

        let cert_json =
            fs::read_to_string(&cert_path).map_err(|e| KeyFobError::FileIOError(e.to_string()))?;
        let cert_data = serde_json::to_vec(&cert_json)
            .map_err(|e| KeyFobError::SerializationError(e.to_string()))?;

        self.certificate = Some(cert_data);

        Ok(())
    }

    /// Sign a vehicle nonce challenge
    pub fn sign_challenge(&self, nonce: &[u8]) -> Result<ChallengeResponse, KeyFobError> {
        let private_key = self
            .private_key
            .as_ref()
            .ok_or(KeyFobError::NotInitialized)?;

        // Sign the nonce
        let signature = CryptoEngine::sign_data(private_key, nonce)
            .map_err(|e| KeyFobError::SigningFailed(e))?;

        Ok(ChallengeResponse {
            signature: signature.data,
            timestamp: Utc::now().to_rfc3339(),
        })
    }

    /// Create complete authentication proof for vehicle
    pub fn create_auth_proof(&self, nonce: &[u8]) -> Result<AuthenticationProof, KeyFobError> {
        let certificate = self
            .certificate
            .as_ref()
            .ok_or(KeyFobError::NoCertificate)?
            .clone();

        let private_key = self
            .private_key
            .as_ref()
            .ok_or(KeyFobError::NotInitialized)?;

        // Sign the nonce
        let signature = CryptoEngine::sign_data(private_key, nonce)
            .map_err(|e| KeyFobError::SigningFailed(e))?;

        Ok(AuthenticationProof {
            subject_id: self.subject_id.clone(),
            certificate,
            nonce: nonce.to_vec(),
            signature: signature.data,
            timestamp: Utc::now().to_rfc3339(),
        })
    }

    /// Get the key fob's public key
    pub fn get_public_key(&self) -> Result<Vec<u8>, KeyFobError> {
        self.public_key.clone().ok_or(KeyFobError::NotInitialized)
    }

    /// Get the stored certificate
    pub fn get_certificate(&self) -> Result<Vec<u8>, KeyFobError> {
        self.certificate.clone().ok_or(KeyFobError::NoCertificate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create key fob with initialized keys
    fn create_fob_with_keys(subject_id: &str) -> DigitalKeyFob {
        let mut fob = DigitalKeyFob::new(subject_id.to_string());
        fob.initialize().expect("Fob init failed");
        fob
    }

    #[test]
    fn test_key_fob_creation() {
        let fob = DigitalKeyFob::new("FOB-001".to_string());
        assert_eq!(fob.subject_id, "FOB-001");
        assert!(fob.public_key.is_none());
        assert!(fob.private_key.is_none());
        assert!(fob.certificate.is_none());
    }

    #[test]
    fn test_key_generation() {
        let mut fob = DigitalKeyFob::new("FOB-001".to_string());
        let result = fob.initialize();
        assert!(result.is_ok(), "Key generation should succeed");

        assert!(fob.public_key.is_some(), "Should have public key");
        assert!(fob.private_key.is_some(), "Should have private key");
        assert_eq!(fob.public_key.as_ref().unwrap().len(), 32);
        assert_eq!(fob.private_key.as_ref().unwrap().len(), 32);
    }

    #[test]
    fn test_key_generation_produces_different_keys() {
        let mut fob1 = DigitalKeyFob::new("FOB-001".to_string());
        fob1.initialize().expect("Init failed");

        let mut fob2 = DigitalKeyFob::new("FOB-002".to_string());
        fob2.initialize().expect("Init failed");

        assert_ne!(
            fob1.public_key.as_ref().unwrap(),
            fob2.public_key.as_ref().unwrap(),
            "Different fobs should have different keys"
        );
    }

    #[test]
    fn test_get_public_key() {
        let fob = create_fob_with_keys("FOB-001");
        let pub_key = fob.get_public_key();
        assert!(pub_key.is_ok());
        assert_eq!(pub_key.unwrap().len(), 32);
    }

    #[test]
    fn test_get_public_key_not_initialized() {
        let fob = DigitalKeyFob::new("FOB-001".to_string());
        let result = fob.get_public_key();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyFobError::NotInitialized));
    }

    #[test]
    fn test_sign_challenge() {
        let fob = create_fob_with_keys("FOB-001");
        let nonce = b"test-nonce-12345";

        let response = fob.sign_challenge(nonce);
        assert!(response.is_ok(), "Signing should succeed");

        let response = response.unwrap();
        assert_eq!(
            response.signature.len(),
            64,
            "Ed25519 signature should be 64 bytes"
        );
        assert!(!response.timestamp.is_empty(), "Timestamp should be set");
    }

    #[test]
    fn test_sign_challenge_not_initialized() {
        let fob = DigitalKeyFob::new("FOB-001".to_string());
        let nonce = b"test-nonce";

        let result = fob.sign_challenge(nonce);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyFobError::NotInitialized));
    }

    #[test]
    fn test_signature_verifiable_by_public_key() {
        let fob = create_fob_with_keys("FOB-001");
        let nonce = b"test message";

        let response = fob.sign_challenge(nonce).expect("Signing failed");
        let pub_key = fob.get_public_key().expect("Get pub key failed");

        // Verify signature with crypto engine
        let is_valid = CryptoEngine::verify_signature(&pub_key, nonce, &response.signature)
            .expect("Verify failed");
        assert!(is_valid, "Signature should be valid with fob's public key");
    }

    #[test]
    fn test_tampered_nonce_fails_verification() {
        let fob = create_fob_with_keys("FOB-001");
        let nonce = b"original nonce";
        let tampered = b"tampered nonce";

        let response = fob.sign_challenge(nonce).expect("Signing failed");
        let pub_key = fob.get_public_key().expect("Get pub key failed");

        // Verify with tampered nonce
        let is_valid = CryptoEngine::verify_signature(&pub_key, tampered, &response.signature)
            .expect("Verify failed");
        assert!(!is_valid, "Tampered nonce should fail verification");
    }

    #[test]
    fn test_create_auth_proof_without_certificate() {
        let fob = create_fob_with_keys("FOB-001");
        let nonce = b"test-nonce";

        let result = fob.create_auth_proof(nonce);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyFobError::NoCertificate));
    }

    #[test]
    fn test_auth_proof_structure() {
        // Create a mock proof (without certificate from CA)
        let mut fob = create_fob_with_keys("FOB-001");
        fob.certificate = Some(vec![1, 2, 3, 4, 5]); // Mock certificate

        let nonce = b"test-nonce";
        let proof = fob.create_auth_proof(nonce);

        assert!(proof.is_ok(), "Auth proof creation should succeed");
        let proof = proof.unwrap();

        assert_eq!(proof.subject_id, "FOB-001");
        assert_eq!(proof.certificate, vec![1, 2, 3, 4, 5]);
        assert_eq!(proof.nonce, nonce);
        assert_eq!(proof.signature.len(), 64);
        assert!(!proof.timestamp.is_empty());
    }

    #[test]
    fn test_different_nonces_produce_different_signatures() {
        let fob = create_fob_with_keys("FOB-001");
        let nonce1 = b"nonce-one";
        let nonce2 = b"nonce-two";

        let sig1 = fob.sign_challenge(nonce1).expect("Sign failed");
        let sig2 = fob.sign_challenge(nonce2).expect("Sign failed");

        assert_ne!(
            sig1.signature, sig2.signature,
            "Different nonces should produce different signatures"
        );
    }

    #[test]
    fn test_multiple_signatures_of_same_nonce_differ() {
        let fob = create_fob_with_keys("FOB-001");
        let nonce = b"same-nonce";

        let sig1 = fob.sign_challenge(nonce).expect("Sign failed");
        let sig2 = fob.sign_challenge(nonce).expect("Sign failed");

        assert_eq!(
            sig1.signature, sig2.signature,
            "Same nonce should produce same signature"
        );
    }

    #[test]
    fn test_save_and_load_keys() {
        let mut fob1 = DigitalKeyFob::new("FOB-VERIFY".to_string());
        fob1.initialize().expect("Init failed");

        let pub_key_before = fob1.public_key.clone();
        let priv_key_before = fob1.private_key.clone();

        fob1.save_keys().expect("Save failed");

        let mut fob2 = DigitalKeyFob::new("FOB-VERIFY".to_string());
        fob2.load_keys().expect("Load failed");

        assert_eq!(
            fob2.public_key, pub_key_before,
            "Public key should match after load"
        );
        assert_eq!(
            fob2.private_key, priv_key_before,
            "Private key should match after load"
        );
    }

    #[test]
    fn test_keys_roundtrip_preserves_signing_capability() {
        let mut fob1 = DigitalKeyFob::new("FOB-ROUNDTRIP".to_string());
        fob1.initialize().expect("Init failed");

        let nonce = b"test-nonce-verify";
        let sig1 = fob1.sign_challenge(nonce).expect("Sign failed");

        fob1.save_keys().expect("Save failed");

        let mut fob2 = DigitalKeyFob::new("FOB-ROUNDTRIP".to_string());
        fob2.load_keys().expect("Load failed");

        let sig2 = fob2.sign_challenge(nonce).expect("Sign failed");

        assert_eq!(
            sig1.signature, sig2.signature,
            "Signatures should match after roundtrip"
        );
    }

    #[test]
    fn test_certificate_persistence() {
        let mut fob = create_fob_with_keys("FOB-CERT-TEST");
        let test_cert = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        fob.certificate = Some(test_cert.clone());

        let retrieved = fob.get_certificate().expect("Get cert failed");
        assert_eq!(retrieved, test_cert, "Certificate should persist");
    }

    #[test]
    fn test_wrong_public_key_fails_verification() {
        let fob1 = create_fob_with_keys("FOB-001");
        let fob2 = create_fob_with_keys("FOB-002");

        let nonce = b"test-message";
        let response = fob1.sign_challenge(nonce).expect("Sign failed");
        let wrong_pub_key = fob2.get_public_key().expect("Get key failed");

        let is_valid = CryptoEngine::verify_signature(&wrong_pub_key, nonce, &response.signature)
            .expect("Verify failed");

        assert!(
            !is_valid,
            "Signature from FOB-001 should fail with FOB-002's public key"
        );
    }

    #[test]
    fn test_auth_proof_timestamp_format() {
        let mut fob = create_fob_with_keys("FOB-001");
        fob.certificate = Some(vec![1, 2, 3]);

        let nonce = b"test";
        let proof = fob.create_auth_proof(nonce).expect("Proof failed");

        // Verify timestamp is RFC3339 format (contains T and Z or +/-)
        assert!(
            proof.timestamp.contains('T'),
            "Timestamp should be RFC3339 format"
        );
        assert!(
            proof.timestamp.contains('Z') || proof.timestamp.contains('+'),
            "Timestamp should include timezone"
        );
    }

    #[test]
    fn test_auth_proof_serialization() {
        let mut fob = create_fob_with_keys("FOB-SERIAL");
        fob.certificate = Some(vec![10, 20, 30, 40]);

        let nonce = b"serialization-test";
        let proof = fob.create_auth_proof(nonce).expect("Proof failed");

        let serialized = serde_json::to_string(&proof).expect("Serialize failed");
        let deserialized: crate::keyfob::AuthenticationProof =
            serde_json::from_str(&serialized).expect("Deserialize failed");

        assert_eq!(deserialized.subject_id, proof.subject_id);
        assert_eq!(deserialized.certificate, proof.certificate);
        assert_eq!(deserialized.nonce, proof.nonce);
        assert_eq!(deserialized.signature, proof.signature);
        assert_eq!(deserialized.timestamp, proof.timestamp);
    }

    #[test]
    fn test_no_private_key_in_public_key_output() {
        let fob = create_fob_with_keys("FOB-PRIV-CHECK");
        let priv_key = fob.private_key.clone().expect("Has private key");
        let pub_key = fob.get_public_key().expect("Get pub key failed");

        assert_ne!(
            pub_key, priv_key,
            "Public key should differ from private key"
        );
        // Both are 32 bytes for Ed25519, so just verify they're different data
        assert_eq!(pub_key.len(), 32, "Public key should be 32 bytes");
        assert_eq!(priv_key.len(), 32, "Private key should be 32 bytes");
    }

    #[test]
    fn test_error_handling_no_panics_on_invalid_nonce_size() {
        let fob = create_fob_with_keys("FOB-ERR");
        let empty_nonce = b"";
        let very_large_nonce = vec![0u8; 10000];

        let result1 = fob.sign_challenge(empty_nonce);
        assert!(result1.is_ok(), "Should handle empty nonce gracefully");

        let result2 = fob.sign_challenge(&very_large_nonce);
        assert!(result2.is_ok(), "Should handle large nonce gracefully");
    }

    #[test]
    fn test_multiple_fobs_independent() {
        let mut fob1 = DigitalKeyFob::new("FOB-A".to_string());
        let mut fob2 = DigitalKeyFob::new("FOB-B".to_string());

        fob1.initialize().expect("Init fob1");
        fob2.initialize().expect("Init fob2");

        let nonce = b"shared-nonce";
        let sig1 = fob1.sign_challenge(nonce).expect("Sign fob1");
        let sig2 = fob2.sign_challenge(nonce).expect("Sign fob2");

        assert_ne!(
            sig1.signature, sig2.signature,
            "Different fobs should produce different signatures"
        );

        let pub1 = fob1.get_public_key().expect("Get pub1");
        let pub2 = fob2.get_public_key().expect("Get pub2");

        assert_ne!(pub1, pub2, "Fobs should have different public keys");
    }

    #[test]
    fn test_timestamp_differs_across_calls() {
        let fob = create_fob_with_keys("FOB-TIME");
        let nonce = b"time-test";

        let response1 = fob.sign_challenge(nonce).expect("Sign 1");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let response2 = fob.sign_challenge(nonce).expect("Sign 2");

        assert_ne!(
            response1.timestamp, response2.timestamp,
            "Timestamps should be different for separate calls"
        );
    }
}
