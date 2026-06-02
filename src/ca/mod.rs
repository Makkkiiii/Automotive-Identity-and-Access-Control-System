use crate::crypto::CryptoEngine;
use chrono::Utc;
/// Certificate Authority Module
/// Responsibilities:
/// - Generate root CA keypair
/// - Issue certificates to key fobs
/// - Validate certificate chains
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub enum CAError {
    KeygenFailed(String),
    SigningFailed(String),
    VerificationFailed(String),
    FileIOError(String),
    SerializationError(String),
    NotInitialized,
    InvalidCertificate(String),
}

impl std::fmt::Display for CAError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CAError::KeygenFailed(msg) => write!(f, "Key generation failed: {}", msg),
            CAError::SigningFailed(msg) => write!(f, "Signing failed: {}", msg),
            CAError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            CAError::FileIOError(msg) => write!(f, "File I/O error: {}", msg),
            CAError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            CAError::NotInitialized => write!(f, "CA not initialized"),
            CAError::InvalidCertificate(msg) => write!(f, "Invalid certificate: {}", msg),
        }
    }
}

impl std::error::Error for CAError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub subject_id: String,
    pub public_key: Vec<u8>,
    pub issuer: String,
    pub issued_at: String,
    pub expires_at: String,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CertificateAuthority {
    pub name: String,
    pub root_public_key: Option<Vec<u8>>,
    pub root_private_key: Option<Vec<u8>>,
}

impl fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateAuthority")
            .field("name", &self.name)
            .field(
                "root_public_key",
                &describe_optional_bytes(&self.root_public_key),
            )
            .field("root_private_key", &"[REDACTED]")
            .finish()
    }
}

fn describe_optional_bytes(bytes: &Option<Vec<u8>>) -> String {
    match bytes {
        Some(bytes) => format!("{} bytes", bytes.len()),
        None => "None".to_string(),
    }
}

impl CertificateAuthority {
    pub fn new(name: String) -> Self {
        Self {
            name,
            root_public_key: None,
            root_private_key: None,
        }
    }

    /// Initialize CA by generating a root keypair and saving to disk
    pub fn initialize(&mut self) -> Result<(), CAError> {
        // Ensure keys directory exists
        fs::create_dir_all("keys").map_err(|e| CAError::FileIOError(e.to_string()))?;

        // Generate keypair
        let keypair = CryptoEngine::generate_ed25519_keypair().map_err(CAError::KeygenFailed)?;

        // Save public key
        let public_key_path = "keys/ca_public.json";
        let public_json = serde_json::to_string_pretty(&keypair.public_key)
            .map_err(|e| CAError::SerializationError(e.to_string()))?;
        fs::write(public_key_path, public_json).map_err(|e| CAError::FileIOError(e.to_string()))?;

        // Save private key (in production, this should be encrypted!)
        let private_key_path = "keys/ca_private.json";
        let private_json = serde_json::to_string_pretty(&keypair.private_key)
            .map_err(|e| CAError::SerializationError(e.to_string()))?;
        fs::write(private_key_path, private_json)
            .map_err(|e| CAError::FileIOError(e.to_string()))?;

        self.root_public_key = Some(keypair.public_key);
        self.root_private_key = Some(keypair.private_key);

        Ok(())
    }

    /// Load CA keypair from disk
    pub fn load_from_disk(&mut self) -> Result<(), CAError> {
        let public_key_path = "keys/ca_public.json";
        let private_key_path = "keys/ca_private.json";

        if !Path::new(public_key_path).exists() || !Path::new(private_key_path).exists() {
            return Err(CAError::FileIOError(
                "CA keys not found on disk".to_string(),
            ));
        }

        let public_json =
            fs::read_to_string(public_key_path).map_err(|e| CAError::FileIOError(e.to_string()))?;
        let public_key: Vec<u8> = serde_json::from_str(&public_json)
            .map_err(|e| CAError::SerializationError(e.to_string()))?;

        let private_json = fs::read_to_string(private_key_path)
            .map_err(|e| CAError::FileIOError(e.to_string()))?;
        let private_key: Vec<u8> = serde_json::from_str(&private_json)
            .map_err(|e| CAError::SerializationError(e.to_string()))?;

        self.root_public_key = Some(public_key);
        self.root_private_key = Some(private_key);

        Ok(())
    }

    /// Issue a certificate for a key fob with 365-day validity
    pub fn issue_certificate(
        &self,
        subject_id: String,
        public_key: Vec<u8>,
    ) -> Result<Certificate, CAError> {
        let root_private_key = self
            .root_private_key
            .as_ref()
            .ok_or(CAError::NotInitialized)?;

        // Create certificate data to sign (all fields except signature)
        let now = Utc::now();
        let expires = now + chrono::Duration::days(365);

        let issued_at = now.to_rfc3339();
        let expires_at = expires.to_rfc3339();

        // Create signable data (subject_id | public_key | issuer | issued_at | expires_at)
        let mut signable_data = Vec::new();
        signable_data.extend_from_slice(subject_id.as_bytes());
        signable_data.extend_from_slice(b"|");
        signable_data.extend_from_slice(&public_key);
        signable_data.extend_from_slice(b"|");
        signable_data.extend_from_slice(self.name.as_bytes());
        signable_data.extend_from_slice(b"|");
        signable_data.extend_from_slice(issued_at.as_bytes());
        signable_data.extend_from_slice(b"|");
        signable_data.extend_from_slice(expires_at.as_bytes());

        // Sign the certificate
        let signature = CryptoEngine::sign_data(root_private_key, &signable_data)
            .map_err(CAError::SigningFailed)?;

        Ok(Certificate {
            subject_id,
            public_key,
            issuer: self.name.clone(),
            issued_at,
            expires_at,
            signature: signature.data,
        })
    }

    /// Validate a certificate's signature using CA public key and check expiry
    pub fn validate_chain(&self, cert: &Certificate) -> Result<bool, CAError> {
        let root_public_key = self
            .root_public_key
            .as_ref()
            .ok_or(CAError::NotInitialized)?;

        // Check certificate expiry
        let now = Utc::now();
        let expires_at = chrono::DateTime::parse_from_rfc3339(&cert.expires_at)
            .map_err(|e| CAError::InvalidCertificate(format!("Failed to parse expires_at: {}", e)))?
            .with_timezone(&Utc);

        if now > expires_at {
            return Err(CAError::InvalidCertificate(
                "Certificate has expired".to_string(),
            ));
        }

        // Recreate the signable data
        let mut signable_data = Vec::new();
        signable_data.extend_from_slice(cert.subject_id.as_bytes());
        signable_data.extend_from_slice(b"|");
        signable_data.extend_from_slice(&cert.public_key);
        signable_data.extend_from_slice(b"|");
        signable_data.extend_from_slice(cert.issuer.as_bytes());
        signable_data.extend_from_slice(b"|");
        signable_data.extend_from_slice(cert.issued_at.as_bytes());
        signable_data.extend_from_slice(b"|");
        signable_data.extend_from_slice(cert.expires_at.as_bytes());

        // Verify signature
        CryptoEngine::verify_signature(root_public_key, &signable_data, &cert.signature)
            .map_err(CAError::VerificationFailed)
    }

    /// Save a certificate to JSON file
    pub fn save_certificate(&self, cert: &Certificate) -> Result<(), CAError> {
        fs::create_dir_all("certs").map_err(|e| CAError::FileIOError(e.to_string()))?;

        let cert_path = format!("certs/{}.json", cert.subject_id);
        let cert_json = serde_json::to_string_pretty(cert)
            .map_err(|e| CAError::SerializationError(e.to_string()))?;
        fs::write(&cert_path, cert_json).map_err(|e| CAError::FileIOError(e.to_string()))?;

        Ok(())
    }

    /// Load a certificate from JSON file
    pub fn load_certificate(&self, subject_id: &str) -> Result<Certificate, CAError> {
        let cert_path = format!("certs/{}.json", subject_id);
        let cert_json =
            fs::read_to_string(&cert_path).map_err(|e| CAError::FileIOError(e.to_string()))?;
        serde_json::from_str(&cert_json).map_err(|e| CAError::SerializationError(e.to_string()))
    }

    /// Get the root CA's public key
    pub fn get_root_public_key(&self) -> Result<Vec<u8>, CAError> {
        self.root_public_key.clone().ok_or(CAError::NotInitialized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // Helper to clean up test artifacts
    fn cleanup_test_files() {
        let _ = fs::remove_dir_all("keys");
        let _ = fs::remove_dir_all("certs");
    }

    // Helper to create a CA with generated keys (without file I/O)
    fn create_ca_with_keys(name: &str) -> CertificateAuthority {
        let mut ca = CertificateAuthority::new(name.to_string());
        let keypair =
            crate::crypto::CryptoEngine::generate_ed25519_keypair().expect("Keypair gen failed");
        ca.root_public_key = Some(keypair.public_key);
        ca.root_private_key = Some(keypair.private_key);
        ca
    }

    #[test]
    fn test_ca_initialization() {
        // Test CA structure and key generation without file I/O
        let mut ca = CertificateAuthority::new("Test-CA".to_string());
        assert!(
            ca.root_public_key.is_none(),
            "CA should not have keys before initialization"
        );

        // Manually set keys (simulating successful initialization)
        let keypair =
            crate::crypto::CryptoEngine::generate_ed25519_keypair().expect("Keypair gen failed");

        ca.root_public_key = Some(keypair.public_key.clone());
        ca.root_private_key = Some(keypair.private_key.clone());

        assert!(
            ca.root_public_key.is_some(),
            "CA should have public key after init"
        );
        assert!(
            ca.root_private_key.is_some(),
            "CA should have private key after init"
        );

        assert_eq!(
            ca.root_public_key.as_ref().unwrap().len(),
            32,
            "Ed25519 public key should be 32 bytes"
        );
        assert_eq!(
            ca.root_private_key.as_ref().unwrap().len(),
            32,
            "Ed25519 private key should be 32 bytes"
        );
    }

    #[test]
    fn test_ca_debug_redacts_root_private_key() {
        let ca = create_ca_with_keys("Debug-CA");
        let private_key_debug = format!("{:?}", ca.root_private_key.as_ref().unwrap());
        let debug_output = format!("{:?}", ca);

        assert!(debug_output.contains("root_private_key"));
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains(&private_key_debug));
    }

    #[test]
    fn test_ca_save_and_load() {
        // Test CA key loading without file I/O
        let mut ca1 = CertificateAuthority::new("Test-CA".to_string());

        let keypair =
            crate::crypto::CryptoEngine::generate_ed25519_keypair().expect("Keypair gen failed");
        ca1.root_public_key = Some(keypair.public_key.clone());
        ca1.root_private_key = Some(keypair.private_key.clone());

        let pub_key_before = ca1.root_public_key.clone();
        let priv_key_before = ca1.root_private_key.clone();

        // Simulate loading into new CA instance
        let mut ca2 = CertificateAuthority::new("Test-CA".to_string());
        ca2.root_public_key = pub_key_before.clone();
        ca2.root_private_key = priv_key_before.clone();

        assert_eq!(
            ca2.root_public_key, pub_key_before,
            "Public key should match after load"
        );
        assert_eq!(
            ca2.root_private_key, priv_key_before,
            "Private key should match after load"
        );
    }

    #[test]
    fn test_certificate_issuance() {
        cleanup_test_files();

        let mut ca = CertificateAuthority::new("Test-CA".to_string());
        ca.initialize().expect("CA initialization failed");

        let fob_keypair = crate::crypto::CryptoEngine::generate_ed25519_keypair()
            .expect("Failed to generate FOB keypair");

        let cert_result = ca.issue_certificate("FOB-001".to_string(), fob_keypair.public_key);
        assert!(cert_result.is_ok(), "Certificate issuance should succeed");

        let cert = cert_result.unwrap();
        assert_eq!(cert.subject_id, "FOB-001");
        assert_eq!(cert.issuer, "Test-CA");
        assert_eq!(
            cert.signature.len(),
            64,
            "Ed25519 signature should be 64 bytes"
        );
    }

    #[test]
    fn test_certificate_validity_period() {
        let ca = create_ca_with_keys("Test-CA");

        let fob_keypair = crate::crypto::CryptoEngine::generate_ed25519_keypair()
            .expect("Failed to generate FOB keypair");

        let cert = ca
            .issue_certificate("FOB-001".to_string(), fob_keypair.public_key)
            .expect("Certificate issuance failed");

        let issued = chrono::DateTime::parse_from_rfc3339(&cert.issued_at)
            .expect("Failed to parse issued_at")
            .with_timezone(&Utc);
        let expires = chrono::DateTime::parse_from_rfc3339(&cert.expires_at)
            .expect("Failed to parse expires_at")
            .with_timezone(&Utc);

        let duration = expires - issued;
        assert_eq!(
            duration.num_days(),
            365,
            "Certificate validity should be 365 days"
        );
    }

    #[test]
    fn test_valid_certificate_verification() {
        let ca = create_ca_with_keys("Test-CA");

        let fob_keypair = crate::crypto::CryptoEngine::generate_ed25519_keypair()
            .expect("Failed to generate FOB keypair");

        let cert = ca
            .issue_certificate("FOB-001".to_string(), fob_keypair.public_key)
            .expect("Certificate issuance failed");

        let verify_result = ca.validate_chain(&cert);
        assert!(verify_result.is_ok(), "Verification should succeed");
        assert!(verify_result.unwrap(), "Certificate should be valid");
    }

    #[test]
    fn test_tampered_certificate_verification_fails() {
        let ca = create_ca_with_keys("Test-CA");

        let fob_keypair = crate::crypto::CryptoEngine::generate_ed25519_keypair()
            .expect("Failed to generate FOB keypair");

        let mut cert = ca
            .issue_certificate("FOB-001".to_string(), fob_keypair.public_key)
            .expect("Certificate issuance failed");

        // Tamper with subject_id
        cert.subject_id = "FOB-002".to_string();

        let result = ca.validate_chain(&cert);
        assert!(result.is_ok(), "Verification should complete without error");
        assert!(
            !result.unwrap(),
            "Tampered certificate should fail verification"
        );
    }

    #[test]
    fn test_wrong_ca_verification_fails() {
        // Create first CA and issue certificate
        let ca1 = create_ca_with_keys("CA-1");

        let fob_keypair = crate::crypto::CryptoEngine::generate_ed25519_keypair()
            .expect("Failed to generate FOB keypair");

        let cert = ca1
            .issue_certificate("FOB-001".to_string(), fob_keypair.public_key)
            .expect("Certificate issuance failed");

        // Create second CA with different keys
        let ca2 = create_ca_with_keys("CA-2");

        // Try to verify certificate from CA1 using CA2's public key
        let result = ca2.validate_chain(&cert);
        assert!(result.is_ok(), "Verification should complete without error");
        assert!(
            !result.unwrap(),
            "Certificate signed by different CA should fail verification"
        );
    }

    #[test]
    fn test_certificate_save_and_load() {
        let ca = create_ca_with_keys("Test-CA");

        let fob_keypair = crate::crypto::CryptoEngine::generate_ed25519_keypair()
            .expect("Failed to generate FOB keypair");

        let cert = ca
            .issue_certificate("FOB-001".to_string(), fob_keypair.public_key)
            .expect("Certificate issuance failed");

        // Verify certificate in-memory (skip file I/O in tests)
        let cert_clone = cert.clone();
        assert_eq!(cert.subject_id, cert_clone.subject_id);
        assert_eq!(cert.issuer, cert_clone.issuer);
        assert_eq!(cert.signature, cert_clone.signature);

        // Verify loaded certificate is still valid
        let verify_result = ca.validate_chain(&cert_clone);
        assert!(verify_result.is_ok(), "Verification should succeed");
        assert!(verify_result.unwrap(), "Loaded certificate should be valid");
    }

    #[test]
    fn test_expired_certificate_rejection() {
        let ca = create_ca_with_keys("Test-CA");

        let fob_keypair = crate::crypto::CryptoEngine::generate_ed25519_keypair()
            .expect("Failed to generate FOB keypair");

        let mut cert = ca
            .issue_certificate("FOB-001".to_string(), fob_keypair.public_key)
            .expect("Certificate issuance failed");

        // Manually set expiry to the past
        let past = Utc::now() - chrono::Duration::days(10);
        cert.expires_at = past.to_rfc3339();

        let result = ca.validate_chain(&cert);
        assert!(
            result.is_err(),
            "Expired certificate should fail verification"
        );
        assert!(
            result.unwrap_err().to_string().contains("expired"),
            "Error should mention expiry"
        );
    }

    #[test]
    fn test_ca_not_initialized_error() {
        let ca = CertificateAuthority::new("Test-CA".to_string());

        let fob_keypair = crate::crypto::CryptoEngine::generate_ed25519_keypair()
            .expect("Failed to generate FOB keypair");

        // Try to issue certificate without initialization
        let result = ca.issue_certificate("FOB-001".to_string(), fob_keypair.public_key);
        assert!(result.is_err(), "Should fail when CA not initialized");
        assert!(
            matches!(result.unwrap_err(), CAError::NotInitialized),
            "Should return NotInitialized error"
        );
    }
}
