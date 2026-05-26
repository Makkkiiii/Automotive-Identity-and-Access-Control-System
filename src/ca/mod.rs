use crate::crypto::CryptoEngine;
use chrono::Utc;
/// Certificate Authority Module
/// Responsibilities:
/// - Generate root CA keypair
/// - Issue certificates to key fobs
/// - Validate certificate chains
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthority {
    pub name: String,
    pub root_public_key: Option<Vec<u8>>,
    pub root_private_key: Option<Vec<u8>>,
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
        let keypair =
            CryptoEngine::generate_ed25519_keypair().map_err(|e| CAError::KeygenFailed(e))?;

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
            .map_err(|e| CAError::SigningFailed(e))?;

        Ok(Certificate {
            subject_id,
            public_key,
            issuer: self.name.clone(),
            issued_at,
            expires_at,
            signature: signature.data,
        })
    }

    /// Validate a certificate's signature using CA public key
    pub fn validate_chain(&self, cert: &Certificate) -> Result<bool, CAError> {
        let root_public_key = self
            .root_public_key
            .as_ref()
            .ok_or(CAError::NotInitialized)?;

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
            .map_err(|e| CAError::VerificationFailed(e))
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
