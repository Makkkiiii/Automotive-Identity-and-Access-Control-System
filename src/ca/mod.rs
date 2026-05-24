/// Certificate Authority Module
/// Responsibilities:
/// - Generate root CA keypair
/// - Issue certificates to key fobs
/// - Validate certificate chains
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuthority {
    pub name: String,
    pub root_public_key: Option<Vec<u8>>,
    pub root_private_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub not_before: String,
    pub not_after: String,
}

impl CertificateAuthority {
    pub fn new(name: String) -> Self {
        Self {
            name,
            root_public_key: None,
            root_private_key: None,
        }
    }

    pub fn initialize(&mut self) -> Result<(), String> {
        Err("Not implemented".to_string())
    }

    pub fn issue_certificate(&self, subject: String) -> Result<Certificate, String> {
        Err("Not implemented".to_string())
    }

    pub fn validate_chain(&self, cert: &Certificate) -> Result<bool, String> {
        Err("Not implemented".to_string())
    }
}
