/// Digital Key Fob Module (DKF)
/// Responsibilities:
/// - Store private key
/// - Receive challenge
/// - Sign nonce
/// - Participate in secure session

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalKeyFob {
    pub fob_id: String,
    pub private_key: Option<Vec<u8>>,
    pub certificate: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub signature: Vec<u8>,
    pub timestamp: String,
}

impl DigitalKeyFob {
    pub fn new(fob_id: String) -> Self {
        Self {
            fob_id,
            private_key: None,
            certificate: None,
        }
    }

    pub fn load_private_key(&mut self, key: Vec<u8>) -> Result<(), String> {
        self.private_key = Some(key);
        Ok(())
    }

    pub fn load_certificate(&mut self, cert: Vec<u8>) -> Result<(), String> {
        self.certificate = Some(cert);
        Ok(())
    }

    pub fn sign_challenge(&self, nonce: &[u8]) -> Result<ChallengeResponse, String> {
        Err("Not implemented".to_string())
    }

    pub fn get_certificate(&self) -> Result<Vec<u8>, String> {
        Err("Not implemented".to_string())
    }
}
