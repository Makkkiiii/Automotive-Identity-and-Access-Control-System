/// Vehicle Control Module (VCM)
/// Responsibilities:
/// - Generate nonce challenges
/// - Verify certificate chains
/// - Verify Ed25519 signatures
/// - Implement challenge-response authentication
use crate::ca::{Certificate, CertificateAuthority};
use crate::crypto::CryptoEngine;
use crate::keyfob::AuthenticationProof;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug)]
pub enum VehicleError {
    NonceGenerationFailed(String),
    CertificateVerificationFailed(String),
    UnknownNonce(String),
    NonceAlreadyUsed(String),
    StaleTimestamp(String),
    InvalidSignature(String),
    FakeCertificate(String),
    TamperedNonce(String),
    SerializationError(String),
    NotInitialized,
}

impl std::fmt::Display for VehicleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VehicleError::NonceGenerationFailed(msg) => {
                write!(f, "Nonce generation failed: {}", msg)
            }
            VehicleError::CertificateVerificationFailed(msg) => {
                write!(f, "Certificate verification failed: {}", msg)
            }
            VehicleError::UnknownNonce(msg) => write!(f, "Unknown nonce: {}", msg),
            VehicleError::NonceAlreadyUsed(msg) => write!(f, "Nonce already used: {}", msg),
            VehicleError::StaleTimestamp(msg) => write!(f, "Stale timestamp: {}", msg),
            VehicleError::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            VehicleError::FakeCertificate(msg) => write!(f, "Fake certificate: {}", msg),
            VehicleError::TamperedNonce(msg) => write!(f, "Tampered nonce: {}", msg),
            VehicleError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            VehicleError::NotInitialized => write!(f, "Vehicle not initialized"),
        }
    }
}

impl std::error::Error for VehicleError {}

/// Record of an active nonce
#[derive(Debug, Clone)]
struct NonceRecord {
    issued_at: DateTime<Utc>,
    used: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AccessGrant {
    Granted,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VehicleControlModule {
    pub vehicle_id: String,
    pub session_active: bool,
    #[serde(skip)]
    active_nonces: HashMap<Vec<u8>, NonceRecord>,
}

impl VehicleControlModule {
    pub fn new(vehicle_id: String) -> Self {
        Self {
            vehicle_id,
            session_active: false,
            active_nonces: HashMap::new(),
        }
    }

    pub fn initialize(&mut self) -> Result<(), VehicleError> {
        // Vehicle is ready for operation
        self.active_nonces.clear();
        Ok(())
    }

    /// Generate a random nonce challenge and track it
    pub fn generate_challenge(&mut self) -> Result<Vec<u8>, VehicleError> {
        // Generate 32-byte random nonce
        let nonce = CryptoEngine::generate_random_nonce(32)
            .map_err(|e| VehicleError::NonceGenerationFailed(e))?;

        // Track the nonce with current timestamp
        self.active_nonces.insert(
            nonce.clone(),
            NonceRecord {
                issued_at: Utc::now(),
                used: false,
            },
        );

        Ok(nonce)
    }

    /// Verify authentication proof from a key fob
    /// Validation steps:
    /// 1. Verify certificate is trusted and not expired
    /// 2. Confirm nonce was issued by vehicle
    /// 3. Confirm nonce has not been used before
    /// 4. Confirm response timestamp is within freshness timeout
    /// 5. Verify Ed25519 signature over the nonce
    /// 6. Mark nonce as used
    pub fn verify_authentication_proof(
        &mut self,
        proof: &AuthenticationProof,
        ca: &CertificateAuthority,
        timeout_secs: i64,
    ) -> Result<AccessGrant, VehicleError> {
        // Step 1: Verify certificate is trusted and not expired
        let cert: Certificate = serde_json::from_slice(&proof.certificate)
            .map_err(|e| VehicleError::SerializationError(e.to_string()))?;

        ca.validate_chain(&cert)
            .map_err(|e| VehicleError::CertificateVerificationFailed(e.to_string()))?;

        // Step 2: Confirm nonce was issued by vehicle (exists in active_nonces)
        if !self.active_nonces.contains_key(&proof.nonce) {
            return Err(VehicleError::UnknownNonce(format!(
                "Nonce not issued by this vehicle"
            )));
        }

        let mut nonce_record = self
            .active_nonces
            .get_mut(&proof.nonce)
            .ok_or_else(|| VehicleError::UnknownNonce("Nonce disappeared".to_string()))?;

        // Step 3: Confirm nonce has not been used before
        if nonce_record.used {
            return Err(VehicleError::NonceAlreadyUsed(
                "Nonce has already been used".to_string(),
            ));
        }

        // Step 4: Confirm response timestamp is within freshness timeout
        let response_time = DateTime::parse_from_rfc3339(&proof.timestamp)
            .map_err(|e| VehicleError::StaleTimestamp(format!("Invalid timestamp format: {}", e)))?
            .with_timezone(&Utc);

        let now = Utc::now();
        let time_diff = (now - response_time).num_seconds();

        if time_diff < 0 || time_diff > timeout_secs {
            return Err(VehicleError::StaleTimestamp(format!(
                "Timestamp outside freshness window ({} seconds)",
                timeout_secs
            )));
        }

        // Step 5: Verify Ed25519 signature over the nonce using certified public key
        CryptoEngine::verify_signature(&cert.public_key, &proof.nonce, &proof.signature)
            .map_err(|e| VehicleError::InvalidSignature(e))?;

        // Step 6: Mark nonce as used
        nonce_record.used = true;

        Ok(AccessGrant::Granted)
    }

    /// Check if a nonce is still valid (not used and within timeout)
    pub fn is_nonce_valid(&self, nonce: &[u8], timeout_secs: i64) -> bool {
        if let Some(record) = self.active_nonces.get(nonce) {
            if record.used {
                return false;
            }
            let age = (Utc::now() - record.issued_at).num_seconds();
            return age >= 0 && age <= timeout_secs;
        }
        false
    }

    /// Mark a nonce as used (for explicit revocation)
    pub fn mark_nonce_used(&mut self, nonce: &[u8]) -> Result<(), VehicleError> {
        if let Some(mut record) = self.active_nonces.get_mut(nonce) {
            record.used = true;
            Ok(())
        } else {
            Err(VehicleError::UnknownNonce("Nonce not found".to_string()))
        }
    }

    pub fn establish_session(&mut self) -> Result<Vec<u8>, VehicleError> {
        Err(VehicleError::NotInitialized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertificateAuthority;
    use crate::keyfob::DigitalKeyFob;

    fn setup_ca_and_fob(fob_id: &str) -> (CertificateAuthority, DigitalKeyFob, Certificate) {
        // Initialize CA
        let mut ca = CertificateAuthority::new("Test-CA".to_string());
        ca.initialize().expect("CA init failed");

        // Initialize key fob
        let mut fob = DigitalKeyFob::new(fob_id.to_string());
        fob.initialize().expect("Fob init failed");

        // Issue certificate
        let cert = ca
            .issue_certificate(fob_id.to_string(), fob.public_key.clone().unwrap())
            .expect("Cert issuance failed");

        // Store certificate in fob
        let cert_json = serde_json::to_vec(&cert).expect("Cert serialization failed");
        fob.certificate = Some(cert_json);

        (ca, fob, cert)
    }

    #[test]
    fn test_vehicle_initialization() {
        let mut vcm = VehicleControlModule::new("VEH-001".to_string());
        assert_eq!(vcm.vehicle_id, "VEH-001");
        assert!(!vcm.session_active);
        let result = vcm.initialize();
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_nonce_challenge() {
        let mut vcm = VehicleControlModule::new("VEH-001".to_string());
        vcm.initialize().expect("Init failed");

        let nonce = vcm.generate_challenge().expect("Nonce generation failed");
        assert_eq!(nonce.len(), 32);
        assert!(vcm.active_nonces.contains_key(&nonce));
    }

    #[test]
    fn test_valid_authentication_accepted() {
        let mut vcm = VehicleControlModule::new("VEH-VALID".to_string());
        vcm.initialize().expect("VCM init failed");

        let (ca, mut fob, _cert) = setup_ca_and_fob("FOB-VALID");

        // Generate nonce
        let nonce = vcm.generate_challenge().expect("Nonce gen failed");

        // Create auth proof
        let proof = fob
            .create_auth_proof(&nonce)
            .expect("Auth proof creation failed");

        // Verify proof
        let result = vcm.verify_authentication_proof(&proof, &ca, 60);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), AccessGrant::Granted);
    }

    #[test]
    fn test_reused_nonce_rejected() {
        let mut vcm = VehicleControlModule::new("VEH-REUSE".to_string());
        vcm.initialize().expect("VCM init failed");

        let (ca, mut fob, _cert) = setup_ca_and_fob("FOB-REUSE");

        // Generate nonce
        let nonce = vcm.generate_challenge().expect("Nonce gen failed");

        // Create auth proof
        let proof1 = fob
            .create_auth_proof(&nonce)
            .expect("Auth proof 1 creation failed");

        // First use should succeed
        let result1 = vcm.verify_authentication_proof(&proof1, &ca, 60);
        assert!(result1.is_ok());

        // Create second proof with same nonce
        let proof2 = fob
            .create_auth_proof(&nonce)
            .expect("Auth proof 2 creation failed");

        // Second use should fail (nonce already used)
        let result2 = vcm.verify_authentication_proof(&proof2, &ca, 60);
        assert!(result2.is_err());
        assert!(matches!(
            result2.unwrap_err(),
            VehicleError::NonceAlreadyUsed(_)
        ));
    }

    #[test]
    fn test_unknown_nonce_rejected() {
        let mut vcm = VehicleControlModule::new("VEH-UNKNOWN".to_string());
        vcm.initialize().expect("VCM init failed");

        let (ca, mut fob, cert) = setup_ca_and_fob("FOB-UNKNOWN");

        // Use a random nonce not issued by vehicle
        let fake_nonce = CryptoEngine::generate_random_nonce(32).expect("Nonce gen failed");

        // Manually create proof with fake nonce
        let proof = AuthenticationProof {
            subject_id: fob.subject_id.clone(),
            certificate: serde_json::to_vec(&cert).expect("Cert serialization failed"),
            nonce: fake_nonce,
            signature: vec![0u8; 64],
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let result = vcm.verify_authentication_proof(&proof, &ca, 60);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VehicleError::UnknownNonce(_)));
    }

    #[test]
    fn test_stale_timestamp_rejected() {
        let mut vcm = VehicleControlModule::new("VEH-STALE".to_string());
        vcm.initialize().expect("VCM init failed");

        let (ca, mut fob, cert) = setup_ca_and_fob("FOB-STALE");

        // Generate nonce
        let nonce = vcm.generate_challenge().expect("Nonce gen failed");

        // Create auth proof but with old timestamp
        let old_time = (Utc::now() - chrono::Duration::seconds(120)).to_rfc3339();
        let signature =
            CryptoEngine::sign_data(&fob.private_key.clone().expect("No priv key"), &nonce)
                .expect("Signing failed");

        let proof = AuthenticationProof {
            subject_id: fob.subject_id.clone(),
            certificate: serde_json::to_vec(&cert).expect("Cert serialization failed"),
            nonce,
            signature: signature.data,
            timestamp: old_time,
        };

        // Verify with 60-second timeout
        let result = vcm.verify_authentication_proof(&proof, &ca, 60);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VehicleError::StaleTimestamp(_)
        ));
    }

    #[test]
    #[test]
    fn test_invalid_signature_rejected() {
        let mut vcm = VehicleControlModule::new("VEH-BADSIG".to_string());
        vcm.initialize().expect("VCM init failed");

        let (ca, mut fob, _cert) = setup_ca_and_fob("FOB-BADSIG");

        // Generate two different nonces
        let nonce1 = vcm.generate_challenge().expect("Nonce1 gen failed");
        let nonce2 = CryptoEngine::generate_random_nonce(32).expect("Nonce2 gen failed");

        // Create proof for nonce1
        let mut proof = fob
            .create_auth_proof(&nonce1)
            .expect("Proof creation failed");

        // But claim it was for nonce2 (signature won't match)
        proof.nonce = nonce2;

        // Verify should fail
        let result = vcm.verify_authentication_proof(&proof, &ca, 60);
        assert!(result.is_err());
        let error = result.unwrap_err();
        // Accept either UnknownNonce (nonce2 not issued) or InvalidSignature (sig doesn't match nonce2)
        assert!(
            matches!(
                error,
                VehicleError::UnknownNonce(_) | VehicleError::InvalidSignature(_)
            ),
            "Got unexpected error: {:?}",
            error
        );
    }

    #[test]
    fn test_certificate_expired_rejected() {
        let mut vcm = VehicleControlModule::new("VEH-EXPIRED".to_string());
        vcm.initialize().expect("VCM init failed");

        let (mut ca, mut fob, _cert_good) = setup_ca_and_fob("FOB-EXPIRED");

        // Generate nonce
        let nonce = vcm.generate_challenge().expect("Nonce gen failed");

        // Create a manually constructed proof with an expired certificate
        // We'll create an expired cert by mocking the data
        let expired_at_str = (Utc::now() - chrono::Duration::days(30)).to_rfc3339();
        let issued_at_str = (Utc::now() - chrono::Duration::days(400)).to_rfc3339();

        // Create signable data with past dates
        let mut signable_data = Vec::new();
        signable_data.extend_from_slice(fob.subject_id.as_bytes());
        signable_data.extend_from_slice(b"|");
        signable_data.extend_from_slice(&fob.public_key.clone().unwrap());
        signable_data.extend_from_slice(b"|");
        signable_data.extend_from_slice(b"Test-CA");
        signable_data.extend_from_slice(b"|");
        signable_data.extend_from_slice(issued_at_str.as_bytes());
        signable_data.extend_from_slice(b"|");
        signable_data.extend_from_slice(expired_at_str.as_bytes());

        // Sign it with CA's private key
        let sig = CryptoEngine::sign_data(&ca.root_private_key.clone().unwrap(), &signable_data)
            .expect("Signing failed");

        // Create expired certificate
        let expired_cert = Certificate {
            subject_id: fob.subject_id.clone(),
            public_key: fob.public_key.clone().unwrap(),
            issuer: "Test-CA".to_string(),
            issued_at: issued_at_str,
            expires_at: expired_at_str,
            signature: sig.data,
        };

        // Create proof with expired certificate
        let proof = AuthenticationProof {
            subject_id: fob.subject_id.clone(),
            certificate: serde_json::to_vec(&expired_cert).expect("Cert serialization failed"),
            nonce,
            signature: CryptoEngine::generate_random_nonce(64).expect("Sig gen"),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        // Verify should fail
        let result = vcm.verify_authentication_proof(&proof, &ca, 60);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VehicleError::CertificateVerificationFailed(_)
        ));
    }

    #[test]
    fn test_tampered_nonce_rejected() {
        let mut vcm = VehicleControlModule::new("VEH-TAMPER".to_string());
        vcm.initialize().expect("VCM init failed");

        let (ca, mut fob, _cert) = setup_ca_and_fob("FOB-TAMPER");

        // Generate nonce
        let nonce = vcm.generate_challenge().expect("Nonce gen failed");

        // Create valid proof
        let proof = fob
            .create_auth_proof(&nonce)
            .expect("Proof creation failed");

        // Tamper with nonce in proof (makes it different from tracked nonce)
        let mut tampered_proof = proof;
        tampered_proof.nonce[0] ^= 0xFF; // Flip bits in first byte

        // Verify should fail (either UnknownNonce or InvalidSignature is fine)
        let result = vcm.verify_authentication_proof(&tampered_proof, &ca, 60);
        assert!(result.is_err());
        // Either error type is acceptable - nonce doesn't match what was signed
        let error = result.unwrap_err();
        assert!(
            matches!(
                error,
                VehicleError::UnknownNonce(_) | VehicleError::InvalidSignature(_)
            ),
            "Unexpected error type: {:?}",
            error
        );
    }

    #[test]
    fn test_error_handling_no_panics() {
        let mut vcm = VehicleControlModule::new("VEH-PANIC".to_string());
        vcm.initialize().expect("VCM init failed");

        // Generate a nonce
        let _nonce = vcm.generate_challenge().expect("Nonce gen failed");

        // Try to verify with empty proof fields - should not panic
        let bad_proof = AuthenticationProof {
            subject_id: "BAD".to_string(),
            certificate: vec![],
            nonce: vec![],
            signature: vec![],
            timestamp: "invalid".to_string(),
        };

        let (ca, _fob, _cert) = setup_ca_and_fob("FOB-PANIC");

        let result = vcm.verify_authentication_proof(&bad_proof, &ca, 60);
        assert!(result.is_err());
        // Main thing: no panic occurred
    }

    #[test]
    fn test_multiple_nonces_tracked_independently() {
        let mut vcm = VehicleControlModule::new("VEH-MULTI".to_string());
        vcm.initialize().expect("VCM init failed");

        let (ca, mut fob, _cert) = setup_ca_and_fob("FOB-MULTI");

        // Generate multiple nonces
        let nonce1 = vcm.generate_challenge().expect("Nonce1 gen failed");
        let nonce2 = vcm.generate_challenge().expect("Nonce2 gen failed");
        let nonce3 = vcm.generate_challenge().expect("Nonce3 gen failed");

        // Verify first nonce
        let proof1 = fob
            .create_auth_proof(&nonce1)
            .expect("Proof1 creation failed");
        let result1 = vcm.verify_authentication_proof(&proof1, &ca, 60);
        assert!(result1.is_ok());

        // Nonce1 should be marked used
        assert!(!vcm.is_nonce_valid(&nonce1, 60));

        // Nonce2 and Nonce3 should still be valid
        assert!(vcm.is_nonce_valid(&nonce2, 60));
        assert!(vcm.is_nonce_valid(&nonce3, 60));

        // Can still use nonce2
        let proof2 = fob
            .create_auth_proof(&nonce2)
            .expect("Proof2 creation failed");
        let result2 = vcm.verify_authentication_proof(&proof2, &ca, 60);
        assert!(result2.is_ok());
    }

    #[test]
    fn test_nonce_validity_timeout() {
        let mut vcm = VehicleControlModule::new("VEH-TIMEOUT".to_string());
        vcm.initialize().expect("VCM init failed");

        // Generate nonce
        let nonce = vcm.generate_challenge().expect("Nonce gen failed");

        // Should be valid with long timeout
        assert!(vcm.is_nonce_valid(&nonce, 60));

        // Should not be valid after marking as used
        vcm.mark_nonce_used(&nonce).expect("Mark used failed");
        assert!(!vcm.is_nonce_valid(&nonce, 60));

        // Generate another nonce
        let nonce2 = vcm.generate_challenge().expect("Nonce2 gen failed");
        // New nonce should be valid
        assert!(vcm.is_nonce_valid(&nonce2, 60));
    }
}
