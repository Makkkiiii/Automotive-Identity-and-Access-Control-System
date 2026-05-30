/// Vehicle Control Module (VCM)
/// Responsibilities:
/// - Generate cryptographically secure nonce challenges
/// - Track nonce lifecycle (issued, used, expired)
/// - Validate nonce state during authentication
/// - Consume/mark nonces after authentication attempts
use crate::crypto::CryptoEngine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug)]
pub enum VehicleError {
    NonceGenerationFailed(String),
    UnknownNonce(String),
    NonceAlreadyUsed(String),
    NotInitialized,
}

impl std::fmt::Display for VehicleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VehicleError::NonceGenerationFailed(msg) => {
                write!(f, "Nonce generation failed: {}", msg)
            }
            VehicleError::UnknownNonce(msg) => write!(f, "Unknown nonce: {}", msg),
            VehicleError::NonceAlreadyUsed(msg) => write!(f, "Nonce already used: {}", msg),
            VehicleError::NotInitialized => write!(f, "Vehicle not initialized"),
        }
    }
}

impl std::error::Error for VehicleError {}

/// Record of an active nonce with lifecycle information
#[derive(Debug, Clone)]
pub struct NonceRecord {
    pub issued_at: DateTime<Utc>,
    pub used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VehicleControlModule {
    pub vehicle_id: String,
    #[serde(skip)]
    active_nonces: HashMap<Vec<u8>, NonceRecord>,
}

impl VehicleControlModule {
    pub fn new(vehicle_id: String) -> Self {
        Self {
            vehicle_id,
            active_nonces: HashMap::new(),
        }
    }

    pub fn initialize(&mut self) -> Result<(), VehicleError> {
        // Vehicle is ready for operation
        self.active_nonces.clear();
        Ok(())
    }

    /// Generate a cryptographically secure random nonce and track it
    pub fn generate_challenge(&mut self) -> Result<Vec<u8>, VehicleError> {
        // Generate 32-byte random nonce
        let nonce =
            CryptoEngine::generate_random_nonce(32).map_err(VehicleError::NonceGenerationFailed)?;

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

    /// Check if a nonce is still valid (not used and within timeout)
    pub fn is_nonce_valid(&self, nonce: &[u8], timeout_secs: i64) -> Result<bool, VehicleError> {
        if let Some(record) = self.active_nonces.get(nonce) {
            if record.used {
                return Err(VehicleError::NonceAlreadyUsed(
                    "Nonce has already been used".to_string(),
                ));
            }
            let age = (Utc::now() - record.issued_at).num_seconds();
            if age < 0 {
                return Ok(false); // Future timestamp (invalid)
            }
            if age >= timeout_secs {
                return Ok(false); // Expired
            }
            return Ok(true); // Valid
        }
        Err(VehicleError::UnknownNonce(
            "Nonce not issued by this vehicle".to_string(),
        ))
    }

    /// Mark a nonce as used/consumed after authentication attempt
    pub fn mark_nonce_used(&mut self, nonce: &[u8]) -> Result<(), VehicleError> {
        if let Some(record) = self.active_nonces.get_mut(nonce) {
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

    #[test]
    fn test_vehicle_initialization() {
        let mut vcm = VehicleControlModule::new("VEH-001".to_string());
        assert_eq!(vcm.vehicle_id, "VEH-001");
        let result = vcm.initialize();
        assert!(result.is_ok());
    }

    #[test]
    fn test_generate_nonce_challenge() {
        let mut vcm = VehicleControlModule::new("VEH-NONCE".to_string());
        vcm.initialize().expect("Init failed");

        let nonce = vcm.generate_challenge().expect("Nonce generation failed");
        assert_eq!(nonce.len(), 32);
    }

    #[test]
    fn test_generate_nonce_unique() {
        let mut vcm = VehicleControlModule::new("VEH-UNIQUE".to_string());
        vcm.initialize().expect("Init failed");

        let nonce1 = vcm.generate_challenge().expect("Nonce1 gen failed");
        let nonce2 = vcm.generate_challenge().expect("Nonce2 gen failed");

        assert_ne!(nonce1, nonce2, "Each nonce should be unique");
    }

    #[test]
    fn test_nonce_valid_after_generation() {
        let mut vcm = VehicleControlModule::new("VEH-VALID".to_string());
        vcm.initialize().expect("Init failed");

        let nonce = vcm.generate_challenge().expect("Nonce gen failed");
        let is_valid = vcm.is_nonce_valid(&nonce, 60);

        assert!(is_valid.is_ok());
        assert!(is_valid.unwrap());
    }

    #[test]
    fn test_unknown_nonce_rejected() {
        let vcm = VehicleControlModule::new("VEH-UNKNOWN".to_string());

        let fake_nonce = vec![0u8; 32];
        let result = vcm.is_nonce_valid(&fake_nonce, 60);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VehicleError::UnknownNonce(_)));
    }

    #[test]
    fn test_mark_nonce_used() {
        let mut vcm = VehicleControlModule::new("VEH-MARK".to_string());
        vcm.initialize().expect("Init failed");

        let nonce = vcm.generate_challenge().expect("Nonce gen failed");

        // Initially valid
        assert!(vcm.is_nonce_valid(&nonce, 60).unwrap());

        // Mark as used
        vcm.mark_nonce_used(&nonce).expect("Mark used failed");

        // Should now be rejected
        let result = vcm.is_nonce_valid(&nonce, 60);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            VehicleError::NonceAlreadyUsed(_)
        ));
    }

    #[test]
    fn test_reused_nonce_rejected() {
        let mut vcm = VehicleControlModule::new("VEH-REUSE".to_string());
        vcm.initialize().expect("Init failed");

        let nonce = vcm.generate_challenge().expect("Nonce gen failed");

        // First check succeeds
        assert!(vcm.is_nonce_valid(&nonce, 60).unwrap());

        // Mark as used
        vcm.mark_nonce_used(&nonce).expect("Mark used failed");

        // Second check should fail
        let result = vcm.is_nonce_valid(&nonce, 60);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_nonces_independent() {
        let mut vcm = VehicleControlModule::new("VEH-MULTI".to_string());
        vcm.initialize().expect("Init failed");

        let nonce1 = vcm.generate_challenge().expect("Nonce1 gen failed");
        let nonce2 = vcm.generate_challenge().expect("Nonce2 gen failed");
        let nonce3 = vcm.generate_challenge().expect("Nonce3 gen failed");

        // All should be valid
        assert!(vcm.is_nonce_valid(&nonce1, 60).unwrap());
        assert!(vcm.is_nonce_valid(&nonce2, 60).unwrap());
        assert!(vcm.is_nonce_valid(&nonce3, 60).unwrap());

        // Mark nonce1 as used
        vcm.mark_nonce_used(&nonce1).expect("Mark used failed");

        // Nonce1 should be rejected, others still valid
        assert!(vcm.is_nonce_valid(&nonce1, 60).is_err());
        assert!(vcm.is_nonce_valid(&nonce2, 60).unwrap());
        assert!(vcm.is_nonce_valid(&nonce3, 60).unwrap());
    }

    #[test]
    fn test_nonce_timeout_validation() {
        let mut vcm = VehicleControlModule::new("VEH-TIMEOUT".to_string());
        vcm.initialize().expect("Init failed");

        let nonce = vcm.generate_challenge().expect("Nonce gen failed");

        // Valid with long timeout
        assert!(vcm.is_nonce_valid(&nonce, 3600).unwrap());

        // Invalid with zero timeout (age is immediate)
        assert!(!vcm.is_nonce_valid(&nonce, 0).unwrap());
    }

    #[test]
    fn test_mark_unknown_nonce_fails() {
        let mut vcm = VehicleControlModule::new("VEH-MARK-FAIL".to_string());

        let fake_nonce = vec![0u8; 32];
        let result = vcm.mark_nonce_used(&fake_nonce);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VehicleError::UnknownNonce(_)));
    }

    #[test]
    fn test_no_panics_on_edge_cases() {
        let mut vcm = VehicleControlModule::new("VEH-PANIC".to_string());
        vcm.initialize().expect("Init failed");

        // Empty nonce
        let empty_nonce = vec![];
        let _ = vcm.is_nonce_valid(&empty_nonce, 60);

        // Large timeout
        let nonce = vcm.generate_challenge().expect("Nonce gen failed");
        let _ = vcm.is_nonce_valid(&nonce, i64::MAX);

        // Zero timeout
        let _ = vcm.is_nonce_valid(&nonce, 0);

        // Main thing: no panic occurred
    }
}
