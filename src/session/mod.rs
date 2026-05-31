use crate::crypto::{CryptoEngine, EncryptedPayload};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const SESSION_CONTEXT_PREFIX: &str = "AIACS_SESSION_V1";
const SESSION_AES_KEY_LEN: usize = 32;
const SESSION_NONCE_LEN: usize = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub vehicle_id: String,
    pub subject_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub established: bool,
}

#[derive(Clone)]
pub struct SessionEphemeralKeyPair {
    private_key: StaticSecret,
    pub public_key: X25519PublicKey,
}

impl fmt::Debug for SessionEphemeralKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionEphemeralKeyPair { <redacted> }")
    }
}

#[derive(Clone)]
pub struct SessionKeyMaterial {
    vehicle_ephemeral_public_key: [u8; 32],
    keyfob_ephemeral_public_key: [u8; 32],
    derived_aes_key: [u8; SESSION_AES_KEY_LEN],
}

impl fmt::Debug for SessionKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionKeyMaterial { <redacted> }")
    }
}

impl SessionKeyMaterial {
    pub fn key_lengths(&self) -> (usize, usize, usize) {
        (
            self.vehicle_ephemeral_public_key.len(),
            self.keyfob_ephemeral_public_key.len(),
            self.derived_aes_key.len(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSessionMessage {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
    pub created_at: String,
}

pub struct SessionValidationEngine;

impl SessionValidationEngine {
    pub fn create_session(
        session_id: String,
        vehicle_id: String,
        subject_id: String,
        timeout_seconds: i64,
    ) -> Result<SessionState, String> {
        if timeout_seconds <= 0 {
            return Err("Session timeout must be positive".to_string());
        }

        let created_at = Utc::now();
        let expires_at = created_at + chrono::Duration::seconds(timeout_seconds);

        Ok(SessionState {
            session_id,
            vehicle_id,
            subject_id,
            created_at: created_at.to_rfc3339(),
            expires_at: expires_at.to_rfc3339(),
            established: true,
        })
    }

    pub fn generate_ephemeral_keypair() -> SessionEphemeralKeyPair {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = X25519PublicKey::from(&private_key);

        SessionEphemeralKeyPair {
            private_key,
            public_key,
        }
    }

    pub fn derive_shared_secret(
        private_key: &StaticSecret,
        peer_public_key: &X25519PublicKey,
    ) -> [u8; 32] {
        private_key.diffie_hellman(peer_public_key).to_bytes()
    }

    pub fn derive_session_key(
        shared_secret: &[u8],
        vehicle_id: &str,
        subject_id: &str,
        session_id: &str,
    ) -> Result<[u8; SESSION_AES_KEY_LEN], String> {
        if shared_secret.len() != 32 {
            return Err("Shared secret must be 32 bytes".to_string());
        }

        let mut okm = [0u8; SESSION_AES_KEY_LEN];
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let context = format!(
            "{}|{}|{}|{}",
            SESSION_CONTEXT_PREFIX, vehicle_id, subject_id, session_id
        );

        hkdf.expand(context.as_bytes(), &mut okm)
            .map_err(|_| "Failed to derive session key".to_string())?;

        Ok(okm)
    }

    pub fn build_session_key_material(
        vehicle_ephemeral_public_key: &X25519PublicKey,
        keyfob_ephemeral_public_key: &X25519PublicKey,
        shared_secret: &[u8],
        vehicle_id: &str,
        subject_id: &str,
        session_id: &str,
    ) -> Result<SessionKeyMaterial, String> {
        let derived_aes_key =
            Self::derive_session_key(shared_secret, vehicle_id, subject_id, session_id)?;

        Ok(SessionKeyMaterial {
            vehicle_ephemeral_public_key: vehicle_ephemeral_public_key.to_bytes(),
            keyfob_ephemeral_public_key: keyfob_ephemeral_public_key.to_bytes(),
            derived_aes_key,
        })
    }

    pub fn establish_session(
        vehicle_id: &str,
        subject_id: &str,
        session_id: &str,
        vehicle_keypair: &SessionEphemeralKeyPair,
        keyfob_keypair: &SessionEphemeralKeyPair,
        timeout_seconds: i64,
    ) -> Result<(SessionState, SessionKeyMaterial), String> {
        let session = Self::create_session(
            session_id.to_string(),
            vehicle_id.to_string(),
            subject_id.to_string(),
            timeout_seconds,
        )?;

        let shared_secret =
            Self::derive_shared_secret(&vehicle_keypair.private_key, &keyfob_keypair.public_key);

        let material = Self::build_session_key_material(
            &vehicle_keypair.public_key,
            &keyfob_keypair.public_key,
            &shared_secret,
            vehicle_id,
            subject_id,
            session_id,
        )?;

        Ok((session, material))
    }

    pub fn encrypt_session_message(
        session_key: &[u8],
        plaintext: &[u8],
    ) -> Result<EncryptedSessionMessage, String> {
        let nonce = CryptoEngine::generate_random_nonce(SESSION_NONCE_LEN)?;
        let encrypted = CryptoEngine::encrypt_aes_gcm(session_key, plaintext, &nonce)?;

        Ok(EncryptedSessionMessage {
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
            tag: encrypted.tag,
            created_at: Utc::now().to_rfc3339(),
        })
    }

    pub fn decrypt_session_message(
        session_key: &[u8],
        encrypted_payload: &EncryptedSessionMessage,
    ) -> Result<Vec<u8>, String> {
        if encrypted_payload.nonce.len() != SESSION_NONCE_LEN {
            return Err("Invalid nonce length in encrypted payload".to_string());
        }

        DateTime::parse_from_rfc3339(&encrypted_payload.created_at)
            .map_err(|e| format!("Invalid encrypted payload timestamp: {}", e))?;

        let payload = EncryptedPayload {
            ciphertext: encrypted_payload.ciphertext.clone(),
            nonce: encrypted_payload.nonce.clone(),
            tag: encrypted_payload.tag.clone(),
        };

        CryptoEngine::decrypt_aes_gcm(session_key, &payload)
    }

    pub fn is_session_active(session: &SessionState) -> Result<bool, String> {
        if !session.established {
            return Ok(false);
        }

        Self::validate_session_timestamp(session)
    }

    pub fn expire_session(session: &mut SessionState) -> Result<(), String> {
        session.established = false;
        Ok(())
    }

    pub fn validate_session_timestamp(session: &SessionState) -> Result<bool, String> {
        let created_at = DateTime::parse_from_rfc3339(&session.created_at)
            .map_err(|e| format!("Invalid created_at timestamp: {}", e))?
            .with_timezone(&Utc);
        let expires_at = DateTime::parse_from_rfc3339(&session.expires_at)
            .map_err(|e| format!("Invalid expires_at timestamp: {}", e))?
            .with_timezone(&Utc);

        if created_at > expires_at {
            return Ok(false);
        }

        let now = Utc::now();
        if now < created_at {
            return Ok(false);
        }

        if now > expires_at {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn derive_session_keys_for_test(
        vehicle_id: &str,
        subject_id: &str,
        session_id: &str,
    ) -> (
        SessionEphemeralKeyPair,
        SessionEphemeralKeyPair,
        [u8; 32],
        [u8; 32],
    ) {
        let vehicle = SessionValidationEngine::generate_ephemeral_keypair();
        let keyfob = SessionValidationEngine::generate_ephemeral_keypair();

        let vehicle_shared =
            SessionValidationEngine::derive_shared_secret(&vehicle.private_key, &keyfob.public_key);
        let keyfob_shared =
            SessionValidationEngine::derive_shared_secret(&keyfob.private_key, &vehicle.public_key);

        assert_eq!(vehicle_shared, keyfob_shared, "Shared secret should match");

        let vehicle_key = SessionValidationEngine::derive_session_key(
            &vehicle_shared,
            vehicle_id,
            subject_id,
            session_id,
        )
        .expect("Vehicle key derivation failed");
        let keyfob_key = SessionValidationEngine::derive_session_key(
            &keyfob_shared,
            vehicle_id,
            subject_id,
            session_id,
        )
        .expect("Keyfob key derivation failed");

        (vehicle, keyfob, vehicle_key, keyfob_key)
    }

    #[test]
    fn test_x25519_shared_secret_agreement_succeeds() {
        let vehicle = SessionValidationEngine::generate_ephemeral_keypair();
        let keyfob = SessionValidationEngine::generate_ephemeral_keypair();

        let vehicle_shared =
            SessionValidationEngine::derive_shared_secret(&vehicle.private_key, &keyfob.public_key);
        let keyfob_shared =
            SessionValidationEngine::derive_shared_secret(&keyfob.private_key, &vehicle.public_key);

        assert_eq!(vehicle_shared, keyfob_shared);
        assert_eq!(vehicle_shared.len(), 32);
    }

    #[test]
    fn test_vehicle_and_keyfob_derive_identical_aes_session_keys() {
        let (_, _, vehicle_key, keyfob_key) =
            derive_session_keys_for_test("VEH-SESSION", "FOB-SESSION", "SESSION-001");

        assert_eq!(vehicle_key, keyfob_key);
        assert_eq!(vehicle_key.len(), 32);
    }

    #[test]
    fn test_different_ephemeral_keys_produce_different_session_keys() {
        let vehicle_a = SessionValidationEngine::generate_ephemeral_keypair();
        let keyfob_a = SessionValidationEngine::generate_ephemeral_keypair();
        let vehicle_b = SessionValidationEngine::generate_ephemeral_keypair();
        let keyfob_b = SessionValidationEngine::generate_ephemeral_keypair();

        let shared_a = SessionValidationEngine::derive_shared_secret(
            &vehicle_a.private_key,
            &keyfob_a.public_key,
        );
        let shared_b = SessionValidationEngine::derive_shared_secret(
            &vehicle_b.private_key,
            &keyfob_b.public_key,
        );

        let key_a = SessionValidationEngine::derive_session_key(
            &shared_a,
            "VEH-SESSION",
            "FOB-SESSION",
            "SESSION-001",
        )
        .expect("Key A derivation failed");
        let key_b = SessionValidationEngine::derive_session_key(
            &shared_b,
            "VEH-SESSION",
            "FOB-SESSION",
            "SESSION-001",
        )
        .expect("Key B derivation failed");

        assert_ne!(key_a, key_b);
    }

    #[test]
    fn test_session_context_binding_changes_derived_key() {
        let vehicle = SessionValidationEngine::generate_ephemeral_keypair();
        let keyfob = SessionValidationEngine::generate_ephemeral_keypair();
        let shared_secret =
            SessionValidationEngine::derive_shared_secret(&vehicle.private_key, &keyfob.public_key);

        let key_1 = SessionValidationEngine::derive_session_key(
            &shared_secret,
            "VEH-1",
            "FOB-1",
            "SESSION-1",
        )
        .expect("Key 1 derivation failed");
        let key_2 = SessionValidationEngine::derive_session_key(
            &shared_secret,
            "VEH-2",
            "FOB-1",
            "SESSION-1",
        )
        .expect("Key 2 derivation failed");
        let key_3 = SessionValidationEngine::derive_session_key(
            &shared_secret,
            "VEH-1",
            "FOB-2",
            "SESSION-1",
        )
        .expect("Key 3 derivation failed");
        let key_4 = SessionValidationEngine::derive_session_key(
            &shared_secret,
            "VEH-1",
            "FOB-1",
            "SESSION-2",
        )
        .expect("Key 4 derivation failed");

        assert_ne!(key_1, key_2);
        assert_ne!(key_1, key_3);
        assert_ne!(key_1, key_4);
    }

    #[test]
    fn test_aes_gcm_encrypt_decrypt_works_with_derived_session_key() {
        let (_, _, vehicle_key, _) =
            derive_session_keys_for_test("VEH-ENC", "FOB-ENC", "SESSION-ENC");
        let plaintext = b"authenticated session message";

        let encrypted = SessionValidationEngine::encrypt_session_message(&vehicle_key, plaintext)
            .expect("Encryption failed");
        let decrypted = SessionValidationEngine::decrypt_session_message(&vehicle_key, &encrypted)
            .expect("Decryption failed");

        assert_eq!(decrypted, plaintext);
        assert_eq!(encrypted.nonce.len(), SESSION_NONCE_LEN);
        assert!(!encrypted.created_at.is_empty());
    }

    #[test]
    fn test_decryption_fails_with_wrong_key() {
        let (_, _, vehicle_key, _) =
            derive_session_keys_for_test("VEH-WRONG", "FOB-WRONG", "SESSION-WRONG");
        let wrong_key = [9u8; SESSION_AES_KEY_LEN];
        let encrypted =
            SessionValidationEngine::encrypt_session_message(&vehicle_key, b"secret message")
                .expect("Encryption failed");

        let result = SessionValidationEngine::decrypt_session_message(&wrong_key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_is_rejected() {
        let (_, _, vehicle_key, _) =
            derive_session_keys_for_test("VEH-TAMPER-C", "FOB-TAMPER-C", "SESSION-TAMPER-C");
        let mut encrypted =
            SessionValidationEngine::encrypt_session_message(&vehicle_key, b"tamper me")
                .expect("Encryption failed");
        encrypted.ciphertext[0] ^= 0x01;

        let result = SessionValidationEngine::decrypt_session_message(&vehicle_key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_nonce_is_rejected() {
        let (_, _, vehicle_key, _) =
            derive_session_keys_for_test("VEH-TAMPER-N", "FOB-TAMPER-N", "SESSION-TAMPER-N");
        let mut encrypted =
            SessionValidationEngine::encrypt_session_message(&vehicle_key, b"tamper nonce")
                .expect("Encryption failed");
        encrypted.nonce[0] ^= 0x01;

        let result = SessionValidationEngine::decrypt_session_message(&vehicle_key, &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_expired_session_is_rejected() {
        let mut session = SessionState {
            session_id: "SESSION-EXPIRED".to_string(),
            vehicle_id: "VEH-EXPIRED".to_string(),
            subject_id: "FOB-EXPIRED".to_string(),
            created_at: (Utc::now() - chrono::Duration::seconds(120)).to_rfc3339(),
            expires_at: (Utc::now() - chrono::Duration::seconds(60)).to_rfc3339(),
            established: true,
        };

        assert!(!SessionValidationEngine::validate_session_timestamp(&session).unwrap());
        assert!(!SessionValidationEngine::is_session_active(&session).unwrap());

        SessionValidationEngine::expire_session(&mut session).unwrap();
        assert!(!session.established);
    }

    #[test]
    fn test_session_validation_and_expire_helpers() {
        let mut session = SessionValidationEngine::create_session(
            "SESSION-HELPERS".to_string(),
            "VEH-HELPERS".to_string(),
            "FOB-HELPERS".to_string(),
            60,
        )
        .expect("Session creation failed");

        assert!(SessionValidationEngine::validate_session_timestamp(&session).unwrap());
        assert!(SessionValidationEngine::is_session_active(&session).unwrap());

        SessionValidationEngine::expire_session(&mut session).unwrap();
        assert!(!SessionValidationEngine::is_session_active(&session).unwrap());
    }

    #[test]
    fn test_no_private_session_key_material_is_exposed() {
        let vehicle = SessionValidationEngine::generate_ephemeral_keypair();
        let keyfob = SessionValidationEngine::generate_ephemeral_keypair();
        let shared_secret =
            SessionValidationEngine::derive_shared_secret(&vehicle.private_key, &keyfob.public_key);
        let material = SessionValidationEngine::build_session_key_material(
            &vehicle.public_key,
            &keyfob.public_key,
            &shared_secret,
            "VEH-PRIVATE",
            "FOB-PRIVATE",
            "SESSION-PRIVATE",
        )
        .expect("Material derivation failed");

        let debug_ephemeral = format!("{:?}", vehicle);
        let debug_material = format!("{:?}", material);

        assert!(debug_ephemeral.contains("<redacted>"));
        assert!(debug_material.contains("<redacted>"));
        assert_eq!(material.key_lengths(), (32, 32, 32));
    }
}
