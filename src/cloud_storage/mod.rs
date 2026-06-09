use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::env;
use std::fmt;

const ENV_FILE: &str = ".env.local";
const DATABASE_URL_ENV: &str = "DATABASE_URL";
const MASTER_KEY_ENV: &str = "AIACS_MASTER_KEY";
const HEALTHY_MESSAGE: &str = "Cloud database connection healthy";
const SCHEMA_INITIALIZED_MESSAGE: &str = "Cloud database schema initialized";
const CUSTOMER_SYNCED_MESSAGE: &str = "Customer metadata synced";
const VEHICLE_SYNCED_MESSAGE: &str = "Vehicle metadata synced";
const KEY_FOB_SYNCED_MESSAGE: &str = "Key fob metadata synced";
const DEMO_METADATA_SYNCED_MESSAGE: &str = "Demo metadata synced to cloud database";
pub const CERTIFICATE_METADATA_SYNCED_MESSAGE: &str = "Certificate metadata synced";
pub const CA_ENCRYPTED_KEY_SYNCED_MESSAGE: &str = "CA encrypted key blob uploaded";
pub const KEY_FOB_ENCRYPTED_KEY_SYNCED_MESSAGE: &str = "Key fob encrypted key blob uploaded";
pub const ENCRYPTED_KEY_BLOBS_SYNCED_MESSAGE: &str =
    "Encrypted key blobs synced to company cloud database";

pub const DEMO_CUSTOMER_ID: &str = "CUST-0001";
pub const DEMO_OWNER_NAME: &str = "Dennis Maharjan";
pub const DEMO_EMAIL: &str = "dennis.m@example.com";
pub const DEMO_VEHICLE_ID: &str = "VEH-0001";
pub const DEMO_VEHICLE_DISPLAY_NAME: &str = "Nissan Magnite 2021";
pub const DEMO_VEHICLE_MAKE: &str = "Nissan";
pub const DEMO_VEHICLE_MODEL: &str = "Magnite";
pub const DEMO_VEHICLE_YEAR: i32 = 2021;
pub const DEMO_FOB_ID: &str = "FOB-0001";
pub const DEMO_FOB_LABEL: &str = "Primary Key Fob";
pub const DEFAULT_PROVISIONING_STATUS: &str = "In Progress";
pub const DEFAULT_CERTIFICATE_STATUS: &str = "Pending";
pub const DEMO_CERTIFICATE_ID: &str = "CERT-FOB-0001";
pub const CERTIFICATE_SIGNATURE_ALGORITHM: &str = "Ed25519";
pub const ISSUED_CERTIFICATE_STATUS: &str = "issued";
pub const CA_ENCRYPTED_KEY_ID: &str = "KEY-CA-0001";
pub const KEY_FOB_ENCRYPTED_KEY_ID: &str = "KEY-FOB-0001";
pub const ENCRYPTED_KEY_ALGORITHM: &str = "AES-256-GCM";
pub const ENCRYPTED_KEY_STORAGE_STATUS: &str = "Client-side encrypted cloud blob";
pub const CA_KEY_PURPOSE: &str = "certificate_authority_signing";
pub const KEY_FOB_KEY_PURPOSE: &str = "key_fob_authentication_signing";

const SCHEMA_STATEMENTS: &[&str] = &[
    r#"
CREATE TABLE IF NOT EXISTS customers (
    customer_id TEXT PRIMARY KEY,
    owner_name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
"#,
    r#"
CREATE TABLE IF NOT EXISTS vehicles (
    vehicle_id TEXT PRIMARY KEY,
    customer_id TEXT REFERENCES customers(customer_id),
    vehicle_display_name TEXT NOT NULL,
    make TEXT,
    model TEXT,
    year INTEGER,
    vin TEXT,
    registration_number TEXT,
    provisioning_status TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
"#,
    r#"
CREATE TABLE IF NOT EXISTS key_fobs (
    fob_id TEXT PRIMARY KEY,
    vehicle_id TEXT REFERENCES vehicles(vehicle_id),
    customer_id TEXT REFERENCES customers(customer_id),
    fob_label TEXT NOT NULL,
    public_key_fingerprint TEXT,
    certificate_status TEXT,
    provisioning_status TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
"#,
    r#"
CREATE TABLE IF NOT EXISTS certificates (
    certificate_id TEXT PRIMARY KEY,
    fob_id TEXT REFERENCES key_fobs(fob_id),
    vehicle_id TEXT REFERENCES vehicles(vehicle_id),
    subject_id TEXT NOT NULL,
    issuer TEXT NOT NULL,
    issued_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    certificate_status TEXT,
    public_key_fingerprint TEXT,
    signature_algorithm TEXT,
    certificate_signature_fingerprint TEXT,
    certificate_json JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
"#,
    r#"
ALTER TABLE certificates
ADD COLUMN IF NOT EXISTS signature_algorithm TEXT;
"#,
    r#"
ALTER TABLE certificates
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();
"#,
    r#"
ALTER TABLE certificates
ADD COLUMN IF NOT EXISTS public_key_fingerprint TEXT;
"#,
    r#"
CREATE TABLE IF NOT EXISTS encrypted_keys (
    key_id TEXT PRIMARY KEY,
    owner_type TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    public_key_fingerprint TEXT,
    encrypted_key_blob BYTEA NOT NULL,
    encryption_nonce BYTEA NOT NULL,
    encryption_algorithm TEXT NOT NULL,
    key_purpose TEXT NOT NULL,
    storage_status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);
"#,
    r#"
CREATE TABLE IF NOT EXISTS provisioning_sessions (
    session_id TEXT PRIMARY KEY,
    customer_id TEXT REFERENCES customers(customer_id),
    vehicle_id TEXT REFERENCES vehicles(vehicle_id),
    fob_id TEXT REFERENCES key_fobs(fob_id),
    auth_result TEXT,
    access_decision TEXT,
    session_method TEXT,
    provisioning_status TEXT,
    report_path TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
"#,
    r#"
CREATE TABLE IF NOT EXISTS audit_logs (
    log_id UUID PRIMARY KEY,
    event_tag TEXT NOT NULL,
    event_message TEXT NOT NULL,
    customer_id TEXT,
    vehicle_id TEXT,
    fob_id TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
"#,
    r#"
CREATE TABLE IF NOT EXISTS diagnostic_results (
    diagnostic_id UUID PRIMARY KEY,
    attack_type TEXT NOT NULL,
    expected_outcome TEXT,
    actual_outcome TEXT,
    defense_status TEXT,
    failure_point TEXT,
    explanation TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
"#,
];

const UPSERT_CUSTOMER_SQL: &str = r#"
INSERT INTO customers (
    customer_id,
    owner_name,
    email,
    phone,
    created_at
) VALUES ($1, $2, $3, $4, NOW())
ON CONFLICT (customer_id) DO UPDATE SET
    owner_name = EXCLUDED.owner_name,
    email = EXCLUDED.email,
    phone = EXCLUDED.phone;
"#;

const UPSERT_VEHICLE_SQL: &str = r#"
INSERT INTO vehicles (
    vehicle_id,
    customer_id,
    vehicle_display_name,
    make,
    model,
    year,
    vin,
    registration_number,
    provisioning_status,
    created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
ON CONFLICT (vehicle_id) DO UPDATE SET
    customer_id = EXCLUDED.customer_id,
    vehicle_display_name = EXCLUDED.vehicle_display_name,
    make = EXCLUDED.make,
    model = EXCLUDED.model,
    year = EXCLUDED.year,
    vin = EXCLUDED.vin,
    registration_number = EXCLUDED.registration_number,
    provisioning_status = EXCLUDED.provisioning_status;
"#;

const UPSERT_KEY_FOB_SQL: &str = r#"
INSERT INTO key_fobs (
    fob_id,
    vehicle_id,
    customer_id,
    fob_label,
    public_key_fingerprint,
    certificate_status,
    provisioning_status,
    created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
ON CONFLICT (fob_id) DO UPDATE SET
    vehicle_id = EXCLUDED.vehicle_id,
    customer_id = EXCLUDED.customer_id,
    fob_label = EXCLUDED.fob_label,
    public_key_fingerprint = EXCLUDED.public_key_fingerprint,
    certificate_status = EXCLUDED.certificate_status,
    provisioning_status = EXCLUDED.provisioning_status;
"#;

const UPSERT_CERTIFICATE_METADATA_SQL: &str = r#"
INSERT INTO certificates (
    certificate_id,
    fob_id,
    subject_id,
    issuer,
    issued_at,
    expires_at,
    public_key_fingerprint,
    signature_algorithm,
    certificate_status,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
ON CONFLICT (certificate_id) DO UPDATE SET
    fob_id = EXCLUDED.fob_id,
    subject_id = EXCLUDED.subject_id,
    issuer = EXCLUDED.issuer,
    issued_at = EXCLUDED.issued_at,
    expires_at = EXCLUDED.expires_at,
    public_key_fingerprint = EXCLUDED.public_key_fingerprint,
    signature_algorithm = EXCLUDED.signature_algorithm,
    certificate_status = EXCLUDED.certificate_status,
    updated_at = NOW();
"#;

const UPSERT_ENCRYPTED_KEY_SQL: &str = r#"
INSERT INTO encrypted_keys (
    key_id,
    owner_type,
    owner_id,
    public_key_fingerprint,
    encrypted_key_blob,
    encryption_nonce,
    encryption_algorithm,
    key_purpose,
    storage_status,
    created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
ON CONFLICT (key_id) DO UPDATE SET
    owner_type = EXCLUDED.owner_type,
    owner_id = EXCLUDED.owner_id,
    public_key_fingerprint = EXCLUDED.public_key_fingerprint,
    encrypted_key_blob = EXCLUDED.encrypted_key_blob,
    encryption_nonce = EXCLUDED.encryption_nonce,
    encryption_algorithm = EXCLUDED.encryption_algorithm,
    key_purpose = EXCLUDED.key_purpose,
    storage_status = EXCLUDED.storage_status;
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomerMetadata {
    pub customer_id: String,
    pub owner_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VehicleMetadata {
    pub vehicle_id: String,
    pub customer_id: String,
    pub vehicle_display_name: String,
    pub make: Option<String>,
    pub model: Option<String>,
    pub year: Option<i32>,
    pub vin: Option<String>,
    pub registration_number: Option<String>,
    pub provisioning_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyFobMetadata {
    pub fob_id: String,
    pub vehicle_id: String,
    pub customer_id: String,
    pub fob_label: String,
    pub public_key_fingerprint: Option<String>,
    pub certificate_status: Option<String>,
    pub provisioning_status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateMetadata {
    pub certificate_id: String,
    pub fob_id: String,
    pub subject_id: String,
    pub issuer: String,
    pub issued_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub public_key_fingerprint: Option<String>,
    pub signature_algorithm: String,
    pub certificate_status: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedKeyBlob {
    pub encrypted_key_blob: Vec<u8>,
    pub encryption_nonce: Vec<u8>,
    pub encryption_algorithm: String,
}

impl fmt::Debug for EncryptedKeyBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedKeyBlob")
            .field(
                "encrypted_key_blob",
                &format!("{} bytes [REDACTED]", self.encrypted_key_blob.len()),
            )
            .field(
                "encryption_nonce",
                &format!("{} bytes [REDACTED]", self.encryption_nonce.len()),
            )
            .field("encryption_algorithm", &self.encryption_algorithm)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedKeyRecord {
    pub key_id: String,
    pub owner_type: String,
    pub owner_id: String,
    pub public_key_fingerprint: Option<String>,
    pub key_purpose: String,
    pub storage_status: String,
    pub encrypted_key: EncryptedKeyBlob,
}

impl fmt::Debug for EncryptedKeyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedKeyRecord")
            .field("key_id", &self.key_id)
            .field("owner_type", &self.owner_type)
            .field("owner_id", &self.owner_id)
            .field("public_key_fingerprint", &self.public_key_fingerprint)
            .field("key_purpose", &self.key_purpose)
            .field("storage_status", &self.storage_status)
            .field("encrypted_key", &self.encrypted_key)
            .finish()
    }
}

pub fn demo_customer_metadata() -> CustomerMetadata {
    CustomerMetadata {
        customer_id: DEMO_CUSTOMER_ID.to_string(),
        owner_name: DEMO_OWNER_NAME.to_string(),
        email: Some(DEMO_EMAIL.to_string()),
        phone: None,
    }
}

pub fn demo_vehicle_metadata(provisioning_status: impl Into<String>) -> VehicleMetadata {
    VehicleMetadata {
        vehicle_id: DEMO_VEHICLE_ID.to_string(),
        customer_id: DEMO_CUSTOMER_ID.to_string(),
        vehicle_display_name: DEMO_VEHICLE_DISPLAY_NAME.to_string(),
        make: Some(DEMO_VEHICLE_MAKE.to_string()),
        model: Some(DEMO_VEHICLE_MODEL.to_string()),
        year: Some(DEMO_VEHICLE_YEAR),
        vin: None,
        registration_number: None,
        provisioning_status: Some(provisioning_status.into()),
    }
}

pub fn demo_key_fob_metadata(
    public_key_fingerprint: Option<String>,
    certificate_status: impl Into<String>,
    provisioning_status: impl Into<String>,
) -> KeyFobMetadata {
    KeyFobMetadata {
        fob_id: DEMO_FOB_ID.to_string(),
        vehicle_id: DEMO_VEHICLE_ID.to_string(),
        customer_id: DEMO_CUSTOMER_ID.to_string(),
        fob_label: DEMO_FOB_LABEL.to_string(),
        public_key_fingerprint,
        certificate_status: Some(certificate_status.into()),
        provisioning_status: Some(provisioning_status.into()),
    }
}

pub fn demo_certificate_metadata(
    public_key_fingerprint: Option<String>,
    issued_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
) -> CertificateMetadata {
    CertificateMetadata {
        certificate_id: DEMO_CERTIFICATE_ID.to_string(),
        fob_id: DEMO_FOB_ID.to_string(),
        subject_id: DEMO_FOB_ID.to_string(),
        issuer: "AIACS-Demo-CA".to_string(),
        issued_at,
        expires_at,
        public_key_fingerprint,
        signature_algorithm: CERTIFICATE_SIGNATURE_ALGORITHM.to_string(),
        certificate_status: ISSUED_CERTIFICATE_STATUS.to_string(),
    }
}

pub fn parse_master_key_from_env() -> Result<[u8; 32], CloudStorageError> {
    let _ = dotenvy::from_filename(ENV_FILE);
    parse_master_key_from_value(env::var(MASTER_KEY_ENV).ok().as_deref())
}

fn parse_master_key_from_value(master_key: Option<&str>) -> Result<[u8; 32], CloudStorageError> {
    let encoded = master_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(CloudStorageError::MissingMasterKey)?;
    let decoded = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| CloudStorageError::InvalidMasterKeyBase64)?;
    decoded
        .try_into()
        .map_err(|_| CloudStorageError::InvalidMasterKeySize)
}

pub fn encrypt_private_key_for_cloud(
    plaintext: &[u8],
    master_key: &[u8; 32],
) -> Result<EncryptedKeyBlob, CloudStorageError> {
    let cipher = Aes256Gcm::new_from_slice(master_key)
        .map_err(|_| CloudStorageError::PrivateKeyEncryptionFailed)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let encrypted_key_blob = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| CloudStorageError::PrivateKeyEncryptionFailed)?;

    Ok(EncryptedKeyBlob {
        encrypted_key_blob,
        encryption_nonce: nonce.to_vec(),
        encryption_algorithm: ENCRYPTED_KEY_ALGORITHM.to_string(),
    })
}

pub struct CloudStorageConfig {
    database_url: String,
}

impl CloudStorageConfig {
    pub fn from_env() -> Result<Self, CloudStorageError> {
        let _ = dotenvy::from_filename(ENV_FILE);
        Self::from_database_url(env::var(DATABASE_URL_ENV).ok())
    }

    fn from_database_url(database_url: Option<String>) -> Result<Self, CloudStorageError> {
        let database_url = database_url
            .filter(|value| !value.trim().is_empty())
            .ok_or(CloudStorageError::MissingDatabaseUrl)?;

        Ok(Self { database_url })
    }
}

impl fmt::Debug for CloudStorageConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudStorageConfig")
            .field("database_url", &"[REDACTED]")
            .finish()
    }
}

pub struct CloudStorageClient {
    pool: PgPool,
}

impl CloudStorageClient {
    pub async fn connect_from_env() -> Result<Self, CloudStorageError> {
        let config = CloudStorageConfig::from_env()?;
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&config.database_url)
            .await
            .map_err(|_| CloudStorageError::ConnectionFailed)?;

        Ok(Self { pool })
    }

    pub async fn health_check(&self) -> Result<String, CloudStorageError> {
        sqlx::query_scalar::<_, i32>("SELECT 1;")
            .fetch_one(&self.pool)
            .await
            .map_err(|_| CloudStorageError::HealthCheckFailed)?;

        Ok(HEALTHY_MESSAGE.to_string())
    }

    pub async fn initialize_schema(&self) -> Result<String, CloudStorageError> {
        for statement in SCHEMA_STATEMENTS {
            sqlx::query(statement)
                .execute(&self.pool)
                .await
                .map_err(|_| CloudStorageError::SchemaInitializationFailed)?;
        }

        Ok(schema_initialized_message().to_string())
    }

    pub async fn upsert_customer(
        &self,
        metadata: &CustomerMetadata,
    ) -> Result<String, CloudStorageError> {
        sqlx::query(UPSERT_CUSTOMER_SQL)
            .bind(&metadata.customer_id)
            .bind(&metadata.owner_name)
            .bind(metadata.email.as_deref())
            .bind(metadata.phone.as_deref())
            .execute(&self.pool)
            .await
            .map_err(|_| CloudStorageError::MetadataSyncFailed)?;

        Ok(CUSTOMER_SYNCED_MESSAGE.to_string())
    }

    pub async fn upsert_vehicle(
        &self,
        metadata: &VehicleMetadata,
    ) -> Result<String, CloudStorageError> {
        sqlx::query(UPSERT_VEHICLE_SQL)
            .bind(&metadata.vehicle_id)
            .bind(&metadata.customer_id)
            .bind(&metadata.vehicle_display_name)
            .bind(metadata.make.as_deref())
            .bind(metadata.model.as_deref())
            .bind(metadata.year)
            .bind(metadata.vin.as_deref())
            .bind(metadata.registration_number.as_deref())
            .bind(metadata.provisioning_status.as_deref())
            .execute(&self.pool)
            .await
            .map_err(|_| CloudStorageError::MetadataSyncFailed)?;

        Ok(VEHICLE_SYNCED_MESSAGE.to_string())
    }

    pub async fn upsert_key_fob(
        &self,
        metadata: &KeyFobMetadata,
    ) -> Result<String, CloudStorageError> {
        sqlx::query(UPSERT_KEY_FOB_SQL)
            .bind(&metadata.fob_id)
            .bind(&metadata.vehicle_id)
            .bind(&metadata.customer_id)
            .bind(&metadata.fob_label)
            .bind(metadata.public_key_fingerprint.as_deref())
            .bind(metadata.certificate_status.as_deref())
            .bind(metadata.provisioning_status.as_deref())
            .execute(&self.pool)
            .await
            .map_err(|_| CloudStorageError::MetadataSyncFailed)?;

        Ok(KEY_FOB_SYNCED_MESSAGE.to_string())
    }

    pub async fn sync_demo_metadata(&self) -> Result<String, CloudStorageError> {
        self.upsert_customer(&demo_customer_metadata()).await?;
        self.upsert_vehicle(&demo_vehicle_metadata(DEFAULT_PROVISIONING_STATUS))
            .await?;
        self.upsert_key_fob(&demo_key_fob_metadata(
            None,
            DEFAULT_CERTIFICATE_STATUS,
            DEFAULT_PROVISIONING_STATUS,
        ))
        .await?;

        Ok(DEMO_METADATA_SYNCED_MESSAGE.to_string())
    }

    pub async fn upsert_certificate_metadata(
        &self,
        metadata: &CertificateMetadata,
    ) -> Result<String, CloudStorageError> {
        sqlx::query(UPSERT_CERTIFICATE_METADATA_SQL)
            .bind(&metadata.certificate_id)
            .bind(&metadata.fob_id)
            .bind(&metadata.subject_id)
            .bind(&metadata.issuer)
            .bind(metadata.issued_at)
            .bind(metadata.expires_at)
            .bind(metadata.public_key_fingerprint.as_deref())
            .bind(&metadata.signature_algorithm)
            .bind(&metadata.certificate_status)
            .execute(&self.pool)
            .await
            .map_err(|_| CloudStorageError::CertificateMetadataSyncFailed)?;

        Ok(CERTIFICATE_METADATA_SYNCED_MESSAGE.to_string())
    }

    pub async fn sync_demo_certificate_metadata(&self) -> Result<String, CloudStorageError> {
        let issued_at = Utc::now();
        let expires_at = issued_at + chrono::Duration::days(365);
        self.upsert_certificate_metadata(&demo_certificate_metadata(
            None,
            Some(issued_at),
            Some(expires_at),
        ))
        .await
    }

    pub async fn upsert_encrypted_key(
        &self,
        record: &EncryptedKeyRecord,
    ) -> Result<String, CloudStorageError> {
        sqlx::query(UPSERT_ENCRYPTED_KEY_SQL)
            .bind(&record.key_id)
            .bind(&record.owner_type)
            .bind(&record.owner_id)
            .bind(record.public_key_fingerprint.as_deref())
            .bind(&record.encrypted_key.encrypted_key_blob)
            .bind(&record.encrypted_key.encryption_nonce)
            .bind(&record.encrypted_key.encryption_algorithm)
            .bind(&record.key_purpose)
            .bind(&record.storage_status)
            .execute(&self.pool)
            .await
            .map_err(|_| CloudStorageError::EncryptedKeySyncFailed)?;

        Ok(encrypted_key_sync_message(&record.key_id).to_string())
    }

    pub async fn sync_demo_encrypted_key_blobs(
        &self,
        ca_record: &EncryptedKeyRecord,
        key_fob_record: &EncryptedKeyRecord,
    ) -> Result<String, CloudStorageError> {
        self.upsert_encrypted_key(ca_record).await?;
        self.upsert_encrypted_key(key_fob_record).await?;

        Ok(ENCRYPTED_KEY_BLOBS_SYNCED_MESSAGE.to_string())
    }
}

impl fmt::Debug for CloudStorageClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudStorageClient")
            .field("pool", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudStorageError {
    MissingDatabaseUrl,
    MissingMasterKey,
    InvalidMasterKeyBase64,
    InvalidMasterKeySize,
    ConnectionFailed,
    HealthCheckFailed,
    SchemaInitializationFailed,
    MetadataSyncFailed,
    CertificateMetadataSyncFailed,
    PrivateKeyEncryptionFailed,
    EncryptedKeySyncFailed,
}

impl fmt::Display for CloudStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudStorageError::MissingDatabaseUrl => f.write_str("DATABASE_URL is not configured"),
            CloudStorageError::MissingMasterKey => {
                f.write_str("AIACS_MASTER_KEY is not configured")
            }
            CloudStorageError::InvalidMasterKeyBase64 => {
                f.write_str("AIACS_MASTER_KEY is not valid base64")
            }
            CloudStorageError::InvalidMasterKeySize => {
                f.write_str("AIACS_MASTER_KEY must decode to 32 bytes")
            }
            CloudStorageError::ConnectionFailed => f.write_str("Cloud database connection failed"),
            CloudStorageError::HealthCheckFailed => {
                f.write_str("Cloud database health check failed")
            }
            CloudStorageError::SchemaInitializationFailed => {
                f.write_str("Cloud database schema initialization failed")
            }
            CloudStorageError::MetadataSyncFailed => f.write_str("Cloud metadata sync failed"),
            CloudStorageError::CertificateMetadataSyncFailed => {
                f.write_str("Certificate metadata sync failed")
            }
            CloudStorageError::PrivateKeyEncryptionFailed => {
                f.write_str("Private key encryption failed")
            }
            CloudStorageError::EncryptedKeySyncFailed => {
                f.write_str("Encrypted key blob sync failed")
            }
        }
    }
}

impl std::error::Error for CloudStorageError {}

fn schema_initialized_message() -> &'static str {
    SCHEMA_INITIALIZED_MESSAGE
}

fn encrypted_key_sync_message(key_id: &str) -> &'static str {
    match key_id {
        CA_ENCRYPTED_KEY_ID => CA_ENCRYPTED_KEY_SYNCED_MESSAGE,
        KEY_FOB_ENCRYPTED_KEY_ID => KEY_FOB_ENCRYPTED_KEY_SYNCED_MESSAGE,
        _ => "Encrypted key blob uploaded",
    }
}

#[cfg(test)]
fn schema_sql() -> String {
    SCHEMA_STATEMENTS.join("\n")
}

#[cfg(test)]
fn metadata_sync_sql() -> String {
    [UPSERT_CUSTOMER_SQL, UPSERT_VEHICLE_SQL, UPSERT_KEY_FOB_SQL].join("\n")
}

#[cfg(test)]
fn certificate_metadata_sync_sql() -> &'static str {
    UPSERT_CERTIFICATE_METADATA_SQL
}

#[cfg(test)]
fn encrypted_key_sync_sql() -> &'static str {
    UPSERT_ENCRYPTED_KEY_SQL
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const SAMPLE_DATABASE_URL: &str =
        "postgresql://demo_user:demo_password@example.neon.tech/demo?sslmode=require";

    #[test]
    fn missing_database_url_returns_safe_error() {
        let error =
            CloudStorageConfig::from_database_url(None).expect_err("missing URL should fail");

        assert_eq!(error, CloudStorageError::MissingDatabaseUrl);
        assert_eq!(error.to_string(), "DATABASE_URL is not configured");
    }

    #[test]
    fn safe_error_message_does_not_include_connection_string() {
        let error = CloudStorageError::ConnectionFailed.to_string();

        assert!(!error.contains(SAMPLE_DATABASE_URL));
        assert!(!error.contains("demo_password"));
        assert!(!error.contains("example.neon.tech"));
    }

    #[test]
    fn cloud_storage_config_debug_redacts_database_url() {
        let config = CloudStorageConfig::from_database_url(Some(SAMPLE_DATABASE_URL.to_string()))
            .expect("sample URL should build config");
        let debug = format!("{:?}", config);

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(SAMPLE_DATABASE_URL));
        assert!(!debug.contains("demo_password"));
        assert!(!debug.contains("example.neon.tech"));
    }

    #[test]
    fn env_example_contains_placeholders_only() {
        let example = fs::read_to_string(".env.example").expect(".env.example should exist");

        let lines: Vec<&str> = example.lines().collect();
        assert_eq!(
            lines,
            vec![
                "DATABASE_URL=postgresql://USER:PASSWORD@HOST/DATABASE?sslmode=require",
                "AIACS_MASTER_KEY=base64_encoded_32_byte_key",
            ]
        );
        assert!(!example.contains("neon.tech"));
    }

    #[test]
    fn schema_sql_contains_all_required_table_names() {
        let schema = schema_sql();

        for table_name in [
            "customers",
            "vehicles",
            "key_fobs",
            "certificates",
            "encrypted_keys",
            "provisioning_sessions",
            "audit_logs",
            "diagnostic_results",
        ] {
            assert!(
                schema.contains(&format!("CREATE TABLE IF NOT EXISTS {}", table_name)),
                "schema should contain {table_name}"
            );
        }
    }

    #[test]
    fn schema_sql_includes_encrypted_key_blob() {
        let schema = schema_sql();

        assert!(schema.contains("encrypted_key_blob BYTEA NOT NULL"));
    }

    #[test]
    fn schema_sql_includes_phase_6a_certificate_metadata_migrations() {
        let schema = schema_sql();

        assert!(schema.contains("ALTER TABLE certificates"));
        assert!(schema.contains("ADD COLUMN IF NOT EXISTS signature_algorithm TEXT"));
        assert!(schema.contains("ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()"));
        assert!(schema.contains("ADD COLUMN IF NOT EXISTS public_key_fingerprint TEXT"));
    }

    #[test]
    fn schema_sql_does_not_include_plaintext_key_columns() {
        let schema = schema_sql().to_lowercase();

        assert!(!schema.contains("private_key"));
        assert!(!schema.contains("raw_key"));
        assert!(!schema.contains("plaintext"));
    }

    #[test]
    fn schema_sql_does_not_include_database_url_or_master_key_names() {
        let schema = schema_sql();

        assert!(!schema.contains("DATABASE_URL"));
        assert!(!schema.contains("AIACS_MASTER_KEY"));
        assert!(!schema.contains(SAMPLE_DATABASE_URL));
    }

    #[test]
    fn initialize_schema_success_message_is_safe() {
        let message = schema_initialized_message();

        assert_eq!(message, "Cloud database schema initialized");
        assert!(!message.contains("DATABASE_URL"));
        assert!(!message.contains("AIACS_MASTER_KEY"));
        assert!(!message.contains("postgresql://"));
    }

    #[test]
    fn metadata_upsert_sql_uses_on_conflict() {
        let sql = metadata_sync_sql();

        assert!(sql.contains("ON CONFLICT (customer_id) DO UPDATE"));
        assert!(sql.contains("ON CONFLICT (vehicle_id) DO UPDATE"));
        assert!(sql.contains("ON CONFLICT (fob_id) DO UPDATE"));
    }

    #[test]
    fn metadata_sync_sql_does_not_contain_secret_env_names() {
        let sql = metadata_sync_sql();

        assert!(!sql.contains("DATABASE_URL"));
        assert!(!sql.contains("AIACS_MASTER_KEY"));
        assert!(!sql.contains(SAMPLE_DATABASE_URL));
    }

    #[test]
    fn metadata_sync_sql_does_not_upload_key_or_session_secret_fields() {
        let sql = metadata_sync_sql().to_lowercase();

        assert!(!sql.contains("private_key"));
        assert!(!sql.contains("raw_key"));
        assert!(!sql.contains("session_key"));
        assert!(!sql.contains("shared_secret"));
        assert!(!sql.contains("encrypted_key_blob"));
        assert!(!sql.contains("certificate_json"));
    }

    #[test]
    fn safe_sync_messages_do_not_contain_secrets() {
        for message in [
            CUSTOMER_SYNCED_MESSAGE,
            VEHICLE_SYNCED_MESSAGE,
            KEY_FOB_SYNCED_MESSAGE,
            DEMO_METADATA_SYNCED_MESSAGE,
            CERTIFICATE_METADATA_SYNCED_MESSAGE,
        ] {
            assert!(!message.contains("DATABASE_URL"));
            assert!(!message.contains("AIACS_MASTER_KEY"));
            assert!(!message.contains("postgresql://"));
            assert!(!message.contains("private_key"));
        }
    }

    #[test]
    fn certificate_metadata_uses_safe_demo_values() {
        let issued_at = Utc::now();
        let expires_at = issued_at + chrono::Duration::days(365);
        let metadata = demo_certificate_metadata(
            Some("SHA256:certificate-public-key".to_string()),
            Some(issued_at),
            Some(expires_at),
        );
        let debug = format!("{metadata:?}");

        assert_eq!(metadata.certificate_id, DEMO_CERTIFICATE_ID);
        assert_eq!(metadata.fob_id, DEMO_FOB_ID);
        assert_eq!(metadata.subject_id, DEMO_FOB_ID);
        assert_eq!(metadata.issuer, "AIACS-Demo-CA");
        assert_eq!(
            metadata.signature_algorithm,
            CERTIFICATE_SIGNATURE_ALGORITHM
        );
        assert_eq!(metadata.certificate_status, ISSUED_CERTIFICATE_STATUS);

        for disallowed in [
            "private_key",
            "raw_key",
            "AIACS_MASTER_KEY",
            "DATABASE_URL",
            "postgresql://",
            "encrypted_key_blob",
            "encryption_nonce",
            "shared_secret",
            "session_key",
        ] {
            assert!(!debug.contains(disallowed));
        }
    }

    #[test]
    fn certificate_metadata_upsert_sql_uses_safe_columns() {
        let sql = certificate_metadata_sync_sql();

        assert!(sql.contains("INSERT INTO certificates"));
        assert!(sql.contains("ON CONFLICT (certificate_id) DO UPDATE"));
        assert!(sql.contains("certificate_id"));
        assert!(sql.contains("fob_id"));
        assert!(sql.contains("subject_id"));
        assert!(sql.contains("issuer"));
        assert!(sql.contains("issued_at"));
        assert!(sql.contains("expires_at"));
        assert!(sql.contains("public_key_fingerprint"));
        assert!(sql.contains("signature_algorithm"));
        assert!(sql.contains("certificate_status"));
        assert!(sql.contains("created_at"));
        assert!(sql.contains("updated_at"));
    }

    #[test]
    fn certificate_metadata_upsert_sql_excludes_secret_columns() {
        let sql = certificate_metadata_sync_sql().to_lowercase();

        for disallowed in [
            "private_key",
            "raw_key",
            "master_key",
            "session_key",
            "shared_secret",
            "certificate_json",
            "encrypted_key_blob",
            "encryption_nonce",
        ] {
            assert!(!sql.contains(disallowed));
        }
    }

    #[test]
    fn demo_metadata_uses_generic_realistic_values() {
        let customer = demo_customer_metadata();
        let vehicle = demo_vehicle_metadata(DEFAULT_PROVISIONING_STATUS);
        let key_fob = demo_key_fob_metadata(
            Some("SHA256:abcd1234".to_string()),
            DEFAULT_CERTIFICATE_STATUS,
            DEFAULT_PROVISIONING_STATUS,
        );
        let combined = format!("{customer:?}\n{vehicle:?}\n{key_fob:?}");

        assert!(combined.contains("CUST-0001"));
        assert!(combined.contains("VEH-0001"));
        assert!(combined.contains("FOB-0001"));
        assert!(combined.contains("Dennis Maharjan"));
        assert!(combined.contains("Nissan Magnite 2021"));
        assert!(combined.contains("Primary Key Fob"));
        assert!(combined.contains("dennis.m@example.com"));
    }

    #[test]
    fn demo_metadata_does_not_use_gui_specific_values() {
        let customer = demo_customer_metadata();
        let vehicle = demo_vehicle_metadata(DEFAULT_PROVISIONING_STATUS);
        let key_fob = demo_key_fob_metadata(
            None,
            DEFAULT_CERTIFICATE_STATUS,
            DEFAULT_PROVISIONING_STATUS,
        );
        let combined = format!("{customer:?}\n{vehicle:?}\n{key_fob:?}");

        for disallowed in [
            "CUST-GUI-001",
            "VEH-GUI-001",
            "FOB-GUI-001",
            "SESSION-GUI-001",
            "demo@example.com",
            "Vehicle 1",
            "Vehicle 2",
        ] {
            assert!(!combined.contains(disallowed));
        }
    }

    fn test_master_key() -> [u8; 32] {
        [7u8; 32]
    }

    fn decrypt_test_blob(
        blob: &EncryptedKeyBlob,
        master_key: &[u8; 32],
    ) -> Result<Vec<u8>, CloudStorageError> {
        let cipher = Aes256Gcm::new_from_slice(master_key)
            .map_err(|_| CloudStorageError::PrivateKeyEncryptionFailed)?;
        cipher
            .decrypt(
                Nonce::from_slice(&blob.encryption_nonce),
                blob.encrypted_key_blob.as_slice(),
            )
            .map_err(|_| CloudStorageError::PrivateKeyEncryptionFailed)
    }

    fn test_encrypted_key_record(
        key_id: &str,
        owner_type: &str,
        owner_id: &str,
        key_purpose: &str,
        plaintext: &[u8],
        master_key: &[u8; 32],
    ) -> EncryptedKeyRecord {
        EncryptedKeyRecord {
            key_id: key_id.to_string(),
            owner_type: owner_type.to_string(),
            owner_id: owner_id.to_string(),
            public_key_fingerprint: Some("SHA256:test-fingerprint".to_string()),
            key_purpose: key_purpose.to_string(),
            storage_status: ENCRYPTED_KEY_STORAGE_STATUS.to_string(),
            encrypted_key: encrypt_private_key_for_cloud(plaintext, master_key)
                .expect("test key material should encrypt"),
        }
    }

    #[test]
    fn master_key_parsing_rejects_missing_value() {
        let error = parse_master_key_from_value(None).expect_err("missing key should fail");

        assert_eq!(error, CloudStorageError::MissingMasterKey);
        assert_eq!(error.to_string(), "AIACS_MASTER_KEY is not configured");
    }

    #[test]
    fn master_key_parsing_rejects_invalid_base64() {
        let error = parse_master_key_from_value(Some("not-valid-base64!"))
            .expect_err("invalid base64 should fail");

        assert_eq!(error, CloudStorageError::InvalidMasterKeyBase64);
        assert_eq!(error.to_string(), "AIACS_MASTER_KEY is not valid base64");
    }

    #[test]
    fn master_key_parsing_rejects_wrong_decoded_size() {
        let encoded = general_purpose::STANDARD.encode([3u8; 31]);
        let error =
            parse_master_key_from_value(Some(&encoded)).expect_err("wrong key size should fail");

        assert_eq!(error, CloudStorageError::InvalidMasterKeySize);
        assert_eq!(
            error.to_string(),
            "AIACS_MASTER_KEY must decode to 32 bytes"
        );
    }

    #[test]
    fn master_key_parsing_accepts_32_byte_base64_value() {
        let encoded = general_purpose::STANDARD.encode(test_master_key());
        let parsed =
            parse_master_key_from_value(Some(&encoded)).expect("valid 32-byte key should parse");

        assert_eq!(parsed, test_master_key());
    }

    #[test]
    fn encrypted_private_key_blob_differs_from_plaintext() {
        let plaintext = b"prototype private key bytes";
        let encrypted = encrypt_private_key_for_cloud(plaintext, &test_master_key())
            .expect("encryption should succeed");

        assert_ne!(encrypted.encrypted_key_blob, plaintext);
        assert_eq!(encrypted.encryption_nonce.len(), 12);
        assert_eq!(encrypted.encryption_algorithm, ENCRYPTED_KEY_ALGORITHM);
    }

    #[test]
    fn encrypted_private_key_blob_uses_fresh_nonce() {
        let plaintext = b"same private key material";
        let first = encrypt_private_key_for_cloud(plaintext, &test_master_key())
            .expect("first encryption should succeed");
        let second = encrypt_private_key_for_cloud(plaintext, &test_master_key())
            .expect("second encryption should succeed");

        assert_ne!(first.encryption_nonce, second.encryption_nonce);
        assert_ne!(first.encrypted_key_blob, second.encrypted_key_blob);
    }

    #[test]
    fn encrypted_private_key_blob_decrypts_with_same_key() {
        let plaintext = b"private key material for test";
        let encrypted = encrypt_private_key_for_cloud(plaintext, &test_master_key())
            .expect("encryption should succeed");
        let decrypted =
            decrypt_test_blob(&encrypted, &test_master_key()).expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypted_private_key_blob_rejects_wrong_key() {
        let plaintext = b"private key material for test";
        let encrypted = encrypt_private_key_for_cloud(plaintext, &test_master_key())
            .expect("encryption should succeed");
        let wrong_key = [9u8; 32];

        assert!(decrypt_test_blob(&encrypted, &wrong_key).is_err());
    }

    #[test]
    fn encrypted_key_debug_redacts_blob_and_nonce_bytes() {
        let plaintext = b"private key material for debug redaction";
        let encrypted = encrypt_private_key_for_cloud(plaintext, &test_master_key())
            .expect("encryption should succeed");
        let blob_debug = format!("{:?}", encrypted.encrypted_key_blob);
        let nonce_debug = format!("{:?}", encrypted.encryption_nonce);
        let debug = format!("{:?}", encrypted);

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&blob_debug));
        assert!(!debug.contains(&nonce_debug));
        assert!(!debug.contains("private key material"));
    }

    #[test]
    fn encrypted_key_safe_messages_do_not_contain_secret_material() {
        for message in [
            CA_ENCRYPTED_KEY_SYNCED_MESSAGE,
            KEY_FOB_ENCRYPTED_KEY_SYNCED_MESSAGE,
            ENCRYPTED_KEY_BLOBS_SYNCED_MESSAGE,
        ] {
            assert!(!message.contains("private key"));
            assert!(!message.contains("AIACS_MASTER_KEY"));
            assert!(!message.contains("DATABASE_URL"));
            assert!(!message.contains("postgresql://"));
            assert!(!message.contains("encrypted_key_blob"));
            assert!(!message.contains("encryption_nonce"));
            assert!(!message.contains("[1, 2, 3]"));
        }
    }

    #[test]
    fn encrypted_key_upsert_sql_uses_ciphertext_and_nonce_columns() {
        let sql = encrypted_key_sync_sql();

        assert!(sql.contains("INSERT INTO encrypted_keys"));
        assert!(sql.contains("ON CONFLICT (key_id) DO UPDATE"));
        assert!(sql.contains("encrypted_key_blob"));
        assert!(sql.contains("encryption_nonce"));
        assert!(sql.contains("encryption_algorithm"));
    }

    #[test]
    fn encrypted_key_upsert_sql_does_not_include_plaintext_secret_columns() {
        let sql = encrypted_key_sync_sql().to_lowercase();

        for disallowed in [
            "private_key",
            "raw_key",
            "session_key",
            "shared_secret",
            "master_key",
        ] {
            assert!(!sql.contains(disallowed));
        }
    }

    #[tokio::test]
    async fn live_cloud_database_health_check_is_opt_in() {
        if env::var("AIACS_RUN_LIVE_DB_TESTS").ok().as_deref() != Some("1") {
            return;
        }

        let client = CloudStorageClient::connect_from_env()
            .await
            .expect("live DB connection should succeed when explicitly enabled");
        let schema = client
            .initialize_schema()
            .await
            .expect("live DB schema initialization should succeed");
        let sync = client
            .sync_demo_metadata()
            .await
            .expect("live DB demo metadata sync should succeed");
        let certificate_sync = client
            .sync_demo_certificate_metadata()
            .await
            .expect("live DB certificate metadata sync should succeed");
        let master_key = parse_master_key_from_env()
            .expect("live encrypted key upload requires AIACS_MASTER_KEY");
        let ca_record = test_encrypted_key_record(
            CA_ENCRYPTED_KEY_ID,
            "ca",
            "AIACS-Demo-CA",
            CA_KEY_PURPOSE,
            b"test-only CA private key material",
            &master_key,
        );
        let key_fob_record = test_encrypted_key_record(
            KEY_FOB_ENCRYPTED_KEY_ID,
            "key_fob",
            DEMO_FOB_ID,
            KEY_FOB_KEY_PURPOSE,
            b"test-only key fob private key material",
            &master_key,
        );
        let encrypted_key_sync = client
            .sync_demo_encrypted_key_blobs(&ca_record, &key_fob_record)
            .await
            .expect("live DB encrypted key upload should succeed");
        let health = client
            .health_check()
            .await
            .expect("live DB health check should succeed");

        assert_eq!(schema, SCHEMA_INITIALIZED_MESSAGE);
        assert_eq!(sync, DEMO_METADATA_SYNCED_MESSAGE);
        assert_eq!(certificate_sync, CERTIFICATE_METADATA_SYNCED_MESSAGE);
        assert_eq!(encrypted_key_sync, ENCRYPTED_KEY_BLOBS_SYNCED_MESSAGE);
        assert_eq!(health, HEALTHY_MESSAGE);

        let customer_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM customers WHERE customer_id = $1);")
                .bind(DEMO_CUSTOMER_ID)
                .fetch_one(&client.pool)
                .await
                .expect("customer verification should query");
        let vehicle_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM vehicles WHERE vehicle_id = $1);")
                .bind(DEMO_VEHICLE_ID)
                .fetch_one(&client.pool)
                .await
                .expect("vehicle verification should query");
        let key_fob_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM key_fobs WHERE fob_id = $1);")
                .bind(DEMO_FOB_ID)
                .fetch_one(&client.pool)
                .await
                .expect("key fob verification should query");

        assert!(customer_exists);
        assert!(vehicle_exists);
        assert!(key_fob_exists);

        let certificate_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM certificates WHERE certificate_id = $1);",
        )
        .bind(DEMO_CERTIFICATE_ID)
        .fetch_one(&client.pool)
        .await
        .expect("certificate verification should query");
        let signature_algorithm: String = sqlx::query_scalar(
            "SELECT signature_algorithm FROM certificates WHERE certificate_id = $1;",
        )
        .bind(DEMO_CERTIFICATE_ID)
        .fetch_one(&client.pool)
        .await
        .expect("certificate signature algorithm should query");
        let certificate_status: String = sqlx::query_scalar(
            "SELECT certificate_status FROM certificates WHERE certificate_id = $1;",
        )
        .bind(DEMO_CERTIFICATE_ID)
        .fetch_one(&client.pool)
        .await
        .expect("certificate status should query");

        assert!(certificate_exists);
        assert_eq!(signature_algorithm, CERTIFICATE_SIGNATURE_ALGORITHM);
        assert_eq!(certificate_status, ISSUED_CERTIFICATE_STATUS);

        for key_id in [CA_ENCRYPTED_KEY_ID, KEY_FOB_ENCRYPTED_KEY_ID] {
            let encrypted_key_blob_len: i32 = sqlx::query_scalar(
                "SELECT octet_length(encrypted_key_blob) FROM encrypted_keys WHERE key_id = $1;",
            )
            .bind(key_id)
            .fetch_one(&client.pool)
            .await
            .expect("encrypted key blob length should query");
            let encryption_nonce_len: i32 = sqlx::query_scalar(
                "SELECT octet_length(encryption_nonce) FROM encrypted_keys WHERE key_id = $1;",
            )
            .bind(key_id)
            .fetch_one(&client.pool)
            .await
            .expect("encryption nonce length should query");
            let encryption_algorithm: String = sqlx::query_scalar(
                "SELECT encryption_algorithm FROM encrypted_keys WHERE key_id = $1;",
            )
            .bind(key_id)
            .fetch_one(&client.pool)
            .await
            .expect("encryption algorithm should query");

            assert!(encrypted_key_blob_len > 0);
            assert!(encryption_nonce_len > 0);
            assert_eq!(encryption_algorithm, ENCRYPTED_KEY_ALGORITHM);
        }
    }
}
