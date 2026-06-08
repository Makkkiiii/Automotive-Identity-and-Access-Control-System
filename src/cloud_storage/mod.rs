use sqlx::{postgres::PgPoolOptions, PgPool};
use std::env;
use std::fmt;

const ENV_FILE: &str = ".env.local";
const DATABASE_URL_ENV: &str = "DATABASE_URL";
const HEALTHY_MESSAGE: &str = "Cloud database connection healthy";
const SCHEMA_INITIALIZED_MESSAGE: &str = "Cloud database schema initialized";
const CUSTOMER_SYNCED_MESSAGE: &str = "Customer metadata synced";
const VEHICLE_SYNCED_MESSAGE: &str = "Vehicle metadata synced";
const KEY_FOB_SYNCED_MESSAGE: &str = "Key fob metadata synced";
const DEMO_METADATA_SYNCED_MESSAGE: &str = "Demo metadata synced to cloud database";

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
    certificate_signature_fingerprint TEXT,
    certificate_json JSONB,
    created_at TIMESTAMPTZ NOT NULL
);
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
    ConnectionFailed,
    HealthCheckFailed,
    SchemaInitializationFailed,
    MetadataSyncFailed,
}

impl fmt::Display for CloudStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudStorageError::MissingDatabaseUrl => f.write_str("DATABASE_URL is not configured"),
            CloudStorageError::ConnectionFailed => f.write_str("Cloud database connection failed"),
            CloudStorageError::HealthCheckFailed => {
                f.write_str("Cloud database health check failed")
            }
            CloudStorageError::SchemaInitializationFailed => {
                f.write_str("Cloud database schema initialization failed")
            }
            CloudStorageError::MetadataSyncFailed => f.write_str("Cloud metadata sync failed"),
        }
    }
}

impl std::error::Error for CloudStorageError {}

fn schema_initialized_message() -> &'static str {
    SCHEMA_INITIALIZED_MESSAGE
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
        ] {
            assert!(!message.contains("DATABASE_URL"));
            assert!(!message.contains("AIACS_MASTER_KEY"));
            assert!(!message.contains("postgresql://"));
            assert!(!message.contains("private_key"));
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
        let health = client
            .health_check()
            .await
            .expect("live DB health check should succeed");

        assert_eq!(schema, SCHEMA_INITIALIZED_MESSAGE);
        assert_eq!(sync, DEMO_METADATA_SYNCED_MESSAGE);
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
    }
}
