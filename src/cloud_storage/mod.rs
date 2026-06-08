use sqlx::{postgres::PgPoolOptions, PgPool};
use std::env;
use std::fmt;

const ENV_FILE: &str = ".env.local";
const DATABASE_URL_ENV: &str = "DATABASE_URL";
const HEALTHY_MESSAGE: &str = "Cloud database connection healthy";
const SCHEMA_INITIALIZED_MESSAGE: &str = "Cloud database schema initialized";

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
        let health = client
            .health_check()
            .await
            .expect("live DB health check should succeed");

        assert_eq!(schema, SCHEMA_INITIALIZED_MESSAGE);
        assert_eq!(health, HEALTHY_MESSAGE);
    }
}
