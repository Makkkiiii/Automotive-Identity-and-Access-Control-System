use sqlx::{postgres::PgPoolOptions, PgPool};
use std::env;
use std::fmt;

const ENV_FILE: &str = ".env.local";
const DATABASE_URL_ENV: &str = "DATABASE_URL";
const HEALTHY_MESSAGE: &str = "Cloud database connection healthy";

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
}

impl fmt::Display for CloudStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudStorageError::MissingDatabaseUrl => f.write_str("DATABASE_URL is not configured"),
            CloudStorageError::ConnectionFailed => f.write_str("Cloud database connection failed"),
            CloudStorageError::HealthCheckFailed => {
                f.write_str("Cloud database health check failed")
            }
        }
    }
}

impl std::error::Error for CloudStorageError {}

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

    #[tokio::test]
    async fn live_cloud_database_health_check_is_opt_in() {
        if env::var("AIACS_RUN_LIVE_DB_TESTS").ok().as_deref() != Some("1") {
            return;
        }

        let client = CloudStorageClient::connect_from_env()
            .await
            .expect("live DB connection should succeed when explicitly enabled");
        let health = client
            .health_check()
            .await
            .expect("live DB health check should succeed");

        assert_eq!(health, HEALTHY_MESSAGE);
    }
}
