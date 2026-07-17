//! Embedded development PostgreSQL server.
//!
//! When `DATABASE_URL` is not set outside production, Luxor runs a real,
//! app-managed PostgreSQL server so that authentication and persistence work
//! without Docker or any locally installed database. Binaries are downloaded
//! once into `~/.theseus/postgresql` and the cluster data lives in `.luxor/`
//! inside the working directory, so accounts and sessions survive restarts.
//!
//! Production images are built without the `embedded-postgres` feature; their
//! configuration requires an explicit `DATABASE_URL`, so this fallback can
//! never activate there.

pub use imp::DevPostgres;

#[cfg(feature = "embedded-postgres")]
mod imp {
    use anyhow::Context;
    use postgresql_embedded::{PostgreSQL, Settings, VersionReq};
    use secrecy::SecretString;
    use std::{path::PathBuf, time::Duration};

    const DATABASE_NAME: &str = "luxor";
    const DATA_ROOT: &str = ".luxor/postgres";

    pub struct DevPostgres {
        server: PostgreSQL,
    }

    impl DevPostgres {
        /// Installs (first run only), starts, and prepares the embedded
        /// server, listening on a random free localhost port.
        pub async fn start() -> anyhow::Result<Self> {
            let root = PathBuf::from(DATA_ROOT);
            std::fs::create_dir_all(&root)
                .with_context(|| format!("could not create {}", root.display()))?;

            let settings = Settings {
                // Track the same major release as the Compose postgres image.
                version: VersionReq::parse("=17").expect("valid version requirement"),
                data_dir: root.join("data"),
                password_file: root.join(".pgpass"),
                // The credentials guard a loopback-only development database;
                // they must be fixed so restarts can reuse the initialized
                // cluster.
                password: "luxor".to_owned(),
                temporary: false,
                // First start covers initdb and a cold boot, which can exceed
                // the crate's 5 second default on slower machines.
                timeout: Some(Duration::from_secs(60)),
                ..Settings::default()
            };

            let mut server = PostgreSQL::new(settings);
            server
                .setup()
                .await
                .context("could not install the embedded PostgreSQL server (the first run downloads it and needs network access)")?;
            server
                .start()
                .await
                .context("could not start the embedded PostgreSQL server")?;
            if !server.database_exists(DATABASE_NAME).await? {
                server.create_database(DATABASE_NAME).await?;
            }
            Ok(Self { server })
        }

        pub fn database_url(&self) -> SecretString {
            SecretString::from(self.server.settings().url(DATABASE_NAME))
        }

        pub async fn stop(self) {
            if let Err(error) = self.server.stop().await {
                tracing::warn!(?error, "embedded PostgreSQL server did not stop cleanly");
            }
        }
    }
}

#[cfg(not(feature = "embedded-postgres"))]
mod imp {
    use secrecy::SecretString;

    /// Stub that keeps startup compiling when the embedded server feature is
    /// disabled; `start` is the only constructor and it always fails.
    pub struct DevPostgres {
        _unconstructible: std::convert::Infallible,
    }

    impl DevPostgres {
        pub async fn start() -> anyhow::Result<Self> {
            anyhow::bail!(
                "DATABASE_URL is not set and this build excludes the embedded development \
                 database (embedded-postgres feature); set DATABASE_URL to a reachable \
                 PostgreSQL instance"
            )
        }

        pub fn database_url(&self) -> SecretString {
            match self._unconstructible {}
        }

        pub async fn stop(self) {
            match self._unconstructible {}
        }
    }
}
