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
    use std::{
        net::{SocketAddr, TcpStream},
        path::{Path, PathBuf},
        time::Duration,
    };

    const DATABASE_NAME: &str = "luxor";
    const DATA_ROOT: &str = ".luxor/postgres";
    // The credentials guard a loopback-only development database; they must
    // be fixed so restarts and attached instances can reuse the initialized
    // cluster.
    const USERNAME: &str = "postgres";
    const PASSWORD: &str = "luxor";

    pub struct DevPostgres {
        mode: Mode,
    }

    enum Mode {
        /// This instance started the server and stops it on shutdown.
        Owned(Box<PostgreSQL>),
        /// Another Luxor instance owns the server; reuse it and leave its
        /// lifecycle alone.
        Attached { port: u16 },
    }

    impl DevPostgres {
        /// Installs (first run only), starts, and prepares the embedded
        /// server, listening on a random free localhost port. If another
        /// instance is already running the workspace's server, it is reused
        /// instead.
        pub async fn start() -> anyhow::Result<Self> {
            let root = PathBuf::from(DATA_ROOT);
            std::fs::create_dir_all(&root)
                .with_context(|| format!("could not create {}", root.display()))?;
            let data_dir = root.join("data");

            if let Some(port) = live_server_port(&data_dir) {
                tracing::info!(
                    port,
                    "reusing the embedded PostgreSQL server another Luxor instance is running"
                );
                return Ok(Self {
                    mode: Mode::Attached { port },
                });
            }

            let settings = Settings {
                // Track the same major release as the Compose postgres image.
                version: VersionReq::parse("=17").expect("valid version requirement"),
                data_dir,
                password_file: root.join(".pgpass"),
                username: USERNAME.to_owned(),
                password: PASSWORD.to_owned(),
                temporary: false,
                // First start covers initdb and a cold boot, which can exceed
                // the crate's 5 second default on slower machines.
                timeout: Some(Duration::from_secs(60)),
                ..Settings::default()
            };

            let mut server = PostgreSQL::new(settings);
            if let Err(error) = server.setup().await {
                forget_failed_server(server);
                return Err(anyhow::Error::new(error).context(
                    "could not install the embedded PostgreSQL server (the first run downloads it and needs network access)",
                ));
            }
            if let Err(error) = server.start().await {
                forget_failed_server(server);
                return Err(anyhow::Error::new(error)
                    .context("could not start the embedded PostgreSQL server"));
            }
            if !server.database_exists(DATABASE_NAME).await? {
                server.create_database(DATABASE_NAME).await?;
            }
            Ok(Self {
                mode: Mode::Owned(Box::new(server)),
            })
        }

        pub fn database_url(&self) -> SecretString {
            match &self.mode {
                Mode::Owned(server) => SecretString::from(server.settings().url(DATABASE_NAME)),
                Mode::Attached { port } => SecretString::from(format!(
                    "postgresql://{USERNAME}:{PASSWORD}@localhost:{port}/{DATABASE_NAME}"
                )),
            }
        }

        pub async fn stop(self) {
            match self.mode {
                Mode::Owned(server) => {
                    if let Err(error) = server.stop().await {
                        tracing::warn!(?error, "embedded PostgreSQL server did not stop cleanly");
                    }
                }
                Mode::Attached { .. } => {}
            }
        }
    }

    /// The crate's `Drop` stops whichever server holds the data directory —
    /// it checks `postmaster.pid`, not whether this handle started it — so a
    /// handle whose startup failed must be leaked, never dropped, or it would
    /// take down a concurrently running instance's server.
    fn forget_failed_server(server: PostgreSQL) {
        std::mem::forget(server);
    }

    /// Returns the port of a reachable PostgreSQL server already serving this
    /// data directory, if any. A stale `postmaster.pid` without a listener is
    /// ignored; PostgreSQL clears it on the next start.
    fn live_server_port(data_dir: &Path) -> Option<u16> {
        let pid_file = std::fs::read_to_string(data_dir.join("postmaster.pid")).ok()?;
        // postmaster.pid line 4 is the server port.
        let port = pid_file.lines().nth(3)?.trim().parse::<u16>().ok()?;
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        TcpStream::connect_timeout(&address, Duration::from_millis(250))
            .is_ok()
            .then_some(port)
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
