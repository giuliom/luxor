//! The listener and the HTTP policy every response is served under.

use crate::config::{validate_origin, ConfigError, Env};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

/// How the app decides a request reached it over TLS. TLS is terminated by
/// the platform proxy, never in-process, so the only available signal is what
/// that proxy reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpsEnforcement {
    /// Accept plaintext. Correct for local development, and for a deployment
    /// whose proxy does not set `x-forwarded-proto`.
    Off,
    /// Turn away requests the proxy marked as plaintext. Carries the same
    /// trust assumption as `CLIENT_IP_SOURCE=x-forwarded-for`: safe only when
    /// a proxy always overwrites the header, since a directly reachable app
    /// lets clients forge it.
    ProxyHeader,
}

impl FromStr for HttpsEnforcement {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "proxy-header" => Ok(Self::ProxyHeader),
            _ => Err(ConfigError::Invalid("HTTPS_ENFORCEMENT", value.to_owned())),
        }
    }
}

/// `Strict-Transport-Security`: how long a browser refuses to reach this host
/// over plaintext after a single successful HTTPS response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HstsSettings {
    pub enabled: bool,
    pub max_age_seconds: u64,
    pub include_subdomains: bool,
    pub preload: bool,
}

impl HstsSettings {
    pub fn header_value(&self) -> String {
        let mut value = format!("max-age={}", self.max_age_seconds);
        if self.include_subdomains {
            value.push_str("; includeSubDomains");
        }
        if self.preload {
            value.push_str("; preload");
        }
        value
    }
}

#[derive(Clone, Debug)]
pub struct HttpSettings {
    pub host: String,
    pub port: u16,
    pub cors_origins: Vec<String>,
    pub body_limit_bytes: usize,
    pub request_timeout_seconds: u64,
    pub hsts: HstsSettings,
    pub https_enforcement: HttpsEnforcement,
    /// Development-only: open the frontend in the system browser once the
    /// listener is bound.
    pub open_browser: bool,
    /// See [`HttpSettings::public_base_url`].
    public_base_url: String,
    bind_address: SocketAddr,
}

impl HttpSettings {
    pub fn from_env(env: &Env) -> Result<Self, ConfigError> {
        let production = env.is_production();

        // Deployed containers sit behind a platform proxy and must accept
        // traffic on all interfaces; local development stays loopback-only.
        let default_host = if production { "0.0.0.0" } else { "127.0.0.1" };
        let host = env.get("APP_HOST").unwrap_or(default_host).to_owned();
        let ip = host
            .parse::<IpAddr>()
            .map_err(|error| ConfigError::Invalid("APP_HOST", error.to_string()))?;
        // Platforms such as Railway and Heroku inject PORT and route traffic
        // to it, so it must win over the locally documented APP_PORT.
        let port = env.parse("PORT", env.parse("APP_PORT", 8080_u16)?)?;
        if port == 0 {
            return Err(ConfigError::Validation(
                "APP_PORT must be greater than zero".into(),
            ));
        }

        let cors_origins = env
            .get("CORS_ORIGINS")
            .unwrap_or("https://localhost:8080")
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if cors_origins.is_empty() {
            return Err(ConfigError::Validation(
                "CORS_ORIGINS must contain at least one origin".into(),
            ));
        }
        for origin in &cors_origins {
            validate_origin("CORS_ORIGINS", origin, production)?;
        }

        // The origin baked into canonical URLs, hreflang alternates, and the
        // sitemap. Origin-only, because the localized routes live at the root
        // of the site; a path prefix would produce URLs the router never
        // serves. An explicit value wins; production falls back to the first
        // CORS origin, which deployments already set to the public URL;
        // development falls back to the local listener address.
        let public_base_url = match env.get("PUBLIC_BASE_URL") {
            Some(value) => {
                validate_origin("PUBLIC_BASE_URL", value, production)?;
                value.trim_end_matches('/').to_owned()
            }
            None if production => cors_origins[0].trim_end_matches('/').to_owned(),
            None => format!("http://{host}:{port}"),
        };

        let body_limit_bytes = env.parse("BODY_LIMIT_BYTES", 1_048_576_usize)?;
        if body_limit_bytes == 0 {
            return Err(ConfigError::Validation(
                "BODY_LIMIT_BYTES must be greater than zero".into(),
            ));
        }
        let request_timeout_seconds = env.parse("REQUEST_TIMEOUT_SECONDS", 30_u64)?;
        if request_timeout_seconds == 0 {
            return Err(ConfigError::Validation(
                "REQUEST_TIMEOUT_SECONDS must be greater than zero".into(),
            ));
        }

        let hsts = parse_hsts(env)?;
        // Production sits behind a platform proxy that terminates TLS and
        // reports the original scheme; local development is reached directly
        // over plaintext http, where the check would reject every request.
        let https_enforcement = match env.get("HTTPS_ENFORCEMENT") {
            Some(value) => value.parse()?,
            None if production => HttpsEnforcement::ProxyHeader,
            None => HttpsEnforcement::Off,
        };
        let open_browser = env.parse("APP_OPEN_BROWSER", false)?;
        if production && open_browser {
            return Err(ConfigError::Validation(
                "APP_OPEN_BROWSER cannot be enabled in production".into(),
            ));
        }

        Ok(Self {
            host,
            port,
            cors_origins,
            body_limit_bytes,
            request_timeout_seconds,
            hsts,
            https_enforcement,
            open_browser,
            public_base_url,
            bind_address: SocketAddr::new(ip, port),
        })
    }

    pub fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }

    /// The absolute origin used in canonical URLs, hreflang alternates, and
    /// the sitemap: `PUBLIC_BASE_URL` when set, otherwise the first CORS
    /// origin in production and the local listener address elsewhere.
    pub fn public_base_url(&self) -> &str {
        &self.public_base_url
    }
}

/// Requirements published by the browser preload list: a two-year max-age is
/// the usual submission, and one year is the documented floor.
const HSTS_PRELOAD_MIN_MAX_AGE: u64 = 31_536_000;

fn parse_hsts(env: &Env) -> Result<HstsSettings, ConfigError> {
    // Sending HSTS from a development server would pin the developer's browser
    // to https on localhost for a year, breaking every other local project on
    // that port.
    let enabled = env.parse("HSTS_ENABLED", env.is_production())?;
    // Zero is allowed and meaningful: it is the only way to release browsers
    // that already cached a policy for this host.
    let max_age_seconds = env.parse("HSTS_MAX_AGE_SECONDS", 31_536_000_u64)?;
    let include_subdomains = env.parse("HSTS_INCLUDE_SUBDOMAINS", true)?;
    let preload = env.parse("HSTS_PRELOAD", false)?;

    if preload && !enabled {
        return Err(ConfigError::Validation(
            "HSTS_PRELOAD requires HSTS_ENABLED".into(),
        ));
    }
    // Submitting a host to the preload list is close to irreversible, so a
    // header that claims preload while failing the list's own requirements is
    // rejected here rather than silently ignored by the browser.
    if preload && (!include_subdomains || max_age_seconds < HSTS_PRELOAD_MIN_MAX_AGE) {
        return Err(ConfigError::Validation(format!(
            "HSTS_PRELOAD requires HSTS_INCLUDE_SUBDOMAINS and an HSTS_MAX_AGE_SECONDS of at least {HSTS_PRELOAD_MIN_MAX_AGE}"
        )));
    }

    Ok(HstsSettings {
        enabled,
        max_age_seconds,
        include_subdomains,
        preload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::values;

    fn settings(pairs: &[(&str, &str)]) -> Result<HttpSettings, ConfigError> {
        HttpSettings::from_env(&Env::new(values(pairs))?)
    }

    /// Production rejects plaintext origins, so a valid production fixture has
    /// to carry an https one.
    fn production(extra: &[(&str, &str)]) -> Result<HttpSettings, ConfigError> {
        let mut pairs = vec![
            ("APP_ENV", "production"),
            ("CORS_ORIGINS", "https://app.example.com"),
        ];
        pairs.extend_from_slice(extra);
        settings(&pairs)
    }

    #[test]
    fn development_defaults_are_valid() {
        let http = settings(&[]).unwrap();
        assert_eq!(http.port, 8080);
        assert_eq!(http.cors_origins, vec!["https://localhost:8080"]);
        assert_eq!(http.request_timeout_seconds, 30);
        assert!(!http.open_browser);
    }

    #[test]
    fn request_timeout_must_be_positive() {
        assert!(matches!(
            settings(&[("REQUEST_TIMEOUT_SECONDS", "0")]),
            Err(ConfigError::Validation(message)) if message.contains("REQUEST_TIMEOUT_SECONDS")
        ));
    }

    #[test]
    fn browser_launch_is_development_only() {
        assert!(
            settings(&[("APP_OPEN_BROWSER", "true")])
                .unwrap()
                .open_browser
        );
        assert!(matches!(
            production(&[("APP_OPEN_BROWSER", "true")]),
            Err(ConfigError::Validation(message)) if message.contains("APP_OPEN_BROWSER")
        ));
    }

    #[test]
    fn injected_platform_port_wins_over_app_port() {
        let http = settings(&[("APP_PORT", "3000"), ("PORT", "8080")]).unwrap();
        assert_eq!(http.port, 8080);
        assert_eq!(http.bind_address().port(), 8080);
    }

    #[test]
    fn production_binds_all_interfaces_by_default() {
        assert_eq!(production(&[]).unwrap().host, "0.0.0.0");
        assert_eq!(settings(&[]).unwrap().host, "127.0.0.1");
    }

    #[test]
    fn invalid_listener_and_cors_values_are_rejected() {
        assert!(matches!(
            settings(&[("APP_HOST", "localhost")]),
            Err(ConfigError::Invalid("APP_HOST", _))
        ));
        assert!(matches!(
            settings(&[("CORS_ORIGINS", "https://example.com/a-path")]),
            Err(ConfigError::Invalid("CORS_ORIGINS", _))
        ));
    }

    #[test]
    fn public_base_url_is_explicit_or_derived() {
        // Development derives the listener address; production derives the
        // deployment's public URL, already configured as the CORS origin.
        assert_eq!(
            settings(&[]).unwrap().public_base_url(),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            production(&[]).unwrap().public_base_url(),
            "https://app.example.com"
        );
        assert_eq!(
            settings(&[("PUBLIC_BASE_URL", "https://console.example.com/")])
                .unwrap()
                .public_base_url(),
            "https://console.example.com"
        );

        // The localized routes live at the site root, so a path prefix would
        // produce canonical URLs the router never serves.
        assert!(matches!(
            settings(&[("PUBLIC_BASE_URL", "https://example.com/console")]),
            Err(ConfigError::Invalid("PUBLIC_BASE_URL", _))
        ));

        // Canonical URLs advertise where credentials will be sent; plaintext
        // in production is the same mistake as a plaintext CORS origin.
        assert!(matches!(
            production(&[("PUBLIC_BASE_URL", "http://app.example.com")]),
            Err(ConfigError::Invalid("PUBLIC_BASE_URL", _))
        ));
    }

    #[test]
    fn hsts_defaults_follow_the_environment() {
        let development = settings(&[]).unwrap();
        assert!(!development.hsts.enabled);
        assert_eq!(development.https_enforcement, HttpsEnforcement::Off);

        let production = production(&[]).unwrap();
        assert!(production.hsts.enabled);
        assert!(production.hsts.include_subdomains);
        assert!(!production.hsts.preload);
        assert_eq!(
            production.hsts.header_value(),
            "max-age=31536000; includeSubDomains"
        );
        assert_eq!(production.https_enforcement, HttpsEnforcement::ProxyHeader);
    }

    #[test]
    fn hsts_preload_requires_the_preload_list_rules() {
        assert!(matches!(
            production(&[("HSTS_PRELOAD", "true"), ("HSTS_INCLUDE_SUBDOMAINS", "false")]),
            Err(ConfigError::Validation(message)) if message.contains("HSTS_PRELOAD")
        ));
        assert!(matches!(
            production(&[("HSTS_PRELOAD", "true"), ("HSTS_MAX_AGE_SECONDS", "3600")]),
            Err(ConfigError::Validation(message)) if message.contains("HSTS_PRELOAD")
        ));
        assert!(matches!(
            production(&[("HSTS_PRELOAD", "true"), ("HSTS_ENABLED", "false")]),
            Err(ConfigError::Validation(message)) if message.contains("HSTS_ENABLED")
        ));

        let valid = production(&[
            ("HSTS_PRELOAD", "true"),
            ("HSTS_MAX_AGE_SECONDS", "63072000"),
        ])
        .unwrap();
        assert_eq!(
            valid.hsts.header_value(),
            "max-age=63072000; includeSubDomains; preload"
        );
    }

    // max-age=0 is the only way to release browsers that already cached a
    // policy, so it must stay expressible.
    #[test]
    fn hsts_max_age_can_be_zeroed_to_release_browsers() {
        let http = production(&[("HSTS_MAX_AGE_SECONDS", "0")]).unwrap();
        assert_eq!(http.hsts.header_value(), "max-age=0; includeSubDomains");
    }

    #[test]
    fn production_rejects_plaintext_cors_origins() {
        assert!(matches!(
            production(&[("CORS_ORIGINS", "http://app.example.com")]),
            Err(ConfigError::Invalid("CORS_ORIGINS", message)) if message.contains("https")
        ));

        // Mixed lists are rejected on the offending entry, not silently
        // accepted because a valid origin appears first.
        assert!(matches!(
            production(&[(
                "CORS_ORIGINS",
                "https://app.example.com,http://staging.example.com"
            )]),
            Err(ConfigError::Invalid("CORS_ORIGINS", _))
        ));

        // Outside production a plaintext origin is how local development runs.
        assert_eq!(
            settings(&[("CORS_ORIGINS", "http://localhost:5173")])
                .unwrap()
                .cors_origins,
            vec!["http://localhost:5173"]
        );
    }

    #[test]
    fn https_enforcement_rejects_unknown_modes() {
        assert!(matches!(
            production(&[("HTTPS_ENFORCEMENT", "maybe")]),
            Err(ConfigError::Invalid("HTTPS_ENFORCEMENT", _))
        ));
        assert_eq!(
            production(&[("HTTPS_ENFORCEMENT", "off")])
                .unwrap()
                .https_enforcement,
            HttpsEnforcement::Off
        );
    }
}
