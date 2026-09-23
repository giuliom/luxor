//! Prebuilt HTTP representations for everything the server sends that is not
//! an API response: the rendered console pages, the sitemap and robots.txt,
//! and the static files compiled into the binary.
//!
//! Every one of these bodies is fixed for the life of the process, so the work
//! a response needs is done once, when the router is built: each body is
//! gzip-compressed ahead of time and given a strong `ETag`, and each static
//! file is given a content-addressed URL. Serving is then a header comparison
//! and a reference-count increment — no templating, hashing, or compression
//! happens on the request path.
//!
//! The URLs decide the cache policy. A content-addressed URL
//! (`/assets/styles.<fingerprint>.css`) names bytes that can never change, so
//! it is cached for a year without revalidation, and a deployment that changes
//! the file changes the URL the pages reference. Everything else — the pages
//! themselves, and the stable file names kept for bookmarks and older pages —
//! is revalidated on every use, which the `ETag` answers with a bodiless 304.
//!
//! Compression is confined to these representations. API responses are not
//! compressed: they carry access tokens next to request-influenced content,
//! the combination a BREACH-style length oracle needs, whereas these bodies
//! are identical for every visitor and hold no secret.

use axum::{
    body::Bytes,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, MethodRouter},
};
use flate2::{write::GzEncoder, Compression};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    sync::{Arc, LazyLock},
};

/// How long a browser or shared cache may reuse a response without asking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CachePolicy {
    /// Stored, but revalidated before every reuse: for URLs whose content
    /// changes when a deployment does.
    Revalidate,
    /// Reused for a year without revalidation: only for content-addressed
    /// URLs, whose content cannot change without the URL changing too.
    Immutable,
}

impl CachePolicy {
    fn header_value(self) -> HeaderValue {
        HeaderValue::from_static(match self {
            Self::Revalidate => "no-cache",
            Self::Immutable => "public, max-age=31536000, immutable",
        })
    }
}

/// One encoding of a body, with the strong validator for exactly these bytes.
struct Representation {
    body: Bytes,
    /// Hex SHA-256 prefix of `body`.
    digest: String,
    etag: HeaderValue,
}

impl Representation {
    fn new(body: Bytes) -> Self {
        // 128 bits: collision-free across any realistic number of versions,
        // and short enough to send on every response.
        let digest: String = Sha256::digest(&body)[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let etag = HeaderValue::try_from(format!("\"{digest}\""))
            .expect("a quoted hex digest is a valid header value");
        Self { body, digest, etag }
    }
}

/// A fixed body, served with conditional-request and content-coding support.
pub struct Asset {
    content_type: HeaderValue,
    /// The natural language of the body, for text written for people.
    content_language: Option<HeaderValue>,
    identity: Representation,
    /// Absent when compression would not make the body smaller.
    gzip: Option<Representation>,
}

impl Asset {
    pub fn new(content_type: &'static str, body: impl Into<Bytes>) -> Self {
        let body = body.into();
        let compressed = gzip(&body);
        // A tiny body can grow under gzip's fixed overhead; offering that
        // coding would only cost the client a decompression.
        let gzip =
            (compressed.len() < body.len()).then(|| Representation::new(Bytes::from(compressed)));
        Self {
            content_type: HeaderValue::from_static(content_type),
            content_language: None,
            identity: Representation::new(body),
            gzip,
        }
    }

    /// Declares the body's language (a BCP 47 tag) in `Content-Language`,
    /// the HTTP counterpart of `<html lang>`.
    pub fn with_content_language(mut self, language: &'static str) -> Self {
        self.content_language = Some(HeaderValue::from_static(language));
        self
    }

    /// A short digest of the uncompressed body, for content-addressed URLs.
    pub fn fingerprint(&self) -> &str {
        &self.identity.digest[..16]
    }

    /// Answers a GET or HEAD for this body.
    pub fn respond(&self, request: &HeaderMap, policy: CachePolicy) -> Response {
        let (representation, coding) = match &self.gzip {
            Some(gzip) if accepts_gzip(request) => (gzip, Some(HeaderValue::from_static("gzip"))),
            _ => (&self.identity, None),
        };

        let mut headers = HeaderMap::new();
        headers.insert(header::CACHE_CONTROL, policy.header_value());
        headers.insert(header::ETAG, representation.etag.clone());
        if self.gzip.is_some() {
            // The coding is chosen per request at one URL, so every response
            // for it — either coding, or a 304 — must tell caches it was.
            headers.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
        }

        // Validators are compared against the representation this request
        // would receive. Each coding has its own ETag, so a cached gzip body
        // is never confirmed to a client asking for the uncompressed one.
        if not_modified(request, &representation.etag) {
            return (StatusCode::NOT_MODIFIED, headers).into_response();
        }

        // Representation metadata travels only with a body; a 304 carries
        // just what updates the cached copy (RFC 9110 §15.4.5).
        headers.insert(header::CONTENT_TYPE, self.content_type.clone());
        if let Some(language) = &self.content_language {
            headers.insert(header::CONTENT_LANGUAGE, language.clone());
        }
        if let Some(coding) = coding {
            headers.insert(header::CONTENT_ENCODING, coding);
        }
        (headers, representation.body.clone()).into_response()
    }
}

/// A GET (and HEAD) route that answers with `asset` under `policy`.
pub fn serve<S>(asset: Arc<Asset>, policy: CachePolicy) -> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    get(move |headers: HeaderMap| async move { asset.respond(&headers, policy) })
}

fn gzip(body: &[u8]) -> Vec<u8> {
    // Each body is compressed once, at startup, so the smallest output is
    // worth the slowest level.
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(body)
        .expect("writing to a Vec cannot fail");
    encoder.finish().expect("writing to a Vec cannot fail")
}

/// Whether the request accepts a gzip-coded response.
///
/// An explicit `gzip` entry (or its `x-gzip` alias) decides; otherwise a `*`
/// entry does. A missing header selects the uncompressed body: RFC 9110 lets
/// a server choose any coding then, but the clients that send none — scripts,
/// health checks, `curl` without `--compressed` — are exactly the ones that
/// cannot decode one. An unreadable quality counts as a refusal, because the
/// uncompressed body is always a safe answer.
fn accepts_gzip(request: &HeaderMap) -> bool {
    let mut gzip = None;
    let mut wildcard = None;
    for value in request.get_all(header::ACCEPT_ENCODING) {
        let Ok(value) = value.to_str() else { continue };
        for entry in value.split(',') {
            let mut parameters = entry.split(';');
            let coding = parameters.next().unwrap_or_default().trim();
            let acceptable = parameters
                .find_map(|parameter| {
                    let (name, value) = parameter.split_once('=')?;
                    name.trim().eq_ignore_ascii_case("q").then(|| value.trim())
                })
                .is_none_or(|quality| quality.parse::<f32>().is_ok_and(|quality| quality > 0.0));
            if coding.eq_ignore_ascii_case("gzip") || coding.eq_ignore_ascii_case("x-gzip") {
                gzip = Some(acceptable);
            } else if coding == "*" {
                wildcard = Some(acceptable);
            }
        }
    }
    gzip.or(wildcard).unwrap_or(false)
}

/// Evaluates `If-None-Match` for a GET or HEAD (RFC 9110 §13.1.2): the
/// condition fails — and the answer is 304 — on `*` or on any listed tag
/// equal to `etag` under weak comparison, which ignores a `W/` prefix an
/// intermediary may have added.
fn not_modified(request: &HeaderMap, etag: &HeaderValue) -> bool {
    request.get_all(header::IF_NONE_MATCH).iter().any(|value| {
        value
            .as_bytes()
            .split(|&byte| byte == b',')
            .map(<[u8]>::trim_ascii)
            .any(|tag| tag == b"*" || tag.strip_prefix(b"W/").unwrap_or(tag) == etag.as_bytes())
    })
}

/// A file compiled into the binary, reachable at two URLs.
pub struct StaticFile {
    /// The file's stable name, kept for anything that addresses it directly —
    /// bookmarks, crawlers, a page rendered by the previous deployment — and
    /// revalidated on every use, since a deployment may change its content.
    pub path: &'static str,
    /// `/assets/<stem>.<fingerprint>.<extension>`, which changes whenever the
    /// content does. The rendered pages reference only this form.
    pub fingerprinted_path: String,
    pub asset: Arc<Asset>,
}

impl StaticFile {
    fn new(path: &'static str, content_type: &'static str, body: &'static [u8]) -> Self {
        let asset = Asset::new(content_type, Bytes::from_static(body));
        let (stem, extension) = path
            .trim_start_matches('/')
            .rsplit_once('.')
            .expect("static file names carry an extension");
        let fingerprinted_path = format!("/assets/{stem}.{}.{extension}", asset.fingerprint());
        Self {
            path,
            fingerprinted_path,
            asset: Arc::new(asset),
        }
    }
}

/// The static files the console pages load.
pub struct StaticFiles {
    pub styles: StaticFile,
    pub script: StaticFile,
    pub favicon: StaticFile,
    /// Fetched on demand by the WebAssembly card, from the URL the page hands
    /// the script.
    pub wasm: StaticFile,
}

impl StaticFiles {
    pub fn all(&self) -> [&StaticFile; 4] {
        [&self.styles, &self.script, &self.favicon, &self.wasm]
    }
}

/// The embedded static files, fingerprinted and compressed once per process:
/// their content is fixed at compile time, so every router shares one copy.
pub fn embedded() -> &'static StaticFiles {
    static FILES: LazyLock<StaticFiles> = LazyLock::new(|| StaticFiles {
        styles: StaticFile::new(
            "/styles.css",
            "text/css; charset=utf-8",
            include_bytes!("../public/styles.css"),
        ),
        script: StaticFile::new(
            "/script.js",
            "text/javascript; charset=utf-8",
            include_bytes!("../public/script.js"),
        ),
        favicon: StaticFile::new(
            "/favicon.svg",
            "image/svg+xml; charset=utf-8",
            include_bytes!("../public/favicon.svg"),
        ),
        // WebAssembly.instantiateStreaming requires exactly this content
        // type, with no parameters.
        wasm: StaticFile::new(
            "/demo.wasm",
            "application/wasm",
            include_bytes!("../public/demo.wasm"),
        ),
    });
    &FILES
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use flate2::read::GzDecoder;
    use std::io::Read;

    fn request_with(name: header::HeaderName, value: &'static str) -> HeaderMap {
        HeaderMap::from_iter([(name, HeaderValue::from_static(value))])
    }

    /// Large and repetitive enough that gzip always pays for itself.
    fn compressible_asset() -> Asset {
        Asset::new("text/plain; charset=utf-8", "luxor ".repeat(200))
    }

    #[test]
    fn gzip_is_chosen_only_when_the_client_accepts_it() {
        for (accept_encoding, expected) in [
            ("gzip", true),
            ("gzip, deflate, br, zstd", true),
            ("br;q=1.0, gzip;q=0.8", true),
            ("GZIP", true),
            ("x-gzip", true),
            ("gzip; Q=0.5", true),
            ("*", true),
            ("*;q=0, gzip", true),
            ("gzip;q=0", false),
            ("gzip; q=0.000", false),
            ("*;q=0", false),
            ("br, *;q=0", false),
            // An explicit entry outranks the wildcard.
            ("gzip;q=0, *", false),
            ("identity", false),
            ("br, deflate", false),
            ("", false),
            ("gzip;q=nonsense", false),
        ] {
            assert_eq!(
                accepts_gzip(&request_with(header::ACCEPT_ENCODING, accept_encoding)),
                expected,
                "Accept-Encoding: {accept_encoding:?}"
            );
        }
        // No header at all is the plain client, not a wildcard.
        assert!(!accepts_gzip(&HeaderMap::new()));

        // Repeated header lines are one list.
        let mut split = HeaderMap::new();
        split.append(header::ACCEPT_ENCODING, HeaderValue::from_static("br"));
        split.append(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(accepts_gzip(&split));
    }

    #[test]
    fn if_none_match_uses_weak_comparison() {
        let etag = HeaderValue::from_static("\"0123abcd\"");
        for (if_none_match, expected) in [
            ("\"0123abcd\"", true),
            ("W/\"0123abcd\"", true),
            ("\"stale\", \"0123abcd\"", true),
            ("\"stale\",W/\"0123abcd\"", true),
            ("*", true),
            ("\"stale\"", false),
            ("0123abcd", false),
            ("\"0123abc\"", false),
            ("", false),
        ] {
            assert_eq!(
                not_modified(&request_with(header::IF_NONE_MATCH, if_none_match), &etag),
                expected,
                "If-None-Match: {if_none_match:?}"
            );
        }
        assert!(!not_modified(&HeaderMap::new(), &etag));
    }

    #[tokio::test]
    async fn gzip_responses_decode_to_the_identity_body() {
        let asset = compressible_asset();

        let plain = asset.respond(&HeaderMap::new(), CachePolicy::Revalidate);
        assert!(!plain.headers().contains_key(header::CONTENT_ENCODING));
        assert_eq!(plain.headers()[header::VARY], "accept-encoding");
        let plain_etag = plain.headers()[header::ETAG].clone();
        let plain_body = to_bytes(plain.into_body(), usize::MAX).await.unwrap();

        let compressed = asset.respond(
            &request_with(header::ACCEPT_ENCODING, "gzip"),
            CachePolicy::Revalidate,
        );
        assert_eq!(compressed.headers()[header::CONTENT_ENCODING], "gzip");
        assert_eq!(compressed.headers()[header::VARY], "accept-encoding");
        assert_eq!(
            compressed.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        // A different representation carries a different strong validator.
        assert_ne!(compressed.headers()[header::ETAG], plain_etag);
        let compressed_body = to_bytes(compressed.into_body(), usize::MAX).await.unwrap();
        assert!(compressed_body.len() < plain_body.len());

        let mut decoded = Vec::new();
        GzDecoder::new(&compressed_body[..])
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, plain_body);
    }

    #[tokio::test]
    async fn matching_validators_answer_not_modified_without_a_body() {
        let asset = compressible_asset();
        let etag = asset.identity.etag.clone();
        let mut request = HeaderMap::new();
        request.insert(header::IF_NONE_MATCH, etag.clone());

        let response = asset.respond(&request, CachePolicy::Immutable);
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
        // A 304 refreshes what the cache holds, so it repeats the validator,
        // the cache policy, and Vary — and describes no body of its own.
        assert_eq!(response.headers()[header::ETAG], etag);
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert_eq!(response.headers()[header::VARY], "accept-encoding");
        assert!(!response.headers().contains_key(header::CONTENT_TYPE));
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
        assert!(to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .is_empty());

        // The identity validator does not confirm the gzip representation.
        request.insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        let response = asset.respond(&request, CachePolicy::Immutable);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_ENCODING], "gzip");
    }

    #[test]
    fn content_language_is_declared_only_where_set_and_only_with_a_body() {
        // Files with no natural language (styles, scripts, images) declare none.
        let untagged = compressible_asset().respond(&HeaderMap::new(), CachePolicy::Revalidate);
        assert!(!untagged.headers().contains_key(header::CONTENT_LANGUAGE));

        let page = compressible_asset().with_content_language("it");
        for accept_encoding in ["identity", "gzip"] {
            let response = page.respond(
                &request_with(header::ACCEPT_ENCODING, accept_encoding),
                CachePolicy::Revalidate,
            );
            assert_eq!(response.headers()[header::CONTENT_LANGUAGE], "it");
        }

        let mut revalidation = HeaderMap::new();
        revalidation.insert(header::IF_NONE_MATCH, page.identity.etag.clone());
        let not_modified = page.respond(&revalidation, CachePolicy::Revalidate);
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
        assert!(!not_modified
            .headers()
            .contains_key(header::CONTENT_LANGUAGE));
    }

    #[test]
    fn bodies_gzip_cannot_shrink_are_offered_uncompressed_only() {
        let tiny = Asset::new("text/plain; charset=utf-8", "ok");
        assert!(tiny.gzip.is_none());

        let response = tiny.respond(
            &request_with(header::ACCEPT_ENCODING, "gzip"),
            CachePolicy::Revalidate,
        );
        assert!(!response.headers().contains_key(header::CONTENT_ENCODING));
        // With one representation there is nothing to vary on.
        assert!(!response.headers().contains_key(header::VARY));
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-cache");
    }

    #[test]
    fn fingerprints_follow_the_content() {
        let first = Asset::new("text/plain", "first");
        let again = Asset::new("text/plain", "first");
        let second = Asset::new("text/plain", "second");
        assert_eq!(first.fingerprint(), again.fingerprint());
        assert_ne!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.fingerprint().len(), 16);
        assert!(first.fingerprint().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn embedded_files_have_distinct_content_addressed_paths() {
        let files = embedded();
        for (file, stem, extension) in [
            (&files.styles, "styles", "css"),
            (&files.script, "script", "js"),
            (&files.favicon, "favicon", "svg"),
            (&files.wasm, "demo", "wasm"),
        ] {
            assert_eq!(
                file.fingerprinted_path,
                format!("/assets/{stem}.{}.{extension}", file.asset.fingerprint())
            );
            assert_eq!(file.path, format!("/{stem}.{extension}"));
        }
    }
}
