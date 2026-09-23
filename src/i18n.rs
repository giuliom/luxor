//! Internationalisation for the embedded browser console.
//!
//! Language-prefixed URLs (`/en`, `/it`) are the source of truth: each locale
//! has its own stable, indexable page, statically generated at startup from
//! one HTML template plus a per-locale dictionary in `locales/<lang>/common.json`.
//! The bare `/` never serves content; it negotiates a locale (explicit cookie
//! preference first, then `Accept-Language`, then the default) and redirects,
//! so a URL that names a language is never overridden by browser settings.
//!
//! Dictionary values are whole sentences with named `{placeholder}` slots —
//! never fragments to concatenate — and are HTML-escaped when substituted, so
//! a translation can never inject markup. The same dictionary is inlined into
//! the page as a non-executing JSON data block for the client-side strings,
//! which keeps one request per page and one source of truth per language.
//!
//! Rendering covers more than text: facts about the deployment that are fixed
//! for the life of the process — the permission matrix, the runtime badge,
//! the content-addressed asset URLs — arrive in [`PageContext`] and are
//! rendered into the page too, so its first response is complete without a
//! script fetching the rest.

use crate::{models::Role, permissions::Permission};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// Name of the cookie that stores an explicitly selected language. It is set
/// by the language selector in the browser and read only by the `/` redirect;
/// it never overrides a language named in the URL.
pub const PREFERENCE_COOKIE: &str = "lang";

/// The default site language, served when nothing better is known and used as
/// the `x-default` hreflang target.
pub const DEFAULT_LOCALE: Locale = Locale::En;

/// Every language the console is available in. Adding a language means adding
/// a `Locale` variant (the compiler then asks for its tag, path, endonym, and
/// dictionary), listing it here, and writing `locales/<lang>/common.json`.
/// Routes, hreflang alternates, the selector, and the sitemap all follow from
/// this list, and the dictionary-parity tests enforce completeness.
pub const SUPPORTED_LOCALES: [Locale; 2] = [Locale::En, Locale::It];

/// A language the console is translated into, identified by its BCP 47 tag.
/// Language is deliberately the only axis: currency, time zone, and number
/// formatting are handled by the browser's `Intl` APIs against this tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Locale {
    En,
    It,
}

impl Locale {
    /// The BCP 47 language tag, also used as the URL prefix.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::It => "it",
        }
    }

    /// The canonical path of this locale's console page.
    pub fn path(self) -> &'static str {
        match self {
            Self::En => "/en",
            Self::It => "/it",
        }
    }

    /// Both languages are left-to-right; a future RTL locale changes only
    /// this method and the template's `dir` attribute follows.
    fn text_direction(self) -> &'static str {
        "ltr"
    }

    /// The language's name in that language, as the selector shows it on
    /// every page: a reader looks for their language by the name they know it
    /// by, so this is deliberately not translated.
    fn endonym(self) -> &'static str {
        match self {
            Self::En => "English",
            Self::It => "Italiano",
        }
    }

    /// Matches a BCP 47 tag by primary subtag, so `it-IT` and `it-CH` both
    /// resolve to Italian: regional variants share one translation until the
    /// content genuinely differs.
    pub fn from_tag(tag: &str) -> Option<Self> {
        let primary = tag.split(['-', '_']).next().unwrap_or_default();
        SUPPORTED_LOCALES
            .into_iter()
            .find(|locale| locale.as_str().eq_ignore_ascii_case(primary))
    }

    fn dictionary_source(self) -> &'static str {
        match self {
            Self::En => include_str!("../locales/en/common.json"),
            Self::It => include_str!("../locales/it/common.json"),
        }
    }

    /// The parsed dictionary. The files are embedded and validated by tests,
    /// so a parse failure is a build defect and fails startup loudly.
    pub fn dictionary(self) -> &'static BTreeMap<String, String> {
        static DICTIONARIES: [OnceLock<BTreeMap<String, String>>; SUPPORTED_LOCALES.len()] =
            [const { OnceLock::new() }; SUPPORTED_LOCALES.len()];
        DICTIONARIES[self as usize].get_or_init(|| {
            serde_json::from_str(self.dictionary_source()).unwrap_or_else(|error| {
                panic!("locales/{}/common.json is malformed: {error}", self)
            })
        })
    }
}

impl std::fmt::Display for Locale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Resolves the locale for a request that names no language in its URL.
///
/// Priority: the explicit `lang` cookie the selector sets, then the browser's
/// `Accept-Language`, then the site default. There is no server-side account
/// preference to consult: the access token lives only in page memory and the
/// refresh cookie is scoped to `/api/auth`, so the server cannot know who is
/// signed in when it serves a page — the preference cookie is the persisted
/// user choice.
pub fn negotiate(cookie_header: Option<&str>, accept_language: Option<&str>) -> Locale {
    cookie_header
        .and_then(cookie_locale)
        .or_else(|| accept_language.and_then(accept_language_locale))
        .unwrap_or(DEFAULT_LOCALE)
}

fn cookie_locale(cookie_header: &str) -> Option<Locale> {
    cookie_header.split(';').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name.trim() == PREFERENCE_COOKIE)
            .then(|| Locale::from_tag(value.trim()))
            .flatten()
    })
}

/// Picks the supported language the client weighted highest. Unsupported tags
/// and `q=0` entries are skipped; ties keep the client's ordering. The weight's
/// name is case-insensitive (`Q=0` is as valid as `q=0`, RFC 9110 §12.4.2),
/// and an unreadable weight disqualifies its entry rather than being read as
/// full preference.
fn accept_language_locale(header: &str) -> Option<Locale> {
    let mut best: Option<(Locale, f32)> = None;
    for entry in header.split(',') {
        let mut parts = entry.split(';');
        let Some(locale) = Locale::from_tag(parts.next().unwrap_or_default().trim()) else {
            continue;
        };
        let weight = parts.find_map(|param| {
            let (name, value) = param.split_once('=')?;
            name.trim().eq_ignore_ascii_case("q").then(|| value.trim())
        });
        let quality = match weight.map(str::parse::<f32>) {
            None => 1.0,
            Some(Ok(quality)) => quality,
            Some(Err(_)) => continue,
        };
        if quality > 0.0 && best.is_none_or(|(_, held)| quality > held) {
            best = Some((locale, quality));
        }
    }
    best.map(|(locale, _)| locale)
}

const INDEX_TEMPLATE: &str = include_str!("../public/index.html");

/// Everything a rendered page shows beyond its language. Each value is fixed
/// for the life of the process, which is what makes rendering the page once at
/// startup — instead of per request, or in the browser after load — correct.
pub struct PageContext<'a> {
    /// Absolute public origin for the canonical, hreflang, and Open Graph URLs.
    pub base_url: &'a str,
    /// Whether this instance runs on the embedded development PostgreSQL
    /// server, which the service card's runtime badge reports.
    pub embedded_database: bool,
    /// The grants the permissions card renders. They are fixed at compile
    /// time (see `permissions.rs`); were they ever loaded from storage, the
    /// matrix would have to be rendered per request instead.
    pub grants: BTreeMap<Role, BTreeSet<Permission>>,
    /// Content-addressed URLs of the static files the page loads.
    pub styles_url: &'a str,
    pub script_url: &'a str,
    pub favicon_url: &'a str,
    pub wasm_url: &'a str,
}

/// Renders the console page for one locale. Called once per locale at startup
/// — static generation, so every response is already in the right language —
/// and panics on an unknown or unclosed placeholder, which the tests catch
/// long before a deployment does.
pub fn render_page(locale: Locale, context: &PageContext<'_>) -> String {
    let mut page = String::with_capacity(INDEX_TEMPLATE.len() * 2);
    let mut rest = INDEX_TEMPLATE;
    while let Some(start) = rest.find("{{") {
        page.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find("}}")
            .expect("unclosed {{ placeholder in public/index.html");
        page.push_str(&resolve_placeholder(&after[..end], locale, context));
        rest = &after[end + 2..];
    }
    page.push_str(rest);
    page
}

fn resolve_placeholder(key: &str, locale: Locale, context: &PageContext<'_>) -> String {
    // Template variables computed by code, not translated. Everything else is
    // a dictionary key, and its value is escaped: translations are treated as
    // untrusted input exactly like any other content.
    match key {
        "lang" => locale.as_str().to_owned(),
        "dir" => locale.text_direction().to_owned(),
        "canonical" => escape_html(&format!("{}{}", context.base_url, locale.path())),
        "alternate_links" => alternate_links(context.base_url),
        "language_links" => language_links(locale),
        "styles_url" => escape_html(context.styles_url),
        "script_url" => escape_html(context.script_url),
        "favicon_url" => escape_html(context.favicon_url),
        "wasm_url" => escape_html(context.wasm_url),
        "runtime_badge" => escape_html(message(
            locale,
            if context.embedded_database {
                "runtime.embedded"
            } else {
                "runtime.fullStack"
            },
        )),
        "permissions_matrix" => permissions_matrix(locale, &context.grants),
        "i18n_json" => inline_dictionary(locale),
        _ => escape_html(message(locale, key)),
    }
}

/// A dictionary entry the renderer needs. The template and the renderer's own
/// lookups are exercised by the rendering tests, so a miss is a defect caught
/// long before a deployment.
fn message(locale: Locale, key: &str) -> &'static str {
    locale
        .dictionary()
        .get(key)
        .map(String::as_str)
        .unwrap_or_else(|| {
            panic!("the page renderer looks up `{key}`, which locales/{locale}/common.json does not define")
        })
}

/// Substitutes `{name}` placeholders exactly as the script's `formatMessage`
/// does: a name without a value is left in place, visibly.
fn format_message(message: &str, values: &[(&str, &str)]) -> String {
    let mut formatted = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(start) = rest.find('{') {
        formatted.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let substitution = after.find('}').and_then(|end| {
            values
                .iter()
                .find(|(name, _)| *name == &after[..end])
                .map(|(_, value)| (end, *value))
        });
        match substitution {
            Some((end, value)) => {
                formatted.push_str(value);
                rest = &after[end + 1..];
            }
            None => {
                formatted.push('{');
                rest = after;
            }
        }
    }
    formatted.push_str(rest);
    formatted
}

/// The permissions card's matrix — one column per role, one row per
/// permission — in the markup the stylesheet and script expect: `data-role`
/// marks the cells the script highlights for the signed-in role. Rendering it
/// here puts the whole table in the first response, for crawlers and slow
/// connections alike, and costs no request after load.
fn permissions_matrix(locale: Locale, grants: &BTreeMap<Role, BTreeSet<Permission>>) -> String {
    let mut html = String::from(r#"<thead><tr><th scope="col">"#);
    html.push_str(&escape_html(message(
        locale,
        "permissions.columnPermission",
    )));
    html.push_str("</th>");
    for role in grants.keys() {
        html.push_str(&format!(
            r#"<th scope="col" class="grant" data-role="{}">{}</th>"#,
            escape_html(role.name()),
            escape_html(message(locale, role_label_key(*role)))
        ));
    }
    html.push_str("</tr></thead><tbody>");

    for permission in Permission::ALL {
        let description = message(locale, permission_description_key(permission));
        html.push_str(&format!(
            r#"<tr><th scope="row"><code>{}</code><span class="permission-hint">{}</span></th>"#,
            escape_html(permission.name()),
            escape_html(description)
        ));
        for (role, granted) in grants {
            let (class, mark, key) = if granted.contains(&permission) {
                ("grant-mark", "✓", "permissions.may")
            } else {
                ("grant-mark denied", "—", "permissions.mayNot")
            };
            let label = format_message(
                message(locale, key),
                &[
                    ("role", message(locale, role_label_key(*role))),
                    ("description", description),
                ],
            );
            html.push_str(&format!(
                r#"<td class="grant" data-role="{}"><span class="{class}" role="img" aria-label="{}">{mark}</span></td>"#,
                escape_html(role.name()),
                escape_html(&label)
            ));
        }
        html.push_str("</tr>");
    }
    html.push_str("</tbody>");
    html
}

/// The page describes each permission in its own language; the API catalog's
/// descriptions are English. The match is exhaustive, so a new permission does
/// not compile until it has a key, and the parity tests then require every
/// language to translate it.
fn permission_description_key(permission: Permission) -> &'static str {
    match permission {
        Permission::ReportsView => "permissions.description.reportsView",
        Permission::RecordsPurge => "permissions.description.recordsPurge",
    }
}

/// Display names for the roles. Their wire names (`admin`, `user`) remain in
/// the API and in the matrix's `data-role` attributes, which the script keys
/// on; people read the translated name. The match is exhaustive, so a new role
/// does not compile until it has a key.
fn role_label_key(role: Role) -> &'static str {
    match role {
        Role::Admin => "roles.admin",
        Role::User => "roles.user",
    }
}

/// Reciprocal hreflang alternates: every language version, this page's own
/// included, plus `x-default` for readers whose language is not offered.
/// Generated from [`SUPPORTED_LOCALES`] so a new language needs no template
/// change.
fn alternate_links(base_url: &str) -> String {
    let base_url = escape_html(base_url);
    SUPPORTED_LOCALES
        .into_iter()
        .map(|locale| (locale.as_str(), locale.path()))
        .chain([("x-default", DEFAULT_LOCALE.path())])
        .map(|(hreflang, path)| {
            format!(r#"<link rel="alternate" hreflang="{hreflang}" href="{base_url}{path}">"#)
        })
        .collect::<Vec<_>>()
        .join("\n    ")
}

/// The language selector: ordinary links a crawler can follow, each naming
/// its language in that language and marked with it, so assistive technology
/// pronounces the name correctly, with the current page marked.
fn language_links(page: Locale) -> String {
    SUPPORTED_LOCALES
        .into_iter()
        .map(|locale| {
            let current = if locale == page {
                r#" aria-current="page""#
            } else {
                ""
            };
            format!(
                r#"<a href="{path}" hreflang="{tag}" lang="{tag}"{current} data-lang-choice="{tag}">{name}</a>"#,
                path = locale.path(),
                tag = locale.as_str(),
                name = locale.endonym(),
            )
        })
        .collect::<Vec<_>>()
        .join("\n            <span aria-hidden=\"true\">·</span>\n            ")
}

/// The dictionary as a JSON data block payload. `</` is escaped so no value
/// can ever terminate the surrounding `<script>` element early; the block has
/// a non-executable type, so the CSP that forbids inline scripts is untouched.
fn inline_dictionary(locale: Locale) -> String {
    serde_json::to_string(locale.dictionary())
        .expect("a string map always serializes")
        .replace("</", "<\\/")
}

/// The XML sitemap: every language version of the page, each carrying the
/// full set of reciprocal hreflang alternates plus `x-default`.
pub fn render_sitemap(base_url: &str) -> String {
    let alternates: String = SUPPORTED_LOCALES
        .into_iter()
        .map(|locale| {
            format!(
                r#"    <xhtml:link rel="alternate" hreflang="{}" href="{}{}"/>{}"#,
                locale,
                escape_html(base_url),
                locale.path(),
                '\n'
            )
        })
        .chain(std::iter::once(format!(
            r#"    <xhtml:link rel="alternate" hreflang="x-default" href="{}{}"/>{}"#,
            escape_html(base_url),
            DEFAULT_LOCALE.path(),
            '\n'
        )))
        .collect();

    let mut sitemap = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\" xmlns:xhtml=\"http://www.w3.org/1999/xhtml\">\n",
    );
    for locale in SUPPORTED_LOCALES {
        sitemap.push_str("  <url>\n");
        sitemap.push_str(&format!(
            "    <loc>{}{}</loc>\n",
            escape_html(base_url),
            locale.path()
        ));
        sitemap.push_str(&alternates);
        sitemap.push_str("  </url>\n");
    }
    sitemap.push_str("</urlset>\n");
    sitemap
}

fn escape_html(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::PermissionStore;

    const SCRIPT_SOURCE: &str = include_str!("../public/script.js");
    const BASE_URL: &str = "https://console.example.com";

    /// This module without its tests: the renderer's own dictionary lookups
    /// (the matrix, the runtime badge) live here rather than in the template.
    fn renderer_source() -> &'static str {
        const SOURCE: &str = include_str!("i18n.rs");
        SOURCE
            .split_once("#[cfg(test)]")
            .map_or(SOURCE, |(code, _)| code)
    }

    fn context(embedded_database: bool) -> PageContext<'static> {
        PageContext {
            base_url: BASE_URL,
            embedded_database,
            grants: PermissionStore.grants(),
            styles_url: "/assets/styles.0123456789abcdef.css",
            script_url: "/assets/script.0123456789abcdef.js",
            favicon_url: "/assets/favicon.0123456789abcdef.svg",
            wasm_url: "/assets/demo.0123456789abcdef.wasm",
        }
    }

    /// `{name}` placeholder names inside one translated message.
    fn placeholder_names(message: &str) -> BTreeSet<&str> {
        let mut names = BTreeSet::new();
        let mut rest = message;
        while let Some(start) = rest.find('{') {
            let after = &rest[start + 1..];
            let Some(end) = after.find('}') else { break };
            let name = &after[..end];
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                names.insert(name);
            }
            rest = &after[end + 1..];
        }
        names
    }

    /// String literals passed to the client's `t("…")` / `tp("…")` helpers.
    fn script_translation_keys(call_prefix: &str) -> BTreeSet<String> {
        let mut keys = BTreeSet::new();
        let mut offset = 0;
        while let Some(position) = SCRIPT_SOURCE[offset..].find(call_prefix) {
            let start = offset + position;
            let preceded_by_word = SCRIPT_SOURCE[..start]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
            let literal = &SCRIPT_SOURCE[start + call_prefix.len()..];
            if !preceded_by_word {
                if let Some(end) = literal.find('"') {
                    keys.insert(literal[..end].to_owned());
                }
            }
            offset = start + call_prefix.len();
        }
        keys
    }

    #[test]
    fn dictionaries_parse_and_share_an_identical_key_set() {
        let english: BTreeSet<_> = Locale::En.dictionary().keys().collect();
        let italian: BTreeSet<_> = Locale::It.dictionary().keys().collect();

        let missing: Vec<_> = english.difference(&italian).collect();
        let obsolete: Vec<_> = italian.difference(&english).collect();
        assert!(
            missing.is_empty() && obsolete.is_empty(),
            "locale dictionaries diverge — missing from it: {missing:?}, obsolete in it: {obsolete:?}"
        );
    }

    #[test]
    fn translations_keep_the_source_placeholders() {
        for (key, english_message) in Locale::En.dictionary() {
            let italian_message = &Locale::It.dictionary()[key];
            assert_eq!(
                placeholder_names(english_message),
                placeholder_names(italian_message),
                "`{key}` translates with different placeholders"
            );
        }
    }

    #[test]
    fn translations_carry_no_markup() {
        for locale in SUPPORTED_LOCALES {
            for (key, message) in locale.dictionary() {
                assert!(
                    !message.contains('<') && !message.contains('>'),
                    "`{key}` in {locale} contains markup; translations are text, not HTML"
                );
            }
        }
    }

    #[test]
    fn every_dictionary_key_is_referenced() {
        // A key is referenced directly (template placeholder, or quoted string
        // in the script or the renderer) or through its parent, which covers
        // plural variants (`telemetry.spans.one`) and dynamic families
        // (`errors.code.<code>`).
        let sources = format!("{INDEX_TEMPLATE}{SCRIPT_SOURCE}{}", renderer_source());
        for locale in SUPPORTED_LOCALES {
            for key in locale.dictionary().keys() {
                let parent_referenced = key
                    .rsplit_once('.')
                    .is_some_and(|(parent, _)| parent.contains('.') && sources.contains(parent));
                assert!(
                    sources.contains(key.as_str()) || parent_referenced,
                    "`{key}` is defined but never used by the template or script"
                );
            }
        }
    }

    #[test]
    fn every_script_lookup_has_a_translation() {
        let dictionary = Locale::En.dictionary();
        for key in script_translation_keys("t(\"") {
            assert!(
                dictionary.contains_key(&key),
                "script.js calls t(\"{key}\") but the dictionary does not define it"
            );
        }
        // Pluralized lookups resolve `<key>.<CLDR category>`, and `other` is
        // the category every language has.
        for key in script_translation_keys("tp(\"") {
            assert!(
                dictionary.contains_key(&format!("{key}.other")),
                "script.js calls tp(\"{key}\") but the dictionary does not define `{key}.other`"
            );
        }
    }

    #[test]
    fn pages_render_with_no_unresolved_placeholders() {
        for locale in SUPPORTED_LOCALES {
            // Both runtime variants, so every lookup the renderer can make is
            // exercised against every dictionary.
            for embedded_database in [true, false] {
                let page = render_page(locale, &context(embedded_database));
                assert!(
                    !page.contains("{{"),
                    "the rendered {locale} page still contains a placeholder"
                );
                assert!(page.contains(&format!(r#"<html lang="{locale}" dir="ltr">"#)));
            }
        }
    }

    #[test]
    fn rendered_pages_carry_reciprocal_seo_metadata() {
        for locale in SUPPORTED_LOCALES {
            let page = render_page(locale, &context(true));
            assert!(page.contains(&format!(
                r#"<link rel="canonical" href="{BASE_URL}{}">"#,
                locale.path()
            )));
            // Link previews name the same URL, title, and description.
            assert!(page.contains(&format!(
                r#"<meta property="og:url" content="{BASE_URL}{}">"#,
                locale.path()
            )));
            let title = escape_html(message(locale, "meta.title"));
            let description = escape_html(message(locale, "meta.description"));
            assert!(page.contains(&format!(r#"<title>{title}</title>"#)));
            assert!(page.contains(&format!(r#"<meta property="og:title" content="{title}">"#)));
            assert!(page.contains(&format!(
                r#"<meta name="description" content="{description}">"#
            )));
            assert!(page.contains(&format!(
                r#"<meta property="og:description" content="{description}">"#
            )));
            // Every page links every language version, itself included.
            for alternate in SUPPORTED_LOCALES {
                assert!(page.contains(&format!(
                    r#"<link rel="alternate" hreflang="{alternate}" href="{BASE_URL}{}">"#,
                    alternate.path()
                )));
            }
            assert!(page.contains(&format!(
                r#"<link rel="alternate" hreflang="x-default" href="{BASE_URL}/en">"#
            )));
        }
    }

    #[test]
    fn pages_are_rendered_in_their_own_language() {
        let english = render_page(Locale::En, &context(true));
        assert!(english.contains("<title>Luxor backend console</title>"));

        let italian = render_page(Locale::It, &context(true));
        assert!(italian.contains("<title>Console backend Luxor</title>"));
        assert!(italian.contains("Autenticazione"));
        // The inlined dictionary matches the page language, so the client
        // never loads a second language's resources.
        assert!(italian.contains(r#""labels.session":"Sessione""#));
        assert!(!italian.contains(r#""labels.session":"Session""#));
    }

    #[test]
    fn the_permission_matrix_is_rendered_in_the_page_language() {
        let italian = render_page(Locale::It, &context(true));
        // One column per role, marked for the script's role highlighting.
        assert!(italian.contains(concat!(
            r#"<table id="permissions-matrix" class="permissions-matrix" aria-label="Matrice dei permessi per ruolo">"#,
            r#"<thead><tr><th scope="col">Permesso</th>"#,
            r#"<th scope="col" class="grant" data-role="admin">Amministratore</th>"#,
            r#"<th scope="col" class="grant" data-role="user">Utente</th></tr></thead>"#,
        )));
        // Descriptions are translated, unlike the API catalog's English ones.
        assert!(italian.contains(concat!(
            r#"<th scope="row"><code>records.purge</code>"#,
            r#"<span class="permission-hint">Eseguire l’eliminazione simulata dei record</span></th>"#,
        )));
        assert!(!italian.contains(Permission::RecordsPurge.description()));
        // Each cell states its grant to assistive technology, not only visually.
        assert!(italian.contains(concat!(
            r#"<td class="grant" data-role="admin"><span class="grant-mark" role="img" aria-label="Amministratore può: Eseguire l’eliminazione simulata dei record">✓</span></td>"#,
            r#"<td class="grant" data-role="user"><span class="grant-mark denied" role="img" aria-label="Utente non può: Eseguire l’eliminazione simulata dei record">—</span></td>"#,
        )));

        let english = render_page(Locale::En, &context(true));
        assert!(english
            .contains(r#"<span class="permission-hint">Read the operational demo report</span>"#));
    }

    /// The rendered grants are the enforced ones, cell for cell.
    #[test]
    fn the_permission_matrix_matches_the_enforced_grants() {
        let matrix = permissions_matrix(Locale::En, &PermissionStore.grants());
        for role in Role::ALL {
            for permission in Permission::ALL {
                let (class, verb) = if PermissionStore.allows(role, permission) {
                    ("grant-mark", "may")
                } else {
                    ("grant-mark denied", "may not")
                };
                let description = message(Locale::En, permission_description_key(permission));
                assert!(
                    matrix.contains(&format!(
                        r#"<span class="{class}" role="img" aria-label="{} {verb}: {}">"#,
                        message(Locale::En, role_label_key(role)),
                        escape_html(description)
                    )),
                    "{role:?} / {permission:?}"
                );
            }
        }
    }

    /// The script looks role names up as `roles.<wire name>`, so the keys the
    /// renderer uses must follow that shape for every role.
    #[test]
    fn role_label_keys_follow_the_wire_names_the_script_uses() {
        assert!(SCRIPT_SOURCE.contains("i18n[`roles.${role}`]"));
        for role in Role::ALL {
            assert_eq!(role_label_key(role), format!("roles.{}", role.name()));
        }
    }

    #[test]
    fn the_language_selector_and_alternates_cover_every_locale() {
        for page_locale in SUPPORTED_LOCALES {
            let page = render_page(page_locale, &context(true));
            for locale in SUPPORTED_LOCALES {
                let current = if locale == page_locale {
                    r#" aria-current="page""#
                } else {
                    ""
                };
                assert!(
                    page.contains(&format!(
                        r#"<a href="{}" hreflang="{locale}" lang="{locale}"{current} data-lang-choice="{locale}">{}</a>"#,
                        locale.path(),
                        locale.endonym()
                    )),
                    "the {page_locale} page's selector is missing {locale}"
                );
            }
            assert_eq!(page.matches(r#"aria-current="page""#).count(), 1);
            // One alternate per language plus x-default, and nothing else.
            assert_eq!(
                page.matches(r#"<link rel="alternate""#).count(),
                SUPPORTED_LOCALES.len() + 1
            );
        }
    }

    #[test]
    fn the_runtime_badge_names_the_database_backend() {
        let embedded = render_page(Locale::En, &context(true));
        assert!(embedded
            .contains(r#"<span id="runtime-badge" class="badge ok">Embedded database</span>"#));

        let external = render_page(Locale::It, &context(false));
        assert!(
            external.contains(r#"<span id="runtime-badge" class="badge ok">Stack completo</span>"#)
        );
    }

    #[test]
    fn pages_reference_their_content_addressed_assets() {
        let page = render_page(Locale::En, &context(true));
        assert!(page.contains(
            r#"<link rel="icon" href="/assets/favicon.0123456789abcdef.svg" type="image/svg+xml">"#
        ));
        assert!(
            page.contains(r#"<link rel="stylesheet" href="/assets/styles.0123456789abcdef.css">"#)
        );
        assert!(page.contains(r#"<script src="/assets/script.0123456789abcdef.js"></script>"#));
        assert!(page.contains(r#"data-module="/assets/demo.0123456789abcdef.wasm""#));
    }

    #[test]
    fn messages_substitute_named_values_only() {
        assert_eq!(
            format_message(
                "{role} may: {description}",
                &[("role", "admin"), ("description", "read")]
            ),
            "admin may: read"
        );
        // Unknown names stay visible, substituted values are not re-scanned,
        // and stray braces survive — as in the script's formatMessage.
        assert_eq!(
            format_message("{a} {missing} {", &[("a", "{a}")]),
            "{a} {missing} {"
        );
        assert_eq!(format_message("{{a}}", &[("a", "x")]), "{x}");
    }

    #[test]
    fn inline_dictionary_cannot_terminate_its_script_element() {
        for locale in SUPPORTED_LOCALES {
            assert!(!inline_dictionary(locale).contains("</"));
        }
    }

    #[test]
    fn sitemap_lists_every_language_with_alternates() {
        let sitemap = render_sitemap(BASE_URL);
        for locale in SUPPORTED_LOCALES {
            assert!(sitemap.contains(&format!("<loc>{BASE_URL}{}</loc>", locale.path())));
            assert!(sitemap.contains(&format!(
                r#"hreflang="{locale}" href="{BASE_URL}{}""#,
                locale.path()
            )));
        }
        assert!(sitemap.contains(r#"hreflang="x-default""#));
    }

    #[test]
    fn locale_tags_match_by_primary_subtag() {
        assert_eq!(Locale::from_tag("it"), Some(Locale::It));
        assert_eq!(Locale::from_tag("it-IT"), Some(Locale::It));
        assert_eq!(Locale::from_tag("IT_ch"), Some(Locale::It));
        assert_eq!(Locale::from_tag("en-GB"), Some(Locale::En));
        assert_eq!(Locale::from_tag("de"), None);
        assert_eq!(Locale::from_tag(""), None);
    }

    #[test]
    fn negotiation_prefers_the_explicit_cookie() {
        let locale = negotiate(Some("theme=sand; lang=it"), Some("en-US,en;q=0.9"));
        assert_eq!(locale, Locale::It);

        // A cookie naming an unsupported language falls through to the header.
        let locale = negotiate(Some("lang=de"), Some("it;q=0.8"));
        assert_eq!(locale, Locale::It);
    }

    #[test]
    fn negotiation_weighs_accept_language_quality() {
        assert_eq!(negotiate(None, Some("it-IT,it;q=0.9,en;q=0.8")), Locale::It);
        assert_eq!(negotiate(None, Some("de-DE,en;q=0.5,it;q=0.9")), Locale::It);
        // q=0 means "not acceptable", not "slightly acceptable".
        assert_eq!(negotiate(None, Some("it;q=0,en;q=0.1")), Locale::En);
        assert_eq!(negotiate(None, Some("de,fr;q=0.9")), Locale::En);
        assert_eq!(negotiate(None, Some("nonsense;;q=zz,,")), Locale::En);
        assert_eq!(negotiate(None, None), Locale::En);
        // The weight's name is case-insensitive, and spaces may surround `;`.
        assert_eq!(negotiate(None, Some("it;Q=0,en;q=0.1")), Locale::En);
        assert_eq!(negotiate(None, Some("en;q=0.5, it ; q=0.9")), Locale::It);
        // An unreadable weight disqualifies its entry instead of counting as
        // full preference.
        assert_eq!(negotiate(None, Some("it;q=high,en;q=0.1")), Locale::En);
    }

    #[test]
    fn html_escaping_covers_markup_and_attribute_characters() {
        assert_eq!(
            escape_html(r#"<a href="x">&'"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }
}
