//! Internationalisation for server-rendered pages.
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
//! [`render_page`] resolves the template's language plumbing — `lang`, `dir`,
//! the canonical URL, hreflang alternates, the language selector, the inlined
//! dictionary — and every dictionary key; whatever else a page shows arrives
//! through the caller's variables, so the renderer knows nothing about any
//! particular page.

use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// Name of the cookie that stores an explicitly selected language. It is set
/// by the language selector in the browser and read only by the `/` redirect;
/// it never overrides a language named in the URL.
pub const PREFERENCE_COOKIE: &str = "lang";

/// The default site language, served when nothing better is known and used as
/// the `x-default` hreflang target.
pub const DEFAULT_LOCALE: Locale = Locale::En;

/// Every language the site is available in. Adding a language means adding
/// a `Locale` variant (the compiler then asks for its tag, path, endonym, and
/// dictionary), listing it here, and writing `locales/<lang>/common.json`.
/// Routes, hreflang alternates, the selector, and the sitemap all follow from
/// this list, and the dictionary-parity tests enforce completeness.
pub const SUPPORTED_LOCALES: [Locale; 2] = [Locale::En, Locale::It];

/// A language the site is translated into, identified by its BCP 47 tag.
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

    /// The canonical path of this locale's page.
    pub fn path(self) -> &'static str {
        match self {
            Self::En => "/en",
            Self::It => "/it",
        }
    }

    /// Both languages are left-to-right; a future RTL locale changes only
    /// this method and the template's `dir` attribute follows.
    pub fn text_direction(self) -> &'static str {
        "ltr"
    }

    /// The language's name in that language, as the selector shows it on
    /// every page: a reader looks for their language by the name they know it
    /// by, so this is deliberately not translated.
    pub fn endonym(self) -> &'static str {
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

/// Sends `/` to the negotiated language version: the explicit cookie
/// preference first, then `Accept-Language`, then the default. The redirect
/// varies on what it read and is never cached, so a shared cache can never
/// pin every visitor to one visitor's language; the language-prefixed URLs
/// it points at are what caches and crawlers index.
pub async fn localized_root(headers: HeaderMap) -> Response {
    let locale = negotiate(
        headers
            .get(header::COOKIE)
            .and_then(|value| value.to_str().ok()),
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|value| value.to_str().ok()),
    );
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, HeaderValue::from_static(locale.path())),
            (
                header::VARY,
                HeaderValue::from_static("Cookie, Accept-Language"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
    )
        .into_response()
}

/// Renders `template` for one locale. Meant to be called once per locale at
/// startup — static generation, so every response is already in the right
/// language.
///
/// A `{{name}}` placeholder resolves to, in order: one of the built-in
/// variables (`lang`, `dir`, `canonical`, `alternate_links`, `language_links`,
/// `i18n_json`), then whatever `variables` returns for it — already-safe
/// markup, inserted as is — and otherwise the HTML-escaped dictionary entry of
/// that name. An unclosed placeholder or a name the dictionary does not define
/// panics, which rendering tests catch long before a deployment does.
pub fn render_page(
    template: &str,
    locale: Locale,
    base_url: &str,
    variables: impl Fn(&str) -> Option<String>,
) -> String {
    let mut page = String::with_capacity(template.len() * 2);
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        page.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find("}}")
            .expect("unclosed {{ placeholder in a page template");
        let key = &after[..end];
        let value = builtin_variable(key, locale, base_url)
            .or_else(|| variables(key))
            .unwrap_or_else(|| escape_html(message(locale, key)));
        page.push_str(&value);
        rest = &after[end + 2..];
    }
    page.push_str(rest);
    page
}

fn builtin_variable(key: &str, locale: Locale, base_url: &str) -> Option<String> {
    Some(match key {
        "lang" => locale.as_str().to_owned(),
        "dir" => locale.text_direction().to_owned(),
        "canonical" => escape_html(&format!("{base_url}{}", locale.path())),
        "alternate_links" => alternate_links(base_url),
        "language_links" => language_links(locale),
        "i18n_json" => inline_dictionary(locale),
        _ => return None,
    })
}

/// A dictionary entry a renderer needs. Templates and renderers are exercised
/// by their rendering tests, so a miss is a defect caught long before a
/// deployment.
pub fn message(locale: Locale, key: &str) -> &'static str {
    locale
        .dictionary()
        .get(key)
        .map(String::as_str)
        .unwrap_or_else(|| {
            panic!("the page renderer looks up `{key}`, which locales/{locale}/common.json does not define")
        })
}

/// Substitutes `{name}` placeholders exactly as the console script's
/// `formatMessage` does: a name without a value is left in place, visibly.
pub fn format_message(message: &str, values: &[(&str, &str)]) -> String {
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

pub fn escape_html(value: &str) -> String {
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
    use std::collections::BTreeSet;

    const BASE_URL: &str = "https://console.example.com";

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
    fn pages_resolve_builtins_then_variables_then_the_dictionary() {
        let template = r#"<html lang="{{lang}}" dir="{{dir}}"><link rel="canonical" href="{{canonical}}"><title>{{meta.title}}</title>{{extra}}</html>"#;
        let page = render_page(template, Locale::It, BASE_URL, |key| {
            (key == "extra").then(|| "<b>markup</b>".to_owned())
        });
        assert_eq!(
            page,
            format!(
                r#"<html lang="it" dir="ltr"><link rel="canonical" href="{BASE_URL}/it"><title>{}</title><b>markup</b></html>"#,
                escape_html(message(Locale::It, "meta.title"))
            )
        );
    }

    #[test]
    #[should_panic(expected = "does not define")]
    fn an_unknown_placeholder_fails_loudly() {
        render_page("{{no.such.key}}", Locale::En, BASE_URL, |_| None);
    }

    #[test]
    fn the_language_selector_and_alternates_cover_every_locale() {
        for page_locale in SUPPORTED_LOCALES {
            let page = render_page(
                "{{alternate_links}}{{language_links}}",
                page_locale,
                BASE_URL,
                |_| None,
            );
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
                assert!(page.contains(&format!(
                    r#"<link rel="alternate" hreflang="{locale}" href="{BASE_URL}{}">"#,
                    locale.path()
                )));
            }
            assert_eq!(page.matches(r#"aria-current="page""#).count(), 1);
            // One alternate per language plus x-default, and nothing else.
            assert_eq!(
                page.matches(r#"<link rel="alternate""#).count(),
                SUPPORTED_LOCALES.len() + 1
            );
            assert!(page.contains(&format!(
                r#"<link rel="alternate" hreflang="x-default" href="{BASE_URL}{}">"#,
                DEFAULT_LOCALE.path()
            )));
        }
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
