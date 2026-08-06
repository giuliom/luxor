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

use std::collections::BTreeMap;
use std::sync::OnceLock;

/// Name of the cookie that stores an explicitly selected language. It is set
/// by the language selector in the browser and read only by the `/` redirect;
/// it never overrides a language named in the URL.
pub const PREFERENCE_COOKIE: &str = "lang";

/// The default site language, served when nothing better is known and used as
/// the `x-default` hreflang target.
pub const DEFAULT_LOCALE: Locale = Locale::En;

/// Every language the console is available in. Adding a language means adding
/// a variant here, a `locales/<lang>/common.json` dictionary, and a route; the
/// dictionary-parity tests then enforce completeness.
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
        static DICTIONARIES: [OnceLock<BTreeMap<String, String>>; 2] =
            [OnceLock::new(), OnceLock::new()];
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
/// and `q=0` entries are skipped; ties keep the client's ordering.
fn accept_language_locale(header: &str) -> Option<Locale> {
    let mut best: Option<(Locale, f32)> = None;
    for entry in header.split(',') {
        let mut parts = entry.split(';');
        let Some(locale) = Locale::from_tag(parts.next().unwrap_or_default().trim()) else {
            continue;
        };
        let quality = parts
            .find_map(|param| param.trim().strip_prefix("q="))
            .and_then(|quality| quality.parse::<f32>().ok())
            .unwrap_or(1.0);
        if quality > 0.0 && best.is_none_or(|(_, held)| quality > held) {
            best = Some((locale, quality));
        }
    }
    best.map(|(locale, _)| locale)
}

const INDEX_TEMPLATE: &str = include_str!("../public/index.html");

/// Renders the console page for one locale. Called once per locale at startup
/// — static generation, so every response is already in the right language —
/// and panics on an unknown or unclosed placeholder, which the tests catch
/// long before a deployment does.
pub fn render_page(locale: Locale, base_url: &str) -> String {
    let mut page = String::with_capacity(INDEX_TEMPLATE.len() * 2);
    let mut rest = INDEX_TEMPLATE;
    while let Some(start) = rest.find("{{") {
        page.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find("}}")
            .expect("unclosed {{ placeholder in public/index.html");
        page.push_str(&resolve_placeholder(&after[..end], locale, base_url));
        rest = &after[end + 2..];
    }
    page.push_str(rest);
    page
}

fn resolve_placeholder(key: &str, locale: Locale, base_url: &str) -> String {
    // Template variables computed by code, not translated. Everything else is
    // a dictionary key, and its value is escaped: translations are treated as
    // untrusted input exactly like any other content.
    match key {
        "lang" => locale.as_str().to_owned(),
        "dir" => locale.text_direction().to_owned(),
        "base_url" => escape_html(base_url),
        "canonical" => escape_html(&format!("{base_url}{}", locale.path())),
        "aria_current_en" => aria_current(locale, Locale::En),
        "aria_current_it" => aria_current(locale, Locale::It),
        "i18n_json" => inline_dictionary(locale),
        _ => escape_html(locale.dictionary().get(key).unwrap_or_else(|| {
            panic!("public/index.html references `{key}`, which locales/{locale}/common.json does not define")
        })),
    }
}

fn aria_current(page: Locale, link: Locale) -> String {
    if page == link {
        r#" aria-current="page""#.to_owned()
    } else {
        String::new()
    }
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
    use std::collections::BTreeSet;

    const SCRIPT_SOURCE: &str = include_str!("../public/script.js");
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
        // A key is referenced directly (template placeholder or quoted string
        // in the script) or through its parent, which covers plural variants
        // (`telemetry.spans.one`) and dynamic families (`errors.code.<code>`).
        let sources = format!("{INDEX_TEMPLATE}{SCRIPT_SOURCE}");
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
            let page = render_page(locale, BASE_URL);
            assert!(
                !page.contains("{{"),
                "the rendered {locale} page still contains a placeholder"
            );
            assert!(page.contains(&format!(r#"<html lang="{locale}" dir="ltr">"#)));
        }
    }

    #[test]
    fn rendered_pages_carry_reciprocal_seo_metadata() {
        for locale in SUPPORTED_LOCALES {
            let page = render_page(locale, BASE_URL);
            assert!(page.contains(&format!(
                r#"<link rel="canonical" href="{BASE_URL}{}">"#,
                locale.path()
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
        let english = render_page(Locale::En, BASE_URL);
        assert!(english.contains("<title>Luxor backend console</title>"));

        let italian = render_page(Locale::It, BASE_URL);
        assert!(italian.contains("<title>Console backend Luxor</title>"));
        assert!(italian.contains("Autenticazione"));
        // The inlined dictionary matches the page language, so the client
        // never loads a second language's resources.
        assert!(italian.contains(r#""labels.session":"Sessione""#));
        assert!(!italian.contains(r#""labels.session":"Session""#));
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
    }

    #[test]
    fn html_escaping_covers_markup_and_attribute_characters() {
        assert_eq!(
            escape_html(r#"<a href="x">&'"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }
}
