//! The browser console: localized pages rendered once at startup, the sitemap
//! and robots.txt, and the static files the pages load.
//!
//! Rendering covers more than text: facts about the deployment that are fixed
//! for the life of the process — the permission matrix, the runtime badge,
//! the content-addressed asset URLs — are rendered into the page too, so its
//! first response is complete without a script fetching the rest.

use crate::{
    access::{AccessPermission, AccessRole, Permission, Role},
    assets::{self, Asset, CachePolicy, StaticFile, StaticFiles},
    i18n::{self, escape_html, format_message, message, Locale, SUPPORTED_LOCALES},
    state::AppState,
};
use axum::{response::Redirect, routing::get, Router};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, LazyLock},
};

const INDEX_TEMPLATE: &str = include_str!("../../public/index.html");

/// The console's static files, fingerprinted and compressed once per process:
/// their content is fixed at compile time, so every router shares one copy.
fn files() -> &'static StaticFiles {
    static FILES: LazyLock<StaticFiles> = LazyLock::new(|| {
        StaticFiles::new([
            StaticFile::new(
                "/styles.css",
                "text/css; charset=utf-8",
                include_bytes!("../../public/styles.css"),
            ),
            StaticFile::new(
                "/script.js",
                "text/javascript; charset=utf-8",
                include_bytes!("../../public/script.js"),
            ),
            StaticFile::new(
                "/favicon.svg",
                "image/svg+xml; charset=utf-8",
                include_bytes!("../../public/favicon.svg"),
            ),
            // Fetched on demand by the WebAssembly card. Instantiating it with
            // WebAssembly.instantiateStreaming requires exactly this content
            // type, with no parameters.
            StaticFile::new(
                "/demo.wasm",
                "application/wasm",
                include_bytes!("../../public/demo.wasm"),
            ),
        ])
    });
    &FILES
}

/// Everything a rendered page shows beyond its language. Each value is fixed
/// for the life of the process, which is what makes rendering the page once at
/// startup — instead of per request, or in the browser after load — correct.
struct PageContext<'a> {
    /// Absolute public origin for the canonical, hreflang, and Open Graph URLs.
    base_url: &'a str,
    /// Whether this instance runs on the embedded development PostgreSQL
    /// server, which the service card's runtime badge reports.
    embedded_database: bool,
    /// The grants the permissions card renders. They are fixed at compile
    /// time (see `app/access.rs`); were they ever loaded from storage, the
    /// matrix would have to be rendered per request instead.
    grants: BTreeMap<Role, BTreeSet<Permission>>,
    files: &'a StaticFiles,
}

impl<'a> PageContext<'a> {
    fn new(core: &'a AppState) -> Self {
        Self {
            base_url: core.config.http.public_base_url(),
            embedded_database: core.config.database.url.is_none(),
            grants: core.permissions.grants(),
            files: files(),
        }
    }
}

/// The console's routes: `/` (a negotiated redirect), one page per language,
/// the sitemap, robots.txt, and the static files.
///
/// Every localized page has its own stable URL and is complete — translated,
/// with the permission matrix and runtime badge filled in — before the first
/// byte is sent, so the browser neither translates nor fetches anything to
/// finish it. Pages, sitemap, and robots.txt are revalidated on every use:
/// their content changes with a deployment, and the ETag makes an unchanged
/// one a 304.
pub fn site<S>(core: &AppState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let context = PageContext::new(core);
    let mut site = Router::new().route("/", get(i18n::localized_root));
    for locale in SUPPORTED_LOCALES {
        let page = Asset::new("text/html; charset=utf-8", render_page(locale, &context))
            .with_content_language(locale.as_str());
        site = site
            .route(
                locale.path(),
                assets::serve(Arc::new(page), CachePolicy::Revalidate),
            )
            // One canonical URL per language: the slashed variant redirects
            // rather than serving a duplicate.
            .route(
                &format!("{}/", locale.path()),
                get(move || async move { Redirect::permanent(locale.path()) }),
            );
    }
    let sitemap = Asset::new(
        "application/xml; charset=utf-8",
        i18n::render_sitemap(context.base_url),
    );
    let robots = Asset::new("text/plain; charset=utf-8", render_robots(context.base_url));
    site.route(
        "/sitemap.xml",
        assets::serve(Arc::new(sitemap), CachePolicy::Revalidate),
    )
    .route(
        "/robots.txt",
        assets::serve(Arc::new(robots), CachePolicy::Revalidate),
    )
    .merge(context.files.routes())
}

/// Renders the console page for one locale: the language plumbing and the
/// translated text come from [`i18n::render_page`], the rest from `context`.
fn render_page(locale: Locale, context: &PageContext<'_>) -> String {
    i18n::render_page(INDEX_TEMPLATE, locale, context.base_url, |key| {
        Some(match key {
            "styles_url" => escape_html(context.files.url("/styles.css")),
            "script_url" => escape_html(context.files.url("/script.js")),
            "favicon_url" => escape_html(context.files.url("/favicon.svg")),
            "wasm_url" => escape_html(context.files.url("/demo.wasm")),
            "runtime_badge" => escape_html(message(
                locale,
                if context.embedded_database {
                    "runtime.embedded"
                } else {
                    "runtime.fullStack"
                },
            )),
            "permissions_matrix" => permissions_matrix(locale, &context.grants),
            _ => return None,
        })
    })
}

/// Points crawlers at the sitemap, whose URL robots.txt requires to be
/// absolute, and keeps them off the API: its JSON is not content, and crawler
/// traffic would spend the per-IP rate-limit budgets. Nothing the pages show
/// depends on it, because they arrive fully rendered.
fn render_robots(base_url: &str) -> String {
    format!("User-agent: *\nDisallow: /api/\n\nSitemap: {base_url}/sitemap.xml\n")
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

    for &permission in Permission::ALL {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{access::PermissionStore, i18n::DEFAULT_LOCALE};

    const SCRIPT_SOURCE: &str = include_str!("../../public/script.js");
    const BASE_URL: &str = "https://console.example.com";

    /// This module without its tests: the renderer's own dictionary lookups
    /// (the matrix, the runtime badge) live here rather than in the template.
    fn renderer_source() -> &'static str {
        const SOURCE: &str = include_str!("console.rs");
        SOURCE
            .split_once("#[cfg(test)]")
            .map_or(SOURCE, |(code, _)| code)
    }

    fn context(embedded_database: bool) -> PageContext<'static> {
        PageContext {
            base_url: BASE_URL,
            embedded_database,
            grants: PermissionStore.grants(),
            files: files(),
        }
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
                r#"<link rel="alternate" hreflang="x-default" href="{BASE_URL}{}">"#,
                DEFAULT_LOCALE.path()
            )));
        }
    }

    #[test]
    fn pages_are_rendered_in_their_own_language() {
        let english = render_page(Locale::En, &context(true));
        assert!(english.contains(&format!(
            "<title>{}</title>",
            escape_html(message(Locale::En, "meta.title"))
        )));

        let italian = render_page(Locale::It, &context(true));
        assert!(italian.contains(&format!(
            "<title>{}</title>",
            escape_html(message(Locale::It, "meta.title"))
        )));
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
        for &role in Role::ALL {
            for &permission in Permission::ALL {
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
        for &role in Role::ALL {
            assert_eq!(role_label_key(role), format!("roles.{}", role.name()));
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
        let files = files();
        assert!(page.contains(&format!(
            r#"<link rel="icon" href="{}" type="image/svg+xml">"#,
            files.url("/favicon.svg")
        )));
        assert!(page.contains(&format!(
            r#"<link rel="stylesheet" href="{}">"#,
            files.url("/styles.css")
        )));
        assert!(page.contains(&format!(
            r#"<script src="{}"></script>"#,
            files.url("/script.js")
        )));
        assert!(page.contains(&format!(r#"data-module="{}""#, files.url("/demo.wasm"))));
    }

    #[test]
    fn embedded_files_have_distinct_content_addressed_paths() {
        let files = files();
        for (path, stem, extension) in [
            ("/styles.css", "styles", "css"),
            ("/script.js", "script", "js"),
            ("/favicon.svg", "favicon", "svg"),
            ("/demo.wasm", "demo", "wasm"),
        ] {
            let file = files.get(path).expect("the console embeds this file");
            assert_eq!(
                file.fingerprinted_path,
                format!("/assets/{stem}.{}.{extension}", file.asset.fingerprint())
            );
        }
        assert_eq!(files.iter().count(), 4);
    }
}
