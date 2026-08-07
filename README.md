# Luxor

[![Build & Tests](https://github.com/giuliom/luxor/actions/workflows/CI.yml/badge.svg)](https://github.com/giuliom/luxor/actions/workflows/CI.yml)

Luxor is a runnable production-oriented Rust backend template built with Axum. It includes PostgreSQL persistence and migrations, Redis cache and queue boundaries, Kafka domain events with an in-process consumer, JWT access tokens with rotating refresh sessions, role-based permissions with a fixed grant matrix, per-client rate limiting, ticket-authenticated realtime WebSockets, provider-neutral OAuth extension points, structured errors and tracing, service-backed tests, and a small same-origin browser console — statically generated in English and Italian at language-prefixed URLs — with live, in-page trace and Rust-to-WebAssembly demos. Local development runs against a real, app-managed embedded PostgreSQL server, so no Docker is required.

## Quick start

Prerequisites: a current stable Rust toolchain. No Docker is required.

```sh
cargo run
```

Open <http://localhost:8080>. When `DATABASE_URL` is not set outside production, Luxor starts an embedded development PostgreSQL server: the first run downloads the server binaries once into `~/.theseus/postgresql`, and cluster data persists in the gitignored `.luxor/` directory, so accounts and sessions survive restarts. When `REDIS_URL` is not set, the cache and queue use in-memory backends, and when `KAFKA_BROKERS` is not set, domain events run over an in-process bus. The embedded database always applies the checked-in migrations at startup; an external `DATABASE_URL` migrates when `AUTO_MIGRATE=true`. Production requires both URLs, and should set `AUTO_MIGRATE=false` and run `luxor migrate` (or `cargo sqlx migrate run`) as a separate, controlled deployment step.

### Running against Docker PostgreSQL, Redis, and Kafka

To exercise the Redis-backed cache and queue and a real Kafka topic, or to develop against the same services production uses, point the URLs at real instances — the Compose file provides all three:

```sh
cargo install sqlx-cli --version 0.8.6 --no-default-features --features rustls,postgres --locked
cp .env.example .env   # then set DATABASE_URL, REDIS_URL, and KAFKA_BROKERS to the Compose values
docker compose up -d
cargo sqlx migrate run
cargo run
```

Compose reads `POSTGRES_PORT`, `REDIS_PORT`, and `KAFKA_PORT` for its host mappings. If a default port is occupied, change that value and the corresponding URL in `.env` before starting the services. `sqlx-cli` 0.8 is used for creating, applying, and reverting migrations.

To stop local infrastructure, use `docker compose down`. Add `--volumes` only when you intentionally want to delete local database and Redis data.

### Debugging in VS Code

With the CodeLLDB extension installed, choose **Debug luxor** and press F5. This default configuration needs no Docker: it runs the embedded development PostgreSQL server with the in-memory cache, queue, and event bus, so the complete authentication and persistence flow works out of the box. It pins `DATABASE_URL`, `REDIS_URL`, and `KAFKA_BROKERS` to empty values so a local `.env` cannot re-point it at external services.

Choose **Debug luxor (Docker PostgreSQL + Redis + Kafka)** to run against real Redis, a real Kafka broker, and an external PostgreSQL. Its pre-launch task requires Docker Desktop, starts all three, and waits for their health checks before launching Luxor. Both configurations set `APP_OPEN_BROWSER=true`, so Luxor opens <http://127.0.0.1:8080/> in the system-default browser immediately after binding its listener. An external browser is intentional because Luxor's security headers prevent the frontend from being embedded in VS Code's Simple Browser.

## HTTP API

All application endpoints are under `/api` and JSON errors use this shape:

```json
{"error":{"code":"bad_request","message":"a valid email is required"}}
```

Every response carries `x-request-id`; an incoming value is preserved, otherwise the server generates one. Requests that exceed the processing deadline (`REQUEST_TIMEOUT_SECONDS`) answer `408` with a `request_timeout` error.

Every `/api` route is rate limited per client IP inside a fixed window, and the `/api/auth` endpoints carry an additional, much stricter budget because they are the brute-force surface. Exceeding a budget answers `429` with a `rate_limited` error plus `Retry-After`, `RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset` headers. Counters live in Redis when `REDIS_URL` is set (shared across instances) and in memory otherwise; see the `RATE_LIMIT_*` and `CLIENT_IP_SOURCE` settings.

| Method | Route | Authentication | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/health` | No | Liveness response |
| `GET` | `/api/runtime` | No | Report the active database, cache, and queue backends |
| `GET` | `/api/hello?name=Ada` | No | Lightweight query demo |
| `GET` | `/api/time` | No | UTC server clock |
| `GET` | `/api/telemetry/demo` | No | Emit nested spans and return trace correlation IDs |
| `GET` | `/api/telemetry/traces/{trace_id}` | No | Return the in-process captured spans for one trace |
| `POST` | `/api/auth/register` | No | Create a password user and session |
| `POST` | `/api/auth/login` | No | Verify credentials and create a session |
| `POST` | `/api/auth/refresh` | Refresh cookie | Rotate the refresh token and issue access JWT |
| `POST` | `/api/auth/logout` | Refresh cookie optional | Revoke the presented session and clear the cookie |
| `GET` | `/api/me` | Bearer JWT | Return the current user |
| `GET` | `/api/permissions` | No | Read the role-permission matrix and permission catalog |
| `GET` | `/api/demo/reports` | Bearer JWT + `reports.view` | Permission-gated sample report |
| `DELETE` | `/api/demo/records` | Bearer JWT + `records.purge` | Permission-gated simulated purge |
| `GET/PUT/DELETE` | `/api/cache/demo` | Bearer JWT | Read, cache, or invalidate a JSON value |
| `POST` | `/api/jobs` | Bearer JWT | Enqueue an audit or email-contract job |
| `POST` | `/api/events` | Bearer JWT | Publish a note to the event topic and return its partition and offset |
| `GET` | `/api/events?limit=20` | Bearer JWT | Read the events this instance has consumed back off the topic |
| `POST` | `/api/realtime/ticket` | Bearer JWT | Mint a single-use ticket for one WebSocket handshake |
| `GET` | `/api/realtime/ws` | Ticket query parameter | Upgrade to the realtime event stream |

Registration and login accept `{"email":"...","password":"..."}`; registration additionally accepts an optional `"role"` of `"admin"` or `"user"` (the default). They return a short-lived access token in JSON and set an opaque refresh token as an HTTP-only, `SameSite=Strict` cookie. Production cookies are `Secure`. The browser demo keeps the access token in a JavaScript variable only—never local or session storage—and sends the refresh cookie only to `/api/auth`.

Passwords travel as plaintext inside the TLS-protected request body — hashing in the browser would only make the hash the password — and are held server-side in a `SecretString` that zeroizes on drop. Neither credential request type derives `Debug`, so there is no way to format a password into a log line, a span field, or a Sentry event. Registration requires 12 to 1024 characters *and* a zxcvbn score of at least 3, with the account's own email supplied as context: `mike@northwind.com` cannot choose `Northwind2026!`, which scores full marks on shape alone because "northwind" is in no dictionary. Only the first 128 bytes are scored, since zxcvbn's matchers are superlinear and the input is attacker-controlled. Login deliberately does not re-check strength, so tightening the policy never locks an existing account out.

Stored hashes are Argon2id at pinned parameters (19 MiB, t=2, p=1 — OWASP's second recommended configuration) with a per-password random salt, written as PHC strings. Pinning them here rather than taking `Argon2::default()` means a crate upgrade cannot move the cost unnoticed. Verification reads algorithm, version, and cost from each stored hash, so raising the pinned values keeps old hashes working; the next successful login for such an account transparently re-hashes it at the new cost and writes it back, best-effort, so an upgrade reaches existing users and not only new ones. A hash already stronger than the pinned values is left alone rather than downgraded.

Refresh tokens are SHA-256 hashed in PostgreSQL and rotate on every use. Reusing a rotated token revokes its entire token family, and a family can never be renewed past `REFRESH_FAMILY_TTL_SECONDS` after the login that created it, so a stolen cookie cannot be kept alive forever. Logout revokes refresh state; already-issued stateless access JWTs remain usable until their intentionally short expiry. Login responds identically — in status and in timing — whether the email is unknown or the password is wrong, so accounts cannot be enumerated. A background task prunes sessions once their whole rotation family has expired (revoked rows are kept until then, because they are what lets rotation detect a replayed stolen token).

## Roles and permissions

Every account carries one of two fixed roles, chosen once at registration and stored in PostgreSQL: `admin` or `user`. The role is immutable afterwards — there is deliberately no endpoint that changes it. It travels as a claim in the access JWT, so permission checks never re-query the database (tokens issued before this feature carry no role claim and fail verification, which pushes clients through the refresh flow for a new token).

What a role may do is defined by a fixed role-permission matrix that is part of the application's authorization contract: `admin` holds both `reports.view` and `records.purge`, `user` holds only `reports.view`. The grants live in code, are identical across restarts and instances, and change only through a code change and deployment; there is no endpoint that edits them. The two `/api/demo` endpoints enforce the grants server-side and answer `403` with a `forbidden` error naming the missing permission.

`GET /api/permissions` serves a public, read-only view of the matrix together with the permission catalog. The browser console renders it and highlights the signed-in role, so you can register one account per role and watch the same request succeed or fail against the enforced grants.

## Configuration

`.env.example` documents every setting. `.env` and environment-specific variants are ignored by Git.

| Variable | Required/default | Notes |
| --- | --- | --- |
| `APP_ENV` | `development` | `development`, `test`, or `production`; production switches logs to JSON |
| `APP_HOST`, `APP_PORT` | `127.0.0.1`, `8080` | Listener address; production defaults to `0.0.0.0`, and a platform-injected `PORT` overrides `APP_PORT` |
| `DATABASE_URL` | Embedded PostgreSQL outside production | PostgreSQL URL; required in production. Unset or empty selects the app-managed embedded development server |
| `REDIS_URL` | In-memory backends outside production | `redis://` or `rediss://`; required in production. Unset or empty selects the in-memory cache and queue |
| `JWT_SECRET` | Unsafe local default outside production | Required in production; unique and at least 32 characters |
| `ACCESS_TOKEN_TTL_SECONDS` | `900` | JWT lifetime |
| `REFRESH_TOKEN_TTL_SECONDS` | `2592000` | Must exceed the access lifetime |
| `REFRESH_FAMILY_TTL_SECONDS` | `7776000` | Absolute cap on refresh rotation (90 days); must be at least the refresh token lifetime |
| `REFRESH_COOKIE_SECURE` | true only in production | Keep true behind production HTTPS |
| `CORS_ORIGINS` | `https://localhost:8080` | Comma-separated exact origins; credentials are enabled. Must all be `https` in production |
| `PUBLIC_BASE_URL` | Derived | Absolute public origin for canonical URLs, hreflang alternates, and the sitemap; development derives the listener address, production the first CORS origin |
| `HSTS_ENABLED` | true only in production | Send `Strict-Transport-Security` |
| `HSTS_MAX_AGE_SECONDS` | `31536000` | `0` releases browsers that cached a policy |
| `HSTS_INCLUDE_SUBDOMAINS` | `true` | Adds `includeSubDomains` |
| `HSTS_PRELOAD` | `false` | Adds `preload`; requires `includeSubDomains` and a max-age of at least one year |
| `HTTPS_ENFORCEMENT` | `proxy-header` in production, else `off` | `off` or `proxy-header`; the latter turns away requests `x-forwarded-proto` marks as plaintext |
| `BODY_LIMIT_BYTES` | `1048576` | JSON body limit |
| `REQUEST_TIMEOUT_SECONDS` | `30` | End-to-end deadline per request, including body reads |
| `RATE_LIMIT_ENABLED` | `true` | Cannot be disabled in production |
| `RATE_LIMIT_AUTH_MAX_REQUESTS`, `RATE_LIMIT_AUTH_WINDOW_SECONDS` | `10` per `60` | Per-IP budget for `/api/auth` endpoints |
| `RATE_LIMIT_API_MAX_REQUESTS`, `RATE_LIMIT_API_WINDOW_SECONDS` | `120` per `60` | Per-IP budget for all `/api` routes |
| `RATE_LIMIT_NAMESPACE` | `luxor:ratelimit` | Redis key prefix for the distributed limiter |
| `CLIENT_IP_SOURCE` | `socket`; `x-forwarded-for` in production | How clients are identified for rate limiting; only use `x-forwarded-for` behind a trusted proxy |
| `KAFKA_BROKERS` | In-process event bus | `host:port` list; unset or empty selects the in-process bus. Every other `KAFKA_*` setting requires it, and startup fails rather than ignoring one |
| `KAFKA_TOPIC` | `luxor.events` | Topic domain events are published to and consumed from |
| `KAFKA_CONSUMER_GROUP` | `luxor-console` | Instances sharing a group split the partitions; different groups each get every event |
| `KAFKA_CLIENT_ID` | `luxor` | Identifies the application in broker logs and metrics |
| `KAFKA_SECURITY_PROTOCOL` | `plaintext` | `plaintext`, `ssl`, `sasl_plaintext`, or `sasl_ssl` |
| `KAFKA_SASL_MECHANISM`, `KAFKA_SASL_USERNAME`, `KAFKA_SASL_PASSWORD` | Empty | Required together by the SASL protocols and refused by the others; `PLAIN`, `SCRAM-SHA-256`, or `SCRAM-SHA-512` |
| `KAFKA_DELIVERY_TIMEOUT_SECONDS` | `10` | Deadline for one publish including acknowledgement; keep it inside the request timeout |
| `REALTIME_MAX_CONNECTIONS` | `100` | WebSockets one instance serves at once; further handshakes answer `503` |
| `REALTIME_TICKET_TTL_SECONDS` | `30` | Lifetime of a single-use connection ticket; capped at 300 |
| `AUTO_MIGRATE` | true outside production | Must normally be false in production; the embedded development database always migrates itself |
| `APP_OPEN_BROWSER` | `false` | Development-only opt-in that opens the frontend in the system-default browser after startup |
| `CACHE_NAMESPACE`, `QUEUE_KEY` | `luxor:cache`, `luxor:queue:jobs` | Redis namespacing |
| `RUST_LOG` | Sensible service defaults | Standard tracing filter syntax |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Empty/disabled | Enables batched OTLP tracing when set |
| `OTEL_SERVICE_NAME` | `luxor` | OpenTelemetry `service.name` resource attribute |
| `SENTRY_DSN` | Empty/disabled | Enables Sentry error capture when set |

Do not commit real secrets or put them in image layers. Inject them at runtime through the deployment platform’s secret manager, use a long random JWT secret, terminate TLS before accepting secure cookies, restrict database/Redis network access, and rotate credentials through a controlled rollout.

## Database migrations

Migrations live in `migrations/` and are embedded into the binary, both for optional development startup and for `luxor migrate`, which applies them once and exits — the release-step command used by deployments (no `sqlx-cli` required at runtime).

```sh
# Create a paired up/down migration while developing
cargo sqlx migrate add -r describe_change

# Apply, inspect, and revert
cargo sqlx migrate run
cargo sqlx migrate info
cargo sqlx migrate revert
```

The checked-in migrations create normalized unique users, hashed refresh sessions with family/revocation indexes, and an audit-event example table. Repository queries bind all inputs and use typed `query_as` result mapping. This avoids requiring a live database merely to compile; teams that adopt SQLx query macros can add a checked-in `.sqlx` offline cache.

## Redis contracts

Cache keys are validated, namespaced, JSON encoded, and always written with a positive TTL. A missing or expired key is a normal cache miss. Cache failures are surfaced as server errors rather than changing authoritative PostgreSQL data. Alongside the usual read, write, and invalidate, the cache exposes an atomic take (`GETDEL` on Redis 6.2+, the write lock held across read and removal in memory) so that single-use credentials such as the realtime connection ticket can be redeemed exactly once even when two callers race.

The queue is enqueue-only. Producers `LPUSH` a version-stable JSON `JobEnvelope` to `QUEUE_KEY`; a separate future worker should use blocking `BRPOP`, which preserves FIFO order. The envelope contains an ID, explicit kind, tagged payload, enqueue time, `attempt`, and `max_attempts`. The worker owns acknowledgement semantics, retry backoff, idempotency, and dead-letter movement. `SendEmail` is only a provider-neutral job contract—this repository deliberately sends no email.

## Kafka event stream

One topic carries what the application announces about itself. Registering an account publishes `user.registered`, enqueueing a job publishes `job.enqueued`, and the console's **Event stream** card publishes `note.published` on demand. A consumer in the same process reads the topic back into a bounded in-memory window that `GET /api/events` serves, so the feed the console renders has genuinely been through the broker — each entry shows the partition and offset the record was written at, which is what distinguishes it from an echo of the publish response.

Records are JSON, keyed, and versioned:

```json
{"id":"9f1c…","schema_version":1,"key":"3cfe10fc-…","occurred_at":"2026-01-01T12:00:00.123Z",
 "kind":"user.registered","payload":{"user_id":"3cfe10fc-…","role":"admin"}}
```

The key is the identifier the event is about — the user, the job, the note's author. Kafka orders records only within a partition and picks the partition from the key, so keying this way is what keeps all events about one entity in order regardless of partition count or how many instances publish. Consumers switch on `kind` and ignore payloads they do not recognize; `schema_version` is what lets a consumer refuse a shape it was never written for. Each record also carries `content-type`, `event-id`, `event-kind`, and `schema-version` headers plus the W3C `traceparent` of the publishing request, so a consumer — this one or someone else's — continues the same trace instead of starting an unrelated one. The producer span is a `producer` span and the consume span a `consumer` span, which is how they appear in Jaeger and in the console's own trace waterfall.

Three delivery decisions are worth naming:

- **The producer is idempotent.** `enable.idempotence` pins `acks=all` and lets librdkafka retry a publish without risking a duplicate or a reordering, so a receipt means every in-sync replica holds the record.
- **This application commits offsets, after handling an event**, rather than letting librdkafka's auto-commit timer acknowledge records that were merely read. Delivery is therefore at-least-once: a crash between handling and committing replays the event, which is a failure a consumer can defend against, unlike the silent loss auto-commit produces. A record that cannot be decoded is committed anyway and logged, because it will never decode later and the alternative is a projection that stops advancing forever; a deployment that must keep such records routes them to a dead-letter topic at that point.
- **Publishing never fails the request that triggered it.** The account already exists and the job is already queued by the time the event is published, so a broker that is briefly unreachable costs the event, logged as lost, rather than the operation. Closing that gap means the transactional outbox pattern — writing the event to PostgreSQL inside the same transaction as the state change and relaying it from there — which is a larger commitment than this boundary makes, and the point at which "at-most-once announcement" stops being acceptable is a per-event decision.

Without `KAFKA_BROKERS` the same publish and consume paths run over an in-process bus, so the card works with nothing installed. It is a stand-in, not a broker: nothing is persisted, there is one partition because there is one process, and no event reaches another instance. `GET /api/runtime` reports which of the two is live, and the console badge follows it.

The client is [rust-rdkafka](https://github.com/fede1024/rust-rdkafka) over librdkafka, compiled from vendored sources together with the OpenSSL it needs for TLS and SASL SCRAM, and statically linked. That keeps `cargo run` working with no system packages installed and leaves the runtime image unchanged; the builder stage of the `Dockerfile` carries the `g++`, `make`, and `perl` those vendored builds need. Kerberos (`GSSAPI`) is deliberately not linked, so managed Kafka is reached with `sasl_ssl` and a SCRAM or PLAIN mechanism.

## Realtime WebSockets

The console's **Realtime** card opens a WebSocket, and everything it receives arrives without a request: a welcome frame, presence as connections come and go, broadcasts from other clients, and a server tick every five seconds. Open <http://localhost:8080> in two tabs, sign in on both, connect, and broadcast — each tab sees the other's arrival and messages. `cargo test --test realtime` drives the same paths through a real listener and a real WebSocket client, so none of it depends on a browser being present.

Connections are opened in two steps, because a browser handshake cannot carry an `Authorization` header:

1. `POST /api/realtime/ticket` with the access token mints a random 256-bit ticket, valid for `REALTIME_TICKET_TTL_SECONDS`. Only its SHA-256 hash is stored, exactly as refresh tokens are handled, so a cache dump yields no usable connection credential.
2. `GET /api/realtime/ws?ticket=…` redeems it. Redemption is a single atomic take, so a replayed ticket — one lifted from an access log or a proxy trace — answers `401`. Putting the JWT itself in that query string is what this avoids: the ticket is spent by the time it could be read anywhere.

Two more checks run before the upgrade. **CORS does not apply to WebSockets** — a page on any origin may open one, and the browser will send it, which is what makes cross-site WebSocket hijacking possible — so the endpoint compares `Origin` against `CORS_ORIGINS` and against the `Host` the request was sent to, and answers `403` otherwise. A handshake carrying no `Origin` at all is allowed, because browsers always send one and its absence marks a non-browser client that cannot be tricked into connecting on a user's behalf; the ticket, not the origin, is what authenticates a connection. The instance then admits the socket only if it is below `REALTIME_MAX_CONNECTIONS`, answering `503` with an `at_capacity` error when it is not. Both the ticket exchange and the upgrade sit under `/api`, so the per-IP rate limiter meters them.

An established socket is metered by the connection itself, since the HTTP rate limiter never sees it again: at most 5 broadcasts per 5 seconds per connection, at most 280 characters each, and messages larger than 8 KiB fail the connection at the protocol level rather than being buffered. The server pings every five seconds and closes a connection that has answered nothing for 60 seconds, because a half-open TCP connection is not an error and would otherwise hold its slot until the process restarts. A client that falls more than 256 events behind is told what it missed instead of being served a silently truncated stream.

Events are JSON with a `type` discriminator inside an envelope carrying the server timestamp and the live connection count, so clients switch on `type` and ignore what they do not recognize:

```json
{"at":"2026-01-01T12:00:00.123Z","connections":2,"type":"message","sequence":7,
 "from":{"user_id":"3cfe10fc-…","role":"admin"},"text":"hello"}
```

The other types are `welcome` (the connection's own identity plus the limits above, so a client renders them rather than hardcoding a copy), `presence`, `tick`, and `notice` — the last being how a connection is told about itself, such as a rejected command or a dropped backlog, without being disconnected for it. Clients send one command, `{"type":"broadcast","text":"…"}`; an unknown one earns a notice rather than a close, so a newer client talking to an older server degrades instead of flapping. Events are fanned out to every connection, so they carry the opaque user id and role, never the account's email. The console reconnects with backoff when a socket drops — a fresh ticket per attempt — and closes it deliberately on sign-out.

The site's Content-Security-Policy needs no WebSocket-specific directive: `connect-src 'self'` covers a same-origin `ws://`/`wss://` connection, and naming a scheme instead would have to allow every host.

The fan-out is in-process. One instance serves its own connections, which is the right shape for this demo and for a single-instance deployment; a horizontally scaled one needs a shared bus (Redis pub/sub, or a dedicated realtime service) before a broadcast reaches clients attached to other instances. That boundary is deliberate, like the queue's missing worker: this is the socket lifecycle, not a distributed message broker.

## WebAssembly demo

The console's WebAssembly card benchmarks a prime sieve compiled from Rust ([`wasm/`](wasm/)) against the identical sieve in JavaScript, cross-checking that both counts agree. After one untimed warmup, each displayed timing is the average of 10 measured iterations. The module is plain `wasm32-unknown-unknown` output with a C-ABI export — no bindings generator or JS glue — and the page loads it with standard `WebAssembly.instantiateStreaming`, which requires the `application/wasm` content type the `/demo.wasm` route serves. The site's Content-Security-Policy allows this with the CSP3 `'wasm-unsafe-eval'` keyword, which permits WebAssembly compilation while continuing to forbid JavaScript `eval`.

The built module is checked in at `public/demo.wasm` and embedded into the server binary like the other static assets, so backend builds, CI, and the Docker image need no WebAssembly toolchain. The `wasm/` crate is deliberately outside the backend build; after changing it, verify and rebuild the committed module:

```sh
rustup target add wasm32-unknown-unknown
cargo test --manifest-path wasm/Cargo.toml
cargo build --manifest-path wasm/Cargo.toml --target wasm32-unknown-unknown --release
cp wasm/target/wasm32-unknown-unknown/release/luxor_wasm.wasm public/demo.wasm
```

## Internationalisation

The console is served in English at [`/en`](http://localhost:8080/en) and Italian at [`/it`](http://localhost:8080/it) — language-prefixed URLs are the source of truth, so every translation has a stable, shareable, indexable address. Each page is statically generated at startup from one HTML template ([`public/index.html`](public/index.html)) and a per-locale dictionary ([`locales/en/common.json`](locales/en/common.json), [`locales/it/common.json`](locales/it/common.json)), so the response is complete in its language before the first byte leaves the server — nothing is translated in the browser after the fact, and there is no wrong-language flash.

`GET /` serves no content: it negotiates a language and answers a `302` with `Vary: Cookie, Accept-Language` and `Cache-Control: no-store`, so a shared cache can never pin every visitor to one visitor's language. The priority is the `lang` cookie the language selector sets (the persisted user choice — the server cannot know the signed-in account when serving a page, because the access token lives only in page memory and the refresh cookie is scoped to `/api/auth`), then the browser's weighted `Accept-Language`, then English. A language named in the URL is never overridden by any of these, and `it-IT`/`it-CH` resolve to Italian by primary subtag — regional variants earn their own locale only when content genuinely differs.

Dictionary entries are stable semantic keys (`errors.code.not_found`, never the English sentence) holding whole messages with named `{placeholder}` slots — sentences are never concatenated from fragments, so word order is free to differ per language. Plural forms live under CLDR category keys (`telemetry.spans.one` / `.other`) selected client-side with `Intl.PluralRules`, and dates, numbers, and unit-tagged durations go through `Intl.DateTimeFormat`/`Intl.NumberFormat` rather than manual formatting. The page's dictionary is inlined as a non-executing JSON data block (allowed by the CSP, which continues to forbid inline scripts; translated values are HTML-escaped when rendered, and `</` is escaped in the block, so a translation can never inject markup or terminate its element), which keeps client-side strings to one language and zero extra requests. The API stays language-neutral: it returns stable error codes, and the console translates the code, keeping the server's request-specific detail visibly appended rather than passing it off as translated.

Each rendered page carries its `<html lang>` and `dir`, a translated title and meta description, a self-referencing canonical URL, and reciprocal `hreflang` alternates (plus `x-default`); `/sitemap.xml` lists every language version, and the language selector is ordinary crawlable links, so search engines discover translations without executing JavaScript or guessing from headers. The absolute origin in those URLs comes from `PUBLIC_BASE_URL` or its documented derivation. Trailing-slash variants (`/en/`) redirect permanently to the canonical form, and language-prefixed URLs make locale part of any CDN cache key by construction.

Unit tests in [`src/i18n.rs`](src/i18n.rs) gate CI on translation health: dictionaries must parse, carry identical key sets (missing and obsolete keys both fail), keep the same placeholders per key across languages, contain no markup, define every key the template and script look up, and define no key nothing uses; rendered pages must contain no unresolved placeholder and correct canonical/hreflang metadata. A client-side lookup that still misses renders its key on screen — a loud, diagnosable failure rather than a silent English fallback. To add a language: add a `Locale` variant and a `locales/<lang>/common.json` (the tests then enforce completeness), and translated slugs beyond the language prefix are unnecessary while the console is a single page.

## Adding an OAuth provider

OAuth is intentionally an extension boundary, not a half-configured provider flow. Set all five `OAUTH_*` variables or none; partial configuration fails startup.

1. Implement `auth::OAuthProvider` for the provider’s authorization URL and code exchange.
2. Generate an `OAuthState`, store it with a short TTL (the cache boundary is suitable), and send the state plus a derived PKCE challenge in the authorization redirect.
3. On callback, atomically consume stored state, use `OAuthState::matches`, exchange the code with the stored verifier, and validate the returned `OAuthIdentity`.
4. Link provider and subject to a local user in a dedicated migration. Do not use an unverified provider email as an account-linking key.
5. Issue the same local access/refresh credentials used by password login. Never expose the client secret or provider tokens to the browser.

## Observability

Development and test logs are compact; production logs are JSON. HTTP spans include OpenTelemetry server-span metadata, method, path, response status, and request ID. Incoming W3C `traceparent`, `tracestate`, and `baggage` headers are extracted so Luxor traces continue an upstream distributed trace. Sentry initializes only when a DSN is present, and server-side errors are captured without exposing internal messages to clients.

The tracer is always on: finished spans are kept in a bounded in-process store (the most recent 512, span names and timings only — attribute values are not retained) that the browser console consumes through `GET /api/telemetry/traces/{trace_id}`. Open <http://localhost:8080> and choose **Generate trace** in the OpenTelemetry card: the demo trace — the HTTP server span, the instrumented handler span, and two concurrent child spans — renders as a span waterfall directly on the page, with no collector required.

When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, the same spans are additionally exported over OTLP/gRPC using the Tokio batch processor and flushed during graceful shutdown. The Compose observability profile runs a local, in-memory Jaeger collector and UI to receive them (a development demo, not a production storage setup):

```sh
docker compose --profile observability up -d
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 \
OTEL_SERVICE_NAME=luxor \
cargo run
```

In Jaeger at <http://localhost:16686>, select the `luxor` service or paste the trace ID shown in the console into its trace lookup; batched export may take a few seconds.

For production, send OTLP to an OpenTelemetry Collector or managed backend, use a deliberate sampling policy, and configure durable retention outside this repository. The local Jaeger profile keeps traces only in memory.

## Tests and quality gates

Fast tests require no services:

```sh
cargo test --lib
```

The complete suite automatically enables the PostgreSQL, Redis, and Kafka integration tests when their addresses exist:

```sh
docker compose up -d
DATABASE_URL=postgres://luxor:luxor@localhost:5432/luxor \
REDIS_URL=redis://127.0.0.1:6379/ \
KAFKA_BROKERS=localhost:9092 \
cargo test --all-targets --all-features
```

Integration tests use random users, Redis namespaces, and Kafka topics and consumer groups, run migrations idempotently, and clean up their records. The Kafka test publishes through a real producer and waits for the record to come back through a real consumer group, so it exercises the round trip rather than the client's API surface. CI starts ephemeral PostgreSQL, Redis, and Kafka services and runs:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-targets --all-features
cargo audit --ignore RUSTSEC-2023-0071
cargo test --all-targets --all-features
```

The scoped RustSec exception is for RSA timing advisory `RUSTSEC-2023-0071`, which enters `Cargo.lock` through SQLx macros' optional MySQL support. CI first fails if `rsa` ever appears in the active dependency graph; the exception is valid only while PostgreSQL remains the sole compiled SQLx driver.

## Deploying to Railway

The repository ships with a multi-stage `Dockerfile` and a `railway.json` that configure the build, the `/api/health` health check, and a pre-deploy `luxor migrate` step, so migrations run as an explicit release step while `AUTO_MIGRATE` stays disabled in production. The image builds with `--no-default-features`, which keeps the embedded development PostgreSQL server (the `embedded-postgres` cargo feature) out of production binaries.

1. Create a Railway project and add **PostgreSQL** and **Redis** database services.
2. Add a service from this GitHub repository. Railway detects the `Dockerfile` and `railway.json` automatically.
3. On the app service, set these variables:

   | Variable | Value |
   | --- | --- |
   | `APP_ENV` | `production` (also baked into the image as a safety default) |
   | `DATABASE_URL` | `${{Postgres.DATABASE_URL}}` |
   | `REDIS_URL` | `${{Redis.REDIS_URL}}` |
   | `JWT_SECRET` | A unique random string of at least 32 characters |
   | `CORS_ORIGINS` | Your public URL, e.g. `https://<service>.up.railway.app` |

4. Deploy. Railway injects `PORT` and the server binds `0.0.0.0:$PORT`; the pre-deploy command applies migrations before traffic shifts, and the health check gates the rollout on `/api/health`.

The reference `DATABASE_URL`/`REDIS_URL` values above use Railway's private networking. The frontend console is served same-origin by the app itself, so no separate frontend deployment is needed.

## Production checklist

- Supply production-only database, Redis, Kafka, JWT, and optional telemetry secrets through a managed store.
- Set `APP_ENV=production`, `AUTO_MIGRATE=false`, `REFRESH_COOKIE_SECURE=true`, and exact HTTPS CORS origins.
- Run migrations as an explicit release step before shifting traffic.
- Use managed PostgreSQL/Redis with TLS, authentication, backups, and least-privilege network rules.
- Terminate HTTPS at a trusted proxy and preserve or generate `x-request-id`. Production then defaults to `HTTPS_ENFORCEMENT=proxy-header`, which redirects plaintext `GET`/`HEAD` to https and refuses every other plaintext method with `403 https_required`. It reads `x-forwarded-proto`, so the proxy must overwrite that header on every request instead of passing a client-supplied one through; a request that arrives without it is allowed, because failing closed would break health checks that bypass the proxy while buying nothing against a caller who can reach the container directly. Network rules, not this check, are what keep that caller out.
- Production also refuses to start with a plaintext `CORS_ORIGINS` entry, and sends `Strict-Transport-Security: max-age=31536000; includeSubDomains`. Enable `HSTS_PRELOAD` only deliberately: preload-list submission is close to irreversible, and the config rejects the flag unless it also meets the list's own `includeSubDomains` and one-year max-age rules.
- Review the rate-limit budgets for your traffic shape; production runs with `x-forwarded-for` client identification by default, which is only safe behind the platform proxy.
- Reach managed Kafka over `sasl_ssl` with a SCRAM mechanism, and give the deployment its own `KAFKA_CONSUMER_GROUP`: instances sharing one split the topic's partitions, which is what you want for scale and not what you want for a second environment reading the same topic. Create the topic with the partition count and retention the workload needs — the app publishes to it and does not create it — and decide before launch which events cannot tolerate the at-most-once announcement described above.
- Size `REALTIME_MAX_CONNECTIONS` against the instance's memory and file-descriptor limits, and confirm the proxy's idle timeout exceeds the five-second server tick. Before scaling past one instance, put a shared bus behind the hub or expect broadcasts to reach only the clients attached to the same instance.
- Set resource limits, health probes, alerting, retention, and sampling for logs/traces/errors.
- Plan JWT-secret rotation, database restore tests, and queue dead-letter handling (expired refresh sessions are pruned automatically).

Beyond the Railway configuration above, this repository intentionally contains no container-publishing, provider-specific OAuth, email-provider, or worker workflow.
