# Luxor

[![Build & Tests](https://github.com/giuliom/luxor/actions/workflows/CI.yml/badge.svg)](https://github.com/giuliom/luxor/actions/workflows/CI.yml)

Luxor is a runnable production-oriented Rust backend template built with Axum. It includes PostgreSQL persistence and migrations, Redis cache and queue boundaries, JWT access tokens with rotating refresh sessions, provider-neutral OAuth extension points, structured errors and tracing, service-backed tests, and a small same-origin browser console.

## Quick start

Prerequisites:

- A current stable Rust toolchain
- Docker with Compose
- `sqlx-cli` 0.8 for creating, applying, and reverting migrations

```sh
cargo install sqlx-cli --version 0.8.6 --no-default-features --features rustls,postgres --locked
cp .env.example .env
docker compose up -d
cargo sqlx migrate run
cargo run
```

Open <http://localhost:8080>. By default the application connects to a local PostgreSQL instance at `localhost:5432` (and Redis at `localhost:6379`); the Compose file provides both, but any locally running PostgreSQL works — point `DATABASE_URL` at it in `.env`. Development startup also applies checked-in migrations when `AUTO_MIGRATE=true`. Production should set it to `false` and run `luxor migrate` (or `cargo sqlx migrate run`) as a separate, controlled deployment step.

Compose reads `POSTGRES_PORT` and `REDIS_PORT` for its host mappings. If either default port is occupied, change that value and the corresponding URL in `.env` before starting the services.

To stop local infrastructure, use `docker compose down`. Add `--volumes` only when you intentionally want to delete local database and Redis data.

### Debugging in VS Code

With the CodeLLDB extension installed, choose **Debug luxor** and press F5. This default configuration needs no Docker: it starts Luxor with an ephemeral in-memory cache and queue, while persistent authentication is disabled. The service, OpenTelemetry, cache, and queue browser demos remain available, and all in-memory data is cleared when the process stops.

Choose **Debug luxor (PostgreSQL + Redis)** when you need the complete authentication and persistence flow. Its pre-launch task requires Docker Desktop, starts PostgreSQL and Redis, and waits for both health checks before launching Luxor. Both configurations set `APP_OPEN_BROWSER=true`, so Luxor opens <http://127.0.0.1:8080/> in the system-default browser immediately after binding its listener. An external browser is intentional because Luxor's security headers prevent the frontend from being embedded in VS Code's Simple Browser.

## HTTP API

All application endpoints are under `/api` and JSON errors use this shape:

```json
{"error":{"code":"bad_request","message":"a valid email is required"}}
```

Every response carries `x-request-id`; an incoming value is preserved, otherwise the server generates one.

| Method | Route | Authentication | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/health` | No | Liveness response |
| `GET` | `/api/runtime` | No | Report full-stack or standalone backend capabilities |
| `GET` | `/api/hello?name=Ada` | No | Lightweight query demo |
| `GET` | `/api/time` | No | UTC server clock |
| `GET` | `/api/telemetry/demo` | No | Emit nested spans and return trace correlation IDs |
| `POST` | `/api/auth/register` | No | Create a password user and session |
| `POST` | `/api/auth/login` | No | Verify credentials and create a session |
| `POST` | `/api/auth/refresh` | Refresh cookie | Rotate the refresh token and issue access JWT |
| `POST` | `/api/auth/logout` | Refresh cookie optional | Revoke the presented session and clear the cookie |
| `GET` | `/api/me` | Bearer JWT | Return the current user |
| `GET/PUT/DELETE` | `/api/cache/demo` | Bearer JWT | Read, cache, or invalidate a JSON value |
| `POST` | `/api/jobs` | Bearer JWT | Enqueue an audit or email-contract job |

Registration and login accept `{"email":"...","password":"..."}`. They return a short-lived access token in JSON and set an opaque refresh token as an HTTP-only, `SameSite=Strict` cookie. Production cookies are `Secure`. The browser demo keeps the access token in a JavaScript variable only—never local or session storage—and sends the refresh cookie only to `/api/auth`.

Refresh tokens are SHA-256 hashed in PostgreSQL and rotate on every use. Reusing a rotated token revokes its entire token family. Logout revokes refresh state; already-issued stateless access JWTs remain usable until their intentionally short expiry.

## Configuration

`.env.example` documents every setting. `.env` and environment-specific variants are ignored by Git.

| Variable | Required/default | Notes |
| --- | --- | --- |
| `APP_ENV` | `development` | `development`, `test`, or `production`; production switches logs to JSON |
| `APP_HOST`, `APP_PORT` | `127.0.0.1`, `8080` | Listener address; production defaults to `0.0.0.0`, and a platform-injected `PORT` overrides `APP_PORT` |
| `DATABASE_URL` | Local default outside production | PostgreSQL URL; required in production |
| `REDIS_URL` | Local default outside production | `redis://` or `rediss://`; required in production |
| `JWT_SECRET` | Unsafe local default outside production | Required in production; unique and at least 32 characters |
| `ACCESS_TOKEN_TTL_SECONDS` | `900` | JWT lifetime |
| `REFRESH_TOKEN_TTL_SECONDS` | `2592000` | Must exceed the access lifetime |
| `REFRESH_COOKIE_SECURE` | true only in production | Keep true behind production HTTPS |
| `CORS_ORIGINS` | `http://localhost:8080` | Comma-separated exact origins; credentials are enabled |
| `BODY_LIMIT_BYTES` | `1048576` | JSON body limit |
| `AUTO_MIGRATE` | true outside production | Must normally be false in production |
| `APP_STANDALONE` | `false` | Development-only in-memory mode; disables persistent authentication and avoids PostgreSQL/Redis connections |
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

Cache keys are validated, namespaced, JSON encoded, and always written with a positive TTL. A missing or expired key is a normal cache miss. Cache failures are surfaced as server errors rather than changing authoritative PostgreSQL data.

The queue is enqueue-only. Producers `LPUSH` a version-stable JSON `JobEnvelope` to `QUEUE_KEY`; a separate future worker should use blocking `BRPOP`, which preserves FIFO order. The envelope contains an ID, explicit kind, tagged payload, enqueue time, `attempt`, and `max_attempts`. The worker owns acknowledgement semantics, retry backoff, idempotency, and dead-letter movement. `SendEmail` is only a provider-neutral job contract—this repository deliberately sends no email.

## Adding an OAuth provider

OAuth is intentionally an extension boundary, not a half-configured provider flow. Set all five `OAUTH_*` variables or none; partial configuration fails startup.

1. Implement `auth::OAuthProvider` for the provider’s authorization URL and code exchange.
2. Generate an `OAuthState`, store it with a short TTL (the cache boundary is suitable), and send the state plus a derived PKCE challenge in the authorization redirect.
3. On callback, atomically consume stored state, use `OAuthState::matches`, exchange the code with the stored verifier, and validate the returned `OAuthIdentity`.
4. Link provider and subject to a local user in a dedicated migration. Do not use an unverified provider email as an account-linking key.
5. Issue the same local access/refresh credentials used by password login. Never expose the client secret or provider tokens to the browser.

## Observability

Development and test logs are compact; production logs are JSON. HTTP spans include OpenTelemetry server-span metadata, method, path, response status, and request ID. Incoming W3C `traceparent`, `tracestate`, and `baggage` headers are extracted so Luxor traces continue an upstream distributed trace. When an OTLP endpoint is present, spans are exported over OTLP/gRPC using the Tokio batch processor and flushed during graceful shutdown. Sentry initializes only when a DSN is present, and server-side errors are captured without exposing internal messages to clients.

The Compose observability profile runs a local, in-memory Jaeger collector and UI. It is a development demo, not a production storage setup:

```sh
docker compose --profile observability up -d
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 \
OTEL_SERVICE_NAME=luxor \
cargo run
```

Open <http://localhost:8080>, choose **Generate trace** in the OpenTelemetry card, and then open <http://localhost:16686>. The API response shows the `service.name`, request ID, trace ID, span ID, and sampling decision; the trace may take a few seconds to appear because export is batched. In Jaeger, select the `luxor` service or paste the trace ID into its trace lookup. The demo trace contains the HTTP server span, the instrumented handler span, and two concurrent child spans.

For production, send OTLP to an OpenTelemetry Collector or managed backend, use a deliberate sampling policy, and configure durable retention outside this repository. The local Jaeger profile keeps traces only in memory.

## Tests and quality gates

Fast tests require no services:

```sh
cargo test --lib
```

The complete suite automatically enables PostgreSQL and Redis integration tests when their URLs exist:

```sh
docker compose up -d
DATABASE_URL=postgres://luxor:luxor@localhost:5432/luxor \
REDIS_URL=redis://127.0.0.1:6379/ \
cargo test --all-targets --all-features
```

Integration tests use random users and Redis namespaces, run migrations idempotently, and clean up their records. CI starts ephemeral PostgreSQL and Redis services and runs:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo build --all-targets --all-features
cargo audit --ignore RUSTSEC-2023-0071
cargo test --all-targets --all-features
```

The scoped RustSec exception is for RSA timing advisory `RUSTSEC-2023-0071`, which enters `Cargo.lock` through SQLx macros' optional MySQL support. CI first fails if `rsa` ever appears in the active dependency graph; the exception is valid only while PostgreSQL remains the sole compiled SQLx driver.

## Deploying to Railway

The repository ships with a multi-stage `Dockerfile` and a `railway.json` that configure the build, the `/api/health` health check, and a pre-deploy `luxor migrate` step, so migrations run as an explicit release step while `AUTO_MIGRATE` stays disabled in production.

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

- Supply production-only database, Redis, JWT, and optional telemetry secrets through a managed store.
- Set `APP_ENV=production`, `AUTO_MIGRATE=false`, `REFRESH_COOKIE_SECURE=true`, and exact HTTPS CORS origins.
- Run migrations as an explicit release step before shifting traffic.
- Use managed PostgreSQL/Redis with TLS, authentication, backups, and least-privilege network rules.
- Terminate HTTPS at a trusted proxy and preserve or generate `x-request-id`.
- Set resource limits, health probes, alerting, retention, and sampling for logs/traces/errors.
- Plan JWT-secret rotation, refresh-session cleanup, database restore tests, and queue dead-letter handling.

Beyond the Railway configuration above, this repository intentionally contains no container-publishing, provider-specific OAuth, email-provider, or worker workflow.
