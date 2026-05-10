# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build

```bash
mkdir -p build && cd build && cmake .. && make
```

The binary is output as `build/api_server`.

### Dependencies (via pkg-config)

- `mysqlclient` — MySQL/MariaDB client
- `libcjson` — JSON parsing
- `libsodium` — cryptography (password hashing, token generation, SHA-256)
- `hiredis` — Redis client
- `uuid` — UUID generation for client request IDs

### Compiler flags

`-Wall -Wextra -pedantic -g -O2`, C11 standard, no extensions.

## Run

The server reads its configuration from a `.env` file at `../.env` (relative to the `build/` directory, i.e., at the repo root). Copy `.env.exemple` to `.env` and fill in:

| Variable | Purpose |
|---|---|
| `SERVER_PORT` | TCP port to listen on |
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` | MySQL connection |
| `REDIS_HOST`, `REDIS_PORT`, `REDIS_USER`, `REDIS_PASSWORD` | Redis connection |

Logs are written to `/var/log/api_c.log` at `DEBUG` level. The server requires both MySQL and Redis to be reachable at startup or it will exit.

```bash
cd build && ./api_server
```

## Tests

All tests are shell scripts using `curl`. Run them from the repo root while the server is running:

```bash
bash tests/test_login.sh
bash tests/test_register.sh
bash tests/test_logout.sh
bash tests/test_profile.sh
```

Security audit test suites are prefixed `test_bb_` (black-box) and `test_gb_` (grey-box).

> **Note** : the GCRA rate limiter (burst=5, TTL=30s) applies to all routes. Test suites that hit the same route more than 5 times in quick succession will receive 429. Wait 30s between runs or between test groups that target the same route.

## Architecture

The server is a **single-threaded, synchronous HTTP/1.1 server** that handles one client connection at a time in a blocking loop. There are no threads or async I/O.

### Request lifecycle

```
accept() → recv() headers → parse Content-Length → recv() body
→ http_parse_request() → rate_limit_check() (Redis)
→ router_dispatch() → [auth_verify() if protected] → handler()
→ send response → close(client_fd)
```

### Module responsibilities

| Module | Role |
|---|---|
| `server/` | Socket lifecycle (`init`/`run`/`shutdown`), main accept loop, header + body reading, Content-Length validation |
| `http/` | Raw buffer → `http_request_t` struct (`http_parser`), building HTTP response with headers (`http_response_builder`) |
| `router/` | Static route table (`route_t[]`). Matches method+path, calls auth middleware for protected routes, calls handler, sends response |
| `middleware/auth` | Extracts `Bearer` token from `Authorization` header via `strncmp` prefix check, validates length (64 hex chars), SHA-256 hashes it, looks it up in MySQL `tokens` table with expiry check |
| `handler/register` | Registers a new user: validates input, hashes password with `crypto_pwhash_str`, inserts into `users` |
| `handler/login` | Authenticates user: validates input whitelist, fetches `password_hash` from DB, verifies with `crypto_pwhash_str_verify`, generates 32-byte random token, stores SHA-256 hash of the **hex string** in `tokens`, returns hex token |
| `handler/logout` | Revokes a token: re-extracts Bearer token, SHA-256 hashes the hex string, `DELETE FROM tokens WHERE token_hash=?`. Returns 401 if token not found (already revoked), 200 on success |
| `handler/profile` | Returns the authenticated user's profile: reads `user_id` from `req->user_id` (set by router after `auth_verify`), `SELECT id, username, first_name, last_name, created_at, updated_at FROM users WHERE id=?`, returns JSON. Password hash is never included in the response |
| `DB/` | MySQL wrapper: `db_connect`, `db_execute` (INSERT/UPDATE/DELETE), `db_select` (returns open `MYSQL_STMT*` for the caller to fetch), `db_close` |
| `cache/` | Redis wrapper: `cache_healthcheck`, `cache_connect` (with AUTH), `cache_execute`, `cache_close` |
| `cache/rate_limit` | GCRA (Generic Cell Rate Algorithm) rate limiting via a Lua script executed atomically in Redis. Key format: `rl:<path>:<client_ip>`. Limits: 5 burst, 30s TTL |
| `utils/token` | SHA-256 hashes a token using libsodium, outputs as hex string |
| `logger/` | File-based logger with four levels (DEBUG/INFO/WARN/ERROR). Macros: `LOG_DEBUG`, `LOG_INFO`, `LOG_WARN`, `LOG_ERROR` |
| `dotenv/` | Parses `.env` file and calls `setenv()` for each key=value pair |
| `models/user.h` | `user_t` struct with field size constants (`USERNAME_MAX=51`, `PASSWORD_HASH_MAX=256`, etc.) |

### Security design

- Passwords hashed with `crypto_pwhash_str` (Argon2id). Sensitive buffers zeroed with `sodium_memzero` after use.
- Tokens stored as SHA-256 hex hashes in the `tokens` table, never in plaintext. Token expiry checked server-side via `expired_at > NOW()`.
- **Token hashing consistency**: both `login` and `auth_verify`/`logout` hash the **hex string** representation of the token (64 chars), not the raw bytes. This must remain consistent.
- **Timing attack mitigation**: when a username is not found, `crypto_pwhash_str_verify` is still called on a pre-computed `dummy_hash` to prevent timing-based user enumeration.
- **Bearer prefix validation**: `auth_verify` uses `strncmp` (not `strstr`) to check the `Authorization` header starts with `"Bearer "`, preventing prefix-bypass attacks.
- **user_id propagation**: after `auth_verify` succeeds, the router copies `user_id` into `req->user_id` (field added to `http_request_t`). Protected handlers read it directly from `req->user_id` — no need to re-parse the token.
- All DB queries use prepared statements (`MYSQL_BIND`) — no string interpolation.
- Request body and header sizes are capped (`BUFFER_SIZE`, `MAX_BODY_SIZE`) before reading.
- Rate limiting applied per `(route, client_ip)` before routing, using an atomic Redis Lua script.
- Protected routes (`is_protected=1`): `auth_verify` runs before the handler. All auth errors (missing header, bad format, unknown token) return 401 — the handler's own validation is a defensive second layer, never publicly visible for auth failures.

### Route table

| Method | Path | Protected | Handler | Status |
|---|---|---|---|---|
| `POST` | `/register` | No | `register_handler` | ✅ Done |
| `POST` | `/login` | No | `login_handler` | ✅ Done |
| `POST` | `/logout` | Yes | `logout_handler` | ✅ Done |
| `GET` | `/profile` | Yes | `get_profile_handler` | ✅ Done |
| `PUT` | `/profile` | Yes | — | 🚧 À faire |
| `DELETE` | `/profile` | Yes | — | 🚧 À faire |

### Adding a new route

1. Write a handler in `handler/` with signature `int my_handler(http_request_t *req, char *body_out, size_t body_out_size)` returning an HTTP status code.
2. Add the handler `.c` file to `CMakeLists.txt` `add_executable(...)`.
3. Add an entry to `route_tables[]` in `router/router.c` and increment `ROUTE_COUNT`.

> **Note** : `BODY_MAX` in `router.c` is set to 1024. The largest expected response body (GET /profile with all fields) peaks at ~414 bytes. Increase if new routes return larger payloads.
