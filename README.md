# 🛡️ VaultGuard

**VaultGuard** is a security-focused Secret Management system built with **.NET 9 / C# 13** (Clean Architecture) on the backend and a **React + TypeScript** client on the frontend. It stores sensitive data — passwords, API keys, credit card info, and private notes — using **envelope-style AES-256-GCM encryption**, JWT-based authentication, and comprehensive audit logging.

This project was built as a hands-on deep dive into secure backend engineering: encryption at rest, defense-in-depth validation, and the kind of test discipline that a real security-sensitive system demands.

---

## ⚠️ Project Status & Honesty Notice

This is a **portfolio / learning project**, not a production-audited commercial product. Before you rely on it for real secrets, know the following:

- **No independent security audit or penetration test has been performed.** Do not use this to store real production credentials.
- **A web frontend now exists** (see [Frontend Client](#-frontend-client) below). No mobile app or browser extension exists yet.
- **A secrets-exposure incident happened during development, and was fixed properly.** Early in the project, the encryption key and JWT signing secret were accidentally committed to `appsettings.json` and pushed to this public repository — twice, including once after an initial rotation that didn't fully solve the problem. The real fix wasn't just changing the values: it was rewriting the entire Git history with `git-filter-repo` to remove the file from every past commit, force-pushing the cleaned history, and generating fresh, random keys that were never exposed. I'm documenting this instead of quietly hiding it, because how you respond to a security mistake matters more than never making one — and "fully purge history + rotate + prevent recurrence" is the correct incident-response pattern, not just editing the current file.
- **AI-assisted development:** Large parts of this codebase — including debugging, test suite repair, architectural refinements, the frontend client, and the incident response above — were built with the help of AI pair-programming (Claude). I designed the domain model, security requirements, and architecture decisions, and directed every change; AI helped implement, debug, and explain them. I believe in being transparent about this: the code has been reviewed and understood by me, not blindly copy-pasted, but I want anyone evaluating this project to know how it was built.
- **No multi-factor authentication (MFA/2FA) yet.** This is a known gap for a system that markets itself as security-first, and it's next on the roadmap.

---

## 🚀 Key Backend Features

- **Envelope Encryption (AES-256-GCM):** Secrets are encrypted with a unique 96-bit nonce per record before touching the database. The database operator never sees plaintext.
- **Password Hashing (BCrypt):** User passwords are never stored or logged in any recoverable form.
- **JWT Authentication + Refresh Tokens:** Stateless auth with short-lived access tokens and rotating refresh tokens.
- **Audit Logging:** Every security-relevant action (login, secret access, decryption, deletion) is logged with a correlation ID, IP address, and timestamp. Logs are append-only at the application level — no code path updates or deletes an audit record. (Worth being precise here: this is enforced in application code, not by a database-level trigger or immutable storage backend. Anyone with direct database access and elevated permissions could still alter the table. Closing that gap — e.g. a write-only DB role, or shipping logs to an append-only store — is on the roadmap.)
- **Defense-in-Depth Input Validation:** FluentValidation rules reject XSS payloads (`<script>`, event handlers, `javascript:` URIs) at the API boundary. SQL injection is mitigated at the data layer via EF Core's parameterized queries rather than blocklist validation — the correct place to solve that problem.
- **IP Safelisting Middleware:** Fail-safe by design — if the safelist configuration is missing or invalid, the middleware blocks all traffic rather than defaulting open.
- **Rate Limiting:** Per-IP request throttling to slow down brute-force and abuse attempts. Currently backed by in-memory counters, which means it resets on restart and doesn't coordinate across multiple instances — fine for a single-instance deployment, not yet horizontally scalable.
- **Global Exception Handling:** Centralized error middleware that returns standardized, sanitized error responses — no stack traces leak in production.
- **Security Headers Middleware:** HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and removal of server-identifying headers (`Server`, `X-Powered-By`, `X-AspNet-Version`).

---

## 🛠️ Technical Stack

**Backend**

| Layer | Technology |
|---|---|
| Runtime | .NET 9 / C# 13 |
| Database | SQL Server (production) / EF Core InMemory (testing) |
| Architecture | Clean Architecture (Domain → Application → Infrastructure → WebAPI) |
| Auth | JWT Bearer + Refresh Tokens |
| Encryption | AES-256-GCM (envelope encryption), BCrypt (password hashing) |
| Validation | FluentValidation |
| Testing | xUnit, Moq, FluentAssertions |

**Frontend** (`client/`)

| Layer | Technology |
|---|---|
| Framework | React 19 + TypeScript, built with Vite |
| Routing | React Router 7 |
| Server state | TanStack Query |
| HTTP | Axios (with a refresh-token interceptor) |
| Styling | Tailwind CSS v4 |
| Icons | lucide-react |
| CSV parsing | PapaParse |

---

## 🏗️ Project Structure

Clean Architecture with strict dependency direction (outer layers depend on inner layers, never the reverse):

- **`VaultGuard.Domain`** — Core entities (`Secret`, `User`, `AuditLog`), value validation, and business rules. Zero external dependencies.
- **`VaultGuard.Application`** — Use cases, DTOs, validators, and service interfaces. Orchestrates domain logic.
- **`VaultGuard.Infrastructure`** — EF Core DbContext, migrations, repositories, encryption service implementation, and external integrations.
- **`VaultGuard.WebAPI`** — Controllers, middleware pipeline (auth, rate limiting, IP safelist, security headers, global exception handling), and API versioning.
- **`client/`** — The React/TypeScript frontend described below. It is a pure HTTP consumer of the WebAPI; no backend code exists to serve it directly, and no backend code was changed to accommodate it.

---

## 💻 Frontend Client

A single-page application in `client/` that consumes every major endpoint the API exposes, over plain HTTP with JWT bearer auth.

**What it covers:**
- **Auth:** registration and sign-in against `/api/Auth`, with automatic refresh-token rotation handled by an Axios response interceptor — a failed request due to an expired access token silently retries once after a successful refresh.
- **Vault registry:** create, edit, reveal (decrypt on demand), and delete secrets, with optional category and expiration date.
- **Bulk entry:** two paths into the vault beyond one-by-one forms — pasting a delimited multi-line list, or uploading a CSV file with interactive column mapping and a preview before import. Both drive the same `/api/Secrets` create endpoint per row; there is no separate bulk-import endpoint on the backend.
- **Account management:** updating profile fields, changing password, and revoking all active sessions via `/api/Users`.
- **Audit trail:** a view against `/api/AuditLogs`, correctly respecting the API's own `Admin`/`Auditor` role restriction — a regular `User` account sees an explicit "access restricted" state instead of a raw, unexplained 403.

**Design intent:** a calm, light, glass-panel visual style (soft blue/violet accents, no dark "hacker terminal" aesthetic) — deliberately chosen so a security tool feels approachable rather than intimidating.

**Running it locally**, alongside the API:
```bash
cd client
npm install
npm run dev
```
It expects the API URL in `client/.env` (`VITE_API_URL`), pointed at wherever `dotnet run --project src/VaultGuard.WebAPI` is listening.

**Known limitations, stated plainly:**
- JWT access and refresh tokens are stored in `localStorage` for simplicity. This is a reasonable trade-off for a local/portfolio deployment, but not what you'd want in a hardened production build — an httpOnly-cookie-based flow is the correct next step there, and is on the roadmap.
- There is no pagination or search on the secrets list; every secret the user owns is fetched in one call. Fine at portfolio scale, a real gap at hundreds-of-entries scale.
- The CSV/paste bulk-import feature calls the single-secret create endpoint once per row client-side — it is a UX convenience, not a server-side bulk operation, so importing a very large file will be as slow as that many individual requests.

---

## 🧪 Test Coverage

This project has a genuinely large automated test suite — **1,100+ tests** spanning:

- **Domain tests:** entity invariants, validation rules, business method behavior
- **Application tests:** validator edge cases (null/empty/whitespace input, XSS payloads, SQL injection strings), service logic with mocked dependencies
- **Infrastructure tests:** repository behavior, EF Core mapping, encryption round-trips, transaction isolation
- **WebAPI tests:** middleware pipeline behavior, integration tests against an in-memory database, authorization and authentication edge cases

A small number of tests are explicitly marked `Skip` with a documented reason (e.g. .NET's `HttpResponse.OnStarting` callback not firing under a mocked test context, or EF Core's InMemory provider not supporting real transactions). These are test-infrastructure limitations, not application bugs — and I'd rather be upfront about that than hide it.

```bash
dotnet test
```

---

## 🔐 Security Design Notes

A few decisions worth explaining, since "why" matters more than "what" in security code:

- **SQL injection is handled at the query layer, not the input layer.** Early versions of this project rejected any input containing SQL keywords (`SELECT`, `DROP`, etc.) at the validator level. This was removed — it broke legitimate input (a secret titled *"Notes on SELECT statements"*) while providing no real protection, since EF Core already parameterizes every query. Defense belongs where the actual risk lives.
- **IP safelist fails closed.** If configuration is missing, null, or malformed, the middleware blocks *all* traffic rather than allowing it. A misconfigured safelist should never silently become "allow everyone."
- **12-byte IV for AES-GCM, not 16.** GCM mode requires a 96-bit nonce per the NIST specification (SP 800-38D) — using a CBC-style 128-bit IV was an early inconsistency that's been corrected across the encryption service, EF Core configuration, and tests.
- **Secrets do not belong in version control, full stop.** See the incident described above. The lasting fix isn't a `.gitignore` entry alone — a file already tracked by Git stays tracked until it's explicitly untracked (`git rm --cached`) or purged from history. `appsettings.Example.json` (placeholder values only) now documents what configuration is expected, without ever containing a real key.
- **A known piece of redundancy, left visible on purpose:** the `Secret` entity stores an `IV` byte array as its own database column, separate from `EncryptedValue`. In the current implementation this is redundant — `AesEncryptionService` already prepends the real nonce to the front of `EncryptedValue`'s own byte layout (`Nonce + Ciphertext + Tag`), and decryption reads the nonce from there, never from the separate column. The `IV` column is written correctly and consistently, just never read back. I'm leaving this note in rather than quietly deleting the column, because "encryption metadata that looks load-bearing but isn't" is exactly the kind of thing a code reviewer should be able to catch — and did.

---

## 🗺️ Roadmap / Known Gaps

- [ ] Multi-factor authentication (TOTP)
- [x] Frontend web client
- [ ] Independent security audit / third-party penetration test
- [ ] Secret rotation policies and expiry notifications
- [ ] Rate limiting backed by distributed cache (currently in-memory, single-instance only)
- [ ] Move frontend token storage from `localStorage` to an httpOnly-cookie-based flow
- [ ] Pagination and search on the secrets list
- [ ] Database-level enforcement of audit log immutability (write-only role or append-only store), not just application-level convention
- [ ] Remove or repurpose the redundant `Secret.IV` column

---

## 📄 License

This project is for educational and portfolio purposes. See [LICENSE](LICENSE) for details.