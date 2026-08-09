# 🛡️ VaultGuard API

**VaultGuard** is a security-focused Secret Management API built with **.NET 9 / C# 13** and **Clean Architecture**. It provides a backend infrastructure for storing sensitive data — passwords, API keys, credit card info, and private notes — using **envelope-style AES-256-GCM encryption**, JWT-based authentication, and comprehensive audit logging.

This project was built as a hands-on deep dive into secure backend engineering: encryption at rest, defense-in-depth validation, and the kind of test discipline that a real security-sensitive system demands.

---

## ⚠️ Project Status & Honesty Notice

This is a **portfolio / learning project**, not a production-audited commercial product. Before you rely on it for real secrets, know the following:

- **No independent security audit or penetration test has been performed.** Do not use this to store real production credentials.
- **No frontend, mobile app, or browser extension exists yet.** This is an API-only backend.
- **AI-assisted development:** Large parts of this codebase — including debugging, test suite repair, and some architectural refinements — were built with the help of AI pair-programming (Claude). I designed the domain model, security requirements, and architecture decisions, and AI helped implement, debug, and stress-test them. I believe in being transparent about this: the code has been reviewed and understood by me, not blindly copy-pasted, but I want anyone evaluating this project to know how it was built.
- **No multi-factor authentication (MFA/2FA) yet.** This is a known gap for a system that markets itself as security-first, and it's next on the roadmap.

---

## 🚀 Key Features

- **Envelope Encryption (AES-256-GCM):** Secrets are encrypted with a unique 96-bit nonce (IV) per record before touching the database. The database operator never sees plaintext.
- **Password Hashing (BCrypt):** User passwords are never stored or logged in any recoverable form.
- **JWT Authentication + Refresh Tokens:** Stateless auth with short-lived access tokens and rotating refresh tokens.
- **Immutable Audit Logging:** Every security-relevant action (login, secret access, decryption, deletion) is logged with a correlation ID, IP address, and timestamp — and audit logs are append-only at the domain level.
- **Defense-in-Depth Input Validation:** FluentValidation rules reject XSS payloads (`<script>`, event handlers, `javascript:` URIs) at the API boundary. SQL injection is mitigated at the data layer via EF Core's parameterized queries rather than blocklist validation — the correct place to solve that problem.
- **IP Safelisting Middleware:** Fail-safe by design — if the safelist configuration is missing or invalid, the middleware blocks all traffic rather than defaulting open.
- **Rate Limiting:** Per-IP request throttling to slow down brute-force and abuse attempts.
- **Global Exception Handling:** Centralized error middleware that returns standardized, sanitized error responses — no stack traces leak in production.
- **Security Headers Middleware:** HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and removal of server-identifying headers (`Server`, `X-Powered-By`, `X-AspNet-Version`).

---

## 🛠️ Technical Stack

| Layer | Technology |
|---|---|
| Runtime | .NET 9 / C# 13 |
| Database | SQL Server (production) / EF Core InMemory (testing) |
| Architecture | Clean Architecture (Domain → Application → Infrastructure → WebAPI) |
| Auth | JWT Bearer + Refresh Tokens |
| Encryption | AES-256-GCM (envelope encryption), BCrypt (password hashing) |
| Validation | FluentValidation |
| Testing | xUnit, Moq, FluentAssertions |

---

## 🏗️ Project Structure

Clean Architecture with strict dependency direction (outer layers depend on inner layers, never the reverse):

- **`VaultGuard.Domain`** — Core entities (`Secret`, `User`, `AuditLog`), value validation, and business rules. Zero external dependencies.
- **`VaultGuard.Application`** — Use cases, DTOs, validators, and service interfaces. Orchestrates domain logic.
- **`VaultGuard.Infrastructure`** — EF Core DbContext, repositories, encryption service implementation, and external integrations.
- **`VaultGuard.WebAPI`** — Controllers, middleware pipeline (auth, rate limiting, IP safelist, security headers, global exception handling), and API versioning.

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

---

## 🗺️ Roadmap / Known Gaps

- [ ] Multi-factor authentication (TOTP)
- [ ] Frontend web client
- [ ] Independent security audit / third-party penetration test
- [ ] Secret rotation policies and expiry notifications
- [ ] Rate limiting backed by distributed cache (currently in-memory, single-instance only)

---

## 📄 License

This project is for educational and portfolio purposes. See [LICENSE](LICENSE) for details.