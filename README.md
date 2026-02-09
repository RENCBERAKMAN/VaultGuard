# 🛡️ VaultGuard API

**VaultGuard** is a security-focused, enterprise-grade Secret Management API built with **.NET 8** and **Clean Architecture**. It provides a robust infrastructure for storing sensitive data such as passwords, API keys, and personal information with a **Zero-Knowledge** approach.

## 🚀 Key Features
- **Zero-Knowledge Encryption:** Data is encrypted before being stored in the database.
- **AES-256 Security:** High-standard symmetric encryption for maximum protection.
- **Clean Architecture:** Decoupled layers (Domain, Application, Infrastructure, WebAPI) for maintainability and testability.
- **Audit Logging:** Every access attempt and data modification is recorded for compliance.
- **RESTful API:** Easily integrable with modern web and mobile applications.

## 🛠️ Technical Stack

* Backend: .NET 9 / C# 13
* Database: SQL Server (Production) / SQLite (Testing)
* Architecture: Clean Architecture
* Security: BCrypt Hashing & AES-256 Encryption


## 🏗️ Project Structure
- `VaultGuard.Domain`: Core entities and interfaces.
- `VaultGuard.Application`: Business logic and use cases.
- `VaultGuard.Infrastructure`: Database context, security services, and external integrations.
- `VaultGuard.WebAPI`: API endpoints and middlewares.