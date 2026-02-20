using System;

namespace VaultGuard.Application.DTOs.Secrets;

/// <summary>
/// Request DTO for creating a new secret in VaultGuard.
/// 
/// SECURITY WORKFLOW:
/// 1. Client sends plaintext RawValue over HTTPS (TLS 1.3+)
/// 2. Backend validates input (XSS, injection, length)
/// 3. Backend encrypts RawValue using AES-256-GCM
/// 4. Encrypted value stored in database
/// 5. RawValue NEVER persisted or logged
/// 6. Audit log entry created (who created, when, from which IP)
/// 
/// THREAT MODEL MITIGATION:
/// - Man-in-the-middle: HTTPS/TLS encryption
/// - SQL Injection: Parameterized queries (EF Core)
/// - XSS: Input sanitization + output encoding
/// - Logging leak: RawValue marked as [SensitiveData]
/// - Replay attack: CSRF token + idempotency key
/// 
/// COMPLIANCE:
/// - PCI-DSS Level 1 (if storing credit cards)
/// - HIPAA (if storing PHI)
/// - SOC 2 Type II audit trail
/// - GDPR right to erasure
/// 
/// VALIDATION:
/// - Performed by FluentValidation (CreateSecretDtoValidator)
/// - Rate limiting: max 100 secrets per user per hour
/// - Duplicate check: same Title + UserId
/// </summary>
/// <remarks>
/// ⚠️ CRITICAL SECURITY WARNING:
/// RawValue contains PLAINTEXT sensitive data. This value must:
/// 1. NEVER be logged (even debug logs)
/// 2. NEVER be cached on client
/// 3. NEVER be stored in plain text
/// 4. NEVER appear in error messages
/// 5. Be encrypted immediately upon receipt
/// 6. Be cleared from memory after encryption (use SecureString if possible)
/// </remarks>
public record CreateSecretDto
{
    /// <summary>
    /// User-friendly title/name for the secret.
    /// 
    /// VALIDATION RULES:
    /// - Required
    /// - MinLength(3) - prevent meaningless titles
    /// - MaxLength(200) - prevent DoS via large payloads
    /// - Regex: ^[a-zA-Z0-9\s\-_\.]+$ (alphanumeric + safe chars)
    /// - Uniqueness: per user (same user cannot have duplicate titles)
    /// 
    /// SECURITY:
    /// - HTML/Script tags sanitized (prevent XSS)
    /// - SQL keywords escaped (prevent SQLi)
    /// - No Unicode RLO/LRO characters (prevent display spoofing)
    /// </summary>
    /// <example>GitHub Personal Access Token - Production</example>
    public string Title { get; init; } = string.Empty;

    /// <summary>
    /// Optional description/notes about the secret.
    /// 
    /// VALIDATION RULES:
    /// - Optional
    /// - MaxLength(1000)
    /// - No script tags (XSS prevention)
    /// 
    /// SECURITY:
    /// - HTML sanitized (allow basic markdown-safe formatting)
    /// - No embedded images (prevent SSRF)
    /// - No external links (prevent phishing)
    /// </summary>
    /// <example>Token for CI/CD pipeline. Expires: 2025-12-31. Contact: devops@company.com</example>
    public string? Description { get; init; }

    /// <summary>
    /// ⚠️ PLAINTEXT SECRET VALUE - HANDLE WITH EXTREME CARE!
    /// 
    /// SECURITY CRITICAL FIELD:
    /// - Contains unencrypted sensitive data (password, API key, etc.)
    /// - Must be encrypted with AES-256-GCM immediately upon receipt
    /// - Must NEVER be logged (use [SensitiveData] attribute in logging framework)
    /// - Must NEVER be cached on client-side
    /// - Must be transmitted ONLY over HTTPS (TLS 1.3+)
    /// 
    /// VALIDATION RULES:
    /// - Required
    /// - MinLength(1) - prevent empty secrets
    /// - MaxLength(10000) - prevent memory DoS (10KB limit)
    /// - No leading/trailing whitespace (auto-trimmed)
    /// 
    /// ENCRYPTION PROCESS:
    /// 1. Validate input length and format
    /// 2. Generate random 256-bit encryption key (per-user master key)
    /// 3. Generate random 96-bit IV (nonce)
    /// 4. Encrypt: AES-256-GCM(Plaintext, Key, IV)
    /// 5. Output: Base64(IV + Ciphertext + AuthTag)
    /// 6. Clear RawValue from memory (overwrite with zeros)
    /// 7. Store only encrypted value in database
    /// 
    /// POST-ENCRYPTION:
    /// - Original RawValue is overwritten in memory
    /// - Garbage collector cannot recover plaintext
    /// - Memory forensics cannot recover plaintext
    /// </summary>
    /// <example>sk-proj-abc123XYZ...sensitive_data...789</example>
    /// <remarks>
    /// 🚨 LOGGING POLICY:
    /// If this value appears in ANY log file, it's a CRITICAL security incident.
    /// Use structured logging with [SensitiveData] attribute:
    /// 
    /// ❌ WRONG: _logger.LogInfo($"Creating secret: {dto.RawValue}");
    /// ✅ RIGHT: _logger.LogInfo("Creating secret for user {UserId}", userId);
    /// </remarks>
    public string RawValue { get; init; } = string.Empty;

    /// <summary>
    /// Optional category/tag for secret organization.
    /// 
    /// PREDEFINED CATEGORIES (Recommended):
    /// - "API Keys"
    /// - "Passwords"
    /// - "Database Credentials"
    /// - "SSH Keys"
    /// - "SSL Certificates"
    /// - "Credit Cards" (requires PCI-DSS compliance)
    /// - "OAuth Tokens"
    /// - "2FA Backup Codes"
    /// 
    /// VALIDATION:
    /// - Optional
    /// - MaxLength(50)
    /// - Alphanumeric + spaces
    /// </summary>
    /// <example>API Keys</example>
    public string? Category { get; init; }

    /// <summary>
    /// Optional expiration date/time (UTC).
    /// 
    /// SECURITY BEST PRACTICES:
    /// - Set expiration for all secrets (defense in depth)
    /// - Recommended rotation periods:
    ///   * API Keys: 90 days
    ///   * Passwords: 180 days
    ///   * SSL Certs: 365 days
    ///   * OAuth Tokens: Follow provider's guidelines
    /// 
    /// COMPLIANCE:
    /// - PCI-DSS requires 90-day rotation for privileged accounts
    /// - NIST recommends rotation on breach suspicion
    /// 
    /// WORKFLOW:
    /// - System sends email notification 7 days before expiration
    /// - Expired secrets are flagged in UI (not auto-deleted)
    /// - Admin dashboard shows upcoming expirations
    /// </summary>
    /// <example>2025-12-31T23:59:59Z</example>
    public DateTime? ExpiresAt { get; init; }
}