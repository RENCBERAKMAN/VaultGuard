using System;

namespace VaultGuard.Application.DTOs.Secrets;

/// <summary>
/// Response DTO for Secret entity. Represents an encrypted secret stored in VaultGuard.
/// 
/// SECURITY CONSIDERATIONS:
/// - This DTO NEVER contains plaintext secret values by default
/// - EncryptedValue is Base64-encoded AES-256 ciphertext (safe for transmission)
/// - Decryption happens on-demand via separate secure endpoint
/// - All access is audited (who, when, from which IP)
/// 
/// USAGE:
/// - Returned from GET /api/secrets (list all secrets)
/// - Returned from GET /api/secrets/{id} (get single secret metadata)
/// - Returned from POST /api/secrets (after creation)
/// 
/// IMMUTABILITY:
/// - Uses 'record' for value semantics and structural equality
/// - Properties are 'init' only (cannot be modified after construction)
/// 
/// AUDIT TRAIL:
/// - Every access to DecryptedValue should trigger audit log entry
/// - LastAccessedAt updates on each decryption operation
/// 
/// COMPLIANCE:
/// - GDPR compliant (user can request deletion)
/// - SOC 2 Type II audit trail support
/// - Zero Trust architecture (never trust, always verify)
/// </summary>
/// <remarks>
/// ⚠️ CRITICAL SECURITY NOTE:
/// If you need plaintext value, call separate endpoint: 
/// POST /api/secrets/{id}/decrypt with explicit audit logging.
/// NEVER add plaintext property to this DTO!
/// </remarks>
public record SecretDto
{
    /// <summary>
    /// Unique identifier for the secret (UUID v4).
    /// </summary>
    /// <example>3fa85f64-5717-4562-b3fc-2c963f66afa6</example>
    public Guid Id { get; init; }

    /// <summary>
    /// User-friendly title/name for the secret.
    /// 
    /// VALIDATION:
    /// - Required
    /// - MinLength(3)
    /// - MaxLength(200)
    /// - No HTML/Script injection (sanitized)
    /// </summary>
    /// <example>AWS Production API Key</example>
    public string Title { get; init; } = string.Empty;

    /// <summary>
    /// Optional description/notes about the secret.
    /// 
    /// VALIDATION:
    /// - Optional
    /// - MaxLength(1000)
    /// - No HTML/Script injection (sanitized)
    /// </summary>
    /// <example>API key for production S3 bucket access. Rotated every 90 days.</example>
    public string? Description { get; init; }

    /// <summary>
    /// Category/tag for secret classification.
    /// 
    /// EXAMPLES:
    /// - "API Keys"
    /// - "Database Credentials"
    /// - "SSH Keys"
    /// - "Credit Cards"
    /// </summary>
    /// <example>API Keys</example>
    public string? Category { get; init; }

    /// <summary>
    /// Base64-encoded AES-256 encrypted value (ciphertext).
    /// 
    /// ⚠️ SECURITY:
    /// - This is ENCRYPTED data (safe to transmit over HTTPS)
    /// - Format: Base64(IV + Ciphertext + Auth Tag)
    /// - Algorithm: AES-256-GCM (Galois/Counter Mode)
    /// - Key derivation: PBKDF2 with 100,000 iterations
    /// 
    /// IMPORTANT:
    /// - NEVER log this value (even though encrypted)
    /// - NEVER cache this value on client-side
    /// - Only decrypt on secure backend with audit trail
    /// </summary>
    /// <remarks>
    /// This field is optional in responses. Some endpoints may exclude it
    /// to reduce payload size when only metadata is needed.
    /// </remarks>
    public string? EncryptedValue { get; init; }

    /// <summary>
    /// Indicates if this secret has an expiration date.
    /// </summary>
    public bool HasExpiration { get; init; }

    /// <summary>
    /// Expiration date/time (UTC). After this, secret is considered expired.
    /// 
    /// SECURITY:
    /// - Expired secrets should be auto-rotated or flagged
    /// - Recommended: Alert user 7 days before expiration
    /// </summary>
    public DateTime? ExpiresAt { get; init; }

    /// <summary>
    /// Indicates if this secret is currently expired.
    /// Computed property based on ExpiresAt and current UTC time.
    /// </summary>
    public bool IsExpired => ExpiresAt.HasValue && ExpiresAt.Value < DateTime.UtcNow;

    /// <summary>
    /// Owner user ID (foreign key).
    /// 
    /// AUTHORIZATION:
    /// - Only owner can decrypt secret
    /// - Only owner can update/delete secret
    /// - Admin can view metadata (not decrypt)
    /// </summary>
    public Guid UserId { get; init; }

    /// <summary>
    /// Timestamp when secret was created (UTC).
    /// Immutable after creation.
    /// </summary>
    public DateTime CreatedAt { get; init; }

    /// <summary>
    /// Timestamp when secret was last accessed/decrypted (UTC).
    /// 
    /// AUDIT TRAIL:
    /// - Updates on every decryption operation
    /// - Used for security monitoring (detect unusual access patterns)
    /// - Compliance reporting (who accessed what, when)
    /// </summary>
    public DateTime? LastAccessedAt { get; init; }

    /// <summary>
    /// Total number of times this secret has been accessed/decrypted.
    /// 
    /// SECURITY MONITORING:
    /// - High access count may indicate compromise
    /// - Unusual spike should trigger alert
    /// </summary>
    public int AccessCount { get; init; }
}