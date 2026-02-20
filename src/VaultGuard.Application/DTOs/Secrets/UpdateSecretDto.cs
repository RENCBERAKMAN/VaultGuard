using System;

namespace VaultGuard.Application.DTOs.Secrets;

/// <summary>
/// Request DTO for updating an existing secret in VaultGuard.
/// 
/// SECURITY WORKFLOW:
/// 1. Client sends updated fields (partial update supported)
/// 2. Backend fetches existing secret from database
/// 3. Authorization check: Is current user the owner?
/// 4. If NewRawValue provided:
///    a. Decrypt old value (for audit comparison)
///    b. Encrypt new value with AES-256-GCM
///    c. Update EncryptedValue column
///    d. Audit log: "Secret value changed"
/// 5. Update metadata (Title, Description, ExpiresAt)
/// 6. Audit log entry: who updated, when, from which IP, what changed
/// 
/// VERSIONING STRATEGY:
/// - VaultGuard does NOT keep historical versions by default (GDPR right to erasure)
/// - If versioning needed, enable "Secret History" feature (separate table)
/// - Each version has its own encryption key (forward secrecy)
/// 
/// AUTHORIZATION:
/// - Only secret owner can update
/// - Admin can view metadata (not decrypt or update)
/// - Shared secrets: require explicit permission grant
/// 
/// AUDIT REQUIREMENTS:
/// - Log: Old Title → New Title
/// - Log: Value changed? (Yes/No, not actual values)
/// - Log: ExpiresAt changed? (Old date → New date)
/// - Log: Requester IP address, User-Agent
/// - Log: Operation duration (detect brute-force timing attacks)
/// </summary>
/// <remarks>
/// ⚠️ PARTIAL UPDATE SUPPORT:
/// All properties are optional. Only provided fields will be updated.
/// Example: To change only Title, send { Id: "...", Title: "New Title" }
/// 
/// ⚠️ SECURITY WARNING:
/// If NewRawValue is provided, the old encrypted value is PERMANENTLY replaced.
/// There is NO rollback mechanism (unless versioning feature is enabled).
/// </remarks>
public record UpdateSecretDto
{
    /// <summary>
    /// ID of the secret to update (required).
    /// 
    /// AUTHORIZATION:
    /// - Backend verifies: Does this secret belong to current user?
    /// - If not: Return 403 Forbidden (not 404, to prevent ID enumeration)
    /// 
    /// SECURITY:
    /// - Prevents horizontal privilege escalation
    /// - Prevents IDOR (Insecure Direct Object Reference) vulnerability
    /// </summary>
    /// <example>3fa85f64-5717-4562-b3fc-2c963f66afa6</example>
    public Guid Id { get; init; }

    /// <summary>
    /// New title/name for the secret (optional).
    /// 
    /// VALIDATION RULES:
    /// - Optional (null = no change)
    /// - If provided: MinLength(3), MaxLength(200)
    /// - Uniqueness check: per user
    /// 
    /// SECURITY:
    /// - HTML/Script sanitization
    /// - SQL keyword escaping
    /// </summary>
    /// <example>GitHub PAT - Production (Rotated)</example>
    public string? Title { get; init; }

    /// <summary>
    /// New description/notes (optional).
    /// 
    /// VALIDATION RULES:
    /// - Optional (null = no change)
    /// - If provided: MaxLength(1000)
    /// 
    /// SECURITY:
    /// - HTML sanitization (allow markdown-safe formatting)
    /// </summary>
    /// <example>Rotated on 2025-02-14 due to suspected compromise. New token active.</example>
    public string? Description { get; init; }

    /// <summary>
    /// ⚠️ NEW PLAINTEXT SECRET VALUE - HANDLE WITH EXTREME CARE!
    /// 
    /// CRITICAL SECURITY FIELD:
    /// - Contains unencrypted sensitive data
    /// - Optional (null = keep existing encrypted value unchanged)
    /// - If provided: Triggers re-encryption workflow
    /// 
    /// RE-ENCRYPTION WORKFLOW:
    /// 1. Fetch existing encrypted value from database
    /// 2. Decrypt old value (for audit trail comparison)
    /// 3. Hash old value (SHA-256) and hash new value
    /// 4. Compare hashes: If identical, skip re-encryption (optimization)
    /// 5. If different:
    ///    a. Generate new random IV (nonce)
    ///    b. Encrypt NewRawValue with AES-256-GCM
    ///    c. Overwrite EncryptedValue column
    ///    d. Audit log: "Secret value changed" (NO actual values logged)
    ///    e. Clear NewRawValue from memory
    /// 
    /// VALIDATION RULES:
    /// - Optional (null = no change)
    /// - If provided: MinLength(1), MaxLength(10000)
    /// 
    /// SECURITY WARNING:
    /// - NEVER log this value
    /// - NEVER cache this value
    /// - NEVER include in error messages
    /// - Transmitted ONLY over HTTPS (TLS 1.3+)
    /// </summary>
    /// <example>ghp_NewTokenValueHere123XYZ...sensitive...789</example>
    /// <remarks>
    /// 🚨 AUDIT TRAIL:
    /// When NewRawValue is updated, audit log records:
    /// - Timestamp (UTC)
    /// - User ID
    /// - Secret ID
    /// - Action: "Secret value updated"
    /// - IP Address
    /// - User-Agent
    /// - Old value hash (SHA-256, first 8 chars) - for verification only
    /// - New value hash (SHA-256, first 8 chars)
    /// 
    /// ❌ NEVER log: Actual old or new plaintext values
    /// </remarks>
    public string? NewRawValue { get; init; }

    /// <summary>
    /// New category/tag (optional).
    /// 
    /// VALIDATION:
    /// - Optional (null = no change)
    /// - If provided: MaxLength(50)
    /// </summary>
    /// <example>OAuth Tokens</example>
    public string? Category { get; init; }

    /// <summary>
    /// New expiration date/time (UTC) (optional).
    /// 
    /// VALIDATION:
    /// - Optional (null = no change)
    /// - If provided: Must be future date (> DateTime.UtcNow)
    /// 
    /// SECURITY:
    /// - Extending expiration requires justification (audit trail)
    /// - Removing expiration (set to null) should trigger warning
    /// 
    /// COMPLIANCE:
    /// - PCI-DSS: Cannot exceed 90 days for privileged credentials
    /// </summary>
    /// <example>2026-06-30T23:59:59Z</example>
    public DateTime? ExpiresAt { get; init; }
}