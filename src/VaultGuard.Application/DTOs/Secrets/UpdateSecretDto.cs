using System;

namespace VaultGuard.Application.DTOs.Secrets;

/// <summary>
/// Request DTO for updating an existing secret.
/// Supports partial updates (null values = no change).
/// </summary>
public record UpdateSecretDto
{
    /// <summary>
    /// Secret ID to update (required).
    /// </summary>
    public Guid Id { get; init; }

    /// <summary>
    /// New title (optional). Null = no change.
    /// </summary>
    public string? Title { get; init; }

    /// <summary>
    /// New description (optional). Null = no change.
    /// </summary>
    public string? Description { get; init; }

    /// <summary>
    /// ⚠️ NEW PLAINTEXT SECRET VALUE (optional).
    /// 
    /// SECURITY CRITICAL:
    /// - Contains unencrypted sensitive data
    /// - NEVER log this value
    /// - Transmitted ONLY over HTTPS
    /// - Re-encrypted with NEW IV on backend
    /// 
    /// NULL: Keep existing encrypted value (no re-encryption)
    /// </summary>
    public string? NewRawValue { get; init; }

    /// <summary>
    /// New category (optional). Null = no change.
    /// </summary>
    public string? Category { get; init; }

    /// <summary>
    /// New expiration date (optional). Null = no change.
    /// </summary>
    public DateTime? ExpiresAt { get; init; }
}