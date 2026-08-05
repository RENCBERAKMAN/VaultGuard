using System;

namespace VaultGuard.Application.DTOs.Secrets;

/// <summary>
/// Response DTO for Secret entity.
/// </summary>
public record SecretDto
{
    public Guid Id { get; init; }
    public string Title { get; init; } = string.Empty;
    public string? Description { get; init; }
    public string? Category { get; init; }
    public string? EncryptedValue { get; init; }
    public bool HasExpiration { get; init; }
    public DateTime? ExpiresAt { get; init; }

    /// <summary>
    /// Computed property - calculated based on ExpiresAt.
    /// </summary>
    public bool IsExpired => ExpiresAt.HasValue && ExpiresAt.Value < DateTime.UtcNow;

    public Guid UserId { get; init; }
    public DateTime CreatedAt { get; init; }

    /// <summary>
    /// ADDED: Last update timestamp.
    /// </summary>
    public DateTime UpdatedAt { get; init; }

    public DateTime? LastAccessedAt { get; init; }
    public int AccessCount { get; init; }
}