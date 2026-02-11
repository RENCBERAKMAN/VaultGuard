using System;

namespace VaultGuard.Application.DTOs.Auth;

/// <summary>
/// JWT authentication token response DTO'su.
/// </summary>
public record TokenDto
{
    /// <summary>
    /// JWT access token.
    /// Authorization: Bearer {AccessToken}
    /// </summary>
    public string AccessToken { get; init; } = string.Empty;

    /// <summary>
    /// Refresh token (optional).
    /// </summary>
    public string? RefreshToken { get; init; }

    /// <summary>
    /// Access token'ın son kullanma tarihi (UTC).
    /// HATA DÜZELTMESİ: İsim 'Expiration' olarak güncellendi.
    /// </summary>
    public DateTime Expiration { get; init; } // Build hatasını çözen satır burası.

    /// <summary>
    /// Token tipi. Standart: "Bearer"
    /// </summary>
    public string TokenType { get; init; } = "Bearer";

    /// <summary>
    /// Token'ın kaç saniye sonra expire olacağı.
    /// </summary>
    public int ExpiresIn { get; init; }
}