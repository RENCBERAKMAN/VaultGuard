using System;

namespace VaultGuard.Application.DTOs.Users;

/// <summary>
/// API response'larında kullanıcı bilgilerini döndürmek için kullanılan güvenli DTO.
/// GÜVENLİK KRİTİK: PasswordHash ve internal alanlar (IsDeleted vb.) asla burada yer almaz.
/// </summary>
public record UserDto
{
    public Guid Id { get; init; }
    public string Email { get; init; } = string.Empty;
    public string Username { get; init; } = string.Empty;

    // PROFİL İÇİN EKLENEN ALANLAR: Bu alanlar olmadan profil sayfası eksik kalır
    public string FirstName { get; init; } = string.Empty;
    public string LastName { get; init; } = string.Empty;
    public string PhoneNumber { get; init; } = string.Empty;

    public string Role { get; init; } = string.Empty;
    public bool IsActive { get; init; }
    public DateTime CreatedAt { get; init; }
    public DateTime? LastLoginAt { get; init; }
}