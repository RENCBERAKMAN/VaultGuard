using System;

namespace VaultGuard.Application.DTOs.Users;

/// <summary>
/// API response'larında kullanıcı bilgilerini döndürmek için kullanılan DTO.
/// 
/// GÜVENLİK KRİTİK:
/// - PasswordHash ASLA bu DTO'da olmamalı!
/// - Sadece client'a gösterilmesi güvenli olan alanlar var
/// 
/// KULLANIM SENARYOLARI:
/// - GetUserById response
/// - GetAllUsers response
/// - Profile görüntüleme
/// - JWT token payload (user bilgisi)
/// 
/// IMMUTABILITY:
/// Record type kullanıldı → immutable, thread-safe
/// </summary>
public record UserDto
{
    /// <summary>
    /// Kullanıcı benzersiz kimliği.
    /// API response'larında user referansı için kullanılır.
    /// </summary>
    public Guid Id { get; init; }

    /// <summary>
    /// Kullanıcı e-posta adresi.
    /// Normalize edilmiş (lowercase, trimmed).
    /// </summary>
    public string Email { get; init; } = string.Empty;

    /// <summary>
    /// Kullanıcı adı.
    /// Unique, alfanumerik + underscore.
    /// </summary>
    public string Username { get; init; } = string.Empty;

    /// <summary>
    /// Kullanıcı rolü.
    /// Değerler: "Admin", "User", "Auditor"
    /// </summary>
    public string Role { get; init; } = string.Empty;

    /// <summary>
    /// Hesap aktif mi?
    /// false ise kullanıcı login yapamaz.
    /// </summary>
    public bool IsActive { get; init; }

    /// <summary>
    /// Hesap oluşturulma tarihi (UTC).
    /// </summary>
    public DateTime CreatedAt { get; init; }

    /// <summary>
    /// Son giriş tarihi (UTC, nullable).
    /// </summary>
    public DateTime? LastLoginAt { get; init; }

    // ❌ PasswordHash ASLA burada olmamalı!
    // ❌ IsDeleted gibi internal alanlar da olmamalı!
}