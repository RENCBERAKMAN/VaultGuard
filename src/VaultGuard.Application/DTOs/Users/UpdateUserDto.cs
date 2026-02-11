using System;

namespace VaultGuard.Application.DTOs.Users;

/// <summary>
/// Mevcut kullanıcı güncelleme request DTO'su.
/// 
/// GÜNCELLENEBILIR ALANLAR:
/// - Email (uniqueness check gerekli)
/// - Username (uniqueness check gerekli)
/// - Role (sadece Admin yapabilir)
/// 
/// GÜNCELLENEMEYEN ALANLAR:
/// - Id (immutable - URL'den gelir)
/// - Password (ChangePasswordDto kullanılmalı)
/// - CreatedAt (immutable)
/// - IsActive (DeactivateAsync/ActivateAsync kullanılmalı)
/// 
/// AUTHORIZATION:
/// - Kullanıcı sadece kendi bilgilerini güncelleyebilir
/// - Admin tüm kullanıcıları güncelleyebilir
/// - Role değiştirme sadece Admin yapabilir
/// 
/// KULLANIM:
/// PUT /api/users/{id}
/// PATCH /api/users/{id} (partial update için)
/// </summary>
public record UpdateUserDto
{
    /// <summary>
    /// Güncellenecek kullanıcının ID'si.
    /// 
    /// NOT: Bu field genellikle URL'den gelir (route parameter).
    /// DTO'da tutulması opsiyonel - controller'da handle edilebilir.
    /// Ama tutarsak validation için kullanışlı (ID boş mu kontrolü).
    /// </summary>
    public Guid Id { get; init; }

    /// <summary>
    /// Yeni e-posta adresi (optional).
    /// 
    /// VALIDATION:
    /// - EmailAddress format (if provided)
    /// - MaxLength(256)
    /// - Unique (service layer'da kontrol edilir)
    /// 
    /// NULL HANDLING:
    /// - null ise değiştirilmez (mevcut email korunur)
    /// - empty string ise validation hatası
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// Yeni kullanıcı adı (optional).
    /// 
    /// VALIDATION:
    /// - MinLength(3) (if provided)
    /// - MaxLength(50)
    /// - Alfanumerik + underscore
    /// - Unique (service layer'da kontrol edilir)
    /// 
    /// NULL HANDLING:
    /// - null ise değiştirilmez
    /// - empty string ise validation hatası
    /// </summary>
    public string? Username { get; init; }

    /// <summary>
    /// Yeni rol (optional, sadece Admin değiştirebilir).
    /// 
    /// AUTHORIZATION:
    /// - Caller Admin değilse bu field ignore edilir
    /// - Admin ise role değiştirilebilir
    /// 
    /// VALIDATION:
    /// - AllowedValues: "Admin", "User", "Auditor"
    /// 
    /// NULL HANDLING:
    /// - null ise değiştirilmez
    /// </summary>
    public string? Role { get; init; }

    // ❌ Password bu DTO'da olmamalı → ChangePasswordDto kullan
    // ❌ IsActive bu DTO'da olmamalı → DeactivateAsync/ActivateAsync kullan
}