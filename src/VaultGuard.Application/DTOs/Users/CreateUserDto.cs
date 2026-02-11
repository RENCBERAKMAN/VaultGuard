namespace VaultGuard.Application.DTOs.Users;

/// <summary>
/// Yeni kullanıcı oluşturma request DTO'su.
/// 
/// VALIDATION KURALLARI:
/// - Email: Required, EmailAddress format, MaxLength(256)
/// - Username: Required, MinLength(3), MaxLength(50), Alfanumerik
/// - Password: Required, MinLength(8), ComplexPassword (büyük/küçük harf, rakam, özel karakter)
/// - Role: Optional, Default("User"), AllowedValues("Admin", "User", "Auditor")
/// 
/// GÜVENLİK:
/// - Password plain-text olarak gelir (HTTPS üzerinden!)
/// - Service layer'da hash'lenecek (BCrypt/Argon2)
/// - Validation controller/middleware seviyesinde yapılmalı
/// 
/// KULLANIM:
/// POST /api/users (Admin creates user)
/// POST /api/auth/register (User self-registration)
/// </summary>
public record CreateUserDto
{
    /// <summary>
    /// E-posta adresi (required, unique).
    /// 
    /// VALIDATION:
    /// - Required
    /// - EmailAddress format
    /// - MaxLength(256)
    /// - Unique (service layer'da kontrol edilir)
    /// </summary>
    public string Email { get; init; } = string.Empty;

    /// <summary>
    /// Kullanıcı adı (required, unique).
    /// 
    /// VALIDATION:
    /// - Required
    /// - MinLength(3)
    /// - MaxLength(50)
    /// - Regex: ^[a-zA-Z0-9_]+$ (alfanumerik + underscore)
    /// - Unique (service layer'da kontrol edilir)
    /// </summary>
    public string Username { get; init; } = string.Empty;

    /// <summary>
    /// Kullanıcı şifresi (plain-text, required).
    /// 
    /// ⚠️ GÜVENLİK UYARISI:
    /// - HTTPS üzerinden gelmeli (TLS encryption)
    /// - Asla loglanmamalı!
    /// - Service layer'da hash'lenecek
    /// 
    /// VALIDATION:
    /// - Required
    /// - MinLength(8) (daha iyi: 12)
    /// - Complexity:
    ///   * En az 1 büyük harf (A-Z)
    ///   * En az 1 küçük harf (a-z)
    ///   * En az 1 rakam (0-9)
    ///   * En az 1 özel karakter (!@#$%^&*)
    /// - Common passwords blacklist (password123, qwerty, etc.)
    /// </summary>
    public string Password { get; init; } = string.Empty;

    /// <summary>
    /// Kullanıcı rolü (optional, default: "User").
    /// 
    /// AUTHORIZATION:
    /// - Sadece Admin kullanıcıları rol atayabilir
    /// - Normal kullanıcılar kayıt olurken Role gönderse bile ignore edilir
    /// - Allowed values: "Admin", "User", "Auditor"
    /// - Default: "User"
    /// </summary>
    public string Role { get; init; } = "User";
}