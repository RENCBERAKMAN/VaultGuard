namespace VaultGuard.Application.DTOs.Auth;

/// <summary>
/// Self-registration (kayıt) request DTO'su.
/// 
/// CreateUserDto İLE FARKI:
/// - CreateUserDto: Admin kullanıcı oluşturur (role atayabilir)
/// - RegisterDto: Kullanıcı kendi kaydını yapar (role atanamaz, default "User")
/// 
/// GÜVENLİK:
/// - CAPTCHA/reCAPTCHA zorunlu (bot prevention)
/// - Email verification workflow (önerilir)
/// - Rate limiting (max 5 registration / hour per IP)
/// - Disposable email filtering (temp-mail.org gibi)
/// 
/// İŞ AKIŞI:
/// 1. CAPTCHA validation
/// 2. Input validation (email format, password strength)
/// 3. Uniqueness check (email, username)
/// 4. Password hashing
/// 5. User creation (Role = "User" fixed)
/// 6. Email verification gönder
/// 7. Welcome email gönder (background job)
/// 8. Audit log yaz
/// 
/// KULLANIM:
/// POST /api/auth/register
/// </summary>
public record RegisterDto
{
    /// <summary>
    /// E-posta adresi (required, unique).
    /// 
    /// VALIDATION:
    /// - Required
    /// - EmailAddress format
    /// - MaxLength(256)
    /// - Unique
    /// - Not disposable email (optional check)
    /// 
    /// EMAIL VERIFICATION:
    /// Kayıt sonrası verification email gönderilir.
    /// Kullanıcı verify etmeden login yapamaz (önerilir).
    /// </summary>
    public string Email { get; init; } = string.Empty;

    /// <summary>
    /// Kullanıcı adı (required, unique).
    /// 
    /// VALIDATION:
    /// - Required
    /// - MinLength(3)
    /// - MaxLength(50)
    /// - Alfanumerik + underscore
    /// - Unique
    /// - Reserved words check (admin, root, system, etc.)
    /// </summary>
    public string Username { get; init; } = string.Empty;

    /// <summary>
    /// Şifre (plain-text, required).
    /// 
    /// ⚠️ GÜVENLİK:
    /// - HTTPS üzerinden gelmeli
    /// - Asla loglanmamalı
    /// - Hash'lenip saklanacak
    /// 
    /// VALIDATION:
    /// - Required
    /// - MinLength(8)
    /// - Complexity check
    /// - Common password blacklist
    /// </summary>
    public string Password { get; init; } = string.Empty;

    /// <summary>
    /// Şifre tekrarı (required).
    /// 
    /// VALIDATION:
    /// - Required
    /// - Must match Password
    /// </summary>
    public string ConfirmPassword { get; init; } = string.Empty;

    /// <summary>
    /// reCAPTCHA token (required).
    /// 
    /// BOT PREVENTION:
    /// Google reCAPTCHA v3 kullanılmalı.
    /// Token backend'de verify edilir.
    /// Score < 0.5 ise kayıt reddedilir.
    /// </summary>
    public string? RecaptchaToken { get; init; }

    // ❌ Role bu DTO'da olmamalı → Default "User" fixed
    // ❌ Self-registration'da role seçimi security risk
}