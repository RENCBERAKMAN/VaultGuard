namespace VaultGuard.Application.DTOs.Auth;

/// <summary>
/// Login request DTO'su.
/// 
/// GÜVENLİK:
/// - HTTPS üzerinden gelmeli (TLS encryption)
/// - Rate limiting uygulanmalı (max 5 attempt / 15 min)
/// - CAPTCHA 3 failed attempt sonrası
/// - Timing attack prevention (constant-time response)
/// 
/// İŞ AKIŞI:
/// 1. Email ile kullanıcı bul
/// 2. IsActive kontrolü
/// 3. Password verify (BCrypt.Verify)
/// 4. JWT token oluştur
/// 5. LastLoginAt güncelle
/// 6. Audit log yaz (success/failed)
/// 
/// KULLANIM:
/// POST /api/auth/login
/// </summary>
public record LoginDto
{
    /// <summary>
    /// E-posta adresi veya username.
    /// 
    /// FLEXIBILITY:
    /// Email veya username ile login desteklenebilir.
    /// Service layer'da email mi username mi kontrol edilir.
    /// 
    /// VALIDATION:
    /// - Required
    /// - MaxLength(256)
    /// 
    /// GÜVENLİK:
    /// - Case-insensitive (normalize edilir)
    /// - Rate limiting (brute force prevention)
    /// </summary>
    public string Email { get; init; } = string.Empty;

    /// <summary>
    /// Kullanıcı şifresi (plain-text).
    /// 
    /// ⚠️ GÜVENLİK KRİTİK:
    /// - HTTPS üzerinden gelmeli
    /// - ASLA LOGLANMAMALI!
    /// - Memory'de minimum süre tutulmalı
    /// - BCrypt.Verify sonrası hemen temizlenmeli
    /// 
    /// VALIDATION:
    /// - Required
    /// 
    /// BRUTE FORCE PROTECTION:
    /// - Max 5 failed attempt → Account lock (15 min)
    /// - Max 10 attempts from same IP → IP block (1 hour)
    /// - CAPTCHA required after 3 failed attempts
    /// </summary>
    public string Password { get; init; } = string.Empty;

    /// <summary>
    /// "Beni hatırla" (optional).
    /// 
    /// TOKEN LIFETIME:
    /// - RememberMe = true → Token 30 gün geçerli (refresh token)
    /// - RememberMe = false → Token 1 gün geçerli
    /// 
    /// GÜVENLİK:
    /// Uzun ömürlü token'lar risk oluşturur.
    /// Kullanıcıya bu riski bildirmek gerekir.
    /// </summary>
    public bool RememberMe { get; init; } = false;
}