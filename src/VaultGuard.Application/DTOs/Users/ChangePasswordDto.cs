namespace VaultGuard.Application.DTOs.Users;

/// <summary>
/// Þifre deðiþtirme request DTO'su.
/// 
/// GÜVENLÝK KURALLARI:
/// - Current password doðrulamasý zorunlu
/// - New password complexity validation
/// - New password != current password
/// - Password history check (son 5 þifre)
/// 
/// ÝÞ AKIÞI:
/// 1. Current password verify (BCrypt.Verify)
/// 2. New password validation (strength check)
/// 3. New password hashing (BCrypt.Hash)
/// 4. Database update
/// 5. Session invalidation (tüm aktif session'larý sonlandýr)
/// 6. Email notification (security alert)
/// 
/// KULLANIM:
/// POST /api/users/{id}/change-password
/// PUT /api/account/password
/// </summary>
public record ChangePasswordDto
{
    /// <summary>
    /// Mevcut þifre (required).
    /// 
    /// GÜVENLÝK:
    /// - Güvenlik katmaný olarak gerekli
    /// - Admin bile current password vermeli (best practice)
    /// - HTTPS üzerinden gelmeli
    /// - Asla loglanmamalý!
    /// 
    /// VALIDATION:
    /// - Required
    /// - Service layer'da BCrypt.Verify ile doðrulanýr
    /// </summary>
    public string CurrentPassword { get; init; } = string.Empty;

    /// <summary>
    /// Yeni þifre (required).
    /// 
    /// GÜVENLÝK:
    /// - HTTPS üzerinden gelmeli
    /// - Asla loglanmamalý!
    /// - Hash'lenip saklanacak
    /// 
    /// VALIDATION:
    /// - Required
    /// - MinLength(8)
    /// - Complexity (büyük/küçük harf, rakam, özel karakter)
    /// - != CurrentPassword
    /// - Not in password history (son 5 þifre)
    /// - Not common password (blacklist check)
    /// </summary>
    public string NewPassword { get; init; } = string.Empty;

    /// <summary>
    /// Yeni þifre tekrarý (required).
    /// 
    /// VALIDATION:
    /// - Required
    /// - Must match NewPassword
    /// 
    /// UX:
    /// Frontend'de client-side validation yapýlmalý.
    /// Backend'de de double-check yapýlýr.
    /// </summary>
    public string ConfirmNewPassword { get; init; } = string.Empty;
}