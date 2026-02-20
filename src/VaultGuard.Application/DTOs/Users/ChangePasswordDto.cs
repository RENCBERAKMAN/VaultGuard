namespace VaultGuard.Application.DTOs.Users;

/// <summary>
/// Þifre deðiþtirme iþlemi için kullanýlan veri transfer nesnesi.
/// </summary>
public class ChangePasswordDto
{
    /// <summary>
    /// Kullanýcýnýn þu anki aktif þifresi.
    /// </summary>
    public string CurrentPassword { get; set; } = string.Empty;

    /// <summary>
    /// Belirlenen yeni þifre.
    /// </summary>
    public string NewPassword { get; set; } = string.Empty;

    /// <summary>
    /// Yeni þifrenin doðrulanmasý için tekrar girilen hali.
    /// </summary>
    public string ConfirmNewPassword { get; set; } = string.Empty;
}