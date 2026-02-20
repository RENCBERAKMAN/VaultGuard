using System;
using BCrypt.Net;
using VaultGuard.Application.Interfaces;

namespace VaultGuard.Infrastructure.Security;

/// <summary>
/// VaultGuard Enterprise-Grade Password Security Service.
/// 
/// SÝBER GÜVENLÝK PRENSÝPLERÝ:
/// - Salt (Tuzlama): Her þifre için otomatik ve benzersiz salt üretilir.
/// - Adaptive Hashing: Donaným güçlendikçe 'Work Factor' artýrýlabilir.
/// - Anti-Timing Attack: Karþýlaþtýrma iþlemi sabit süreli koruma saðlar.
/// </summary>
public sealed class BCryptPasswordHasher : IPasswordHasher
{
    /// <summary>
    /// Work Factor (Cost): Algoritmanýn kaç kez döneceðini belirler.
    /// 11 deðeri, günümüz donanýmlarý için siber güvenlik ve performans dengesidir (Sweet Spot).
    /// </summary>
    private const int WorkFactor = 11;

    /// <summary>
    /// Þifreyi siber güvenlik standartlarýnda hash'ler.
    /// </summary>
    /// <param name="password">Plain-text þifre</param>
    /// <returns>Hashlenmiþ ve tuzlanmýþ string</returns>
    /// <exception cref="ArgumentNullException">Þifre boþ ise fýrlatýlýr</exception>
    public string HashPassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentNullException(nameof(password), "Þifre mühürlenmek için boþ býrakýlamaz.");

        // SÝBER GÜVENLÝK: BCrypt algoritmasý her seferinde farklý bir salt üretir.
        // EnhancedEntropy: True seçeneði ile modern sistemlerde daha güçlü bir entropy saðlanýr.
        return BCrypt.Net.BCrypt.EnhancedHashPassword(password, WorkFactor);
    }

    /// <summary>
    /// Girilen þifreyi veritabanýndaki hash ile doðrular.
    /// </summary>
    /// <param name="password">Kullanýcýnýn giriþ yaptýðý düz metin þifre</param>
    /// <param name="hashedPassword">Veritabanýndaki mühürlü hash</param>
    /// <returns>Doðrulama baþarýlý ise true</returns>
    public bool VerifyPassword(string password, string hashedPassword)
    {
        if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(hashedPassword))
            return false;

        try
        {
            // SÝBER GÜVENLÝK: Side-channel saldýrýlarýný önlemek için güvenli karþýlaþtýrma yapar.
            return BCrypt.Net.BCrypt.EnhancedVerify(password, hashedPassword);
        }
        catch (Exception)
        {
            // HATA YÖNETÝMÝ: Geçersiz hash formatý gelirse sýzýntý vermemek için false dönülür.
            return false;
        }
    }
}