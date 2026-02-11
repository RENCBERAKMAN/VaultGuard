namespace VaultGuard.Application.Interfaces;

/// <summary>
/// Þifre hash'leme ve doðrulama için arayüz.
/// 
/// AMACLAR:
/// 1. Application katmanýný spesifik hash algoritmasýndan (BCrypt, Argon2) baðýmsýz kýlar
/// 2. Hash algoritmasý deðiþse bile Application katmaný etkilenmez
/// 3. Test edilebilirlik artýrýr (mock hasher oluþturabilirsiniz)
/// 
/// GÜVENLÝK NOTU:
/// Implementation'da mutlaka güçlü bir hash algoritmasý (BCrypt, Argon2, PBKDF2) kullanýlmalýdýr.
/// Asla MD5, SHA1 veya düz SHA256 kullanmayýn!
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Plain-text þifreyi hash'ler.
    /// 
    /// GÜVENLÝK:
    /// - Her hash benzersiz olmalý (salt kullanýmý zorunlu)
    /// - Hash algoritmasý: BCrypt (önerilen) veya Argon2
    /// - Cost factor: Minimum 12 (BCrypt için)
    /// 
    /// KULLANIM:
    /// - Kayýt (Register) iþlemi
    /// - Þifre deðiþtirme
    /// </summary>
    /// <param name="password">Plain-text þifre</param>
    /// <returns>Hash'lenmiþ þifre (60+ karakter)</returns>
    /// <exception cref="ArgumentException">Þifre boþ veya null ise</exception>
    string HashPassword(string password);

    /// <summary>
    /// Plain-text þifrenin hash ile eþleþip eþleþmediðini kontrol eder.
    /// 
    /// GÜVENLÝK:
    /// - Timing attack'lere karþý constant-time comparison kullanýlmalý
    /// - Baþarýsýz denemeler loglanmalý (brute force tespiti için)
    /// 
    /// KULLANIM:
    /// - Login iþlemi
    /// - Þifre doðrulama
    /// </summary>
    /// <param name="password">Plain-text þifre (kullanýcýdan gelen)</param>
    /// <param name="hashedPassword">Veritabanýndaki hash'lenmiþ þifre</param>
    /// <returns>Eþleþirse true, deðilse false</returns>
    /// <exception cref="ArgumentException">Parametrelerden biri boþ veya null ise</exception>
    bool VerifyPassword(string password, string hashedPassword);
}