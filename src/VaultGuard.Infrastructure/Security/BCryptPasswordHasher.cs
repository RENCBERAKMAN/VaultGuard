using System;
using BCrypt.Net;
using VaultGuard.Application.Interfaces;

namespace VaultGuard.Infrastructure.Security;

/// <summary>
/// VaultGuard Enterprise-Grade Password Security Service.
/// 
/// S�BER G�VENL�K PRENS�PLER�:
/// - Salt (Tuzlama): Her �ifre i�in otomatik ve benzersiz salt �retilir.
/// - Adaptive Hashing: Donan�m g��lendik�e 'Work Factor' art�r�labilir.
/// - Anti-Timing Attack: Kar��la�t�rma i�lemi sabit s�reli koruma sa�lar.
/// </summary>
public sealed class BCryptPasswordHasher : IPasswordHasher
{
    /// <summary>
    /// Work Factor (Cost): Algoritman�n ka� kez d�nece�ini belirler.
    /// 11 de�eri, g�n�m�z donan�mlar� i�in siber g�venlik ve performans dengesidir (Sweet Spot).
    /// </summary>
    private const int WorkFactor = 11;

    /// <summary>
    /// �ifreyi siber g�venlik standartlar�nda hash'ler.
    /// </summary>
    /// <param name="password">Plain-text �ifre</param>
    /// <returns>Hashlenmi� ve tuzlanm�� string</returns>
    /// <exception cref="ArgumentNullException">�ifre bo� ise f�rlat�l�r</exception>
    public string HashPassword(string password)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentNullException(nameof(password), "�ifre m�h�rlenmek i�in bo� b�rak�lamaz.");

        // S�BER G�VENL�K: BCrypt algoritmas� her seferinde farkl� bir salt �retir.
        // EnhancedEntropy: True se�ene�i ile modern sistemlerde daha g��l� bir entropy sa�lan�r.
        return BCrypt.Net.BCrypt.EnhancedHashPassword(password, WorkFactor);
    }

    /// <summary>
    /// Girilen �ifreyi veritaban�ndaki hash ile do�rular.
    /// </summary>
    /// <param name="password">Kullan�c�n�n giri� yapt��� d�z metin �ifre</param>
    /// <param name="hashedPassword">Veritaban�ndaki m�h�rl� hash</param>
    /// <returns>Do�rulama ba�ar�l� ise true</returns>
    public bool VerifyPassword(string password, string hashedPassword)
    {
        if (string.IsNullOrWhiteSpace(password) || string.IsNullOrWhiteSpace(hashedPassword))
            return false;

                try
        {
            // SİBER GÜVENLİK: Side-channel saldırılarını önlemek için güvenli karşılaştırma yapar.
            return BCrypt.Net.BCrypt.EnhancedVerify(password, hashedPassword);
        }
        catch (Exception ex)
        {
            Console.WriteLine("!!! VERIFY PASSWORD EXCEPTION: " + ex.GetType().FullName + " - " + ex.Message);
            Console.WriteLine("!!! STACK TRACE: " + ex.StackTrace);
            return false;
        }
    }
}