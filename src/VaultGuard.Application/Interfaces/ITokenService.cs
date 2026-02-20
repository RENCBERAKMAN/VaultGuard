using VaultGuard.Domain.Entities;

namespace VaultGuard.Application.Interfaces;

/// <summary>
/// VaultGuard Güvenli Kimlik Doðrulama Servisi Sözleþmesi (Interface).
/// Uygulama katmaný (Application), JWT üretim detaylarýný bilmez; sadece bu arayüzü kullanýr.
/// </summary>
public interface ITokenService
{
    /// <summary>
    /// Verilen kullanýcý için kriptografik olarak imzalanmýþ (HMAC-SHA512) bir JWT üretir.
    /// </summary>
    /// <param name="user">Token içerisine (Payload) yetki bilgileri gömülecek kullanýcý varlýðý.</param>
    /// <returns>API isteklerinde 'Authorization: Bearer' baþlýðýnda kullanýlacak Token string'i.</returns>
    string CreateToken(User user);
}