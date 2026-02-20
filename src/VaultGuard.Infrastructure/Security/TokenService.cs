using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using VaultGuard.Application.Interfaces;
using VaultGuard.Domain.Entities;

namespace VaultGuard.Infrastructure.Security;

/// <summary>
/// VaultGuard Enterprise-Grade Authentication Token Service.
/// 
/// SÝBER GÜVENLÝK PRENSÝPLERÝ:
/// - Cryptographic Strength: HMAC-SHA512 kullanýlarak imza güvenliði saðlanýr.
/// - Principle of Least Privilege: Sadece yetkilendirme için gerekli minimum claim'ler eklenir.
/// - Configuration Security: Hassas anahtarlar doðrudan kodda deðil, IConfiguration üzerinden yönetilir.
/// </summary>
public sealed class TokenService : ITokenService
{
    private readonly IConfiguration _configuration;
    private readonly SymmetricSecurityKey _key;

    public TokenService(IConfiguration configuration)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));

        // SÝBER GÜVENLÝK: Secret Key'in varlýðý ve uzunluðu kontrol edilir. 
        // JWT HS512 için anahtar en az 64 karakter (512 bit) olmalýdýr.
        var jwtSecret = _configuration["Jwt:Secret"];
        if (string.IsNullOrWhiteSpace(jwtSecret) || jwtSecret.Length < 64)
        {
            throw new InvalidOperationException(
                "SÝBER GÜVENLÝK KRÝTÝK: JWT Secret anahtarý eksik veya çok kýsa! " +
                "En az 64 karakterlik bir anahtar appsettings.json içerisinde tanýmlanmalýdýr.");
        }

        _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
    }

    /// <summary>
    /// Kullanýcý için 7 gün geçerli, yüksek güvenlikli bir JWT üretir.
    /// </summary>
    /// <param name="user">Token üretilecek Domain User entity'si</param>
    /// <returns>Mühürlenmiþ JWT string</returns>
    public string CreateToken(User user)
    {
        // 1. Claim Set (Kimlik Bilgileri): Hassas olmayan, yetki odaklý bilgiler.
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
            new Claim(ClaimTypes.Role, user.Role) // Rol tabanlý yetkilendirme (RBAC) için
        };

        // 2. Ýmza Hazýrlýðý: HMAC-SHA512 algoritmasý ile en üst düzey imza güvenliði.
        var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);

        // 3. Token Tanýmý: Süre, Alýcý ve Gönderici bilgileri.
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddDays(7), // Token süresi: 7 gün (Config'e çekilebilir)
            SigningCredentials = creds,
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Audience"]
        };

        // 4. Üretim ve Mühürleme
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }
}