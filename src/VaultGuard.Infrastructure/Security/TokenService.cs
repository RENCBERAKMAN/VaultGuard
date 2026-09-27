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
/// S�BER G�VENL�K PRENS�PLER�:
/// - Cryptographic Strength: HMAC-SHA512 kullan�larak imza g�venli�i sa�lan�r.
/// - Principle of Least Privilege: Sadece yetkilendirme i�in gerekli minimum claim'ler eklenir.
/// - Configuration Security: Hassas anahtarlar do�rudan kodda de�il, IConfiguration �zerinden y�netilir.
/// </summary>
public sealed class TokenService : ITokenService
{
    private readonly IConfiguration _configuration;
    private readonly SymmetricSecurityKey _key;

    public TokenService(IConfiguration configuration)
    {
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));

        // S�BER G�VENL�K: Secret Key'in varl��� ve uzunlu�u kontrol edilir. 
        // JWT HS512 i�in anahtar en az 64 karakter (512 bit) olmal�d�r.
                var jwtSecret = _configuration["Jwt:SecretKey"] ?? _configuration["Jwt:Secret"];
        if (string.IsNullOrWhiteSpace(jwtSecret) || jwtSecret.Length < 64)
        {
            throw new InvalidOperationException(
                "S�BER G�VENL�K KR�T�K: JWT Secret anahtar� eksik veya �ok k�sa! " +
                "En az 64 karakterlik bir anahtar appsettings.json i�erisinde tan�mlanmal�d�r.");
        }

        _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
    }

    /// <summary>
    /// Kullan�c� i�in 7 g�n ge�erli, y�ksek g�venlikli bir JWT �retir.
    /// </summary>
    /// <param name="user">Token �retilecek Domain User entity'si</param>
    /// <returns>M�h�rlenmi� JWT string</returns>
    public string CreateToken(User user)
    {
        // 1. Claim Set (Kimlik Bilgileri): Hassas olmayan, yetki odakl� bilgiler.
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
            new Claim(ClaimTypes.Role, user.Role) // Rol tabanl� yetkilendirme (RBAC) i�in
        };

        // 2. �mza Haz�rl���: HMAC-SHA512 algoritmas� ile en �st d�zey imza g�venli�i.
        var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);

        // 3. Token Tan�m�: S�re, Al�c� ve G�nderici bilgileri.
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddDays(7), // Token s�resi: 7 g�n (Config'e �ekilebilir)
            SigningCredentials = creds,
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Audience"]
        };

        // 4. �retim ve M�h�rleme
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }
}