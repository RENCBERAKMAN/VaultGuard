using System;
using System.Threading;
using System.Threading.Tasks;
using VaultGuard.Application.DTOs.Auth;
using VaultGuard.Domain.Common.Results;

namespace VaultGuard.Application.Interfaces;

/// <summary>
/// Authentication (kimlik doðrulama) iþlemleri için servis soyutlamasý.
/// Login, register ve token yönetimi bu serviste yapýlýr.
/// </summary>
public interface IAuthService
{
    /// <summary>
    /// Kullanýcý giriþi yapar ve JWT token döner.
    /// Brute force korumasý için rate limiting uygulanmalý.
    /// </summary>
    /// <param name="loginDto">Email ve þifre</param>
    /// <param name="cancellationToken">Ýptal token</param>
    /// <returns>JWT token bilgileri</returns>
    Task<IDataResult<TokenDto>> LoginAsync(LoginDto loginDto, CancellationToken cancellationToken = default);

    /// <summary>
    /// Yeni kullanýcý kaydý yapar.
    /// Role otomatik "User" olarak atanýr - admin atanamaz.
    /// </summary>
    /// <param name="registerDto">Kayýt bilgileri</param>
    /// <param name="cancellationToken">Ýptal token</param>
    /// <returns>JWT token bilgileri</returns>
    Task<IDataResult<TokenDto>> RegisterAsync(RegisterDto registerDto, CancellationToken cancellationToken = default);
    Task<IResult> LogoutAsync(string userId, CancellationToken cancellationToken = default);
    /// <summary>
    /// Refresh token ile yeni access token alýr.
    /// Token rotation uygulanmalý - eski token invalidate edilir.
    /// </summary>
    /// <param name="refreshToken">Mevcut refresh token</param>
    /// <param name="cancellationToken">Ýptal token</param>
    /// <returns>Yeni JWT token bilgileri</returns>
    Task<IDataResult<TokenDto>> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Kullanýcýnýn tüm aktif token'larýný invalidate eder.
    /// Logout veya þifre deðiþtirme sonrasý çaðrýlýr.
    /// </summary>
    /// <param name="userId">Kullanýcý ID</param>
    /// <param name="cancellationToken">Ýptal token</param>
    /// <returns>Baþarý durumu</returns>
    Task<IResult> RevokeAllTokensAsync(Guid userId, CancellationToken cancellationToken = default);
}