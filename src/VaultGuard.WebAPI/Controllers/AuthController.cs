using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;
// IResult çakýþmasýný önlemek için Alias (Takma ad) mühürlüyoruz
using IResult = VaultGuard.Domain.Common.Results.IResult;
using VaultGuard.Domain.Common.Results;
using VaultGuard.Application.Interfaces;
using VaultGuard.Application.DTOs.Auth;
using VaultGuard.WebAPI.Common;


namespace VaultGuard.WebAPI.Controllers;

/// <summary>
/// Kimlik doðrulama (Auth) iþlemlerini yöneten profesyonel kontrolcü.
/// GÜVENLÝK: Anti-Enumeration ve Siber Güvenlik standartlarýna uygundur.
/// </summary>
public class AuthController : BaseController
{
    private readonly IAuthService _authService;
    private readonly ILogger<AuthController> _logger;

    // GÜVENLÝK: Brute-force korumasý için ErrorResult (Soyut olmayan somut sýnýf) kullanýyoruz
    private static readonly ErrorResult BruteForceProtectionResponse = new("Çok fazla baþarýsýz deneme yapýldý. Güvenliðiniz için iþlem kýsýtlandý.");

    public AuthController(IAuthService authService, ILogger<AuthController> logger)
    {
        _authService = authService ?? throw new ArgumentNullException(nameof(authService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto, CancellationToken cancellationToken = default)
    {
        try
        {
            if (dto == null)
                return ToResponse(new ErrorResult("Geçersiz istek formatý."));

            // DTO Dönüþümü: Servis katmanýnýn beklediði mühürlü paket
            var result = await _authService.RegisterAsync(dto, cancellationToken);


            if (!result.Success)
            {
                _logger.LogWarning("Kayýt denemesi baþarýsýz: {Email}", dto.Email);
                // SÝBER GÜVENLÝK: Hata ne olursa olsun dýþarýya 'Kayýt tamamlanamadý' mesajý verilir (Anti-Enumeration)
                return ToResponse(new ErrorResult("Kayýt iþlemi þu anda tamamlanamýyor."));
            }

            return ToResponse(new SuccessResult("Kayýt baþarýlý. Kasanýza giriþ yapabilirsiniz."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Register iþleminde kritik hata!");
            return StatusCode(500, new ErrorResult("Sistemde bir hata oluþtu."));
        }
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto, CancellationToken cancellationToken = default)
    {
        try
        {
            if (dto == null)
                return ToResponse(new ErrorResult("Geçersiz giriþ denemesi."));

            var result = await _authService.LoginAsync(dto, cancellationToken);


 

            if (!result.Success)
            {
                _logger.LogWarning("Baþarýsýz login denemesi: {Email}", dto.Email);

                // Brute-force kontrolü
                if (result.Message?.Contains("çok fazla") ?? false)
                    return StatusCode(429, BruteForceProtectionResponse);

                return ToResponse(new ErrorResult("E-posta veya þifre hatalý."));
            }

            return ToResponse(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login iþleminde kritik hata!");
            return StatusCode(500, new ErrorResult("Giriþ yapýlamadý."));
        }
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto dto, CancellationToken cancellationToken = default)
    {
        // Eski "request == null" kontrolünü "dto == null" olarak güncelle
        if (dto == null || string.IsNullOrWhiteSpace(dto.RefreshToken))
            return ToResponse(new ErrorResult("Geçersiz token isteði."));

        // Servis katmanýna dto içindeki token'ý gönderiyoruz
        var result = await _authService.RefreshTokenAsync(dto.RefreshToken, cancellationToken);

        if (!result.Success)
            return StatusCode(401, new ErrorResult("Oturum süresi dolmuþ."));

        return ToResponse(result);
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken cancellationToken = default)
    {
        var userId = GetCurrentUserId();
        if (string.IsNullOrEmpty(userId))
            return Unauthorized();

        // NOT: IAuthService içinde LogoutAsync metodun yoksa IUserService'e de taþýyabiliriz.
        // Eðer metod ismi farklýysa burayý güncellemelisin.
        // Not: User ID'sini Guid'e çevirerek gönderiyoruz.
        var result = await _authService.RevokeAllTokensAsync(Guid.Parse(userId), cancellationToken);

        return ToResponse(result);
    }
}