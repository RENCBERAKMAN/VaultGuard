using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging; 
using Microsoft.AspNetCore.Mvc;
using System;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using VaultGuard.Application.DTOs.Users;
using VaultGuard.Application.Interfaces;
using VaultGuard.Domain.Common.Results;
using VaultGuard.WebAPI.Common;
using IResult = VaultGuard.Domain.Common.Results.IResult;

namespace VaultGuard.WebAPI.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class UsersController : BaseController
{
    // Mockları tanımla
    private readonly IUserService _userService;
    private readonly ILogger<UsersController> _logger;

    public UsersController(IUserService userService, ILogger<UsersController> logger)
    {
        _userService = userService;
        _logger = logger;
    }

    // ============================================================================
    // 👤 PROFIL İŞLEMLERİ (GET ME)
    // ============================================================================

    /// <summary>
    /// Mevcut kullanıcının profil bilgilerini getirir.
    /// Hem entegrasyon testlerini karşılar hem de servis katmanıyla tam uyumludur.
    /// </summary>
    [HttpGet("me")]
    public async Task<IActionResult> GetMe(CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            if (string.IsNullOrWhiteSpace(userId))
                return Unauthorized(new ErrorResult("Yetkilendirme hatası."));

            // DEĞİŞİKLİK: 'userId' artık Guid.Parse edilerek gönderiliyor.
            var result = await _userService.GetUserProfileAsync(Guid.Parse(userId), cancellationToken);

            if (!result.Success)
            {
                _logger.LogWarning($"GetMe: Kullanıcı bulunamadı - {userId}");
                return NotFound(result);
            }

            return ToResponse(result);
        }
        catch (Exception ex)
        {
            _logger.LogError($"GetMe işleminde hata: {ex.Message}");
            return StatusCode(500, new ErrorResult("Profil bilgileri alınırken sistem hatası oluştu."));
        }
    }

    // ============================================================================
    // 🔐 GÜVENLİK İŞLEMLERİ (PASSWORD & LOGOUT)
    // ============================================================================

    /// <summary>
    /// NIST standartlarına uygun şekilde şifre değiştirme işlemini yönetir.
    /// </summary>
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            // 1. Kullanıcı ID'sini güvenli bir şekilde alıyoruz
            var userId = GetCurrentUserId();
            if (string.IsNullOrWhiteSpace(userId))
                return Unauthorized(new ErrorResult("Yetkilendirme hatası."));

            // 2. Web katmanındaki modeli (request), Application katmanındaki DTO'ya mapliyoruz.
            // DİKKAT: Sadece bir kez tanımlıyoruz ve 'CurrentPassword' ismini kullanıyoruz.
            var changePasswordDto = new ChangePasswordDto
            {
                CurrentPassword = request.OldPassword, // Modeldeki 'Old', DTO'daki 'Current'a gider.
                NewPassword = request.NewPassword,
                ConfirmNewPassword = request.NewPassword // Eğer request'te confirm yoksa yeniyi iki kez set et
            };

            // 3. Servis katmanına ID'yi Guid olarak gönderiyoruz
            var result = await _userService.ChangePasswordAsync(Guid.Parse(userId), changePasswordDto, cancellationToken);

            // 4. Standart Result Pattern yanıtını dönüyoruz
            return ToResponse(result);
        }
        catch (Exception ex)
        {
            _logger.LogError($"ChangePassword işleminde kritik hata: {ex.Message}");
            return StatusCode(500, new ErrorResult("Şifre güncellenirken sistem hatası oluştu."));
        }
    }

    /// <summary>
    /// Güvenlik Damgasını (SecurityStamp) yenileyerek tüm aktif oturumları anında sonlandırır.
    /// </summary>
    [HttpPost("logout-all")]
    public async Task<IActionResult> LogoutAllDevices(CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            if (string.IsNullOrWhiteSpace(userId)) return Unauthorized();

            // Hem token revoke işlemi hem de domain seviyesinde stamp güncellemesi tetiklenir
            var result = await _userService.LogoutAllDevicesAsync(Guid.Parse(userId), cancellationToken);

            return ToResponse(result);
        }
        catch (Exception ex)
        {
            _logger.LogError($"LogoutAllDevices hatası: {ex.Message}");
            return StatusCode(500, new ErrorResult("Oturumlar kapatılırken bir hata oluştu."));
        }
    }

    // ============================================================================
    // 📝 GÜNCELLEME İŞLEMLERİ (UPDATE PROFILE)
    // ============================================================================

    /// <summary>
    /// Kullanıcı profil verilerini DTO üzerinden güvenli şekilde günceller.
    /// </summary>
    [HttpPut("profile")]
    public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = GetCurrentUserId();
            if (string.IsNullOrWhiteSpace(userId)) return Unauthorized();
            if (request == null) return BadRequest(new ErrorResult("Veri boş olamaz."));

            var userIdGuid = Guid.Parse(userId);

            var updateUserDto = new UpdateUserDto
            {
                Id = userIdGuid, // DTO içinde de kalsın (opsiyonel ama tutarlılık iyidir)
                FirstName = request.FirstName,
                LastName = request.LastName,
                PhoneNumber = request.PhoneNumber
            };

            // DEĞİŞİKLİK: Servis artık (ID, DTO, Token) bekliyor.
            var result = await _userService.UpdateAsync(userIdGuid, updateUserDto, cancellationToken);

            return ToResponse(result);
        }
        catch (Exception ex)
        {
            _logger.LogError($"UpdateProfile hatası: {ex.Message}");
            return StatusCode(500, new ErrorResult("Profil güncellenirken beklenmedik bir hata oluştu."));
        }
    }
    // ============================================================================
    // REQUEST MODELS (İsim karmaşasını önlemek için buraya ekliyoruz)
    // ============================================================================

    public record ChangePasswordRequest
    {
        public string OldPassword { get; init; } = string.Empty;
        public string NewPassword { get; init; } = string.Empty;
    }

    public record UpdateProfileRequest
    {
        public string? FirstName { get; init; }
        public string? LastName { get; init; }
        public string? PhoneNumber { get; init; }
    }
}