using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
// IResult çakışmasını önlemek için Alias kullanıyoruz
using IResult = VaultGuard.Domain.Common.Results.IResult;
using VaultGuard.Domain.Common.Results;

namespace VaultGuard.WebAPI.Common;

/// <summary>
/// Tüm API kontrolcülerinin temel sınıfı.
/// RESPONSIBILITIES:
/// - IResult/IDataResult → HTTP Status Code eşleme
/// - Merkezi JWT Claim yönetimi (User ID, Username)
/// - Bilgi sızdırmayan (Secure) hata yanıtları
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public abstract class BaseController : ControllerBase
{
    #region Response Mapping (IResult -> IActionResult)

    protected IActionResult ToResponse(IResult result)
    {
        if (result.Success)
        {
            return Ok(new { success = true, message = result.Message });
        }

        return BadRequest(new { success = false, message = result.Message, errorCode = result.ErrorCode });
    }

    protected IActionResult ToResponse<T>(IDataResult<T> result)
    {
        if (result.Success)
        {
            if (result.Data != null)
            {
                return Ok(new { success = true, message = result.Message, data = result.Data });
            }

            return NotFound(new { success = false, message = result.Message ?? "Kaynak bulunamadı." });
        }

        return BadRequest(new { success = false, message = result.Message, errorCode = result.ErrorCode });
    }

    protected IActionResult ToResponse<T>(IDataResult<T> result, int successStatusCode)
    {
        if (result.Success)
        {
            return StatusCode(successStatusCode, new { success = true, message = result.Message, data = result.Data });
        }

        return BadRequest(new { success = false, message = result.Message, errorCode = result.ErrorCode });
    }

    #endregion

    #region JWT Claim Helpers (Security Focus)

    /// <summary>
    /// JWT token içerisinden güvenli bir şekilde Claim değeri çeker.
    /// </summary>
    protected string? GetClaimValue(string claimType)
    {
        return User?.FindFirst(claimType)?.Value;
    }

    /// <summary>
    /// Mevcut kullanıcının ID'sini (NameIdentifier) döner.
    /// </summary>
    protected string? GetCurrentUserId()
    {
        return GetClaimValue(ClaimTypes.NameIdentifier);
    }

    /// <summary>
    /// Mevcut kullanıcının adını (Name) döner.
    /// </summary>
    protected string? GetCurrentUsername()
    {
        return GetClaimValue(ClaimTypes.Name);
    }

    #endregion

    #region Custom Status Responses

    protected IActionResult Unauthorized(string message = "Kimlik doğrulama başarısız.")
    {
        return base.Unauthorized(new { success = false, message = message, errorCode = "ERR_UNAUTHORIZED" });
    }

    protected IActionResult Forbidden(string message = "Bu işlem için yetkiniz bulunmuyor.")
    {
        return StatusCode(403, new { success = false, message = message, errorCode = "ERR_FORBIDDEN" });
    }

    #endregion
}