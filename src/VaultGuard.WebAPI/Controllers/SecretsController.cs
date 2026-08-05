using System;
using System.Linq;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using VaultGuard.Application.DTOs.Secrets;
using VaultGuard.Application.Interfaces;
using VaultGuard.Domain.Common.Results;
// ✅ DÜZELTME: Models namespace KALDIRILDI (yok)

namespace VaultGuard.WebAPI.Controllers;

/// <summary>
/// REST API controller for secure secret management operations.
/// 
/// SECURITY ARCHITECTURE:
/// - [Authorize]: All endpoints require valid JWT token
/// - Ownership Verification: Service layer enforces IDOR protection
/// - Audit Logging: All decrypt/delete operations logged automatically
/// - Rate Limiting: 100 requests/hour per user (middleware)
/// - Generic Errors: No stack traces or internal details leaked
/// 
/// RESTFUL DESIGN:
/// - GET /api/secrets → List all secrets (current user)
/// - GET /api/secrets/{id} → Get single secret (encrypted)
/// - GET /api/secrets/{id}/decrypt → Decrypt secret (AUDIT LOGGED)
/// - POST /api/secrets → Create new secret (201 Created)
/// - PUT /api/secrets → Update existing secret
/// - DELETE /api/secrets/{id} → Soft delete secret
/// 
/// HTTP STATUS CODES:
/// - 200 OK: Successful GET/PUT/DELETE
/// - 201 Created: Successful POST with Location header
/// - 400 Bad Request: Validation errors, duplicate title, quota exceeded
/// - 401 Unauthorized: Invalid/missing JWT token
/// - 403 Forbidden: User doesn't own secret
/// - 404 Not Found: Secret doesn't exist
/// - 410 Gone: Secret expired (special case for decrypt)
/// - 500 Internal Server Error: Generic error (no details)
/// 
/// COMPLIANCE:
/// - OWASP Top 10: Input validation, auth, error handling
/// - GDPR: Right to erasure (soft delete with recovery)
/// - SOC 2: Audit logging, access controls
/// - PCI-DSS: Encryption at rest and in transit
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
[Produces("application/json")]
public class SecretsController : ControllerBase
{
    private readonly ISecretService _secretService;
    private readonly ICurrentUserService _currentUserService;

    public SecretsController(
        ISecretService secretService,
        ICurrentUserService currentUserService)
    {
        _secretService = secretService ?? throw new ArgumentNullException(nameof(secretService));
        _currentUserService = currentUserService ?? throw new ArgumentNullException(nameof(currentUserService));
    }

    /// <summary>
    /// Retrieves all secrets owned by the current authenticated user.
    /// </summary>
    [HttpGet]
    [ProducesResponseType(typeof(ApiResponse<IEnumerable<SecretDto>>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<ApiResponse<IEnumerable<SecretDto>>>> GetAllSecrets(
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = _currentUserService.UserId;
            if (!userId.HasValue)
            {
                return Unauthorized(new ApiErrorResponse
                {
                    Success = false,
                    Message = "User authentication failed. Please log in again."
                });
            }

            var result = await _secretService.GetSecretsByUserIdAsync(
                userId.Value,
                cancellationToken);

            return HandleDataResult(result);
        }
        catch (OperationCanceledException)
        {
            return StatusCode(408, new ApiErrorResponse
            {
                Success = false,
                Message = "Request timeout. Please try again."
            });
        }
        catch (Exception)
        {
            return StatusCode(500, new ApiErrorResponse
            {
                Success = false,
                Message = "An unexpected error occurred while retrieving secrets."
            });
        }
    }

    /// <summary>
    /// Retrieves a single secret by ID (encrypted value included).
    /// </summary>
    [HttpGet("{id:guid}")]
    [ProducesResponseType(typeof(ApiResponse<SecretDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<ApiResponse<SecretDto>>> GetSecretById(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = _currentUserService.UserId;
            if (!userId.HasValue)
            {
                return Unauthorized(new ApiErrorResponse
                {
                    Success = false,
                    Message = "User authentication failed."
                });
            }

            var result = await _secretService.GetSecretByIdAsync(
                id,
                userId.Value,
                cancellationToken);

            return HandleDataResult(result);
        }
        catch (OperationCanceledException)
        {
            return StatusCode(408, new ApiErrorResponse
            {
                Success = false,
                Message = "Request timeout."
            });
        }
        catch (Exception)
        {
            return StatusCode(500, new ApiErrorResponse
            {
                Success = false,
                Message = "An unexpected error occurred."
            });
        }
    }

    /// <summary>
    /// 🔓 CRITICAL: Decrypts and returns the plaintext value of a secret.
    /// </summary>
    [HttpGet("{id:guid}/decrypt")]
    [ProducesResponseType(typeof(ApiResponse<string>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status410Gone)]
    public async Task<ActionResult<ApiResponse<string>>> DecryptSecret(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = _currentUserService.UserId;
            if (!userId.HasValue)
            {
                return Unauthorized(new ApiErrorResponse
                {
                    Success = false,
                    Message = "User authentication failed."
                });
            }

            var ipAddress = _currentUserService.IpAddress;

            var result = await _secretService.GetDecryptedValueAsync(
                id,
                userId.Value,
                ipAddress,
                cancellationToken);

            if (!result.Success && result.Message.Contains("expired", StringComparison.OrdinalIgnoreCase))
            {
                return StatusCode(410, new ApiErrorResponse
                {
                    Success = false,
                    Message = result.Message
                });
            }

            return HandleDataResult(result);
        }
        catch (OperationCanceledException)
        {
            return StatusCode(408, new ApiErrorResponse
            {
                Success = false,
                Message = "Request timeout."
            });
        }
        catch (Exception)
        {
            return StatusCode(500, new ApiErrorResponse
            {
                Success = false,
                Message = "An unexpected error occurred while decrypting the secret."
            });
        }
    }

    /// <summary>
    /// Creates a new encrypted secret for the current user.
    /// </summary>
    [HttpPost]
    [ProducesResponseType(typeof(ApiResponse<SecretDto>), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<ApiResponse<SecretDto>>> CreateSecret(
        [FromBody] CreateSecretDto dto,
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiErrorResponse
                {
                    Success = false,
                    Message = "Validation failed. Please check your input.",
                    Errors = ModelState.ToDictionary(
                        kvp => kvp.Key,
                        kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>()
                    )
                });
            }

            var userId = _currentUserService.UserId;
            if (!userId.HasValue)
            {
                return Unauthorized(new ApiErrorResponse
                {
                    Success = false,
                    Message = "User authentication failed."
                });
            }

            var ipAddress = _currentUserService.IpAddress;

            var result = await _secretService.CreateSecretAsync(
                dto,
                userId.Value,
                ipAddress,
                cancellationToken);

            if (result.Success && result.Data != null)
            {
                return CreatedAtAction(
                    actionName: nameof(GetSecretById),
                    routeValues: new { id = result.Data.Id },
                    value: new ApiResponse<SecretDto>
                    {
                        Success = true,
                        Message = result.Message,
                        Data = result.Data
                    });
            }

            return BadRequest(new ApiErrorResponse
            {
                Success = false,
                Message = result.Message
            });
        }
        catch (OperationCanceledException)
        {
            return StatusCode(408, new ApiErrorResponse
            {
                Success = false,
                Message = "Request timeout."
            });
        }
        catch (Exception)
        {
            return StatusCode(500, new ApiErrorResponse
            {
                Success = false,
                Message = "An unexpected error occurred while creating the secret."
            });
        }
    }

    /// <summary>
    /// Updates an existing secret (partial update supported).
    /// </summary>
    [HttpPut]
    [ProducesResponseType(typeof(ApiResponse<SecretDto>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<ApiResponse<SecretDto>>> UpdateSecret(
        [FromBody] UpdateSecretDto dto,
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiErrorResponse
                {
                    Success = false,
                    Message = "Validation failed. Please check your input.",
                    Errors = ModelState.ToDictionary(
                        kvp => kvp.Key,
                        kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>()
                    )
                });
            }

            var userId = _currentUserService.UserId;
            if (!userId.HasValue)
            {
                return Unauthorized(new ApiErrorResponse
                {
                    Success = false,
                    Message = "User authentication failed."
                });
            }

            var ipAddress = _currentUserService.IpAddress;

            var result = await _secretService.UpdateSecretAsync(
                dto,
                userId.Value,
                ipAddress,
                cancellationToken);

            return HandleDataResult(result);
        }
        catch (OperationCanceledException)
        {
            return StatusCode(408, new ApiErrorResponse
            {
                Success = false,
                Message = "Request timeout."
            });
        }
        catch (Exception)
        {
            return StatusCode(500, new ApiErrorResponse
            {
                Success = false,
                Message = "An unexpected error occurred while updating the secret."
            });
        }
    }

    /// <summary>
    /// Deletes a secret (soft delete - recoverable within 30 days).
    /// </summary>
    [HttpDelete("{id:guid}")]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status403Forbidden)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<ApiResponse<object>>> DeleteSecret(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userId = _currentUserService.UserId;
            if (!userId.HasValue)
            {
                return Unauthorized(new ApiErrorResponse
                {
                    Success = false,
                    Message = "User authentication failed."
                });
            }

            var ipAddress = _currentUserService.IpAddress;

            var result = await _secretService.DeleteSecretAsync(
                id,
                userId.Value,
                ipAddress,
                cancellationToken);

            return HandleResult(result);
        }
        catch (OperationCanceledException)
        {
            return StatusCode(408, new ApiErrorResponse
            {
                Success = false,
                Message = "Request timeout."
            });
        }
        catch (Exception)
        {
            return StatusCode(500, new ApiErrorResponse
            {
                Success = false,
                Message = "An unexpected error occurred while deleting the secret."
            });
        }
    }

    // ====================================================================
    // HELPER METHODS
    // ====================================================================

    private ActionResult<ApiResponse<T>> HandleDataResult<T>(IDataResult<T> result)
    {
        if (result.Success)
        {
            return Ok(new ApiResponse<T>
            {
                Success = true,
                Message = result.Message,
                Data = result.Data
            });
        }

        var message = result.Message;

        if (message.Contains("not found", StringComparison.OrdinalIgnoreCase))
        {
            return NotFound(new ApiErrorResponse { Success = false, Message = result.Message });
        }

        if (message.Contains("forbidden", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("permission", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("not authorized", StringComparison.OrdinalIgnoreCase))
        {
            return StatusCode(403, new ApiErrorResponse { Success = false, Message = result.Message });
        }

        if (message.Contains("unauthorized", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("not authenticated", StringComparison.OrdinalIgnoreCase))
        {
            return Unauthorized(new ApiErrorResponse { Success = false, Message = result.Message });
        }

        return BadRequest(new ApiErrorResponse { Success = false, Message = result.Message });
    }

    // ✅ DÜZELTME: Tam namespace kullanarak IResult belirsizliğini çözdük!
    private ActionResult<ApiResponse<object>> HandleResult(VaultGuard.Domain.Common.Results.IResult result)
    {
        if (result.Success)
        {
            return Ok(new ApiResponse<object>
            {
                Success = true,
                Message = result.Message,
                Data = null
            });
        }

        var message = result.Message;

        if (message.Contains("not found", StringComparison.OrdinalIgnoreCase))
        {
            return NotFound(new ApiErrorResponse { Success = false, Message = result.Message });
        }

        if (message.Contains("forbidden", StringComparison.OrdinalIgnoreCase) ||
            message.Contains("permission", StringComparison.OrdinalIgnoreCase))
        {
            return StatusCode(403, new ApiErrorResponse { Success = false, Message = result.Message });
        }

        if (message.Contains("unauthorized", StringComparison.OrdinalIgnoreCase))
        {
            return Unauthorized(new ApiErrorResponse { Success = false, Message = result.Message });
        }

        return BadRequest(new ApiErrorResponse { Success = false, Message = result.Message });
    }
}

