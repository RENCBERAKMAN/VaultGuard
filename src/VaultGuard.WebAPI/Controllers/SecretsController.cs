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

namespace VaultGuard.WebAPI.Controllers;

/// <summary>
/// REST API controller for secure secret management operations.
/// 
/// SECURITY:
/// - [Authorize]: All endpoints require valid JWT token
/// - Ownership Verification: Service layer enforces user can only access their own secrets
/// - Audit Logging: All sensitive operations (decrypt, delete) logged automatically
/// - Rate Limiting: 100 requests/hour per user (configured in middleware)
/// 
/// RESTFUL DESIGN:
/// - GET /api/secrets - List all secrets (current user)
/// - GET /api/secrets/{id} - Get single secret (encrypted)
/// - GET /api/secrets/{id}/decrypt - Decrypt secret (audit logged)
/// - POST /api/secrets - Create new secret
/// - PUT /api/secrets - Update existing secret
/// - DELETE /api/secrets/{id} - Delete secret (soft delete)
/// 
/// HTTP STATUS CODES:
/// - 200 OK: Successful GET/PUT/DELETE
/// - 201 Created: Successful POST
/// - 400 Bad Request: Validation errors
/// - 401 Unauthorized: Invalid/missing JWT token
/// - 403 Forbidden: User doesn't own this secret
/// - 404 Not Found: Secret doesn't exist
/// - 500 Internal Server Error: Unexpected errors
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
[Produces("application/json")]
public class SecretsController : ControllerBase
{
    private readonly ISecretService _secretService;
    private readonly ICurrentUserService _currentUserService;

    /// <summary>
    /// Initializes a new instance of SecretsController.
    /// </summary>
    /// <param name="secretService">Service for secret business logic</param>
    /// <param name="currentUserService">Service for current user context</param>
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
    /// <param name="cancellationToken">Cancellation token for request timeout</param>
    /// <returns>List of secrets with encrypted values (no plaintext)</returns>
    /// <response code="200">Returns list of secrets successfully</response>
    /// <response code="401">User is not authenticated</response>
    /// <response code="500">Internal server error occurred</response>
    [HttpGet]
    [ProducesResponseType(typeof(ApiResponse<IEnumerable<SecretDto>>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ApiResponse<IEnumerable<SecretDto>>>> GetAllSecrets(
        CancellationToken cancellationToken = default)
    {
        try
        {
            // SECURITY: Get current user ID from JWT claims
            var userId = _currentUserService.UserId;
            if (!userId.HasValue)
            {
                return Unauthorized(new ApiErrorResponse
                {
                    Success = false,
                    Message = "User authentication failed. Please log in again."
                });
            }

            // FETCH: All secrets for current user
            var result = await _secretService.GetSecretsByUserIdAsync(userId.Value, cancellationToken);

            // RETURN: Result as HTTP response
            return HandleDataResult(result);
        }
        catch (Exception ex)
        {
            // SECURITY: Generic error message (don't leak internal details)
            return StatusCode(500, new ApiErrorResponse
            {
                Success = false,
                Message = "An unexpected error occurred while retrieving secrets. Please try again later."
            });
        }
    }

    /// <summary>
    /// Retrieves a single secret by ID (encrypted value included, NOT decrypted).
    /// </summary>
    /// <param name="id">Secret unique identifier (GUID)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Secret details with encrypted value</returns>
    /// <response code="200">Returns secret details successfully</response>
    /// <response code="401">User is not authenticated</response>
    /// <response code="403">User doesn't have permission to access this secret</response>
    /// <response code="404">Secret not found</response>
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
            // FETCH: Secret by ID (service layer handles authorization)
            var result = await _secretService.GetSecretByIdAsync(id, cancellationToken);

            // RETURN: Result as HTTP response
            return HandleDataResult(result);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new ApiErrorResponse
            {
                Success = false,
                Message = "An unexpected error occurred while retrieving the secret."
            });
        }
    }

    /// <summary>
    /// 🔓 CRITICAL: Decrypts and returns the plaintext value of a secret.
    /// 
    /// ⚠️ SECURITY WARNING:
    /// This operation is AUDITED and LOGGED. Every access to plaintext values is tracked.
    /// Rate limit: 100 decryptions per user per hour.
    /// 
    /// Use cases:
    /// - User needs to copy password to clipboard
    /// - Application needs to retrieve API key for integration
    /// - Administrator performing security audit (with proper authorization)
    /// </summary>
    /// <param name="id">Secret unique identifier</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Plaintext (decrypted) secret value</returns>
    /// <response code="200">Returns decrypted secret value (SENSITIVE DATA!)</response>
    /// <response code="401">User is not authenticated</response>
    /// <response code="403">User doesn't have permission to decrypt this secret</response>
    /// <response code="404">Secret not found</response>
    /// <response code="410">Secret has expired</response>
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
            // DECRYPT: Secret value (service layer handles authorization + audit logging)
            var result = await _secretService.GetDecryptedValueAsync(id, cancellationToken);

            // SPECIAL CASE: Check for expired secret (410 Gone)
            if (!result.Success && result.Message.Contains("expired", StringComparison.OrdinalIgnoreCase))
            {
                return StatusCode(410, new ApiErrorResponse
                {
                    Success = false,
                    Message = result.Message
                });
            }

            // RETURN: Result as HTTP response
            return HandleDataResult(result);
        }
        catch (Exception ex)
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
    /// <param name="dto">Secret creation data (contains PLAINTEXT value)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Created secret with metadata</returns>
    /// <response code="201">Secret created successfully</response>
    /// <response code="400">Validation errors (duplicate title, invalid data, quota exceeded)</response>
    /// <response code="401">User is not authenticated</response>
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
            // VALIDATION: Model state (FluentValidation automatic)
            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiErrorResponse
                {
                    Success = false,
                    Message = "Validation failed. Please check your input data.",
                    Errors = ModelState.ToDictionary(
    kvp => kvp.Key,
    kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>()
)
                });
            }

            // CREATE: New secret (service layer handles encryption + audit logging)
            var result = await _secretService.CreateSecretAsync(dto, cancellationToken);

            // RETURN: 201 Created with Location header
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

            // VALIDATION ERROR: Duplicate title, quota exceeded, etc.
            return BadRequest(new ApiErrorResponse
            {
                Success = false,
                Message = result.Message
            });
        }
        catch (Exception ex)
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
    /// <param name="dto">Update data (only provided fields are updated)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Updated secret with metadata</returns>
    /// <response code="200">Secret updated successfully</response>
    /// <response code="400">Validation errors (invalid data, no changes)</response>
    /// <response code="401">User is not authenticated</response>
    /// <response code="403">User doesn't have permission to update this secret</response>
    /// <response code="404">Secret not found</response>
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
            // VALIDATION: Model state
            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiErrorResponse
                {
                    Success = false,
                    Message = "Validation failed. Please check your input data.",
                    Errors = ModelState.ToDictionary(
    kvp => kvp.Key,
    kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>()
)
                });
            }

            // UPDATE: Secret (service layer handles authorization + re-encryption if needed)
            var result = await _secretService.UpdateSecretAsync(dto, cancellationToken);

            // RETURN: Result as HTTP response
            return HandleDataResult(result);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new ApiErrorResponse
            {
                Success = false,
                Message = "An unexpected error occurred while updating the secret."
            });
        }
    }

    /// <summary>
    /// Deletes a secret (soft delete - can be recovered within 30 days).
    /// </summary>
    /// <param name="id">Secret unique identifier</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Deletion confirmation</returns>
    /// <response code="200">Secret deleted successfully</response>
    /// <response code="401">User is not authenticated</response>
    /// <response code="403">User doesn't have permission to delete this secret</response>
    /// <response code="404">Secret not found</response>
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
            // DELETE: Secret (service layer handles authorization + audit logging)
            var result = await _secretService.DeleteSecretAsync(id, cancellationToken);

            // RETURN: Result as HTTP response
            return HandleResult(result);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new ApiErrorResponse
            {
                Success = false,
                Message = "An unexpected error occurred while deleting the secret."
            });
        }
    }

    // ====================================================================
    // HELPER METHODS: Result Pattern → HTTP Status Codes
    // ====================================================================

    /// <summary>
    /// Converts IDataResult to ActionResult with appropriate HTTP status code.
    /// </summary>
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

        // ERROR MAPPING: Based on error message keywords
        var message = result.Message.ToLower();

        if (message.Contains("not found"))
        {
            return NotFound(new ApiErrorResponse
            {
                Success = false,
                Message = result.Message
            });
        }

        if (message.Contains("forbidden") || message.Contains("permission") || message.Contains("not authorized"))
        {
            return StatusCode(403, new ApiErrorResponse
            {
                Success = false,
                Message = result.Message
            });
        }

        if (message.Contains("unauthorized") || message.Contains("not authenticated"))
        {
            return Unauthorized(new ApiErrorResponse
            {
                Success = false,
                Message = result.Message
            });
        }

        // DEFAULT: Bad Request
        return BadRequest(new ApiErrorResponse
        {
            Success = false,
            Message = result.Message
        });
    }

    /// <summary>
    /// Converts IResult to ActionResult with appropriate HTTP status code.
    /// </summary>
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

        // ERROR MAPPING: Same as HandleDataResult
        var message = result.Message.ToLower();

        if (message.Contains("not found"))
        {
            return NotFound(new ApiErrorResponse
            {
                Success = false,
                Message = result.Message
            });
        }

        if (message.Contains("forbidden") || message.Contains("permission") || message.Contains("not authorized"))
        {
            return StatusCode(403, new ApiErrorResponse
            {
                Success = false,
                Message = result.Message
            });
        }

        if (message.Contains("unauthorized") || message.Contains("not authenticated"))
        {
            return Unauthorized(new ApiErrorResponse
            {
                Success = false,
                Message = result.Message
            });
        }

        return BadRequest(new ApiErrorResponse
        {
            Success = false,
            Message = result.Message
        });
    }
}