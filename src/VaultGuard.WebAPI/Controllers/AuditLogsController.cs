using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using VaultGuard.Application.Interfaces;
using VaultGuard.Domain.Entities;

namespace VaultGuard.WebAPI.Controllers;

/// <summary>
/// REST API controller for viewing audit logs (Admin/Auditor access only).
/// 
/// SECURITY:
/// - [Authorize(Roles = "Admin,Auditor")]: Only Admin and Auditor roles can access
/// - Read-Only: No create/update/delete operations (audit logs are immutable)
/// - Compliance: SOC 2, GDPR, PCI-DSS, HIPAA audit trail requirements
/// 
/// RESTFUL DESIGN:
/// - GET /api/auditlogs/user/{userId} - User's activity history
/// - GET /api/auditlogs/resource/{resourceId} - Resource access history
/// - GET /api/auditlogs/recent - Recent security events (dashboard)
/// 
/// USE CASES:
/// - Security monitoring: Detect suspicious activity patterns
/// - Compliance audits: Prove who accessed what and when
/// - Forensic investigation: Reconstruct timeline of security incidents
/// - User support: Help users track their own activity
/// 
/// PERFORMANCE:
/// - Pagination: Skip/Take parameters for large datasets
/// - Indexing: Database indexes on UserId, ResourceId, Timestamp
/// - Caching: Consider Redis cache for dashboard (5 min TTL)
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin,Auditor")]
[Produces("application/json")]
public class AuditLogsController : ControllerBase
{
    private readonly IAuditLogRepository _auditLogRepository;
    private readonly ICurrentUserService _currentUserService;

    /// <summary>
    /// Initializes a new instance of AuditLogsController.
    /// </summary>
    /// <param name="auditLogRepository">Repository for audit log data access</param>
    /// <param name="currentUserService">Service for current user context</param>
    public AuditLogsController(
        IAuditLogRepository auditLogRepository,
        ICurrentUserService currentUserService)
    {
        _auditLogRepository = auditLogRepository ?? throw new ArgumentNullException(nameof(auditLogRepository));
        _currentUserService = currentUserService ?? throw new ArgumentNullException(nameof(currentUserService));
    }

    /// <summary>
    /// Retrieves audit logs for a specific user (Admin/Auditor only).
    /// </summary>
    /// <param name="userId">Target user's unique identifier</param>
    /// <param name="skip">Pagination: Number of records to skip (default: 0)</param>
    /// <param name="take">Pagination: Number of records to take (default: 100, max: 1000)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of audit log entries for the specified user</returns>
    /// <response code="200">Returns audit logs successfully</response>
    /// <response code="400">Invalid pagination parameters</response>
    /// <response code="401">User is not authenticated</response>
    /// <response code="403">User doesn't have Admin or Auditor role</response>
    [HttpGet("user/{userId:guid}")]
    [ProducesResponseType(typeof(ApiResponse<IEnumerable<AuditLog>>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status403Forbidden)]
    public async Task<ActionResult<ApiResponse<IEnumerable<AuditLog>>>> GetUserAuditLogs(
        Guid userId,
        [FromQuery] int skip = 0,
        [FromQuery] int take = 100,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // VALIDATION: Pagination parameters
            if (skip < 0)
            {
                return BadRequest(new ApiErrorResponse
                {
                    Success = false,
                    Message = "Skip parameter cannot be negative"
                });
            }

            if (take < 1 || take > 1000)
            {
                return BadRequest(new ApiErrorResponse
                {
                    Success = false,
                    Message = "Take parameter must be between 1 and 1000"
                });
            }

            // FETCH: Audit logs for user
            var logs = await _auditLogRepository.GetByUserIdAsync(userId, skip, take, cancellationToken);

            // AUDIT: Log that admin/auditor viewed someone's logs
            // TODO: Call IAuditLogService.LogSecurityEventAsync here
            // eventType: "AUDIT_LOG_ACCESSED"
            // action: $"Admin {_currentUserService.Email} viewed logs for user {userId}"

            return Ok(new ApiResponse<IEnumerable<AuditLog>>
            {
                Success = true,
                Message = $"Retrieved {logs.Count()} audit logs for user {userId}",
                Data = logs
            });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new ApiErrorResponse
            {
                Success = false,
                Message = "An unexpected error occurred while retrieving audit logs."
            });
        }
    }

    /// <summary>
    /// Retrieves audit logs for a specific resource (Secret, User, etc.).
    /// </summary>
    /// <param name="resourceId">Target resource's unique identifier</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of audit log entries for the specified resource</returns>
    /// <response code="200">Returns audit logs successfully</response>
    /// <response code="401">User is not authenticated</response>
    /// <response code="403">User doesn't have Admin or Auditor role</response>
    [HttpGet("resource/{resourceId:guid}")]
    [ProducesResponseType(typeof(ApiResponse<IEnumerable<AuditLog>>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status403Forbidden)]
    public async Task<ActionResult<ApiResponse<IEnumerable<AuditLog>>>> GetResourceAuditLogs(
        Guid resourceId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // FETCH: Audit logs for resource
            var logs = await _auditLogRepository.GetByResourceIdAsync(resourceId, cancellationToken);

            return Ok(new ApiResponse<IEnumerable<AuditLog>>
            {
                Success = true,
                Message = $"Retrieved {logs.Count()} audit logs for resource {resourceId}",
                Data = logs
            });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new ApiErrorResponse
            {
                Success = false,
                Message = "An unexpected error occurred while retrieving audit logs."
            });
        }
    }

    /// <summary>
    /// Retrieves most recent audit logs across all users (Dashboard).
    /// </summary>
    /// <param name="count">Number of recent logs to retrieve (default: 100, max: 1000)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of recent audit log entries</returns>
    /// <response code="200">Returns recent audit logs successfully</response>
    /// <response code="400">Invalid count parameter</response>
    /// <response code="401">User is not authenticated</response>
    /// <response code="403">User doesn't have Admin or Auditor role</response>
    [HttpGet("recent")]
    [ProducesResponseType(typeof(ApiResponse<IEnumerable<AuditLog>>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status403Forbidden)]
    public async Task<ActionResult<ApiResponse<IEnumerable<AuditLog>>>> GetRecentAuditLogs(
        [FromQuery] int count = 100,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // VALIDATION: Count parameter
            if (count < 1 || count > 1000)
            {
                return BadRequest(new ApiErrorResponse
                {
                    Success = false,
                    Message = "Count parameter must be between 1 and 1000"
                });
            }

            // FETCH: Recent audit logs
            var logs = await _auditLogRepository.GetRecentLogsAsync(count, cancellationToken);

            return Ok(new ApiResponse<IEnumerable<AuditLog>>
            {
                Success = true,
                Message = $"Retrieved {logs.Count()} recent audit logs",
                Data = logs
            });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new ApiErrorResponse
            {
                Success = false,
                Message = "An unexpected error occurred while retrieving audit logs."
            });
        }
    }

    /// <summary>
    /// Gets total count of audit logs (for statistics).
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Total count of audit log entries</returns>
    /// <response code="200">Returns total count successfully</response>
    /// <response code="401">User is not authenticated</response>
    /// <response code="403">User doesn't have Admin or Auditor role</response>
    [HttpGet("count")]
    [ProducesResponseType(typeof(ApiResponse<int>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(ApiErrorResponse), StatusCodes.Status403Forbidden)]
    public async Task<ActionResult<ApiResponse<int>>> GetTotalCount(
        CancellationToken cancellationToken = default)
    {
        try
        {
            // FETCH: Total count (expensive operation, consider caching)
            var totalCount = await _auditLogRepository.GetTotalCountAsync(cancellationToken);

            return Ok(new ApiResponse<int>
            {
                Success = true,
                Message = "Total audit log count retrieved successfully",
                Data = totalCount
            });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new ApiErrorResponse
            {
                Success = false,
                Message = "An unexpected error occurred while counting audit logs."
            });
        }
    }
}