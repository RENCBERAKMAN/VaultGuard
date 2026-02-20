using System;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using VaultGuard.Application.Interfaces;

namespace VaultGuard.Infrastructure.Services;

/// <summary>
/// Service for accessing current authenticated user context from HttpContext.
/// 
/// ARCHITECTURE:
/// - Stateless: No internal state, reads from HttpContext each time
/// - Thread-Safe: HttpContext is scoped per request (thread-safe)
/// - Scoped Lifetime: One instance per HTTP request (DI configuration)
/// 
/// JWT TOKEN FLOW:
/// 1. Client sends: Authorization: Bearer <JWT_TOKEN>
/// 2. [Authorize] middleware validates JWT signature
/// 3. [Authorize] populates HttpContext.User (ClaimsPrincipal)
/// 4. This service extracts claims from HttpContext.User
/// 
/// CLAIMS MAPPING:
/// - ClaimTypes.NameIdentifier → UserId (Guid)
/// - ClaimTypes.Email → Email (string)
/// - ClaimTypes.Role → Role (string)
/// - "jti" → Token ID (for revocation checks)
/// 
/// SECURITY:
/// - Zero Trust: Always verify claims exist before using
/// - Null Safety: Properties return null if claim missing
/// - No Caching: Always read fresh from HttpContext (stateless)
/// 
/// PERFORMANCE:
/// - Lightweight: Only reads from HttpContext (no I/O)
/// - Lazy Evaluation: Properties computed on demand
/// - No Allocation: Guid? and bool primitives (stack allocated)
/// </summary>
public sealed class CurrentUserService : ICurrentUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    /// <summary>
    /// Initializes a new instance of CurrentUserService.
    /// </summary>
    /// <param name="httpContextAccessor">Accessor for current HTTP context</param>
    public CurrentUserService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
    }

    /// <inheritdoc/>
    public Guid? UserId
    {
        get
        {
            // SECURITY: Verify HttpContext and User exist
            var user = _httpContextAccessor.HttpContext?.User;
            if (user == null || !user.Identity?.IsAuthenticated == true)
            {
                return null;
            }

            // EXTRACT: NameIdentifier claim (UserId)
            var userIdClaim = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrWhiteSpace(userIdClaim))
            {
                return null;
            }

            // PARSE: String to Guid
            if (Guid.TryParse(userIdClaim, out var userId))
            {
                return userId;
            }

            // INVALID: Claim value is not a valid Guid
            return null;
        }
    }

    /// <inheritdoc/>
    public bool IsAuthenticated
    {
        get
        {
            // SECURITY: Check if user is authenticated
            var user = _httpContextAccessor.HttpContext?.User;
            return user?.Identity?.IsAuthenticated == true;
        }
    }

    /// <inheritdoc/>
    public string? IpAddress
    {
        get
        {
            // EXTRACT: Remote IP address from connection
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext == null)
            {
                return null;
            }

            // PROXY HANDLING: Check X-Forwarded-For header first (if behind proxy)
            var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(forwardedFor))
            {
                // FORMAT: X-Forwarded-For: client-ip, proxy1-ip, proxy2-ip
                // TAKE: First IP (client IP, not proxy IP)
                var clientIp = forwardedFor.Split(',').FirstOrDefault()?.Trim();
                if (!string.IsNullOrWhiteSpace(clientIp))
                {
                    return clientIp;
                }
            }

            // FALLBACK: Direct connection (no proxy)
            var remoteIp = httpContext.Connection.RemoteIpAddress;
            if (remoteIp == null)
            {
                return null;
            }

            // NORMALIZE: IPv4-mapped IPv6 to IPv4
            // Example: ::ffff:203.0.113.42 → 203.0.113.42
            if (remoteIp.IsIPv4MappedToIPv6)
            {
                return remoteIp.MapToIPv4().ToString();
            }

            return remoteIp.ToString();
        }
    }

    /// <inheritdoc/>
    public string? Role
    {
        get
        {
            // SECURITY: Verify user is authenticated
            var user = _httpContextAccessor.HttpContext?.User;
            if (user == null || !user.Identity?.IsAuthenticated == true)
            {
                return null;
            }

            // EXTRACT: Role claim
            return user.FindFirst(ClaimTypes.Role)?.Value;
        }
    }

    /// <inheritdoc/>
    public string? Email
    {
        get
        {
            // SECURITY: Verify user is authenticated
            var user = _httpContextAccessor.HttpContext?.User;
            if (user == null || !user.Identity?.IsAuthenticated == true)
            {
                return null;
            }

            // EXTRACT: Email claim
            return user.FindFirst(ClaimTypes.Email)?.Value;
        }
    }
}