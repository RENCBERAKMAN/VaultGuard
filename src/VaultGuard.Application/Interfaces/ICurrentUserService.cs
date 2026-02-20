using System;

namespace VaultGuard.Application.Interfaces;

/// <summary>
/// Stateless service interface for accessing current authenticated user context.
/// 
/// ARCHITECTURE PATTERN:
/// This service extracts user identity from HttpContext (JWT claims):
/// - Scoped lifetime (per HTTP request)
/// - Thread-safe (no shared state)
/// - Stateless (reads from HttpContext.User each time)
/// - Testable (mockable for unit tests)
/// 
/// ┌─────────────────────────────────────────────────────────────┐
/// │ JWT Token → [Authorize] → HttpContext.User → ICurrentUser   │
/// │  (Client)     (Middleware)    (ClaimsPrincipal)   (Service) │
/// └─────────────────────────────────────────────────────────────┘
/// 
/// JWT TOKEN STRUCTURE:
/// {
///   "sub": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",  // UserId (Subject)
///   "email": "user@example.com",
///   "role": "User",  // or "Admin"
///   "jti": "jwt-id-123",  // Token ID
///   "nbf": 1707907200,  // Not Before (Unix timestamp)
///   "exp": 1707993600,  // Expiration (Unix timestamp)
///   "iat": 1707907200,  // Issued At (Unix timestamp)
///   "iss": "VaultGuard",  // Issuer
///   "aud": "VaultGuard-API"  // Audience
/// }
/// 
/// CLAIMS MAPPING:
/// - ClaimTypes.NameIdentifier → UserId (Guid)
/// - ClaimTypes.Email → Email (string)
/// - ClaimTypes.Role → Role (string: "User", "Admin")
/// - "jti" → TokenId (Guid)
/// 
/// SECURITY PRINCIPLES:
/// 1. **Zero Trust**: Always verify claims exist and are valid
/// 2. **Least Privilege**: Return only necessary information
/// 3. **Stateless**: No session state, only JWT token data
/// 4. **Immutable**: Properties are read-only (no setters)
/// 5. **Thread-Safe**: No shared mutable state
/// 
/// AUTHORIZATION FLOW:
/// 1. Client sends: Authorization: Bearer <JWT_TOKEN>
/// 2. [Authorize] middleware validates JWT signature
/// 3. [Authorize] middleware populates HttpContext.User
/// 4. ICurrentUserService reads claims from HttpContext.User
/// 5. Service layer uses UserId for authorization checks
/// 
/// ERROR HANDLING:
/// - If JWT invalid: [Authorize] returns 401 Unauthorized (before reaching service)
/// - If JWT expired: [Authorize] returns 401 Unauthorized
/// - If JWT missing: IsAuthenticated = false, UserId = null
/// - If claims missing: UserId = null (graceful degradation)
/// 
/// TESTING:
/// - Unit tests: Mock ICurrentUserService (set UserId, IsAuthenticated)
/// - Integration tests: Use TestServer with fake JWT tokens
/// - Example:
///   var mockCurrentUser = new Mock<ICurrentUserService>();
///   mockCurrentUser.Setup(x => x.UserId).Returns(testUserId);
///   mockCurrentUser.Setup(x => x.IsAuthenticated).Returns(true);
/// 
/// PERFORMANCE:
/// - Lightweight: Only reads from HttpContext (no database calls)
/// - Cached per request: Properties evaluated once per HTTP request
/// - No allocation overhead: Guid? and bool primitives
/// </summary>
/// <remarks>
/// ⚠️ STATELESS DESIGN:
/// This service does NOT store user data. It only reads from HttpContext.User.
/// Every property access re-evaluates claims (unless cached by implementation).
/// 
/// ⚠️ THREAD SAFETY:
/// HttpContext is scoped per request (thread-safe within single request).
/// This service MUST be registered as Scoped (not Singleton).
/// 
/// ⚠️ AUTHORIZATION:
/// This service provides identity, NOT authorization.
/// Authorization checks (e.g., "Does user own this secret?") belong in:
/// - Service layer (ISecretService)
/// - Authorization policies (ClaimsPrincipal.IsInRole)
/// - Authorization handlers (IAuthorizationHandler)
/// 
/// Example usage in service layer:
/// public async Task<IDataResult<SecretDto>> GetSecretByIdAsync(Guid secretId)
/// {
///     var secret = await _repository.GetByIdAsync(secretId);
///     if (secret == null) return new ErrorDataResult<SecretDto>("Secret not found");
///     
///     // Authorization check
///     if (secret.UserId != _currentUserService.UserId)
///     {
///         await _auditLogService.LogSecurityEventAsync(
///             "UNAUTHORIZED_ACCESS",
///             _currentUserService.UserId,
///             secretId,
///             "Attempted to access secret owned by another user",
///             "Failure",
///             _currentUserService.IpAddress,
///             null
///         );
///         return new ErrorDataResult<SecretDto>("Forbidden");
///     }
///     
///     return new SuccessDataResult<SecretDto>(_mapper.Map<SecretDto>(secret));
/// }
/// </remarks>
public interface ICurrentUserService
{
    /// <summary>
    /// Gets the unique identifier of the current authenticated user.
    /// 
    /// IMPLEMENTATION:
    /// - Extract from: HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)
    /// - Parse to: Guid
    /// - Return: Guid? (null if not authenticated or claim missing)
    /// 
    /// USE CASES:
    /// - Authorization: "Does user own this secret?"
    /// - Audit logging: "Who performed this action?"
    /// - Data filtering: "Show only this user's secrets"
    /// 
    /// NULL SCENARIOS:
    /// - User not authenticated (no JWT token)
    /// - JWT token missing "sub" claim (malformed token)
    /// - JWT token has invalid "sub" value (not a valid Guid)
    /// 
    /// SECURITY:
    /// - This value is trusted (JWT signature verified by middleware)
    /// - No additional validation needed in service layer
    /// - Used for authorization checks (ownership verification)
    /// </summary>
    /// <example>
    /// if (_currentUserService.UserId == secret.UserId)
    /// {
    ///     // User owns this secret, allow access
    /// }
    /// else
    /// {
    ///     // User does NOT own this secret, deny access
    ///     return new ErrorResult("Forbidden: You do not own this secret");
    /// }
    /// </example>
    Guid? UserId { get; }

    /// <summary>
    /// Gets a value indicating whether the current user is authenticated.
    /// 
    /// IMPLEMENTATION:
    /// - Check: HttpContext.User?.Identity?.IsAuthenticated ?? false
    /// - Return: bool (true if JWT token valid, false otherwise)
    /// 
    /// USE CASES:
    /// - Public endpoints: Allow anonymous access
    /// - Protected endpoints: Require authentication
    /// - Conditional logic: Show different UI for authenticated users
    /// 
    /// TRUE WHEN:
    /// - Valid JWT token in Authorization header
    /// - JWT signature verified
    /// - JWT not expired
    /// 
    /// FALSE WHEN:
    /// - No JWT token (anonymous request)
    /// - JWT token invalid (signature mismatch)
    /// - JWT token expired
    /// - JWT token revoked (blacklisted)
    /// </summary>
    /// <example>
    /// if (!_currentUserService.IsAuthenticated)
    /// {
    ///     return new ErrorResult("Unauthorized: Please log in");
    /// }
    /// </example>
    bool IsAuthenticated { get; }

    /// <summary>
    /// Gets the IP address of the current user's request.
    /// 
    /// IMPLEMENTATION:
    /// - Extract from: HttpContext.Connection.RemoteIpAddress?.ToString()
    /// - Handle: IPv4 and IPv6 formats
    /// - Handle: Reverse proxy (X-Forwarded-For header)
    /// 
    /// USE CASES:
    /// - Audit logging: "Who accessed from where?"
    /// - Security monitoring: "Unusual login location?"
    /// - Geo-blocking: "Block access from specific countries"
    /// - Rate limiting: "Max 100 requests per IP per hour"
    /// 
    /// IPv4 vs IPv6:
    /// - IPv4: 203.0.113.42
    /// - IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
    /// - IPv4-mapped IPv6: ::ffff:203.0.113.42
    /// 
    /// REVERSE PROXY:
    /// If behind nginx/CloudFlare/AWS ALB, use X-Forwarded-For:
    /// - X-Forwarded-For: client-ip, proxy1-ip, proxy2-ip
    /// - Use: First IP in chain (client IP, not proxy IP)
    /// 
    /// NULL SCENARIOS:
    /// - Local testing (no remote IP)
    /// - Load balancer misconfiguration
    /// 
    /// SECURITY:
    /// - IP spoofing: Mitigated by HTTPS/TLS
    /// - IP rotation: VPN/Tor users (audit log still records)
    /// </summary>
    /// <example>
    /// await _auditLogService.LogSecurityEventAsync(
    ///     "SECRET_DECRYPTED",
    ///     _currentUserService.UserId,
    ///     secretId,
    ///     "User decrypted secret value",
    ///     "Success",
    ///     _currentUserService.IpAddress,  // Audit trail
    ///     null
    /// );
    /// </example>
    string? IpAddress { get; }

    /// <summary>
    /// Gets the role(s) of the current authenticated user.
    /// 
    /// IMPLEMENTATION:
    /// - Extract from: HttpContext.User.FindFirstValue(ClaimTypes.Role)
    /// - Return: string ("User", "Admin", "Auditor")
    /// 
    /// USE CASES:
    /// - Role-based authorization: "Only Admin can delete all secrets"
    /// - Feature flags: "Show admin menu if role = Admin"
    /// - Audit logging: "User X (Admin) performed Y"
    /// 
    /// ROLES IN VAULTGUARD:
    /// - "User": Standard user (CRUD their own secrets)
    /// - "Admin": Administrator (view all secrets metadata, manage users)
    /// - "Auditor": Read-only access to audit logs (compliance)
    /// 
    /// NULL SCENARIOS:
    /// - User not authenticated
    /// - JWT token missing "role" claim
    /// </summary>
    string? Role { get; }

    /// <summary>
    /// Gets the email address of the current authenticated user.
    /// 
    /// IMPLEMENTATION:
    /// - Extract from: HttpContext.User.FindFirstValue(ClaimTypes.Email)
    /// - Return: string (email address)
    /// 
    /// USE CASES:
    /// - Display in UI: "Logged in as: user@example.com"
    /// - Notifications: "Send email to current user"
    /// - Audit logging: "User email for human-readable logs"
    /// 
    /// NULL SCENARIOS:
    /// - User not authenticated
    /// - JWT token missing "email" claim
    /// </summary>
    string? Email { get; }
}