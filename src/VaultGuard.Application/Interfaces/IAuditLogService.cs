using System;
using System.Threading;
using System.Threading.Tasks;
using VaultGuard.Domain.Common.Results;

namespace VaultGuard.Application.Interfaces;

/// <summary>
/// Service interface for comprehensive security audit logging.
/// 
/// SECURITY ARCHITECTURE:
/// This service is the cornerstone of VaultGuard's security monitoring:
/// - Immutable audit trail (append-only, no updates/deletes)
/// - Real-time threat detection (unusual access patterns)
/// - Forensic investigation support (complete event history)
/// - Compliance reporting (SOC 2, GDPR, PCI-DSS, HIPAA)
/// 
/// ┌─────────────────────────────────────────────────────────────┐
/// │ Every Sensitive Operation → IAuditLogService → Database     │
/// │   (Create/Update/Delete/Decrypt)   (Append-only)            │
/// └─────────────────────────────────────────────────────────────┘
/// 
/// CRITICAL SECURITY EVENTS LOGGED:
/// 1. 🔐 SECRET_CREATED - New secret added
/// 2. 🔓 SECRET_DECRYPTED - Plaintext value accessed (MOST CRITICAL)
/// 3. ✏️ SECRET_UPDATED - Metadata or value changed
/// 4. 🗑️ SECRET_DELETED - Secret removed (soft/hard)
/// 5. 🔑 USER_LOGIN_SUCCESS - Authentication successful
/// 6. ❌ USER_LOGIN_FAILED - Authentication failed (brute-force detection)
/// 7. 🚪 USER_LOGOUT - Session terminated
/// 8. 🔒 PASSWORD_CHANGED - User credential update
/// 9. ⚠️ UNAUTHORIZED_ACCESS - Authorization failure (potential attack)
/// 10. 🚨 SUSPICIOUS_ACTIVITY - Rate limit exceeded, unusual patterns
/// 
/// COMPLIANCE REQUIREMENTS:
/// - **SOC 2 Type II (Trust Service Criteria)**:
///   * CC6.1: Logical access controls
///   * CC7.2: System operations monitoring
///   * CC7.3: Data security event detection
/// 
/// - **GDPR Article 32 (Security of Processing)**:
///   * Ability to ensure ongoing confidentiality
///   * Ability to restore availability after incident
///   * Process for testing security measures
/// 
/// - **PCI-DSS Requirement 10**:
///   * 10.1: Implement audit trails
///   * 10.2: Log all access to cardholder data
///   * 10.3: Record required entries
///   * 10.5: Secure audit trails
///   * 10.6: Review logs daily
/// 
/// - **HIPAA §164.312(b) (Audit Controls)**:
///   * Hardware, software, procedural mechanisms
///   * Record and examine activity in systems
///   * Contain or use PHI
/// 
/// - **NIST SP 800-53 AU-2 (Audit Events)**:
///   * Identify types of events to audit
///   * Coordinate auditing with incident response
/// 
/// THREAT DETECTION:
/// - **Brute-force attacks**: Multiple failed decryption attempts
/// - **Privilege escalation**: Unauthorized access attempts
/// - **Data exfiltration**: Unusual bulk decryption patterns
/// - **Account compromise**: Login from unexpected location/device
/// - **Insider threat**: Excessive access to secrets
/// 
/// RETENTION POLICY:
/// - Active logs: Queryable in main database (90 days)
/// - Archived logs: Cold storage (7 years for compliance)
/// - Deletion: NEVER (immutable audit trail)
/// - Export: Daily backup to immutable storage (AWS S3 Glacier)
/// 
/// PERFORMANCE:
/// - Async logging (non-blocking for user operations)
/// - Fire-and-forget pattern (don't wait for log write)
/// - Background queue: RabbitMQ/Azure Service Bus (optional)
/// - Write-optimized database: Time-series DB (InfluxDB) or NoSQL (MongoDB)
/// </summary>
/// <remarks>
/// ⚠️ LOGGING BEST PRACTICES:
/// 1. ✅ DO log: Event type, UserId, Timestamp, IP, Result (Success/Fail)
/// 2. ✅ DO log: ResourceId (SecretId), Action, Duration
/// 3. ❌ DON'T log: Plaintext secret values
/// 4. ❌ DON'T log: Encrypted secret values (unnecessary, risky)
/// 5. ❌ DON'T log: Passwords (even hashed ones)
/// 6. ✅ DO hash: PII data (email, phone) for privacy
/// 7. ✅ DO truncate: Long values (user-agent, referer)
/// 8. ✅ DO sanitize: SQL injection attempts in input data
/// </remarks>
public interface IAuditLogService
{
    /// <summary>
    /// Logs a security-relevant event with full context.
    /// 
    /// IMPLEMENTATION:
    /// 1. Validate input parameters (not null, event type enum)
    /// 2. Enrich event data:
    ///    - Server timestamp (UTC)
    ///    - Correlation ID (trace distributed requests)
    ///    - Session ID (track user session)
    ///    - Request ID (link related operations)
    /// 3. Serialize to JSON (structured logging)
    /// 4. Write to AuditLogs table (append-only)
    /// 5. Optionally: Push to SIEM (Splunk, ELK, Azure Sentinel)
    /// 6. Return: SuccessResult (logging failures should NOT break app)
    /// 
    /// FIRE-AND-FORGET:
    /// - Audit logging should NEVER block user operations
    /// - Use: Task.Run(() => LogAsync(...)) for async background write
    /// - Handle: Logging failures gracefully (fallback to file/queue)
    /// 
    /// STRUCTURED LOGGING:
    /// JSON format for machine parsing:
    /// {
    ///   "eventType": "SECRET_DECRYPTED",
    ///   "userId": "a1b2c3d4-...",
    ///   "secretId": "e5f6g7h8-...",
    ///   "timestamp": "2025-02-14T12:34:56.789Z",
    ///   "ipAddress": "203.0.113.42",
    ///   "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
    ///   "result": "Success",
    ///   "duration": "15ms",
    ///   "correlationId": "9i0j1k2l-...",
    ///   "additionalData": {
    ///     "secretTitle": "AWS Production API Key",
    ///     "accessMethod": "Web UI"
    ///   }
    /// }
    /// 
    /// ERROR HANDLING:
    /// - If logging fails: Write to fallback (file, queue, console)
    /// - If database down: Buffer in memory (max 1000 entries)
    /// - If buffer full: Oldest entries dropped (accept data loss over crash)
    /// - Alert: DevOps team if logging fails repeatedly
    /// </summary>
    /// <param name="eventType">Type of security event (enum: LOGIN, DECRYPT, etc.)</param>
    /// <param name="userId">User who performed the action (nullable for anonymous)</param>
    /// <param name="resourceId">Target resource ID (SecretId, UserId, etc.)</param>
    /// <param name="action">Descriptive action name (e.g., "Secret Decrypted")</param>
    /// <param name="result">Operation result (Success/Failure)</param>
    /// <param name="ipAddress">Client IP address (for geo-location analysis)</param>
    /// <param name="userAgent">Client browser/app (for device tracking)</param>
    /// <param name="additionalData">Optional JSON metadata (max 4KB)</param>
    /// <param name="cancellationToken">Cancellation token (graceful shutdown)</param>
    /// <returns>
    /// Success: Always returns SuccessResult (logging failures don't fail operations)
    /// Failure: ErrorResult logged internally, never thrown to caller
    /// </returns>
    /// <example>
    /// // Log successful secret decryption
    /// await _auditLogService.LogSecurityEventAsync(
    ///     eventType: "SECRET_DECRYPTED",
    ///     userId: currentUser.Id,
    ///     resourceId: secret.Id,
    ///     action: "User decrypted secret value",
    ///     result: "Success",
    ///     ipAddress: Request.HttpContext.Connection.RemoteIpAddress.ToString(),
    ///     userAgent: Request.Headers["User-Agent"].ToString(),
    ///     additionalData: JsonSerializer.Serialize(new {
    ///         SecretTitle = secret.Title,
    ///         AccessMethod = "Web UI",
    ///         AccessCount = secret.AccessCount + 1
    ///     }),
    ///     cancellationToken
    /// );
    /// 
    /// // Log failed unauthorized access
    /// await _auditLogService.LogSecurityEventAsync(
    ///     eventType: "UNAUTHORIZED_ACCESS",
    ///     userId: currentUser.Id,
    ///     resourceId: secretId,
    ///     action: "User attempted to decrypt secret owned by another user",
    ///     result: "Failure",
    ///     ipAddress: ipAddress,
    ///     userAgent: userAgent,
    ///     additionalData: JsonSerializer.Serialize(new {
    ///         SecretOwnerId = secret.UserId,
    ///         AttemptedAction = "Decrypt"
    ///     }),
    ///     cancellationToken
    /// );
    /// </example>
    Task<IResult> LogSecurityEventAsync(
        string eventType,
        Guid? userId,
        Guid? resourceId,
        string action,
        string result,
        string? ipAddress,
        string? userAgent,
        string? additionalData = null,
        CancellationToken cancellationToken = default);
}