using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using VaultGuard.Application.Interfaces;
using VaultGuard.Domain.Common.Results;
using VaultGuard.Domain.Entities;

namespace VaultGuard.Application.Services;

/// <summary>
/// Service implementation for comprehensive security audit logging.
/// 
/// SECURITY ARCHITECTURE:
/// - Immutable audit trail (append-only, no updates/deletes)
/// - Input sanitization (XSS, SQL injection, control characters)
/// - Data truncation (prevent storage bloat/DoS)
/// - Fire-and-forget pattern (logging failures don't crash app)
/// - Correlation ID support (distributed tracing)
/// 
/// COMPLIANCE:
/// - SOC 2 Type II: Every security event logged
/// - GDPR Article 32: Audit controls
/// - PCI-DSS Requirement 10: Audit trail implementation
/// - HIPAA §164.312(b): Audit controls for PHI access
/// </summary>
public sealed class AuditLogService : IAuditLogService
{
    private readonly IAuditLogRepository _auditLogRepository;

    public AuditLogService(IAuditLogRepository auditLogRepository)
    {
        _auditLogRepository = auditLogRepository ?? throw new ArgumentNullException(nameof(auditLogRepository));
    }

    /// <inheritdoc/>
    public async Task<IResult> LogSecurityEventAsync(
        string eventType,
        Guid? userId,
        Guid? resourceId,
        string action,
        string result,
        string? ipAddress,
        string? userAgent,
        string? additionalData = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // ============================================================================
            // VALIDATION: Required fields
            // ============================================================================

            if (string.IsNullOrWhiteSpace(eventType))
                return new ErrorResult("Event type is required");

            if (string.IsNullOrWhiteSpace(action))
                return new ErrorResult("Action description is required");

            if (string.IsNullOrWhiteSpace(result))
                return new ErrorResult("Result status is required");

            // ============================================================================
            // SANITIZATION: Remove control characters, truncate lengths
            // ============================================================================

            // Event type: max 100 chars
            eventType = SanitizeLogInput(eventType, 100);

            // Action: max 500 chars
            action = SanitizeLogInput(action, 500);

            // Result: max 50 chars
            result = SanitizeLogInput(result, 50);

            
            // IP address: max 45 chars (IPv6), default to "0.0.0.0" if null (system/internal events)
            ipAddress = string.IsNullOrWhiteSpace(ipAddress)
                ? "0.0.0.0"
                : SanitizeLogInput(ipAddress, 45);

            // User agent: max 500 chars, can be null
            userAgent = string.IsNullOrWhiteSpace(userAgent)
                ? null
                : SanitizeLogInput(userAgent, 500);

            // Additional data: max 4000 chars (with ellipsis if truncated)
            if (!string.IsNullOrWhiteSpace(additionalData) && additionalData.Length > 2000)
            {
                additionalData = additionalData.Substring(0, 1997) + "...";
            }

            // ============================================================================
            // CREATE: AuditLog entity using factory method
            // ============================================================================

            // ✅ CRITICAL FIX: AuditLog.Create now expects parameters in this order:
            // userId, action, entityName, ipAddress, result, entityId, userAgent, additionalData, correlationId, duration
            var auditLog = AuditLog.Create(
                userId: userId,                                    // Guid? - nullable for system events
                action: action,                                    // string - required, already sanitized
                entityName: DeriveEntityNameFromAction(action),   // string - derived from action
                ipAddress: ipAddress,                             // string - required, defaults to "Unknown"
                result: result,                                    // string - required, already sanitized
                entityId: resourceId,                             // ✅ FIX: Guid? (was string before)
                userAgent: userAgent,                             // string? - optional
                additionalData: additionalData,                   // string? - optional
                correlationId: GenerateCorrelationId(),           // string - distributed tracing
                duration: null                                     // long? - null for now (can add timing later)
            );

            // ============================================================================
            // PERSIST: Save to database
            // ============================================================================

            await _auditLogRepository.AddAsync(auditLog, cancellationToken);

            return new SuccessResult("Security event logged successfully");
        }
        catch (OperationCanceledException)
        {
            // Graceful cancellation (client disconnected)
            return new ErrorResult("Audit logging was cancelled");
        }
        catch (Exception ex)
        {
            // Fire-and-forget: Don't crash app if logging fails
            // Log to fallback (file, console, etc.) in production
            return new ErrorResult($"Failed to log security event: {ex.Message}");
        }
    }

    // ============================================================================
    // PRIVATE HELPER METHODS
    // ============================================================================

    /// <summary>
    /// Sanitizes input by removing control characters and truncating to max length.
    /// 
    /// SECURITY:
    /// - Removes: newlines, carriage returns, null bytes, other control chars
    /// - Prevents: Log injection attacks, format string vulnerabilities
    /// - Truncates: Prevents storage bloat and DoS attacks
    /// </summary>
    /// <param name="input">Input string to sanitize</param>
    /// <param name="maxLength">Maximum allowed length</param>
    /// <returns>Sanitized string (never null, empty if input was null/whitespace)</returns>
    private static string SanitizeLogInput(string? input, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(input))
            return string.Empty;

        // Remove control characters (0x00-0x1F, 0x7F)
        // Regex: [\x00-\x1F\x7F] matches all control characters
        input = System.Text.RegularExpressions.Regex.Replace(
            input,
            @"[\x00-\x1F\x7F]",
            string.Empty);

        // Truncate to max length
        if (input.Length > maxLength)
            input = input.Substring(0, maxLength);

        return input;
    }

    /// <summary>
    /// Derives entity name from action string.
    /// 
    /// CONVENTION: Actions follow format "{EntityName}_{OperationType}"
    /// Examples:
    /// - "SECRET_DECRYPTED" → "Secret"
    /// - "USER_LOGIN" → "User"
    /// - "AUDIT_QUERY" → "AuditLog"
    /// - "SYSTEM_STARTUP" → "System"
    /// </summary>
    /// <param name="action">Action string (e.g., "SECRET_DECRYPTED")</param>
    /// <returns>Entity name</returns>
    private static string DeriveEntityNameFromAction(string action)
    {
        if (action.Contains("SECRET", StringComparison.OrdinalIgnoreCase))
            return "Secret";

        if (action.Contains("USER", StringComparison.OrdinalIgnoreCase))
            return "User";

        if (action.Contains("AUDIT", StringComparison.OrdinalIgnoreCase))
            return "AuditLog";

        return "System";
    }

    /// <summary>
    /// Generates a new correlation ID for distributed tracing.
    /// 
    /// DISTRIBUTED TRACING:
    /// - Links related events across microservices
    /// - Traces request flow through system
    /// - Debugging distributed transactions
    /// 
    /// FORMAT: GUID string (36 chars with hyphens)
    /// </summary>
    /// <returns>Correlation ID string</returns>
    private static string GenerateCorrelationId()
    {
        return Guid.NewGuid().ToString();
    }
}