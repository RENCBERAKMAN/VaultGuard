using System;
using System.Linq;
using System.Text.RegularExpressions;

namespace VaultGuard.Domain.Entities;

/// <summary>
/// AUDIT LOG ENTITY: Immutable Security Event Recording
/// 
/// DDD PRINCIPLES:
/// - Value Object Pattern: Immutable after creation
/// - Factory Method: Static Create() for controlled creation
/// - Rich Validation: Comprehensive input validation
/// - No BaseEntity: Different lifecycle (never updated/deleted)
/// 
/// SECURITY ARCHITECTURE:
/// - Immutability: Once created, never modified (tamper-proof)
/// - Complete Audit Trail: Who, What, When, Where, Why
/// - Compliance Ready: GDPR, SOC 2, HIPAA, PCI-DSS
/// - Forensic Analysis: Full context for security investigations
/// </summary>
public sealed class AuditLog
{
    // ============================================================================
    // PUBLIC PROPERTIES (Init-Only - Immutable)
    // ============================================================================

    /// <summary>
    /// IDENTITY: Unique audit log ID
    /// </summary>
    public Guid Id { get; init; }

    /// <summary>
    /// USER ID: Who performed the action
    /// </summary>
    public Guid? UserId { get; init; }

    /// <summary>
    /// ACTION: Event type identifier
    /// </summary>
    public string Action { get; init; } = string.Empty;

    /// <summary>
    /// ENTITY NAME: Target entity type
    /// </summary>
    public string EntityName { get; init; } = string.Empty;

    /// <summary>
    /// ENTITY ID: Target entity identifier
    /// </summary>
    public Guid? EntityId { get; init; }

    /// <summary>
    /// TIMESTAMP: When event occurred (UTC)
    /// </summary>
    public DateTime Timestamp { get; init; }

    /// <summary>
    /// IP ADDRESS: Source IP of request
    /// </summary>
    public string IpAddress { get; init; } = string.Empty;

    /// <summary>
    /// USER AGENT: Browser/client identification
    /// </summary>
    public string? UserAgent { get; init; }

    /// <summary>
    /// RESULT: Operation outcome
    /// </summary>
    public string Result { get; init; } = string.Empty;

    /// <summary>
    /// ADDITIONAL DATA: Event-specific context (JSON)
    /// </summary>
    public string? AdditionalData { get; init; }

    /// <summary>
    /// CORRELATION ID: Distributed request tracing
    /// 
    /// USE:
    /// - Link related events across microservices
    /// - Trace request flow through system
    /// - Debug distributed transactions
    /// 
    /// FORMAT: GUID string or trace ID
    /// </summary>
    public string CorrelationId { get; init; } = string.Empty;

    /// <summary>
    /// DURATION: Operation duration in milliseconds
    /// 
    /// USE:
    /// - Performance monitoring
    /// - Anomaly detection (unusually slow operations)
    /// - SLA compliance tracking
    /// 
    /// NULL: Duration not measured
    /// </summary>
    public long? Duration { get; init; }

    // ============================================================================
    // ALIAS PROPERTIES (Service Compatibility)
    // ============================================================================

    /// <summary>
    /// EVENT TYPE: Alias for Action (service compatibility)
    /// 
    /// Some services expect "EventType" instead of "Action"
    /// </summary>
    public string EventType => Action;

    /// <summary>
    /// RESOURCE ID: Alias for EntityId (service compatibility)
    /// 
    /// Some services expect "ResourceId" instead of "EntityId"
    /// Returns string representation (empty if null)
    /// </summary>
    public string ResourceId => EntityId?.ToString() ?? string.Empty;

    // ============================================================================
    // PRIVATE CONSTRUCTOR (EF Core)
    // ============================================================================

    private AuditLog()
    {
        // EF Core requires parameterless constructor
    }

    // ============================================================================
    // FACTORY METHOD (DDD Pattern)
    // ============================================================================

    /// <summary>
    /// FACTORY METHOD: Create immutable audit log
    /// 
    /// IMMUTABILITY: Once created, never modified
    /// VALIDATION: Comprehensive input validation
    /// SECURITY: Sensitive data detection
    /// </summary>
    public static AuditLog Create(
        Guid? userId,
        string action,
        string entityName,
        string ipAddress,
        string result,
        Guid? entityId = null,
        string? userAgent = null,
        string? additionalData = null,
        string correlationId = "",
        long? duration = null)
    {
        var validatedUserId = ValidateUserId(userId);
        var validatedAction = ValidateAction(action);
        var validatedEntityName = ValidateEntityName(entityName);
        var validatedIpAddress = ValidateIpAddress(ipAddress);
        var validatedResult = ValidateResult(result);
        var validatedUserAgent = ValidateUserAgent(userAgent);
        var validatedAdditionalData = ValidateAdditionalData(additionalData);
        var validatedCorrelationId = ValidateCorrelationId(correlationId);
        var validatedDuration = ValidateDuration(duration);

        return new AuditLog
        {
            Id = Guid.NewGuid(),
            UserId = validatedUserId,
            Action = validatedAction,
            EntityName = validatedEntityName,
            EntityId = entityId,
            Timestamp = DateTime.UtcNow,
            IpAddress = validatedIpAddress,
            UserAgent = validatedUserAgent,
            Result = validatedResult,
            AdditionalData = validatedAdditionalData,
            CorrelationId = validatedCorrelationId,
            Duration = validatedDuration
        };
    }

    // ============================================================================
    // QUERY METHODS (Business Logic)
    // ============================================================================

    /// <summary>
    /// IS SUCCESS: Check if operation succeeded
    /// </summary>
    public bool IsSuccess => Result.Equals("Success", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// IS FAILURE: Check if operation failed
    /// </summary>
    public bool IsFailure => !IsSuccess;

    /// <summary>
    /// IS SECURITY RELATED: Check if security event
    /// </summary>
    public bool IsSecurityRelated()
    {
        var securityKeywords = new[]
        {
            "Login", "Logout", "Password", "Role", "Permission",
            "Access", "Denied", "Failed", "Lock", "MFA", "2FA",
            "Authentication", "Authorization", "Security"
        };

        return securityKeywords.Any(keyword =>
            Action.Contains(keyword, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// IS AUTHENTICATION EVENT: Check if login/logout
    /// </summary>
    public bool IsAuthenticationEvent()
    {
        var authKeywords = new[] { "Login", "Logout", "Session", "Authentication" };
        return authKeywords.Any(keyword =>
            Action.Contains(keyword, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// IS DATA ACCESS: Check if data viewed/decrypted
    /// </summary>
    public bool IsDataAccessEvent()
    {
        var accessKeywords = new[] { "Viewed", "Decrypted", "Exported", "Downloaded", "Accessed" };
        return accessKeywords.Any(keyword =>
            Action.Contains(keyword, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// BELONGS TO USER: Check if event is for user
    /// </summary>
    public bool BelongsToUser(Guid userId) => UserId.HasValue && UserId.Value == userId;

    /// <summary>
    /// BELONGS TO ENTITY: Check if event is for entity
    /// </summary>
    public bool BelongsToEntity(string entityName) =>
        EntityName.Equals(entityName, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// IS WITHIN DATE RANGE: Check if event in timeframe
    /// </summary>
    public bool IsWithinDateRange(DateTime startDate, DateTime endDate) =>
        Timestamp >= startDate && Timestamp <= endDate;

    // ============================================================================
    // PRIVATE VALIDATION METHODS
    // ============================================================================

    private static Guid? ValidateUserId(Guid? userId)
    {
        if (userId.HasValue && userId.Value == Guid.Empty)
            throw new ArgumentException(
                "User ID cannot be Guid.Empty. Use null for system events.",
                nameof(userId));

        return userId;
    }

    private static string ValidateAction(string action)
    {
        if (string.IsNullOrWhiteSpace(action))
            throw new ArgumentException("Action cannot be empty", nameof(action));

        var trimmed = action.Trim();

        if (trimmed.Length > 100)
            throw new ArgumentException("Action too long (max 100 characters)", nameof(action));

        if (!trimmed.Contains('_'))
            throw new ArgumentException(
                "Action should follow format: '{EntityName}_{OperationType}' (e.g., 'Secret_Viewed')",
                nameof(action));

        return trimmed;
    }

    private static string ValidateEntityName(string entityName)
    {
        if (string.IsNullOrWhiteSpace(entityName))
            throw new ArgumentException("Entity name cannot be empty", nameof(entityName));

        var trimmed = entityName.Trim();

        if (trimmed.Length > 50)
            throw new ArgumentException("Entity name too long (max 50 characters)", nameof(entityName));

        var validEntities = new[] { "User", "Secret", "AuditLog", "System" };

        var matched = Array.Find(validEntities, e => e.Equals(trimmed, StringComparison.OrdinalIgnoreCase));

        if (matched == null)
            throw new ArgumentException(
                $"Invalid entity name. Valid values: {string.Join(", ", validEntities)}",
                nameof(entityName));

        return matched;
    }

    private static string ValidateIpAddress(string ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
            throw new ArgumentException("IP address cannot be empty", nameof(ipAddress));

        var trimmed = ipAddress.Trim();

        if (trimmed.Length > 45)
            throw new ArgumentException("IP address too long (max 45 characters for IPv6)", nameof(ipAddress));

        var hasValidFormat = trimmed.Contains('.') || trimmed.Contains(':');

        if (!hasValidFormat)
            throw new ArgumentException("Invalid IP address format (expected IPv4 or IPv6)", nameof(ipAddress));

        if (trimmed.Contains('.') && !trimmed.Contains(':'))
        {
            var ipv4Regex = new Regex(@"^(\d{1,3}\.){3}\d{1,3}$");
            if (!ipv4Regex.IsMatch(trimmed))
                throw new ArgumentException("Invalid IPv4 address format", nameof(ipAddress));
        }

        return trimmed;
    }

    private static string ValidateResult(string result)
    {
        if (string.IsNullOrWhiteSpace(result))
            throw new ArgumentException("Result cannot be empty", nameof(result));

        var trimmed = result.Trim();

        if (trimmed.Length > 20)
            throw new ArgumentException("Result too long (max 20 characters)", nameof(result));

        var validResults = new[] { "Success", "Failure", "Denied", "Error" };

        var matched = Array.Find(validResults, r => r.Equals(trimmed, StringComparison.OrdinalIgnoreCase));

        if (matched == null)
            throw new ArgumentException(
                $"Invalid result. Valid values: {string.Join(", ", validResults)}",
                nameof(result));

        return matched;
    }

    private static string? ValidateUserAgent(string? userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent))
            return null;

        var trimmed = userAgent.Trim();

        if (trimmed.Length > 500)
            throw new ArgumentException("User agent too long (max 500 characters)", nameof(userAgent));

        return trimmed;
    }

    private static string? ValidateAdditionalData(string? additionalData)
    {
        if (string.IsNullOrWhiteSpace(additionalData))
            return null;

        var trimmed = additionalData.Trim();

        if (trimmed.Length > 2000)
            throw new ArgumentException("Additional data too long (max 2000 characters)", nameof(additionalData));

        var sensitiveKeywords = new[] { "password", "secret", "token", "key", "creditcard", "ssn" };
        var lowerData = trimmed.ToLower();

        foreach (var keyword in sensitiveKeywords)
        {
            if (lowerData.Contains(keyword))
                throw new ArgumentException(
                    $"Additional data contains sensitive keyword '{keyword}'. Never log sensitive data!",
                    nameof(additionalData));
        }

        return trimmed;
    }

    private static string ValidateCorrelationId(string correlationId)
    {
        if (string.IsNullOrWhiteSpace(correlationId))
            return string.Empty;

        var trimmed = correlationId.Trim();

        if (trimmed.Length > 100)
            throw new ArgumentException("Correlation ID too long (max 100 characters)", nameof(correlationId));

        return trimmed;
    }

    private static long? ValidateDuration(long? duration)
    {
        if (!duration.HasValue)
            return null;

        if (duration.Value < 0)
            throw new ArgumentException("Duration cannot be negative", nameof(duration));

        if (duration.Value > 3600000) // 1 hour = 3,600,000 ms
            throw new ArgumentException("Duration too long (max 1 hour)", nameof(duration));

        return duration.Value;
    }
}