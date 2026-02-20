using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using VaultGuard.Application.Interfaces;
using VaultGuard.Domain.Common.Results;
using VaultGuard.Domain.Entities;

namespace VaultGuard.Application.Services;

public sealed class AuditLogService : IAuditLogService
{
    private readonly IAuditLogRepository _auditLogRepository;

    public AuditLogService(IAuditLogRepository auditLogRepository)
    {
        _auditLogRepository = auditLogRepository ?? throw new ArgumentNullException(nameof(auditLogRepository));
    }

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
            // VALIDATION
            if (string.IsNullOrWhiteSpace(eventType))
                return new ErrorResult("Event type is required");
            if (string.IsNullOrWhiteSpace(action))
                return new ErrorResult("Action is required");
            if (string.IsNullOrWhiteSpace(result))
                return new ErrorResult("Result is required");

            // SANITIZE
            eventType = SanitizeLogInput(eventType, 100) ?? eventType;
            action = SanitizeLogInput(action, 500) ?? action;
            result = SanitizeLogInput(result, 50) ?? result;
            ipAddress = SanitizeLogInput(ipAddress, 45) ?? "Unknown";
            userAgent = SanitizeLogInput(userAgent, 500);

            if (!string.IsNullOrWhiteSpace(additionalData) && additionalData.Length > 4000)
                additionalData = additionalData.Substring(0, 3997) + "...";

            // CREATE: Use AuditLog.Create() factory method
            var auditLog = AuditLog.Create(
                userId: userId,
                action: action!,
                entityName: DeriveEntityNameFromAction(action),
                ipAddress: ipAddress,
                result: result!,
                entityId: resourceId,
                userAgent: userAgent,
                additionalData: additionalData,
                correlationId: GetCorrelationId(),
                duration: null
            );

            await _auditLogRepository.AddAsync(auditLog, cancellationToken);
            return new SuccessResult("Security event logged successfully");
        }
        catch (OperationCanceledException)
        {
            return new ErrorResult("Audit logging was cancelled");
        }
        catch (Exception ex)
        {
            return new ErrorResult($"Failed to log security event: {ex.Message}");
        }
    }

    private static string SanitizeLogInput(string? input, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(input))
            return string.Empty; // null yerine boþ string dönüyoruz

        input = System.Text.RegularExpressions.Regex.Replace(input, @"[\x00-\x1F\x7F]", string.Empty);

        if (input.Length > maxLength)
            input = input.Substring(0, maxLength);

        return input;
    }

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

    private static string GetCorrelationId()
    {
        return Guid.NewGuid().ToString();
    }
}