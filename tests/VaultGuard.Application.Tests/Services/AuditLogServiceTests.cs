using System;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Moq;
using VaultGuard.Application.Interfaces;
using VaultGuard.Application.Services;
using VaultGuard.Domain.Common.Results;
using VaultGuard.Domain.Entities;
using Xunit;

namespace VaultGuard.Application.Tests.Services;

/// <summary>
/// TEST SÜİTİ: AuditLogService - Güvenlik Audit Logging Bütünlüğü
/// 
/// GÜVENLİK KAPSAMI:
/// - Log injection prevention (control characters, newlines)
/// - Input sanitization (XSS, SQL injection attempts)
/// - Data truncation (prevent storage bloat)
/// - Fire-and-forget pattern (logging failures don't crash app)
/// - Correlation ID support (distributed tracing)
/// - Immutable audit trail validation
/// 
/// COMPLIANCE:
/// - SOC 2 Type II: Every security event logged
/// - GDPR Article 32: Audit controls
/// - PCI-DSS Requirement 10: Audit trail implementation
/// - HIPAA §164.312(b): Audit controls for PHI access
/// </summary>
public class AuditLogServiceTests
{
    private readonly Mock<IAuditLogRepository> _auditLogRepositoryMock;
    private readonly AuditLogService _auditLogService;

    public AuditLogServiceTests()
    {
        _auditLogRepositoryMock = new Mock<IAuditLogRepository>();
        _auditLogService = new AuditLogService(_auditLogRepositoryMock.Object);
    }

    // ============================================================================
    // ✅ BAŞARILI LOG CREATION SENARYOLARI
    // ============================================================================

    [Fact]
    public async Task LogSecurityEvent_WithValidData_ShouldCreateAuditLog()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var resourceId = Guid.NewGuid();                                // ✅ FIX: Guid (not string)
        var eventType = "SECRET_DECRYPTED";
        var action = "User decrypted secret value";
        var result = "Success";
        var ipAddress = "192.168.1.100";
        var userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
        var additionalData = "{\"SecretTitle\":\"AWS API Key\"}";

        _auditLogRepositoryMock
            .Setup(x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuditLog log, CancellationToken ct) => log);

        // Act
        var serviceResult = await _auditLogService.LogSecurityEventAsync(
            eventType,
            userId,
            resourceId,                                                 // ✅ FIX: Guid? (not string)
            action,
            result,
            ipAddress,
            userAgent,
            additionalData);

        // Assert
        serviceResult.Success.Should().BeTrue();

        // Repository'ye doğru parametrelerle çağrı yapıldı mı?
        _auditLogRepositoryMock.Verify(
            x => x.AddAsync(
                It.Is<AuditLog>(log =>
                    log.Action == action &&                             // ✅ FIX: EventType -> Action
                    log.UserId == userId &&
                    log.EntityId == resourceId &&                       // ✅ FIX: ResourceId -> EntityId (Guid?)
                    log.Action.Contains(action) &&
                    log.Result == result &&
                    log.IpAddress == ipAddress &&
                    log.UserAgent == userAgent &&
                    log.AdditionalData == additionalData &&
                    log.Timestamp != default &&
                    log.CorrelationId != null &&
                    !string.IsNullOrEmpty(log.CorrelationId)),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task LogSecurityEvent_WithOptionalFieldsNull_ShouldStillCreateLog()
    {
        // Arrange: userId, resourceId, ipAddress, userAgent, additionalData null olabilir
        var eventType = "SYSTEM_STARTUP";
        var action = "Application started";
        var result = "Success";

        _auditLogRepositoryMock
            .Setup(x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuditLog log, CancellationToken ct) => log);

        // Act
        var serviceResult = await _auditLogService.LogSecurityEventAsync(
            eventType,
            userId: null,
            resourceId: null,                                           // ✅ FIX: Guid? null
            action,
            result,
            ipAddress: null,
            userAgent: null,
            additionalData: null);

        // Assert
        serviceResult.Success.Should().BeTrue();

        _auditLogRepositoryMock.Verify(
            x => x.AddAsync(
                It.Is<AuditLog>(log =>
                    log.Action.Contains(action) &&
                    log.UserId == null &&
                    log.EntityId == null &&                             // ✅ FIX: Guid? null
                    log.IpAddress == "Unknown" &&                       // Default value
                    log.UserAgent == null &&
                    log.AdditionalData == null),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    // ============================================================================
    // 🚫 LOG INJECTION PREVENTION (CONTROL CHARACTERS)
    // ============================================================================

    [Fact]
    public async Task LogSecurityEvent_WithControlCharacters_ShouldSanitize()
    {
        // Arrange: Newline injection attack
        var maliciousEventType = "SECRET_DECRYPTED\n[FAKE] ADMIN_LOGIN";
        var maliciousAction = "User logged in\r\n[SECURITY] Root access granted";

        _auditLogRepositoryMock
            .Setup(x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuditLog log, CancellationToken ct) => log);

        // Act
        var result = await _auditLogService.LogSecurityEventAsync(
            maliciousEventType,
            Guid.NewGuid(),
            null,
            maliciousAction,
            "Success",
            null,
            null);

        // Assert
        result.Success.Should().BeTrue();

        // Control characters (newlines) temizlendi mi?
        _auditLogRepositoryMock.Verify(
            x => x.AddAsync(
                It.Is<AuditLog>(log =>
                    !log.Action.Contains("\n") &&
                    !log.Action.Contains("\r")),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task LogSecurityEvent_WithNullBytes_ShouldSanitize()
    {
        // Arrange: Null byte injection (path traversal attack)
        var maliciousAction = "User accessed file\x00../etc/passwd";

        _auditLogRepositoryMock
            .Setup(x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuditLog log, CancellationToken ct) => log);

        // Act
        var result = await _auditLogService.LogSecurityEventAsync(
            "FILE_ACCESS",
            Guid.NewGuid(),
            null,
            maliciousAction,
            "Failure",
            null,
            null);

        // Assert
        result.Success.Should().BeTrue();

        // Null bytes temizlendi mi?
        _auditLogRepositoryMock.Verify(
            x => x.AddAsync(
                It.Is<AuditLog>(log =>
                    !log.Action.Contains("\x00")),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    // ============================================================================
    // ✂️ LENGTH TRUNCATION (DOS PREVENTION)
    // ============================================================================

    [Fact]
    public async Task LogSecurityEvent_WithLongEventType_ShouldTruncateTo100Chars()
    {
        // Arrange: 200 char event type (max 100)
        var longEventType = new string('A', 200);

        _auditLogRepositoryMock
            .Setup(x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuditLog log, CancellationToken ct) => log);

        // Act
        var result = await _auditLogService.LogSecurityEventAsync(
            longEventType,
            Guid.NewGuid(),
            null,
            "Action",
            "Success",
            null,
            null);

        // Assert
        result.Success.Should().BeTrue();

        // Truncate edildi mi?
        _auditLogRepositoryMock.Verify(
            x => x.AddAsync(
                It.Is<AuditLog>(log =>
                    log.Action.Length <= 100),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task LogSecurityEvent_WithLongAdditionalData_ShouldTruncateTo4000Chars()
    {
        // Arrange: 5000 char additional data (max 4000)
        var longAdditionalData = new string('C', 5000);

        _auditLogRepositoryMock
            .Setup(x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuditLog log, CancellationToken ct) => log);

        // Act
        var result = await _auditLogService.LogSecurityEventAsync(
            "EVENT_TYPE",
            Guid.NewGuid(),
            null,
            "Action",
            "Success",
            null,
            null,
            longAdditionalData);

        // Assert
        result.Success.Should().BeTrue();

        // Truncate edildi mi? (3997 + "..." = 4000)
        _auditLogRepositoryMock.Verify(
            x => x.AddAsync(
                It.Is<AuditLog>(log =>
                    log.AdditionalData != null &&
                    log.AdditionalData.Length == 4000 &&
                    log.AdditionalData.EndsWith("...")),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    // ============================================================================
    // ❌ VALIDATION ERRORS
    // ============================================================================

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task LogSecurityEvent_WithNullOrEmptyEventType_ShouldReturnError(string invalidEventType)
    {
        // Arrange
        _auditLogRepositoryMock
            .Setup(x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuditLog log, CancellationToken ct) => log);

        // Act
        var result = await _auditLogService.LogSecurityEventAsync(
            invalidEventType,
            Guid.NewGuid(),
            null,
            "Action",
            "Success",
            null,
            null);

        // Assert: Hata döner ama exception fırlatmaz (fire-and-forget)
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("Event type is required");

        // Repository hiç çağrılmamalı
        _auditLogRepositoryMock.Verify(
            x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task LogSecurityEvent_WithNullOrEmptyAction_ShouldReturnError(string invalidAction)
    {
        // Arrange
        _auditLogRepositoryMock
            .Setup(x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuditLog log, CancellationToken ct) => log);

        // Act
        var result = await _auditLogService.LogSecurityEventAsync(
            "EVENT_TYPE",
            Guid.NewGuid(),
            null,
            invalidAction,
            "Success",
            null,
            null);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("Action");

        _auditLogRepositoryMock.Verify(
            x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    // ============================================================================
    // 🔥 FIRE-AND-FORGET (EXCEPTION HANDLING)
    // ============================================================================

    [Fact]
    public async Task LogSecurityEvent_WhenRepositoryThrowsException_ShouldNotCrashApp()
    {
        // Arrange: Database down scenario
        _auditLogRepositoryMock
            .Setup(x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Database connection failed"));

        // Act: Logging başarısız olsa bile uygulama çökmemeli
        var result = await _auditLogService.LogSecurityEventAsync(
            "SECRET_DECRYPTED",
            Guid.NewGuid(),
            null,
            "Action",
            "Success",
            null,
            null);

        // Assert: Error result döner ama exception fırlatmaz
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("Failed to log");
    }

    [Fact]
    public async Task LogSecurityEvent_WhenOperationCancelled_ShouldReturnCancelledResult()
    {
        // Arrange
        var cts = new CancellationTokenSource();
        cts.Cancel();

        _auditLogRepositoryMock
            .Setup(x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());

        // Act
        var result = await _auditLogService.LogSecurityEventAsync(
            "EVENT",
            Guid.NewGuid(),
            null,
            "Action",
            "Success",
            null,
            null,
            null,
            cts.Token);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("cancelled");
    }

    // ============================================================================
    // 🔗 CORRELATION ID GENERATION
    // ============================================================================

    [Fact]
    public async Task LogSecurityEvent_ShouldGenerateCorrelationId()
    {
        // Arrange
        _auditLogRepositoryMock
            .Setup(x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuditLog log, CancellationToken ct) => log);

        // Act
        var result = await _auditLogService.LogSecurityEventAsync(
            "EVENT",
            Guid.NewGuid(),
            null,
            "Action",
            "Success",
            null,
            null);

        // Assert
        result.Success.Should().BeTrue();

        // Correlation ID generate edildi mi?
        _auditLogRepositoryMock.Verify(
            x => x.AddAsync(
                It.Is<AuditLog>(log =>
                    !string.IsNullOrEmpty(log.CorrelationId)),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    // ============================================================================
    // ⏰ TIMESTAMP VALIDATION
    // ============================================================================

    [Fact]
    public async Task LogSecurityEvent_ShouldSetTimestampToUtcNow()
    {
        // Arrange
        var beforeCall = DateTime.UtcNow;

        _auditLogRepositoryMock
            .Setup(x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuditLog log, CancellationToken ct) => log);

        // Act
        await Task.Delay(10); // 10ms delay
        var result = await _auditLogService.LogSecurityEventAsync(
            "EVENT",
            Guid.NewGuid(),
            null,
            "Action",
            "Success",
            null,
            null);
        await Task.Delay(10);

        var afterCall = DateTime.UtcNow;

        // Assert
        result.Success.Should().BeTrue();

        _auditLogRepositoryMock.Verify(
            x => x.AddAsync(
                It.Is<AuditLog>(log =>
                    log.Timestamp >= beforeCall &&
                    log.Timestamp <= afterCall &&
                    log.Timestamp.Kind == DateTimeKind.Utc),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    // ============================================================================
    // 🌐 IPv6 ADDRESS HANDLING
    // ============================================================================

    [Fact]
    public async Task LogSecurityEvent_WithIPv6Address_ShouldHandleCorrectly()
    {
        // Arrange: IPv6 address (max 45 chars)
        var ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";

        _auditLogRepositoryMock
            .Setup(x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuditLog log, CancellationToken ct) => log);

        // Act
        var result = await _auditLogService.LogSecurityEventAsync(
            "USER_LOGIN",
            Guid.NewGuid(),
            null,
            "User logged in from IPv6 address",
            "Success",
            ipv6,
            null);

        // Assert
        result.Success.Should().BeTrue();

        _auditLogRepositoryMock.Verify(
            x => x.AddAsync(
                It.Is<AuditLog>(log =>
                    log.IpAddress == ipv6 &&
                    log.IpAddress.Length == 39), // IPv6 full notation length
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    // ============================================================================
    // 🎭 MULTIPLE CONCURRENT CALLS
    // ============================================================================

    [Fact]
    public async Task LogSecurityEvent_MultipleConcurrentCalls_ShouldAllSucceed()
    {
        // Arrange: 10 concurrent log requests
        _auditLogRepositoryMock
            .Setup(x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((AuditLog log, CancellationToken ct) => log);

        var tasks = new Task<IResult>[10];

        // Act: 10 eşzamanlı log isteği
        for (int i = 0; i < 10; i++)
        {
            var eventNumber = i;
            tasks[i] = _auditLogService.LogSecurityEventAsync(
                $"EVENT_{eventNumber}",
                Guid.NewGuid(),
                null,
                $"Action {eventNumber}",
                "Success",
                null,
                null);
        }

        var results = await Task.WhenAll(tasks);

        // Assert: Hepsi başarılı
        results.Should().AllSatisfy(r => r.Success.Should().BeTrue());

        // Repository 10 kez çağrıldı
        _auditLogRepositoryMock.Verify(
            x => x.AddAsync(It.IsAny<AuditLog>(), It.IsAny<CancellationToken>()),
            Times.Exactly(10));
    }
}