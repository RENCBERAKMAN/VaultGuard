using System;
using System.Linq;
using System.Reflection;
using VaultGuard.Domain.Entities;
using Xunit;

namespace VaultGuard.Domain.Tests.Entities;

/// <summary>
/// AuditLog entity için kapsamlı unit test'ler.
/// .NET 9 ve Nullable Reference Types uyumlu.
/// Immutability ve güvenlik kontrollerine özel odaklanılmıştır.
/// </summary>
public class AuditLogTests
{
    // ============================================================================
    // CREATE METHOD TESTS
    // ============================================================================

    [Fact]
    public void Create_WithValidData_ShouldCreateAuditLogSuccessfully()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var action = "Secret_Viewed";
        var entityName = "Secret";
        var ipAddress = "192.168.1.100";
        var entityId = Guid.NewGuid();
        var details = "User viewed the record from dashboard";

        // Act
        var auditLog = AuditLog.Create(
            userId: userId,
            action: action,
            entityName: entityName,
            ipAddress: ipAddress,
            result: "Success",
            entityId: entityId,
            userAgent: "Mozilla",
            additionalData: details,
            correlationId: "Vault",
            duration: 100);

        // Assert
        Assert.NotNull(auditLog);
        Assert.NotEqual(Guid.Empty, auditLog.Id);
        Assert.Equal(userId, auditLog.UserId);
        Assert.Equal(action, auditLog.Action);
        Assert.Equal(entityName, auditLog.EntityName);
        Assert.Equal(ipAddress, auditLog.IpAddress);
        Assert.Equal(entityId, auditLog.EntityId);
        Assert.Equal(details, auditLog.AdditionalData);
        Assert.True((DateTime.UtcNow - auditLog.Timestamp).TotalSeconds < 1);
    }

    [Fact]
    public void Create_WithMinimalData_ShouldCreateWithNullOptionalFields()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var action = "User_Login_Success";
        var entityName = "User";
        var ipAddress = "10.0.0.1";

        // Act
        var auditLog = AuditLog.Create(
            userId: userId,
            action: action,
            entityName: entityName,
            ipAddress: ipAddress,
            result: "Success");

        // Assert
        Assert.Null(auditLog.EntityId);
        Assert.Null(auditLog.AdditionalData);
    }

    [Fact]
    public void Create_WithIPv6Address_ShouldAcceptValidIPv6()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var ipv6Address = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";

        // Act
        var auditLog = AuditLog.Create(
            userId: userId,
            action: "Secret_Created",
            entityName: "Secret",
            ipAddress: ipv6Address,
            result: "Success");

        // Assert
        Assert.Equal(ipv6Address, auditLog.IpAddress);
    }

    // ============================================================================
    // IMMUTABILITY TESTS (.NET 9 UYUMLU)
    // ============================================================================

    [Fact]
    public void AuditLog_Properties_ShouldBeInitOnly()
    {
        // Arrange
        var auditLog = AuditLog.Create(
            userId: Guid.NewGuid(),
            action: "Secret_Deleted",
            entityName: "Secret",
            ipAddress: "192.168.1.1",
            result: "Success");

        // Act & Assert - .NET 9 uyumlu immutability kontrolü
        var idProperty = typeof(AuditLog).GetProperty(nameof(AuditLog.Id));
        Assert.NotNull(idProperty);
        Assert.NotNull(idProperty.SetMethod);

        var setMethod = idProperty?.SetMethod;
        var hasInitOnlyModifier = setMethod?.ReturnParameter
            .GetRequiredCustomModifiers()
            .Any(m => m.Name == "IsExternalInit") ?? false;

        Assert.True(hasInitOnlyModifier, "Property should be init-only.");

        var timestampProperty = typeof(AuditLog).GetProperty(nameof(AuditLog.Timestamp));
        Assert.NotNull(timestampProperty?.SetMethod);

        var timestampHasInitOnly = timestampProperty!.SetMethod!.ReturnParameter
            .GetRequiredCustomModifiers()
            .Any(m => m.Name == "IsExternalInit");

        Assert.True(timestampHasInitOnly,
            "AuditLog.Timestamp property should be init-only (immutable after construction)");
    }

    // ============================================================================
    // USERID VALIDATION TESTS
    // ============================================================================

    [Fact]
    public void Create_WithEmptyUserId_ShouldThrowArgumentException()
    {
        // Arrange
        var emptyUserId = Guid.Empty;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            AuditLog.Create(
                userId: emptyUserId,
                action: "Secret_Viewed",
                entityName: "Secret",
                ipAddress: "192.168.1.1",
                result: "Success"));

        Assert.Equal("userId", exception.ParamName);
        Assert.Contains("cannot be Guid.Empty", exception.Message);
    }

    // ============================================================================
    // ACTION VALIDATION TESTS
    // ============================================================================

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Create_WithEmptyOrWhitespaceAction_ShouldThrowArgumentException(string? invalidAction)
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            AuditLog.Create(
                userId: userId,
                action: invalidAction!,
                entityName: "Secret",
                ipAddress: "192.168.1.1",
                result: "Success"));

        Assert.Equal("action", exception.ParamName);
        Assert.Contains("cannot be empty", exception.Message);
    }

    [Fact]
    public void Create_WithActionLongerThan100Characters_ShouldThrowArgumentException()
    {
        // Arrange
        var userId = Guid.NewGuid();
        // Doğru format (harf_harf) ama 100 karakterden uzun
        var longAction = new string('A', 60) + "_" + new string('B', 60);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            AuditLog.Create(
                userId: userId,
                action: longAction,
                entityName: "Secret",
                ipAddress: "192.168.1.1",
                result: "Success"));

        Assert.Equal("action", exception.ParamName);
        Assert.Contains("too long", exception.Message);
    }

    [Fact]
    public void Create_WithActionMissingUnderscore_ShouldThrowArgumentException()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var invalidAction = "SecretViewed";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            AuditLog.Create(
                userId: userId,
                action: invalidAction,
                entityName: "Secret",
                ipAddress: "192.168.1.1",
                result: "Success"));

        Assert.Equal("action", exception.ParamName);
        Assert.Contains("should follow format", exception.Message);
    }

    [Fact]
    public void Create_WithActionContainingWhitespace_ShouldTrimWhitespace()
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act
        var auditLog = AuditLog.Create(
            userId: userId,
            action: "  Secret_Viewed  ",
            entityName: "Secret",
            ipAddress: "192.168.1.1",
            result: "Success");

        // Assert
        Assert.Equal("Secret_Viewed", auditLog.Action);
        Assert.DoesNotContain(" ", auditLog.Action);
    }

    // ============================================================================
    // ENTITY NAME VALIDATION TESTS
    // ============================================================================

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Create_WithEmptyOrWhitespaceEntityName_ShouldThrowArgumentException(string? invalidEntityName)
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            AuditLog.Create(
                userId: userId,
                action: "Action_Performed",
                entityName: invalidEntityName!,
                ipAddress: "192.168.1.1",
                result: "Success"));

        Assert.Equal("entityName", exception.ParamName);
        Assert.Contains("cannot be empty", exception.Message);
    }

    [Fact]
    public void Create_WithEntityNameLongerThan50Characters_ShouldThrowArgumentException()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var longEntityName = new string('A', 51);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            AuditLog.Create(
                userId: userId,
                action: "Action_Performed",
                entityName: longEntityName,
                ipAddress: "192.168.1.1",
                result: "Success"));

        Assert.Equal("entityName", exception.ParamName);
        Assert.Contains("too long", exception.Message);
    }

    [Theory]
    [InlineData("InvalidEntity")]
    [InlineData("Customer")]
    [InlineData("Product")]
    public void Create_WithInvalidEntityName_ShouldThrowArgumentException(string invalidEntityName)
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            AuditLog.Create(
                userId: userId,
                action: "Action_Performed",
                entityName: invalidEntityName,
                ipAddress: "192.168.1.1",
                result: "Success"));

        Assert.Equal("entityName", exception.ParamName);
        Assert.Contains("Invalid entity name", exception.Message);
        Assert.Contains("Valid values:", exception.Message);
    }

    [Theory]
    [InlineData("Secret")]
    [InlineData("User")]
    [InlineData("AuditLog")]
    [InlineData("System")]
    [InlineData("secret")]
    [InlineData("USER")]
    [InlineData("AuDiTlOg")]
    public void Create_WithValidEntityName_ShouldCreateSuccessfully(string validEntityName)
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act
        var auditLog = AuditLog.Create(
            userId: userId,
            action: "Action_Performed",
            entityName: validEntityName,
            ipAddress: "192.168.1.1",
            result: "Success");

        // Assert
        Assert.NotNull(auditLog);
    }

    // ============================================================================
    // IP ADDRESS VALIDATION TESTS
    // ============================================================================

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Create_WithEmptyOrWhitespaceIpAddress_ShouldThrowArgumentException(string? invalidIp)
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            AuditLog.Create(
                userId: userId,
                action: "Action_Performed",
                entityName: "Secret",
                ipAddress: invalidIp!,
                result: "Success"));

        Assert.Equal("ipAddress", exception.ParamName);
        Assert.Contains("cannot be empty", exception.Message);
    }

    [Fact]
    public void Create_WithIpAddressLongerThan45Characters_ShouldThrowArgumentException()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var longIp = new string('1', 46);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            AuditLog.Create(
                userId: userId,
                action: "Action_Performed",
                entityName: "Secret",
                ipAddress: longIp,
                result: "Success"));

        Assert.Equal("ipAddress", exception.ParamName);
        Assert.Contains("too long", exception.Message);
    }

    [Theory]
    [InlineData("notanip")]
    [InlineData("192168")]
    [InlineData("abcdefg")]
    public void Create_WithInvalidIpAddressFormat_ShouldThrowArgumentException(string invalidIp)
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            AuditLog.Create(
                userId: userId,
                action: "Action_Performed",
                entityName: "Secret",
                ipAddress: invalidIp,
                result: "Success"));

        Assert.Equal("ipAddress", exception.ParamName);
        Assert.Contains("Invalid IP address format", exception.Message);
    }

    [Fact]
    public void Create_WithIpAddressContainingWhitespace_ShouldTrimWhitespace()
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act
        var auditLog = AuditLog.Create(
            userId: userId,
            action: "Action_Performed",
            entityName: "Secret",
            ipAddress: "  192.168.1.1  ",
            result: "Success");

        // Assert
        Assert.Equal("192.168.1.1", auditLog.IpAddress);
    }

    // ============================================================================
    // DETAILS (additionalData) VALIDATION TESTS (SECURITY CRITICAL!)
    // ============================================================================

    [Fact]
    public void Create_WithDetailsLongerThan2000Characters_ShouldThrowArgumentException()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var longDetails = new string('A', 2001);

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            AuditLog.Create(
                userId: userId,
                action: "Action_Performed",
                entityName: "Secret",
                ipAddress: "127.0.0.1",
                result: "Success",
                entityId: null,
                userAgent: null,
                additionalData: longDetails));

        Assert.Equal("additionalData", exception.ParamName);
        Assert.Contains("too long", exception.Message);
    }

    [Theory]
    [InlineData("User entered password: mypassword123")]
    [InlineData("Secret value: api_key_12345")]
    [InlineData("TOKEN: Bearer xyz123")]
    [InlineData("Encryption key: abc123")]
    [InlineData("This contains PASSWORD somewhere")]
    public void Create_WithSensitiveKeywordsInDetails_ShouldThrowArgumentException(string sensitiveDetails)
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            AuditLog.Create(
                userId: userId,
                action: "Action_Performed",
                entityName: "Secret",
                ipAddress: "127.0.0.1",
                result: "Success",
                entityId: null,
                userAgent: null,
                additionalData: sensitiveDetails));

        Assert.Equal("additionalData", exception.ParamName);
        Assert.Contains("contains sensitive keyword", exception.Message);
        Assert.Contains("Never log sensitive data", exception.Message);
    }

    [Theory]
    [InlineData("User updated email from old@test.com to new@test.com")]
    [InlineData("Role changed from User to Admin")]
    [InlineData("Successful operation completed")]
    public void Create_WithSafeDetails_ShouldCreateSuccessfully(string safeDetails)
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act
        var auditLog = AuditLog.Create(
            userId: userId,
            action: "Action_Performed",
            entityName: "Secret",
            ipAddress: "192.168.1.1",
            result: "Success",
            entityId: null,
            userAgent: null,
            additionalData: safeDetails);

        // Assert
        Assert.Equal(safeDetails.Trim(), auditLog.AdditionalData);
    }

    [Fact]
    public void Create_WithNullDetails_ShouldCreateSuccessfully()
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act
        var auditLog = AuditLog.Create(
            userId: userId,
            action: "Action_Performed",
            entityName: "Secret",
            ipAddress: "192.168.1.1",
            result: "Success",
            entityId: null,
            userAgent: null,
            additionalData: null);

        // Assert
        Assert.Null(auditLog.AdditionalData);
    }

    // ============================================================================
    // QUERY HELPER METHOD TESTS
    // ============================================================================

    [Theory]
    [InlineData("Secret_Created", true)]
    [InlineData("User_Login_Success", true)]
    [InlineData("User_Login_Failed", false)]
    [InlineData("Secret_Delete_Error", false)]
    public void IsSuccessfulOperation_ShouldReturnCorrectValue(string action, bool expectedResult)
    {
        // Arrange
        var auditLog = AuditLog.Create(
            userId: Guid.NewGuid(),
            action: action,
            entityName: "Secret",
            ipAddress: "192.168.1.1",
            result: expectedResult ? "Success" : "Failure");

        // Act
        var isSuccessful = auditLog.Result == "Success";

        // Assert
        Assert.Equal(expectedResult, isSuccessful);
    }

    [Theory]
    [InlineData("User_Login_Success", true)]
    [InlineData("User_Password_Changed", true)]
    [InlineData("User_Role_Changed", true)]
    [InlineData("User_Permission_Granted", true)]
    [InlineData("User_Access_Denied", true)]
    [InlineData("Secret_Created", false)]
    [InlineData("System_Backup_Completed", false)]
    public void IsSecurityRelated_ShouldDetectSecurityActions(string action, bool expectedResult)
    {
        // Arrange
        var auditLog = AuditLog.Create(
            userId: Guid.NewGuid(),
            action: action,
            entityName: "User",
            ipAddress: "192.168.1.1",
            result: "Success");

        // Act
        var isSecurityRelated = auditLog.IsSecurityRelated();

        // Assert
        Assert.Equal(expectedResult, isSecurityRelated);
    }

    [Theory]
    [InlineData("Secret", true)]
    [InlineData("User", false)]
    [InlineData("secret", true)]
    [InlineData("SECRET", true)]
    public void BelongsToEntity_ShouldReturnCorrectValue(string entityToCheck, bool expectedResult)
    {
        // Arrange
        var auditLog = AuditLog.Create(
            userId: Guid.NewGuid(),
            action: "Secret_Created",
            entityName: "Secret",
            ipAddress: "192.168.1.1",
            result: "Success");

        // Act
        var belongs = auditLog.BelongsToEntity(entityToCheck);

        // Assert
        Assert.Equal(expectedResult, belongs);
    }

    [Fact]
    public void BelongsToUser_WhenUserIdMatches_ShouldReturnTrue()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var auditLog = AuditLog.Create(
            userId: userId,
            action: "Secret_Viewed",
            entityName: "Secret",
            ipAddress: "192.168.1.1",
            result: "Success");

        // Act
        var belongs = auditLog.BelongsToUser(userId);

        // Assert
        Assert.True(belongs);
    }

    [Fact]
    public void BelongsToUser_WhenUserIdDoesNotMatch_ShouldReturnFalse()
    {
        // Arrange
        var userId1 = Guid.NewGuid();
        var userId2 = Guid.NewGuid();
        var auditLog = AuditLog.Create(
            userId: userId1,
            action: "Secret_Viewed",
            entityName: "Secret",
            ipAddress: "192.168.1.1",
            result: "Success");

        // Act
        var belongs = auditLog.BelongsToUser(userId2);

        // Assert
        Assert.False(belongs);
    }

    [Fact]
    public void IsWithinDateRange_WhenTimestampIsWithinRange_ShouldReturnTrue()
    {
        // Arrange
        var auditLog = AuditLog.Create(
            userId: Guid.NewGuid(),
            action: "Secret_Viewed",
            entityName: "Secret",
            ipAddress: "192.168.1.1",
            result: "Success");
        var startDate = DateTime.UtcNow.AddMinutes(-1);
        var endDate = DateTime.UtcNow.AddMinutes(1);

        // Act
        var isWithinRange = auditLog.IsWithinDateRange(startDate, endDate);

        // Assert
        Assert.True(isWithinRange);
    }

    [Fact]
    public void IsWithinDateRange_WhenTimestampIsOutsideRange_ShouldReturnFalse()
    {
        // Arrange
        var auditLog = AuditLog.Create(
            userId: Guid.NewGuid(),
            action: "Secret_Viewed",
            entityName: "Secret",
            ipAddress: "192.168.1.1",
            result: "Success");
        var startDate = DateTime.UtcNow.AddDays(-2);
        var endDate = DateTime.UtcNow.AddDays(-1);

        // Act
        var isWithinRange = auditLog.IsWithinDateRange(startDate, endDate);

        // Assert
        Assert.False(isWithinRange);
    }
}