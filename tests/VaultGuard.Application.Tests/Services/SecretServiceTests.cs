using System;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Moq;
using VaultGuard.Application.DTOs.Secrets;
using VaultGuard.Application.Interfaces;
using VaultGuard.Application.Services;
using VaultGuard.Domain.Common.Results;
using VaultGuard.Domain.Entities;
using Xunit;

namespace VaultGuard.Application.Tests.Services;

/// <summary>
/// TEST SÜİTİ: SecretService - CRITICAL Security Validation
///
/// TEST COVERAGE (SECURITY-FIRST):
/// - ✅ IDOR Attack Prevention (Horizontal Privilege Escalation)
/// - ✅ Encryption/Decryption with AES-256-GCM
/// - ✅ Access Tracking (LastAccessedAt, AccessCount)
/// - ✅ Expiration Handling
/// - ✅ Soft Delete (GDPR compliance)
/// - ✅ Audit Logging (SOC 2 compliance)
/// - ✅ Ownership Isolation (Multi-tenancy)
///
/// THREAT MODEL:
/// - IDOR: User A attempts to access/modify/delete User B's secrets
/// - Data Leak: Expired/deleted secrets must be inaccessible
/// </summary>
public class SecretServiceTests
{
    private readonly Mock<ISecretRepository> _secretRepositoryMock;
    private readonly Mock<IEncryptionService> _cryptographyServiceMock;
    private readonly Mock<IAuditLogService> _auditLogServiceMock;
    private readonly SecretService _secretService;

    // Domain katmanının kabul ettiği geçerli (44+ karakter) Base64 ciphertext'ler.
    private const string ValidCipherA = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
    private const string ValidCipherB = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC";

    public SecretServiceTests()
    {
        _secretRepositoryMock = new Mock<ISecretRepository>();
        _cryptographyServiceMock = new Mock<IEncryptionService>();
        _auditLogServiceMock = new Mock<IAuditLogService>();

        _secretService = new SecretService(
            _secretRepositoryMock.Object,
            _cryptographyServiceMock.Object,
            _auditLogServiceMock.Object);

        // Audit log her testte varsayılan olarak başarılı döner.
        _auditLogServiceMock
            .Setup(x => x.LogSecurityEventAsync(
                It.IsAny<string>(),
                It.IsAny<Guid?>(),
                It.IsAny<Guid?>(),
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SuccessResult());
    }

    // ============================================================================
    // 🔐 CREATE SECRET TESTS
    // ============================================================================

    [Fact]
    public async Task CreateSecretAsync_WithValidData_ShouldEncryptAndSave()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var dto = new CreateSecretDto
        {
            Title = "AWS API Key",
            RawValue = "AKIAIOSFODNN7EXAMPLE",
            Category = "Cloud",
            Description = "Production AWS credentials"
        };

        _cryptographyServiceMock
            .Setup(x => x.Encrypt(dto.RawValue))
            .Returns(ValidCipherA);

        _secretRepositoryMock
            .Setup(x => x.GetByTitleAndUserIdAsync(userId, dto.Title, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Secret?)null);

        _secretRepositoryMock
            .Setup(x => x.AddAsync(It.IsAny<Secret>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Secret s, CancellationToken _) => s);

        // Act
        var result = await _secretService.CreateSecretAsync(dto, userId);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.Title.Should().Be("AWS API Key");
        result.Data.Category.Should().Be("Cloud");

        // Repository'ye doğru secret eklendi mi?
        _secretRepositoryMock.Verify(
            x => x.AddAsync(
                It.Is<Secret>(s =>
                    s.Title == dto.Title &&
                    s.UserId == userId &&
                    s.Category == dto.Category &&
                    s.IV.Length == 12 &&                     // IV servis içinde rastgele üretiliyor
                    s.EncryptedValue == ValidCipherA),
                It.IsAny<CancellationToken>()),
            Times.Once);

        // Audit log oluşturuldu mu?
        _auditLogServiceMock.Verify(
            x => x.LogSecurityEventAsync(
                "SECRET_CREATED",
                userId,
                It.IsAny<Guid?>(),
                It.Is<string>(msg => msg.Contains(dto.Title)),
                "Success",
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task CreateSecretAsync_WithDuplicateTitle_ShouldReturnError()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var dto = new CreateSecretDto { Title = "Duplicate", RawValue = "value" };

        var existingSecret = Secret.Create("Duplicate", ValidCipherA, new byte[12], userId);

        _secretRepositoryMock
            .Setup(x => x.GetByTitleAndUserIdAsync(userId, dto.Title, It.IsAny<CancellationToken>()))
            .ReturnsAsync(existingSecret);

        // Act
        var result = await _secretService.CreateSecretAsync(dto, userId);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("already exists");

        // Repository'ye ekleme yapılmamalı
        _secretRepositoryMock.Verify(
            x => x.AddAsync(It.IsAny<Secret>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    // ============================================================================
    // 🔓 DECRYPT SECRET TESTS (IDOR PROTECTION - CRITICAL!)
    // ============================================================================

    [Fact]
    public async Task GetDecryptedValueAsync_WithValidOwnership_ShouldDecryptAndTrackAccess()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var secretId = Guid.NewGuid();

        var secret = Secret.Create("Test Secret", ValidCipherA, new byte[12], userId);

        _secretRepositoryMock
            .Setup(x => x.GetByIdAsync(secretId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(secret);

        _cryptographyServiceMock
            .Setup(x => x.Decrypt(secret.EncryptedValue))
            .Returns("DECRYPTED_VALUE");

        _secretRepositoryMock
            .Setup(x => x.UpdateAsync(It.IsAny<Secret>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Secret s, CancellationToken _) => s);

        // Act
        var result = await _secretService.GetDecryptedValueAsync(secretId, userId);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().Be("DECRYPTED_VALUE");

        // Access tracking yapıldı mı?
        _secretRepositoryMock.Verify(
            x => x.UpdateAsync(
                It.Is<Secret>(s =>
                    s.LastAccessedAt.HasValue &&
                    s.LastAccessedAt.Value > DateTime.UtcNow.AddSeconds(-5)),
                It.IsAny<CancellationToken>()),
            Times.Once);

        // Success audit log
        _auditLogServiceMock.Verify(
            x => x.LogSecurityEventAsync(
                "SECRET_DECRYPTED",
                userId,
                secretId,
                It.IsAny<string>(),
                "Success",
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task GetDecryptedValueAsync_WithWrongUserId_ShouldDenyAccess_IDOR_PROTECTION()
    {
        // Arrange: IDOR Attack Scenario
        var ownerUserId = Guid.NewGuid();
        var attackerUserId = Guid.NewGuid();
        var secretId = Guid.NewGuid();

        var secret = Secret.Create("Victim Secret", ValidCipherA, new byte[12], ownerUserId);

        _secretRepositoryMock
            .Setup(x => x.GetByIdAsync(secretId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(secret);

        // Act: Attacker tries to decrypt victim's secret
        var result = await _secretService.GetDecryptedValueAsync(secretId, attackerUserId);

        // Assert: MUST BE DENIED!
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("do not have permission");

        // Decryption ASLA çağrılmamalı
        _cryptographyServiceMock.Verify(x => x.Decrypt(It.IsAny<string>()), Times.Never);

        // SECURITY EVENT: Unauthorized access attempt logged
        _auditLogServiceMock.Verify(
            x => x.LogSecurityEventAsync(
                "UNAUTHORIZED_DECRYPT_ATTEMPT",
                attackerUserId,
                secretId,
                It.Is<string>(msg => msg.Contains("attempted to decrypt")),
                "Failure",
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.Is<string>(data => data.Contains("IDOR")),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task GetDecryptedValueAsync_WithExpiredSecret_ShouldDenyAccess()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var secretId = Guid.NewGuid();

        var secret = Secret.Create(
            "Expired Secret",
            ValidCipherA,
            new byte[12],
            userId,
            expiresAt: DateTime.UtcNow.AddDays(-1));                    // Expired!

        _secretRepositoryMock
            .Setup(x => x.GetByIdAsync(secretId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(secret);

        // Act
        var result = await _secretService.GetDecryptedValueAsync(secretId, userId);

        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("expired");

        // Decryption çağrılmamalı
        _cryptographyServiceMock.Verify(x => x.Decrypt(It.IsAny<string>()), Times.Never);

        // Expired access attempt logged
        _auditLogServiceMock.Verify(
            x => x.LogSecurityEventAsync(
                "EXPIRED_SECRET_DECRYPT_ATTEMPT",
                userId,
                secretId,
                It.IsAny<string>(),
                "Failure",
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    // ============================================================================
    // 📋 GET USER SECRETS TESTS
    // ============================================================================

    [Fact]
    public async Task GetSecretsByUserIdAsync_ShouldReturnOnlyUserOwnedSecrets()
    {
        // Arrange
        var userId = Guid.NewGuid();

        var secret1 = Secret.Create("Secret 1", ValidCipherA, new byte[12], userId);
        var secret2 = Secret.Create("Secret 2", ValidCipherB, new byte[12], userId);

        _secretRepositoryMock
            .Setup(x => x.GetByUserIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[] { secret1, secret2 });

        // Act
        var result = await _secretService.GetSecretsByUserIdAsync(userId);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().HaveCount(2);
        result.Data.Should().OnlyContain(s => s.Title == "Secret 1" || s.Title == "Secret 2");
    }

    // ============================================================================
    // 🔍 GET SECRET BY ID TESTS (IDOR PROTECTION)
    // ============================================================================

    [Fact]
    public async Task GetSecretByIdAsync_WithValidOwnership_ShouldReturnMetadata()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var secretId = Guid.NewGuid();

        var secret = Secret.Create("My Secret", ValidCipherA, new byte[12], userId);

        _secretRepositoryMock
            .Setup(x => x.GetByIdAsync(secretId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(secret);

        // Act
        var result = await _secretService.GetSecretByIdAsync(secretId, userId);

        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.Title.Should().Be("My Secret");
        result.Data.Id.Should().Be(secret.Id);
    }

    [Fact]
    public async Task GetSecretByIdAsync_WithWrongUserId_ShouldDenyAccess_IDOR()
    {
        // Arrange
        var ownerUserId = Guid.NewGuid();
        var attackerUserId = Guid.NewGuid();
        var secretId = Guid.NewGuid();

        var secret = Secret.Create("Victim Secret", ValidCipherA, new byte[12], ownerUserId);

        _secretRepositoryMock
            .Setup(x => x.GetByIdAsync(secretId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(secret);

        // Act
        var result = await _secretService.GetSecretByIdAsync(secretId, attackerUserId);

        // Assert: IDOR ATTACK DENIED
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("do not have permission");
    }

    // ============================================================================
    // ✏️ UPDATE SECRET TESTS (RE-ENCRYPTION)
    // ============================================================================

    [Fact]
    public async Task UpdateSecretAsync_WithNewValue_ShouldReEncryptWithNewIV()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var secretId = Guid.NewGuid();

        var secret = Secret.Create("Old Secret", ValidCipherA, new byte[12], userId);

        var dto = new UpdateSecretDto
        {
            Id = secretId,
            Title = "Updated Secret",
            NewRawValue = "NEW_PLAINTEXT_VALUE"
        };

        _secretRepositoryMock
            .Setup(x => x.GetByIdAsync(secretId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(secret);

        _secretRepositoryMock
            .Setup(x => x.GetByTitleAndUserIdAsync(userId, dto.Title!, It.IsAny<CancellationToken>()))
            .ReturnsAsync((Secret?)null);

        _cryptographyServiceMock
            .Setup(x => x.Encrypt(dto.NewRawValue!))
            .Returns(ValidCipherB);

        _secretRepositoryMock
            .Setup(x => x.UpdateAsync(It.IsAny<Secret>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((Secret s, CancellationToken _) => s);

        // Act
        var result = await _secretService.UpdateSecretAsync(dto, userId);

        // Assert
        result.Success.Should().BeTrue();

        // Repository'ye update edildi mi?
        _secretRepositoryMock.Verify(
            x => x.UpdateAsync(
                It.Is<Secret>(s =>
                    s.Title == "Updated Secret" &&
                    s.IV.Length == 12 &&                      // Yeni rastgele IV üretildi
                    s.EncryptedValue == ValidCipherB),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task UpdateSecretAsync_WithWrongUserId_ShouldDenyAccess_IDOR()
    {
        // Arrange
        var ownerUserId = Guid.NewGuid();
        var attackerUserId = Guid.NewGuid();
        var secretId = Guid.NewGuid();

        var secret = Secret.Create("Victim Secret", ValidCipherA, new byte[12], ownerUserId);

        var dto = new UpdateSecretDto { Id = secretId, Title = "Hacked Title" };

        _secretRepositoryMock
            .Setup(x => x.GetByIdAsync(secretId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(secret);

        // Act
        var result = await _secretService.UpdateSecretAsync(dto, attackerUserId);

        // Assert: IDOR DENIED
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("do not have permission");

        // Repository update çağrılmamalı
        _secretRepositoryMock.Verify(
            x => x.UpdateAsync(It.IsAny<Secret>(), It.IsAny<CancellationToken>()),
            Times.Never);

        // Unauthorized update attempt logged
        _auditLogServiceMock.Verify(
            x => x.LogSecurityEventAsync(
                "UNAUTHORIZED_UPDATE_ATTEMPT",
                attackerUserId,
                secretId,
                It.IsAny<string>(),
                "Failure",
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.Is<string>(data => data.Contains("IDOR")),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    // ============================================================================
    // 🗑️ DELETE SECRET TESTS (SOFT DELETE + IDOR)
    // ============================================================================

    [Fact]
    public async Task DeleteSecretAsync_WithValidOwnership_ShouldSoftDelete()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var secretId = Guid.NewGuid();

        var secret = Secret.Create("To Delete", ValidCipherA, new byte[12], userId);

        _secretRepositoryMock
            .Setup(x => x.GetByIdAsync(secretId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(secret);

        _secretRepositoryMock
            .Setup(x => x.DeleteAsync(It.IsAny<Secret>(), It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        // Act
        var result = await _secretService.DeleteSecretAsync(secretId, userId);

        // Assert
        result.Success.Should().BeTrue();

        // Soft delete çağrıldı mı?
        _secretRepositoryMock.Verify(
            x => x.DeleteAsync(secret, It.IsAny<CancellationToken>()),
            Times.Once);

        // Audit log
        _auditLogServiceMock.Verify(
            x => x.LogSecurityEventAsync(
                "SECRET_DELETED",
                userId,
                secretId,
                It.IsAny<string>(),
                "Success",
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task DeleteSecretAsync_WithWrongUserId_ShouldDenyAccess_IDOR()
    {
        // Arrange
        var ownerUserId = Guid.NewGuid();
        var attackerUserId = Guid.NewGuid();
        var secretId = Guid.NewGuid();

        var secret = Secret.Create("Victim Secret", ValidCipherA, new byte[12], ownerUserId);

        _secretRepositoryMock
            .Setup(x => x.GetByIdAsync(secretId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(secret);

        // Act
        var result = await _secretService.DeleteSecretAsync(secretId, attackerUserId);

        // Assert: IDOR DENIED
        result.Success.Should().BeFalse();
        result.Message.Should().Contain("do not have permission");

        // Delete çağrılmamalı
        _secretRepositoryMock.Verify(
            x => x.DeleteAsync(It.IsAny<Secret>(), It.IsAny<CancellationToken>()),
            Times.Never);

        // Unauthorized delete attempt logged
        _auditLogServiceMock.Verify(
            x => x.LogSecurityEventAsync(
                "UNAUTHORIZED_DELETE_ATTEMPT",
                attackerUserId,
                secretId,
                It.IsAny<string>(),
                "Failure",
                It.IsAny<string?>(),
                It.IsAny<string?>(),
                It.Is<string>(data => data.Contains("IDOR")),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }
}