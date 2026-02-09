using System;
using VaultGuard.Domain.Entities;
using Xunit;

namespace VaultGuard.Domain.Tests.Entities;

/// <summary>
/// Secret entity için kapsamlý unit test'ler.
/// .NET 9 ve Nullable Reference Types uyumlu.
/// Þifreleme, soft delete ve eriþim takibi testleri içerir.
/// </summary>
public class SecretTests
{
    // ============================================================================
    // CREATE METHOD TESTS
    // ============================================================================

    [Fact]
    public void Create_WithValidParameters_ShouldCreateSecret()
    {
        // Arrange
        var name = "My API Key";
        var encryptedData = new byte[] { 1, 2, 3, 4, 5 };
        var iv = new byte[16]; // AES-256 için 16 byte IV
        var ownerId = Guid.NewGuid();

        // Act
        var secret = Secret.Create(name, encryptedData, iv, ownerId);

        // Assert
        Assert.NotNull(secret);
        Assert.NotEqual(Guid.Empty, secret.Id);
        Assert.Equal(name, secret.Name);
        Assert.Equal(encryptedData, secret.EncryptedData);
        Assert.Equal(iv, secret.IV);
        Assert.Equal(ownerId, secret.OwnerId);
        Assert.False(secret.IsDeleted);
        Assert.Null(secret.LastAccessedAt);
        Assert.Null(secret.DeletedAt);
        Assert.True(secret.CreatedAt <= DateTime.UtcNow);
    }

    // ============================================================================
    // NAME VALIDATION TESTS
    // ============================================================================

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("   ")]
    public void Create_WithEmptyOrWhitespaceName_ShouldThrowArgumentException(string? invalidName)
    {
        // Arrange
        var encryptedData = new byte[] { 1, 2, 3 };
        var iv = new byte[16];
        var ownerId = Guid.NewGuid();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            Secret.Create(invalidName!, encryptedData, iv, ownerId));

        Assert.Equal("name", exception.ParamName);
        Assert.Contains("cannot be empty", exception.Message);
    }

    [Fact]
    public void Create_WithNameContainingWhitespace_ShouldTrimWhitespace()
    {
        // Arrange
        var name = "  My Secret  ";
        var encryptedData = new byte[] { 1, 2, 3 };
        var iv = new byte[16];
        var ownerId = Guid.NewGuid();

        // Act
        var secret = Secret.Create(name, encryptedData, iv, ownerId);

        // Assert
        Assert.Equal("My Secret", secret.Name);
        Assert.DoesNotContain("  ", secret.Name);
    }

    // ============================================================================
    // ENCRYPTED DATA VALIDATION TESTS
    // ============================================================================

    [Fact]
    public void Create_WithNullEncryptedData_ShouldThrowArgumentException()
    {
        // Arrange
        var name = "My Secret";
        byte[]? encryptedData = null;
        var iv = new byte[16];
        var ownerId = Guid.NewGuid();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            Secret.Create(name, encryptedData!, iv, ownerId));

        Assert.Equal("encryptedData", exception.ParamName);
        Assert.Contains("cannot be empty", exception.Message);
    }

    [Fact]
    public void Create_WithEmptyEncryptedData_ShouldThrowArgumentException()
    {
        // Arrange
        var name = "My Secret";
        var encryptedData = Array.Empty<byte>();
        var iv = new byte[16];
        var ownerId = Guid.NewGuid();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            Secret.Create(name, encryptedData, iv, ownerId));

        Assert.Equal("encryptedData", exception.ParamName);
        Assert.Contains("cannot be empty", exception.Message);
    }

    // ============================================================================
    // IV (INITIALIZATION VECTOR) VALIDATION TESTS
    // ============================================================================

    [Fact]
    public void Create_WithNullIV_ShouldThrowArgumentException()
    {
        // Arrange
        var name = "My Secret";
        var encryptedData = new byte[] { 1, 2, 3 };
        byte[]? iv = null;
        var ownerId = Guid.NewGuid();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            Secret.Create(name, encryptedData, iv!, ownerId));

        Assert.Equal("iv", exception.ParamName);
        Assert.Contains("must be exactly 16 bytes", exception.Message);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(8)]
    [InlineData(15)]
    [InlineData(17)]
    [InlineData(32)]
    public void Create_WithInvalidIVLength_ShouldThrowArgumentException(int invalidLength)
    {
        // Arrange
        var name = "My Secret";
        var encryptedData = new byte[] { 1, 2, 3 };
        var iv = new byte[invalidLength];
        var ownerId = Guid.NewGuid();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            Secret.Create(name, encryptedData, iv, ownerId));

        Assert.Equal("iv", exception.ParamName);
        Assert.Contains("must be exactly 16 bytes", exception.Message);
    }

    [Fact]
    public void Create_WithValidIVLength_ShouldCreateSuccessfully()
    {
        // Arrange
        var name = "My Secret";
        var encryptedData = new byte[] { 1, 2, 3 };
        var iv = new byte[16]; // Exactly 16 bytes
        var ownerId = Guid.NewGuid();

        // Act
        var secret = Secret.Create(name, encryptedData, iv, ownerId);

        // Assert
        Assert.NotNull(secret);
        Assert.Equal(16, secret.IV.Length);
    }

    // ============================================================================
    // OWNER ID VALIDATION TESTS
    // ============================================================================

    [Fact]
    public void Create_WithEmptyOwnerId_ShouldThrowArgumentException()
    {
        // Arrange
        var name = "My Secret";
        var encryptedData = new byte[] { 1, 2, 3 };
        var iv = new byte[16];
        var ownerId = Guid.Empty;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            Secret.Create(name, encryptedData, iv, ownerId));

        Assert.Equal("ownerId", exception.ParamName);
        Assert.Contains("cannot be empty", exception.Message);
    }

    // ============================================================================
    // MARKASACCESSED METHOD TESTS
    // ============================================================================

    [Fact]
    public void MarkAsAccessed_ShouldSetLastAccessedAt()
    {
        // Arrange
        var secret = Secret.Create(
            "My Secret",
            new byte[] { 1, 2, 3 },
            new byte[16],
            Guid.NewGuid());

        Assert.Null(secret.LastAccessedAt);

        var beforeAccess = DateTime.UtcNow;

        // Act
        secret.MarkAsAccessed();

        var afterAccess = DateTime.UtcNow;

        // Assert
        Assert.NotNull(secret.LastAccessedAt);
        Assert.InRange(secret.LastAccessedAt.Value, beforeAccess, afterAccess);
    }

    [Fact]
    public void MarkAsAccessed_CalledMultipleTimes_ShouldUpdateToMostRecentTime()
    {
        // Arrange
        var secret = Secret.Create(
            "My Secret",
            new byte[] { 1, 2, 3 },
            new byte[16],
            Guid.NewGuid());

        // Act
        secret.MarkAsAccessed();
        var firstAccessTime = secret.LastAccessedAt;

        System.Threading.Thread.Sleep(10); // Small delay

        secret.MarkAsAccessed();
        var secondAccessTime = secret.LastAccessedAt;

        // Assert
        Assert.NotNull(firstAccessTime);
        Assert.NotNull(secondAccessTime);
        Assert.True(secondAccessTime > firstAccessTime);
    }

    // ============================================================================
    // UPDATENAME METHOD TESTS
    // ============================================================================

    [Fact]
    public void UpdateName_WithValidName_ShouldUpdateName()
    {
        // Arrange
        var secret = Secret.Create(
            "Old Name",
            new byte[] { 1, 2, 3 },
            new byte[16],
            Guid.NewGuid());

        var newName = "New Secret Name";

        // Act
        secret.UpdateName(newName);

        // Assert
        Assert.Equal(newName, secret.Name);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("   ")]
    public void UpdateName_WithEmptyOrWhitespaceName_ShouldThrowArgumentException(string? invalidName)
    {
        // Arrange
        var secret = Secret.Create(
            "Old Name",
            new byte[] { 1, 2, 3 },
            new byte[16],
            Guid.NewGuid());

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            secret.UpdateName(invalidName!));

        Assert.Equal("newName", exception.ParamName);
    }

    // ============================================================================
    // REENCRYPT METHOD TESTS
    // ============================================================================

    [Fact]
    public void ReEncrypt_WithValidData_ShouldUpdateEncryptedDataAndIV()
    {
        // Arrange
        var originalData = new byte[] { 1, 2, 3 };
        var originalIV = new byte[16];
        var secret = Secret.Create(
            "My Secret",
            originalData,
            originalIV,
            Guid.NewGuid());

        var newEncryptedData = new byte[] { 4, 5, 6, 7 };
        var newIV = new byte[16];

        // Act
        secret.ReEncrypt(newEncryptedData, newIV);

        // Assert
        Assert.Equal(newEncryptedData, secret.EncryptedData);
        Assert.Equal(newIV, secret.IV);
        Assert.NotEqual(originalData, secret.EncryptedData);
    }

    [Fact]
    public void ReEncrypt_WithNullEncryptedData_ShouldThrowArgumentException()
    {
        // Arrange
        var secret = Secret.Create(
            "My Secret",
            new byte[] { 1, 2, 3 },
            new byte[16],
            Guid.NewGuid());

        byte[]? newEncryptedData = null;
        var newIV = new byte[16];

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            secret.ReEncrypt(newEncryptedData!, newIV));

        Assert.Equal("newEncryptedData", exception.ParamName);
    }

    [Fact]
    public void ReEncrypt_WithInvalidIVLength_ShouldThrowArgumentException()
    {
        // Arrange
        var secret = Secret.Create(
            "My Secret",
            new byte[] { 1, 2, 3 },
            new byte[16],
            Guid.NewGuid());

        var newEncryptedData = new byte[] { 4, 5, 6 };
        var newIV = new byte[8]; // Invalid: should be 16

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            secret.ReEncrypt(newEncryptedData, newIV));

        Assert.Equal("newIV", exception.ParamName);
        Assert.Contains("must be exactly 16 bytes", exception.Message);
    }

    // ============================================================================
    // SOFT DELETE TESTS
    // ============================================================================

    [Fact]
    public void MarkAsDeleted_ShouldSetIsDeletedAndDeletedAt()
    {
        // Arrange
        var secret = Secret.Create(
            "My Secret",
            new byte[] { 1, 2, 3 },
            new byte[16],
            Guid.NewGuid());

        Assert.False(secret.IsDeleted);
        Assert.Null(secret.DeletedAt);

        var beforeDeletion = DateTime.UtcNow;

        // Act
        secret.MarkAsDeleted();

        var afterDeletion = DateTime.UtcNow;

        // Assert
        Assert.True(secret.IsDeleted);
        Assert.NotNull(secret.DeletedAt);
        Assert.InRange(secret.DeletedAt.Value, beforeDeletion, afterDeletion);
    }

    [Fact]
    public void Restore_ShouldClearIsDeletedAndDeletedAt()
    {
        // Arrange
        var secret = Secret.Create(
            "My Secret",
            new byte[] { 1, 2, 3 },
            new byte[16],
            Guid.NewGuid());

        secret.MarkAsDeleted();
        Assert.True(secret.IsDeleted);
        Assert.NotNull(secret.DeletedAt);

        // Act
        secret.Restore();

        // Assert
        Assert.False(secret.IsDeleted);
        Assert.Null(secret.DeletedAt);
    }

    [Fact]
    public void Restore_OnNonDeletedSecret_ShouldWork()
    {
        // Arrange
        var secret = Secret.Create(
            "My Secret",
            new byte[] { 1, 2, 3 },
            new byte[16],
            Guid.NewGuid());

        Assert.False(secret.IsDeleted);

        // Act
        secret.Restore();

        // Assert
        Assert.False(secret.IsDeleted);
        Assert.Null(secret.DeletedAt);
    }

    // ============================================================================
    // TIMESTAMP TESTS
    // ============================================================================

    [Fact]
    public void Create_ShouldSetCreatedAtToCurrentUtcTime()
    {
        // Arrange
        var beforeCreation = DateTime.UtcNow;

        // Act
        var secret = Secret.Create(
            "My Secret",
            new byte[] { 1, 2, 3 },
            new byte[16],
            Guid.NewGuid());

        var afterCreation = DateTime.UtcNow;

        // Assert
        Assert.InRange(secret.CreatedAt, beforeCreation, afterCreation);
    }

    // ============================================================================
    // MULTIPLE SECRETS - UNIQUE IDS
    // ============================================================================

    [Fact]
    public void Create_MultipleSecrets_ShouldHaveUniqueIds()
    {
        // Arrange
        var ownerId = Guid.NewGuid();

        // Act
        var secret1 = Secret.Create("Secret 1", new byte[] { 1 }, new byte[16], ownerId);
        var secret2 = Secret.Create("Secret 2", new byte[] { 2 }, new byte[16], ownerId);
        var secret3 = Secret.Create("Secret 3", new byte[] { 3 }, new byte[16], ownerId);

        // Assert
        Assert.NotEqual(secret1.Id, secret2.Id);
        Assert.NotEqual(secret2.Id, secret3.Id);
        Assert.NotEqual(secret1.Id, secret3.Id);
    }

    // ============================================================================
    // INTEGRATION SCENARIO TEST
    // ============================================================================

    [Fact]
    public void Secret_CompleteLifecycle_ShouldWorkCorrectly()
    {
        // Arrange - Create
        var secret = Secret.Create(
            "Production API Key",
            new byte[] { 1, 2, 3, 4, 5 },
            new byte[16],
            Guid.NewGuid());

        Assert.False(secret.IsDeleted);
        Assert.Null(secret.LastAccessedAt);

        // Act - Access
        secret.MarkAsAccessed();
        Assert.NotNull(secret.LastAccessedAt);

        // Act - Update Name
        secret.UpdateName("Staging API Key");
        Assert.Equal("Staging API Key", secret.Name);

        // Act - Re-encrypt (key rotation)
        var newEncryptedData = new byte[] { 6, 7, 8, 9, 10 };
        var newIV = new byte[16];
        secret.ReEncrypt(newEncryptedData, newIV);
        Assert.Equal(newEncryptedData, secret.EncryptedData);

        // Act - Delete
        secret.MarkAsDeleted();
        Assert.True(secret.IsDeleted);
        Assert.NotNull(secret.DeletedAt);

        // Act - Restore
        secret.Restore();
        Assert.False(secret.IsDeleted);
        Assert.Null(secret.DeletedAt);

        // Assert - All operations successful
        Assert.NotNull(secret);
    }
}