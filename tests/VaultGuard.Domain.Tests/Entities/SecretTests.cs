using System;
using VaultGuard.Domain.Entities;
using Xunit;

namespace VaultGuard.Domain.Tests.Entities;

/// <summary>
/// Secret entity i�in kapsaml� unit test'ler.
/// .NET 9 ve Nullable Reference Types uyumlu.
/// �ifreleme, soft delete ve eri�im takibi testleri i�erir.
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
        var title = "My API Key";
        var encryptedValue = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"; // Base64 String
        var iv = new byte[12]; // 12 byte IV
        var userId = Guid.NewGuid();

        // Act
        var secret = Secret.Create(title, encryptedValue, iv, userId);

        // Assert
        Assert.NotNull(secret);
        Assert.Equal(title, secret.Title);
        Assert.Equal(encryptedValue, secret.EncryptedValue);
        Assert.Equal(iv, secret.IV);
        Assert.Equal(userId, secret.UserId);
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
        var encryptedValue = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
        var iv = new byte[12];
        var ownerId = Guid.NewGuid();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
        Secret.Create(invalidName!, encryptedValue, iv, ownerId));

        Assert.Equal("title", exception.ParamName);
        Assert.Contains("cannot be empty", exception.Message);
    }

    [Fact]
    public void Create_WithNameContainingWhitespace_ShouldTrimWhitespace()
    {
        // Arrange
        var name = "  My Secret  ";
        var encryptedValue = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
        var iv = new byte[12];
        var ownerId = Guid.NewGuid();

        // Act
        var secret = Secret.Create(name, encryptedValue, iv, ownerId);

        // Assert
        Assert.Equal("My Secret", secret.Title);
        Assert.DoesNotContain("  ", secret.Title);
    }

    // ============================================================================
    // ENCRYPTED DATA VALIDATION TESTS
    // ============================================================================

    [Fact]
    public void Create_WithNullEncryptedData_ShouldThrowArgumentException()
    {
        // Arrange
        var name = "My Secret";
        string? encryptedValue = null;
        var iv = new byte[12];
        var ownerId = Guid.NewGuid();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            Secret.Create(name, encryptedValue!, iv, ownerId));

        Assert.Equal("encryptedValue", exception.ParamName);
        Assert.Contains("cannot be empty", exception.Message);
    }

    [Fact]
    public void Create_WithEmptyEncryptedData_ShouldThrowArgumentException()
    {
        // Arrange
        var name = "My Secret";
        var encryptedValue = "";
        var iv = new byte[12];
        var ownerId = Guid.NewGuid();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
    Secret.Create(name, encryptedValue, iv, ownerId));

        Assert.Equal("encryptedValue", exception.ParamName);
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
        var encryptedValue = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
        byte[]? iv = null;
        var ownerId = Guid.NewGuid();

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            Secret.Create(name, encryptedValue, iv!, ownerId));

        Assert.Equal("iv", exception.ParamName);
       Assert.Contains("IV cannot be null or empty", exception.Message);
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
    var encryptedValue = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
    var iv = new byte[invalidLength];
    var ownerId = Guid.NewGuid();

    // Act & Assert
    var exception = Assert.Throws<ArgumentException>(() =>
        Secret.Create(name, encryptedValue, iv, ownerId));

    Assert.Equal("iv", exception.ParamName);
    // IV validation mesajı "IV cannot be null or empty" (invalidLength=0 için) 
    // veya "must be exactly 12 bytes" (diğer uzunluklar için) olabilir
    Assert.True(
        exception.Message.Contains("IV cannot be null or empty") || 
        exception.Message.Contains("must be exactly 12 bytes"),
        $"Exception message should mention IV validation, but got: {exception.Message}");
}

    [Fact]
    public void Create_WithValidIVLength_ShouldCreateSuccessfully()
    {
        // Arrange
        var name = "My Secret";
        var encryptedValue = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
        var iv = new byte[12]; // Exactly 12 bytes
        var ownerId = Guid.NewGuid();

        // Act
        var secret = Secret.Create(name, encryptedValue, iv, ownerId);

        // Assert
        Assert.NotNull(secret);
        Assert.Equal(12, secret.IV.Length);
    }

    // ============================================================================
    // OWNER ID VALIDATION TESTS
    // ============================================================================

    [Fact]
    public void Create_WithEmptyOwnerId_ShouldThrowArgumentException()
    {
        // Arrange
        var name = "My Secret";
        var encryptedValue = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
        var iv = new byte[12];
        var ownerId = Guid.Empty;

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            Secret.Create(name, encryptedValue, iv, ownerId));

        Assert.Equal("userId", exception.ParamName);
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
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            new byte[12],
            Guid.NewGuid());

        Assert.Null(secret.LastAccessedAt);

        var beforeAccess = DateTime.UtcNow;

        // Act
        secret.RecordAccess();

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
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            new byte[12],
            Guid.NewGuid());

        // Act
        secret.RecordAccess();
        var firstAccessTime = secret.LastAccessedAt;

        System.Threading.Thread.Sleep(10); // Small delay

        secret.RecordAccess();
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
    "Old Title",            // �sim Title olarak g�ncellendi (iste�e ba�l�)
    "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", // D�ZELT�LD�: Base64 string
    new byte[12],           // D�ZELT�LD�: 12 byte (GCM Standard�)
    Guid.NewGuid());

        var newName = "New Secret Name";

        // Act
        secret.UpdateTitle(newName);

        // Assert
        Assert.Equal(newName, secret.Title);
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
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            new byte[12],
            Guid.NewGuid());

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            secret.UpdateTitle(invalidName!));

        Assert.Equal("newTitle", exception.ParamName);
    }

    // ============================================================================
    // REENCRYPT METHOD TESTS
    // ============================================================================

    [Fact]
    public void ReEncrypt_WithValidData_ShouldUpdateEncryptedDataAndIV()
    {
        var originalValue = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
        var originalIV = new byte[12];
        var secret = Secret.Create(
            "My Secret",
            originalValue,
            originalIV,
            Guid.NewGuid());

        var newEncryptedValue = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC"; // 44 karakter geçerli Base64
        var newIV = new byte[12];

        // Act
        secret.ReEncrypt(newEncryptedValue, newIV);

        // Assert (Do�rulama k�sm�n� da unutma)
        Assert.Equal(newEncryptedValue, secret.EncryptedValue);
        Assert.Equal(newIV, secret.IV);
    }

    [Fact]
    public void ReEncrypt_WithNullEncryptedData_ShouldThrowArgumentException()
    {
        // Arrange
        var secret = Secret.Create(
            "My Secret",
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            new byte[12],
            Guid.NewGuid());

        string? newEncryptedValue = null;
        var newIV = new byte[12];

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            secret.ReEncrypt(newEncryptedValue!, newIV));

        Assert.Equal("newEncryptedValue", exception.ParamName);
    }

    [Fact]
    public void ReEncrypt_WithInvalidIVLength_ShouldThrowArgumentException()
    {
        // Arrange
        var secret = Secret.Create(
            "My Secret",
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            new byte[12],
            Guid.NewGuid());

        var newEncryptedValue = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC";
        var newIV = new byte[8]; // Invalid: should be 12

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            secret.ReEncrypt(newEncryptedValue, newIV));

        Assert.Equal("newIV", exception.ParamName);
        Assert.Contains("must be exactly 12 bytes", exception.Message);
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
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            new byte[12],
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
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            new byte[12],
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
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            new byte[12],
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
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            new byte[12],
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
    var userId = Guid.NewGuid();

    // Act
    var secret1 = Secret.Create("Secret 1", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", new byte[12], userId);
    var secret2 = Secret.Create("Secret 2", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", new byte[12], userId);
    var secret3 = Secret.Create("Secret 3", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", new byte[12], userId);

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
        "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",  // 44 char geçerli Base64
        new byte[12],
        Guid.NewGuid());

    Assert.False(secret.IsDeleted);
    Assert.Null(secret.LastAccessedAt);

    // Act - Access
    secret.RecordAccess();
    Assert.NotNull(secret.LastAccessedAt);

    // Act - Update Name
    secret.UpdateTitle("Staging API Key");
    Assert.Equal("Staging API Key", secret.Title);

    // Act - Re-encrypt (key rotation)
    var newEncryptedValue = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC";  // 44 char geçerli Base64
    var newIV = new byte[12];
    secret.ReEncrypt(newEncryptedValue, newIV);

    // Assert
    Assert.Equal(newEncryptedValue, secret.EncryptedValue);

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