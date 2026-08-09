using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Threading.Tasks;
using VaultGuard.Domain.Entities;
using VaultGuard.Infrastructure.Persistence;
using Xunit;

namespace VaultGuard.Infrastructure.Tests.Persistence;

/// <summary>
/// TEST SÜİTİ: SecretRepository - CRITICAL Data Isolation Tests
/// 
/// SECURITY FOCUS (KRİTİK!):
/// - **Ownership Isolation**: User A ASLA User B'nin secret'larını görememeli
/// - **Soft Delete**: Deleted secret'lar normal sorgularda GELMEMELİ
/// - **Data Leakage Prevention**: Cross-user data access engellenmeli
/// 
/// THREAT MODEL:
/// - Horizontal Privilege Escalation: User A → User B'nin verisi
/// - Data Breach: Deleted data leak (GDPR violation)
/// - IDOR Attack: Secret ID manipulation
/// 
/// COMPLIANCE:
/// - GDPR Article 32: Data protection by design
/// - SOC 2: Logical access controls
/// - PCI-DSS: Cardholder data isolation
/// </summary>
public class SecretRepositoryTests : RepositoryTestBase
{
    private readonly SecretRepository _repository;

    public SecretRepositoryTests()
    {
        _repository = new SecretRepository(Context);
    }

    // ====================================================================
    // HELPER METHOD: Generate random 12-byte IV
    // ====================================================================
    private static byte[] GenerateIV()
    {
        var iv = new byte[12];
        System.Security.Cryptography.RandomNumberGenerator.Fill(iv);
        return iv;
    }

    // ====================================================================
    // ✅ CREATE TESTS
    // ====================================================================

    [Fact]
    public async Task AddAsync_WithValidSecret_ShouldAddToDatabase()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var iv = GenerateIV(); // ✅ byte[] olarak oluşturuldu

        var secret = Secret.Create(
            title: "Test Secret",
            encryptedValue: "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
            iv: iv,
            userId: userId);

        // Act
        await _repository.AddAsync(secret);
        await Context.SaveChangesAsync();

        // Assert
        var savedSecret = await Context.Secrets.FirstOrDefaultAsync(s => s.Id == secret.Id);
        savedSecret.Should().NotBeNull();
        savedSecret!.Title.Should().Be("Test Secret");
        savedSecret.UserId.Should().Be(userId);
        savedSecret.IsDeleted.Should().BeFalse();
    }

    // ====================================================================
    // 🔒 OWNERSHIP ISOLATION TESTS (KRİTİK!)
    // ====================================================================

    [Fact]
    public async Task GetByUserIdAsync_ShouldReturnOnlyUserOwnedSecrets()
    {
        // Arrange
        var userA = Guid.NewGuid();
        var userB = Guid.NewGuid();

        var secretA1 = Secret.Create("Secret A1", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", GenerateIV(), userA);
        var secretA2 = Secret.Create("Secret A2", "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC", GenerateIV(), userA);
        var secretB1 = Secret.Create("Secret B1", "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0ND", GenerateIV(), userB);
        var secretB2 = Secret.Create("Secret B2", "RERERERERERERERERERERERERERERERERERERERERERE", GenerateIV(), userB);

        await _repository.AddAsync(secretA1);
        await _repository.AddAsync(secretA2);
        await _repository.AddAsync(secretB1);
        await _repository.AddAsync(secretB2);
        await Context.SaveChangesAsync();

        // Act
        var userASecrets = await _repository.GetByUserIdAsync(userA);

        // Assert
        userASecrets.Should().HaveCount(2);
        userASecrets.Should().OnlyContain(s => s.UserId == userA);
        userASecrets.Should().Contain(s => s.Title == "Secret A1");
        userASecrets.Should().Contain(s => s.Title == "Secret A2");
        userASecrets.Should().NotContain(s => s.UserId == userB);
    }

    [Fact]
    public async Task GetByUserIdAsync_WithWrongUserId_ShouldReturnEmpty()
    {
        // Arrange
        var userA = Guid.NewGuid();
        var userB = Guid.NewGuid();

        var secretA1 = Secret.Create("Secret A1", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", GenerateIV(), userA);

        await _repository.AddAsync(secretA1);
        await Context.SaveChangesAsync();

        // Act
        var userBSecrets = await _repository.GetByUserIdAsync(userB);

        // Assert
        userBSecrets.Should().BeEmpty();
        userBSecrets.Should().NotContain(s => s.UserId == userA);
    }

    [Fact]
    public async Task GetByUserIdAsync_WithMultipleUsers_ShouldIsolateData()
    {
        // Arrange
        var user1 = Guid.NewGuid();
        var user2 = Guid.NewGuid();
        var user3 = Guid.NewGuid();

        await _repository.AddAsync(Secret.Create("U1-S1", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", GenerateIV(), user1));
        await _repository.AddAsync(Secret.Create("U1-S2", "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC", GenerateIV(), user1));
        await _repository.AddAsync(Secret.Create("U2-S1", "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0ND", GenerateIV(), user2));
        await _repository.AddAsync(Secret.Create("U2-S2", "RERERERERERERERERERERERERERERERERERERERERERE", GenerateIV(), user2));
        await _repository.AddAsync(Secret.Create("U3-S1", "RUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVF", GenerateIV(), user3));
        await _repository.AddAsync(Secret.Create("U3-S2", "RkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZG", GenerateIV(), user3));
        await Context.SaveChangesAsync();

        // Act
        var user1Secrets = await _repository.GetByUserIdAsync(user1);
        var user2Secrets = await _repository.GetByUserIdAsync(user2);
        var user3Secrets = await _repository.GetByUserIdAsync(user3);

        // Assert
        user1Secrets.Should().HaveCount(2);
        user1Secrets.Should().OnlyContain(s => s.UserId == user1);

        user2Secrets.Should().HaveCount(2);
        user2Secrets.Should().OnlyContain(s => s.UserId == user2);

        user3Secrets.Should().HaveCount(2);
        user3Secrets.Should().OnlyContain(s => s.UserId == user3);

        user1Secrets.Should().NotContain(s => s.UserId == user2 || s.UserId == user3);
        user2Secrets.Should().NotContain(s => s.UserId == user1 || s.UserId == user3);
        user3Secrets.Should().NotContain(s => s.UserId == user1 || s.UserId == user2);
    }

    // ====================================================================
    // 🗑️ SOFT DELETE TESTS (KRİTİK!)
    // ====================================================================

    [Fact]
    public async Task GetByUserIdAsync_ShouldExcludeDeletedSecrets()
    {
        // Arrange
        var userId = Guid.NewGuid();

        var activeSecret = Secret.Create("Active Secret", "RkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZG", GenerateIV(), userId);
        var deletedSecret = Secret.Create("Deleted Secret", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", GenerateIV(), userId);
        deletedSecret.MarkAsDeleted();

        await _repository.AddAsync(activeSecret);
        await _repository.AddAsync(deletedSecret);
        await Context.SaveChangesAsync();

        // Act
        var secrets = await _repository.GetByUserIdAsync(userId);

        // Assert
        secrets.Should().HaveCount(1);
        secrets.Should().Contain(s => s.Title == "Active Secret");
        secrets.Should().NotContain(s => s.Title == "Deleted Secret");
        secrets.Should().OnlyContain(s => s.IsDeleted == false);
    }

    [Fact]
    public async Task GetByIdAsync_WithDeletedSecret_ShouldReturnNull()
    {
        // Arrange
        var userId = Guid.NewGuid();

        var secret = Secret.Create("Deleted Secret", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", GenerateIV(), userId);
        secret.MarkAsDeleted();

        await _repository.AddAsync(secret);
        await Context.SaveChangesAsync();

        // Act
        var foundSecret = await _repository.GetByIdAsync(secret.Id);

        // Assert
        foundSecret.Should().BeNull();
    }

    [Fact]
    public async Task DeleteAsync_ShouldMarkSecretAsDeleted()
    {
        // Arrange
        var userId = Guid.NewGuid();

        var secret = Secret.Create("To Delete", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", GenerateIV(), userId);

        await _repository.AddAsync(secret);
        await Context.SaveChangesAsync();

        // Act
        await _repository.DeleteAsync(secret);
        await Context.SaveChangesAsync();

        // Assert
        var deletedSecret = await Context.Secrets
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(s => s.Id == secret.Id);

        deletedSecret.Should().NotBeNull();
        deletedSecret!.IsDeleted.Should().BeTrue();
        deletedSecret.DeletedAt.Should().NotBeNull();
        deletedSecret.DeletedAt.Value.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    // ====================================================================
    // 🏷️ CATEGORIZATION TESTS
    // ====================================================================

    [Fact]
    public async Task GetByTitleAndUserIdAsync_WithExistingTitle_ShouldReturnSecret()
    {
        // Arrange
        var userId = Guid.NewGuid();

        var secret = Secret.Create("Unique Title", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", GenerateIV(), userId);

        await _repository.AddAsync(secret);
        await Context.SaveChangesAsync();

        // Act
        var foundSecret = await _repository.GetByTitleAndUserIdAsync(userId, "Unique Title");

        // Assert
        foundSecret.Should().NotBeNull();
        foundSecret!.Title.Should().Be("Unique Title");
        foundSecret.UserId.Should().Be(userId);
    }

    [Fact]
    public async Task GetByTitleAndUserIdAsync_WithSameTitle_ShouldIsolateByUserId()
    {
        // Arrange
        var userA = Guid.NewGuid();
        var userB = Guid.NewGuid();

        var secretA = Secret.Create("AWS Key", "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", GenerateIV(), userA);
        var secretB = Secret.Create("AWS Key", "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC", GenerateIV(), userB);

        await _repository.AddAsync(secretA);
        await _repository.AddAsync(secretB);
        await Context.SaveChangesAsync();

        // Act
        var foundSecret = await _repository.GetByTitleAndUserIdAsync(userA, "AWS Key");

        // Assert
        foundSecret.Should().NotBeNull();
        foundSecret!.UserId.Should().Be(userA);
        foundSecret.Id.Should().Be(secretA.Id);
        foundSecret.Id.Should().NotBe(secretB.Id);
    }

    // ====================================================================
    // 📊 COUNT TESTS
    // ====================================================================

    [Fact]
    public async Task GetCountByUserIdAsync_ShouldReturnCorrectCount()
    {
        // Arrange
        var userId = Guid.NewGuid();

        for (int i = 1; i <= 3; i++)
        {
            var secret = Secret.Create($"Secret {i}", "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC", GenerateIV(), userId);
            await _repository.AddAsync(secret);
        }
        await Context.SaveChangesAsync();

        // Act
        var count = await _repository.GetCountByUserIdAsync(userId);

        // Assert
        count.Should().Be(3);
    }

    [Fact]
    public async Task GetCountByUserIdAsync_ShouldExcludeDeletedSecrets()
    {
        // Arrange
        var userId = Guid.NewGuid();

        var active1 = Secret.Create("Active 1", "RUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVF", GenerateIV(), userId);
        var active2 = Secret.Create("Active 2", "RkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZG", GenerateIV(), userId);
        var deleted = Secret.Create("Deleted", "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC", GenerateIV(), userId);
        deleted.MarkAsDeleted();

        await _repository.AddAsync(active1);
        await _repository.AddAsync(active2);
        await _repository.AddAsync(deleted);
        await Context.SaveChangesAsync();

        // Act
        var count = await _repository.GetCountByUserIdAsync(userId);

        // Assert
        count.Should().Be(2);
    }

    // ====================================================================
    // 🔍 READ TESTS
    // ====================================================================

    [Fact]
    public async Task GetByIdAsync_WithExistingId_ShouldReturnSecret()
    {
        // Arrange
        var userId = Guid.NewGuid();

        var secret = Secret.Create("Test Secret", "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC", GenerateIV(), userId);

        await _repository.AddAsync(secret);
        await Context.SaveChangesAsync();

        // Act
        var foundSecret = await _repository.GetByIdAsync(secret.Id);

        // Assert
        foundSecret.Should().NotBeNull();
        foundSecret!.Id.Should().Be(secret.Id);
        foundSecret.Title.Should().Be("Test Secret");
    }

    // ====================================================================
    // ✏️ UPDATE TESTS
    // ====================================================================

    [Fact]
    public async Task UpdateAsync_ShouldUpdateSecret()
    {
        // Arrange
        var userId = Guid.NewGuid();

        var secret = Secret.Create("Old Name", "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC", GenerateIV(), userId);

        await _repository.AddAsync(secret);
        await Context.SaveChangesAsync();

        // Act
        secret.UpdateTitle("New Name");
        await _repository.UpdateAsync(secret);
        await Context.SaveChangesAsync();

        // Assert
        var updatedSecret = await _repository.GetByIdAsync(secret.Id);

        updatedSecret.Should().NotBeNull();
        updatedSecret!.Title.Should().Be("New Name");
    }

    [Fact]
    public async Task UpdateAsync_WithAccessTracking_ShouldUpdateTimestamp()
    {
        // Arrange
        var userId = Guid.NewGuid();

        var secret = Secret.Create("Test Secret", "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC", GenerateIV(), userId);

        await _repository.AddAsync(secret);
        await Context.SaveChangesAsync();

        // Act
        secret.RecordAccess();
        await _repository.UpdateAsync(secret);
        await Context.SaveChangesAsync();

        // Assert
        var updatedSecret = await _repository.GetByIdAsync(secret.Id);

        updatedSecret.Should().NotBeNull();
        updatedSecret!.LastAccessedAt.Should().NotBeNull();
        updatedSecret.LastAccessedAt.Value.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    // ====================================================================
    // 🎯 EDGE CASES
    // ====================================================================

    [Fact]
    public async Task GetByUserIdAsync_ShouldReturnNewestFirst()
    {
        // Arrange
        var userId = Guid.NewGuid();

        var secret1 = Secret.Create("Secret 1", "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC", GenerateIV(), userId);

        await _repository.AddAsync(secret1);
        await Context.SaveChangesAsync();

        await Task.Delay(100);

        var secret2 = Secret.Create("Secret 2", "RUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVF", GenerateIV(), userId);

        await _repository.AddAsync(secret2);
        await Context.SaveChangesAsync();

        // Act
        var secrets = (await _repository.GetByUserIdAsync(userId)).ToList();

        // Assert
        secrets.Should().HaveCount(2);
        secrets[0].Title.Should().Be("Secret 2");
        secrets[1].Title.Should().Be("Secret 1");
    }
}