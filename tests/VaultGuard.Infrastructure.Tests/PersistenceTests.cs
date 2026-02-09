using Microsoft.EntityFrameworkCore;
using System;
using System.Threading.Tasks;
using VaultGuard.Domain.Entities;
using VaultGuard.Infrastructure.Persistence;
using Xunit;

namespace VaultGuard.Infrastructure.Tests.Persistence;

/// <summary>
/// VaultGuardDbContext ve EF Core Configuration'larýn doðruluðunu test eder.
/// SQLite InMemory database kullanarak gerçek veritabaný iþlemlerini test eder.
/// </summary>
public class PersistenceTests : IDisposable
{
    private readonly VaultGuardDbContext _context;

    public PersistenceTests()
    {
        // SQLite InMemory database - her test için yeni bir instance
        var options = new DbContextOptionsBuilder<VaultGuardDbContext>()
            .UseSqlite("DataSource=:memory:")
            .Options;

        _context = new VaultGuardDbContext(options);
        _context.Database.OpenConnection(); // SQLite memory database için gerekli
        _context.Database.EnsureCreated(); // Schema oluþtur
    }

    public void Dispose()
    {
        _context.Database.CloseConnection();
        _context.Dispose();
    }

    // ============================================================================
    // DATABASE CREATION TESTS
    // ============================================================================

    [Fact]
    public void Database_CanCreateSchema_Successfully()
    {
        // Act
        var canConnect = _context.Database.CanConnect();

        // Assert
        Assert.True(canConnect);
    }

    [Fact]
    public void Database_HasCorrectTables_AfterMigration()
    {
        // Arrange & Act
        var tableNames = _context.Model.GetEntityTypes()
            .Select(t => t.GetTableName())
            .ToList();

        // Assert
        Assert.Contains("Users", tableNames);
        Assert.Contains("Secrets", tableNames);
        Assert.Contains("AuditLogs", tableNames);
    }

    // ============================================================================
    // USER ENTITY PERSISTENCE TESTS
    // ============================================================================

    [Fact]
    public async Task User_CanBeSavedAndRetrieved_Successfully()
    {
        // Arrange
        var user = User.Create(
            "test@vaultguard.com",
            "testuser",
            "hashed_password_123456789",
            "User");

        // Act - Save
        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();

        // Clear tracking to simulate a fresh query
        _context.ChangeTracker.Clear();

        // Act - Retrieve
        var retrievedUser = await _context.Users
            .FirstOrDefaultAsync(u => u.Id == user.Id);

        // Assert
        Assert.NotNull(retrievedUser);
        Assert.Equal(user.Id, retrievedUser.Id);
        Assert.Equal(user.Email, retrievedUser.Email);
        Assert.Equal(user.Username, retrievedUser.Username);
        Assert.Equal(user.PasswordHash, retrievedUser.PasswordHash);
        Assert.Equal(user.Role, retrievedUser.Role);
    }

    [Fact]
    public async Task User_EmailIsUnique_ConstraintEnforced()
    {
        // Arrange
        var email = "duplicate@vaultguard.com";
        var user1 = User.Create(email, "user1", "hash1234567890123456", "User");
        var user2 = User.Create(email, "user2", "hash2345678901234567", "User");

        // Act
        await _context.Users.AddAsync(user1);
        await _context.SaveChangesAsync();

        await _context.Users.AddAsync(user2);

        // Assert
        await Assert.ThrowsAsync<DbUpdateException>(async () =>
            await _context.SaveChangesAsync());
    }

    [Fact]
    public async Task User_UsernameIsUnique_ConstraintEnforced()
    {
        // Arrange
        var username = "duplicateuser";
        var user1 = User.Create("user1@test.com", username, "hash1234567890123456", "User");
        var user2 = User.Create("user2@test.com", username, "hash2345678901234567", "User");

        // Act
        await _context.Users.AddAsync(user1);
        await _context.SaveChangesAsync();

        await _context.Users.AddAsync(user2);

        // Assert
        await Assert.ThrowsAsync<DbUpdateException>(async () =>
            await _context.SaveChangesAsync());
    }

    [Fact]
    public async Task User_CanUpdateProperties_Successfully()
    {
        // Arrange
        var user = User.Create(
            "test@vaultguard.com",
            "testuser",
            "hashed_password_123456789",
            "User");

        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();

        // Act
        user.UpdateEmail("newemail@vaultguard.com");
        user.ChangeRole("Admin");
        await _context.SaveChangesAsync();

        _context.ChangeTracker.Clear();

        var updatedUser = await _context.Users.FindAsync(user.Id);

        // Assert
        Assert.NotNull(updatedUser);
        Assert.Equal("newemail@vaultguard.com", updatedUser.Email);
        Assert.Equal("Admin", updatedUser.Role);
    }

    // ============================================================================
    // SECRET ENTITY PERSISTENCE TESTS
    // ============================================================================

    [Fact]
    public async Task Secret_CanBeSavedAndRetrieved_Successfully()
    {
        // Arrange
        var owner = User.Create(
            "owner@vaultguard.com",
            "secretowner",
            "hashed_password_123456789",
            "User");

        await _context.Users.AddAsync(owner);
        await _context.SaveChangesAsync();

        var secret = Secret.Create(
            "API Key",
            new byte[] { 1, 2, 3, 4, 5 },
            new byte[16],
            owner.Id);

        // Act - Save
        await _context.Secrets.AddAsync(secret);
        await _context.SaveChangesAsync();

        _context.ChangeTracker.Clear();

        // Act - Retrieve
        var retrievedSecret = await _context.Secrets
            .FirstOrDefaultAsync(s => s.Id == secret.Id);

        // Assert
        Assert.NotNull(retrievedSecret);
        Assert.Equal(secret.Id, retrievedSecret.Id);
        Assert.Equal(secret.Name, retrievedSecret.Name);
        Assert.Equal(secret.EncryptedData, retrievedSecret.EncryptedData);
        Assert.Equal(secret.IV, retrievedSecret.IV);
        Assert.Equal(owner.Id, retrievedSecret.OwnerId);
    }

    [Fact]
    public async Task Secret_SoftDelete_WorksCorrectly()
    {
        // Arrange
        var owner = User.Create(
            "owner@vaultguard.com",
            "secretowner",
            "hashed_password_123456789",
            "User");

        await _context.Users.AddAsync(owner);
        await _context.SaveChangesAsync();

        var secret = Secret.Create(
            "API Key",
            new byte[] { 1, 2, 3 },
            new byte[16],
            owner.Id);

        await _context.Secrets.AddAsync(secret);
        await _context.SaveChangesAsync();

        // Act - Soft Delete
        secret.MarkAsDeleted();
        await _context.SaveChangesAsync();

        _context.ChangeTracker.Clear();

        // Assert - Query filter should exclude deleted secrets
        var activeSecret = await _context.Secrets
            .FirstOrDefaultAsync(s => s.Id == secret.Id);

        Assert.Null(activeSecret); // Should be filtered out

        // Assert - IgnoreQueryFilters should include deleted secrets
        var deletedSecret = await _context.Secrets
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(s => s.Id == secret.Id);

        Assert.NotNull(deletedSecret);
        Assert.True(deletedSecret.IsDeleted);
        Assert.NotNull(deletedSecret.DeletedAt);
    }

    [Fact]
    public void Secret_ForeignKey_RestrictDelete_Enforced()
    {
        // Arrange
        var owner = User.Create(
            "owner@vaultguard.com",
            "secretowner",
            "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1", // GÜVENLÝK: Geçerli Hash
            "User");

        _context.Users.Add(owner);
        _context.SaveChanges();

        var secret = Secret.Create(
            "API Key",
            new byte[] { 1, 2, 3 },
            new byte[16],
            owner.Id);

        _context.Secrets.Add(secret);
        _context.SaveChanges();

        // Act & Assert - Try to delete user with secrets
        // EF Core, 'Restrict' kuralý nedeniyle kullanýcý silindiðinde sýrlar (Secrets) 
        // sahipsiz kalacaðý için bu iþlemi C# tarafýnda durdurur.
        Assert.Throws<InvalidOperationException>(() => _context.Users.Remove(owner));
    }
    // ============================================================================
    // AUDITLOG ENTITY PERSISTENCE TESTS
    // ============================================================================

    [Fact]
    public async Task AuditLog_CanBeSavedAndRetrieved_Successfully()
    {
        // Arrange
        var user = User.Create(
            "test@vaultguard.com",
            "testuser",
            "hashed_password_123456789",
            "User");

        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();

        var auditLog = AuditLog.Create(
    user.Id,
    "Secret_Viewed",
    "Secret",
    "192.168.1.100",
    Guid.NewGuid(),
    "User viewed a record from dashboard");

        // Act - Save
        await _context.AuditLogs.AddAsync(auditLog);
        await _context.SaveChangesAsync();

        _context.ChangeTracker.Clear();

        // Act - Retrieve
        var retrievedLog = await _context.AuditLogs
            .FirstOrDefaultAsync(a => a.Id == auditLog.Id);

        // Assert
        Assert.NotNull(retrievedLog);
        Assert.Equal(auditLog.Id, retrievedLog.Id);
        Assert.Equal(auditLog.UserId, retrievedLog.UserId);
        Assert.Equal(auditLog.Action, retrievedLog.Action);
        Assert.Equal(auditLog.EntityName, retrievedLog.EntityName);
        Assert.Equal(auditLog.IpAddress, retrievedLog.IpAddress);
    }

    [Fact] // Artýk async olmasýna gerek yok çünkü Remove() aþamasýnda duruyoruz
    public void AuditLog_ForeignKey_RestrictDelete_Enforced()
    {
        // 1. Arrange - Kullanýcýyý geçerli bir hash ile oluþtur
        var user = User.Create(
            "test@vaultguard.com",
            "testuser",
            "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1", // Geçerli Hash
            "User");

        _context.Users.Add(user);
        _context.SaveChanges();

        // 2. Arrange - Kullanýcýya baðlý bir log oluþtur
        var auditLog = AuditLog.Create(
            user.Id,
            "User_Login",
            "User",
            "192.168.1.100",
            null, // EntityId
            "User logged in successfully"); // 'secret' kelimesi içermeyen detay

        _context.AuditLogs.Add(auditLog);
        _context.SaveChanges();

        // 3. Act & Assert 
        // EF Core, kullanýcýya baðlý loglar olduðu için Remove() metodu çaðrýldýðý an 
        // InvalidOperationException fýrlatarak iþlemi durdurur.
        Assert.Throws<InvalidOperationException>(() => _context.Users.Remove(user));
    }

    // ============================================================================
    // RELATIONSHIP TESTS
    // ============================================================================

    [Fact]
    public async Task User_CanHaveMultipleSecrets_Successfully()
    {
        // Arrange
        var user = User.Create(
            "owner@vaultguard.com",
            "multiowner",
            "hashed_password_123456789",
            "User");

        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();

        var secret1 = Secret.Create("Secret 1", new byte[] { 1 }, new byte[16], user.Id);
        var secret2 = Secret.Create("Secret 2", new byte[] { 2 }, new byte[16], user.Id);
        var secret3 = Secret.Create("Secret 3", new byte[] { 3 }, new byte[16], user.Id);

        await _context.Secrets.AddRangeAsync(secret1, secret2, secret3);
        await _context.SaveChangesAsync();

        _context.ChangeTracker.Clear();

        // Act
        var userSecrets = await _context.Secrets
            .Where(s => s.OwnerId == user.Id)
            .ToListAsync();

        // Assert
        Assert.Equal(3, userSecrets.Count);
    }

    [Fact]
    public async Task User_CanHaveMultipleAuditLogs_Successfully()
    {
        // Arrange
        var user = User.Create(
            "test@vaultguard.com",
            "testuser",
            "hashed_password_123456789",
            "User");

        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();

        var log1 = AuditLog.Create(user.Id, "User_Login", "User", "192.168.1.1");
        var log2 = AuditLog.Create(user.Id, "Secret_Created", "Secret", "192.168.1.1");
        var log3 = AuditLog.Create(user.Id, "Secret_Viewed", "Secret", "192.168.1.1");

        await _context.AuditLogs.AddRangeAsync(log1, log2, log3);
        await _context.SaveChangesAsync();

        _context.ChangeTracker.Clear();

        // Act
        var userLogs = await _context.AuditLogs
            .Where(a => a.UserId == user.Id)
            .ToListAsync();

        // Assert
        Assert.Equal(3, userLogs.Count);
    }

    // ============================================================================
    // TRANSACTION TESTS
    // ============================================================================

    [Fact]
    public async Task Transaction_Rollback_OnError_WorksCorrectly()
    {
        // Arrange
        var user = User.Create(
            "test@vaultguard.com",
            "testuser",
            "hashed_password_123456789",
            "User");

        // Act & Assert
        await using var transaction = await _context.Database.BeginTransactionAsync();
        try
        {
            await _context.Users.AddAsync(user);
            await _context.SaveChangesAsync();

            // Simulate error - try to add duplicate email
            var duplicateUser = User.Create(
                "test@vaultguard.com",
                "anotheruser",
                "hashed_password_987654321",
                "User");

            await _context.Users.AddAsync(duplicateUser);
            await _context.SaveChangesAsync(); // Should throw

            await transaction.CommitAsync();
            Assert.Fail("Should have thrown DbUpdateException");
        }
        catch (DbUpdateException)
        {
            await transaction.RollbackAsync();
        }

        _context.ChangeTracker.Clear();

        // Assert - User should not exist after rollback
        var userCount = await _context.Users.CountAsync();
        Assert.Equal(0, userCount);
    }
}