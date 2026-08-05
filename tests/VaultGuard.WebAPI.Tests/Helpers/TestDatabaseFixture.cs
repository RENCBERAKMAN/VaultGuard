using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using VaultGuard.Domain.Entities;
using VaultGuard.Infrastructure.Persistence;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Helpers;

public class TestDatabaseFixture : IDisposable
{
    public const string AdminEmail = "admin@vaultguard.test";
    public const string AdminUsername = "admin";
    public const string NormalUserEmail = "user@vaultguard.test";
    public const string NormalUsername = "testuser";
    public const string TestPassword = "Test@1234";

    private readonly string _databaseName;
    private readonly DbContextOptions<VaultGuardDbContext> _options;
    private bool _disposed = false;

    public Guid AdminUserId { get; private set; }
    public Guid NormalUserId { get; private set; }

    public TestDatabaseFixture()
    {
        _databaseName = $"VaultGuardTestDb_{Guid.NewGuid()}";

        _options = new DbContextOptionsBuilder<VaultGuardDbContext>()
            .UseInMemoryDatabase(databaseName: _databaseName)
            .EnableSensitiveDataLogging()
            .Options;

        using var context = CreateContext();
        SeedDatabase(context);
    }

    public VaultGuardDbContext CreateContext()
    {
        return new VaultGuardDbContext(_options);
    }

    public void ClearDatabase()
    {
        using var context = CreateContext();
        context.Secrets.RemoveRange(context.Secrets);
        context.Users.RemoveRange(context.Users);
        context.SaveChanges();
    }

    public void ResetDatabase()
    {
        ClearDatabase();
        using var context = CreateContext();
        SeedDatabase(context);
    }

    public Task ResetDatabaseAsync()
    {
        ResetDatabase();
        return Task.CompletedTask;
    }

    public Guid AddUser(User user)
    {
        using var context = CreateContext();
        context.Users.Add(user);
        context.SaveChanges();
        return user.Id;
    }

    public void AddUsers(IEnumerable<User> users)
    {
        using var context = CreateContext();
        context.Users.AddRange(users);
        context.SaveChanges();
    }

    public Guid AddSecret(Secret secret)
    {
        using var context = CreateContext();
        context.Secrets.Add(secret);
        context.SaveChanges();
        return secret.Id;
    }

    public void AddSecrets(IEnumerable<Secret> secrets)
    {
        using var context = CreateContext();
        context.Secrets.AddRange(secrets);
        context.SaveChanges();
    }

    public User? FindUserByEmail(string email)
    {
        using var context = CreateContext();
        return context.Users.FirstOrDefault(u => u.Email == email);
    }

    public Task<User?> GetUserByEmailAsync(string email)
    {
        return Task.FromResult(FindUserByEmail(email));
    }

    public User? FindUserById(Guid id)
    {
        using var context = CreateContext();
        return context.Users.Find(id);
    }

    public int GetSecretCount(Guid userId)
    {
        using var context = CreateContext();
        return context.Secrets.Count(s => s.UserId == userId);
    }

    public int GetTotalUserCount()
    {
        using var context = CreateContext();
        return context.Users.Count();
    }

    public Task<int> GetUserCountAsync()
    {
        return Task.FromResult(GetTotalUserCount());
    }

    public int GetTotalSecretCount()
    {
        using var context = CreateContext();
        return context.Secrets.Count();
    }

    private void SeedDatabase(VaultGuardDbContext context)
    {
        if (context.Users.Any())
        {
            AdminUserId = context.Users.First(u => u.Email == AdminEmail).Id;
            NormalUserId = context.Users.First(u => u.Email == NormalUserEmail).Id;
            return;
        }

        var adminUser = CreateAdminUser();
        context.Users.Add(adminUser);
        AdminUserId = adminUser.Id;

        var testUser = CreateTestUser();
        context.Users.Add(testUser);
        NormalUserId = testUser.Id;

        context.SaveChanges();

        var secrets = CreateTestSecrets(testUser.Id);
        context.Secrets.AddRange(secrets);

        context.SaveChanges();
    }

    private static User CreateAdminUser()
    {
        var passwordHash = "$2a$11$" + Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes(TestPassword)).PadRight(53, 'A')[..53];

        return User.Create(AdminEmail, AdminUsername, passwordHash, role: "Admin");
    }

    private static User CreateTestUser()
    {
        var passwordHash = "$2a$11$" + Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes(TestPassword)).PadRight(53, 'A')[..53];

        return User.Create(NormalUserEmail, NormalUsername, passwordHash, role: "User");
    }

    private static List<Secret> CreateTestSecrets(Guid userId)
    {
        const string fakeCipherA = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
        const string fakeCipherB = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC";

        return new List<Secret>
        {
            Secret.Create("AWS API Key", fakeCipherA, new byte[12], userId, category: "Cloud"),
            Secret.Create("Production DB Password", fakeCipherB, new byte[12], userId, category: "Database")
        };
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            using var context = CreateContext();
            context.Database.EnsureDeleted();
        }

        _disposed = true;
    }

    ~TestDatabaseFixture()
    {
        Dispose(false);
    }
}