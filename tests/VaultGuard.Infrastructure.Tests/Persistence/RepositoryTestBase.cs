using System;
using Microsoft.EntityFrameworkCore;
using VaultGuard.Infrastructure.Persistence;
using Xunit;

namespace VaultGuard.Infrastructure.Tests.Persistence;

/// <summary>
/// Base class for all repository tests with InMemory database setup.
/// 
/// DATABASE PROVIDER:
/// Uses EF Core InMemory provider for:
/// - Fast test execution (no I/O overhead)
/// - Isolated test environment (each test gets fresh database)
/// - No external dependencies (no SQL Server installation needed)
/// 
/// LIMITATIONS OF INMEMORY PROVIDER:
/// - No referential integrity enforcement (foreign keys)
/// - No unique constraints enforcement (must test manually)
/// - No SQL-specific features (stored procedures, triggers)
/// - Not suitable for integration tests (use SQLite for that)
/// 
/// ALTERNATIVE: SQLite InMemory
/// For more realistic tests with constraints:
/// - options.UseSqlite("DataSource=:memory:")
/// - connection.Open() required (keeps database alive)
/// - Supports foreign keys and unique constraints
/// 
/// TEST ISOLATION:
/// - Each test class gets unique database name
/// - Database disposed after each test
/// - No state leakage between tests
/// 
/// THREAD SAFETY:
/// - DbContext is NOT thread-safe
/// - Each test runs in isolation (xUnit default)
/// - Parallel test execution supported (different databases)
/// </summary>
public abstract class RepositoryTestBase : IDisposable
{
    protected VaultGuardDbContext Context { get; private set; }
    protected DbContextOptions<VaultGuardDbContext> Options { get; private set; }

    protected RepositoryTestBase()
    {
        // Create unique database name for this test class
        var databaseName = $"VaultGuardTestDb_{Guid.NewGuid()}";

        // Configure InMemory database
        Options = new DbContextOptionsBuilder<VaultGuardDbContext>()
            .UseInMemoryDatabase(databaseName)
            .EnableSensitiveDataLogging() // For debugging test failures
            .Options;

        // Create DbContext
        Context = new VaultGuardDbContext(Options);

        // Ensure database is created (schema)
        Context.Database.EnsureCreated();
    }

    /// <summary>
    /// Creates a fresh DbContext instance (for testing context disposal scenarios).
    /// </summary>
    protected VaultGuardDbContext CreateContext()
    {
        return new VaultGuardDbContext(Options);
    }

    /// <summary>
    /// Clears all data from the database (for test cleanup).
    /// </summary>
    protected void ClearDatabase()
    {
        Context.Secrets.RemoveRange(Context.Secrets);
        Context.AuditLogs.RemoveRange(Context.AuditLogs);
        Context.Users.RemoveRange(Context.Users);
        Context.SaveChanges();
    }

    /// <summary>
    /// Disposes the DbContext and deletes the InMemory database.
    /// </summary>
    public virtual void Dispose()
    {
        Context?.Database.EnsureDeleted();
        Context?.Dispose();
        GC.SuppressFinalize(this);
    }
}