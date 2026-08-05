using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using VaultGuard.Application.Interfaces;
using VaultGuard.Domain.Entities;
using VaultGuard.Infrastructure.Persistence;

namespace VaultGuard.Infrastructure.Persistence;

/// <summary>
/// Repository implementation for Secret entity with EF Core 9.
/// 
/// ARCHITECTURE:
/// - Repository Pattern: Abstracts database access from business logic
/// - Unit of Work: DbContext manages transactions (SaveChanges called by service layer)
/// - Soft Delete: IsDeleted flag prevents physical deletion (GDPR compliance)
/// - Eager Loading: Include() for navigation properties (prevent N+1 queries)
/// - No Tracking: Read-only queries use AsNoTracking() for performance
/// 
/// PERFORMANCE OPTIMIZATIONS:
/// - AsNoTracking(): 30-40% faster for read-only queries (no change tracking overhead)
/// - Compiled Queries: EF Core caches query plans automatically
/// - Indexing: Database indexes on UserId, Title, CreatedAt (see Configurations)
/// - Pagination: Skip/Take for large datasets (future enhancement)
/// 
/// THREAD SAFETY:
/// - DbContext is NOT thread-safe (scoped lifetime per HTTP request)
/// - Each repository instance has its own DbContext
/// - No shared mutable state
/// 
/// SECURITY:
/// - Soft Delete: Prevents accidental data loss + maintains audit trail
/// - Parameterized Queries: EF Core prevents SQL injection automatically
/// - No raw SQL: All queries use LINQ (safe by design)
/// </summary>
public sealed class SecretRepository : ISecretRepository
{
    private readonly VaultGuardDbContext _context;

    /// <summary>
    /// Initializes a new instance of SecretRepository.
    /// </summary>
    /// <param name="context">EF Core database context</param>
    public SecretRepository(VaultGuardDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc/>
    public async Task<IEnumerable<Secret>> GetByUserIdAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        // PERFORMANCE: AsNoTracking() for read-only queries
        // SOFT DELETE: Filter IsDeleted == false
        // SORTING: Order by CreatedAt DESC (newest first)
        // ✅ FIX: OwnerId -> UserId
        return await _context.Secrets
            .AsNoTracking()
            .Where(s => s.UserId == userId && !s.IsDeleted)
            .OrderByDescending(s => s.CreatedAt)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<Secret?> GetByIdAsync(
        Guid id,
        CancellationToken cancellationToken = default)
    {
        // PERFORMANCE: AsNoTracking() for read-only queries
        // SOFT DELETE: Filter IsDeleted == false
        // NULL SAFETY: Returns null if not found (not exception)
        return await _context.Secrets
            .AsNoTracking()
            .FirstOrDefaultAsync(s => s.Id == id && !s.IsDeleted, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<Secret?> GetByTitleAndUserIdAsync(
        Guid userId,
        string title,
        CancellationToken cancellationToken = default)
    {
        // VALIDATION: Null/empty title check
        if (string.IsNullOrWhiteSpace(title))
        {
            return null;
        }

        // CASE INSENSITIVE: Use ToLower() for comparison
        // SOFT DELETE: Filter IsDeleted == false
        // PERFORMANCE: AsNoTracking() for read-only query
        // ✅ FIX: OwnerId -> UserId, Name -> Title
        return await _context.Secrets
            .AsNoTracking()
            .FirstOrDefaultAsync(
                s => s.UserId == userId &&
                     s.Title.ToLower() == title.ToLower() &&
                     !s.IsDeleted,
                cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<Secret> AddAsync(
        Secret secret,
        CancellationToken cancellationToken = default)
    {
        // VALIDATION: Null check
        if (secret == null)
        {
            throw new ArgumentNullException(nameof(secret));
        }

        // ADD: Entity to context (not committed yet)
        await _context.Secrets.AddAsync(secret, cancellationToken);

        // NOTE: SaveChanges NOT called here (Unit of Work pattern)
        // Service layer calls _context.SaveChangesAsync() after all operations

        return secret;
    }

    /// <inheritdoc/>
    public async Task<Secret> UpdateAsync(
        Secret secret,
        CancellationToken cancellationToken = default)
    {
        // VALIDATION: Null check
        if (secret == null)
        {
            throw new ArgumentNullException(nameof(secret));
        }

        // UPDATE: Mark entity as modified
        // EF Core will track changes and update database on SaveChanges()
        _context.Entry(secret).State = EntityState.Modified;

        // Return the secret (async for consistency, though operation is synchronous)
        return await Task.FromResult(secret);
    }

    /// <inheritdoc/>
    public async Task DeleteAsync(
        Secret secret,
        CancellationToken cancellationToken = default)
    {
        // VALIDATION: Null check
        if (secret == null)
        {
            throw new ArgumentNullException(nameof(secret));
        }

        // SOFT DELETE: Use domain method
        // ✅ FIX: Call MarkAsDeleted() which sets IsDeleted = true and DeletedAt = DateTime.UtcNow
        secret.MarkAsDeleted();

        // UPDATE: Save soft delete flags to database
        await UpdateAsync(secret, cancellationToken);

        // HARD DELETE (Alternative - uncomment for physical deletion):
        // _context.Secrets.Remove(secret);

        // NOTE: For GDPR compliance, consider:
        // 1. Soft delete for 30 days (recovery period)
        // 2. Background job: Hard delete after 30 days
        // 3. Audit log persists even after hard delete
    }

    /// <inheritdoc/>
    public async Task<int> GetCountByUserIdAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        // PERFORMANCE: CountAsync() more efficient than loading all entities
        // SOFT DELETE: Filter IsDeleted == false
        // ✅ FIX: OwnerId -> UserId
        return await _context.Secrets
            .CountAsync(s => s.UserId == userId && !s.IsDeleted, cancellationToken);
    }
}