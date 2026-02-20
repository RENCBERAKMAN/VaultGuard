using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VaultGuard.Domain.Entities;

namespace VaultGuard.Application.Interfaces;

/// <summary>
/// Repository pattern interface for Secret entity persistence operations.
/// 
/// ARCHITECTURE PATTERN:
/// This interface abstracts database access using Repository Pattern:
/// - Hides EF Core implementation details from application layer
/// - Enables unit testing with in-memory repositories (mocking)
/// - Supports database provider switching (SQL Server, PostgreSQL, SQLite)
/// - Enforces CQRS separation (Command/Query Responsibility Segregation)
/// 
/// SECURITY ARCHITECTURE:
/// ┌─────────────────────────────────────────────────────────────┐
/// │ ISecretService → ISecretRepository → DbContext → Database   │
/// │    (Business)      (Abstraction)     (EF Core)   (SQL Server)│
/// └─────────────────────────────────────────────────────────────┘
/// 
/// CRITICAL SECURITY PRINCIPLES:
/// 1. **Encrypted at Rest**: All Secret.EncryptedValue columns stored as varbinary
/// 2. **Parameterized Queries**: EF Core prevents SQL injection (NEVER use raw SQL)
/// 3. **No Plaintext Leakage**: Repository NEVER handles plaintext values
/// 4. **Soft Delete Support**: IsDeleted flag for GDPR compliance
/// 5. **Optimistic Concurrency**: RowVersion/Timestamp for conflict detection
/// 
/// PERFORMANCE OPTIMIZATIONS:
/// - Async/await for non-blocking I/O
/// - IQueryable for deferred execution (LINQ optimization)
/// - Eager loading with Include() to prevent N+1 queries
/// - Pagination support (Skip/Take)
/// - Index on: UserId, Title, CreatedAt, ExpiresAt
/// 
/// TRANSACTION MANAGEMENT:
/// - Implementation uses DbContext transaction scope
/// - Repository does NOT commit (UnitOfWork pattern responsibility)
/// - Bulk operations wrapped in single transaction
/// 
/// THREAD SAFETY:
/// - DbContext is NOT thread-safe (scoped lifetime)
/// - Repository instance is scoped per HTTP request
/// - No shared state between requests
/// 
/// TESTING:
/// - Interface enables mocking with Moq/NSubstitute
/// - In-memory provider for integration tests
/// - Fake repository for unit tests
/// </summary>
/// <remarks>
/// ⚠️ IMPLEMENTATION GUIDELINES:
/// 1. Use EF Core for implementation (Infrastructure layer)
/// 2. Apply Include() for navigation properties (User, Category)
/// 3. Apply AsNoTracking() for read-only queries (performance)
/// 4. Apply Where(x => !x.IsDeleted) for soft delete filter
/// 5. Return Domain entities (NOT DTOs - that's service layer job)
/// 6. Handle DbUpdateException gracefully (unique constraint violations)
/// </remarks>
public interface ISecretRepository
{
    /// <summary>
    /// Retrieves all secrets owned by a specific user.
    /// 
    /// QUERY OPTIMIZATION:
    /// - Filter: WHERE UserId = @userId AND IsDeleted = false
    /// - Sort: ORDER BY CreatedAt DESC (newest first)
    /// - Include: User navigation property (eager loading)
    /// - AsNoTracking: Read-only query (performance boost)
    /// 
    /// PAGINATION (Future Enhancement):
    /// - Add: int skip, int take parameters
    /// - Implement: query.Skip(skip).Take(take)
    /// 
    /// SECURITY:
    /// - No authorization check here (service layer responsibility)
    /// - Returns encrypted values (safe for retrieval)
    /// </summary>
    /// <param name="userId">Owner user ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of Secret entities (Domain layer)</returns>
    Task<IEnumerable<Secret>> GetByUserIdAsync(
        Guid userId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a single secret by its unique identifier.
    /// 
    /// QUERY OPTIMIZATION:
    /// - Filter: WHERE Id = @secretId AND IsDeleted = false
    /// - Include: User navigation property
    /// - AsNoTracking: If read-only operation
    /// 
    /// SECURITY:
    /// - No authorization check here (service layer responsibility)
    /// - Returns null if not found (not exception)
    /// 
    /// ERROR HANDLING:
    /// - Return null if not found (NOT throw exception)
    /// - Service layer maps null → ErrorDataResult("Not Found")
    /// </summary>
    /// <param name="id">Unique secret identifier</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Secret entity or null if not found</returns>
    Task<Secret?> GetByIdAsync(
        Guid id,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a secret with given title already exists for a user.
    /// 
    /// USE CASE:
    /// - Validate uniqueness before creating/updating secret
    /// - Prevent duplicate titles per user
    /// 
    /// QUERY:
    /// - Filter: WHERE UserId = @userId AND Title = @title AND IsDeleted = false
    /// - Exclude: Current secret ID (for update validation)
    /// 
    /// PERFORMANCE:
    /// - Index: CREATE INDEX IX_Secrets_UserId_Title ON Secrets(UserId, Title)
    /// - Query plan: Index seek (O(log n))
    /// 
    /// CASE SENSITIVITY:
    /// - Use: StringComparison.OrdinalIgnoreCase
    /// - Database: COLLATE SQL_Latin1_General_CP1_CI_AS (case-insensitive)
    /// </summary>
    /// <param name="userId">Owner user ID</param>
    /// <param name="title">Secret title to check</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Secret entity if duplicate found, null otherwise</returns>
    Task<Secret?> GetByTitleAndUserIdAsync(
        Guid userId,
        string title,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Adds a new secret to the database.
    /// 
    /// WORKFLOW:
    /// 1. Validate: Entity is not null
    /// 2. Assign: Id = Guid.NewGuid() (if not set)
    /// 3. Set: CreatedAt = DateTime.UtcNow
    /// 4. Set: UpdatedAt = DateTime.UtcNow
    /// 5. DbContext.Secrets.Add(secret)
    /// 6. Return: Entity with Id assigned
    /// 
    /// TRANSACTION:
    /// - Does NOT call SaveChangesAsync (UnitOfWork pattern)
    /// - Service layer calls SaveChangesAsync after all operations
    /// 
    /// CONCURRENCY:
    /// - OptimisticConcurrencyException handled by service layer
    /// </summary>
    /// <param name="secret">Secret entity to add</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Added entity with generated Id</returns>
    Task<Secret> AddAsync(
        Secret secret,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing secret in the database.
    /// 
    /// WORKFLOW:
    /// 1. Attach: DbContext.Secrets.Attach(secret)
    /// 2. Mark: Entry(secret).State = EntityState.Modified
    /// 3. Set: UpdatedAt = DateTime.UtcNow
    /// 4. Return: Updated entity
    /// 
    /// OPTIMISTIC CONCURRENCY:
    /// - RowVersion/Timestamp column for conflict detection
    /// - DbUpdateConcurrencyException thrown if conflict
    /// 
    /// PARTIAL UPDATE:
    /// - Service layer fetches entity first
    /// - Modifies only changed properties
    /// - Calls UpdateAsync with modified entity
    /// </summary>
    /// <param name="secret">Secret entity to update</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Updated entity</returns>
    Task<Secret> UpdateAsync(
        Secret secret,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a secret from the database (soft or hard delete).
    /// 
    /// SOFT DELETE (Recommended):
    /// - Set: IsDeleted = true, DeletedAt = DateTime.UtcNow
    /// - Call: UpdateAsync(secret)
    /// - Allows: Recovery within retention period
    /// 
    /// HARD DELETE (GDPR):
    /// - Call: DbContext.Secrets.Remove(secret)
    /// - Permanent removal (no recovery)
    /// - Cascade: Delete related audit logs? (NO - keep for compliance)
    /// 
    /// AUDIT TRAIL:
    /// - Deletion event logged before calling this method
    /// - Audit log persists even after hard delete
    /// </summary>
    /// <param name="secret">Secret entity to delete</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Task representing the asynchronous operation</returns>
    Task DeleteAsync(
        Secret secret,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Counts total secrets owned by a user (for quota enforcement).
    /// 
    /// USE CASE:
    /// - Enforce user quota (max 1000 secrets per user)
    /// - Dashboard statistics
    /// 
    /// QUERY:
    /// - Filter: WHERE UserId = @userId AND IsDeleted = false
    /// - Count: COUNT(*)
    /// 
    /// PERFORMANCE:
    /// - Index: IX_Secrets_UserId
    /// - Query plan: Index scan + aggregate
    /// </summary>
    /// <param name="userId">Owner user ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Total count of active secrets</returns>
    Task<int> GetCountByUserIdAsync(
        Guid userId,
        CancellationToken cancellationToken = default);
}