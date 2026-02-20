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
/// Repository implementation for AuditLog entity (append-only, immutable).
/// 
/// SECURITY ARCHITECTURE:
/// - Append-Only: No Update or Delete methods (audit logs are immutable)
/// - Tamper-Proof: Once written, cannot be modified (compliance requirement)
/// - Retention Policy: Background job handles archival/deletion (not this class)
/// 
/// COMPLIANCE:
/// - SOC 2 Type II: Immutable audit trail for security monitoring
/// - GDPR Article 30: Records of processing activities
/// - PCI-DSS Requirement 10: Audit trail cannot be altered
/// - HIPAA §164.312(b): Audit controls must be immutable
/// 
/// PERFORMANCE OPTIMIZATIONS:
/// - AsNoTracking(): Read-only queries (30-40% faster)
/// - Batch Inserts: Consider bulk insert for high-throughput (future)
/// - Indexing: UserId, EventType, Timestamp (see Configurations)
/// - Partitioning: Monthly partitions for large datasets (future)
/// 
/// THREAD SAFETY:
/// - DbContext is scoped (one instance per HTTP request)
/// - No shared mutable state
/// - Concurrent writes handled by database
/// </summary>
public sealed class AuditLogRepository : IAuditLogRepository
{
    private readonly VaultGuardDbContext _context;

    /// <summary>
    /// Initializes a new instance of AuditLogRepository.
    /// </summary>
    /// <param name="context">EF Core database context</param>
    public AuditLogRepository(VaultGuardDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    /// <inheritdoc/>
    public async Task<AuditLog> AddAsync(
        AuditLog auditLog,
        CancellationToken cancellationToken = default)
    {
        // VALIDATION: Null check
        if (auditLog == null)
        {
            throw new ArgumentNullException(nameof(auditLog));
        }

       

        // IMMUTABILITY CHECK: Verify timestamp is not in future (prevent time manipulation)
        if (auditLog.Timestamp > DateTime.UtcNow.AddMinutes(5)) // 5 min tolerance for clock skew
        {
            throw new InvalidOperationException("Audit log timestamp cannot be in the future");
        }

        // ADD: Entity to context
        await _context.AuditLogs.AddAsync(auditLog, cancellationToken);

        // NOTE: SaveChanges NOT called here (Unit of Work pattern)
        // Service layer calls _context.SaveChangesAsync()

        return auditLog;
    }

    /// <inheritdoc/>
    public async Task<IEnumerable<AuditLog>> GetByUserIdAsync(
        Guid userId,
        int skip = 0,
        int take = 100,
        CancellationToken cancellationToken = default)
    {
        // VALIDATION: Pagination parameters
        if (skip < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(skip), "Skip cannot be negative");
        }

        if (take < 1 || take > 1000)
        {
            throw new ArgumentOutOfRangeException(nameof(take), "Take must be between 1 and 1000");
        }

        // PERFORMANCE: AsNoTracking() for read-only query
        // PAGINATION: Skip/Take for large datasets
        // SORTING: Order by Timestamp DESC (newest first)
        return await _context.AuditLogs
            .AsNoTracking()
            .Where(a => a.UserId == userId)
            .OrderByDescending(a => a.Timestamp)
            .Skip(skip)
            .Take(take)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<IEnumerable<AuditLog>> GetRecentLogsAsync(
        int count = 100,
        CancellationToken cancellationToken = default)
    {
        // VALIDATION: Count parameter
        if (count < 1 || count > 1000)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "Count must be between 1 and 1000");
        }

        // PERFORMANCE: AsNoTracking() for read-only query
        // SORTING: Order by Timestamp DESC (newest first)
        // LIMIT: Take only requested count
        return await _context.AuditLogs
            .AsNoTracking()
            .OrderByDescending(a => a.Timestamp)
            .Take(count)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<IEnumerable<AuditLog>> GetByResourceIdAsync(
        Guid resourceId,
        CancellationToken cancellationToken = default)
    {
        // PERFORMANCE: AsNoTracking() for read-only query
        // FILTER: By ResourceId (SecretId, UserId, etc.)
        // SORTING: Order by Timestamp DESC (newest first)
        return await _context.AuditLogs
            .AsNoTracking()
            .Where(a => a.ResourceId == resourceId.ToString())
            .OrderByDescending(a => a.Timestamp)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<int> GetTotalCountAsync(
        CancellationToken cancellationToken = default)
    {
        // PERFORMANCE: CountAsync() efficient for large tables
        // CACHING: Consider caching this value (5 min TTL) in production
        return await _context.AuditLogs.CountAsync(cancellationToken);
    }

    // ====================================================================
    // ❌ NO UPDATE OR DELETE METHODS
    // ====================================================================
    // Audit logs are IMMUTABLE. No UpdateAsync() or DeleteAsync() methods.
    // Retention policy enforced by background job (not application code).
    // For compliance: Logs retained 7 years, then archived to cold storage.
}