using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VaultGuard.Domain.Entities;

namespace VaultGuard.Application.Interfaces;

/// <summary>
/// Repository interface for audit log persistence (append-only operations).
/// 
/// SECURITY ARCHITECTURE:
/// Audit logs are the IMMUTABLE historical record of all security events:
/// - Append-only: No UPDATE or DELETE operations (ever!)
/// - Write-optimized: Bulk inserts for performance
/// - Query-optimized: Indexed on UserId, Timestamp, EventType
/// - Tamper-proof: Digital signatures (optional, high-security env)
/// 
/// ┌─────────────────────────────────────────────────────────────┐
/// │ IAuditLogService → IAuditLogRepository → AuditLogs Table    │
/// │   (Business logic)   (Data access)        (Immutable)       │
/// └─────────────────────────────────────────────────────────────┘
/// 
/// COMPLIANCE REQUIREMENTS:
/// - **SOC 2**: Audit logs retained for minimum 1 year (we use 7 years)
/// - **GDPR**: Right to access personal data (includes audit logs)
/// - **PCI-DSS**: Audit logs retained for 1 year (online), 3 years (archive)
/// - **HIPAA**: Audit logs retained for 6 years
/// 
/// DATA MODEL:
/// AuditLog Entity:
/// - Id (Guid): Primary key
/// - EventType (string): "SECRET_DECRYPTED", "USER_LOGIN", etc.
/// - UserId (Guid?): Actor who performed action (nullable for anonymous)
/// - ResourceId (Guid?): Target resource (SecretId, UserId, etc.)
/// - Action (string): Human-readable description
/// - Result (string): "Success" or "Failure"
/// - Timestamp (DateTime): UTC timestamp (immutable)
/// - IpAddress (string): Client IP address
/// - UserAgent (string): Client browser/app
/// - AdditionalData (string): JSON metadata (max 4KB)
/// - CorrelationId (Guid): Trace distributed requests
/// - Duration (TimeSpan?): Operation duration
/// 
/// DATABASE SCHEMA:
/// CREATE TABLE AuditLogs (
///     Id uniqueidentifier PRIMARY KEY,
///     EventType nvarchar(100) NOT NULL,
///     UserId uniqueidentifier NULL,
///     ResourceId uniqueidentifier NULL,
///     Action nvarchar(500) NOT NULL,
///     Result nvarchar(50) NOT NULL,
///     Timestamp datetime2 NOT NULL DEFAULT GETUTCDATE(),
///     IpAddress nvarchar(45) NULL,
///     UserAgent nvarchar(500) NULL,
///     AdditionalData nvarchar(max) NULL,
///     CorrelationId uniqueidentifier NULL,
///     Duration bigint NULL, -- milliseconds
///     CONSTRAINT CK_AuditLogs_Result CHECK (Result IN ('Success', 'Failure'))
/// );
/// 
/// -- Performance indexes
/// CREATE NONCLUSTERED INDEX IX_AuditLogs_UserId ON AuditLogs(UserId, Timestamp DESC);
/// CREATE NONCLUSTERED INDEX IX_AuditLogs_EventType ON AuditLogs(EventType, Timestamp DESC);
/// CREATE NONCLUSTERED INDEX IX_AuditLogs_ResourceId ON AuditLogs(ResourceId, Timestamp DESC);
/// CREATE NONCLUSTERED INDEX IX_AuditLogs_Timestamp ON AuditLogs(Timestamp DESC);
/// 
/// PARTITIONING STRATEGY (High Volume):
/// - Partition by Timestamp (monthly partitions)
/// - Archive old partitions to cold storage (AWS S3 Glacier)
/// - Keep recent 90 days in hot storage (fast queries)
/// 
/// RETENTION POLICY:
/// - Active (Database): 90 days
/// - Warm Archive (Blob Storage): 1 year
/// - Cold Archive (Glacier): 7 years
/// - Deletion: After 7 years (compliance maximum)
/// 
/// PERFORMANCE OPTIMIZATIONS:
/// - Bulk insert: Batch multiple logs in single transaction
/// - Async writes: Fire-and-forget pattern
/// - Read replicas: Separate read-only database for queries
/// - NoSQL alternative: MongoDB, InfluxDB for time-series data
/// </summary>
/// <remarks>
/// ⚠️ CRITICAL RESTRICTIONS:
/// 1. ❌ NO UpdateAsync method (audit logs are immutable)
/// 2. ❌ NO DeleteAsync method (retention policy enforced by background job)
/// 3. ✅ ONLY AddAsync for new entries (append-only)
/// 4. ✅ ONLY read queries (GetByUserId, GetRecent, etc.)
/// 
/// ⚠️ SECURITY WARNING:
/// Audit logs contain sensitive metadata (IPs, user agents, actions).
/// Access to this repository should be restricted to:
/// - IAuditLogService (internal use only)
/// - Admin dashboard (read-only, with authorization)
/// - Security team (forensic investigation)
/// - Compliance auditors (external review)
/// </remarks>
public interface IAuditLogRepository
{
    /// <summary>
    /// Adds a new audit log entry (append-only operation).
    /// 
    /// WORKFLOW:
    /// 1. Validate: Entity is not null
    /// 2. Assign: Id = Guid.NewGuid() (if not set)
    /// 3. Set: Timestamp = DateTime.UtcNow (if not set)
    /// 4. DbContext.AuditLogs.Add(auditLog)
    /// 5. Return: Entity with Id assigned
    /// 
    /// TRANSACTION:
    /// - Wrapped in transaction (UnitOfWork pattern)
    /// - Service layer calls SaveChangesAsync
    /// 
    /// BULK INSERT (High Volume):
    /// - Use: DbContext.BulkInsertAsync() for batching
    /// - Batch size: 1000 entries per transaction
    /// - Background queue: RabbitMQ/Azure Service Bus
    /// 
    /// ERROR HANDLING:
    /// - If insert fails: Write to fallback (file, queue)
    /// - Never throw exception to caller (fire-and-forget)
    /// </summary>
    /// <param name="auditLog">Audit log entity to persist</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Added entity with generated Id</returns>
    Task<AuditLog> AddAsync(
        AuditLog auditLog,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves all audit logs for a specific user.
    /// 
    /// QUERY:
    /// - Filter: WHERE UserId = @userId
    /// - Sort: ORDER BY Timestamp DESC (newest first)
    /// - Pagination: OFFSET @skip ROWS FETCH NEXT @take ROWS ONLY
    /// 
    /// USE CASES:
    /// - User profile: "Your recent activity"
    /// - Admin dashboard: "User X's activity history"
    /// - Security investigation: "What did user Y do?"
    /// 
    /// AUTHORIZATION:
    /// - Users can view their own logs
    /// - Admin can view all logs
    /// - Security team can view all logs
    /// 
    /// PERFORMANCE:
    /// - Index: IX_AuditLogs_UserId (covering index)
    /// - Pagination: Required for large datasets
    /// </summary>
    /// <param name="userId">User whose logs to retrieve</param>
    /// <param name="skip">Pagination offset (default: 0)</param>
    /// <param name="take">Pagination limit (default: 100, max: 1000)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of audit log entities</returns>
    Task<IEnumerable<AuditLog>> GetByUserIdAsync(
        Guid userId,
        int skip = 0,
        int take = 100,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves most recent audit logs (admin dashboard).
    /// 
    /// QUERY:
    /// - Sort: ORDER BY Timestamp DESC
    /// - Limit: TOP @count
    /// 
    /// USE CASES:
    /// - Admin dashboard: "Recent security events"
    /// - Real-time monitoring: "Live activity feed"
    /// - Incident response: "What happened in last hour?"
    /// 
    /// AUTHORIZATION:
    /// - Admin only
    /// - Security team only
    /// 
    /// PERFORMANCE:
    /// - Index: IX_AuditLogs_Timestamp (covering index)
    /// - Cache: Redis cache for last 100 logs (5 min TTL)
    /// </summary>
    /// <param name="count">Number of recent logs to retrieve (max: 1000)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of recent audit log entities</returns>
    Task<IEnumerable<AuditLog>> GetRecentLogsAsync(
        int count = 100,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves audit logs for a specific resource (Secret, User, etc.).
    /// 
    /// QUERY:
    /// - Filter: WHERE ResourceId = @resourceId
    /// - Sort: ORDER BY Timestamp DESC
    /// 
    /// USE CASES:
    /// - Secret detail page: "Who accessed this secret?"
    /// - Forensic investigation: "History of secret X"
    /// - Compliance audit: "Prove who accessed data"
    /// 
    /// AUTHORIZATION:
    /// - Resource owner can view
    /// - Admin can view
    /// - Security team can view
    /// </summary>
    /// <param name="resourceId">Target resource ID (SecretId, etc.)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of audit log entities</returns>
    Task<IEnumerable<AuditLog>> GetByResourceIdAsync(
        Guid resourceId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Counts total audit logs (for pagination).
    /// 
    /// QUERY:
    /// - Count: SELECT COUNT(*) FROM AuditLogs
    /// 
    /// PERFORMANCE:
    /// - Expensive operation on large tables (millions of rows)
    /// - Cache result (5 min TTL)
    /// - Use: Approximate count for UI (acceptable error margin)
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Total count of audit logs</returns>
    Task<int> GetTotalCountAsync(
        CancellationToken cancellationToken = default);
}