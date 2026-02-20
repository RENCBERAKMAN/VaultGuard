using System;

namespace VaultGuard.Domain.Common;

/// <summary>
/// BASE ENTITY: Abstract base class for all domain entities
/// 
/// DDD PRINCIPLES:
/// - Common properties (Id, timestamps, soft delete)
/// - Protected setters (encapsulation)
/// - Audit trail support (CreatedAt, UpdatedAt)
/// - Soft delete support (IsDeleted, DeletedAt)
/// </summary>
public abstract class BaseEntity
{
    /// <summary>
    /// UNIQUE IDENTIFIER: Primary key for entity
    /// </summary>
    public Guid Id { get; protected set; }

    /// <summary>
    /// CREATED AT: Entity creation timestamp (UTC)
    /// IMMUTABLE: Set once in constructor, never changed
    /// </summary>
    public DateTime CreatedAt { get; protected set; }

    /// <summary>
    /// UPDATED AT: Last modification timestamp (UTC)
    /// MUTABLE: Updated via UpdateTimestamp() method
    /// </summary>
    public DateTime UpdatedAt { get; protected set; }

    /// <summary>
    /// IS DELETED: Soft delete flag
    /// GDPR: Supports right to erasure with recovery period
    /// </summary>
    public bool IsDeleted { get; protected set; }

    /// <summary>
    /// DELETED AT: Soft delete timestamp (UTC)
    /// NULL: Entity not deleted
    /// </summary>
    public DateTime? DeletedAt { get; protected set; }

    /// <summary>
    /// CONSTRUCTOR: Initialize base entity properties
    /// Called by child class constructors
    /// </summary>
    protected BaseEntity()
    {
        Id = Guid.NewGuid();
        CreatedAt = DateTime.UtcNow;
        UpdatedAt = DateTime.UtcNow;
        IsDeleted = false;
        DeletedAt = null;
    }

    /// <summary>
    /// UPDATE TIMESTAMP: Refresh UpdatedAt timestamp
    /// CALL: Every business method that modifies state
    /// </summary>
    protected void UpdateTimestamp()
    {
        UpdatedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// MARK AS DELETED: Soft delete entity
    /// Sets IsDeleted flag and DeletedAt timestamp
    /// </summary>
    public void MarkAsDeleted()
    {
        IsDeleted = true;
        DeletedAt = DateTime.UtcNow;
        UpdateTimestamp();
    }
    public void Restore()
    {
        IsDeleted = false;
        DeletedAt = null;
        UpdateTimestamp();
    }
}