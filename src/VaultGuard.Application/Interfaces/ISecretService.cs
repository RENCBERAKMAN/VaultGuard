using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VaultGuard.Application.DTOs.Secrets;
using VaultGuard.Domain.Common.Results;

namespace VaultGuard.Application.Interfaces;

/// <summary>
/// Core business logic service interface for secure secret management operations.
/// 
/// ARCHITECTURE PATTERN:
/// This interface defines the application service layer contract that orchestrates:
/// - Secret lifecycle management (CRUD operations)
/// - AES-256-GCM encryption/decryption workflows
/// - Authorization checks (ownership verification)
/// - Audit trail triggers (every sensitive operation logged)
/// - Business rule validation (uniqueness, expiration, quotas)
/// 
/// SECURITY ARCHITECTURE:
/// ┌─────────────────────────────────────────────────────────────┐
/// │ Controller → ISecretService → ISecretRepository + IEncryption│
/// │                              ↓                                │
/// │                         IAuditLogService                      │
/// └─────────────────────────────────────────────────────────────┘
/// 
/// CRITICAL SECURITY PRINCIPLES:
/// 1. **Separation of Concerns**: Decryption is SEPARATE from retrieval
///    - GetSecretByIdAsync → Returns ENCRYPTED value + metadata
///    - GetDecryptedValueAsync → Explicit audit-triggering decryption
/// 
/// 2. **Audit-First Design**: Every decrypt operation MUST log:
///    - Who (UserId)
///    - When (Timestamp UTC)
///    - What (SecretId)
///    - Where (IP Address)
///    - Why (Optional: Access reason/ticket number)
/// 
/// 3. **Defense in Depth**:
///    - Authorization at service layer (not just controller)
///    - Encryption at rest (database)
///    - Encryption in transit (HTTPS)
///    - Zero Trust (always verify ownership)
/// 
/// 4. **Least Privilege**: User can only access their own secrets
///    - Admin can view metadata (not decrypt)
///    - Shared secrets require explicit grant (future feature)
/// 
/// COMPLIANCE:
/// - SOC 2 Type II: Comprehensive audit trail
/// - GDPR Article 32: State-of-the-art encryption
/// - PCI-DSS 3.2.1: Cryptographic key management
/// - NIST SP 800-53: Access control enforcement
/// 
/// THREAD SAFETY:
/// - Implementations MUST be thread-safe (scoped DI lifetime)
/// - CancellationToken support for graceful cancellation
/// - No shared mutable state between requests
/// 
/// PERFORMANCE:
/// - Async/await for I/O operations (database, audit logs)
/// - Pagination recommended for GetSecretsByUserIdAsync (future)
/// - Caching NOT recommended (security over performance)
/// </summary>
/// <remarks>
/// ⚠️ IMPLEMENTATION CHECKLIST:
/// Every method implementation MUST:
/// 1. ✅ Validate input parameters (null checks, business rules)
/// 2. ✅ Verify authorization (current user owns the secret)
/// 3. ✅ Perform operation (encrypt/decrypt/CRUD)
/// 4. ✅ Log audit event (success/failure)
/// 5. ✅ Return IResult/IDataResult (never throw exceptions to controller)
/// 6. ✅ Handle CancellationToken (respect client disconnection)
/// </remarks>
public interface ISecretService
{
    /// <summary>
    /// Retrieves all secrets owned by a specific user (encrypted values included).
    /// 
    /// SECURITY FLOW:
    /// 1. Verify: Is requesterId == userId? (Authorization)
    /// 2. If Admin: Allow metadata view (exclude EncryptedValue)
    /// 3. Fetch secrets from repository
    /// 4. Map to SecretDto (Domain → DTO)
    /// 5. Audit log: "User {userId} listed their secrets"
    /// 
    /// AUTHORIZATION:
    /// - Users can ONLY list their own secrets
    /// - Admin can list all secrets (metadata only, no encrypted values)
    /// 
    /// PAGINATION (Recommended Future Enhancement):
    /// - Add: int pageNumber, int pageSize parameters
    /// - Return: PagedResult<SecretDto> with TotalCount, TotalPages
    /// 
    /// PERFORMANCE:
    /// - Query optimizations: EF Core Include() for eager loading
    /// - No N+1 query problem (single database roundtrip)
    /// </summary>
    /// <param name="userId">Owner user ID (must match current authenticated user)</param>
    /// <param name="cancellationToken">Cancellation token for request timeout</param>
    /// <returns>
    /// Success: IDataResult with List of SecretDto (encrypted values included)
    /// Failure: ErrorDataResult with authorization/database errors
    /// </returns>
    /// <example>
    /// var result = await _secretService.GetSecretsByUserIdAsync(currentUserId, ct);
    /// if (result.Success) 
    /// {
    ///     foreach (var secret in result.Data) 
    ///     {
    ///         Console.WriteLine($"{secret.Title}: {secret.EncryptedValue}");
    ///     }
    /// }
    /// </example>
    Task<IDataResult<IEnumerable<SecretDto>>> GetSecretsByUserIdAsync(
        Guid userId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a single secret by ID (encrypted value included, NO auto-decryption).
    /// 
    /// CRITICAL SECURITY DESIGN:
    /// This method returns the ENCRYPTED value. To get plaintext, client must:
    /// 1. Call GetSecretByIdAsync (get metadata + encrypted value)
    /// 2. Explicitly call GetDecryptedValueAsync (triggers audit log)
    /// 
    /// WHY SEPARATION?
    /// - Decryption is expensive (CPU-bound AES operation)
    /// - Decryption must be audited (compliance requirement)
    /// - Many use cases only need metadata (title, expiration, access count)
    /// 
    /// SECURITY FLOW:
    /// 1. Verify: Does secret exist?
    /// 2. Verify: Does current user own this secret?
    /// 3. If not owner + not admin: Return 403 Forbidden
    /// 4. Fetch secret from repository
    /// 5. Map to SecretDto
    /// 6. NO audit log (read-only metadata access)
    /// 
    /// AUTHORIZATION:
    /// - Owner: Full access
    /// - Admin: Metadata only (EncryptedValue excluded)
    /// - Other users: 403 Forbidden
    /// 
    /// ERROR HANDLING:
    /// - 404 Not Found: Secret doesn't exist
    /// - 403 Forbidden: Not authorized to view
    /// - 410 Gone: Secret expired (optional, depends on business rules)
    /// </summary>
    /// <param name="secretId">Unique secret identifier</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>
    /// Success: IDataResult with SecretDto (EncryptedValue included)
    /// Failure: ErrorDataResult with "Not Found" or "Forbidden" message
    /// </returns>
    Task<IDataResult<SecretDto>> GetSecretByIdAsync(
        Guid secretId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// 🚨 CRITICAL SECURITY METHOD: Decrypts a secret value (AUDIT LOGGED).
    /// 
    /// ⚠️ THIS IS THE MOST SENSITIVE OPERATION IN THE ENTIRE SYSTEM!
    /// 
    /// ZERO TRUST SECURITY WORKFLOW:
    /// 1. ✅ Verify: Does secret exist?
    /// 2. ✅ Verify: Is current user the owner?
    /// 3. ✅ Verify: Is secret not expired?
    /// 4. ✅ Fetch encrypted value from database
    /// 5. ✅ Decrypt using AES-256-GCM (IEncryptionService)
    /// 6. ✅ Increment AccessCount in database
    /// 7. ✅ Update LastAccessedAt timestamp
    /// 8. ✅ **MANDATORY AUDIT LOG**:
    ///       - Event: "SECRET_DECRYPTED"
    ///       - UserId: Current authenticated user
    ///       - SecretId: Target secret
    ///       - Timestamp: UTC now
    ///       - IpAddress: Request origin
    ///       - UserAgent: Client browser/app
    ///       - Result: Success/Failure
    /// 9. ✅ Return plaintext value (NEVER log this!)
    /// 
    /// THREAT MODEL MITIGATION:
    /// - Brute-force: Rate limiting (100 decryptions/hour per user)
    /// - Replay attack: Short-lived JWT tokens + CSRF protection
    /// - MITM: HTTPS/TLS 1.3 mandatory
    /// - Privilege escalation: Authorization checks at every layer
    /// - Data exfiltration: Audit trail detects unusual access patterns
    /// 
    /// COMPLIANCE REQUIREMENTS:
    /// - SOC 2: Every access to sensitive data must be logged
    /// - GDPR Art 32: "Ability to ensure ongoing confidentiality"
    /// - PCI-DSS 10.2: Audit trail for access to cardholder data
    /// - HIPAA §164.312(b): Audit controls for PHI access
    /// 
    /// RATE LIMITING (Recommended):
    /// - Max 100 decryptions per user per hour
    /// - Max 10 decryptions per secret per hour (detect compromise)
    /// - Exponential backoff on repeated failures
    /// 
    /// PERFORMANCE:
    /// - Decryption is CPU-bound (~1ms per operation)
    /// - Do NOT cache decrypted values (security over performance)
    /// - Consider: Background job for batch decryption (admin export)
    /// </summary>
    /// <param name="secretId">Secret to decrypt</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>
    /// Success: IDataResult with plaintext string (NEVER log this!)
    /// Failure: ErrorDataResult with authorization/decryption errors
    /// </returns>
    /// <remarks>
    /// 🚨 LOGGING POLICY:
    /// ❌ NEVER log the returned plaintext value!
    /// ❌ NEVER log the encrypted value!
    /// ✅ DO log: SecretId, UserId, Timestamp, IP, Success/Failure
    /// 
    /// Example audit log entry:
    /// {
    ///   "EventType": "SECRET_DECRYPTED",
    ///   "SecretId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    ///   "UserId": "a1b2c3d4-...",
    ///   "Timestamp": "2025-02-14T12:34:56Z",
    ///   "IpAddress": "203.0.113.42",
    ///   "UserAgent": "Mozilla/5.0...",
    ///   "Result": "Success"
    /// }
    /// </remarks>
    Task<IDataResult<string>> GetDecryptedValueAsync(
        Guid secretId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Creates a new encrypted secret for the current user.
    /// 
    /// SECURITY WORKFLOW:
    /// 1. ✅ Validate CreateSecretDto (FluentValidation)
    /// 2. ✅ Check: User quota (max 1000 secrets per user)
    /// 3. ✅ Check: Duplicate title (same user + same title = reject)
    /// 4. ✅ Encrypt RawValue using AES-256-GCM:
    ///       - Generate random 96-bit IV (nonce)
    ///       - Encrypt: AES-GCM(Plaintext, UserKey, IV)
    ///       - Output: Base64(IV + Ciphertext + AuthTag)
    /// 5. ✅ Map DTO → Domain Entity (Secret)
    /// 6. ✅ Persist to database (only encrypted value)
    /// 7. ✅ Audit log: "SECRET_CREATED" (no values logged)
    /// 8. ✅ Clear RawValue from memory (security)
    /// 9. ✅ Return SecretDto (encrypted value included)
    /// 
    /// VALIDATION:
    /// - Title: Required, 3-200 chars, unique per user
    /// - RawValue: Required, 1-10000 chars (10KB limit)
    /// - ExpiresAt: Optional, must be future date
    /// - Category: Optional, 50 chars max
    /// 
    /// AUTHORIZATION:
    /// - Any authenticated user can create secrets
    /// - Rate limit: 100 creates per user per hour
    /// 
    /// BUSINESS RULES:
    /// - User cannot exceed quota (1000 secrets)
    /// - Duplicate titles rejected (per user)
    /// - Expired secrets auto-flagged (not deleted)
    /// </summary>
    /// <param name="dto">Secret creation data (contains PLAINTEXT RawValue)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>
    /// Success: IDataResult with created SecretDto (ID assigned)
    /// Failure: ErrorDataResult with validation/quota/duplicate errors
    /// </returns>
    Task<IDataResult<SecretDto>> CreateSecretAsync(
        CreateSecretDto dto,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing secret (partial update supported).
    /// 
    /// SECURITY WORKFLOW:
    /// 1. ✅ Verify: Does secret exist?
    /// 2. ✅ Verify: Is current user the owner?
    /// 3. ✅ Validate UpdateSecretDto
    /// 4. ✅ If NewRawValue provided:
    ///       a. Decrypt old value (for audit comparison)
    ///       b. Hash old value (SHA-256)
    ///       c. Hash new value (SHA-256)
    ///       d. If hashes identical: Skip re-encryption
    ///       e. Else: Re-encrypt with new IV
    ///       f. Audit log: "SECRET_VALUE_CHANGED" (hashes logged, not values)
    /// 5. ✅ Update metadata (Title, Description, ExpiresAt)
    /// 6. ✅ Persist changes
    /// 7. ✅ Audit log: "SECRET_UPDATED" (what changed)
    /// 8. ✅ Return updated SecretDto
    /// 
    /// PARTIAL UPDATE:
    /// - Only provided fields are updated
    /// - Null values = no change
    /// - Example: { Id: "...", Title: "New Title" } → Only title updated
    /// 
    /// AUTHORIZATION:
    /// - Only owner can update
    /// - Admin cannot update (read-only access)
    /// 
    /// VALIDATION:
    /// - Title: If provided, 3-200 chars, unique per user
    /// - NewRawValue: If provided, 1-10000 chars
    /// - ExpiresAt: If provided, must be future date
    /// </summary>
    /// <param name="dto">Update data (partial)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>
    /// Success: IDataResult with updated SecretDto
    /// Failure: ErrorDataResult with authorization/validation errors
    /// </returns>
    Task<IDataResult<SecretDto>> UpdateSecretAsync(
        UpdateSecretDto dto,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Permanently deletes a secret (GDPR right to erasure).
    /// 
    /// SECURITY WORKFLOW:
    /// 1. ✅ Verify: Does secret exist?
    /// 2. ✅ Verify: Is current user the owner?
    /// 3. ✅ Soft delete (recommended): Set IsDeleted = true
    ///       - Allows recovery within 30 days
    ///       - Maintains audit trail integrity
    /// 4. ✅ OR Hard delete (GDPR): Physically remove from database
    ///       - Keep audit log reference (SecretId only)
    ///       - No recovery possible
    /// 5. ✅ Audit log: "SECRET_DELETED" (permanent record)
    /// 6. ✅ Return success result
    /// 
    /// SOFT DELETE vs HARD DELETE:
    /// - Soft Delete (Recommended):
    ///   * Set IsDeleted flag = true
    ///   * Exclude from queries (WHERE IsDeleted = false)
    ///   * Background job: Purge after 30 days
    ///   * Allows: "Oops, I deleted it by mistake" recovery
    /// 
    /// - Hard Delete (GDPR Compliant):
    ///   * Physical removal from database
    ///   * Irreversible (no recovery)
    ///   * Audit log keeps reference: "User X deleted secret Y"
    ///   * Required for: "Right to be forgotten" requests
    /// 
    /// AUTHORIZATION:
    /// - Only owner can delete
    /// - Admin cannot delete (data integrity)
    /// 
    /// AUDIT TRAIL:
    /// - Deletion event ALWAYS logged
    /// - Audit log persists even after hard delete
    /// - Compliance: SOC 2, GDPR Art 30 (Records of processing)
    /// </summary>
    /// <param name="secretId">Secret to delete</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>
    /// Success: IResult (no data returned)
    /// Failure: ErrorResult with "Not Found" or "Forbidden" message
    /// </returns>
    Task<IResult> DeleteSecretAsync(
        Guid secretId,
        CancellationToken cancellationToken = default);
}