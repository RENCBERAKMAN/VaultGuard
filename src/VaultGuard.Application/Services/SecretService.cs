using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using VaultGuard.Application.Interfaces;
using VaultGuard.Application.DTOs.Secrets;
using VaultGuard.Domain.Common.Results;
using VaultGuard.Domain.Entities;

namespace VaultGuard.Application.Services;

/// <summary>
/// SECRET MANAGEMENT SERVICE - Enterprise-Grade Security
/// 
/// SECURITY ARCHITECTURE:
/// - ✅ AES-256-GCM Encryption (NIST FIPS 197)
/// - ✅ Ownership Validation (IDOR prevention)
/// - ✅ Audit Logging (SOC 2, PCI-DSS compliance)
/// - ✅ Access Tracking (LastAccessedAt, AccessCount)
/// - ✅ Expiration Support (Automatic rotation)
/// - ✅ Domain-Driven Design (Rich domain model)
/// 
/// COMPLIANCE:
/// - PCI-DSS Requirement 3: Encrypted data at rest
/// - HIPAA §164.312: Encryption of PHI
/// - GDPR Article 32: Security measures
/// - SOC 2: Encryption key management
/// </summary>
public sealed class SecretService : ISecretService
{
    private readonly ISecretRepository _secretRepository;
    private readonly IEncryptionService _encryptionService;
    private readonly IAuditLogService _auditLogService;

    public SecretService(
        ISecretRepository secretRepository,
        IEncryptionService encryptionService,
        IAuditLogService auditLogService)
    {
        _secretRepository = secretRepository ?? throw new ArgumentNullException(nameof(secretRepository));
        _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
        _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
    }

    // ============================================================================
    // 🔐 CREATE SECRET
    // ============================================================================

    /// <inheritdoc/>
    public async Task<IDataResult<SecretDto>> CreateSecretAsync(
        CreateSecretDto dto,
        Guid userId,
        string? ipAddress = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // 1. VALIDATION
            if (string.IsNullOrWhiteSpace(dto.Title))
                return new ErrorDataResult<SecretDto>("Secret title is required");

            if (string.IsNullOrWhiteSpace(dto.RawValue))
                return new ErrorDataResult<SecretDto>("Secret value is required");

            // 2. DUPLICATE CHECK
            var existingSecret = await _secretRepository.GetByTitleAndUserIdAsync(
                userId,
                dto.Title,
                cancellationToken);

            if (existingSecret != null)
                return new ErrorDataResult<SecretDto>(
                    $"A secret with title '{dto.Title}' already exists");

            // 3. QUOTA CHECK (max 1000 secrets per user)
            var secretCount = await _secretRepository.GetCountByUserIdAsync(userId, cancellationToken);
            if (secretCount >= 1000)
                return new ErrorDataResult<SecretDto>(
                    "Secret quota exceeded. Maximum 1000 secrets per user.");

            // 4. ENCRYPTION
            string encryptedBase64;
            try
            {
                encryptedBase64 = _encryptionService.Encrypt(dto.RawValue);

                if (string.IsNullOrWhiteSpace(encryptedBase64))
                    throw new InvalidOperationException("Encryption resulted in empty value");
            }
            catch (Exception ex)
            {
                return new ErrorDataResult<SecretDto>($"Encryption failed: {ex.Message}");
            }

            // 5. EXTRACT REAL NONCE FROM ENCRYPTED VALUE
            // AesEncryptionService çıktısı: Nonce(12) + Ciphertext + Tag(16) formatında Base64'tür.
            // Secret.IV alanının gerçek (decrypt'te kullanılabilir) veriyle tutarlı olması için
            // rastgele/sahte IV üretmek yerine gerçek nonce'u buradan çıkarıyoruz.
            var encryptedRawBytes = Convert.FromBase64String(encryptedBase64);
            var iv = new byte[12];
            Buffer.BlockCopy(encryptedRawBytes, 0, iv, 0, 12);
            // 6. CREATE DOMAIN ENTITY
            var secret = Secret.Create(
                title: dto.Title,
                encryptedValue: encryptedBase64,
                iv: iv,
                userId: userId,
                category: dto.Category ?? "Other",
                description: dto.Description,
                expiresAt: dto.ExpiresAt);

            // 7. PERSISTENCE
            await _secretRepository.AddAsync(secret, cancellationToken);

            // 8. AUDIT LOG
            await _auditLogService.LogSecurityEventAsync(
                eventType: "SECRET_CREATED",
                userId: userId,
                resourceId: secret.Id,
                action: $"User created secret: {dto.Title}",
                result: "Success",
                ipAddress: ipAddress,
                userAgent: null,
                additionalData: $"{{\"Category\":\"{secret.Category}\"}}",
                cancellationToken: cancellationToken);

            // 9. RESPONSE DTO
            var responseDto = new SecretDto
            {
                Id = secret.Id,
                Title = secret.Title,
                Category = secret.Category,
                Description = secret.Description,
                CreatedAt = secret.CreatedAt,
                UpdatedAt = secret.UpdatedAt,
                ExpiresAt = secret.ExpiresAt,
                LastAccessedAt = secret.LastAccessedAt,
                AccessCount = secret.AccessCount,
                UserId = secret.UserId,
                HasExpiration = secret.ExpiresAt.HasValue
            };

            return new SuccessDataResult<SecretDto>(
                responseDto,
                "Secret created successfully");
        }
        catch (OperationCanceledException)
        {
            return new ErrorDataResult<SecretDto>("Operation was cancelled");
        }
        catch (Exception ex)
        {
            await _auditLogService.LogSecurityEventAsync(
                eventType: "SECRET_CREATION_FAILED",
                userId: userId,
                resourceId: null,
                action: $"Failed to create secret: {dto.Title}",
                result: "Failure",
                ipAddress: ipAddress,
                userAgent: null,
                additionalData: $"{{\"Error\":\"{ex.Message}\"}}",
                cancellationToken: cancellationToken);

            return new ErrorDataResult<SecretDto>(
                $"Failed to create secret: {ex.Message}");
        }
    }

    // ============================================================================
    // 🔓 DECRYPT SECRET
    // ============================================================================

    /// <inheritdoc/>
    public async Task<IDataResult<string>> GetDecryptedValueAsync(
        Guid secretId,
        Guid userId,
        string? ipAddress = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // 1. FETCH SECRET
            var secret = await _secretRepository.GetByIdAsync(secretId, cancellationToken);

            if (secret == null)
            {
                await _auditLogService.LogSecurityEventAsync(
                    eventType: "SECRET_DECRYPTION_FAILED",
                    userId: userId,
                    resourceId: secretId,
                    action: "Secret not found",
                    result: "Failure",
                    ipAddress: ipAddress,
                    userAgent: null,
                    additionalData: "{\"Reason\":\"NotFound\"}",
                    cancellationToken: cancellationToken);

                return new ErrorDataResult<string>("Secret not found");
            }

            // 2. IDOR PROTECTION (CRITICAL!)
            if (secret.UserId != userId)
            {
                await _auditLogService.LogSecurityEventAsync(
                    eventType: "UNAUTHORIZED_DECRYPT_ATTEMPT",
                    userId: userId,
                    resourceId: secretId,
                    action: $"User {userId} attempted to decrypt secret owned by {secret.UserId}",
                    result: "Failure",
                    ipAddress: ipAddress,
                    userAgent: null,
                    additionalData: $"{{\"AttackType\":\"IDOR\",\"VictimUserId\":\"{secret.UserId}\"}}",
                    cancellationToken: cancellationToken);

                return new ErrorDataResult<string>(
                    "Forbidden: You do not have permission to decrypt this secret");
            }

            // 3. EXPIRATION CHECK
            if (secret.IsExpired)
            {
                await _auditLogService.LogSecurityEventAsync(
                    eventType: "EXPIRED_SECRET_DECRYPT_ATTEMPT",
                    userId: userId,
                    resourceId: secretId,
                    action: $"User attempted to decrypt expired secret: {secret.Title}",
                    result: "Failure",
                    ipAddress: ipAddress,
                    userAgent: null,
                    additionalData: $"{{\"ExpiresAt\":\"{secret.ExpiresAt:O}\"}}",
                    cancellationToken: cancellationToken);

                return new ErrorDataResult<string>("Secret has expired and cannot be decrypted");
            }

            // 4. DECRYPTION
            string decryptedValue;
            try
            {
                decryptedValue = _encryptionService.Decrypt(secret.EncryptedValue);

                if (string.IsNullOrWhiteSpace(decryptedValue))
                    throw new InvalidOperationException("Decryption resulted in empty value");
            }
            catch (Exception ex)
            {
                await _auditLogService.LogSecurityEventAsync(
                    eventType: "SECRET_DECRYPTION_FAILED",
                    userId: userId,
                    resourceId: secretId,
                    action: "Decryption failed due to cryptographic error",
                    result: "Failure",
                    ipAddress: ipAddress,
                    userAgent: null,
                    additionalData: $"{{\"ErrorType\":\"{ex.GetType().Name}\"}}",
                    cancellationToken: cancellationToken);

                return new ErrorDataResult<string>(
                    "Failed to decrypt secret. Data may be corrupted or encryption key changed.");
            }

            // 5. ACCESS TRACKING
            secret.RecordAccess();
            await _secretRepository.UpdateAsync(secret, cancellationToken);

            // 6. AUDIT LOG (Success)
            await _auditLogService.LogSecurityEventAsync(
                eventType: "SECRET_DECRYPTED",
                userId: userId,
                resourceId: secretId,
                action: $"User successfully decrypted secret: {secret.Title}",
                result: "Success",
                ipAddress: ipAddress,
                userAgent: null,
                additionalData: $"{{\"AccessCount\":{secret.AccessCount}}}",
                cancellationToken: cancellationToken);

            return new SuccessDataResult<string>(
                decryptedValue,
                "Secret decrypted successfully");
        }
        catch (OperationCanceledException)
        {
            return new ErrorDataResult<string>("Operation was cancelled");
        }
        catch (Exception ex)
        {
            await _auditLogService.LogSecurityEventAsync(
                eventType: "SECRET_DECRYPTION_ERROR",
                userId: userId,
                resourceId: secretId,
                action: "Exception during secret decryption",
                result: "Failure",
                ipAddress: ipAddress,
                userAgent: null,
                additionalData: $"{{\"Error\":\"{ex.Message}\"}}",
                cancellationToken: cancellationToken);

            return new ErrorDataResult<string>($"Failed to decrypt secret: {ex.Message}");
        }
    }

    // ============================================================================
    // 📋 GET ALL USER SECRETS
    // ============================================================================

    /// <inheritdoc/>
    public async Task<IDataResult<IEnumerable<SecretDto>>> GetSecretsByUserIdAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var secrets = await _secretRepository.GetByUserIdAsync(userId, cancellationToken);

            var responseDtos = secrets.Select(s => new SecretDto
            {
                Id = s.Id,
                Title = s.Title,
                Category = s.Category,
                Description = s.Description,
                CreatedAt = s.CreatedAt,
                UpdatedAt = s.UpdatedAt,
                ExpiresAt = s.ExpiresAt,
                LastAccessedAt = s.LastAccessedAt,
                AccessCount = s.AccessCount,
                UserId = s.UserId,
                HasExpiration = s.ExpiresAt.HasValue
            }).ToList();

            return new SuccessDataResult<IEnumerable<SecretDto>>(
                responseDtos,
                $"Retrieved {responseDtos.Count} secrets successfully");
        }
        catch (OperationCanceledException)
        {
            return new ErrorDataResult<IEnumerable<SecretDto>>("Operation was cancelled");
        }
        catch (Exception ex)
        {
            return new ErrorDataResult<IEnumerable<SecretDto>>(
                $"Failed to retrieve secrets: {ex.Message}");
        }
    }

    // ============================================================================
    // 🔍 GET SECRET BY ID
    // ============================================================================

    /// <inheritdoc/>
    public async Task<IDataResult<SecretDto>> GetSecretByIdAsync(
        Guid secretId,
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var secret = await _secretRepository.GetByIdAsync(secretId, cancellationToken);

            if (secret == null)
                return new ErrorDataResult<SecretDto>("Secret not found");

            // IDOR PROTECTION
            if (secret.UserId != userId)
            {
                await _auditLogService.LogSecurityEventAsync(
                    eventType: "UNAUTHORIZED_ACCESS_ATTEMPT",
                    userId: userId,
                    resourceId: secretId,
                    action: "User attempted to access secret owned by another user",
                    result: "Failure",
                    ipAddress: null,
                    userAgent: null,
                    additionalData: null,
                    cancellationToken: cancellationToken);

                return new ErrorDataResult<SecretDto>(
                    "Forbidden: You do not have permission to access this secret");
            }

            var responseDto = new SecretDto
            {
                Id = secret.Id,
                Title = secret.Title,
                Category = secret.Category,
                Description = secret.Description,
                CreatedAt = secret.CreatedAt,
                UpdatedAt = secret.UpdatedAt,
                ExpiresAt = secret.ExpiresAt,
                LastAccessedAt = secret.LastAccessedAt,
                AccessCount = secret.AccessCount,
                UserId = secret.UserId,
                HasExpiration = secret.ExpiresAt.HasValue
            };

            return new SuccessDataResult<SecretDto>(
                responseDto,
                "Secret retrieved successfully");
        }
        catch (OperationCanceledException)
        {
            return new ErrorDataResult<SecretDto>("Operation was cancelled");
        }
        catch (Exception ex)
        {
            return new ErrorDataResult<SecretDto>(
                $"Failed to retrieve secret: {ex.Message}");
        }
    }

    // ============================================================================
    // ✏️ UPDATE SECRET
    // ============================================================================

    /// <inheritdoc/>
    public async Task<IDataResult<SecretDto>> UpdateSecretAsync(
        UpdateSecretDto dto,
        Guid userId,
        string? ipAddress = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // 1. FETCH + OWNERSHIP VALIDATION
            var secret = await _secretRepository.GetByIdAsync(dto.Id, cancellationToken);

            if (secret == null)
                return new ErrorDataResult<SecretDto>("Secret not found");

            if (secret.UserId != userId)
            {
                await _auditLogService.LogSecurityEventAsync(
                    eventType: "UNAUTHORIZED_UPDATE_ATTEMPT",
                    userId: userId,
                    resourceId: dto.Id,
                    action: $"User {userId} attempted to update secret owned by {secret.UserId}",
                    result: "Failure",
                    ipAddress: ipAddress,
                    userAgent: null,
                    additionalData: "{\"AttackType\":\"IDOR\"}",
                    cancellationToken: cancellationToken);

                return new ErrorDataResult<SecretDto>(
                    "Forbidden: You do not have permission to update this secret");
            }

            // Track changes
            var changedFields = new List<string>();

            // 2. TITLE UPDATE
            if (!string.IsNullOrWhiteSpace(dto.Title) && dto.Title != secret.Title)
            {
                var existingSecret = await _secretRepository.GetByTitleAndUserIdAsync(
                    userId,
                    dto.Title,
                    cancellationToken);

                if (existingSecret != null && existingSecret.Id != dto.Id)
                    return new ErrorDataResult<SecretDto>(
                        $"A secret with title '{dto.Title}' already exists");

                secret.UpdateTitle(dto.Title);
                changedFields.Add("Title");
            }

            // 3. DESCRIPTION UPDATE
            if (dto.Description != null && dto.Description != secret.Description)
            {
                secret.UpdateDescription(dto.Description);
                changedFields.Add("Description");
            }

            // 4. CATEGORY UPDATE
            if (dto.Category != null && dto.Category != secret.Category)
            {
                secret.UpdateCategory(dto.Category);
                changedFields.Add("Category");
            }

            // 5. VALUE UPDATE (RE-ENCRYPTION)
            if (!string.IsNullOrWhiteSpace(dto.NewRawValue))
            {
                try
                {
                    var newEncryptedValue = _encryptionService.Encrypt(dto.NewRawValue);

                    if (string.IsNullOrWhiteSpace(newEncryptedValue))
                        throw new InvalidOperationException("Encryption resulted in empty value");

                    // Extract real nonce from re-encrypted value (aynı gerekçe: CreateSecretAsync'e bak)
                    var newEncryptedRawBytes = Convert.FromBase64String(newEncryptedValue);
                    var newIv = new byte[12];
                    Buffer.BlockCopy(newEncryptedRawBytes, 0, newIv, 0, 12);

                    secret.ReEncrypt(newEncryptedValue, newIv);
                    changedFields.Add("Value");

                    // Audit value change
                    await _auditLogService.LogSecurityEventAsync(
                        eventType: "SECRET_VALUE_CHANGED",
                        userId: userId,
                        resourceId: secret.Id,
                        action: $"User changed secret value: {secret.Title}",
                        result: "Success",
                        ipAddress: ipAddress,
                        userAgent: null,
                        additionalData: null,
                        cancellationToken: cancellationToken);
                }
                catch (Exception ex)
                {
                    return new ErrorDataResult<SecretDto>($"Re-encryption failed: {ex.Message}");
                }
            }

            // 6. EXPIRATION UPDATE
            if (dto.ExpiresAt.HasValue && dto.ExpiresAt != secret.ExpiresAt)
            {
                if (dto.ExpiresAt.Value < DateTime.UtcNow)
                    return new ErrorDataResult<SecretDto>("Expiration date must be in the future");

                secret.SetExpiration(dto.ExpiresAt);
                changedFields.Add("ExpiresAt");
            }

            // If nothing changed, return early
            if (changedFields.Count == 0)
            {
                var unchangedDto = new SecretDto
                {
                    Id = secret.Id,
                    Title = secret.Title,
                    Category = secret.Category,
                    Description = secret.Description,
                    CreatedAt = secret.CreatedAt,
                    UpdatedAt = secret.UpdatedAt,
                    ExpiresAt = secret.ExpiresAt,
                    LastAccessedAt = secret.LastAccessedAt,
                    AccessCount = secret.AccessCount,
                    UserId = secret.UserId,
                    HasExpiration = secret.ExpiresAt.HasValue
                };
                return new SuccessDataResult<SecretDto>(unchangedDto, "No changes to update");
            }

            // 7. PERSISTENCE
            await _secretRepository.UpdateAsync(secret, cancellationToken);

            // 8. AUDIT LOG
            await _auditLogService.LogSecurityEventAsync(
                eventType: "SECRET_UPDATED",
                userId: userId,
                resourceId: secret.Id,
                action: $"User updated secret: {secret.Title}",
                result: "Success",
                ipAddress: ipAddress,
                userAgent: null,
                additionalData: $"{{\"ChangedFields\":[\"{string.Join("\",\"", changedFields)}\"]}}",
                cancellationToken: cancellationToken);

            // 9. RESPONSE
            var responseDto = new SecretDto
            {
                Id = secret.Id,
                Title = secret.Title,
                Category = secret.Category,
                Description = secret.Description,
                CreatedAt = secret.CreatedAt,
                UpdatedAt = secret.UpdatedAt,
                ExpiresAt = secret.ExpiresAt,
                LastAccessedAt = secret.LastAccessedAt,
                AccessCount = secret.AccessCount,
                UserId = secret.UserId,
                HasExpiration = secret.ExpiresAt.HasValue
            };

            return new SuccessDataResult<SecretDto>(
                responseDto,
                "Secret updated successfully");
        }
        catch (OperationCanceledException)
        {
            return new ErrorDataResult<SecretDto>("Operation was cancelled");
        }
        catch (Exception ex)
        {
            await _auditLogService.LogSecurityEventAsync(
                eventType: "SECRET_UPDATE_FAILED",
                userId: userId,
                resourceId: dto.Id,
                action: "Failed to update secret",
                result: "Failure",
                ipAddress: ipAddress,
                userAgent: null,
                additionalData: $"{{\"Error\":\"{ex.Message}\"}}",
                cancellationToken: cancellationToken);

            return new ErrorDataResult<SecretDto>(
                $"Failed to update secret: {ex.Message}");
        }
    }

    // ============================================================================
    // 🗑️ DELETE SECRET
    // ============================================================================

    /// <inheritdoc/>
    public async Task<IResult> DeleteSecretAsync(
        Guid secretId,
        Guid userId,
        string? ipAddress = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // 1. FETCH + OWNERSHIP VALIDATION
            var secret = await _secretRepository.GetByIdAsync(secretId, cancellationToken);

            if (secret == null)
                return new ErrorResult("Secret not found");

            if (secret.UserId != userId)
            {
                await _auditLogService.LogSecurityEventAsync(
                    eventType: "UNAUTHORIZED_DELETE_ATTEMPT",
                    userId: userId,
                    resourceId: secretId,
                    action: $"User {userId} attempted to delete secret owned by {secret.UserId}",
                    result: "Failure",
                    ipAddress: ipAddress,
                    userAgent: null,
                    additionalData: "{\"AttackType\":\"IDOR\"}",
                    cancellationToken: cancellationToken);

                return new ErrorResult(
                    "Forbidden: You do not have permission to delete this secret");
            }

            // 2. SOFT DELETE
            await _secretRepository.DeleteAsync(secret, cancellationToken);

            // 3. AUDIT LOG
            await _auditLogService.LogSecurityEventAsync(
                eventType: "SECRET_DELETED",
                userId: userId,
                resourceId: secretId,
                action: $"User deleted secret: {secret.Title}",
                result: "Success",
                ipAddress: ipAddress,
                userAgent: null,
                additionalData: $"{{\"Category\":\"{secret.Category}\"}}",
                cancellationToken: cancellationToken);

            return new SuccessResult("Secret deleted successfully");
        }
        catch (OperationCanceledException)
        {
            return new ErrorResult("Operation was cancelled");
        }
        catch (Exception ex)
        {
            await _auditLogService.LogSecurityEventAsync(
                eventType: "SECRET_DELETION_FAILED",
                userId: userId,
                resourceId: secretId,
                action: "Failed to delete secret",
                result: "Failure",
                ipAddress: ipAddress,
                userAgent: null,
                additionalData: $"{{\"Error\":\"{ex.Message}\"}}",
                cancellationToken: cancellationToken);

            return new ErrorResult($"Failed to delete secret: {ex.Message}");
        }
    }
}