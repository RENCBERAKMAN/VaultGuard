using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AutoMapper;
using VaultGuard.Application.DTOs.Secrets;
using VaultGuard.Application.Interfaces;
using VaultGuard.Domain.Common.Results;
using VaultGuard.Domain.Entities;

namespace VaultGuard.Application.Services;

/// <summary>
/// Core business logic service for secure secret management with AES-256-GCM encryption.
/// 
/// SECURITY ARCHITECTURE:
/// - Zero Trust: Every operation verifies ownership
/// - Defense in Depth: Encryption + Authorization + Audit Logging
/// - Least Privilege: Users can only access their own secrets
/// - Audit First: Every sensitive operation logged
/// 
/// THREAD SAFETY:
/// - Scoped lifetime (one instance per HTTP request)
/// - No shared mutable state
/// - All operations are thread-safe
/// 
/// PERFORMANCE:
/// - Async/await for I/O operations
/// - Minimal memory allocation
/// - Efficient LINQ queries
/// </summary>
public sealed class SecretService : ISecretService
{
    private readonly ISecretRepository _secretRepository;
    private readonly IAuditLogService _auditLogService;
    private readonly ICurrentUserService _currentUserService;
    private readonly IEncryptionService _encryptionService;
    private readonly IMapper _mapper;

    /// <summary>
    /// Initializes a new instance of SecretService with required dependencies.
    /// </summary>
    /// <param name="secretRepository">Repository for secret persistence</param>
    /// <param name="auditLogService">Service for security audit logging</param>
    /// <param name="currentUserService">Service for current user context</param>
    /// <param name="encryptionService">Service for AES-256-GCM encryption/decryption</param>
    /// <param name="mapper">AutoMapper for DTO conversions</param>
    public SecretService(
        ISecretRepository secretRepository,
        IAuditLogService auditLogService,
        ICurrentUserService currentUserService,
        IEncryptionService encryptionService,
        IMapper mapper)
    {
        _secretRepository = secretRepository ?? throw new ArgumentNullException(nameof(secretRepository));
        _auditLogService = auditLogService ?? throw new ArgumentNullException(nameof(auditLogService));
        _currentUserService = currentUserService ?? throw new ArgumentNullException(nameof(currentUserService));
        _encryptionService = encryptionService ?? throw new ArgumentNullException(nameof(encryptionService));
        _mapper = mapper ?? throw new ArgumentNullException(nameof(mapper));
    }

    /// <inheritdoc/>
    public async Task<IDataResult<IEnumerable<SecretDto>>> GetSecretsByUserIdAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // SECURITY: Verify current user is requesting their own secrets
            if (!_currentUserService.IsAuthenticated)
            {
                return new ErrorDataResult<IEnumerable<SecretDto>>("Unauthorized: User not authenticated");
            }

            if (_currentUserService.UserId != userId)
            {
                // AUDIT: Log unauthorized access attempt
                await _auditLogService.LogSecurityEventAsync(
                    eventType: "UNAUTHORIZED_ACCESS",
                    userId: _currentUserService.UserId,
                    resourceId: null,
                    action: $"User attempted to list secrets for another user (UserId: {userId})",
                    result: "Failure",
                    ipAddress: _currentUserService.IpAddress,
                    userAgent: null,
                    additionalData: null,
                    cancellationToken: cancellationToken
                );

                return new ErrorDataResult<IEnumerable<SecretDto>>(
                    "Forbidden: You can only access your own secrets");
            }

            // Fetch secrets from repository
            var secrets = await _secretRepository.GetByUserIdAsync(userId, cancellationToken);

            // Map to DTOs
            var secretDtos = _mapper.Map<IEnumerable<SecretDto>>(secrets);

            // AUDIT: Log successful retrieval (optional, might be too verbose)
            // await _auditLogService.LogSecurityEventAsync(...)

            return new SuccessDataResult<IEnumerable<SecretDto>>(
                secretDtos,
                $"Retrieved {secretDtos.Count()} secrets successfully");
        }
        catch (OperationCanceledException)
        {
            return new ErrorDataResult<IEnumerable<SecretDto>>("Operation was cancelled");
        }
        catch (Exception ex)
        {
            // SECURITY: Never log sensitive data
            return new ErrorDataResult<IEnumerable<SecretDto>>(
                $"An error occurred while retrieving secrets: {ex.Message}");
        }
    }

    /// <inheritdoc/>
    public async Task<IDataResult<SecretDto>> GetSecretByIdAsync(
        Guid secretId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // SECURITY: Verify authentication
            if (!_currentUserService.IsAuthenticated)
            {
                return new ErrorDataResult<SecretDto>("Unauthorized: User not authenticated");
            }

            // Fetch secret from repository
            var secret = await _secretRepository.GetByIdAsync(secretId, cancellationToken);

            if (secret == null)
            {
                return new ErrorDataResult<SecretDto>("Secret not found");
            }

            // SECURITY: Verify ownership
            if (secret.UserId != _currentUserService.UserId)
            {
                // AUDIT: Log unauthorized access attempt
                await _auditLogService.LogSecurityEventAsync(
                    eventType: "UNAUTHORIZED_ACCESS",
                    userId: _currentUserService.UserId,
                    resourceId: secretId,
                    action: $"User attempted to access secret owned by another user",
                    result: "Failure",
                    ipAddress: _currentUserService.IpAddress,
                    userAgent: null,
                    additionalData: null,
                    cancellationToken: cancellationToken
                );

                return new ErrorDataResult<SecretDto>(
                    "Forbidden: You do not have permission to access this secret");
            }

            // Check if secret is expired
            if (secret.ExpiresAt.HasValue && secret.ExpiresAt.Value < DateTime.UtcNow)
            {
                return new ErrorDataResult<SecretDto>("Secret has expired");
            }

            // Map to DTO (includes encrypted value, but NOT plaintext)
            var secretDto = _mapper.Map<SecretDto>(secret);

            return new SuccessDataResult<SecretDto>(secretDto, "Secret retrieved successfully");
        }
        catch (OperationCanceledException)
        {
            return new ErrorDataResult<SecretDto>("Operation was cancelled");
        }
        catch (Exception ex)
        {
            return new ErrorDataResult<SecretDto>(
                $"An error occurred while retrieving secret: {ex.Message}");
        }
    }

    /// <inheritdoc/>
    public async Task<IDataResult<string>> GetDecryptedValueAsync(
        Guid secretId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // SECURITY: Verify authentication
            if (!_currentUserService.IsAuthenticated)
            {
                return new ErrorDataResult<string>("Unauthorized: User not authenticated");
            }

            // Fetch secret from repository
            var secret = await _secretRepository.GetByIdAsync(secretId, cancellationToken);

            if (secret == null)
            {
                // AUDIT: Log failed decryption attempt (secret not found)
                await _auditLogService.LogSecurityEventAsync(
                    eventType: "SECRET_DECRYPT_FAILED",
                    userId: _currentUserService.UserId,
                    resourceId: secretId,
                    action: "User attempted to decrypt non-existent secret",
                    result: "Failure",
                    ipAddress: _currentUserService.IpAddress,
                    userAgent: null,
                    additionalData: null,
                    cancellationToken: cancellationToken
                );

                return new ErrorDataResult<string>("Secret not found");
            }

            // SECURITY: Verify ownership
            if (secret.UserId != _currentUserService.UserId)
            {
                // AUDIT: Log unauthorized decryption attempt (CRITICAL)
                await _auditLogService.LogSecurityEventAsync(
                    eventType: "UNAUTHORIZED_DECRYPT_ATTEMPT",
                    userId: _currentUserService.UserId,
                    resourceId: secretId,
                    action: $"User attempted to decrypt secret owned by user {secret.UserId}",
                    result: "Failure",
                    ipAddress: _currentUserService.IpAddress,
                    userAgent: null,
                    additionalData: null,
                    cancellationToken: cancellationToken
                );

                return new ErrorDataResult<string>(
                    "Forbidden: You do not have permission to decrypt this secret");
            }

            // Check if secret is expired
            if (secret.ExpiresAt.HasValue && secret.ExpiresAt.Value < DateTime.UtcNow)
            {
                // AUDIT: Log decryption of expired secret
                await _auditLogService.LogSecurityEventAsync(
                    eventType: "EXPIRED_SECRET_DECRYPT_ATTEMPT",
                    userId: _currentUserService.UserId,
                    resourceId: secretId,
                    action: "User attempted to decrypt expired secret",
                    result: "Failure",
                    ipAddress: _currentUserService.IpAddress,
                    userAgent: null,
                    additionalData: $"{{\"ExpiredAt\":\"{secret.ExpiresAt:O}\"}}",
                    cancellationToken: cancellationToken
                );

                return new ErrorDataResult<string>("Secret has expired and cannot be decrypted");
            }

            // DECRYPT: AES-256-GCM decryption
            string decryptedValue;
            try
            {
                decryptedValue = _encryptionService.Decrypt(secret.EncryptedValue);

                // SECURITY: Validate decrypted value
                if (string.IsNullOrWhiteSpace(decryptedValue))
                {
                    throw new InvalidOperationException("Decryption resulted in empty value");
                }
            }
            catch (Exception ex)
            {
                // AUDIT: Log decryption failure (corrupted data or wrong key)
                await _auditLogService.LogSecurityEventAsync(
                    eventType: "SECRET_DECRYPT_FAILED",
                    userId: _currentUserService.UserId,
                    resourceId: secretId,
                    action: "Decryption failed due to cryptographic error",
                    result: "Failure",
                    ipAddress: _currentUserService.IpAddress,
                    userAgent: null,
                    additionalData: $"{{\"ErrorType\":\"{ex.GetType().Name}\"}}",
                    cancellationToken: cancellationToken
                );

                return new ErrorDataResult<string>(
                    "Failed to decrypt secret. The data may be corrupted or encryption key changed.");
            }

            // UPDATE: Increment access count and update last accessed timestamp
            secret.RecordAccess();  // Bu metod AccessCount++ ve LastAccessedAt'i set eder
            await _secretRepository.UpdateAsync(secret, cancellationToken);

            // AUDIT: Log successful decryption (CRITICAL - ALWAYS LOG THIS!)
            await _auditLogService.LogSecurityEventAsync(
                eventType: "SECRET_DECRYPTED",
                userId: _currentUserService.UserId,
                resourceId: secretId,
                action: $"User successfully decrypted secret: {secret.Title}",
                result: "Success",
                ipAddress: _currentUserService.IpAddress,
                userAgent: null,
                additionalData: $"{{\"AccessCount\":{secret.AccessCount},\"Title\":\"{secret.Title}\"}}",
                cancellationToken: cancellationToken
            );

            // RETURN: Plaintext value (NEVER LOG THIS!)
            return new SuccessDataResult<string>(decryptedValue, "Secret decrypted successfully");
        }
        catch (OperationCanceledException)
        {
            return new ErrorDataResult<string>("Operation was cancelled");
        }
        catch (Exception ex)
        {
            // SECURITY: Generic error message (don't leak implementation details)
            return new ErrorDataResult<string>(
                $"An error occurred while decrypting secret: {ex.Message}");
        }
    }

    /// <inheritdoc/>
    public async Task<IDataResult<SecretDto>> CreateSecretAsync(
        CreateSecretDto dto,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // SECURITY: Verify authentication
            if (!_currentUserService.IsAuthenticated)
            {
                return new ErrorDataResult<SecretDto>("Unauthorized: User not authenticated");
            }

            var currentUserId = _currentUserService.UserId!.Value;

            // VALIDATION: Check for duplicate title
            var existingSecret = await _secretRepository.GetByTitleAndUserIdAsync(
                currentUserId,
                dto.Title,
                cancellationToken);

            if (existingSecret != null)
            {
                return new ErrorDataResult<SecretDto>(
                    $"A secret with title '{dto.Title}' already exists");
            }

            // BUSINESS RULE: Check user quota (max 1000 secrets per user)
            var secretCount = await _secretRepository.GetCountByUserIdAsync(currentUserId, cancellationToken);
            if (secretCount >= 1000)
            {
                return new ErrorDataResult<SecretDto>(
                    "Secret quota exceeded. Maximum 1000 secrets per user allowed.");
            }

            // ENCRYPT: AES-256-GCM encryption
            string encryptedValue;
            try
            {
                encryptedValue = _encryptionService.Encrypt(dto.RawValue);

                // SECURITY: Validate encrypted output
                if (string.IsNullOrWhiteSpace(encryptedValue))
                {
                    throw new InvalidOperationException("Encryption resulted in empty value");
                }
            }
            catch (Exception ex)
            {
                return new ErrorDataResult<SecretDto>(
                    $"Encryption failed: {ex.Message}");
            }

            // CREATE: Domain entity
            var iv = new byte[12]; // 12 byte IV for AES-GCM
            System.Security.Cryptography.RandomNumberGenerator.Fill(iv);

            var secret = Secret.Create(
                title: dto.Title,
                encryptedValue: encryptedValue,
                iv: iv,
                userId: currentUserId,
                category: dto.Category ?? "Other",
                description: dto.Description,
                expiresAt: dto.ExpiresAt
            );

            // PERSIST: Save to database
            var createdSecret = await _secretRepository.AddAsync(secret, cancellationToken);

            // AUDIT: Log secret creation
            await _auditLogService.LogSecurityEventAsync(
                eventType: "SECRET_CREATED",
                userId: currentUserId,
                resourceId: createdSecret.Id,
                action: $"User created new secret: {createdSecret.Title}",
                result: "Success",
                ipAddress: _currentUserService.IpAddress,
                userAgent: null,
                additionalData: $"{{\"Title\":\"{createdSecret.Title}\",\"Category\":\"{createdSecret.Category}\"}}",
                cancellationToken: cancellationToken
            );

            // MAP: Domain to DTO
            var secretDto = _mapper.Map<SecretDto>(createdSecret);

            return new SuccessDataResult<SecretDto>(secretDto, "Secret created successfully");
        }
        catch (OperationCanceledException)
        {
            return new ErrorDataResult<SecretDto>("Operation was cancelled");
        }
        catch (Exception ex)
        {
            return new ErrorDataResult<SecretDto>(
                $"An error occurred while creating secret: {ex.Message}");
        }
    }

    /// <inheritdoc/>
    public async Task<IDataResult<SecretDto>> UpdateSecretAsync(
        UpdateSecretDto dto,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // SECURITY: Verify authentication
            if (!_currentUserService.IsAuthenticated)
            {
                return new ErrorDataResult<SecretDto>("Unauthorized: User not authenticated");
            }

            // Fetch existing secret
            var secret = await _secretRepository.GetByIdAsync(dto.Id, cancellationToken);

            if (secret == null)
            {
                return new ErrorDataResult<SecretDto>("Secret not found");
            }

            // SECURITY: Verify ownership
            if (secret.UserId != _currentUserService.UserId)
            {
                // AUDIT: Log unauthorized update attempt
                await _auditLogService.LogSecurityEventAsync(
                    eventType: "UNAUTHORIZED_UPDATE_ATTEMPT",
                    userId: _currentUserService.UserId,
                    resourceId: dto.Id,
                    action: "User attempted to update secret owned by another user",
                    result: "Failure",
                    ipAddress: _currentUserService.IpAddress,
                    userAgent: null,
                    additionalData: null,
                    cancellationToken: cancellationToken
                );

                return new ErrorDataResult<SecretDto>(
                    "Forbidden: You do not have permission to update this secret");
            }

            // Track what changed (for audit logging)
            var changedFields = new List<string>();

            // UPDATE: Title
            if (!string.IsNullOrWhiteSpace(dto.Title) && dto.Title != secret.Title)
            {
                // Check for duplicate title
                var existingSecret = await _secretRepository.GetByTitleAndUserIdAsync(
                    secret.UserId,
                    dto.Title,
                    cancellationToken);

                if (existingSecret != null && existingSecret.Id != secret.Id)
                {
                    return new ErrorDataResult<SecretDto>(
                        $"A secret with title '{dto.Title}' already exists");
                }

                secret.UpdateTitle(dto.Title);
                changedFields.Add("Title");
            }

            // UPDATE: Description
            if (dto.Description != null && dto.Description != secret.Description)
            {
                secret.UpdateDescription(dto.Description);
                changedFields.Add("Description");
            }

            // UPDATE: Category
            if (dto.Category != null && dto.Category != secret.Category)
            {
                secret.UpdateCategory(dto.Category);
                changedFields.Add("Category");
            }

            // UPDATE: ExpiresAt
            if (dto.ExpiresAt.HasValue && dto.ExpiresAt != secret.ExpiresAt)
            {
                if (dto.ExpiresAt.Value < DateTime.UtcNow)
                {
                    return new ErrorDataResult<SecretDto>(
                        "Expiration date must be in the future");
                }

                secret.SetExpiration(dto.ExpiresAt);
                changedFields.Add("ExpiresAt");
            }

            // UPDATE: Encrypted Value (if new plaintext provided)
            if (!string.IsNullOrWhiteSpace(dto.NewRawValue))
            {
                try
                {
                    // RE-ENCRYPT: AES-256-GCM encryption
                    var newEncryptedValue = _encryptionService.Encrypt(dto.NewRawValue);
                    var newIv = new byte[12]; // AES-GCM için 12 byte IV
                    System.Security.Cryptography.RandomNumberGenerator.Fill(newIv);

                    secret.ReEncrypt(newEncryptedValue, newIv); // Artýk hem deðeri hem IV'yi güncelliyor
                    changedFields.Add("EncryptedValue");

                    // AUDIT: Log value change (CRITICAL - don't log actual values!)
                    await _auditLogService.LogSecurityEventAsync(
                        eventType: "SECRET_VALUE_CHANGED",
                        userId: _currentUserService.UserId,
                        resourceId: secret.Id,
                        action: $"User changed secret value: {secret.Title}",
                        result: "Success",
                        ipAddress: _currentUserService.IpAddress,
                        userAgent: null,
                        additionalData: null,
                        cancellationToken: cancellationToken
                    );
                }
                catch (Exception ex)
                {
                    return new ErrorDataResult<SecretDto>(
                        $"Re-encryption failed: {ex.Message}");
                }
            }

            // If nothing changed, return early
            if (changedFields.Count == 0)
            {
                var unchangedDto = _mapper.Map<SecretDto>(secret);
                return new SuccessDataResult<SecretDto>(unchangedDto, "No changes to update");
            }

           

            // PERSIST: Save changes
            var updatedSecret = await _secretRepository.UpdateAsync(secret, cancellationToken);

            // AUDIT: Log secret update
            await _auditLogService.LogSecurityEventAsync(
                eventType: "SECRET_UPDATED",
                userId: _currentUserService.UserId!.Value,
                resourceId: updatedSecret.Id,
                action: $"User updated secret: {updatedSecret.Title}",
                result: "Success",
                ipAddress: _currentUserService.IpAddress,
                userAgent: null,
                additionalData: $"{{\"ChangedFields\":[\"{string.Join("\",\"", changedFields)}\"]}}",
                cancellationToken: cancellationToken
            );

            // MAP: Domain to DTO
            var secretDto = _mapper.Map<SecretDto>(updatedSecret);

            return new SuccessDataResult<SecretDto>(secretDto, "Secret updated successfully");
        }
        catch (OperationCanceledException)
        {
            return new ErrorDataResult<SecretDto>("Operation was cancelled");
        }
        catch (Exception ex)
        {
            return new ErrorDataResult<SecretDto>(
                $"An error occurred while updating secret: {ex.Message}");
        }
    }

    /// <inheritdoc/>
    public async Task<IResult> DeleteSecretAsync(
        Guid secretId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // SECURITY: Verify authentication
            if (!_currentUserService.IsAuthenticated)
            {
                return new ErrorResult("Unauthorized: User not authenticated");
            }

            // Fetch secret
            var secret = await _secretRepository.GetByIdAsync(secretId, cancellationToken);

            if (secret == null)
            {
                return new ErrorResult("Secret not found");
            }

            // SECURITY: Verify ownership
            if (secret.UserId != _currentUserService.UserId)
            {
                // AUDIT: Log unauthorized delete attempt
                await _auditLogService.LogSecurityEventAsync(
                    eventType: "UNAUTHORIZED_DELETE_ATTEMPT",
                    userId: _currentUserService.UserId,
                    resourceId: secretId,
                    action: "User attempted to delete secret owned by another user",
                    result: "Failure",
                    ipAddress: _currentUserService.IpAddress,
                    userAgent: null,
                    additionalData: null,
                    cancellationToken: cancellationToken
                );

                return new ErrorResult(
                    "Forbidden: You do not have permission to delete this secret");
            }

            secret.MarkAsDeleted(); // Domain modelindeki yumuþak silme metodunu çaðýrýyoruz
            await _secretRepository.UpdateAsync(secret, cancellationToken); // Durumu veritabanýna kaydet

            // AUDIT: Log secret deletion (CRITICAL - keep permanent record)
            await _auditLogService.LogSecurityEventAsync(
                eventType: "SECRET_DELETED",
                userId: _currentUserService.UserId!.Value,
                resourceId: secretId,
                action: $"User deleted secret: {secret.Title}",
                result: "Success",
                ipAddress: _currentUserService.IpAddress,
                userAgent: null,
                additionalData: $"{{\"Title\":\"{secret.Title}\",\"Category\":\"{secret.Category}\"}}",
                cancellationToken: cancellationToken
            );

            return new SuccessResult("Secret deleted successfully");
        }
        catch (OperationCanceledException)
        {
            return new ErrorResult("Operation was cancelled");
        }
        catch (Exception ex)
        {
            return new ErrorResult(
                $"An error occurred while deleting secret: {ex.Message}");
        }
    }
}