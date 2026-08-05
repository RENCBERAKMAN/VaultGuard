using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VaultGuard.Application.DTOs.Secrets;
using VaultGuard.Domain.Common.Results;

namespace VaultGuard.Application.Interfaces;

public interface ISecretService
{
    // 📋 GET USER SECRETS
    Task<IDataResult<IEnumerable<SecretDto>>> GetSecretsByUserIdAsync(
        Guid userId,
        CancellationToken cancellationToken = default);

    // 🔍 GET BY ID
    Task<IDataResult<SecretDto>> GetSecretByIdAsync(
        Guid secretId,
        Guid userId,
        CancellationToken cancellationToken = default);

    // 🔓 DECRYPT
    Task<IDataResult<string>> GetDecryptedValueAsync(
        Guid secretId,
        Guid userId,
        string? ipAddress = null,
        CancellationToken cancellationToken = default);

    // 🔐 CREATE
    Task<IDataResult<SecretDto>> CreateSecretAsync(
        CreateSecretDto dto,
        Guid userId,
        string? ipAddress = null,
        CancellationToken cancellationToken = default);

    // ✏️ UPDATE
    Task<IDataResult<SecretDto>> UpdateSecretAsync(
        UpdateSecretDto dto,
        Guid userId,
        string? ipAddress = null,
        CancellationToken cancellationToken = default);

    // 🗑️ DELETE (Veri dönmediği için düz IResult)
    Task<IResult> DeleteSecretAsync(
        Guid secretId,
        Guid userId,
        string? ipAddress = null,
        CancellationToken cancellationToken = default);
}