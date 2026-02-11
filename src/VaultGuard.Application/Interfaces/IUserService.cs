using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VaultGuard.Application.DTOs.Users;
using VaultGuard.Domain.Common.Results;

namespace VaultGuard.Application.Interfaces;

/// <summary>
/// Kullanıcı CRUD operasyonları için servis soyutlaması.
/// Authentication hariç tüm user işlemleri bu serviste yapılır.
/// </summary>
public interface IUserService
{
    /// <summary>
    /// ID ile kullanıcı getirir.
    /// </summary>
    /// <param name="userId">Kullanıcı ID</param>
    /// <param name="cancellationToken">İptal token</param>
    /// <returns>Kullanıcı bulunduysa UserDto, yoksa hata</returns>
    Task<IDataResult<UserDto>> GetByIdAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Email ile kullanıcı getirir.
    /// Public API'de kullanılmamalı - user enumeration riski.
    /// </summary>
    /// <param name="email">Email adresi</param>
    /// <param name="cancellationToken">İptal token</param>
    /// <returns>Kullanıcı bulunduysa UserDto, yoksa hata</returns>
    Task<IDataResult<UserDto>> GetByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Tüm kullanıcıları getirir (admin only).
    /// Pagination eklenmeli - performans için.
    /// </summary>
    /// <param name="cancellationToken">İptal token</param>
    /// <returns>Kullanıcı listesi</returns>
    Task<IDataResult<List<UserDto>>> GetAllAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Yeni kullanıcı oluşturur (admin only).
    /// </summary>
    /// <param name="createUserDto">Kullanıcı bilgileri</param>
    /// <param name="cancellationToken">İptal token</param>
    /// <returns>Oluşturulan kullanıcı</returns>
    Task<IDataResult<UserDto>> CreateAsync(CreateUserDto createUserDto, CancellationToken cancellationToken = default);

    /// <summary>
    /// Kullanıcı bilgilerini günceller.
    /// Kullanıcı sadece kendi bilgilerini, admin herkesi güncelleyebilir.
    /// </summary>
    /// <param name="updateUserDto">Güncellenecek bilgiler</param>
    /// <param name="cancellationToken">İptal token</param>
    /// <returns>Güncellenmiş kullanıcı</returns>
    Task<IDataResult<UserDto>> UpdateAsync(UpdateUserDto updateUserDto, CancellationToken cancellationToken = default);

    /// <summary>
    /// Kullanıcı şifresini değiştirir.
    /// Mevcut şifre doğrulaması yapılır.
    /// </summary>
    /// <param name="userId">Kullanıcı ID</param>
    /// <param name="changePasswordDto">Şifre bilgileri</param>
    /// <param name="cancellationToken">İptal token</param>
    /// <returns>Başarı durumu</returns>
    Task<IResult> ChangePasswordAsync(Guid userId, ChangePasswordDto changePasswordDto, CancellationToken cancellationToken = default);

    /// <summary>
    /// Kullanıcı hesabını deaktive eder.
    /// Soft delete - kullanıcı login yapamaz ama veriler korunur.
    /// </summary>
    /// <param name="userId">Kullanıcı ID</param>
    /// <param name="cancellationToken">İptal token</param>
    /// <returns>Başarı durumu</returns>
    Task<IResult> DeactivateAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Kullanıcı hesabını aktive eder.
    /// </summary>
    /// <param name="userId">Kullanıcı ID</param>
    /// <param name="cancellationToken">İptal token</param>
    /// <returns>Başarı durumu</returns>
    Task<IResult> ActivateAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Kullanıcıyı kalıcı olarak siler (admin only).
    /// GDPR uyumluluğu için - kullanıcı verilerini tamamen siler.
    /// </summary>
    /// <param name="userId">Kullanıcı ID</param>
    /// <param name="cancellationToken">İptal token</param>
    /// <returns>Başarı durumu</returns>
    Task<IResult> DeleteAsync(Guid userId, CancellationToken cancellationToken = default);
}