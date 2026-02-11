using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VaultGuard.Domain.Entities;

namespace VaultGuard.Application.Interfaces;

/// <summary>
/// User entity için Repository arayüzü.
/// 
/// AMACLAR:
/// 1. Application katmanýný Infrastructure'dan (EF Core) baðýmsýz kýlar.
/// 2. Dependency Inversion Principle (DIP) saðlar.
/// 3. Test edilebilirliði artýrýr (Mocking desteði).
/// </summary>
public interface IUserRepository
{
    // ============================================================================
    // READ OPERATIONS (Sorgulama)
    // ============================================================================

    /// <summary>
    /// Kullanýcýyý ID'sine göre getirir.
    /// </summary>
    Task<User?> GetByIdAsync(Guid userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Kullanýcýyý email adresine göre getirir.
    /// </summary>
    Task<User?> GetByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Kullanýcýyý username'e göre getirir.
    /// </summary>
    Task<User?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default);

    /// <summary>
    /// Email adresinin veritabanýnda var olup olmadýðýný kontrol eder.
    /// </summary>
    Task<bool> ExistsByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Username'in veritabanýnda var olup olmadýðýný kontrol eder.
    /// </summary>
    Task<bool> ExistsByUsernameAsync(string username, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sistemdeki tüm kullanýcýlarý getirir.
    /// 
    /// KRÝTÝK GÜNCELLEME:
    /// 'GetAllActiveAsync' ismi, UserService ile uyum için 'GetAllAsync' olarak deðiþtirildi.
    /// Bu sayede 'error CS1061' hatasý çözülmüþtür.
    /// </summary>
    Task<List<User>> GetAllAsync(CancellationToken cancellationToken = default);

    // ============================================================================
    // WRITE OPERATIONS (Komutlar)
    // ============================================================================

    /// <summary>
    /// Yeni bir kullanýcý ekler.
    /// </summary>
    Task AddAsync(User user, CancellationToken cancellationToken = default);

    /// <summary>
    /// Mevcut bir kullanýcýyý günceller (Memory takibi için).
    /// </summary>
    void Update(User user);

    /// <summary>
    /// Kullanýcýyý veritabanýndan kalýcý olarak siler (Hard Delete).
    /// </summary>
    void Delete(User user);

    /// <summary>
    /// Unit of Work: Tüm deðiþiklikleri tek seferde veritabanýna yansýtýr.
    /// </summary>
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}