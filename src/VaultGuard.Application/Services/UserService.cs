using System;
using System.Collections.Generic;
using System.Linq; // Select ve ToList için gerekli
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using VaultGuard.Application.Interfaces;
using VaultGuard.Application.DTOs.Users; // UserDto, UpdateUserDto, ChangePasswordDto burada
using VaultGuard.Domain.Common.Results;  // Result Pattern'in gerçek adresi
using VaultGuard.Domain.Entities;        // User entity'si burada

namespace VaultGuard.Application.Services;

/// <summary>
/// Kullanıcı yönetimi için Application Service.
/// 
/// SORUMLULUKLAR:
/// - Kullanıcı CRUD işlemleri
/// - İş kurallarının uygulanması
/// - DTO dönüşümleri
/// - Güvenlik kontrolleri
/// 
/// MİMARİ PRENSİPLER:
/// ✅ Infrastructure'dan (EF Core) tamamen bağımsız
/// ✅ Repository pattern kullanımı
/// ✅ Dependency Injection
/// ✅ Result pattern ile tutarlı hata yönetimi
/// 
/// GÜVENLİK:
/// - PasswordHash asla DTO'ya dahil edilmez
/// - User enumeration attack önlenir
/// - Role-based validation yapılır
/// </summary>
public class UserService : IUserService
{
    private readonly IUserRepository _userRepository;
    private readonly IPasswordHasher _passwordHasher;

    /// <summary>
    /// Constructor - Dependency Injection
    /// </summary>
    public UserService(
        IUserRepository userRepository,
        IPasswordHasher passwordHasher)
    {
        _userRepository = userRepository;
        _passwordHasher = passwordHasher;
    }

    // ============================================================================
    // QUERY OPERATIONS (READ)
    // ============================================================================

    /// <summary>
    /// Kullanıcıyı ID'sine göre getirir.
    /// 
    /// GÜVENLİK:
    /// - PasswordHash DTO'ya dahil edilmez
    /// - Deaktif kullanıcılar da getirilir (admin senaryoları için)
    /// </summary>
    public async Task<IDataResult<UserDto>> GetByIdAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);

            if (user == null)
            {
                return new ErrorDataResult<UserDto>(
                    message: "Kullanıcı bulunamadı.");
            }

            var userDto = ToDto(user);
            return new SuccessDataResult<UserDto>(
                data: userDto,
                message: "Kullanıcı başarıyla getirildi.");
        }
        catch (OperationCanceledException)
        {
            throw; // "throw;" yazmazsan hata dışarı çıkmaz, test fail olur!
        }
        catch (Exception ex)
        {
            return new ErrorDataResult<UserDto>(
                message: $"Kullanıcı getirilirken bir hata oluştu: {ex.Message}");
        }
    }

    /// <summary>
    /// Kullanıcıyı email adresine göre getirir.
    /// 
    /// GÜVENLİK UYARISI:
    /// Bu metod user enumeration attack'e açık olabilir.
    /// Sadece internal kullanım için tasarlanmıştır.
    /// Public API'lerde kullanmayın!
    /// </summary>
    public async Task<IDataResult<UserDto>> GetByEmailAsync(
        string email,
        CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(email))
            {
                return new ErrorDataResult<UserDto>(
                    message: "Email adresi boş olamaz.");
            }

            var user = await _userRepository.GetByEmailAsync(email, cancellationToken);

            if (user == null)
            {
                return new ErrorDataResult<UserDto>(
                    message: "Kullanıcı bulunamadı.");
            }

            var userDto = ToDto(user);
            return new SuccessDataResult<UserDto>(
                data: userDto,
                message: "Kullanıcı başarıyla getirildi.");
        }
        catch (OperationCanceledException)

        {

            throw; // "throw;" yazmazsan hata dışarı çıkmaz, test fail olur!

        }
        catch (Exception ex)
        {
            return new ErrorDataResult<UserDto>(
                message: $"Kullanıcı getirilirken bir hata oluştu: {ex.Message}");
        }
    }

    // ============================================================================
    // COMMAND OPERATIONS (CREATE, UPDATE, DELETE)
    // ============================================================================

    /// <summary>
    /// Yeni kullanıcı oluşturur (Register).
    /// 
    /// İŞ KURALLARI:
    /// 1. Email benzersiz olmalı
    /// 2. Username benzersiz olmalı
    /// 3. Şifre hash'lenmeli
    /// 4. Varsayılan rol "User"
    /// 
    /// GÜVENLİK:
    /// - Şifre plain-text olarak saklanmaz
    /// - Email normalizasyonu yapılır (Repository'de)
    /// - Username format kontrolü yapılır (Domain'de)
    /// </summary>
    /// <summary>
    /// Yeni kullanıcı oluşturur (Register/Create).
    /// 
    /// GÜVENLİK VE MİMARİ:
    /// - CreateUserDto kullanılarak parametre sızıntısı önlenir.
    /// - Domain katmanındaki iş kuralları (User.Create) işletilir.
    /// </summary>
    /// <summary>
    /// Yeni kullanıcı oluşturur (Register/Create).
    /// 
    /// GÜVENLİK VE MİMARİ:
    /// - CreateUserDto kullanılarak parametre sızıntısı önlenir.
    /// - Domain katmanındaki iş kuralları (User.Create) işletilir.
    /// </summary>
    public async Task<IDataResult<UserDto>> CreateAsync(
        CreateUserDto createUserDto, // Veriler artık paket (DTO) olarak geliyor
        CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            // 1. Validasyon (Paket içeriği kontrol ediliyor)
            if (string.IsNullOrWhiteSpace(createUserDto.Email))
            {
                return new ErrorDataResult<UserDto>(message: "Email adresi boş olamaz.");
            }

            if (string.IsNullOrWhiteSpace(createUserDto.Username))
            {
                return new ErrorDataResult<UserDto>(message: "Kullanıcı adı boş olamaz.");
            }

            if (string.IsNullOrWhiteSpace(createUserDto.Password))
            {
                return new ErrorDataResult<UserDto>(message: "Şifre boş olamaz.");
            }

            // 2. Email benzersizlik kontrolü (Repository üzerinden)
            var emailExists = await _userRepository.ExistsByEmailAsync(createUserDto.Email, cancellationToken);
            if (emailExists)
            {
                return new ErrorDataResult<UserDto>(message: "Bu email adresi zaten kullanılıyor.");
            }

            // 3. Username benzersizlik kontrolü
            var usernameExists = await _userRepository.ExistsByUsernameAsync(createUserDto.Username, cancellationToken);
            if (usernameExists)
            {
                return new ErrorDataResult<UserDto>(message: "Bu kullanıcı adı zaten kullanılıyor.");
            }

            // 4. Şifre hash'le (IPasswordHasher servisi ile)
            var passwordHash = _passwordHasher.HashPassword(createUserDto.Password);

            // 5. Domain entity oluştur (Rol varsayılan olarak "User" atanabilir)
            // Not: Eğer DTO içinde Role gelmiyorsa buraya sabit "User" yazabiliriz.
            var user = User.Create(createUserDto.Email, createUserDto.Username, passwordHash, "User");

            // 6. Veritabanına kaydet (Repository Pattern)
            await _userRepository.AddAsync(user, cancellationToken);
            await _userRepository.SaveChangesAsync(cancellationToken);

            // 7. DTO dönüşümü ve başarı yanıtı
            var userDto = ToDto(user);
            return new SuccessDataResult<UserDto>(
                data: userDto,
                message: "Kullanıcı başarıyla oluşturuldu.");
        }
        catch (OperationCanceledException)

        {

            throw; // "throw;" yazmazsan hata dışarı çıkmaz, test fail olur!

        }
        catch (ArgumentException ex)
        {
            // Domain katmanından gelen kural ihlalleri
            return new ErrorDataResult<UserDto>(message: $"Validasyon hatası: {ex.Message}");
        }
        catch (Exception ex)
        {
            return new ErrorDataResult<UserDto>(
                message: $"Kullanıcı oluşturulurken beklenmedik bir hata oluştu: {ex.Message}");
        }
    }

    /// <summary>
    /// Kullanıcı bilgilerini günceller.
    /// 
    /// GÜVENLİK:
    /// - Şifre bu metod ile değiştirilmez (ChangePasswordAsync kullanılmalı)
    /// - Rol değişikliği ayrı bir metod ile yapılmalı (admin yetkisi gerekir)
    /// </summary>
    /// <summary>
    /// Mevcut bir kullanıcının profil bilgilerini günceller.
    /// 
    /// GÜVENLİK VE MİMARİ:
    /// - UpdateUserDto kullanılarak sadece izin verilen alanların değişimi sağlanır.
    /// - Email ve Username benzersizlik kontrolleri Repository seviyesinde yapılır.
    /// </summary>
    public async Task<IDataResult<UserDto>> UpdateAsync(
        UpdateUserDto updateUserDto, // Parametre artık bir paket (DTO) olarak geliyor
        CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            // 1. Kullanıcıyı getir (DTO içindeki ID üzerinden)
            var user = await _userRepository.GetByIdAsync(updateUserDto.Id, cancellationToken);

            if (user == null)
            {
                return new ErrorDataResult<UserDto>(message: "Kullanıcı bulunamadı.");
            }

            // 2. Email güncelleme (Eğer yeni bir email gelmişse ve mevcut olandan farklıysa)
            if (!string.IsNullOrWhiteSpace(updateUserDto.Email) && updateUserDto.Email != user.Email)
            {
                // Yeni email başka bir kullanıcıda var mı kontrolü
                var emailExists = await _userRepository.ExistsByEmailAsync(updateUserDto.Email, cancellationToken);
                if (emailExists)
                {
                    return new ErrorDataResult<UserDto>(message: "Bu email adresi zaten başka bir kullanıcı tarafından kullanılıyor.");
                }

                user.UpdateEmail(updateUserDto.Email);
            }

            // 3. Username güncelleme (Eğer yeni bir kullanıcı adı gelmişse ve farklıysa)
            if (!string.IsNullOrWhiteSpace(updateUserDto.Username) && updateUserDto.Username != user.Username)
            {
                // Yeni kullanıcı adı sistemde var mı kontrolü
                var usernameExists = await _userRepository.ExistsByUsernameAsync(updateUserDto.Username, cancellationToken);
                if (usernameExists)
                {
                    return new ErrorDataResult<UserDto>(message: "Bu kullanıcı adı zaten alınmış.");
                }

                user.UpdateUsername(updateUserDto.Username);
            }

            // 4. Değişiklikleri Repository üzerinden işaretle ve kaydet
            _userRepository.Update(user);
            await _userRepository.SaveChangesAsync(cancellationToken);

            // 5. Güncel entity'yi DTO'ya çevirip başarıyla dön
            var userDto = ToDto(user);
            return new SuccessDataResult<UserDto>(
                data: userDto,
                message: "Kullanıcı bilgileri başarıyla güncellendi.");
        }
        catch (OperationCanceledException)

        {

            throw; // "throw;" yazmazsan hata dışarı çıkmaz, test fail olur!

        }
        catch (ArgumentException ex)
        {
            // Domain entity içindeki validasyon kuralları ihlal edilirse (Örn: geçersiz format)
            return new ErrorDataResult<UserDto>(message: $"Validasyon hatası: {ex.Message}");
        }
        catch (Exception ex)
        {
            return new ErrorDataResult<UserDto>(
                message: $"Kullanıcı güncellenirken beklenmedik bir hata oluştu: {ex.Message}");
        }
    }

    /// <summary>
    /// Kullanıcı şifresini değiştirir.
    /// 
    /// GÜVENLİK:
    /// - Mevcut şifre doğrulanır
    /// - Yeni şifre hash'lenir
    /// - Şifre geçmişi tutulabilir (gelecekte)
    /// </summary>
    /// <summary>
    /// Kullanıcının mevcut şifresini doğrular ve yenisiyle değiştirir.
    /// 
    /// GÜVENLİK:
    /// - Mevcut şifre plain-text olarak asla saklanmaz, hash üzerinden doğrulanır.
    /// - Yeni şifre kaydedilmeden önce mutlaka hash'lenir.
    /// </summary>
    public async Task<IResult> ChangePasswordAsync(
        Guid userId,
        ChangePasswordDto changePasswordDto, // Parametreler paket (DTO) olarak geliyor
        CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            // 1. Kullanıcıyı getir (Repository üzerinden)
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);

            if (user == null)
            {
                return new ErrorResult(message: "Kullanıcı bulunamadı.");
            }

            // 2. Mevcut şifreyi doğrula (Paket içindeki CurrentPassword kullanılıyor)
            // Veritabanındaki hash ile kullanıcının girdiği şifre karşılaştırılır.
            if (!_passwordHasher.VerifyPassword(changePasswordDto.CurrentPassword, user.PasswordHash))
            {
                return new ErrorResult(message: "Mevcut şifreniz hatalı.");
            }

            // 3. Yeni şifreyi hash'le (Paket içindeki NewPassword kullanılıyor)
            var newPasswordHash = _passwordHasher.HashPassword(changePasswordDto.NewPassword);

            // 4. Domain entity üzerinden şifre değişimini gerçekleştir
            user.ChangePassword(newPasswordHash);

            // 5. Değişiklikleri veritabanına yansıt
            _userRepository.Update(user);
            await _userRepository.SaveChangesAsync(cancellationToken);

            return new SuccessResult(message: "Şifreniz başarıyla değiştirildi.");
        }
        catch (OperationCanceledException)

        {

            throw; // "throw;" yazmazsan hata dışarı çıkmaz, test fail olur!

        }
        catch (ArgumentException ex)
        {
            // Domain katmanındaki şifre politikası ihlalleri
            return new ErrorResult(message: $"Validasyon hatası: {ex.Message}");
        }
        catch (Exception ex)
        {
            return new ErrorResult(
                message: $"Şifre değiştirilirken beklenmedik bir hata oluştu: {ex.Message}");
        }
    }

    /// <summary>
    /// Kullanıcı rolünü değiştirir.
    /// 
    /// GÜVENLİK:
    /// Bu metod SADECE Admin yetkisiyle çağrılmalıdır.
    /// Authorization kontrolü Controller'da yapılır.
    /// </summary>
    public async Task<IDataResult<UserDto>> ChangeRoleAsync(
        Guid userId,
        string newRole,
        CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return new ErrorDataResult<UserDto>(
                    message: "Kullanıcı bulunamadı.");
            }

            user.ChangeRole(newRole);

            _userRepository.Update(user);
            await _userRepository.SaveChangesAsync(cancellationToken);

            var userDto = ToDto(user);
            return new SuccessDataResult<UserDto>(
                data: userDto,
                message: "Kullanıcı rolü başarıyla değiştirildi.");
        }
        catch (OperationCanceledException)

        {

            throw; // "throw;" yazmazsan hata dışarı çıkmaz, test fail olur!

        }
        catch (ArgumentException ex)
        {
            return new ErrorDataResult<UserDto>(
                message: $"Validasyon hatası: {ex.Message}");
        }
        catch (Exception ex)
        {
            return new ErrorDataResult<UserDto>(
                message: $"Rol değiştirilirken bir hata oluştu: {ex.Message}");
        }
    }

    /// <summary>
    /// Kullanıcıyı deaktive eder (soft delete).
    /// 
    /// GÜVENLİK:
    /// Hard delete yerine soft delete kullanılır (GDPR uyumlu).
    /// </summary>
    public async Task<IResult> DeactivateAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return new ErrorResult(message: "Kullanıcı bulunamadı.");
            }

            user.Deactivate();

            _userRepository.Update(user);
            await _userRepository.SaveChangesAsync(cancellationToken);

            return new SuccessResult(message: "Kullanıcı başarıyla deaktive edildi.");
        }
        catch (OperationCanceledException)

        {

            throw; // "throw;" yazmazsan hata dışarı çıkmaz, test fail olur!

        }
        catch (Exception ex)
        {
            return new ErrorResult(
                message: $"Kullanıcı deaktive edilirken bir hata oluştu: {ex.Message}");
        }
    }
    // ============================================================================
    // EKSTRA OPERASYONLAR (LIST & DELETE)
    // ============================================================================

    /// <summary>
    /// Sistemdeki tüm kullanıcıları listeler.
    /// 
    /// MİMARİ:
    /// - Repository'den gelen Entity listesini, ToDto ile DTO listesine çevirir.
    /// </summary>
    public async Task<IDataResult<List<UserDto>>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var users = await _userRepository.GetAllAsync(cancellationToken);

            // Entity listesini tek tek DTO'ya mapliyoruz.
            var userDtos = users.Select(u => ToDto(u)).ToList();

            return new SuccessDataResult<List<UserDto>>(
                data: userDtos,
                message: "Tüm kullanıcılar başarıyla listelendi.");
        }
        catch (OperationCanceledException)

        {

            throw; // "throw;" yazmazsan hata dışarı çıkmaz, test fail olur!

        }
        catch (Exception ex)
        {
            return new ErrorDataResult<List<UserDto>>(
                message: $"Kullanıcı listesi alınırken bir hata oluştu: {ex.Message}");
        }
    }

    /// <summary>
    /// Bir kullanıcıyı sistemden kalıcı olarak (Hard Delete) siler.
    /// 
    /// DİKKAT:
    /// Siber güvenlik ve denetim (audit) gereği genellikle DeactivateAsync (Soft Delete) 
    /// tercih edilir. Bu metod kritik durumlarda kullanılmalıdır.
    /// </summary>
    public async Task<IResult> DeleteAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);

            if (user == null)
            {
                return new ErrorResult(message: "Silinecek kullanıcı bulunamadı.");
            }

            _userRepository.Delete(user);
            await _userRepository.SaveChangesAsync(cancellationToken);

            return new SuccessResult(message: "Kullanıcı sistemden kalıcı olarak silindi.");
        }
        catch (OperationCanceledException)

        {

            throw; // "throw;" yazmazsan hata dışarı çıkmaz, test fail olur!

        }
        catch (Exception ex)
        {
            return new ErrorResult(
                message: $"Kullanıcı silinirken beklenmedik bir hata oluştu: {ex.Message}");
        }
    }
    /// <summary>
    /// Deaktive edilmiş kullanıcıyı tekrar aktive eder.
    /// </summary>
    public async Task<IResult> ActivateAsync(
        Guid userId,
        CancellationToken cancellationToken = default)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return new ErrorResult(message: "Kullanıcı bulunamadı.");
            }

            user.Activate();

            _userRepository.Update(user);
            await _userRepository.SaveChangesAsync(cancellationToken);

            return new SuccessResult(message: "Kullanıcı başarıyla aktive edildi.");
        }
        catch (OperationCanceledException)

        {

            throw; // "throw;" yazmazsan hata dışarı çıkmaz, test fail olur!

        }
        catch (Exception ex)
        {
            return new ErrorResult(
                message: $"Kullanıcı aktive edilirken bir hata oluştu: {ex.Message}");
        }
    }


    // ============================================================================
    // DTO MAPPING (MANUAL - NO AUTOMAPPER)
    // ============================================================================

    /// <summary>
    /// User entity'sini UserDto'ya dönüştürür.
    /// 
    /// GÜVENLİK KRİTİK:
    /// PasswordHash ASLA DTO'ya dahil edilmez!
    /// Bu, veri sızıntısını (data leaking) önler.
    /// </summary>
    private static UserDto ToDto(User user)
    {
        return new UserDto
        {
            Id = user.Id,
            Email = user.Email,
            Username = user.Username,
            Role = user.Role,
            IsActive = user.IsActive,
            CreatedAt = user.CreatedAt,
            LastLoginAt = user.LastLoginAt
            // PasswordHash ASLA eklenmez!
        };
    }
}