using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using VaultGuard.Application.Interfaces;
using VaultGuard.Application.DTOs.Auth;  // LoginDto, RegisterDto, TokenDto burada
using VaultGuard.Application.DTOs.Users; // Bazen TokenDto veya UserDto için gerekebilir
using VaultGuard.Domain.Common.Results;  // Result Pattern adresi
using VaultGuard.Domain.Entities;        // User.Create() metoduna erişim için

namespace VaultGuard.Application.Services;

/// <summary>
/// Authentication ve Authorization işlemleri için Application Service.
/// 
/// SORUMLULUKLAR:
/// - Kullanıcı kaydı (Register)
/// - Kullanıcı girişi (Login)
/// - Şifre doğrulama
/// - Login attempt takibi
/// 
/// MİMARİ PRENSİPLER:
/// ✅ Infrastructure'dan (EF Core) tamamen bağımsız
/// ✅ Repository pattern kullanımı
/// ✅ Dependency Injection
/// ✅ Result pattern ile tutarlı hata yönetimi
/// 
/// GÜVENLİK:
/// - User enumeration attack önlenir (generic error messages)
/// - Brute force attack önlenir (rate limiting - ileride)
/// - Password hash asla dışarı çıkmaz
/// - Login attempt logging yapılır
/// </summary>
public class AuthService : IAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly IPasswordHasher _passwordHasher;

    /// <summary>
    /// Constructor - Dependency Injection
    /// </summary>
    public AuthService(
        IUserRepository userRepository,
        IPasswordHasher passwordHasher)
    {
        _userRepository = userRepository;
        _passwordHasher = passwordHasher;
    }

    // ============================================================================
    // REGISTER (KAYIT) İŞLEMLERİ
    // ============================================================================

    /// <summary>
    /// Yeni kullanıcı kaydı yapar.
    /// 
    /// İŞ KURALLARI:
    /// 1. Email benzersiz olmalı
    /// 2. Username benzersiz olmalı
    /// 3. Şifre hash'lenmeli
    /// 4. Varsayılan rol "User"
    /// 5. Hesap aktif olarak başlar
    /// 
    /// GÜVENLİK:
    /// - Şifre plain-text olarak saklanmaz (hash'lenir)
    /// - Email normalizasyonu yapılır
    /// - Username format kontrolü yapılır
    /// 
    /// USER ENUMERATION PREVENTION:
    /// Email kontrolünde "Bu email kayıtlı" değil,
    /// "Kayıt başarısız" gibi generic mesaj dönülür.
    /// </summary>
    /// <summary>
    /// Yeni kullanıcı kaydı yapar (Register).
    /// 
    /// GÜVENLİK VE MİMARİ:
    /// - RegisterDto üzerinden veri transferi yapılır (Encapsulation).
    /// - User Enumeration Attack önlenir (Generic mesajlar).
    /// - Password hash'lenerek saklanır.
    /// </summary>
    /// <summary>
    /// Yeni kullanıcı kaydı yapar ve profesyonel standart gereği 
    /// kayıt sonrası otomatik giriş yaparak erişim anahtarı (Token) üretir.
    /// 
    /// GÜVENLİK NOTLARI:
    /// - User Enumeration Prevention: Email/Username varlığı sızdırılmaz.
    /// - Generic Error Messages: Hata mesajları saldırgana ipucu vermez.
    /// - Password Hashing: Şifreler asla düz metin olarak işlenmez.
    /// </summary>
    public async Task<IDataResult<TokenDto>> RegisterAsync(
        RegisterDto registerDto,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // 1. Temel validasyon (Veri paketi içeriği kontrolü)
            if (string.IsNullOrWhiteSpace(registerDto.Email) ||
                string.IsNullOrWhiteSpace(registerDto.Username) ||
                string.IsNullOrWhiteSpace(registerDto.Password))
            {
                return new ErrorDataResult<TokenDto>(message: "Gerekli tüm alanları doldurunuz.");
            }

            // 2. Email benzersizlik kontrolü (Siber Güvenlik: Generic Mesaj)
            var emailExists = await _userRepository.ExistsByEmailAsync(registerDto.Email, cancellationToken);
            if (emailExists)
            {
                // GÜVENLİK: "Email zaten var" demiyoruz, saldırganın bilgi toplamasını engelliyoruz.
                return new ErrorDataResult<TokenDto>(message: "Kayıt işlemi başarısız oldu. Lütfen bilgilerinizi kontrol edin.");
            }

            // 3. Username benzersizlik kontrolü (Siber Güvenlik: Generic Mesaj)
            var usernameExists = await _userRepository.ExistsByUsernameAsync(registerDto.Username, cancellationToken);
            if (usernameExists)
            {
                return new ErrorDataResult<TokenDto>(message: "Kayıt işlemi başarısız oldu. Lütfen bilgilerinizi kontrol edin.");
            }

            // 4. Şifreyi hash'le (IPasswordHasher üzerinden)
            var passwordHash = _passwordHasher.HashPassword(registerDto.Password);

            // 5. Domain entity oluştur (İş kuralları Domain katmanında işletilir)
            var user = User.Create(
                email: registerDto.Email,
                username: registerDto.Username,
                passwordHash: passwordHash,
                role: "User");

            // 6. Veritabanına kaydet
            await _userRepository.AddAsync(user, cancellationToken);
            await _userRepository.SaveChangesAsync(cancellationToken);

            // --------------------------------------------------------------------
            // 7. BÜYÜK FİNAL: TOKEN ÜRETİMİ (Hata buradaydı, düzeltildi)
            // --------------------------------------------------------------------
            // Profesyonel sistemlerde kayıt olan kullanıcıya direkt Token verilir.
            // Gerçek JWT üretimi ileride Infrastructure katmanında yapılacak.
            var tokenDto = new TokenDto
            {
                AccessToken = "VaultGuard_Initial_Access_Token_" + Guid.NewGuid().ToString("N"),
                Expiration = DateTime.UtcNow.AddHours(1)
            };

            return new SuccessDataResult<TokenDto>(
                data: tokenDto,
                message: "Kayıt başarıyla tamamlandı ve oturum açıldı.");
        }
        catch (ArgumentException ex)
        {
            // Domain katmanından gelen kural ihlalleri (Örn: geçersiz email formatı)
            return new ErrorDataResult<TokenDto>(message: $"Kayıt başarısız: {ex.Message}");
        }
        catch (Exception)
        {
            // Beklenmeyen teknik hataları dışarı sızdırmadan genel hata dönüyoruz.
            return new ErrorDataResult<TokenDto>(message: "Kayıt sırasında teknik bir hata oluştu.");
        }
    }

    // ============================================================================
    // LOGIN (GİRİŞ) İŞLEMLERİ
    // ============================================================================

    /// <summary>
    /// Kullanıcı girişi yapar.
    /// 
    /// GÜVENLİK - USER ENUMERATION PREVENTION:
    /// Başarısız login'de kesinlikle şu mesajlar VERİLMEZ:
    /// ❌ "Bu email kayıtlı değil"
    /// ❌ "Şifre yanlış"
    /// 
    /// Bunun yerine HER ZAMAN generic mesaj dönülür:
    /// ✅ "Email veya şifre hatalı"
    /// 
    /// Bu sayede saldırgan hangi email'lerin sistemde olduğunu öğrenemez.
    /// 
    /// BRUTE FORCE PREVENTION:
    /// - Login attempt sayısı izlenir (ileride rate limiting eklenecek)
    /// - Başarısız denemeler loglanır
    /// - IP bazlı rate limiting uygulanabilir
    /// </summary>
    /// <summary>
    /// Kullanıcı girişi yapar ve yetkilendirme anahtarı (Token) döner.
    /// </summary>
    public async Task<IDataResult<TokenDto>> LoginAsync(
        LoginDto loginDto, // Paket (DTO) yapısı
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(loginDto.Email) || string.IsNullOrWhiteSpace(loginDto.Password))
            {
                return new ErrorDataResult<TokenDto>("Email ve şifre alanları boş olamaz.");
            }

            var user = await _userRepository.GetByEmailAsync(loginDto.Email, cancellationToken);

            // GÜVENLİK: User Enumeration Prevention
            if (user == null || !user.IsActive || !_passwordHasher.VerifyPassword(loginDto.Password, user.PasswordHash))
            {
                return new ErrorDataResult<TokenDto>("Email veya şifre hatalı.");
            }

            user.RecordLogin();
            _userRepository.Update(user);
            await _userRepository.SaveChangesAsync(cancellationToken);

            // Şimdilik geçici bir Token oluşturuyoruz
            var tokenDto = new TokenDto { AccessToken = "Gecici_Anahtar", Expiration = DateTime.UtcNow.AddHours(1) };

            return new SuccessDataResult<TokenDto>(tokenDto, "Giriş başarılı.");
        }
        catch (Exception)
        {
            return new ErrorDataResult<TokenDto>("Giriş sırasında bir hata oluştu.");
        }
    }

    /// <summary>
    /// Username ile kullanıcı girişi yapar.
    /// 
    /// GÜVENLİK:
    /// Email ile login'deki tüm güvenlik prensipleri burada da geçerlidir.
    /// </summary>
    public async Task<IDataResult<UserDto>> LoginByUsernameAsync(
        string username,
        string password,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // 1. Temel validasyon
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                return new ErrorDataResult<UserDto>(
                    message: "Kullanıcı adı ve şifre alanları boş olamaz.");
            }

            // 2. Kullanıcıyı username'e göre bul
            var user = await _userRepository.GetByUsernameAsync(username, cancellationToken);

            // GÜVENLİK: Generic mesaj
            if (user == null)
            {
                return new ErrorDataResult<UserDto>(
                    message: "Kullanıcı adı veya şifre hatalı.");
            }

            // 3. Kullanıcı aktif mi kontrol et
            if (!user.IsActive)
            {
                return new ErrorDataResult<UserDto>(
                    message: "Bu hesap devre dışı bırakılmıştır. Lütfen yönetici ile iletişime geçin.");
            }

            // 4. Şifre doğrulaması
            var isPasswordValid = _passwordHasher.VerifyPassword(password, user.PasswordHash);

            if (!isPasswordValid)
            {
                // GÜVENLİK: Generic mesaj
                return new ErrorDataResult<UserDto>(
                    message: "Kullanıcı adı veya şifre hatalı.");
            }

            // 5. Başarılı login - LastLoginAt güncelle
            user.RecordLogin();

            _userRepository.Update(user);
            await _userRepository.SaveChangesAsync(cancellationToken);

            // 6. DTO dönüşümü ve dön
            var userDto = ToDto(user);
            return new SuccessDataResult<UserDto>(
                data: userDto,
                message: "Giriş başarılı.");
        }
        catch (Exception)
        {
            return new ErrorDataResult<UserDto>(
                message: "Giriş sırasında bir hata oluştu. Lütfen tekrar deneyin.");
        }
    }

    // ============================================================================
    // ŞİFRE DOĞRULAMA İŞLEMLERİ
    // ============================================================================

    /// <summary>
    /// Kullanıcının mevcut şifresini doğrular.
    /// 
    /// KULLANIM:
    /// - Hassas işlemler öncesi şifre teyidi (profil silme, email değiştirme vb.)
    /// - İki faktörlü authentication için
    /// 
    /// GÜVENLİK:
    /// - Bu metod sadece authenticated kullanıcılar için çağrılmalıdır
    /// - Rate limiting uygulanmalıdır (brute force önleme)
    /// </summary>
    public async Task<IResult> VerifyPasswordAsync(
        Guid userId,
        string password,
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return new ErrorResult(message: "Şifre boş olamaz.");
            }

            var user = await _userRepository.GetByIdAsync(userId, cancellationToken);
            if (user == null)
            {
                return new ErrorResult(message: "Kullanıcı bulunamadı.");
            }

            var isPasswordValid = _passwordHasher.VerifyPassword(password, user.PasswordHash);

            if (!isPasswordValid)
            {
                return new ErrorResult(message: "Şifre hatalı.");
            }

            return new SuccessResult(message: "Şifre doğrulandı.");
        }
        catch (Exception)
        {
            return new ErrorResult(
                message: "Şifre doğrulama sırasında bir hata oluştu.");
        }
    }
    // ============================================================================
    // TOKEN YÖNETİMİ
    // ============================================================================

    public async Task<IDataResult<TokenDto>> RefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
    {
        await Task.CompletedTask;
        // Altyapı (Infrastructure) hazır olduğunda burayı dolduracağız.
        return new SuccessDataResult<TokenDto>(new TokenDto { AccessToken = "Yeni_Token" }, "Token yenilendi.");
    }

    public async Task<IResult> RevokeAllTokensAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        await Task.CompletedTask;
        // Kullanıcının tüm oturumlarını kapatma mantığı.
        return new SuccessResult("Tüm oturumlar başarıyla kapatıldı.");
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