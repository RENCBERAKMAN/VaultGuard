using Microsoft.EntityFrameworkCore;
using System;
using System.Threading.Tasks;
using VaultGuard.Application.DTOs.Auth;
using VaultGuard.Application.DTOs.Users;
using VaultGuard.Application.Interfaces;
using VaultGuard.Domain.Entities;
using VaultGuard.WebAPI.Tests.Helpers;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Integration;

/// <summary>
/// Kullanıcı yönetimi için uçtan uca (End-to-End) integration testleri.
/// 
/// TEST KAPSAMI:
/// 1. Kullanıcı kayıt (Register) → Database → Login → JWT Token (Full Cycle)
/// 2. Duplicate email/username kontrolü (Conflict detection)
/// 3. Şifre değiştirme → SecurityStamp güncelleme (Token invalidation)
/// 4. Deaktif kullanıcı login denemesi (Authorization)
/// 5. Concurrency ve Entity Tracking (DbContext isolation)
/// 
/// TASARIM PRENSİPLERİ:
/// - MOCK KULLANILMAZ! Gerçek servisler, gerçek database (SQLite in-memory)
/// - TestDatabaseFixture ile izole edilmiş test ortamı
/// - Her test kendi arrange/act/assert fazında ayrı DbContext kullanır
/// - AAA pattern (Arrange-Act-Assert) milimetrik uygulanır
/// - Security-first approach (password hashing, token validation)
/// 
/// GÜVENLİK:
/// - Şifreler BCrypt ile hash'lenir (plain-text asla saklanmaz)
/// - JWT token'lar gerçek provider ile üretilir
/// - SecurityStamp mekanizması test edilir (session invalidation)
/// - Deaktif kullanıcı erişim kontrolü test edilir
/// 
/// NOT: Bu sınıf IClassFixture<TestDatabaseFixture> kullanır.
/// xUnit her test için fixture'ı paylaşır ama database her test için reset edilir.
/// </summary>
public class UserManagementTests : IClassFixture<TestDatabaseFixture>, IAsyncLifetime
{
    // ============================================================================
    // FIELDS & CONSTRUCTOR
    // ============================================================================

    /// <summary>
    /// Test database fixture (SQLite in-memory).
    /// Her test için temiz database sağlar.
    /// </summary>
    private readonly TestDatabaseFixture _fixture;

    /// <summary>
    /// Test için kullanılacak servisler.
    /// Mock değil, gerçek implementation'lar kullanılır.
    /// </summary>
    private IUserService? _userService;
    private IAuthService? _authService;

    public UserManagementTests(TestDatabaseFixture fixture)
    {
        _fixture = fixture;
    }

    // ============================================================================
    // TEST LIFECYCLE (IAsyncLifetime)
    // ============================================================================

    /// <summary>
    /// Her test başlamadan önce çalışır.
    /// 
    /// İŞ AKIŞI:
    /// 1. Database'i reset et (temiz state)
    /// 2. Servisleri initialize et (dependency injection simülasyonu)
    /// 
    /// NEDEN?
    /// Her test izole edilmiş ortamda çalışmalı.
    /// Bir testin verisi diğerini etkilememeli.
    /// </summary>
    public async Task InitializeAsync()
    {
        // Database reset (seed data ile)
        await _fixture.ResetDatabaseAsync();

        // Servisleri initialize et
        // NOT: Gerçek projede DI container'dan çözümlenecek
        // Şimdilik manual instantiation (test amaçlı)

        var context = _fixture.CreateContext();

        // ⚠️ DİKKAT: Aşağıdaki servisler henüz implement edilmemiş!
        // Bu placeholder kod - gerçek implementasyon gelince uncomment edilecek

        // _userService = new UserService(context, passwordHasher, auditService);
        // _authService = new AuthService(context, passwordHasher, jwtProvider, auditService);

        // Şimdilik null bırakıyoruz - testler skip edilecek
    }

    /// <summary>
    /// Her test bittikten sonra çalışır.
    /// 
    /// Cleanup işlemi (şimdilik boş - fixture zaten dispose ediliyor).
    /// </summary>
    public Task DisposeAsync()
    {
        return Task.CompletedTask;
    }

    // ============================================================================
    // SCENARIO 1: FULL REGISTRATION → LOGIN CYCLE
    // ============================================================================

    /// <summary>
    /// TAM DÖNGÜ TESTİ: Register → Database Verify → Login → Token Validation
    /// 
    /// TEST ADIMLARI (AAA):
    /// 
    /// ARRANGE:
    /// 1. MockDataGenerator ile geçerli RegisterDto oluştur
    /// 2. Unique email/username garanti et (seed data ile çakışmamalı)
    /// 
    /// ACT (Phase 1 - Register):
    /// 3. AuthService.RegisterAsync() çağır
    /// 4. Result.Success assert et
    /// 5. Yeni DbContext ile kullanıcının database'e yazıldığını doğrula
    /// 6. PasswordHash'in BCrypt formatında olduğunu doğrula
    /// 
    /// ACT (Phase 2 - Login):
    /// 7. Aynı credentials ile AuthService.LoginAsync() çağır
    /// 8. Result.Success assert et
    /// 9. TokenDto dönüldüğünü assert et
    /// 
    /// ASSERT (Token Validation):
    /// 10. AccessToken null/empty değil
    /// 11. RefreshToken null/empty değil
    /// 12. ExpiresAt gelecekte bir tarih
    /// 13. TokenType = "Bearer"
    /// 
    /// GÜVENLİK KONTROLLERI:
    /// - Şifre plain-text değil BCrypt hash
    /// - Token JWT formatında (3 part: header.payload.signature)
    /// - Token expiration set edilmiş
    /// 
    /// İZOLASYON:
    /// Her ACT fazında yeni DbContext kullanılır (tracking conflict önlenir).
    /// </summary>
    [Fact(Skip = "Services not implemented yet - TDD placeholder")]
    public async Task Register_Then_Login_ShouldReturn_ValidToken()
    {
        // ============================================================================
        // ARRANGE
        // ============================================================================

        // 1. Geçerli RegisterDto oluştur
        var registerDto = MockDataGenerator.CreateValidRegisterDto(
            email: "newuser@vaultguard.test", // Unique email (seed data ile çakışmaz)
            username: "newuser123", // Unique username
            password: MockDataGenerator.Passwords.ValidStrong // Test@1234
        );

        // 2. Credentials'ları sakla (login için kullanılacak)
        var email = registerDto.Email;
        var password = registerDto.Password;

        // ============================================================================
        // ACT - PHASE 1: REGISTER
        // ============================================================================

        // 3. Register işlemi
        // var registerResult = await _authService!.RegisterAsync(registerDto);

        // 4. Register başarılı mı?
        // Assert.True(registerResult.Success, registerResult.Message);
        // Assert.NotNull(registerResult.Data);

        // 5. Database verification (yeni DbContext ile - izolasyon)
        // using (var verifyContext = _fixture.CreateContext())
        // {
        //     var createdUser = await verifyContext.Users
        //         .FirstOrDefaultAsync(u => u.Email == email);
        //     
        //     Assert.NotNull(createdUser);
        //     Assert.Equal(email, createdUser.Email);
        //     Assert.Equal("newuser123", createdUser.Username);
        //     Assert.Equal("User", createdUser.Role); // Default role
        //     Assert.True(createdUser.IsActive);
        //     
        //     // 6. Password hash kontrolü
        //     Assert.NotEmpty(createdUser.PasswordHash);
        //     Assert.NotEqual(password, createdUser.PasswordHash); // Plain-text değil!
        //     
        //     // BCrypt hash format: $2a$10$... (60 karakter)
        //     Assert.StartsWith("$2", createdUser.PasswordHash);
        //     Assert.True(createdUser.PasswordHash.Length >= 60);
        //     
        //     // BCrypt verify (şifre doğru hash'lenmiş mi?)
        //     var isPasswordValid = MockDataGenerator.VerifyPassword(password, createdUser.PasswordHash);
        //     Assert.True(isPasswordValid);
        // }

        // ============================================================================
        // ACT - PHASE 2: LOGIN
        // ============================================================================

        // 7. Login işlemi (kayıt sırasında kullanılan credentials)
        // var loginDto = new LoginDto
        // {
        //     Email = email,
        //     Password = password,
        //     RememberMe = false
        // };

        // var loginResult = await _authService!.LoginAsync(loginDto);

        // 8. Login başarılı mı?
        // Assert.True(loginResult.Success, loginResult.Message);
        // Assert.NotNull(loginResult.Data);

        // ============================================================================
        // ASSERT - TOKEN VALIDATION
        // ============================================================================

        // 9. TokenDto validation
        // var token = loginResult.Data;

        // 10. AccessToken kontrolü
        // Assert.NotNull(token.AccessToken);
        // Assert.NotEmpty(token.AccessToken);

        // JWT format: 3 part separated by dots (header.payload.signature)
        // var jwtParts = token.AccessToken.Split('.');
        // Assert.Equal(3, jwtParts.Length);

        // 11. RefreshToken kontrolü (opsiyonel - RememberMe=false ise null olabilir)
        // if (loginDto.RememberMe)
        // {
        //     Assert.NotNull(token.RefreshToken);
        //     Assert.NotEmpty(token.RefreshToken);
        // }

        // 12. Expiration kontrolü
        // Assert.True(token.ExpiresAt > DateTime.UtcNow);
        // Assert.True(token.ExpiresIn > 0);

        // 13. TokenType kontrolü
        // Assert.Equal("Bearer", token.TokenType);
    }

    // ============================================================================
    // SCENARIO 2: DUPLICATE EMAIL/USERNAME CONFLICT
    // ============================================================================

    /// <summary>
    /// DUPLICATE DETECTION TESTİ: Var olan email ile kayıt denemesi
    /// 
    /// TEST ADIMLARI:
    /// 
    /// ARRANGE:
    /// 1. Seed data'da zaten var olan email kullan (admin@vaultguard.test)
    /// 2. RegisterDto oluştur
    /// 
    /// ACT:
    /// 3. AuthService.RegisterAsync() çağır
    /// 
    /// ASSERT:
    /// 4. Result.Success = false
    /// 5. ErrorCode = "ERR_EMAIL_EXISTS" veya benzeri
    /// 6. Exception fırlatılmamış (Result pattern ile handle edilmiş)
    /// 7. Database'e yeni kayıt EKLENMEMİŞ (verify)
    /// 
    /// GÜVENLİK:
    /// Duplicate email/username enumeration saldırısına karşı koruma.
    /// Generic error message ("Email already in use" - hangi email belli olmamalı).
    /// 
    /// DATABASE INTEGRITY:
    /// Unique constraint violation database seviyesinde engellenir.
    /// </summary>
    [Fact(Skip = "Services not implemented yet - TDD placeholder")]
    public async Task Register_WithExistingEmail_ShouldFail()
    {
        // ============================================================================
        // ARRANGE
        // ============================================================================

        // 1. Seed data'dan var olan email kullan
        var existingEmail = TestDatabaseFixture.AdminEmail; // admin@vaultguard.test

        // 2. RegisterDto oluştur (email duplicate, username unique)
        var registerDto = MockDataGenerator.CreateValidRegisterDto(
            email: existingEmail, // DUPLICATE!
            username: "uniqueuser123", // Unique
            password: MockDataGenerator.Passwords.ValidStrong
        );

        // User count before (doğrulama için)
        var userCountBefore = await _fixture.GetUserCountAsync();

        // ============================================================================
        // ACT
        // ============================================================================

        // 3. Register işlemi (başarısız olmalı)
        // var result = await _authService!.RegisterAsync(registerDto);

        // ============================================================================
        // ASSERT
        // ============================================================================

        // 4. Başarısız sonuç
        // Assert.False(result.Success);

        // 5. Error code kontrolü
        // Assert.NotNull(result.ErrorCode);
        // Assert.Contains("EMAIL", result.ErrorCode, StringComparison.OrdinalIgnoreCase);
        // veya
        // Assert.Contains("EXISTS", result.ErrorCode, StringComparison.OrdinalIgnoreCase);

        // 6. Error message kontrolü (generic olmalı - security)
        // Assert.Contains("already", result.Message, StringComparison.OrdinalIgnoreCase);

        // 7. Database'e yeni kayıt eklenmemiş
        var userCountAfter = await _fixture.GetUserCountAsync();
        Assert.Equal(userCountBefore, userCountAfter);
    }

    /// <summary>
    /// DUPLICATE USERNAME TESTİ: Var olan username ile kayıt denemesi
    /// 
    /// Register_WithExistingEmail ile benzer mantık.
    /// Bu sefer username duplicate, email unique.
    /// </summary>
    [Fact(Skip = "Services not implemented yet - TDD placeholder")]
    public async Task Register_WithExistingUsername_ShouldFail()
    {
        // ARRANGE
        var existingUsername = TestDatabaseFixture.AdminUsername; // admin

        var registerDto = MockDataGenerator.CreateValidRegisterDto(
            email: "uniqueemail@vaultguard.test", // Unique
            username: existingUsername, // DUPLICATE!
            password: MockDataGenerator.Passwords.ValidStrong
        );

        var userCountBefore = await _fixture.GetUserCountAsync();

        // ACT
        // var result = await _authService!.RegisterAsync(registerDto);

        // ASSERT
        // Assert.False(result.Success);
        // Assert.Contains("USERNAME", result.ErrorCode, StringComparison.OrdinalIgnoreCase);

        var userCountAfter = await _fixture.GetUserCountAsync();
        Assert.Equal(userCountBefore, userCountAfter);
    }

    // ============================================================================
    // SCENARIO 3: PASSWORD CHANGE → SECURITY STAMP UPDATE
    // ============================================================================

    /// <summary>
    /// SECURITY STAMP TESTİ: Şifre değiştirme sonrası SecurityStamp güncellenmeli
    /// 
    /// SECURITY STAMP NEDİR?
    /// Kullanıcının "security state"ini temsil eden unique identifier.
    /// Şifre değiştiğinde veya kritik bilgi değiştiğinde güncellenir.
    /// Eski JWT token'lar SecurityStamp ile validate edilir - değişmişse invalid olur.
    /// 
    /// TEST ADIMLARI:
    /// 
    /// ARRANGE:
    /// 1. Seed data'daki normal user'ı kullan
    /// 2. Eski SecurityStamp'i database'den oku (initial value)
    /// 
    /// ACT:
    /// 3. ChangePasswordDto oluştur (current + new password)
    /// 4. UserService.ChangePasswordAsync() çağır
    /// 
    /// ASSERT:
    /// 5. Result.Success = true
    /// 6. Yeni DbContext ile user'ı database'den oku
    /// 7. SecurityStamp değişmiş (old != new)
    /// 8. PasswordHash değişmiş
    /// 9. Yeni şifre ile login olunabiliyor
    /// 10. Eski şifre ile login OLUNAMIYOR
    /// 
    /// GÜVENLİK:
    /// - Şifre değiştiğinde eski token'lar invalidate edilir
    /// - Session hijacking riski azalır
    /// - Şifre sızıntısı durumunda hızlı tepki
    /// 
    /// NOT: User entity'de SecurityStamp property'si yoksa bu test skip edilir.
    /// Ama production sistemde mutlaka olmalı!
    /// </summary>
    [Fact(Skip = "SecurityStamp property not implemented yet")]
    public async Task ChangePassword_Should_UpdateSecurityStamp()
    {
        // ============================================================================
        // ARRANGE
        // ============================================================================

        // 1. Seed data'daki normal user
        var userId = _fixture.NormalUserId;
        var currentPassword = TestDatabaseFixture.TestPassword; // Test@1234
        var newPassword = "NewSecurePassword@2024";

        // 2. Eski SecurityStamp'i oku (initial state)
        string oldSecurityStamp;
        string oldPasswordHash;

        using (var arrangeContext = _fixture.CreateContext())
        {
            var user = await arrangeContext.Users.FindAsync(userId);
            Assert.NotNull(user);

            // oldSecurityStamp = user.SecurityStamp; // Property henüz yok
            oldPasswordHash = user.PasswordHash;

            Assert.NotEmpty(oldPasswordHash);
            // Assert.NotEmpty(oldSecurityStamp);
        }

        // ============================================================================
        // ACT
        // ============================================================================

        // 3. ChangePasswordDto
        var changePasswordDto = new ChangePasswordDto
        {
            CurrentPassword = currentPassword,
            NewPassword = newPassword,
            ConfirmNewPassword = newPassword
        };

        // 4. Şifre değiştirme işlemi
        // var result = await _userService!.ChangePasswordAsync(userId, changePasswordDto);

        // ============================================================================
        // ASSERT
        // ============================================================================

        // 5. İşlem başarılı
        // Assert.True(result.Success, result.Message);

        // 6. Database'den güncel user'ı oku (yeni DbContext ile)
        using (var assertContext = _fixture.CreateContext())
        {
            var updatedUser = await assertContext.Users.FindAsync(userId);
            Assert.NotNull(updatedUser);

            // 7. SecurityStamp değişmiş
            // var newSecurityStamp = updatedUser.SecurityStamp;
            // Assert.NotEqual(oldSecurityStamp, newSecurityStamp);

            // 8. PasswordHash değişmiş
            var newPasswordHash = updatedUser.PasswordHash;
            Assert.NotEqual(oldPasswordHash, newPasswordHash);

            // 9. Yeni şifre ile verify
            var isNewPasswordValid = MockDataGenerator.VerifyPassword(newPassword, newPasswordHash);
            Assert.True(isNewPasswordValid);

            // 10. Eski şifre ile verify (başarısız olmalı)
            var isOldPasswordValid = MockDataGenerator.VerifyPassword(currentPassword, newPasswordHash);
            Assert.False(isOldPasswordValid);
        }

        // 11. Yeni şifre ile login olunabiliyor
        // var loginDto = new LoginDto
        // {
        //     Email = TestDatabaseFixture.NormalUserEmail,
        //     Password = newPassword
        // };
        // 
        // var loginResult = await _authService!.LoginAsync(loginDto);
        // Assert.True(loginResult.Success);

        // 12. Eski şifre ile login OLUNAMIYOR
        // var oldLoginDto = new LoginDto
        // {
        //     Email = TestDatabaseFixture.NormalUserEmail,
        //     Password = currentPassword // ESKİ ŞİFRE
        // };
        // 
        // var oldLoginResult = await _authService!.LoginAsync(oldLoginDto);
        // Assert.False(oldLoginResult.Success);
        // Assert.Contains("Invalid", oldLoginResult.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ============================================================================
    // SCENARIO 4: INACTIVE USER LOGIN ATTEMPT
    // ============================================================================

    /// <summary>
    /// DEACTIVE USER LOGIN TESTİ: Deaktif kullanıcı login olamamalı
    /// 
    /// TEST ADIMLARI:
    /// 
    /// ARRANGE:
    /// 1. Seed data'daki normal user'ı kullan
    /// 2. User'ı deaktif et (IsActive = false)
    /// 3. Database'e kaydet
    /// 
    /// ACT:
    /// 4. Doğru credentials ile login dene
    /// 
    /// ASSERT:
    /// 5. Result.Success = false
    /// 6. ErrorCode = "AUTH_ACCOUNT_INACTIVE" veya benzeri
    /// 7. Token dönülMEMİŞ (null)
    /// 
    /// GÜVENLİK:
    /// - Admin hesap askıya alma (account lockout)
    /// - Şüpheli aktivite durumunda erişim engelleme
    /// - Hesap silme yerine deaktif etme (soft delete)
    /// 
    /// AUTHORIZATION:
    /// IsActive kontrolü authentication sürecinde yapılmalı.
    /// </summary>
    [Fact(Skip = "Services not implemented yet - TDD placeholder")]
    public async Task Login_WithInactiveUser_ShouldFail()
    {
        // ============================================================================
        // ARRANGE
        // ============================================================================

        // 1. Seed data'daki normal user
        var userId = _fixture.NormalUserId;
        var email = TestDatabaseFixture.NormalUserEmail;
        var password = TestDatabaseFixture.TestPassword;

        // 2. User'ı deaktif et
        using (var arrangeContext = _fixture.CreateContext())
        {
            var user = await arrangeContext.Users.FindAsync(userId);
            Assert.NotNull(user);

            user.Deactivate(); // Domain method
            await arrangeContext.SaveChangesAsync();
        }

        // 3. Deaktif olduğunu doğrula
        using (var verifyContext = _fixture.CreateContext())
        {
            var user = await verifyContext.Users.FindAsync(userId);
            Assert.NotNull(user);
            Assert.False(user.IsActive);
        }

        // ============================================================================
        // ACT
        // ============================================================================

        // 4. Login denemesi (doğru credentials ama inactive user)
        var loginDto = new LoginDto
        {
            Email = email,
            Password = password,
            RememberMe = false
        };

        // var result = await _authService!.LoginAsync(loginDto);

        // ============================================================================
        // ASSERT
        // ============================================================================

        // 5. Login başarısız
        // Assert.False(result.Success);

        // 6. Error code kontrolü
        // Assert.NotNull(result.ErrorCode);
        // Assert.Contains("INACTIVE", result.ErrorCode, StringComparison.OrdinalIgnoreCase);
        // veya
        // Assert.Contains("LOCKED", result.ErrorCode, StringComparison.OrdinalIgnoreCase);

        // 7. Error message kontrolü
        // Assert.Contains("deactivated", result.Message, StringComparison.OrdinalIgnoreCase);
        // veya
        // Assert.Contains("locked", result.Message, StringComparison.OrdinalIgnoreCase);

        // 8. Token dönülmemiş
        // Assert.Null(result.Data);
    }

    // ============================================================================
    // SCENARIO 5: WRONG PASSWORD LOGIN ATTEMPT
    // ============================================================================

    /// <summary>
    /// YANLIŞ ŞİFRE TESTİ: Yanlış şifre ile login denemesi
    /// 
    /// GÜVENLİK:
    /// - Brute force protection (rate limiting ile birlikte)
    /// - Timing attack prevention (constant-time response)
    /// - Information leakage prevention (generic error message)
    /// 
    /// ASSERT:
    /// - Result.Success = false
    /// - ErrorCode = "AUTH_INVALID_CREDENTIALS"
    /// - Message generic ("Invalid email or password" - hangi alan yanlış belli olmamalı)
    /// - Token null
    /// </summary>
    [Fact(Skip = "Services not implemented yet - TDD placeholder")]
    public async Task Login_WithWrongPassword_ShouldFail()
    {
        // ARRANGE
        var email = TestDatabaseFixture.AdminEmail;
        var wrongPassword = "WrongPassword123!";

        var loginDto = new LoginDto
        {
            Email = email,
            Password = wrongPassword
        };

        // ACT
        // var result = await _authService!.LoginAsync(loginDto);

        // ASSERT
        // Assert.False(result.Success);
        // Assert.NotNull(result.ErrorCode);
        // Assert.Contains("INVALID", result.ErrorCode, StringComparison.OrdinalIgnoreCase);

        // Generic error message (security)
        // Assert.Contains("Invalid", result.Message);
        // Assert.DoesNotContain("password", result.Message, StringComparison.OrdinalIgnoreCase);

        // Assert.Null(result.Data);
    }

    // ============================================================================
    // SCENARIO 6: NON-EXISTENT USER LOGIN ATTEMPT
    // ============================================================================

    /// <summary>
    /// VAR OLMAYAN KULLANICI TESTİ: Database'de olmayan email ile login
    /// 
    /// GÜVENLİK:
    /// - Email enumeration prevention (aynı error message)
    /// - Timing attack prevention
    /// 
    /// ASSERT:
    /// - "User not found" DEME! ("Invalid email or password" - generic)
    /// - Aynı error code (AUTH_INVALID_CREDENTIALS)
    /// </summary>
    [Fact(Skip = "Services not implemented yet - TDD placeholder")]
    public async Task Login_WithNonExistentEmail_ShouldFail()
    {
        // ARRANGE
        var nonExistentEmail = "nonexistent@vaultguard.test";
        var anyPassword = MockDataGenerator.Passwords.ValidStrong;

        var loginDto = new LoginDto
        {
            Email = nonExistentEmail,
            Password = anyPassword
        };

        // ACT
        // var result = await _authService!.LoginAsync(loginDto);

        // ASSERT
        // Assert.False(result.Success);

        // GÜVENLİK: Generic error (email enumeration önleme)
        // Assert.Contains("Invalid", result.Message);
        // Assert.DoesNotContain("not found", result.Message, StringComparison.OrdinalIgnoreCase);
        // Assert.DoesNotContain("exist", result.Message, StringComparison.OrdinalIgnoreCase);

        // Assert.Null(result.Data);
    }

    // ============================================================================
    // SCENARIO 7: CONCURRENT CONTEXT ISOLATION
    // ============================================================================

    /// <summary>
    /// TRACKING CONFLICT TESTİ: Aynı entity farklı context'lerde tracked
    /// 
    /// SORUN:
    /// Aynı test içinde aynı entity farklı DbContext'lerde track edilirse:
    /// "The instance of entity type cannot be tracked because another instance
    /// with the same key value is already being tracked."
    /// 
    /// ÇÖZÜM:
    /// Her fazda (Arrange, Act, Assert) ayrı DbContext kullan.
    /// 
    /// TEST:
    /// 1. Context1 ile user oku ve tracked olduğunu doğrula
    /// 2. Context2 ile aynı user'ı oku
    /// 3. Exception fırlatılmamalı (farklı context'ler)
    /// 4. Her iki user instance'ı farklı referans olmalı (NotSame)
    /// </summary>
    [Fact]
    public async Task MultipleContexts_ShouldNot_CauseTrackingConflict()
    {
        // ARRANGE
        var userId = _fixture.AdminUserId;

        // ============================================================================
        // ACT - PHASE 1: Context1 ile user oku
        // ============================================================================

        User user1;
        using (var context1 = _fixture.CreateContext())
        {
            user1 = await context1.Users.FindAsync(userId);
            Assert.NotNull(user1);

            // Tracked olduğunu doğrula
            var entry1 = context1.Entry(user1);
            Assert.Equal(EntityState.Unchanged, entry1.State);
        } // context1 dispose edildi

        // ============================================================================
        // ACT - PHASE 2: Context2 ile aynı user'ı oku
        // ============================================================================

        User user2;
        using (var context2 = _fixture.CreateContext())
        {
            // Exception fırlatmamalı (farklı context)
            user2 = await context2.Users.FindAsync(userId);
            Assert.NotNull(user2);

            var entry2 = context2.Entry(user2);
            Assert.Equal(EntityState.Unchanged, entry2.State);
        }

        // ============================================================================
        // ASSERT
        // ============================================================================

        // Farklı instance'lar (farklı context'lerden geldi)
        Assert.NotSame(user1, user2);

        // Ama aynı ID ve data
        Assert.Equal(user1.Id, user2.Id);
        Assert.Equal(user1.Email, user2.Email);
    }

    // ============================================================================
    // SCENARIO 8: DATABASE TRANSACTION ROLLBACK
    // ============================================================================

    /// <summary>
    /// TRANSACTION ROLLBACK TESTİ: Hata durumunda rollback
    /// 
    /// TEST:
    /// 1. Transaction başlat
    /// 2. User oluştur ve kaydet
    /// 3. Exception fırlat (simulate error)
    /// 4. Transaction rollback
    /// 5. User database'e EKLENMEMİŞ olmalı
    /// 
    /// GÜVENLİK:
    /// Partial state corruption prevention.
    /// Atomicity guarantee.
    /// </summary>
    [Fact]
    public async Task Transaction_OnError_ShouldRollback()
    {
        // ARRANGE
        var initialUserCount = await _fixture.GetUserCountAsync();

        var newUser = MockDataGenerator.CreateValidUser();

        // ACT
        using (var context = _fixture.CreateContext())
        {
            using var transaction = await context.Database.BeginTransactionAsync();

            try
            {
                // User ekle
                context.Users.Add(newUser);
                await context.SaveChangesAsync();

                // Simulate error
                throw new Exception("Simulated error for rollback test");

                // Bu satıra asla gelinmeyecek
                // await transaction.CommitAsync();
            }
            catch
            {
                // Rollback
                await transaction.RollbackAsync();
            }
        }

        // ASSERT
        var finalUserCount = await _fixture.GetUserCountAsync();

        // User eklenmemiş (rollback oldu)
        Assert.Equal(initialUserCount, finalUserCount);

        // Verify: User database'de yok
        var user = await _fixture.GetUserByEmailAsync(newUser.Email);
        Assert.Null(user);
    }
}