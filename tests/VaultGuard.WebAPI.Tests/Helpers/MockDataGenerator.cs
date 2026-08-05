using BCrypt.Net;
using Bogus;
using System;
using System.Collections.Generic;
using VaultGuard.Application.DTOs.Auth;
using VaultGuard.Application.DTOs.Users;
using VaultGuard.Domain.Entities;

namespace VaultGuard.WebAPI.Tests.Helpers;

/// <summary>
/// Test senaryolarý için sahte (mock) veri üretimi yapan helper sýnýf.
/// 
/// KULLANIM ALANLARI:
/// - Unit testler için domain entity'ler
/// - Integration testler için DTO'lar
/// - Güvenlik testleri için invalid/malicious data
/// - Load testleri için bulk data
/// 
/// TEKNOLOJÝLER:
/// - Bogus: Gerçekçi sahte veri üretimi (Faker)
/// - BCrypt.Net: Gerçek password hashing
/// 
/// GÜVENLÝK TESTLERÝ:
/// Bu sýnýf security test senaryolarý için özel olarak tasarlanmýþtýr:
/// - XSS payload'larý (Cross-Site Scripting)
/// - SQL Injection payload'larý
/// - Boundary value testing (max length, empty, null)
/// - Format validation testing (invalid email, weak password)
/// </summary>
public static class MockDataGenerator
{
    // ============================================================================
    // BOGUS FAKER INSTANCES (THREAD-SAFE SINGLETON)
    // ============================================================================

    /// <summary>
    /// Thread-safe Bogus Faker instance.
    /// Her test için ayný instance kullanýlýr (performance).
    /// Locale: "tr" (Türkçe isimler, adresler)
    /// </summary>
    private static readonly Faker Faker = new("tr");

    /// <summary>
    /// Deterministik (repeatable) testler için seed'li Faker.
    /// Seed: 42 (her çalýþtýrmada ayný veriyi üretir)
    /// </summary>
    private static readonly Faker DeterministicFaker = new("tr") { Random = new Randomizer(42) };

    // ============================================================================
    // CONSTANTS (TEST DATA)
    // ============================================================================

    /// <summary>
    /// Test þifreleri için sabit deðerler.
    /// Validation testlerinde kullanýlýr.
    /// </summary>
    public static class Passwords
    {
        /// <summary>Geçerli, güçlü þifre.</summary>
        public const string ValidStrong = "Test@1234";

        /// <summary>Zayýf þifre (sadece lowercase).</summary>
        public const string WeakLowercase = "password";

        /// <summary>Zayýf þifre (sadece uppercase).</summary>
        public const string WeakUppercase = "PASSWORD";

        /// <summary>Zayýf þifre (sadece rakam).</summary>
        public const string WeakNumeric = "12345678";

        /// <summary>Çok kýsa þifre (min length violation).</summary>
        public const string TooShort = "Aa1!";

        /// <summary>Yaygýn þifre (blacklist check için).</summary>
        public const string CommonPassword = "password123";

        /// <summary>SQL Injection denemesi.</summary>
        public const string SqlInjection = "' OR '1'='1";

        /// <summary>XSS payload.</summary>
        public const string XssPayload = "<script>alert('XSS')</script>";
    }

    /// <summary>
    /// Test email adresleri için sabit deðerler.
    /// </summary>
    public static class Emails
    {
        /// <summary>Geçerli email (test için).</summary>
        public const string ValidTest = "test@vaultguard.com";

        /// <summary>Admin email (seed data için).</summary>
        public const string AdminTest = "admin@vaultguard.com";

        /// <summary>Geçersiz format (@ yok).</summary>
        public const string InvalidNoAt = "testvaultguard.com";

        /// <summary>Geçersiz format (domain yok).</summary>
        public const string InvalidNoDomain = "test@";

        /// <summary>Geçersiz format (. yok).</summary>
        public const string InvalidNoDot = "test@vaultguard";

        /// <summary>SQL Injection denemesi.</summary>
        public const string SqlInjection = "test' OR '1'='1@mail.com";

        /// <summary>XSS payload.</summary>
        public const string XssPayload = "<script>alert('XSS')</script>@mail.com";

        /// <summary>Çok uzun email (max length violation).</summary>
        public static string TooLong => new string('a', 250) + "@test.com"; // 260 chars
    }

    /// <summary>
    /// Test username'leri için sabit deðerler.
    /// </summary>
    public static class Usernames
    {
        /// <summary>Geçerli username.</summary>
        public const string ValidTest = "test_user";

        /// <summary>Admin username.</summary>
        public const string AdminTest = "admin";

        /// <summary>Geçersiz (çok kýsa).</summary>
        public const string TooShort = "ab";

        /// <summary>Geçersiz (özel karakter).</summary>
        public const string InvalidSpecialChars = "test-user!";

        /// <summary>Geçersiz (boþluk).</summary>
        public const string InvalidWithSpace = "test user";

        /// <summary>SQL Injection denemesi.</summary>
        public const string SqlInjection = "admin' OR '1'='1";

        /// <summary>XSS payload.</summary>
        public const string XssPayload = "<script>alert('XSS')</script>";

        /// <summary>Çok uzun username (max length violation).</summary>
        public static string TooLong => new string('a', 51); // 51 chars
    }

    // ============================================================================
    // USER ENTITY GENERATORS
    // ============================================================================

    /// <summary>
    /// Geçerli, aktif bir User entity oluþturur.
    /// 
    /// KULLANIM:
    /// - Integration testler için seed data
    /// - Unit testler için test fixture
    /// 
    /// ÖZELLÝKLER:
    /// - Email: Gerçekçi, unique
    /// - Username: Alfanumerik, unique
    /// - PasswordHash: BCrypt hash'li (gerçek)
    /// - Role: "User" (default)
    /// - IsActive: true
    /// - CreatedAt: Now
    /// </summary>
    /// <param name="role">Kullanýcý rolü (default: "User").</param>
    /// <param name="password">Plain-text þifre (hash'lenecek, default: "Test@1234").</param>
    /// <param name="deterministicSeed">true ise her çalýþtýrmada ayný veri üretir.</param>
    /// <returns>Yeni User entity.</returns>
    public static User CreateValidUser(
        string role = "User",
        string password = Passwords.ValidStrong,
        bool deterministicSeed = false)
    {
        var faker = deterministicSeed ? DeterministicFaker : Faker;

        // GÜVENLÝK: Gerçek BCrypt hashing (test ortamýnda bile)
        var passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

        // Bogus ile gerçekçi veri üretimi
        var email = faker.Internet.Email().ToLower();
        var username = faker.Internet.UserName().Replace(".", "_").Replace("-", "_").ToLower();

        // Domain factory method kullanarak oluþtur (validation dahil)
        return User.Create(email, username, passwordHash, role);
    }

    /// <summary>
    /// Admin rolünde bir User oluþturur.
    /// 
    /// KULLANIM:
    /// - Seed data için SuperAdmin
    /// - Authorization testleri için admin user
    /// </summary>
    public static User CreateAdminUser(
        string email = Emails.AdminTest,
        string username = Usernames.AdminTest,
        string password = Passwords.ValidStrong)
    {
        var passwordHash = BCrypt.Net.BCrypt.HashPassword(password);
        return User.Create(email, username, passwordHash, "Admin");
    }

    /// <summary>
    /// Deaktif (IsActive = false) bir User oluþturur.
    /// 
    /// KULLANIM:
    /// - Login testleri (deaktif kullanýcý giriþ yapamamalý)
    /// - Authorization testleri
    /// 
    /// GÜVENLÝK TESTÝ:
    /// Deaktif kullanýcýlarýn sisteme eriþememesi test edilir.
    /// </summary>
    public static User CreateInactiveUser()
    {
        var user = CreateValidUser();
        user.Deactivate(); // Domain method ile deaktif et
        return user;
    }

    /// <summary>
    /// Soft-deleted (IsDeleted = true) bir User oluþturur.
    /// 
    /// NOT: User entity'de IsDeleted property'si yoksa bu metod çalýþmaz.
    /// Þimdilik manual olarak iþaretliyoruz.
    /// 
    /// KULLANIM:
    /// - Global query filter testleri
    /// - Soft delete senaryolarý
    /// </summary>
    public static User CreateSoftDeletedUser()
    {
        var user = CreateValidUser();
        // NOT: User entity'de IsDeleted property'si yok
        // Þimdilik IsActive = false kullanarak simulate ediyoruz
        user.Deactivate();
        return user;
    }

    /// <summary>
    /// Birden fazla User entity oluþturur (bulk data).
    /// 
    /// KULLANIM:
    /// - Load testleri
    /// - Pagination testleri
    /// - Search/filter testleri
    /// </summary>
    /// <param name="count">Oluþturulacak user sayýsý.</param>
    /// <param name="role">Tüm kullanýcýlarýn rolü.</param>
    /// <returns>User listesi.</returns>
    public static List<User> CreateMultipleUsers(int count, string role = "User")
    {
        var users = new List<User>();
        for (int i = 0; i < count; i++)
        {
            users.Add(CreateValidUser(role));
        }
        return users;
    }

    // ============================================================================
    // DTO GENERATORS - VALID VARIANTS
    // ============================================================================

    /// <summary>
    /// Geçerli bir RegisterDto oluþturur.
    /// 
    /// KULLANIM:
    /// - Register endpoint testleri
    /// - Validation testleri (positive test)
    /// 
    /// VALIDATION:
    /// - Email: Valid format
    /// - Username: Alfanumerik, 3-50 karakter
    /// - Password: Güçlü (büyük/küçük harf, rakam, özel karakter)
    /// - ConfirmPassword: Password ile ayný
    /// </summary>
    public static RegisterDto CreateValidRegisterDto(
        string? email = null,
        string? username = null,
        string? password = null)
    {
        return new RegisterDto
        {
            Email = email ?? Faker.Internet.Email().ToLower(),
            Username = username ?? Faker.Internet.UserName().Replace(".", "_").Replace("-", "_").ToLower(),
            Password = password ?? Passwords.ValidStrong,
            ConfirmPassword = password ?? Passwords.ValidStrong,
            RecaptchaToken = "mock_recaptcha_token_for_testing"
        };
    }

    /// <summary>
    /// Geçerli bir LoginDto oluþturur.
    /// 
    /// KULLANIM:
    /// - Login endpoint testleri
    /// - Authentication testleri
    /// </summary>
    public static LoginDto CreateValidLoginDto(
        string email = Emails.ValidTest,
        string password = Passwords.ValidStrong,
        bool rememberMe = false)
    {
        return new LoginDto
        {
            Email = email,
            Password = password,
            RememberMe = rememberMe
        };
    }

    /// <summary>
    /// Geçerli bir CreateUserDto oluþturur.
    /// 
    /// KULLANIM:
    /// - Admin user creation testleri
    /// - CRUD testleri
    /// </summary>
    public static CreateUserDto CreateValidCreateUserDto(
        string? email = null,
        string? username = null,
        string? password = null,
        string role = "User")
    {
        return new CreateUserDto
        {
            Email = email ?? Faker.Internet.Email().ToLower(),
            Username = username ?? Faker.Internet.UserName().Replace(".", "_").Replace("-", "_").ToLower(),
            Password = password ?? Passwords.ValidStrong,
            Role = role
        };
    }

    /// <summary>
    /// Geçerli bir UpdateUserDto oluþturur.
    /// 
    /// KULLANIM:
    /// - Update endpoint testleri
    /// - Validation testleri
    /// </summary>
    public static UpdateUserDto CreateValidUpdateUserDto(
        Guid userId,
        string? email = null,
        string? username = null,
        string? role = null)
    {
        return new UpdateUserDto
        {
            Id = userId,
            Email = email ?? Faker.Internet.Email().ToLower(),
            Username = username ?? Faker.Internet.UserName().Replace(".", "_").Replace("-", "_").ToLower(),
            Role = role
        };
    }

    /// <summary>
    /// Geçerli bir ChangePasswordDto oluþturur.
    /// 
    /// KULLANIM:
    /// - Change password endpoint testleri
    /// - Security testleri
    /// </summary>
    public static ChangePasswordDto CreateValidChangePasswordDto(
        string currentPassword = Passwords.ValidStrong,
        string newPassword = "NewTest@1234")
    {
        return new ChangePasswordDto
        {
            CurrentPassword = currentPassword,
            NewPassword = newPassword,
            ConfirmNewPassword = newPassword
        };
    }

    // ============================================================================
    // DTO GENERATORS - INVALID VARIANTS (SECURITY TESTING)
    // ============================================================================

    /// <summary>
    /// Geçersiz email formatýna sahip RegisterDto oluþturur.
    /// 
    /// GÜVENLÝK TESTÝ:
    /// Email validation bypass denemesi.
    /// </summary>
    public static RegisterDto CreateRegisterDtoWithInvalidEmail()
    {
        return new RegisterDto
        {
            Email = Emails.InvalidNoAt, // @ yok
            Username = Faker.Internet.UserName(),
            Password = Passwords.ValidStrong,
            ConfirmPassword = Passwords.ValidStrong
        };
    }

    /// <summary>
    /// Zayýf þifreye sahip RegisterDto oluþturur.
    /// 
    /// GÜVENLÝK TESTÝ:
    /// Password strength validation bypass denemesi.
    /// </summary>
    public static RegisterDto CreateRegisterDtoWithWeakPassword()
    {
        return new RegisterDto
        {
            Email = Faker.Internet.Email().ToLower(),
            Username = Faker.Internet.UserName(),
            Password = Passwords.WeakLowercase, // Sadece küçük harf
            ConfirmPassword = Passwords.WeakLowercase
        };
    }

    /// <summary>
    /// Þifre ve confirm password uyumsuz RegisterDto oluþturur.
    /// 
    /// GÜVENLÝK TESTÝ:
    /// Password confirmation validation bypass denemesi.
    /// </summary>
    public static RegisterDto CreateRegisterDtoWithMismatchedPasswords()
    {
        return new RegisterDto
        {
            Email = Faker.Internet.Email().ToLower(),
            Username = Faker.Internet.UserName(),
            Password = Passwords.ValidStrong,
            ConfirmPassword = "DifferentPassword123!" // Farklý þifre
        };
    }

    /// <summary>
    /// SQL Injection payload içeren RegisterDto oluþturur.
    /// 
    /// GÜVENLÝK TESTÝ (PENETRATION):
    /// SQL Injection saldýrý denemesi.
    /// Sistem bunu engellemeli (parameterized queries).
    /// </summary>
    public static RegisterDto CreateRegisterDtoWithSqlInjection()
    {
        return new RegisterDto
        {
            Email = Emails.SqlInjection, // ' OR '1'='1@mail.com
            Username = Usernames.SqlInjection, // admin' OR '1'='1
            Password = Passwords.ValidStrong,
            ConfirmPassword = Passwords.ValidStrong
        };
    }

    /// <summary>
    /// XSS payload içeren RegisterDto oluþturur.
    /// 
    /// GÜVENLÝK TESTÝ (PENETRATION):
    /// Cross-Site Scripting saldýrý denemesi.
    /// Sistem bunu sanitize etmeli (HTML encoding).
    /// </summary>
    public static RegisterDto CreateRegisterDtoWithXssPayload()
    {
        return new RegisterDto
        {
            Email = Faker.Internet.Email().ToLower(),
            Username = Usernames.XssPayload, // <script>alert('XSS')</script>
            Password = Passwords.ValidStrong,
            ConfirmPassword = Passwords.ValidStrong
        };
    }

    /// <summary>
    /// Maksimum uzunluðu aþan email ile RegisterDto oluþturur.
    /// 
    /// GÜVENLÝK TESTÝ (BOUNDARY):
    /// MaxLength validation bypass denemesi.
    /// Sistem 256 karakteri aþan email'i reddetmeli.
    /// </summary>
    public static RegisterDto CreateRegisterDtoWithTooLongEmail()
    {
        return new RegisterDto
        {
            Email = Emails.TooLong, // 260 chars
            Username = Faker.Internet.UserName(),
            Password = Passwords.ValidStrong,
            ConfirmPassword = Passwords.ValidStrong
        };
    }

    /// <summary>
    /// Maksimum uzunluðu aþan username ile RegisterDto oluþturur.
    /// 
    /// GÜVENLÝK TESTÝ (BOUNDARY):
    /// MaxLength validation bypass denemesi.
    /// Sistem 50 karakteri aþan username'i reddetmeli.
    /// </summary>
    public static RegisterDto CreateRegisterDtoWithTooLongUsername()
    {
        return new RegisterDto
        {
            Email = Faker.Internet.Email().ToLower(),
            Username = Usernames.TooLong, // 51 chars
            Password = Passwords.ValidStrong,
            ConfirmPassword = Passwords.ValidStrong
        };
    }

    /// <summary>
    /// Boþ alanlarla RegisterDto oluþturur.
    /// 
    /// GÜVENLÝK TESTÝ (VALIDATION):
    /// Required field validation bypass denemesi.
    /// Sistem boþ alanlarý reddetmeli.
    /// </summary>
    public static RegisterDto CreateRegisterDtoWithEmptyFields()
    {
        return new RegisterDto
        {
            Email = string.Empty,
            Username = string.Empty,
            Password = string.Empty,
            ConfirmPassword = string.Empty
        };
    }

    /// <summary>
    /// Null alanlarla RegisterDto oluþturur.
    /// 
    /// GÜVENLÝK TESTÝ (VALIDATION):
    /// Null reference exception denemesi.
    /// Sistem null kontrolü yapmalý.
    /// </summary>
    public static RegisterDto CreateRegisterDtoWithNullFields()
    {
        return new RegisterDto
        {
            Email = null!,
            Username = null!,
            Password = null!,
            ConfirmPassword = null!
        };
    }

    /// <summary>
    /// Yanlýþ þifre ile LoginDto oluþturur.
    /// 
    /// GÜVENLÝK TESTÝ:
    /// Brute force protection testi.
    /// Sistem 5 yanlýþ denemeden sonra hesabý kilitlemeli.
    /// </summary>
    public static LoginDto CreateLoginDtoWithWrongPassword(string email = Emails.ValidTest)
    {
        return new LoginDto
        {
            Email = email,
            Password = "WrongPassword123!", // Yanlýþ þifre
            RememberMe = false
        };
    }

    // ============================================================================
    // UTILITY METHODS
    // ============================================================================

    /// <summary>
    /// Rastgele bir Guid oluþturur.
    /// Test ID'leri için kullanýlýr.
    /// </summary>
    public static Guid CreateRandomGuid() => Guid.NewGuid();

    /// <summary>
    /// Var olmayan (non-existent) bir Guid oluþturur.
    /// "Not found" testleri için kullanýlýr.
    /// </summary>
    public static Guid CreateNonExistentGuid() => Guid.NewGuid();

    /// <summary>
    /// BCrypt hash'lenmiþ þifre oluþturur.
    /// Test seed data için kullanýlýr.
    /// </summary>
    /// <param name="plainPassword">Plain-text þifre.</param>
    /// <returns>BCrypt hash.</returns>
    public static string HashPassword(string plainPassword)
    {
        return BCrypt.Net.BCrypt.HashPassword(plainPassword);
    }

    /// <summary>
    /// Þifre doðrulama (verify) iþlemi.
    /// Test assertion'larýnda kullanýlýr.
    /// </summary>
    /// <param name="plainPassword">Plain-text þifre.</param>
    /// <param name="hashedPassword">Hash'lenmiþ þifre.</param>
    /// <returns>true ise þifre doðru.</returns>
    public static bool VerifyPassword(string plainPassword, string hashedPassword)
    {
        return BCrypt.Net.BCrypt.Verify(plainPassword, hashedPassword);
    }
}