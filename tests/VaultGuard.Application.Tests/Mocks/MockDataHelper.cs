using System;
using VaultGuard.Application.DTOs.Users; // Sonuna .Users ekledik
using VaultGuard.Domain.Entities;

namespace VaultGuard.Application.Tests.Common;

/// <summary>
/// Test verileri üretmek için merkezi veri fabrikası.
/// 
/// AMAÇ:
/// - Gerçekçi test verileri üretmek
/// - Test verilerini merkezi bir yerden yönetmek
/// - Test senaryolarında veri tutarlılığı sağlamak
/// 
/// GÜVENLİK:
/// Test verileri gerçek production verileri gibi validation'lardan geçmelidir.
/// </summary>
public static class MockDataHelper
{
    // ============================================================================
    // USER ENTITY FACTORY
    // ============================================================================

    /// <summary>
    /// Varsayılan test kullanıcısı oluşturur.
    /// Tüm validation kurallarını geçen gerçekçi bir kullanıcı döner.
    /// </summary>
    public static User CreateValidUser()
    {
        return User.Create(
            email: "test@vaultguard.com",
            username: "testuser",
            passwordHash: "hashed_password_12345678901234567890", // Min 20 karakter
            role: "User");
    }

    /// <summary>
    /// Admin rolüne sahip test kullanıcısı oluşturur.
    /// </summary>
    public static User CreateAdminUser()
    {
        return User.Create(
            email: "admin@vaultguard.com",
            username: "adminuser",
            passwordHash: "hashed_admin_password_1234567890",
            role: "Admin");
    }

    /// <summary>
    /// Deaktif (IsActive=false) test kullanıcısı oluşturur.
    /// 
    /// GÜVENLİK TESLERİ İÇİN:
    /// Login testlerinde deaktif kullanıcıların engellendiğini test etmek için.
    /// </summary>
    public static User CreateInactiveUser()
    {
        var user = User.Create(
            email: "inactive@vaultguard.com",
            username: "inactiveuser",
            passwordHash: "hashed_password_12345678901234567890",
            role: "User");

        user.Deactivate();
        return user;
    }

    /// <summary>
    /// Özel parametrelerle kullanıcı oluşturur.
    /// Test senaryolarında özelleştirilmiş veriler için.
    /// </summary>
    public static User CreateUser(
        string email,
        string username,
        string passwordHash,
        string role = "User")
    {
        return User.Create(email, username, passwordHash, role);
    }

    // ============================================================================
    // USER DTO FACTORY
    // ============================================================================

    /// <summary>
    /// User entity'sinden UserDto oluşturur.
    /// Service'lerin döndüğü DTO yapısını simüle eder.
    /// 
    /// GÜVENLİK:
    /// PasswordHash ASLA DTO'ya dahil edilmez!
    /// </summary>
    public static UserDto ToDto(User user)
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

    /// <summary>
    /// Varsayılan UserDto oluşturur.
    /// </summary>
    public static UserDto CreateValidUserDto()
    {
        var user = CreateValidUser();
        return ToDto(user);
    }

    // ============================================================================
    // TEST DATA CONSTANTS
    // ============================================================================

    /// <summary>
    /// Test senaryolarında kullanılacak sabit değerler.
    /// </summary>
    public static class Constants
    {
        // Email'ler
        public const string ValidEmail = "test@vaultguard.com";
        public const string InvalidEmail = "invalid-email";
        public const string NonExistentEmail = "notfound@vaultguard.com";

        // Username'ler
        public const string ValidUsername = "testuser";
        public const string InvalidUsername = "ab"; // Çok kısa (min 3 karakter)
        public const string NonExistentUsername = "notfounduser";

        // Şifreler
        public const string ValidPassword = "Test123!@#";
        public const string InvalidPassword = "123"; // Çok kısa
        public const string WrongPassword = "WrongPass123!";

        // Hash'ler
        public const string ValidPasswordHash = "hashed_password_12345678901234567890";

        // Roller
        public const string RoleUser = "User";
        public const string RoleAdmin = "Admin";
        public const string RoleAuditor = "Auditor";
        public const string InvalidRole = "InvalidRole";

        // Generic mesajlar (User Enumeration Prevention için)
        public const string GenericLoginError = "Email veya şifre hatalı";
        public const string GenericRegisterError = "Kayıt işlemi başarısız oldu";
    }

    // ============================================================================
    // TIMING ATTACK TEST HELPERS
    // ============================================================================

    /// <summary>
    /// İki işlemin süresini karşılaştırır.
    /// Timing attack testleri için kullanılır.
    /// 
    /// GÜVENLİK:
    /// Mevcut kullanıcı vs olmayan kullanıcı login süresi aynı olmalı.
    /// Aksi halde saldırgan hangi email'lerin sistemde olduğunu anlayabilir.
    /// </summary>
    /// <param name="action">Test edilecek işlem</param>
    /// <returns>İşlem süresi (millisaniye)</returns>
    public static long MeasureExecutionTime(Action action)
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        action();
        watch.Stop();
        return watch.ElapsedMilliseconds;
    }

    /// <summary>
    /// Async işlemin süresini ölçer.
    /// </summary>
    public static async System.Threading.Tasks.Task<long> MeasureExecutionTimeAsync(
        Func<System.Threading.Tasks.Task> asyncAction)
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        await asyncAction();
        watch.Stop();
        return watch.ElapsedMilliseconds;
    }

    // ============================================================================
    // BOUNDARY TEST DATA
    // ============================================================================

    /// <summary>
    /// Boundary (sınır) testleri için uç case'ler.
    /// Buffer overflow ve validation bypass testleri için.
    /// </summary>
    public static class BoundaryTestData
    {
        // Boş ve null değerler
        public const string EmptyString = "";
        public const string WhitespaceString = "   ";
        public static readonly string? NullString = null;

        // Çok uzun değerler (Buffer overflow testi)
        public static readonly string LongEmail = new string('a', 255) + "@test.com"; // Max 254 karakter
        public static readonly string LongUsername = new string('a', 51); // Max 50 karakter
        public static readonly string LongPassword = new string('a', 1000);

        // SQL Injection denemeleri
        public const string SqlInjectionAttempt = "'; DROP TABLE Users; --";
        public const string XssAttempt = "<script>alert('XSS')</script>";

        // Special characters
        public const string SpecialCharsEmail = "test+tag@domain.co.uk";
        public const string UnicodeUsername = "用户名"; // Unicode karakterler
    }
}