using System;
using System.Linq;

namespace VaultGuard.Domain.Entities;

/// <summary>
/// Kullanýcý varlýðýný temsil eder.
/// Sealed olarak tanýmlanmýþtýr çünkü kullanýcý varlýðýnýn domain kurallarý korunmalýdýr.
/// Geniþletme ihtiyacý durumunda kalýtým yerine composition pattern kullanýlmalýdýr.
/// </summary>
public sealed class User
{
    /// <summary>
    /// Benzersiz kullanýcý kimliði (Primary Key).
    /// init kullanýlarak oluþturulduktan sonra deðiþtirilemez hale getirilmiþtir.
    /// Guid tercih edilmiþtir çünkü distributed sistemlerde çakýþma riski yoktur.
    /// </summary>
    public Guid Id { get; init; }

    /// <summary>
    /// Kullanýcýnýn e-posta adresi (benzersiz olmalýdýr).
    /// private set ile sadece iþ metodlarý üzerinden deðiþtirilebilir.
    /// Normalizasyon: Her zaman küçük harf ve trim edilmiþ olarak saklanýr.
    /// Maksimum uzunluk: 254 karakter (RFC 5321 standardý)
    /// </summary>
    public string Email { get; private set; } = string.Empty;

    /// <summary>
    /// Kullanýcý adý (benzersiz olmalýdýr).
    /// private set ile sadece iþ metodlarý üzerinden deðiþtirilebilir.
    /// Kullaným alanlarý:
    /// 1. Kullanýcý dostu giriþ (email yerine username ile login)
    /// 2. Profil görüntüleme (@username formatýnda)
    /// 3. Mention sistemi (sosyal özellikler için)
    /// Maksimum uzunluk: 50 karakter
    /// </summary>
    public string Username { get; private set; } = string.Empty;

    /// <summary>
    /// Kullanýcýnýn hashlenmiþ þifresi.
    /// Güvenlik kritik: Asla plain-text þifre saklanmaz!
    /// Hash algoritmasý: BCrypt veya Argon2 (Infrastructure katmanýnda uygulanýr)
    /// private set ile sadece iþ metodlarý üzerinden deðiþtirilebilir.
    /// </summary>
    public string PasswordHash { get; private set; } = string.Empty;

    /// <summary>
    /// Kullanýcýnýn sistem rolü.
    /// Geçerli deðerler: "Admin", "User", "Auditor"
    /// NOT: Gelecekte UserRole enum'ýna dönüþtürülmesi önerilir (yazým hatalarýný engeller).
    /// Varsayýlan deðer: "User"
    /// </summary>
    public string Role { get; private set; } = "User";

    /// <summary>
    /// Kullanýcýnýn sisteme kaydolduðu tarih ve saat (UTC).
    /// init kullanýlarak oluþturulduktan sonra deðiþtirilemez.
    /// Audit trail ve compliance için kritik öneme sahiptir.
    /// </summary>
    public DateTime CreatedAt { get; init; }

    /// <summary>
    /// Kullanýcýnýn hesabýnýn aktif olup olmadýðýný belirtir.
    /// false ise kullanýcý sisteme giriþ yapamaz.
    /// Kullaným senaryolarý:
    /// - Hesap askýya alma
    /// - Geçici eriþim engelleme
    /// - Silme yerine soft-delete (GDPR uyumlu)
    /// </summary>
    public bool IsActive { get; private set; } = true;

    /// <summary>
    /// Kullanýcýnýn son giriþ yaptýðý tarih (UTC).
    /// Nullable olmasýnýn nedeni: Ýlk oluþturulduðunda henüz giriþ yapýlmamýþtýr.
    /// Kullaným alanlarý:
    /// 1. Güvenlik: Anormal aktivite tespiti
    /// 2. Compliance: Audit raporlarý
    /// 3. UX: "Hoþ geldin, 3 gün önce giriþ yaptýn" mesajlarý
    /// </summary>
    public DateTime? LastLoginAt { get; private set; }

    // ============================================================================
    // CONSTRUCTORS
    // ============================================================================

    /// <summary>
    /// Private parameterless constructor.
    /// EF Core tarafýndan entity'leri veritabanýndan yüklerken kullanýlýr.
    /// Ýþ mantýðýnda kullanýlmamalýdýr; bunun yerine static factory method (Create) kullanýlýr.
    /// </summary>
    private User()
    {
        // EF Core için gerekli
    }

    /// <summary>
    /// Yeni bir kullanýcý oluþturmak için static factory method.
    /// Bu pattern kullanýlmasýnýn nedenleri:
    /// 1. Validation logic'i merkezi bir yerde toplanýr
    /// 2. Invalid state'te obje oluþturulmasý engellenir
    /// 3. Constructor overload kargaþasý önlenir
    /// 4. Domain events tetiklenebilir (ileride)
    /// </summary>
    /// <param name="email">Kullanýcýnýn e-posta adresi (benzersiz olmalý)</param>
    /// <param name="username">Kullanýcý adý (benzersiz olmalý)</param>
    /// <param name="passwordHash">Hashlenmiþ þifre (plain-text deðil!)</param>
    /// <param name="role">Kullanýcý rolü (varsayýlan: "User")</param>
    /// <returns>Yeni User instance'ý</returns>
    /// <exception cref="ArgumentException">Parametreler geçersizse fýrlatýlýr</exception>
    public static User Create(
        string email,
        string username,
        string passwordHash,
        string role = "User")
    {
        // Email validation
        if (string.IsNullOrWhiteSpace(email))
            throw new ArgumentException("Email cannot be empty.", nameof(email));

        // Email normalizasyonu
        var normalizedEmail = email.Trim().ToLower();

        // Email format kontrolü (Geliþtirilmiþ versiyon)
        if (!normalizedEmail.Contains('@') ||
            !normalizedEmail.Contains('.') ||
            normalizedEmail.StartsWith('@') ||
            normalizedEmail.EndsWith('.'))
        {
            throw new ArgumentException("Invalid email format.", nameof(email));
        }

        // Email uzunluk kontrolü (RFC 5321)
        if (normalizedEmail.Length > 254)
            throw new ArgumentException("Email is too long (max 254 characters).", nameof(email));

        // Username validation
        if (string.IsNullOrWhiteSpace(username))
            throw new ArgumentException("Username cannot be empty.", nameof(username));

        var trimmedUsername = username.Trim();

        // Username uzunluk kontrolü
        if (trimmedUsername.Length < 3)
            throw new ArgumentException("Username must be at least 3 characters.", nameof(username));

        if (trimmedUsername.Length > 50)
            throw new ArgumentException("Username is too long (max 50 characters).", nameof(username));

        // Username format kontrolü (sadece alfanumerik ve alt çizgi)
        if (!System.Text.RegularExpressions.Regex.IsMatch(trimmedUsername, @"^[a-zA-Z0-9_]+$"))
            throw new ArgumentException(
                "Username can only contain letters, numbers, and underscores.",
                nameof(username));

        // PasswordHash validation
        if (string.IsNullOrWhiteSpace(passwordHash))
            throw new ArgumentException("Password hash cannot be empty.", nameof(passwordHash));

        // PasswordHash minimum uzunluk kontrolü (BCrypt hash'i minimum 60 karakter)
        if (passwordHash.Length < 20)
            throw new ArgumentException(
                "Invalid password hash. Ensure you're passing a hashed password, not plain-text.",
                nameof(passwordHash));

        // Role validation
        if (string.IsNullOrWhiteSpace(role))
            throw new ArgumentException("Role cannot be empty.", nameof(role));

        // Role deðerleri kontrol (Domain'de sabit kalabilir veya enum'a dönüþtürülebilir)
        var validRoles = new[] { "Admin", "User", "Auditor" };
        if (!validRoles.Contains(role, StringComparer.OrdinalIgnoreCase))
            throw new ArgumentException(
                $"Invalid role. Valid roles: {string.Join(", ", validRoles)}",
                nameof(role));

        return new User
        {
            Id = Guid.NewGuid(),
            Email = normalizedEmail,
            Username = trimmedUsername,
            PasswordHash = passwordHash,
            Role = role,
            CreatedAt = DateTime.UtcNow,
            IsActive = true,
            LastLoginAt = null // Henüz giriþ yapýlmadý
        };
    }

    // ============================================================================
    // BUSINESS METHODS
    // ============================================================================

    /// <summary>
    /// Kullanýcýnýn e-posta adresini günceller.
    /// Domain event tetiklenebilir: EmailChangedEvent (ileride)
    /// </summary>
    /// <param name="newEmail">Yeni e-posta adresi</param>
    /// <exception cref="ArgumentException">Geçersiz e-posta formatý</exception>
    public void UpdateEmail(string newEmail)
    {
        if (string.IsNullOrWhiteSpace(newEmail))
            throw new ArgumentException("Email cannot be empty.", nameof(newEmail));

        var normalizedEmail = newEmail.Trim().ToLower();

        if (!normalizedEmail.Contains('@') || !normalizedEmail.Contains('.'))
            throw new ArgumentException("Invalid email format.", nameof(newEmail));

        if (normalizedEmail.Length > 254)
            throw new ArgumentException("Email is too long (max 254 characters).", nameof(newEmail));

        Email = normalizedEmail;

        // TODO: Domain Event - EmailChangedEvent
    }

    /// <summary>
    /// Kullanýcý adýný günceller.
    /// Domain event tetiklenebilir: UsernameChangedEvent (ileride)
    /// </summary>
    /// <param name="newUsername">Yeni kullanýcý adý</param>
    /// <exception cref="ArgumentException">Geçersiz username formatý</exception>
    public void UpdateUsername(string newUsername)
    {
        if (string.IsNullOrWhiteSpace(newUsername))
            throw new ArgumentException("Username cannot be empty.", nameof(newUsername));

        var trimmedUsername = newUsername.Trim();

        if (trimmedUsername.Length < 3)
            throw new ArgumentException("Username must be at least 3 characters.", nameof(newUsername));

        if (trimmedUsername.Length > 50)
            throw new ArgumentException("Username is too long (max 50 characters).", nameof(newUsername));

        if (!System.Text.RegularExpressions.Regex.IsMatch(trimmedUsername, @"^[a-zA-Z0-9_]+$"))
            throw new ArgumentException(
                "Username can only contain letters, numbers, and underscores.",
                nameof(newUsername));

        Username = trimmedUsername;

        // TODO: Domain Event - UsernameChangedEvent
    }

    /// <summary>
    /// Kullanýcýnýn þifresini deðiþtirir.
    /// NOT: Bu metod sadece hashlenmiþ þifre kabul eder!
    /// Plain-text þifre asla domain katmanýna girmemelidir.
    /// </summary>
    /// <param name="newPasswordHash">Yeni hashlenmiþ þifre</param>
    /// <exception cref="ArgumentException">Geçersiz password hash</exception>
    public void ChangePassword(string newPasswordHash)
    {
        if (string.IsNullOrWhiteSpace(newPasswordHash))
            throw new ArgumentException("Password hash cannot be empty.", nameof(newPasswordHash));

        if (newPasswordHash.Length < 20)
            throw new ArgumentException(
                "Invalid password hash. Ensure you're passing a hashed password, not plain-text.",
                nameof(newPasswordHash));

        PasswordHash = newPasswordHash;

        // TODO: Domain Event - PasswordChangedEvent
        // Kullanýcýya e-posta bildirimi gönderilebilir
    }

    /// <summary>
    /// Kullanýcýnýn rolünü deðiþtirir.
    /// Yetki yükseltme/düþürme iþlemleri için kullanýlýr.
    /// Sadece Admin rolündeki kullanýcýlar bu iþlemi yapabilir (Application katmanýnda kontrol edilir).
    /// </summary>
    /// <param name="newRole">Yeni rol ("Admin", "User", "Auditor")</param>
    /// <exception cref="ArgumentException">Geçersiz rol</exception>
    public void ChangeRole(string newRole)
    {
        if (string.IsNullOrWhiteSpace(newRole))
            throw new ArgumentException("Role cannot be empty.", nameof(newRole));

        var validRoles = new[] { "Admin", "User", "Auditor" };
        if (!validRoles.Contains(newRole, StringComparer.OrdinalIgnoreCase))
            throw new ArgumentException(
                $"Invalid role. Valid roles: {string.Join(", ", validRoles)}",
                nameof(newRole));

        Role = newRole;

        // TODO: Domain Event - RoleChangedEvent
    }

    /// <summary>
    /// Kullanýcýnýn hesabýný devre dýþý býrakýr.
    /// Soft-delete yaklaþýmý (GDPR uyumlu).
    /// Kullaným senaryolarý:
    /// - Admin tarafýndan hesap askýya alma
    /// - Güvenlik ihlali durumunda eriþim engelleme
    /// - Kullanýcý hesabýný silmek yerine devre dýþý býrakma
    /// </summary>
    public void Deactivate()
    {
        IsActive = false;

        // TODO: Domain Event - UserDeactivatedEvent
    }

    /// <summary>
    /// Kullanýcýnýn hesabýný yeniden aktif hale getirir.
    /// </summary>
    public void Activate()
    {
        IsActive = true;

        // TODO: Domain Event - UserActivatedEvent
    }

    /// <summary>
    /// Kullanýcýnýn son giriþ zamanýný günceller.
    /// Her baþarýlý login iþleminde çaðrýlmalýdýr.
    /// </summary>
    public void RecordLogin()
    {
        LastLoginAt = DateTime.UtcNow;

        // TODO: Domain Event - UserLoggedInEvent
        // Güvenlik: Anormal lokasyon/IP tespiti için kullanýlabilir
    }

    /// <summary>
    /// Kullanýcýnýn son giriþ zamanýný belirli bir deðere ayarlar.
    /// Test ve migration senaryolarý için kullanýlýr.
    /// </summary>
    /// <param name="loginTime">Ayarlanacak giriþ zamaný</param>
    public void UpdateLastLogin(DateTime loginTime)
    {
        LastLoginAt = loginTime;
    }

    /// <summary>
    /// Kullanýcýnýn Admin rolünde olup olmadýðýný kontrol eder.
    /// </summary>
    /// <returns>Admin ise true, deðilse false</returns>
    public bool IsAdmin()
    {
        return Role.Equals("Admin", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Kullanýcýnýn hesabýnýn aktif olup olmadýðýný ve giriþ yapýp yapamayacaðýný kontrol eder.
    /// </summary>
    /// <returns>Aktif ise true, deðilse false</returns>
    public bool CanLogin()
    {
        return IsActive;
    }
}