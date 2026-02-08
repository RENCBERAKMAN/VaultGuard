using System;
using System.Threading;
using VaultGuard.Domain.Entities;

namespace VaultGuard.Domain.Tests.Entities;

/// <summary>
/// User entity için kapsamlý unit test'ler.
/// AAA (Arrange-Act-Assert) pattern kullanýlmýþtýr.
/// </summary>
public class UserTests
{
    // ============================================================================
    // CREATE METHOD TESTS
    // ============================================================================

    [Fact]
    public void Create_WithValidData_ShouldCreateUserSuccessfully()
    {
        // Arrange
        var email = "test@vaultguard.com";
        var passwordHash = "HashedPassword123456789012345"; // 20+ karakter
        var role = "User";

        // Act
        var user = User.Create(email, passwordHash, role);

        // Assert
        Assert.NotNull(user);
        Assert.NotEqual(Guid.Empty, user.Id);
        Assert.Equal("test@vaultguard.com", user.Email); // Normalized (lowercase)
        Assert.Equal(passwordHash, user.PasswordHash);
        Assert.Equal(role, user.Role);
        Assert.True(user.IsActive);
        Assert.Null(user.LastLoginAt); // Henüz giriþ yapýlmamýþ
        Assert.True((DateTime.UtcNow - user.CreatedAt).TotalSeconds < 1); // Az önce oluþturuldu
    }

    [Fact]
    public void Create_WithUppercaseEmail_ShouldNormalizeToLowercase()
    {
        // Arrange
        var email = "TEST@VAULTGUARD.COM";
        var passwordHash = "HashedPassword123456789012345";

        // Act
        var user = User.Create(email, passwordHash);

        // Assert
        Assert.Equal("test@vaultguard.com", user.Email);
    }

    [Fact]
    public void Create_WithEmailContainingWhitespace_ShouldTrimWhitespace()
    {
        // Arrange
        var email = "  test@vaultguard.com  ";
        var passwordHash = "HashedPassword123456789012345";

        // Act
        var user = User.Create(email, passwordHash);

        // Assert
        Assert.Equal("test@vaultguard.com", user.Email);
        Assert.DoesNotContain(" ", user.Email);
    }

    [Fact]
    public void Create_WithDefaultRole_ShouldSetRoleToUser()
    {
        // Arrange
        var email = "test@vaultguard.com";
        var passwordHash = "HashedPassword123456789012345";

        // Act
        var user = User.Create(email, passwordHash); // Role parametresi verilmedi

        // Assert
        Assert.Equal("User", user.Role);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Create_WithEmptyOrWhitespaceEmail_ShouldThrowArgumentException(string invalidEmail)
    {
        // Arrange
        var passwordHash = "HashedPassword123456789012345";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            User.Create(invalidEmail, passwordHash));

        Assert.Equal("email", exception.ParamName);
        Assert.Contains("cannot be empty", exception.Message);
    }

    [Theory]
    [InlineData("notanemail")]           // @ yok
    [InlineData("missing@domain")]       // . yok
    [InlineData("@nodomain.com")]        // Local part yok
    [InlineData("noat.com")]             // @ yok
    public void Create_WithInvalidEmailFormat_ShouldThrowArgumentException(string invalidEmail)
    {
        // Arrange
        var passwordHash = "HashedPassword123456789012345";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            User.Create(invalidEmail, passwordHash));

        Assert.Equal("email", exception.ParamName);
        Assert.Contains("Invalid email format", exception.Message);
    }

    [Fact]
    public void Create_WithEmailLongerThan254Characters_ShouldThrowArgumentException()
    {
        // Arrange
        var longEmail = new string('a', 250) + "@test.com"; // 260 karakter
        var passwordHash = "HashedPassword123456789012345";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            User.Create(longEmail, passwordHash));

        Assert.Equal("email", exception.ParamName);
        Assert.Contains("too long", exception.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Create_WithEmptyOrWhitespacePasswordHash_ShouldThrowArgumentException(string invalidHash)
    {
        // Arrange
        var email = "test@vaultguard.com";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            User.Create(email, invalidHash));

        Assert.Equal("passwordHash", exception.ParamName);
        Assert.Contains("cannot be empty", exception.Message);
    }

    [Fact]
    public void Create_WithShortPasswordHash_ShouldThrowArgumentException()
    {
        // Arrange
        var email = "test@vaultguard.com";
        var shortHash = "short"; // 20 karakterden kýsa

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            User.Create(email, shortHash));

        Assert.Equal("passwordHash", exception.ParamName);
        Assert.Contains("Invalid password hash", exception.Message);
        Assert.Contains("hashed password, not plain-text", exception.Message);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void Create_WithEmptyOrWhitespaceRole_ShouldThrowArgumentException(string invalidRole)
    {
        // Arrange
        var email = "test@vaultguard.com";
        var passwordHash = "HashedPassword123456789012345";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            User.Create(email, passwordHash, invalidRole));

        Assert.Equal("role", exception.ParamName);
        Assert.Contains("cannot be empty", exception.Message);
    }

    [Theory]
    [InlineData("InvalidRole")]
    [InlineData("SuperAdmin")]
    [InlineData("Guest")]
    public void Create_WithInvalidRole_ShouldThrowArgumentException(string invalidRole)
    {
        // Arrange
        var email = "test@vaultguard.com";
        var passwordHash = "HashedPassword123456789012345";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            User.Create(email, passwordHash, invalidRole));

        Assert.Equal("role", exception.ParamName);
        Assert.Contains("Invalid role", exception.Message);
        Assert.Contains("Valid roles:", exception.Message);
    }

    [Theory]
    [InlineData("Admin")]
    [InlineData("User")]
    [InlineData("Auditor")]
    [InlineData("admin")]      // Case-insensitive
    [InlineData("USER")]       // Case-insensitive
    [InlineData("AuDiToR")]    // Case-insensitive
    public void Create_WithValidRole_ShouldCreateUserSuccessfully(string validRole)
    {
        // Arrange
        var email = "test@vaultguard.com";
        var passwordHash = "HashedPassword123456789012345";

        // Act
        var user = User.Create(email, passwordHash, validRole);

        // Assert
        Assert.NotNull(user);
        Assert.Equal(validRole, user.Role);
    }

    // ============================================================================
    // UPDATE EMAIL TESTS
    // ============================================================================

    [Fact]
    public void UpdateEmail_WithValidEmail_ShouldUpdateSuccessfully()
    {
        // Arrange
        var user = User.Create("old@vaultguard.com", "HashedPassword123456789012345");
        var newEmail = "new@vaultguard.com";

        // Act
        user.UpdateEmail(newEmail);

        // Assert
        Assert.Equal("new@vaultguard.com", user.Email);
    }

    [Fact]
    public void UpdateEmail_WithUppercaseEmail_ShouldNormalizeToLowercase()
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345");

        // Act
        user.UpdateEmail("NEW@VAULTGUARD.COM");

        // Assert
        Assert.Equal("new@vaultguard.com", user.Email);
    }

    [Fact]
    public void UpdateEmail_WithEmailContainingWhitespace_ShouldTrimWhitespace()
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345");

        // Act
        user.UpdateEmail("  new@vaultguard.com  ");

        // Assert
        Assert.Equal("new@vaultguard.com", user.Email);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void UpdateEmail_WithEmptyOrWhitespaceEmail_ShouldThrowArgumentException(string invalidEmail)
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345");

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            user.UpdateEmail(invalidEmail));

        Assert.Equal("newEmail", exception.ParamName);
    }

    [Theory]
    [InlineData("notanemail")]
    [InlineData("missing@domain")]
    public void UpdateEmail_WithInvalidEmailFormat_ShouldThrowArgumentException(string invalidEmail)
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345");

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            user.UpdateEmail(invalidEmail));

        Assert.Equal("newEmail", exception.ParamName);
        Assert.Contains("Invalid email format", exception.Message);
    }

    // ============================================================================
    // CHANGE PASSWORD TESTS
    // ============================================================================

    [Fact]
    public void ChangePassword_WithValidPasswordHash_ShouldUpdateSuccessfully()
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "OldHashedPassword12345678901234");
        var newPasswordHash = "NewHashedPassword12345678901234";

        // Act
        user.ChangePassword(newPasswordHash);

        // Assert
        Assert.Equal(newPasswordHash, user.PasswordHash);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void ChangePassword_WithEmptyOrWhitespaceHash_ShouldThrowArgumentException(string invalidHash)
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345");

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            user.ChangePassword(invalidHash));

        Assert.Equal("newPasswordHash", exception.ParamName);
    }

    [Fact]
    public void ChangePassword_WithShortHash_ShouldThrowArgumentException()
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345");

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            user.ChangePassword("short"));

        Assert.Equal("newPasswordHash", exception.ParamName);
        Assert.Contains("hashed password, not plain-text", exception.Message);
    }

    // ============================================================================
    // CHANGE ROLE TESTS
    // ============================================================================

    [Theory]
    [InlineData("Admin")]
    [InlineData("User")]
    [InlineData("Auditor")]
    public void ChangeRole_WithValidRole_ShouldUpdateSuccessfully(string newRole)
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345", "User");

        // Act
        user.ChangeRole(newRole);

        // Assert
        Assert.Equal(newRole, user.Role);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void ChangeRole_WithEmptyOrWhitespaceRole_ShouldThrowArgumentException(string invalidRole)
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345");

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            user.ChangeRole(invalidRole));

        Assert.Equal("newRole", exception.ParamName);
    }

    [Theory]
    [InlineData("InvalidRole")]
    [InlineData("SuperAdmin")]
    public void ChangeRole_WithInvalidRole_ShouldThrowArgumentException(string invalidRole)
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345");

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            user.ChangeRole(invalidRole));

        Assert.Equal("newRole", exception.ParamName);
        Assert.Contains("Invalid role", exception.Message);
    }

    // ============================================================================
    // ACTIVATE / DEACTIVATE TESTS
    // ============================================================================

    [Fact]
    public void Deactivate_ShouldSetIsActiveToFalse()
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345");
        Assert.True(user.IsActive); // Baþlangýçta aktif

        // Act
        user.Deactivate();

        // Assert
        Assert.False(user.IsActive);
    }

    [Fact]
    public void Activate_ShouldSetIsActiveToTrue()
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345");
        user.Deactivate(); // Önce deaktif et
        Assert.False(user.IsActive);

        // Act
        user.Activate();

        // Assert
        Assert.True(user.IsActive);
    }

    // ============================================================================
    // RECORD LOGIN TESTS
    // ============================================================================

    [Fact]
    public void RecordLogin_ShouldUpdateLastLoginAt()
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345");
        Assert.Null(user.LastLoginAt); // Baþlangýçta null

        // Act
        user.RecordLogin();

        // Assert
        Assert.NotNull(user.LastLoginAt);
        Assert.True((DateTime.UtcNow - user.LastLoginAt.Value).TotalSeconds < 1);
    }

    [Fact]
    public void RecordLogin_CalledTwice_ShouldUpdateToLatestTime()
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345");
        user.RecordLogin();
        var firstLoginTime = user.LastLoginAt;

        // Act
        Thread.Sleep(100); // 100ms bekle
        user.RecordLogin();

        // Assert
        Assert.NotNull(user.LastLoginAt);
        Assert.True(user.LastLoginAt > firstLoginTime);
    }

    // ============================================================================
    // IS ADMIN TESTS
    // ============================================================================

    [Fact]
    public void IsAdmin_WhenRoleIsAdmin_ShouldReturnTrue()
    {
        // Arrange
        var user = User.Create("admin@vaultguard.com", "HashedPassword123456789012345", "Admin");

        // Act
        var isAdmin = user.IsAdmin();

        // Assert
        Assert.True(isAdmin);
    }

    [Theory]
    [InlineData("User")]
    [InlineData("Auditor")]
    public void IsAdmin_WhenRoleIsNotAdmin_ShouldReturnFalse(string role)
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345", role);

        // Act
        var isAdmin = user.IsAdmin();

        // Assert
        Assert.False(isAdmin);
    }

    [Fact]
    public void IsAdmin_ShouldBeCaseInsensitive()
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345", "admin");

        // Act
        var isAdmin = user.IsAdmin();

        // Assert
        Assert.True(isAdmin); // Küçük harf "admin" de geçerli
    }

    // ============================================================================
    // CAN LOGIN TESTS
    // ============================================================================

    [Fact]
    public void CanLogin_WhenUserIsActive_ShouldReturnTrue()
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345");

        // Act
        var canLogin = user.CanLogin();

        // Assert
        Assert.True(canLogin);
    }

    [Fact]
    public void CanLogin_WhenUserIsDeactivated_ShouldReturnFalse()
    {
        // Arrange
        var user = User.Create("test@vaultguard.com", "HashedPassword123456789012345");
        user.Deactivate();

        // Act
        var canLogin = user.CanLogin();

        // Assert
        Assert.False(canLogin);
    }
}