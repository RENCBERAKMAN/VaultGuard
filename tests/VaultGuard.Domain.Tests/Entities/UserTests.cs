using System;
using VaultGuard.Domain.Entities;
using Xunit;

namespace VaultGuard.Domain.Tests.Entities;

public class UserTests
{
    // ============================================================================
    // TEST 1: Baþarýlý User Oluþturma
    // ============================================================================
    [Fact]
    public void Create_WithValidParameters_ShouldCreateUser()
    {
        // Arrange - Test verilerini hazýrla
        var email = "test@vaultguard.com";
        var username = "testuser";
        var passwordHash = "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1";
        var role = "User";

        // Act - Test edilen metodu çalýþtýr
        var user = User.Create(email, username, passwordHash, role);

        // Assert - Sonuçlarý doðrula
        Assert.NotNull(user);
        Assert.Equal(email, user.Email);
        Assert.Equal(username, user.Username);
        Assert.Equal(passwordHash, user.PasswordHash);
        Assert.Equal(role, user.Role);
        Assert.NotEqual(Guid.Empty, user.Id);
        Assert.True(user.CreatedAt <= DateTime.UtcNow);
        Assert.Null(user.LastLoginAt);
        Assert.True(user.IsActive);
    }

    // ============================================================================
    // TEST 2: Varsayýlan Role ile User Oluþturma
    // ============================================================================
    [Fact]
    public void Create_WithoutRole_ShouldUseDefaultUserRole()
    {
        // Arrange
        var email = "admin@vaultguard.com";
        var username = "adminuser";
        var passwordHash = "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1";

        // Act - Role parametresi verilmeden çaðýr
        var user = User.Create(email, username, passwordHash);

        // Assert - Varsayýlan role "User" olmalý
        Assert.Equal("User", user.Role);
    }

    // ============================================================================
    // TEST 3: Email Validation
    // ============================================================================
    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("   ")]
    public void Create_WithInvalidEmail_ShouldThrowArgumentException(string? invalidEmail)
    {
        // Arrange
        var username = "testuser";
        var passwordHash = "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            User.Create(invalidEmail!, username, passwordHash));

        Assert.Contains("email", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ============================================================================
    // TEST 4: Username Validation
    // ============================================================================
    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("   ")]
    public void Create_WithInvalidUsername_ShouldThrowArgumentException(string? invalidUsername)
    {
        // Arrange
        var email = "test@vaultguard.com";
        var passwordHash = "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            User.Create(email, invalidUsername!, passwordHash));

        Assert.Contains("username", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ============================================================================
    // TEST 5: Password Hash Validation
    // ============================================================================
    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("   ")]
    public void Create_WithInvalidPasswordHash_ShouldThrowArgumentException(string? invalidPasswordHash)
    {
        // Arrange
        var email = "test@vaultguard.com";
        var username = "testuser";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            User.Create(email, username, invalidPasswordHash!));

        Assert.Contains("password", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ============================================================================
    // TEST 6: Admin User Oluþturma
    // ============================================================================
    [Fact]
    public void Create_WithAdminRole_ShouldCreateAdminUser()
    {
        // Arrange
        var email = "admin@vaultguard.com";
        var username = "superadmin";
        var passwordHash = "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1";
        var role = "Admin";

        // Act
        var adminUser = User.Create(email, username, passwordHash, role);

        // Assert
        Assert.Equal("Admin", adminUser.Role);
        Assert.Equal(email, adminUser.Email);
        Assert.Equal(username, adminUser.Username);
        Assert.True(adminUser.IsActive);
    }

    // ============================================================================
    // TEST 7: User Deactivation
    // ============================================================================
    [Fact]
    public void Deactivate_ShouldSetIsActiveToFalse()
    {
        // Arrange - Aktif bir user oluþtur
        var user = User.Create(
            email: "test@vaultguard.com",
            username: "testuser",
            passwordHash: "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1");

        Assert.True(user.IsActive); // Baþlangýçta aktif olmalý

        // Act - User'ý deaktive et
        user.Deactivate();

        // Assert - IsActive false olmalý
        Assert.False(user.IsActive);
    }

    // ============================================================================
    // TEST 8: RecordLogin Method
    // ============================================================================
    [Fact]
    public void RecordLogin_ShouldSetLastLoginAtToCurrentTime()
    {
        // Arrange
        var user = User.Create(
            email: "test@vaultguard.com",
            username: "testuser",
            passwordHash: "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1");

        Assert.Null(user.LastLoginAt); // Baþlangýçta null olmalý

        var beforeLogin = DateTime.UtcNow;

        // Act
        user.RecordLogin();

        var afterLogin = DateTime.UtcNow;

        // Assert
        Assert.NotNull(user.LastLoginAt);
        Assert.InRange(user.LastLoginAt.Value, beforeLogin, afterLogin);
    }

    // ============================================================================
    // TEST 9: UpdateLastLogin Method (Yeni Test)
    // ============================================================================
    [Fact]
    public void UpdateLastLogin_ShouldSetLastLoginAtToSpecifiedTime()
    {
        // Arrange
        var user = User.Create(
            email: "test@vaultguard.com",
            username: "testuser",
            passwordHash: "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1");

        Assert.Null(user.LastLoginAt); // Baþlangýçta null olmalý

        // Act
        var specificLoginTime = new DateTime(2025, 1, 15, 10, 30, 0, DateTimeKind.Utc);
        user.UpdateLastLogin(specificLoginTime);

        // Assert
        Assert.NotNull(user.LastLoginAt);
        Assert.Equal(specificLoginTime, user.LastLoginAt.Value);
    }

    // ============================================================================
    // TEST 10: Multiple Users - Unique IDs
    // ============================================================================
    [Fact]
    public void Create_MultipleUsers_ShouldHaveUniqueIds()
    {
        // Arrange & Act
        var user1 = User.Create("user1@test.com", "user1", "hashed_password_111111");
        var user2 = User.Create("user2@test.com", "user2", "hashed_password_222222");
        var user3 = User.Create("user3@test.com", "user3", "hashed_password_333333");

        // Assert - Her user'ýn ID'si farklý olmalý
        Assert.NotEqual(user1.Id, user2.Id);
        Assert.NotEqual(user2.Id, user3.Id);
        Assert.NotEqual(user1.Id, user3.Id);
    }

    // ============================================================================
    // TEST 11: CreatedAt Timestamp Validation
    // ============================================================================
    [Fact]
    public void Create_ShouldSetCreatedAtToCurrentUtcTime()
    {
        // Arrange
        var beforeCreation = DateTime.UtcNow;

        // Act
        var user = User.Create(
            email: "test@vaultguard.com",
            username: "testuser",
            passwordHash: "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1");

        var afterCreation = DateTime.UtcNow;

        // Assert - CreatedAt þu anki UTC zamanýna yakýn olmalý
        Assert.InRange(user.CreatedAt, beforeCreation, afterCreation);
    }

    // ============================================================================
    // TEST 12: ChangePassword Method
    // ============================================================================
    [Fact]
    public void ChangePassword_WithValidHash_ShouldUpdatePasswordHash()
    {
        // Arrange
        var user = User.Create(
            email: "test@vaultguard.com",
            username: "testuser",
            passwordHash: "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1");

        var newPasswordHash = "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e2";

        // Act
        user.ChangePassword(newPasswordHash);

        // Assert
        Assert.Equal(newPasswordHash, user.PasswordHash);
    }

    // ============================================================================
    // TEST 13: ChangeRole Method
    // ============================================================================
    [Fact]
    public void ChangeRole_WithValidRole_ShouldUpdateRole()
    {
        // Arrange
        var user = User.Create(
            email: "test@vaultguard.com",
            username: "testuser",
            passwordHash: "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1");

        Assert.Equal("User", user.Role);

        // Act
        user.ChangeRole("Admin");

        // Assert
        Assert.Equal("Admin", user.Role);
    }

    // ============================================================================
    // TEST 14: IsAdmin Method
    // ============================================================================
    [Fact]
    public void IsAdmin_WhenRoleIsAdmin_ShouldReturnTrue()
    {
        // Arrange
        var adminUser = User.Create(
            email: "admin@vaultguard.com",
            username: "adminuser",
            passwordHash: "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1",
            role: "Admin");

        // Act & Assert
        Assert.True(adminUser.IsAdmin());
    }

    [Fact]
    public void IsAdmin_WhenRoleIsNotAdmin_ShouldReturnFalse()
    {
        // Arrange
        var regularUser = User.Create(
            email: "user@vaultguard.com",
            username: "regularuser",
            passwordHash: "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1");

        // Act & Assert
        Assert.False(regularUser.IsAdmin());
    }

    // ============================================================================
    // TEST 15: CanLogin Method
    // ============================================================================
    [Fact]
    public void CanLogin_WhenUserIsActive_ShouldReturnTrue()
    {
        // Arrange
        var user = User.Create(
            email: "test@vaultguard.com",
            username: "testuser",
            passwordHash: "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1");

        // Act & Assert
        Assert.True(user.CanLogin());
    }

    [Fact]
    public void CanLogin_WhenUserIsInactive_ShouldReturnFalse()
    {
        // Arrange
        var user = User.Create(
            email: "test@vaultguard.com",
            username: "testuser",
            passwordHash: "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1");

        user.Deactivate();

        // Act & Assert
        Assert.False(user.CanLogin());
    }

    // ============================================================================
    // TEST 16: Email Normalization
    // ============================================================================
    [Fact]
    public void Create_ShouldNormalizeEmailToLowercase()
    {
        // Arrange
        var email = "TeSt@VaultGuard.COM";

        // Act
        var user = User.Create(email, "testuser", "hashed_password_123456");

        // Assert
        Assert.Equal("test@vaultguard.com", user.Email);
    }

    // ============================================================================
    // TEST 17: Username Format Validation
    // ============================================================================
    [Theory]
    [InlineData("ab")] // Too short
    [InlineData("user name")] // Contains space
    [InlineData("user-name")] // Contains hyphen
    [InlineData("user@name")] // Contains special char
    public void Create_WithInvalidUsernameFormat_ShouldThrowArgumentException(string invalidUsername)
    {
        // Arrange
        var email = "test@vaultguard.com";
        var passwordHash = "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1";

        // Act & Assert
        var exception = Assert.Throws<ArgumentException>(() =>
            User.Create(email, invalidUsername, passwordHash));

        Assert.Contains("username", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ============================================================================
    // TEST 18: Valid Username Formats
    // ============================================================================
    [Theory]
    [InlineData("user123")]
    [InlineData("test_user")]
    [InlineData("User_123")]
    [InlineData("___")]
    public void Create_WithValidUsernameFormat_ShouldCreateSuccessfully(string validUsername)
    {
        // Arrange
        var email = "test@vaultguard.com";
        var passwordHash = "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1";

        // Act
        var user = User.Create(email, validUsername, passwordHash);

        // Assert
        Assert.Equal(validUsername, user.Username);
    }

    // ============================================================================
    // TEST 19: Activate Method
    // ============================================================================
    [Fact]
    public void Activate_AfterDeactivation_ShouldSetIsActiveToTrue()
    {
        // Arrange
        var user = User.Create(
            email: "test@vaultguard.com",
            username: "testuser",
            passwordHash: "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1");

        user.Deactivate();
        Assert.False(user.IsActive);

        // Act
        user.Activate();

        // Assert
        Assert.True(user.IsActive);
    }

    // ============================================================================
    // TEST 20: UpdateEmail Method
    // ============================================================================
    [Fact]
    public void UpdateEmail_WithValidEmail_ShouldUpdateEmail()
    {
        // Arrange
        var user = User.Create(
            email: "old@vaultguard.com",
            username: "testuser",
            passwordHash: "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1");

        var newEmail = "new@vaultguard.com";

        // Act
        user.UpdateEmail(newEmail);

        // Assert
        Assert.Equal(newEmail, user.Email);
    }

    // ============================================================================
    // TEST 21: UpdateUsername Method
    // ============================================================================
    [Fact]
    public void UpdateUsername_WithValidUsername_ShouldUpdateUsername()
    {
        // Arrange
        var user = User.Create(
            email: "test@vaultguard.com",
            username: "oldusername",
            passwordHash: "$2a$11$q9h/lSu3v36vE6K5A4yR.eB5OQ.5JzB1X9pQzY5H5f6W7b8c9d0e1");

        var newUsername = "newusername";

        // Act
        user.UpdateUsername(newUsername);

        // Assert
        Assert.Equal(newUsername, user.Username);
    }
}