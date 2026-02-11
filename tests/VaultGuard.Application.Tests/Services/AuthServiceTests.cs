using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using VaultGuard.Application.Services;
using VaultGuard.Application.Tests.Common;
using VaultGuard.Application.DTOs.Auth;
using VaultGuard.Domain.Entities;
using Xunit;

namespace VaultGuard.Application.Tests.Services;

/// <summary>
/// AuthService - Production-Grade Security Tests
/// Protects against: User Enumeration, Timing Attacks, Brute Force, Data Leaking
/// </summary>
public class AuthServiceTests : TestBase
{
    private readonly AuthService _authService;

    public AuthServiceTests()
    {
        _authService = new AuthService(MockUserRepository.Object, MockPasswordHasher.Object);
    }

    [Fact]
    public async Task Register_WithValidData_ShouldReturnTokenWithoutSensitiveData()
    {
        const string realisticHash = "$2a$11$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
        var dto = new RegisterDto { Email = "newuser@vault.com", Username = "newuser", Password = "SecurePass123!" };
        MockPasswordHasher.Setup(x => x.HashPassword(dto.Password)).Returns(realisticHash);

        var result = await _authService.RegisterAsync(dto);

        Assert.True(result.Success, $"Registration failed: {result.Message}");
        Assert.NotNull(result.Data);
        Assert.False(string.IsNullOrWhiteSpace(result.Data.AccessToken));
        Assert.True(result.Data.Expiration > DateTime.UtcNow);

        var properties = result.Data.GetType().GetProperties();
        var hasSensitiveData = properties.Any(p => p.Name.Contains("Password", StringComparison.OrdinalIgnoreCase) || p.Name.Contains("Hash", StringComparison.OrdinalIgnoreCase));
        Assert.False(hasSensitiveData, "SECURITY BREACH: Sensitive data leaked in TokenDto");

        VerifyPasswordHashedOnce();
        VerifySaveOccurredOnce();
    }

    [Fact]
    public async Task Register_WithExistingEmail_ShouldReturnGenericMessage()
    {
        MockUserRepository.Setup(x => x.ExistsByEmailAsync("taken@vault.com", It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var dto = new RegisterDto { Email = "taken@vault.com", Username = "user", Password = "Pass123!" };

        var result = await _authService.RegisterAsync(dto);

        Assert.False(result.Success);
        Assert.Contains("başarısız", result.Message.ToLower());
        Assert.DoesNotContain("email", result.Message.ToLower());
        Assert.DoesNotContain("kayıtlı", result.Message.ToLower());
        Assert.DoesNotContain("mevcut", result.Message.ToLower());
        VerifyPasswordNeverHashed();
        VerifyNoSaveOccurred();
    }

    [Fact]
    public async Task Register_WithExistingUsername_ShouldReturnGenericMessage()
    {
        MockUserRepository.Setup(x => x.ExistsByUsernameAsync("takenuser", It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var dto = new RegisterDto { Email = "new@vault.com", Username = "takenuser", Password = "Pass123!" };

        var result = await _authService.RegisterAsync(dto);

        Assert.False(result.Success);
        Assert.Contains("başarısız", result.Message.ToLower());
        Assert.DoesNotContain("kullanıcı adı", result.Message.ToLower());
        Assert.DoesNotContain("username", result.Message.ToLower());
        VerifyPasswordNeverHashed();
        VerifyNoSaveOccurred();
    }

    [Theory]
    [InlineData("", "user", "Pass123!")]
    [InlineData("test@test.com", "", "Pass123!")]
    [InlineData("test@test.com", "user", "")]
    public async Task Register_WithEmptyFields_ShouldReturnValidationError(string email, string username, string password)
    {
        var dto = new RegisterDto { Email = email, Username = username, Password = password };
        var result = await _authService.RegisterAsync(dto);
        Assert.False(result.Success);
        Assert.Contains("tüm alanları doldurunuz", result.Message.ToLower());
        VerifyNoSaveOccurred();
    }

    [Fact]
    public async Task Register_WithNullDto_ShouldReturnError()
    {
        var result = await _authService.RegisterAsync(null!);
        Assert.False(result.Success);
        VerifyNoSaveOccurred();
    }

    [Fact]
    public async Task Register_WhenCancelled_ShouldThrowOperationCanceledException()
    {
        var cts = new CancellationTokenSource();
        cts.Cancel();

        MockUserRepository.Setup(x => x.ExistsByEmailAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ThrowsAsync(new OperationCanceledException());
        MockUserRepository.Setup(x => x.ExistsByUsernameAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ThrowsAsync(new OperationCanceledException());

        var dto = new RegisterDto { Email = "test@vault.com", Username = "user", Password = "Pass123!" };

        // KRİTİK: Hem 'await' hem 'ThrowsAsync' bir arada olmalı!
        await Assert.ThrowsAsync<OperationCanceledException>(async () => await _authService.RegisterAsync(dto, cts.Token));
    }

    [Fact]
    public async Task Login_WithValidCredentials_ShouldReturnToken()
    {
        var user = MockDataHelper.CreateValidUser();
        SetupUserExists(user);
        MockPasswordHasher.Setup(x => x.VerifyPassword("CorrectPass123", user.PasswordHash)).Returns(true);
        var dto = new LoginDto { Email = user.Email, Password = "CorrectPass123" };

        var result = await _authService.LoginAsync(dto);

        Assert.True(result.Success);
        Assert.NotNull(result.Data);
        Assert.NotNull(result.Data.AccessToken);
        Assert.True(result.Data.Expiration > DateTime.UtcNow);
        MockUserRepository.Verify(x => x.Update(It.Is<User>(u => u.Id == user.Id)), Times.Once);
        VerifySaveOccurredOnce();
    }

    [Fact]
    public async Task Login_WithNonExistentEmail_ShouldReturnGenericMessage()
    {
        SetupUserNotFound();
        var dto = new LoginDto { Email = "ghost@vault.com", Password = "AnyPass123" };

        var result = await _authService.LoginAsync(dto);

        Assert.False(result.Success);
        const string expectedMessage = "email veya şifre hatalı.";
        Assert.Equal(expectedMessage, result.Message.ToLower());
        VerifyNoSaveOccurred();
    }

    [Fact]
    public async Task Login_WithWrongPassword_ShouldReturnGenericMessage()
    {
        var user = MockDataHelper.CreateValidUser();
        SetupUserExists(user);
        SetupPasswordVerifyFails();
        var dto = new LoginDto { Email = user.Email, Password = "WrongPass123" };

        var result = await _authService.LoginAsync(dto);

        Assert.False(result.Success);
        const string expectedMessage = "email veya şifre hatalı.";
        Assert.Equal(expectedMessage, result.Message.ToLower());
        VerifyNoSaveOccurred();
    }

    [Fact]
    public async Task Login_CompareNonExistentVsWrongPassword_ShouldReturnIdenticalMessages()
    {
        SetupUserNotFound();
        var dto1 = new LoginDto { Email = "ghost@vault.com", Password = "Pass123" };
        var result1 = await _authService.LoginAsync(dto1);

        var user = MockDataHelper.CreateValidUser();
        SetupUserExists(user);
        SetupPasswordVerifyFails();
        var dto2 = new LoginDto { Email = user.Email, Password = "WrongPass" };
        var result2 = await _authService.LoginAsync(dto2);

        Assert.Equal(result1.Message.ToLower(), result2.Message.ToLower());
        Assert.Contains("email veya şifre", result1.Message.ToLower());
        Assert.Contains("email veya şifre", result2.Message.ToLower());
    }

    [Fact]
    public async Task Login_WithInactiveUser_ShouldReturnGenericError()
    {
        var user = MockDataHelper.CreateInactiveUser();
        SetupUserExists(user);
        MockPasswordHasher.Setup(x => x.VerifyPassword("Pass123", user.PasswordHash)).Returns(true);
        var dto = new LoginDto { Email = user.Email, Password = "Pass123" };

        var result = await _authService.LoginAsync(dto);

        Assert.False(result.Success);
        Assert.Contains("email veya şifre hatalı", result.Message.ToLower());
        MockUserRepository.Verify(x => x.Update(It.IsAny<User>()), Times.Never);
        VerifyNoSaveOccurred();
    }

    [Fact]
    public async Task Login_WithNullDto_ShouldReturnError()
    {
        var result = await _authService.LoginAsync(null!);
        Assert.False(result.Success);
        VerifyNoSaveOccurred();
    }

    [Theory]
    [InlineData("", "password")]
    [InlineData("test@test.com", "")]
    [InlineData("", "")]
    public async Task Login_WithEmptyFields_ShouldReturnError(string email, string password)
    {
        var dto = new LoginDto { Email = email, Password = password };
        var result = await _authService.LoginAsync(dto);
        Assert.False(result.Success);
        VerifyNoSaveOccurred();
    }

    [Fact]
    public async Task VerifyPassword_WithCorrectPassword_ShouldReturnSuccess()
    {
        var user = MockDataHelper.CreateValidUser();
        SetupUserExists(user);
        MockPasswordHasher.Setup(x => x.VerifyPassword("CorrectPass", user.PasswordHash)).Returns(true);

        var result = await _authService.VerifyPasswordAsync(user.Id, "CorrectPass");

        Assert.True(result.Success);
        Assert.Contains("doğrulandı", result.Message.ToLower());
    }

    [Fact]
    public async Task VerifyPassword_WithWrongPassword_ShouldReturnError()
    {
        var user = MockDataHelper.CreateValidUser();
        SetupUserExists(user);
        SetupPasswordVerifyFails();

        var result = await _authService.VerifyPasswordAsync(user.Id, "WrongPass");

        Assert.False(result.Success);
        Assert.Contains("hatalı", result.Message.ToLower());
    }

    [Fact]
    public async Task VerifyPassword_WithNonExistentUser_ShouldReturnError()
    {
        SetupUserNotFound();
        var result = await _authService.VerifyPasswordAsync(Guid.NewGuid(), "AnyPass");
        Assert.False(result.Success);
        Assert.Contains("bulunamadı", result.Message.ToLower());
    }
}