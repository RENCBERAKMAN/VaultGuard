using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using VaultGuard.Application.Services;
using VaultGuard.Application.Tests.Common;
using VaultGuard.Application.DTOs.Users;
using VaultGuard.Domain.Entities;
using Xunit;

namespace VaultGuard.Application.Tests.Services;

/// <summary>
/// UserService - Production-Grade Security Tests
/// Protects against: Email/Username Enumeration, Data Leaking, Unauthorized Access
/// </summary>
public class UserServiceTests : TestBase
{
    private readonly UserService _userService;

    public UserServiceTests()
    {
        _userService = new UserService(MockUserRepository.Object, MockPasswordHasher.Object);
    }

    [Fact]
    public async Task GetById_WithExistingUser_ShouldReturnDtoWithoutPasswordHash()
    {
        var user = MockDataHelper.CreateValidUser();
        SetupUserExists(user);

        var result = await _userService.GetByIdAsync(user.Id);

        Assert.True(result.Success);
        Assert.NotNull(result.Data);
        Assert.Equal(user.Id, result.Data.Id);
        Assert.Equal(user.Email, result.Data.Email);

        var properties = result.Data.GetType().GetProperties();
        var hasPasswordHash = properties.Any(p => p.Name.Contains("Password", StringComparison.OrdinalIgnoreCase));
        Assert.False(hasPasswordHash, "SECURITY BREACH: PasswordHash leaked in UserDto");
    }

    [Fact]
    public async Task GetById_WithNonExistentUser_ShouldReturnError()
    {
        SetupUserNotFound();
        var result = await _userService.GetByIdAsync(Guid.NewGuid());
        Assert.False(result.Success);
        Assert.Null(result.Data);
        Assert.Contains("bulunamadı", result.Message.ToLower());
    }

    [Fact]
    public async Task GetByEmail_WithValidEmail_ShouldReturnUser()
    {
        var user = MockDataHelper.CreateValidUser();
        SetupUserExists(user);

        var result = await _userService.GetByEmailAsync(user.Email);

        Assert.True(result.Success);
        Assert.NotNull(result.Data);
        Assert.Equal(user.Email, result.Data.Email);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public async Task GetByEmail_WithInvalidEmail_ShouldReturnError(string? email)
    {
        var result = await _userService.GetByEmailAsync(email!);
        Assert.False(result.Success);
        Assert.Contains("boş olamaz", result.Message.ToLower());
    }

    [Fact]
    public async Task Create_WithExistingEmail_ShouldRejectAtomically()
    {
        MockUserRepository.Setup(x => x.ExistsByEmailAsync("existing@vault.com", It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var dto = new CreateUserDto { Email = "existing@vault.com", Username = "newuser", Password = "Pass123!" };

        var result = await _userService.CreateAsync(dto);

        Assert.False(result.Success);
        Assert.Contains("email", result.Message.ToLower());
        Assert.Contains("kullanılıyor", result.Message.ToLower());
        VerifyPasswordNeverHashed();
        VerifyNoSaveOccurred();
        MockUserRepository.Verify(x => x.AddAsync(It.IsAny<User>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Create_WithExistingUsername_ShouldRejectAtomically()
    {
        MockUserRepository.Setup(x => x.ExistsByUsernameAsync("takenuser", It.IsAny<CancellationToken>())).ReturnsAsync(true);
        var dto = new CreateUserDto { Email = "new@vault.com", Username = "takenuser", Password = "Pass123!" };

        var result = await _userService.CreateAsync(dto);

        Assert.False(result.Success);
        Assert.Contains("kullanıcı adı", result.Message.ToLower());
        VerifyPasswordNeverHashed();
        VerifyNoSaveOccurred();
        MockUserRepository.Verify(x => x.AddAsync(It.IsAny<User>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Create_WithValidData_ShouldSucceed()
    {
        const string validHash = "$2a$11$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
        var dto = new CreateUserDto { Email = "new@vault.com", Username = "newuser", Password = "Pass123!" };
        MockPasswordHasher.Setup(x => x.HashPassword(dto.Password)).Returns(validHash);

        var result = await _userService.CreateAsync(dto);

        Assert.True(result.Success, $"User creation failed: {result.Message}");
        Assert.NotNull(result.Data);
        Assert.Equal(dto.Email, result.Data.Email);
        Assert.Equal(dto.Username, result.Data.Username);
        VerifyPasswordHashedOnce();
        MockUserRepository.Verify(x => x.AddAsync(It.IsAny<User>(), It.IsAny<CancellationToken>()), Times.Once);
        VerifySaveOccurredOnce();
    }

    [Fact]
    public async Task Update_WithExistingEmail_ShouldValidateUniqueness()
    {
        var user = MockDataHelper.CreateValidUser();
        SetupUserExists(user);
        MockUserRepository.Setup(x => x.ExistsByEmailAsync("taken@vault.com", It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var dto = new UpdateUserDto { Id = user.Id, Email = "taken@vault.com" };
        var result = await _userService.UpdateAsync(user.Id, dto);

        Assert.False(result.Success);
        Assert.Contains("email", result.Message.ToLower());
        Assert.Contains("kullanılıyor", result.Message.ToLower());
        MockUserRepository.Verify(x => x.Update(It.IsAny<User>()), Times.Never);
        VerifyNoSaveOccurred();
    }

    [Fact]
    public async Task Update_WithExistingUsername_ShouldValidateUniqueness()
    {
        var user = MockDataHelper.CreateValidUser();
        SetupUserExists(user);
        MockUserRepository.Setup(x => x.ExistsByUsernameAsync("takenuser", It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var dto = new UpdateUserDto { Id = user.Id, Username = "takenuser" };
        var result = await _userService.UpdateAsync(user.Id, dto);

        Assert.False(result.Success);
        Assert.Contains("kullanıcı adı", result.Message.ToLower());
        MockUserRepository.Verify(x => x.Update(It.IsAny<User>()), Times.Never);
        VerifyNoSaveOccurred();
    }

    [Fact]
    public async Task Update_WithValidData_ShouldSucceed()
    {
        var user = MockDataHelper.CreateValidUser();
        SetupUserExists(user);
        MockUserRepository.Setup(x => x.ExistsByEmailAsync("new@vault.com", It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var dto = new UpdateUserDto { Id = user.Id, Email = "new@vault.com" };
        var result = await _userService.UpdateAsync(user.Id, dto);

        Assert.True(result.Success);
        MockUserRepository.Verify(x => x.Update(It.Is<User>(u => u.Id == user.Id)), Times.Once);
        VerifySaveOccurredOnce();
    }

    [Fact]
    public async Task ChangePassword_WithWrongCurrentPassword_ShouldNotHashNewPassword()
    {
        var user = MockDataHelper.CreateValidUser();
        SetupUserExists(user);
        SetupPasswordVerifyFails();

        var dto = new ChangePasswordDto { CurrentPassword = "WrongPass", NewPassword = "NewPass123!" };
        var result = await _userService.ChangePasswordAsync(user.Id, dto);

        Assert.False(result.Success);
        Assert.Contains("mevcut şifreniz hatalı", result.Message.ToLower());
        VerifyPasswordNeverHashed();
        MockUserRepository.Verify(x => x.Update(It.IsAny<User>()), Times.Never);
        VerifyNoSaveOccurred();
    }

    [Fact]
    public async Task ChangePassword_WithCorrectCurrentPassword_ShouldHashAndUpdate()
    {
        // Arrange
        // 1. Önce gerçekçi bir hash tanımlıyoruz
        const string realisticHash = "$2a$11$q5MkhSBls68UfuzS.7C39unY.vV6u8E.9QpC/9.m56l.vRk8N.123";

        // 2. Kullanıcıyı MockDataHelper yerine direkt Domain'in kendi metoduyla, hash'i vererek oluşturuyoruz
        var user = User.Create(
            email: "test@vault.com",
            username: "testuser",
            passwordHash: realisticHash, // Hash'i burada enjekte ediyoruz
            role: "User"
        );

        // 3. Repository ve Hasher Setup
        MockUserRepository.Setup(x => x.GetByIdAsync(user.Id, It.IsAny<CancellationToken>()))
                          .ReturnsAsync(user);

        MockPasswordHasher.Setup(x => x.VerifyPassword(It.IsAny<string>(), It.IsAny<string>()))
                          .Returns(true);

        MockPasswordHasher.Setup(x => x.HashPassword(It.IsAny<string>()))
                          .Returns(realisticHash);

        var dto = new ChangePasswordDto { CurrentPassword = "CorrectPass", NewPassword = "NewPass123!" };

        // Act
        var result = await _userService.ChangePasswordAsync(user.Id, dto);

        // Assert
        Assert.True(result.Success, $"HATA MESAJI: {result.Message}");
        MockUserRepository.Verify(x => x.Update(It.Is<User>(u => u.Id == user.Id)), Times.Once);
        VerifySaveOccurredOnce();
    }

    [Fact]
    public async Task Deactivate_WithActiveUser_ShouldSetInactive()
    {
        var user = MockDataHelper.CreateValidUser();
        Assert.True(user.IsActive);
        SetupUserExists(user);

        var result = await _userService.DeactivateAsync(user.Id);

        Assert.True(result.Success);
        MockUserRepository.Verify(x => x.Update(It.Is<User>(u => u.Id == user.Id && !u.IsActive)), Times.Once);
        VerifySaveOccurredOnce();
    }

    [Fact]
    public async Task Activate_WithInactiveUser_ShouldSetActive()
    {
        var user = MockDataHelper.CreateInactiveUser();
        Assert.False(user.IsActive);
        SetupUserExists(user);

        var result = await _userService.ActivateAsync(user.Id);

        Assert.True(result.Success);
        MockUserRepository.Verify(x => x.Update(It.Is<User>(u => u.Id == user.Id && u.IsActive)), Times.Once);
        VerifySaveOccurredOnce();
    }

    [Fact]
    public async Task Create_WithNullDto_ShouldReturnError()
    {
        var result = await _userService.CreateAsync(null!);
        Assert.False(result.Success);
        VerifyNoSaveOccurred();
    }

    [Theory]
    [InlineData("", "user", "Pass123!")]
    [InlineData("test@test.com", "", "Pass123!")]
    [InlineData("test@test.com", "user", "")]
    public async Task Create_WithEmptyFields_ShouldReturnError(string email, string username, string password)
    {
        var dto = new CreateUserDto { Email = email, Username = username, Password = password };
        var result = await _userService.CreateAsync(dto);
        Assert.False(result.Success);
        VerifyNoSaveOccurred();
    }

    [Fact]
    public async Task Create_WhenCancelled_ShouldThrowOperationCanceledException()
    {
        var cts = new CancellationTokenSource();
        cts.Cancel();

        // Tüm asenkron girişleri kilitliyoruz
        MockUserRepository.Setup(x => x.ExistsByEmailAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ThrowsAsync(new OperationCanceledException());
        MockUserRepository.Setup(x => x.ExistsByUsernameAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ThrowsAsync(new OperationCanceledException());
        MockUserRepository.Setup(x => x.AddAsync(It.IsAny<User>(), It.IsAny<CancellationToken>())).ThrowsAsync(new OperationCanceledException());

        var dto = new CreateUserDto { Email = "test@vault.com", Username = "user", Password = "Pass123!" };

        // KRİTİK: Hem 'await' hem 'ThrowsAsync' bir arada olmalı!
        await Assert.ThrowsAsync<OperationCanceledException>(async () => await _userService.CreateAsync(dto, cts.Token));
    }
}