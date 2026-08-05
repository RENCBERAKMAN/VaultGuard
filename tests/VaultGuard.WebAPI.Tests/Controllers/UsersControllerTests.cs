using System;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using VaultGuard.Application.DTOs.Users;
using VaultGuard.Application.Interfaces;
using VaultGuard.Domain.Common.Results;
using VaultGuard.WebAPI.Controllers;
using ChangePasswordRequestModel = VaultGuard.WebAPI.Controllers.UsersController.ChangePasswordRequest;
using UpdateProfileRequestModel = VaultGuard.WebAPI.Controllers.UsersController.UpdateProfileRequest;
using ChangePasswordDto = VaultGuard.Application.DTOs.Users.ChangePasswordDto;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Controllers;

/// <summary>
/// TEST S��T�: UsersController - Authorization Guard & JWT Claim Extraction
/// 
/// TEST KAPSAMI:
/// - [Authorize] attribute varl���
/// - JWT claim'lerinden user ID �ekimi (GetCurrentUserId)
/// - Thin Controller prensibi (servis delegasyonu)
/// - CancellationToken propagation
/// - Input validation
/// - Authorization failures
/// 
/// G�VENL�K FOKUSu:
/// - Unauthorized access prevention
/// - Secure identity extraction
/// - Service communication integrity
/// </summary>
public class UsersControllerTests
{
    private readonly Mock<IUserService> _userServiceMock;
    private readonly Mock<ILogger<UsersController>> _loggerMock;
    private readonly UsersController _controller;

    public UsersControllerTests()
    {
        _userServiceMock = new Mock<IUserService>();
        _loggerMock = new Mock<ILogger<UsersController>>();

        _controller = new UsersController(_userServiceMock.Object, _loggerMock.Object);

        // HttpContext sim�lasyonu (JWT Claims i�in)
        SetupAuthenticatedUser();
    }

    // ============================================================================
    // AUTHORIZATION ATTRIBUTE TESTLER�
    // ============================================================================

    [Fact]
    public void UsersController_ShouldHaveAuthorizeAttribute()
    {
        // Arrange & Act: Controller class'�na [Authorize] attribute var m�?
        var controllerType = typeof(UsersController);
        var attributes = controllerType.GetCustomAttributes(typeof(AuthorizeAttribute), true);

        // Assert: [Authorize] attribute mevcut olmal�
        attributes.Should().NotBeEmpty(
            because: "UsersController t�m endpoint'lerde authentication gerektirir");
    }

    [Fact]
    public void GetMe_ShouldNotHaveAllowAnonymousAttribute()
    {
        // Arrange: GetMe endpoint'i
        var methodInfo = typeof(UsersController).GetMethod("GetMe");

        // Act
        var allowAnonymousAttributes = methodInfo?.GetCustomAttributes(
            typeof(AllowAnonymousAttribute), true);

        // Assert: [AllowAnonymous] olmamal� (authentication zorunlu)
        allowAnonymousAttributes.Should().BeEmpty();
    }

    [Fact]
    public void ChangePassword_ShouldNotHaveAllowAnonymousAttribute()
    {
        // Arrange
        var methodInfo = typeof(UsersController).GetMethod("ChangePassword");

        // Act
        var allowAnonymousAttributes = methodInfo?.GetCustomAttributes(
            typeof(AllowAnonymousAttribute), true);

        // Assert
        allowAnonymousAttributes.Should().BeEmpty();
    }

    // ============================================================================
    // GET ME (PROFILE) ENDPOINT TESTLER�
    // ============================================================================

    [Fact]
    public async Task GetMe_WithAuthenticatedUser_ShouldCallServiceWithUserId()
    {
        // Arrange: JWT'den al�nan user ID
        var userId = Guid.NewGuid().ToString();
        SetupAuthenticatedUser(userId);

        var userDto = new UserDto
        {
            Id = Guid.Parse(userId),
            Email = "user@test.com",
            Username = "testuser"
        };

        _userServiceMock
    .Setup(s => s.GetUserProfileAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
    .ReturnsAsync(new SuccessDataResult<UserDto>(userDto));

        // Act
        var result = await _controller.GetMe(CancellationToken.None);

        // Assert & Verify: Parametre tipini Guid olarak do�rula
        _userServiceMock.Verify(
            s => s.GetUserProfileAsync(Guid.Parse(userId), It.IsAny<CancellationToken>()),
            Times.Once);

        // 200 OK d�nd� m�?
        result.Should().BeOfType<OkObjectResult>();
    }

    [Fact]
    public async Task GetMe_ShouldPassCancellationTokenToService()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString(); // Ge�erli Guid
        SetupAuthenticatedUser(userId);

        var cts = new CancellationTokenSource();
        var token = cts.Token;

        _userServiceMock
     .Setup(s => s.GetUserProfileAsync(It.IsAny<Guid>(), token)) // Guid tipi
     .ReturnsAsync(new SuccessDataResult<UserDto>(new UserDto()));
        // Act
        await _controller.GetMe(token);

        // Assert: Token do�ru iletildi mi?
        _userServiceMock.Verify(s => s.GetUserProfileAsync(Guid.Parse(userId), token), Times.Once);
    }

    [Fact]
    public async Task GetMe_UserIdNotInClaims_ShouldReturn401()
    {
        // Arrange: JWT claim'lerinde user ID yok
        SetupUnauthenticatedUser();

        // Act
        var result = await _controller.GetMe(CancellationToken.None);

        // Assert: 401 Unauthorized
        result.Should().BeOfType<UnauthorizedObjectResult>();

        // Servis �a�r�lmamal�
        _userServiceMock.Verify(
    s => s.GetUserProfileAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()),
    Times.Never);
    }

    [Fact]
    public async Task GetMe_ServiceReturnsNotFound_ShouldReturn404()
    {
        // Arrange: Kullan�c� bulunamad�
        var userId = Guid.NewGuid().ToString(); // Ger�ek bir Guid string'i
        SetupAuthenticatedUser(userId);

        _userServiceMock
            .Setup(s => s.GetUserProfileAsync(Guid.Parse(userId), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ErrorDataResult<UserDto>("Kullan�c� bulunamad�."));

        var result = await _controller.GetMe(CancellationToken.None);

        result.Should().BeOfType<NotFoundObjectResult>();
    }

    // ============================================================================
    // CHANGE PASSWORD ENDPOINT TESTLER�
    // ============================================================================

    [Fact]
    public async Task ChangePassword_WithValidData_ShouldCallServiceAndReturn200()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        SetupAuthenticatedUser(userId);

        var request = new ChangePasswordRequestModel
        {
            OldPassword = "OldPass123!",
            NewPassword = "NewPass456!",
        };

        _userServiceMock
    .Setup(s => s.ChangePasswordAsync(It.IsAny<Guid>(), It.IsAny<ChangePasswordDto>(), It.IsAny<CancellationToken>()))
    .ReturnsAsync(new SuccessResult("�ifre de�i�tirildi."));
        // Act
        var result = await _controller.ChangePassword(request, CancellationToken.None);

        // Assert: 200 OK
        result.Should().BeOfType<OkObjectResult>();

        // Servis do�ru parametrelerle �a�r�ld� m�?
        _userServiceMock.Verify(s => s.ChangePasswordAsync(Guid.Parse(userId), It.IsAny<ChangePasswordDto>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ChangePassword_ShouldPassCancellationTokenToService()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        SetupAuthenticatedUser(userId);
        var request = new ChangePasswordRequestModel { OldPassword = "Old", NewPassword = "New" };
        var cts = new CancellationTokenSource();

        _userServiceMock
            .Setup(s => s.ChangePasswordAsync(It.IsAny<Guid>(), It.IsAny<ChangePasswordDto>(), cts.Token))
            .ReturnsAsync(new SuccessResult());

        await _controller.ChangePassword(request, cts.Token);

        _userServiceMock.Verify(s => s.ChangePasswordAsync(Guid.Parse(userId), It.IsAny<ChangePasswordDto>(), cts.Token), Times.Once);
    }

    [Fact]
    public async Task ChangePassword_WithNullRequest_ShouldReturn400()
    {
        ChangePasswordRequestModel? nullRequest = null;

        var result = await _controller.ChangePassword(nullRequest!, CancellationToken.None);

        result.Should().BeOfType<BadRequestObjectResult>();
        _userServiceMock.Verify(s => s.ChangePasswordAsync(It.IsAny<Guid>(), It.IsAny<ChangePasswordDto>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ChangePassword_WithEmptyFields_ShouldReturn400()
    {
        // Arrange
        var changePasswordRequest = new ChangePasswordRequestModel
        {
            OldPassword = "",
            NewPassword = ""
        };

        // Act
        var result = await _controller.ChangePassword(changePasswordRequest, CancellationToken.None);

        // Assert
        result.Should().BeOfType<BadRequestObjectResult>();

        _userServiceMock.Verify(
    s => s.ChangePasswordAsync(
        It.IsAny<Guid>(), It.IsAny<ChangePasswordDto>(),
        It.IsAny<CancellationToken>()),
    Times.Never);
    }

    [Fact]
    public async Task ChangePassword_OldPasswordSameAsNew_ShouldReturn400()
    {
        // Arrange: Yeni �ifre eski �ifre ile ayn�
        var changePasswordRequest = new ChangePasswordRequestModel
        {
            OldPassword = "SamePass123!",
            NewPassword = "SamePass123!"
        };

        // Act
        var result = await _controller.ChangePassword(changePasswordRequest, CancellationToken.None);

        // Assert
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public async Task ChangePassword_ServiceReturnsError_ShouldReturnGenericMessage()
    {
        // Arrange: Eski �ifre yanl��
        var userId = Guid.NewGuid().ToString();
        SetupAuthenticatedUser(userId);

        var request = new ChangePasswordRequestModel { OldPassword = "WrongOldPass!", NewPassword = "NewPass123!" };

        // Setup: Yeni imza (Guid, DTO, Token)
        _userServiceMock
            .Setup(s => s.ChangePasswordAsync(Guid.Parse(userId), It.IsAny<ChangePasswordDto>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ErrorResult("Mevcut �ifre hatal�."));

        var result = await _controller.ChangePassword(request, CancellationToken.None);

        // Assert: Generic error message (anti-enumeration)
        result.Should().BeOfType<BadRequestObjectResult>();

        var badRequest = result as BadRequestObjectResult;
        var responseValue = badRequest.Value.ToString();

        // G�VENL�K: "Mevcut �ifre hatal�" detay� s�zd�r�lmamal�
        responseValue.Should().NotContain("Mevcut �ifre");
        responseValue.Should().NotContain("Wrong old password");
    }

    [Fact]
    public async Task ChangePassword_UserIdNotInClaims_ShouldReturn401()
    {
        // Arrange: JWT claim yok
        SetupUnauthenticatedUser();
        var request = new ChangePasswordRequestModel { OldPassword = "Old", NewPassword = "New" };

        var result = await _controller.ChangePassword(request, CancellationToken.None);

        result.Should().BeOfType<UnauthorizedObjectResult>();
        // Verify: Yeni imzaya g�re do�rula
        _userServiceMock.Verify(s => s.ChangePasswordAsync(It.IsAny<Guid>(), It.IsAny<ChangePasswordDto>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // ============================================================================
    // LOGOUT ALL DEVICES ENDPOINT TESTLER�
    // ============================================================================

    [Fact]
    public async Task LogoutAllDevices_ShouldCallServiceAndReturn200()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString(); // Ger�ek Guid
        SetupAuthenticatedUser(userId);

        _userServiceMock
            .Setup(s => s.LogoutAllDevicesAsync(Guid.Parse(userId), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SuccessResult("T�m oturumlar kapat�ld�."));

        var result = await _controller.LogoutAllDevices(CancellationToken.None);

        // Assert
        result.Should().BeOfType<OkObjectResult>();

        _userServiceMock.Verify(s => s.LogoutAllDevicesAsync(Guid.Parse(userId), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task LogoutAllDevices_ShouldPassCancellationToken()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        SetupAuthenticatedUser(userId);
        var cts = new CancellationTokenSource();
        var token = cts.Token;

        _userServiceMock
    .Setup(s => s.LogoutAllDevicesAsync(It.IsAny<Guid>(), cts.Token))
    .ReturnsAsync(new SuccessResult());

        // Act
        await _controller.LogoutAllDevices(cts.Token);

        _userServiceMock.Verify(s => s.LogoutAllDevicesAsync(Guid.Parse(userId), cts.Token), Times.Once);
    }

    [Fact]
    public async Task LogoutAllDevices_UserIdNotInClaims_ShouldReturn401()
    {
        // Arrange
        SetupUnauthenticatedUser();

        // Act
        var result = await _controller.LogoutAllDevices(CancellationToken.None);

        // Assert
        result.Should().BeOfType<UnauthorizedObjectResult>();

        _userServiceMock.Verify(
    s => s.LogoutAllDevicesAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()),
    Times.Never);
    }

    // ============================================================================
    // UPDATE PROFILE ENDPOINT TESTLER�
    // ============================================================================

    [Fact]
    public async Task UpdateProfile_WithValidData_ShouldCallServiceAndReturn200()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        SetupAuthenticatedUser(userId);

        var request = new UpdateProfileRequestModel
        {
            FirstName = "John",
            LastName = "Doe",
            PhoneNumber = "+12345"
        };

        var updatedUserDto = new UserDto
        {
            Id = Guid.Parse(userId),
            Email = "john@test.com",
            Username = "johndoe"
        };

        _userServiceMock
    .Setup(s => s.UpdateAsync(It.IsAny<Guid>(), It.IsAny<UpdateUserDto>(), It.IsAny<CancellationToken>()))
    .ReturnsAsync(new SuccessDataResult<UserDto>(new UserDto { Id = Guid.Parse(userId) }));

        // Act
        var result = await _controller.UpdateProfile(request, CancellationToken.None);

        // Assert
        result.Should().BeOfType<OkObjectResult>();

        result.Should().BeOfType<OkObjectResult>();
        _userServiceMock.Verify(s => s.UpdateAsync(Guid.Parse(userId), It.IsAny<UpdateUserDto>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task UpdateProfile_WithNullRequest_ShouldReturn400()
    {
        // Arrange
        UpdateProfileRequestModel? nullRequest = null;

        var result = await _controller.UpdateProfile(nullRequest!, CancellationToken.None);

        result.Should().BeOfType<BadRequestObjectResult>();
        // Verify: Servis yeni imzas�yla (Guid ve DTO) hi� �a�r�lmamal�
        _userServiceMock.Verify(
            s => s.UpdateAsync(It.IsAny<Guid>(), It.IsAny<UpdateUserDto>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    // ============================================================================
    // EXCEPTION HANDLING TESTLER�
    // ============================================================================

    [Fact]
    public async Task GetMe_OperationCanceled_ShouldReturn408()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        SetupAuthenticatedUser(userId);

        var cts = new CancellationTokenSource();
        cts.Cancel();

        _userServiceMock
    .Setup(s => s.GetUserProfileAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
    .ThrowsAsync(new OperationCanceledException());
        // Act
        var result = await _controller.GetMe(cts.Token);

        // Assert: 408 Request Timeout
        var statusCodeResult = result as ObjectResult;
        statusCodeResult?.StatusCode.Should().Be(408);
    }

    [Fact]
    public async Task ChangePassword_UnexpectedException_ShouldReturn500()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        SetupAuthenticatedUser(userId);

        var request = new ChangePasswordRequestModel { OldPassword = "Old", NewPassword = "New" };

        _userServiceMock
     .Setup(s => s.ChangePasswordAsync(It.IsAny<Guid>(), It.IsAny<ChangePasswordDto>(), It.IsAny<CancellationToken>()))
     .ThrowsAsync(new Exception("Unexpected error"));

        // Act
       var result = await _controller.ChangePassword(request, CancellationToken.None);

        var statusCodeResult = result as ObjectResult;
        statusCodeResult?.StatusCode.Should().Be(500);
    }

    // ============================================================================
    // THIN CONTROLLER PRENS�B� DO�RULAMA
    // ============================================================================

    [Fact]
    public async Task AllEndpoints_ShouldDelegateToService()
    {
        // Arrange
        var userId = Guid.NewGuid().ToString();
        SetupAuthenticatedUser(userId);

        var changePasswordRequest = new ChangePasswordRequestModel
        {
            OldPassword = "Old123!",
            NewPassword = "New456!"
        };

        _userServiceMock
        .Setup(s => s.GetUserProfileAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
        .ReturnsAsync(new SuccessDataResult<UserDto>(new UserDto()));

        _userServiceMock
        .Setup(s => s.ChangePasswordAsync(It.IsAny<Guid>(), It.IsAny<ChangePasswordDto>(), It.IsAny<CancellationToken>()))
        .ReturnsAsync(new SuccessResult());

        // Act
        await _controller.GetMe(CancellationToken.None);
        await _controller.ChangePassword(changePasswordRequest, CancellationToken.None);
        // Assert: T�m endpoint'ler servise delegate etti
        _userServiceMock.Verify(s => s.GetUserProfileAsync(Guid.Parse(userId), It.IsAny<CancellationToken>()), Times.Once);
        _userServiceMock.Verify(s => s.ChangePasswordAsync(Guid.Parse(userId), It.IsAny<ChangePasswordDto>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ============================================================================
    // HELPER METHODS - JWT CLAIM SIMULATION
    // ============================================================================

    private void SetupAuthenticatedUser(string userId = "default-user-id")
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId),
            new Claim(ClaimTypes.Name, "testuser"),
            new Claim(ClaimTypes.Email, "test@test.com")
        };

        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = principal
            }
        };
    }

    private void SetupUnauthenticatedUser()
    {
        // Bo� claims (authenticated de�il)
        var identity = new ClaimsIdentity();
        var principal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = principal
            }
        };
    }
}

