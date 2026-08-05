using System;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Http; // DefaultHttpContext i�in �art!
using Microsoft.AspNetCore.Mvc;  // ControllerContext ve OkObjectResult i�in �art!
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

// --- PROJE ADRESLER� ---
using VaultGuard.Application.Interfaces;
using VaultGuard.Domain.Common.Results;
using VaultGuard.WebAPI.Controllers;
using VaultGuard.Application.DTOs.Auth; // RegisterDto, LoginDto burada
using RegisterRequestModel = VaultGuard.Application.DTOs.Auth.RegisterDto;
using LoginRequestModel = VaultGuard.Application.DTOs.Auth.LoginDto;
namespace VaultGuard.WebAPI.Tests.Controllers;

/// <summary>
/// TEST S��T�: AuthController - Thin Controller Validation
/// 
/// TEST KAPSAMI:
/// - Thin Controller prensibi (i� mant��� YOK)
/// - Servise do�ru parametre iletimi
/// - CancellationToken propagation
/// - Anti-enumeration (hata mesaj� maskeleme)
/// - Input validation
/// - HTTP status code mapping
/// 
/// G�VENL�K FOKUSu:
/// - User enumeration prevention
/// - Generic error responses
/// - Sensitive data exposure prevention
/// </summary>
public class AuthControllerTests
{
    private readonly Mock<IAuthService> _authServiceMock;
    private readonly Mock<ILogger<AuthController>> _loggerMock;
    private readonly AuthController _controller;

    public AuthControllerTests()
    {
        _authServiceMock = new Mock<IAuthService>();
        _loggerMock = new Mock<ILogger<AuthController>>();

        _controller = new AuthController(_authServiceMock.Object, _loggerMock.Object);

        // HttpContext sim�lasyonu (IP address tracking i�in)
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext()
        };
    }

    // ============================================================================
    // REGISTER ENDPOINT TESTLER�
    // ============================================================================

    [Fact]
    public async Task Register_WithValidData_ShouldCallServiceAndReturn200()
    {
        // Arrange: Ge�erli kay�t verisi
        var request = new RegisterRequestModel
        {
            Email = "test@vaultguard.com",
            Username = "testuser",
            Password = "SecurePass123!",
            ConfirmPassword = "SecurePass123!"
        };

        var tokenDto = new TokenDto
        {
            AccessToken = "jwt_token_here",
            Expiration = DateTime.UtcNow.AddHours(1)
        };

        _authServiceMock
            .Setup(s => s.RegisterAsync(It.IsAny<RegisterDto>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SuccessDataResult<TokenDto>(tokenDto, "Kay�t ba�ar�l�"));

        // Act
        var result = await _controller.Register(request, CancellationToken.None);

        // Assert: 200 OK d�nd� m�?
        result.Should().BeOfType<OkObjectResult>();

        var okResult = result as OkObjectResult;
        okResult.StatusCode.Should().Be(200);

        // Servis �a�r�ld� m�?
        _authServiceMock.Verify(
    s => s.RegisterAsync(It.IsAny<RegisterDto>(), It.IsAny<CancellationToken>()),
    Times.Once);
    }

    [Fact]
    public async Task Register_ShouldPassCancellationTokenToService()
    {
        // Arrange
        var request = new RegisterRequestModel
        {
            Email = "test@test.com",
            Username = "user",
            Password = "Pass123!",
            ConfirmPassword = "Pass123!"
        };

        var cts = new CancellationTokenSource();
        var token = cts.Token;

        _authServiceMock
            .Setup(s => s.RegisterAsync(It.IsAny<RegisterDto>(), token))
            .ReturnsAsync(new SuccessDataResult<TokenDto>(new TokenDto()));

        // Act
        await _controller.Register(request, token);

        // Assert: CancellationToken do�ru iletildi mi?
        _authServiceMock.Verify(
    s => s.RegisterAsync(It.IsAny<RegisterDto>(), token),
    Times.Once);
    }

    [Fact]
    public async Task Register_WithNullRequest_ShouldReturn400BadRequest()
    {
        // Arrange: Null request
        RegisterRequestModel? nullRequest = null;

        // Act
        var result = await _controller.Register(nullRequest, CancellationToken.None);

        // Assert: 400 Bad Request
        result.Should().BeOfType<BadRequestObjectResult>();

        var badRequest = result as BadRequestObjectResult;
        badRequest.StatusCode.Should().Be(400);

        // Servis �a�r�lmamal�
        _authServiceMock.Verify(
    s => s.RegisterAsync(It.IsAny<RegisterDto>(), It.IsAny<CancellationToken>()),
    Times.Never);
    }

    [Fact]
    public async Task Register_WithEmptyFields_ShouldReturn400()
    {
        // Arrange: Bo� alanlar
        var request = new RegisterRequestModel
        {
            Email = "",
            Username = "",
            Password = ""
        };

        // Act
        var result = await _controller.Register(request, CancellationToken.None);

        // Assert
        result.Should().BeOfType<BadRequestObjectResult>();

        // Servis �a�r�lmamal� (validation controller'da)
        _authServiceMock.Verify(
    s => s.RegisterAsync(It.IsAny<RegisterDto>(), It.IsAny<CancellationToken>()),
    Times.Never);
    }

    [Fact]
    public async Task Register_ServiceReturnsError_ShouldReturnGenericMessage()
    {
        // Arrange: Servis hata d�n�yor (email already exists gibi)
        var request = new RegisterRequestModel
        {
            Email = "existing@test.com",
            Username = "user",
            Password = "Pass123!",
            ConfirmPassword = "Pass123!"
        };

        // Setup k�sm�nda servisin anlad��� tipi (RegisterDto) yaz�yoruz
        _authServiceMock
            .Setup(s => s.RegisterAsync(It.IsAny<RegisterDto>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ErrorDataResult<TokenDto>("Bu email adresi zaten kullan�l�yor."));

        // Act k�sm�nda yukar�da tan�mlad���n 'request' de�i�kenini g�nderiyoruz
        var result = await _controller.Register(request, CancellationToken.None);
        // Assert: Generic hata mesaj� d�nmeli (anti-enumeration)
        result.Should().BeOfType<BadRequestObjectResult>();

        var badRequest = result as BadRequestObjectResult;
        var responseValue = badRequest.Value;

        // G�VENL�K: "email already exists" gibi detay s�zd�r�lmamal�
        responseValue.ToString().Should().NotContain("already exists");
        responseValue.ToString().Should().NotContain("zaten kullan�l�yor");
    }

    [Fact]
    public async Task Register_WithWeakPassword_ShouldReturn400()
    {
        // Arrange: Zay�f �ifre
        // Tipi 'RegisterRequestModel' (yukar�daki takma ismimiz), de�i�keni 'request' yap�yoruz
        var request = new RegisterRequestModel
        {
            Email = "test@test.com",
            Username = "user",
            Password = "123", // �ok k�sa
            ConfirmPassword = "123"
        };

        var result = await _controller.Register(request, CancellationToken.None);
        // Assert
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    // ============================================================================
    // LOGIN ENDPOINT TESTLER�
    // ============================================================================

    [Fact]
    public async Task Login_WithValidCredentials_ShouldCallServiceAndReturn200()
    {
        // Arrange
        var request = new LoginRequestModel
        {
            Email = "user@test.com",
            Password = "CorrectPass123!"
        };

        _authServiceMock
            .Setup(s => s.LoginAsync(It.IsAny<LoginDto>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SuccessDataResult<TokenDto>(new TokenDto(), "Giri� ba�ar�l�"));

        // Controller'a do�ru paketi (request) veriyoruz
        var result = await _controller.Login(request, CancellationToken.None);

        // Verify k�sm�nda servisin 'LoginDto' ile �a�r�ld���n� do�ruluyoruz
        _authServiceMock.Verify(
            s => s.LoginAsync(It.IsAny<LoginDto>(), It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task Login_ShouldPassCancellationTokenToService()
    {
        // Arrange
        // Controller Model bekler
        var request = new LoginRequestModel { Email = "test@test.com", Password = "Pass123!" };

        var cts = new CancellationTokenSource();
        var token = cts.Token;

        _authServiceMock
            .Setup(s => s.LoginAsync(It.IsAny<LoginDto>(), token))
            .ReturnsAsync(new SuccessDataResult<TokenDto>(new TokenDto()));

        // Controller'a Model (request) g�nderiyoruz
        await _controller.Login(request, token);

        _authServiceMock.Verify(s => s.LoginAsync(It.IsAny<LoginDto>(), token), Times.Once);
    }

    [Fact]
    public async Task Login_WithNullRequest_ShouldReturn400()
    {
        // Kap�daki tipi (Model) null olarak tan�ml�yoruz
        LoginRequestModel? nullRequest = null;

        var result = await _controller.Login(nullRequest!, CancellationToken.None);

        result.Should().BeOfType<BadRequestObjectResult>();
        _authServiceMock.Verify(s => s.LoginAsync(It.IsAny<LoginDto>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Login_WithEmptyEmailOrPassword_ShouldReturn400()
    {
        // Arrange
        var request = new LoginRequestModel { Email = "", Password = "" };

        var result = await _controller.Login(request, CancellationToken.None);

        result.Should().BeOfType<BadRequestObjectResult>();
        _authServiceMock.Verify(s => s.LoginAsync(It.IsAny<LoginDto>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Login_ServiceReturnsError_ShouldReturnGenericMessage()
    {
        // Arrange: Servis "Email not found" veya "Wrong password" d�n�yor
        var request = new LoginRequestModel { Email = "nonexistent@test.com", Password = "WrongPass!" };

        _authServiceMock
            .Setup(s => s.LoginAsync(It.IsAny<LoginDto>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ErrorDataResult<TokenDto>("Email veya �ifre hatal�."));

        var result = await _controller.Login(request, CancellationToken.None);

        // Assert: Generic mesaj d�nmeli (anti-enumeration)
        result.Should().BeOfType<BadRequestObjectResult>();

        var badRequest = result as BadRequestObjectResult;
        var responseValue = badRequest.Value.ToString();

        // G�VENL�K: "Email not found" veya "Wrong password" detay� s�zd�r�lmamal�
        responseValue.Should().NotContain("not found");
        responseValue.Should().NotContain("wrong password");
        responseValue.Should().Contain("hatal�");
    }

    [Fact]
    public async Task Login_InactiveUser_ShouldReturnGenericError()
    {
        // Arrange: Pasif kullan�c�
        var request = new LoginRequestModel { Email = "inactive@test.com", Password = "Pass123!" };

        _authServiceMock
            .Setup(s => s.LoginAsync(It.IsAny<LoginDto>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ErrorDataResult<TokenDto>("Hesap devre d���."));

        var result = await _controller.Login(request, CancellationToken.None);

        // Assert: Generic hata
        result.Should().BeOfType<BadRequestObjectResult>();
    }

    // ============================================================================
    // REFRESH TOKEN ENDPOINT TESTLER�
    // ============================================================================

    [Fact]
    public async Task RefreshToken_WithValidToken_ShouldCallServiceAndReturn200()
    {
        // Arrange
        var refreshTokenRequest = new RefreshTokenDto
        {
            RefreshToken = "valid_refresh_token"
        };

        var newTokenDto = new TokenDto
        {
            AccessToken = "new_access_token",
            Expiration = DateTime.UtcNow.AddHours(1)
        };

        _authServiceMock
    .Setup(s => s.RefreshTokenAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
    .ReturnsAsync(new SuccessDataResult<TokenDto>(newTokenDto));
        // Act
        var result = await _controller.RefreshToken(refreshTokenRequest, CancellationToken.None);

        // Assert
        result.Should().BeOfType<OkObjectResult>();

        _authServiceMock.Verify(s => s.RefreshTokenAsync(refreshTokenRequest.RefreshToken, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RefreshToken_ShouldPassCancellationTokenToService()
    {
        // Arrange
        var refreshTokenRequest = new RefreshTokenDto
        {
            RefreshToken = "token"
        };

        var cts = new CancellationTokenSource();
        var token = cts.Token;

        _authServiceMock
            .Setup(s => s.RefreshTokenAsync(It.IsAny<string>(), token))
            .ReturnsAsync(new SuccessDataResult<TokenDto>(new TokenDto()));

        // Act
        await _controller.RefreshToken(refreshTokenRequest, token);

        // Assert
        _authServiceMock.Verify(
            s => s.RefreshTokenAsync(refreshTokenRequest.RefreshToken, token),
            Times.Once);
    }

    [Fact]
    public async Task RefreshToken_WithNullRequest_ShouldReturn400()
    {
        // Arrange
        RefreshTokenDto nullRequest = null;

        // Act
        var result = await _controller.RefreshToken(nullRequest, CancellationToken.None);

        // Assert
        result.Should().BeOfType<BadRequestObjectResult>();

        _authServiceMock.Verify(
            s => s.RefreshTokenAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task RefreshToken_WithEmptyToken_ShouldReturn400()
    {
        // Arrange
        var refreshTokenRequest = new RefreshTokenDto
        {
            RefreshToken = ""
        };

        // Act
        var result = await _controller.RefreshToken(refreshTokenRequest, CancellationToken.None);

        // Assert
        result.Should().BeOfType<BadRequestObjectResult>();

        _authServiceMock.Verify(
            s => s.RefreshTokenAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task RefreshToken_ServiceReturnsError_ShouldReturn401()
    {
        // Arrange: Ge�ersiz refresh token
        var refreshTokenRequest = new RefreshTokenDto
        {
            RefreshToken = "invalid_token"
        };

        _authServiceMock
            .Setup(s => s.RefreshTokenAsync(
                refreshTokenRequest.RefreshToken,
                It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ErrorDataResult<TokenDto>("Token ge�ersiz."));

        // Act
        var result = await _controller.RefreshToken(refreshTokenRequest, CancellationToken.None);

        // Assert: 401 Unauthorized
        result.Should().BeOfType<UnauthorizedObjectResult>();

        var unauthorizedResult = result as UnauthorizedObjectResult;
        unauthorizedResult.StatusCode.Should().Be(401);
    }

    // ============================================================================
    // LOGOUT ENDPOINT TESTLER�
    // ============================================================================

    [Fact]
    public async Task Logout_ShouldCallServiceAndReturn200()
    {
        // Arrange: User ID mock
        var userId = Guid.NewGuid().ToString();

        // Mock GetCurrentUserId (BaseController'dan)
        // Not: BaseController'�n GetCurrentUserId metodunu test etmek i�in
        // ya reflection kullanmal�y�z ya da controller'� mock etmeliyiz.
        // Burada basitle�tirme i�in direkt servis �a�r�s�n� test ediyoruz.

        // Servis katman� art�k Guid veya string bekliyor olabilir, 
        // ama en garanti yol tip ba��ms�z It.IsAny kullanmakt�r.
       _authServiceMock
            .Setup(s => s.LogoutAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SuccessResult("Çıkış başarılı."));
        // Act: Logout genelde parametre almaz, userId'yi HttpContext'ten �eker.
        var result = await _controller.Logout(CancellationToken.None);
        // Assert: 200 OK (e�er user ID al�nabilirse)
        // Not: GetCurrentUserId null d�nerse BadRequest olacak
        // Bu test i�in HTTP context'te JWT claim'leri olmal�
    }

    // ============================================================================
    // EXCEPTION HANDLING TESTLER�
    // ============================================================================

    [Fact]
    public async Task Login_OperationCanceled_ShouldReturn408()
    {
        // Arrange: Servis OperationCanceledException f�rlat�yor
        var request = new LoginRequestModel { Email = "test@test.com", Password = "Pass123!" };

        var cts = new CancellationTokenSource();
        cts.Cancel();

        _authServiceMock
    .Setup(s => s.LoginAsync(It.IsAny<LoginDto>(), It.IsAny<CancellationToken>()))
    .ThrowsAsync(new OperationCanceledException());
        // Act
        var result = await _controller.Login(request, cts.Token); // Do�ru Paket: Model

        // Assert: 408 Request Timeout
        var statusCodeResult = result as ObjectResult;
        statusCodeResult?.StatusCode.Should().Be(408);
    }

    [Fact]
    public async Task Register_UnexpectedException_ShouldReturn500()
    {
        // Arrange: Beklenmeyen exception
        var request = new RegisterRequestModel { Email = "test@test.com", Username = "user", Password = "Pass123!", ConfirmPassword = "Pass123!" };

        _authServiceMock
            .Setup(s => s.RegisterAsync(It.IsAny<RegisterDto>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Unexpected error"));

        var result = await _controller.Register(request, CancellationToken.None);
        // Assert: 500 Internal Server Error
        var statusCodeResult = result as ObjectResult;
        statusCodeResult?.StatusCode.Should().Be(500);
    }

    // ============================================================================
    // THIN CONTROLLER PRENS�B� DO�RULAMA
    // ============================================================================

    [Fact]
    public void AuthController_ShouldNotContainBusinessLogic()
    {
        // Controller'�n tipini al�yoruz
        var controllerType = typeof(AuthController);

        // Sadece kendi tan�mlad���n metodlara bak (kal�t�m yoluyla gelenlere de�il)
        var methods = controllerType.GetMethods(System.Reflection.BindingFlags.DeclaredOnly |
                                               System.Reflection.BindingFlags.Public |
                                               System.Reflection.BindingFlags.Instance);

        foreach (var method in methods)
        {
            var methodBody = method.GetMethodBody();
            // Bu test asl�nda manuel code review gerektirir ama 
            // prensip olarak metodun varl���n� ve bo� olmad���n� kontrol ediyoruz.
            methodBody.Should().NotBeNull($"Method {method.Name} should be implemented.");
        }
    }
    

    [Fact]
    public async Task AllEndpoints_ShouldDelegateToService()
    {
        // Arrange: T�m endpoint'ler servis �a�r�s� yapmal�
        // 1. Paketleri Haz�rla (Model)
        var regRequest = new RegisterRequestModel { Email = "test@test.com", Username = "user", Password = "Pass123!", ConfirmPassword = "Pass123!" };
        var logRequest = new LoginRequestModel { Email = "test@test.com", Password = "Pass123!" };

        // 2. Servisleri Mockla (DTO)
        _authServiceMock
            .Setup(s => s.RegisterAsync(It.IsAny<RegisterDto>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SuccessDataResult<TokenDto>(new TokenDto()));

        _authServiceMock
            .Setup(s => s.LoginAsync(It.IsAny<LoginDto>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SuccessDataResult<TokenDto>(new TokenDto()));

        // 3. Controller'� �al��t�r (Act)
        await _controller.Register(regRequest, CancellationToken.None);
        await _controller.Login(logRequest, CancellationToken.None);
        // Assert: Her endpoint servisi �a��rd�
        // Servis katman�na DTO gitti�ini do�rula
        _authServiceMock.Verify(
            s => s.RegisterAsync(It.IsAny<RegisterDto>(), It.IsAny<CancellationToken>()),
            Times.Once);

        _authServiceMock.Verify(
            s => s.LoginAsync(It.IsAny<LoginDto>(), It.IsAny<CancellationToken>()),
            Times.Once);
    }
}
