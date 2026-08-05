using System;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using VaultGuard.Domain.Common.Results;
using IResult = VaultGuard.Domain.Common.Results.IResult;
using VaultGuard.WebAPI.Controllers;
using VaultGuard.WebAPI.Common;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Common;

/// <summary>
/// TEST SÜİTİ: BaseController - Response Standardization & Identity Security
/// 
/// GÜVENLİK KAPSAMI:
/// - Response standardization (IResult → HTTP codes)
/// - Identity extraction security (GetCurrentUserId)
/// - Claim-based authorization helpers
/// - Error response sanitization
/// 
/// MİMARİ FOKUSu:
/// - Consistent API responses
/// - HTTP status code mapping accuracy
/// - Secure identity retrieval
/// </summary>
public class BaseControllerTests
{
    private readonly TestController _controller;

    public BaseControllerTests()
    {
        _controller = new TestController();

        // HttpContext simülasyonu
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext()
        };
    }

    // ============================================================================
    // ToResponse(IResult) TESTLERİ - SUCCESS SENARYOLARI
    // ============================================================================

    [Fact]
    public void ToResponse_SuccessResult_ShouldReturn200Ok()
    {
        // Arrange
        var result = new SuccessResult("İşlem başarılı");

        // Act
        var actionResult = _controller.TestToResponse(result);

        // Assert: 200 OK
        actionResult.Should().BeOfType<OkObjectResult>();

        var okResult = actionResult as OkObjectResult;
        okResult.StatusCode.Should().Be(200);
    }

    [Fact]
    public void ToResponse_SuccessResult_ResponseShouldContainSuccessTrue()
    {
        // Arrange
        var result = new SuccessResult("Başarılı");

        // Act
        var actionResult = _controller.TestToResponse(result) as OkObjectResult;

        // Assert: success: true
        var responseValue = actionResult.Value;
        var successProperty = responseValue.GetType().GetProperty("success");
        var successValue = (bool)successProperty.GetValue(responseValue);

        successValue.Should().BeTrue();
    }

    [Fact]
    public void ToResponse_SuccessResult_ResponseShouldContainMessage()
    {
        // Arrange
        var expectedMessage = "İşlem başarıyla tamamlandı";
        var result = new SuccessResult(expectedMessage);

        // Act
        var actionResult = _controller.TestToResponse(result) as OkObjectResult;

        // Assert: message field içeriği
        var responseValue = actionResult.Value;
        var messageProperty = responseValue.GetType().GetProperty("message");
        var messageValue = (string)messageProperty.GetValue(responseValue);

        messageValue.Should().Be(expectedMessage);
    }

    // ============================================================================
    // ToResponse(IResult) TESTLERİ - ERROR SENARYOLARI
    // ============================================================================

    [Fact]
    public void ToResponse_ErrorResult_ShouldReturn400BadRequest()
    {
        // Arrange
        var result = new ErrorResult("Hata oluştu");

        // Act
        var actionResult = _controller.TestToResponse(result);

        // Assert: 400 Bad Request
        actionResult.Should().BeOfType<BadRequestObjectResult>();

        var badRequestResult = actionResult as BadRequestObjectResult;
        badRequestResult.StatusCode.Should().Be(400);
    }

    [Fact]
    public void ToResponse_ErrorResult_ResponseShouldContainSuccessFalse()
    {
        // Arrange
        var result = new ErrorResult("Hata");

        // Act
        var actionResult = _controller.TestToResponse(result) as BadRequestObjectResult;

        // Assert: success: false
        var responseValue = actionResult.Value;
        var successProperty = responseValue.GetType().GetProperty("success");
        var successValue = (bool)successProperty.GetValue(responseValue);

        successValue.Should().BeFalse();
    }

    [Fact]
    public void ToResponse_ErrorResultWithErrorCode_ResponseShouldContainErrorCode()
    {
        // Arrange
        var result = new ErrorResult("Hata", "ERR_VALIDATION");

        // Act
        var actionResult = _controller.TestToResponse(result) as BadRequestObjectResult;

        // Assert: errorCode field
        var responseValue = actionResult.Value;
        var errorCodeProperty = responseValue.GetType().GetProperty("errorCode");
        var errorCodeValue = (string)errorCodeProperty.GetValue(responseValue);

        errorCodeValue.Should().Be("ERR_VALIDATION");
    }

    [Fact]
    public void ToResponse_ErrorResult_ShouldNotExposeInternalErrorDetails()
    {
        // Arrange: InternalErrorDetails var
        var exception = new Exception("Internal server error");
        var result = new ErrorResult("Genel hata", "ERR_500", exception);

        // Act
        var actionResult = _controller.TestToResponse(result) as BadRequestObjectResult;

        // Assert: InternalErrorDetails ASLA response'da olmamalı
        var responseValue = actionResult.Value;
        var properties = responseValue.GetType().GetProperties();

        properties.Should().NotContain(p => p.Name == "internalErrorDetails" || p.Name == "InternalErrorDetails",
            because: "InternalErrorDetails güvenlik riski oluşturur");
    }

    // ============================================================================
    // ToResponse(IDataResult<T>) TESTLERİ - SUCCESS SENARYOLARI
    // ============================================================================

    [Fact]
    public void ToResponse_SuccessDataResult_ShouldReturn200Ok()
    {
        // Arrange
        var data = new TestDto { Id = 1, Name = "Test" };
        var result = new SuccessDataResult<TestDto>(data, "Veri getirildi");

        // Act
        var actionResult = _controller.TestToResponse(result);

        // Assert: 200 OK
        actionResult.Should().BeOfType<OkObjectResult>();

        var okResult = actionResult as OkObjectResult;
        okResult.StatusCode.Should().Be(200);
    }

    [Fact]
    public void ToResponse_SuccessDataResult_ResponseShouldContainData()
    {
        // Arrange
        var data = new TestDto { Id = 123, Name = "TestData" };
        var result = new SuccessDataResult<TestDto>(data);

        // Act
        var actionResult = _controller.TestToResponse(result) as OkObjectResult;

        // Assert: data field
        var responseValue = actionResult.Value;
        var dataProperty = responseValue.GetType().GetProperty("data");
        var dataValue = dataProperty.GetValue(responseValue) as TestDto;

        dataValue.Should().NotBeNull();
        dataValue.Id.Should().Be(123);
        dataValue.Name.Should().Be("TestData");
    }

    [Fact]
    public void ToResponse_SuccessDataResultWithNullData_ShouldReturn404NotFound()
    {
        // Arrange: Data null (kayıt bulunamadı senaryosu)
        var result = new SuccessDataResult<TestDto>(null, "Bulunamadı");

        // Act
        var actionResult = _controller.TestToResponse(result);

        // Assert: 404 Not Found
        actionResult.Should().BeOfType<NotFoundObjectResult>();

        var notFoundResult = actionResult as NotFoundObjectResult;
        notFoundResult.StatusCode.Should().Be(404);
    }

    // ============================================================================
    // ToResponse(IDataResult<T>) TESTLERİ - ERROR SENARYOLARI
    // ============================================================================

    [Fact]
    public void ToResponse_ErrorDataResult_ShouldReturn400BadRequest()
    {
        // Arrange
        var result = new ErrorDataResult<TestDto>("Veri alınamadı");

        // Act
        var actionResult = _controller.TestToResponse(result);

        // Assert: 400 Bad Request
        actionResult.Should().BeOfType<BadRequestObjectResult>();
    }

    [Fact]
    public void ToResponse_ErrorDataResult_ResponseShouldNotContainData()
    {
        // Arrange
        var result = new ErrorDataResult<TestDto>("Hata");

        // Act
        var actionResult = _controller.TestToResponse(result) as BadRequestObjectResult;

        // Assert: data field olmamalı (security best practice)
        var responseValue = actionResult.Value;
        var properties = responseValue.GetType().GetProperties();

        properties.Should().NotContain(p => p.Name == "data",
            because: "Hatalı response'larda data gösterilmemeli");
    }

    // ============================================================================
    // ToResponse(IDataResult<T>, int) TESTLERİ - CUSTOM STATUS CODE
    // ============================================================================

    [Fact]
    public void ToResponse_SuccessDataResultWith201_ShouldReturn201Created()
    {
        // Arrange: Kayıt oluşturma senaryosu
        var data = new TestDto { Id = 1, Name = "Created" };
        var result = new SuccessDataResult<TestDto>(data);

        // Act
        var actionResult = _controller.TestToResponseWithStatusCode(result, 201);

        // Assert: 201 Created
        actionResult.Should().BeOfType<ObjectResult>();

        var objectResult = actionResult as ObjectResult;
        objectResult.StatusCode.Should().Be(201);
    }

    [Fact]
    public void ToResponse_SuccessDataResultWith204_ShouldReturn204NoContent()
    {
        // Arrange: Silme işlemi senaryosu
        var data = new TestDto { Id = 1, Name = "Deleted" };
        var result = new SuccessDataResult<TestDto>(data);

        // Act
        var actionResult = _controller.TestToResponseWithStatusCode(result, 204);

        // Assert: 204 No Content
        var objectResult = actionResult as ObjectResult;
        objectResult.StatusCode.Should().Be(204);
    }

    // ============================================================================
    // Unauthorized() HELPER TESTLERİ
    // ============================================================================

    [Fact]
    public void Unauthorized_WithDefaultMessage_ShouldReturn401()
    {
        // Arrange & Act
        var actionResult = _controller.TestUnauthorized();

        // Assert: 401 Unauthorized
        actionResult.Should().BeOfType<UnauthorizedObjectResult>();

        var unauthorizedResult = actionResult as UnauthorizedObjectResult;
        unauthorizedResult.StatusCode.Should().Be(401);
    }

    [Fact]
    public void Unauthorized_WithDefaultMessage_ResponseShouldContainErrorCode()
    {
        // Arrange & Act
        var actionResult = _controller.TestUnauthorized() as UnauthorizedObjectResult;

        // Assert: errorCode = "ERR_UNAUTHORIZED"
        var responseValue = actionResult.Value;
        var errorCodeProperty = responseValue.GetType().GetProperty("errorCode");
        var errorCodeValue = (string)errorCodeProperty.GetValue(responseValue);

        errorCodeValue.Should().Be("ERR_UNAUTHORIZED");
    }

    [Fact]
    public void Unauthorized_WithCustomMessage_ShouldReturnCustomMessage()
    {
        // Arrange
        var customMessage = "Token süresi dolmuş";

        // Act
        var actionResult = _controller.TestUnauthorizedWithMessage(customMessage) as UnauthorizedObjectResult;

        // Assert
        var responseValue = actionResult.Value;
        var messageProperty = responseValue.GetType().GetProperty("message");
        var messageValue = (string)messageProperty.GetValue(responseValue);

        messageValue.Should().Be(customMessage);
    }

    // ============================================================================
    // Forbidden() HELPER TESTLERİ
    // ============================================================================

    [Fact]
    public void Forbidden_WithDefaultMessage_ShouldReturn403()
    {
        // Arrange & Act
        var actionResult = _controller.TestForbidden();

        // Assert: 403 Forbidden
        actionResult.Should().BeOfType<ObjectResult>();

        var objectResult = actionResult as ObjectResult;
        objectResult.StatusCode.Should().Be(403);
    }

    [Fact]
    public void Forbidden_ResponseShouldContainErrorCode()
    {
        // Arrange & Act
        var actionResult = _controller.TestForbidden() as ObjectResult;

        // Assert: errorCode = "ERR_FORBIDDEN"
        var responseValue = actionResult.Value;
        var errorCodeProperty = responseValue.GetType().GetProperty("errorCode");
        var errorCodeValue = (string)errorCodeProperty.GetValue(responseValue);

        errorCodeValue.Should().Be("ERR_FORBIDDEN");
    }

    // ============================================================================
    // GetCurrentUserId() TESTLERİ - SECURITY CRITICAL
    // ============================================================================

    [Fact]
    public void GetCurrentUserId_WithAuthenticatedUser_ShouldReturnUserId()
    {
        // Arrange: JWT claim'lerinde user ID var
        var expectedUserId = "user-guid-12345";
        SetupAuthenticatedUser(expectedUserId);

        // Act
        var userId = _controller.TestGetCurrentUserId();

        // Assert: User ID doğru çekildi
        userId.Should().Be(expectedUserId);
    }

    [Fact]
    public void GetCurrentUserId_WithUnauthenticatedUser_ShouldReturnNull()
    {
        // Arrange: Claim'ler yok (authenticated değil)
        SetupUnauthenticatedUser();

        // Act
        var userId = _controller.TestGetCurrentUserId();

        // Assert: null dönmeli
        userId.Should().BeNull();
    }

    [Fact]
    public void GetCurrentUserId_WithMissingNameIdentifierClaim_ShouldReturnNull()
    {
        // Arrange: NameIdentifier claim yok (sadece Email var gibi)
        var claims = new[]
        {
            new Claim(ClaimTypes.Email, "test@test.com")
            // NameIdentifier yok
        };

        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);

        _controller.ControllerContext.HttpContext.User = principal;

        // Act
        var userId = _controller.TestGetCurrentUserId();

        // Assert: null dönmeli
        userId.Should().BeNull();
    }

    [Fact]
    public void GetCurrentUserId_WithEmptyNameIdentifier_ShouldReturnEmptyString()
    {
        // Arrange: NameIdentifier claim boş
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, "")
        };

        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);

        _controller.ControllerContext.HttpContext.User = principal;

        // Act
        var userId = _controller.TestGetCurrentUserId();

        // Assert: Boş string dönmeli
        userId.Should().BeEmpty();
    }

    // ============================================================================
    // GetCurrentUsername() TESTLERİ
    // ============================================================================

    [Fact]
    public void GetCurrentUsername_WithAuthenticatedUser_ShouldReturnUsername()
    {
        // Arrange
        var expectedUsername = "testuser";
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, "user-123"),
            new Claim(ClaimTypes.Name, expectedUsername)
        };

        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);

        _controller.ControllerContext.HttpContext.User = principal;

        // Act
        var username = _controller.TestGetCurrentUsername();

        // Assert
        username.Should().Be(expectedUsername);
    }

    [Fact]
    public void GetCurrentUsername_WithUnauthenticatedUser_ShouldReturnNull()
    {
        // Arrange
        SetupUnauthenticatedUser();

        // Act
        var username = _controller.TestGetCurrentUsername();

        // Assert
        username.Should().BeNull();
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private void SetupAuthenticatedUser(string userId)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId),
            new Claim(ClaimTypes.Name, "testuser"),
            new Claim(ClaimTypes.Email, "test@test.com")
        };

        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);

        _controller.ControllerContext.HttpContext.User = principal;
    }

    private void SetupUnauthenticatedUser()
    {
        var identity = new ClaimsIdentity(); // Boş claims
        var principal = new ClaimsPrincipal(identity);

        _controller.ControllerContext.HttpContext.User = principal;
    }
}

// ============================================================================
// TEST CONTROLLER (BaseController'dan türeyen test sınıfı)
// ============================================================================

/// <summary>
/// BaseController'ın protected metodlarını test etmek için wrapper controller
/// </summary>
public class TestController : BaseController
{
    // ToResponse(IResult) test wrapper
    public IActionResult TestToResponse(IResult result)
    {
        return ToResponse(result);
    }

    // ToResponse(IDataResult<T>) test wrapper
    public IActionResult TestToResponse<T>(IDataResult<T> result)
    {
        return ToResponse(result);
    }

    // ToResponse(IDataResult<T>, int) test wrapper
    public IActionResult TestToResponseWithStatusCode<T>(IDataResult<T> result, int statusCode)
    {
        return ToResponse(result, statusCode);
    }

    // Unauthorized() test wrapper
    public IActionResult TestUnauthorized()
    {
        return Unauthorized();
    }

    // Unauthorized(string) test wrapper
    public IActionResult TestUnauthorizedWithMessage(string message)
    {
        return Unauthorized(message);
    }

    // Forbidden() test wrapper
    public IActionResult TestForbidden()
    {
        return Forbidden();
    }

    // GetCurrentUserId() test wrapper
    public string TestGetCurrentUserId()
    {
        return GetCurrentUserId();
    }

    // GetCurrentUsername() test wrapper
    public string TestGetCurrentUsername()
    {
        return GetCurrentUsername();
    }
}

// ============================================================================
// TEST DTO
// ============================================================================

/// <summary>
/// Test için basit DTO
/// </summary>
public class TestDto
{
    public int Id { get; set; }
    public string Name { get; set; }
}