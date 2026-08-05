using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using VaultGuard.Application.DTOs.Secrets;
using VaultGuard.Application.Interfaces;
using VaultGuard.Domain.Common.Results;
using VaultGuard.WebAPI.Controllers;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Controllers;

/// <summary>
/// TEST SÜİTİ: SecretsController - API Security Unit Tests
/// 
/// SECURITY FOCUS:
/// - **Ownership Verification**: User SADECE kendi secret'larını görür
/// - **IDOR Protection**: Başkasının secret'ı 403 Forbidden döner
/// - **Input Validation**: Eksik/invalid data 400 Bad Request döner
/// - **Authorization**: Tüm endpoint'ler [Authorize] attribute gerektirir
/// 
/// THREAT MODEL:
/// - Horizontal Privilege Escalation: User A → User B secret access
/// - IDOR Attack: Secret ID manipulation
/// - Injection Attacks: XSS, SQL injection via input
/// - Authentication Bypass: Invalid/missing JWT
/// 
/// TEST APPROACH:
/// - Mock ISecretService & ICurrentUserService
/// - Test controller logic (not service logic)
/// - Verify HTTP status codes
/// - Verify response structure
/// </summary>
public class SecretsControllerTests
{
    private readonly Mock<ISecretService> _mockSecretService;
    private readonly Mock<ICurrentUserService> _mockCurrentUserService;
    private readonly SecretsController _controller;
    private readonly Guid _currentUserId;

    public SecretsControllerTests()
    {
        _mockSecretService = new Mock<ISecretService>();
        _mockCurrentUserService = new Mock<ICurrentUserService>();
        _controller = new SecretsController(_mockSecretService.Object, _mockCurrentUserService.Object);

        // Setup: Current authenticated user
        _currentUserId = Guid.NewGuid();
        _mockCurrentUserService.Setup(x => x.UserId).Returns(_currentUserId);
        _mockCurrentUserService.Setup(x => x.Email).Returns("test@vaultguard.com");
    }

    // ============================================================================
    // ✅ OWNERSHIP VERIFICATION TESTS (KRİTİK!)
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - OWNERSHIP VERIFICATION KRİTİK:
    /// GetAllSecrets - User SADECE kendi secret'larını listeler.
    /// 
    /// THREAT: Horizontal Privilege Escalation
    /// - User A calls GET /api/secrets
    /// - System returns User B, C, D secrets → DATA BREACH!
    /// 
    /// MITIGATION: Service layer filters by UserId
    /// </summary>
    [Fact]
    public async Task GetAllSecrets_ShouldReturnOnlyCurrentUserSecrets()
    {
        // Arrange: Mock service returns user's secrets
        var expectedSecrets = new List<SecretDto>
        {
            new SecretDto { Id = Guid.NewGuid(), Title = "My Secret 1" },
            new SecretDto { Id = Guid.NewGuid(), Title = "My Secret 2" }
        };

        _mockSecretService
            .Setup(x => x.GetSecretsByUserIdAsync(_currentUserId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SuccessDataResult<IEnumerable<SecretDto>>(
                expectedSecrets,
                "Secrets retrieved successfully"));

        // Act
        var result = await _controller.GetAllSecrets();

        // Assert: 200 OK
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.StatusCode.Should().Be(200);

        // Verify: Service called with correct UserId
        _mockSecretService.Verify(
            x => x.GetSecretsByUserIdAsync(_currentUserId, It.IsAny<CancellationToken>()),
            Times.Once);

        // Verify: Response contains user's secrets
        var response = okResult.Value.Should().BeAssignableTo<ApiResponse<IEnumerable<SecretDto>>>().Subject;
        response.Success.Should().BeTrue();
        response.Data.Should().HaveCount(2);
        response.Data.Should().BeEquivalentTo(expectedSecrets);
    }

    /// <summary>
    /// SECURITY TEST - NO AUTHENTICATED USER:
    /// GetAllSecrets without UserId - 401 Unauthorized.
    /// </summary>
    [Fact]
    public async Task GetAllSecrets_WithoutAuthenticatedUser_ShouldReturn401()
    {
        // Arrange: No authenticated user
        _mockCurrentUserService.Setup(x => x.UserId).Returns((Guid?)null);

        // Act
        var result = await _controller.GetAllSecrets();

        // Assert: 401 Unauthorized
        var unauthorizedResult = result.Result.Should().BeOfType<UnauthorizedObjectResult>().Subject;
        unauthorizedResult.StatusCode.Should().Be(401);

        var response = unauthorizedResult.Value.Should().BeAssignableTo<ApiErrorResponse>().Subject;
        response.Success.Should().BeFalse();
        response.Message.Should().Contain("authentication");
    }

    // ============================================================================
    // 🔒 IDOR PROTECTION TESTS (KRİTİK!)
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - IDOR PROTECTION KRİTİK:
    /// GetSecretById - Başkasının secret'ı 403 Forbidden.
    /// 
    /// IDOR ATTACK:
    /// - User A knows User B's secret ID (from URL, log, etc.)
    /// - User A: GET /api/secrets/{UserB_SecretId}
    /// - Expected: 403 Forbidden (not 404!)
    /// - Actual (if vulnerable): 200 OK with User B's data → BREACH!
    /// 
    /// MITIGATION: Service layer authorization check
    /// </summary>
    [Fact]
    public async Task GetSecretById_OtherUserSecret_ShouldReturn403Forbidden()
    {
        // Arrange: Secret belongs to another user
        var otherUserSecretId = Guid.NewGuid();

        _mockSecretService
            .Setup(x => x.GetSecretByIdAsync(otherUserSecretId, It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ErrorDataResult<SecretDto>(
                "You do not have permission to access this secret."));

        // Act
        var result = await _controller.GetSecretById(otherUserSecretId);

        // Assert: 403 Forbidden
        var forbiddenResult = result.Result.Should().BeOfType<ObjectResult>().Subject;
        forbiddenResult.StatusCode.Should().Be(403);

        var response = forbiddenResult.Value.Should().BeAssignableTo<ApiErrorResponse>().Subject;
        response.Success.Should().BeFalse();
        response.Message.Should().Contain("permission");
    }

    /// <summary>
    /// SECURITY TEST - IDOR WITH 404:
    /// GetSecretById - Non-existent secret 404 Not Found.
    /// 
    /// SECURITY DECISION: 403 vs 404?
    /// - 403: "You're not authorized" (reveals secret exists)
    /// - 404: "Not found" (doesn't reveal existence)
    /// 
    /// RECOMMENDATION: 404 for better security (don't leak info)
    /// </summary>
    [Fact]
    public async Task GetSecretById_NonExistentSecret_ShouldReturn404()
    {
        // Arrange: Secret doesn't exist
        var nonExistentId = Guid.NewGuid();

        _mockSecretService
            .Setup(x => x.GetSecretByIdAsync(nonExistentId, It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ErrorDataResult<SecretDto>("Secret not found."));

        // Act
        var result = await _controller.GetSecretById(nonExistentId);

        // Assert: 404 Not Found
        var notFoundResult = result.Result.Should().BeOfType<NotFoundObjectResult>().Subject;
        notFoundResult.StatusCode.Should().Be(404);

        var response = notFoundResult.Value.Should().BeAssignableTo<ApiErrorResponse>().Subject;
        response.Success.Should().BeFalse();
        response.Message.Should().Contain("not found");
    }

    /// <summary>
    /// SECURITY TEST - DECRYPT IDOR:
    /// DecryptSecret - Other user's secret 403 Forbidden.
    /// CRITICAL: Decrypt is most sensitive operation!
    /// </summary>
    [Fact]
    public async Task DecryptSecret_OtherUserSecret_ShouldReturn403()
    {
        // Arrange
        var otherUserSecretId = Guid.NewGuid();

        _mockSecretService
            .Setup(x => x.GetDecryptedValueAsync(otherUserSecretId, It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ErrorDataResult<string>(
                "You are not authorized to decrypt this secret."));

        // Act
        var result = await _controller.DecryptSecret(otherUserSecretId);

        // Assert: 403 Forbidden
        var forbiddenResult = result.Result.Should().BeOfType<ObjectResult>().Subject;
        forbiddenResult.StatusCode.Should().Be(403);
    }

    // ============================================================================
    // ❌ INPUT VALIDATION TESTS (400 Bad Request)
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - INPUT VALIDATION:
    /// CreateSecret with invalid model - 400 Bad Request.
    /// 
    /// VALIDATION SCENARIOS:
    /// - Missing required fields (Title, RawValue)
    /// - Too long fields (DoS prevention)
    /// - XSS payloads (script tags)
    /// - SQL injection attempts
    /// </summary>
    [Fact]
    public async Task CreateSecret_WithInvalidModel_ShouldReturn400()
    {
        // Arrange: Invalid model state
        _controller.ModelState.AddModelError("Title", "Title is required");
        _controller.ModelState.AddModelError("RawValue", "RawValue is required");

        var invalidDto = new CreateSecretDto
        {
            Title = "", // Missing
            RawValue = "" // Missing
        };

        // Act
        var result = await _controller.CreateSecret(invalidDto);

        // Assert: 400 Bad Request
        var badRequestResult = result.Result.Should().BeOfType<BadRequestObjectResult>().Subject;
        badRequestResult.StatusCode.Should().Be(400);

        var response = badRequestResult.Value.Should().BeAssignableTo<ApiErrorResponse>().Subject;
        response.Success.Should().BeFalse();
        response.Message.Should().Contain("Validation failed");
        response.Errors.Should().NotBeNull();
    }

    /// <summary>
    /// SECURITY TEST - DUPLICATE TITLE:
    /// CreateSecret with duplicate title - 400 Bad Request.
    /// Business rule: Title must be unique per user.
    /// </summary>
    [Fact]
    public async Task CreateSecret_WithDuplicateTitle_ShouldReturn400()
    {
        // Arrange: Service rejects duplicate
        var dto = new CreateSecretDto
        {
            Title = "Existing Title",
            RawValue = "password123"
        };

        _mockSecretService
            .Setup(x => x.CreateSecretAsync(dto, It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ErrorDataResult<SecretDto>(
                "A secret with this title already exists."));

        // Act
        var result = await _controller.CreateSecret(dto);

        // Assert: 400 Bad Request
        var badRequestResult = result.Result.Should().BeOfType<BadRequestObjectResult>().Subject;
        badRequestResult.StatusCode.Should().Be(400);
    }

    /// <summary>
    /// SECURITY TEST - QUOTA EXCEEDED:
    /// CreateSecret when quota exceeded - 400 Bad Request.
    /// DoS prevention: Max 1000 secrets per user.
    /// </summary>
    [Fact]
    public async Task CreateSecret_QuotaExceeded_ShouldReturn400()
    {
        // Arrange: Quota exceeded
        var dto = new CreateSecretDto
        {
            Title = "New Secret",
            RawValue = "password123"
        };

        _mockSecretService
            .Setup(x => x.CreateSecretAsync(dto, It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ErrorDataResult<SecretDto>(
                "You have reached the maximum limit of 1000 secrets."));

        // Act
        var result = await _controller.CreateSecret(dto);

        // Assert: 400 Bad Request
        var badRequestResult = result.Result.Should().BeOfType<BadRequestObjectResult>().Subject;
        badRequestResult.StatusCode.Should().Be(400);

        var response = badRequestResult.Value.Should().BeAssignableTo<ApiErrorResponse>().Subject;
        response.Message.Should().Contain("maximum limit");
    }

    // ============================================================================
    // ✅ SUCCESS SCENARIOS
    // ============================================================================

    /// <summary>
    /// SUCCESS TEST:
    /// GetSecretById - Own secret returns 200 OK.
    /// </summary>
    [Fact]
    public async Task GetSecretById_OwnSecret_ShouldReturn200()
    {
        // Arrange
        var secretId = Guid.NewGuid();
        var expectedSecret = new SecretDto
        {
            Id = secretId,
            Title = "My Secret",
            EncryptedValue = "encrypted_data_here"
        };

        _mockSecretService
            .Setup(x => x.GetSecretByIdAsync(secretId, It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SuccessDataResult<SecretDto>(
                expectedSecret,
                "Secret retrieved successfully"));

        // Act
        var result = await _controller.GetSecretById(secretId);

        // Assert: 200 OK
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.StatusCode.Should().Be(200);

        var response = okResult.Value.Should().BeAssignableTo<ApiResponse<SecretDto>>().Subject;
        response.Success.Should().BeTrue();
        response.Data.Should().BeEquivalentTo(expectedSecret);
    }

    /// <summary>
    /// SUCCESS TEST:
    /// DecryptSecret - Own secret returns 200 OK with plaintext.
    /// </summary>
    [Fact]
    public async Task DecryptSecret_OwnSecret_ShouldReturn200WithPlaintext()
    {
        // Arrange
        var secretId = Guid.NewGuid();
        var plaintextValue = "MyS3cr3tP@ssw0rd!";

        _mockSecretService
            .Setup(x => x.GetDecryptedValueAsync(secretId, It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SuccessDataResult<string>(
                plaintextValue,
                "Secret decrypted successfully"));

        // Act
        var result = await _controller.DecryptSecret(secretId);

        // Assert: 200 OK
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.StatusCode.Should().Be(200);

        var response = okResult.Value.Should().BeAssignableTo<ApiResponse<string>>().Subject;
        response.Success.Should().BeTrue();
        response.Data.Should().Be(plaintextValue);
    }

    /// <summary>
    /// SUCCESS TEST:
    /// CreateSecret - Valid data returns 201 Created.
    /// </summary>
    [Fact]
    public async Task CreateSecret_ValidData_ShouldReturn201Created()
    {
        // Arrange
        var dto = new CreateSecretDto
        {
            Title = "New Secret",
            RawValue = "password123",
            Description = "Test description"
        };

        var createdSecret = new SecretDto
        {
            Id = Guid.NewGuid(),
            Title = dto.Title,
            Description = dto.Description
        };

        _mockSecretService
            .Setup(x => x.CreateSecretAsync(dto, It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SuccessDataResult<SecretDto>(
                createdSecret,
                "Secret created successfully"));

        // Act
        var result = await _controller.CreateSecret(dto);

        // Assert: 201 Created
        var createdResult = result.Result.Should().BeOfType<CreatedAtActionResult>().Subject;
        createdResult.StatusCode.Should().Be(201);
        createdResult.ActionName.Should().Be(nameof(SecretsController.GetSecretById));
        createdResult.RouteValues["id"].Should().Be(createdSecret.Id);

        var response = createdResult.Value.Should().BeAssignableTo<ApiResponse<SecretDto>>().Subject;
        response.Success.Should().BeTrue();
        response.Data.Should().BeEquivalentTo(createdSecret);
    }

    /// <summary>
    /// SUCCESS TEST:
    /// UpdateSecret - Valid data returns 200 OK.
    /// </summary>
    [Fact]
    public async Task UpdateSecret_ValidData_ShouldReturn200()
    {
        // Arrange
        var dto = new UpdateSecretDto
        {
            Id = Guid.NewGuid(),
            Title = "Updated Title"
        };

        var updatedSecret = new SecretDto
        {
            Id = dto.Id,
            Title = dto.Title
        };

        _mockSecretService
            .Setup(x => x.UpdateSecretAsync(dto, It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SuccessDataResult<SecretDto>(
                updatedSecret,
                "Secret updated successfully"));

        // Act
        var result = await _controller.UpdateSecret(dto);

        // Assert: 200 OK
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.StatusCode.Should().Be(200);
    }

    /// <summary>
    /// SUCCESS TEST:
    /// DeleteSecret - Own secret returns 200 OK.
    /// </summary>
    [Fact]
    public async Task DeleteSecret_OwnSecret_ShouldReturn200()
    {
        // Arrange
        var secretId = Guid.NewGuid();

        _mockSecretService
            .Setup(x => x.DeleteSecretAsync(secretId, It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new SuccessResult("Secret deleted successfully"));

        // Act
        var result = await _controller.DeleteSecret(secretId);

        // Assert: 200 OK
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.StatusCode.Should().Be(200);
    }

    // ============================================================================
    // ⏰ EXPIRATION TESTS
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - EXPIRED SECRET:
    /// DecryptSecret - Expired secret returns 410 Gone.
    /// </summary>
    [Fact]
    public async Task DecryptSecret_ExpiredSecret_ShouldReturn410Gone()
    {
        // Arrange: Secret expired
        var secretId = Guid.NewGuid();

        _mockSecretService
            .Setup(x => x.GetDecryptedValueAsync(secretId, It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ErrorDataResult<string>(
                "This secret has expired and can no longer be decrypted."));

        // Act
        var result = await _controller.DecryptSecret(secretId);

        // Assert: 410 Gone
        var goneResult = result.Result.Should().BeOfType<ObjectResult>().Subject;
        goneResult.StatusCode.Should().Be(410);

        var response = goneResult.Value.Should().BeAssignableTo<ApiErrorResponse>().Subject;
        response.Message.Should().Contain("expired");
    }

    // ============================================================================
    // 🔥 ERROR HANDLING TESTS
    // ============================================================================

    /// <summary>
    /// ERROR TEST:
    /// GetAllSecrets - Service exception returns 500.
    /// Security: Don't leak internal error details.
    /// </summary>
    [Fact]
    public async Task GetAllSecrets_ServiceThrows_ShouldReturn500()
    {
        // Arrange: Service throws exception
        _mockSecretService
            .Setup(x => x.GetSecretsByUserIdAsync(_currentUserId, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Database connection failed"));

        // Act
        var result = await _controller.GetAllSecrets();

        // Assert: 500 Internal Server Error
        var errorResult = result.Result.Should().BeOfType<ObjectResult>().Subject;
        errorResult.StatusCode.Should().Be(500);

        var response = errorResult.Value.Should().BeAssignableTo<ApiErrorResponse>().Subject;
        response.Success.Should().BeFalse();
        // Security: Generic error message (don't leak "Database connection failed")
        response.Message.Should().Contain("unexpected error");
        response.Message.Should().NotContain("Database");
    }
}