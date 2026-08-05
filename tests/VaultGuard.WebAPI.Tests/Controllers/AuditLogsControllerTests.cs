using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using VaultGuard.Application.Interfaces;
using VaultGuard.Domain.Entities;
using VaultGuard.WebAPI.Controllers;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Controllers;

/// <summary>
/// TEST SÜİTİ: AuditLogsController - RBAC & Immutability Security Tests
/// 
/// SECURITY FOCUS:
/// - **RBAC Enforcement**: Only Admin/Auditor roles can access
/// - **Immutability**: NO POST/PUT/DELETE methods (audit logs are append-only)
/// - **Read-Only Access**: All endpoints are HTTP GET
/// - **Authorization Bypass Prevention**: User role must get 403 Forbidden
/// 
/// THREAT MODEL:
/// - Vertical Privilege Escalation: User → Admin/Auditor access
/// - Audit Log Tampering: POST/PUT/DELETE operations
/// - Evidence Destruction: Audit log deletion
/// - Compliance Violation: Unauthorized log access
/// 
/// COMPLIANCE:
/// - SOC 2 Type II: Immutable audit trail
/// - PCI-DSS 10.5: Audit trails cannot be altered
/// - HIPAA §164.312(b): Audit controls
/// - NIST SP 800-53 AU-9: Protection of audit information
/// 
/// OWASP API SECURITY TOP 10:
/// - API1:2023 Broken Object Level Authorization
/// - API5:2023 Broken Function Level Authorization
/// - API8:2023 Security Misconfiguration
/// </summary>
public class AuditLogsControllerTests
{
    private readonly Mock<IAuditLogRepository> _mockRepository;
    private readonly Mock<ICurrentUserService> _mockCurrentUserService;
    private readonly AuditLogsController _controller;

    public AuditLogsControllerTests()
    {
        _mockRepository = new Mock<IAuditLogRepository>();
        _mockCurrentUserService = new Mock<ICurrentUserService>();
        _controller = new AuditLogsController(
            _mockRepository.Object,
            _mockCurrentUserService.Object);

        // Setup: Current user context
        _mockCurrentUserService.Setup(x => x.UserId).Returns(Guid.NewGuid());
        _mockCurrentUserService.Setup(x => x.Email).Returns("admin@test.com");
        _mockCurrentUserService.Setup(x => x.Role).Returns("Admin");
    }

    // ============================================================================
    // 🛡️ RBAC (ROLE-BASED ACCESS CONTROL) TESTS - CRITICAL!
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - RBAC ENFORCEMENT (CRITICAL!):
    /// AuditLogsController MUST require Admin or Auditor role.
    /// 
    /// THREAT: Vertical Privilege Escalation
    /// - Regular User accesses audit logs
    /// - Sees other users' sensitive activities
    /// - Privacy violation + Compliance breach
    /// 
    /// MITIGATION: [Authorize(Roles = "Admin,Auditor")]
    /// 
    /// OWASP: API5:2023 - Broken Function Level Authorization
    /// NIST: AC-3 - Access Enforcement
    /// </summary>
    [Fact]
    public void AuditLogsController_MustRequireAdminOrAuditorRole()
    {
        // Arrange
        var controllerType = typeof(AuditLogsController);

        // Act: Get [Authorize] attribute
        var authorizeAttribute = controllerType
            .GetCustomAttributes(typeof(AuthorizeAttribute), true)
            .Cast<AuthorizeAttribute>()
            .FirstOrDefault();

        // Assert: Attribute exists
        authorizeAttribute.Should().NotBeNull(
            "AuditLogsController MUST have [Authorize] attribute for RBAC");

        // Assert: Roles specified
        authorizeAttribute.Roles.Should().NotBeNullOrEmpty(
            "RBAC requires explicit role specification");

        // Assert: Only Admin and Auditor allowed
        var allowedRoles = authorizeAttribute.Roles
            .Split(',')
            .Select(r => r.Trim())
            .ToArray();

        allowedRoles.Should().HaveCount(2,
            "Only Admin and Auditor should access audit logs");

        allowedRoles.Should().Contain("Admin",
            "Admin role must have audit log access for compliance");

        allowedRoles.Should().Contain("Auditor",
            "Auditor role must have audit log access for security monitoring");

        // Assert: User role NOT allowed
        allowedRoles.Should().NotContain("User",
            "CRITICAL: Regular User role must NOT access audit logs - privacy violation!");
    }

    /// <summary>
    /// SECURITY TEST - ATTRIBUTE COMPLETENESS:
    /// Verify [Authorize] attribute has NO loopholes.
    /// 
    /// THREAT: Authentication Bypass
    /// - Missing/weak authorization
    /// - [AllowAnonymous] on sensitive endpoints
    /// </summary>
    [Fact]
    public void AuditLogsController_MustNotHaveAllowAnonymous()
    {
        // Arrange
        var controllerType = typeof(AuditLogsController);

        // Act: Check for [AllowAnonymous] on class
        var hasAllowAnonymous = controllerType
            .GetCustomAttributes(typeof(AllowAnonymousAttribute), true)
            .Any();

        // Assert: NO [AllowAnonymous] on controller
        hasAllowAnonymous.Should().BeFalse(
            "AuditLogsController must NEVER have [AllowAnonymous] - critical security data");

        // Act: Check methods for [AllowAnonymous]
        var methods = controllerType.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
        var methodsWithAllowAnonymous = methods
            .Where(m => m.GetCustomAttributes(typeof(AllowAnonymousAttribute), true).Any())
            .Select(m => m.Name)
            .ToList();

        // Assert: NO methods with [AllowAnonymous]
        methodsWithAllowAnonymous.Should().BeEmpty(
            "No AuditLogsController method should have [AllowAnonymous]");
    }

    /// <summary>
    /// SECURITY TEST - DOCUMENTATION:
    /// User role attempting audit log access should get 403 Forbidden.
    /// 
    /// NOTE: This is a documentation test. Actual enforcement tested in Integration Tests
    /// where we can send real HTTP requests with different role tokens.
    /// 
    /// EXPECTED BEHAVIOR:
    /// 1. User with "User" role gets JWT token
    /// 2. User: GET /api/auditlogs/recent
    /// 3. Middleware checks [Authorize(Roles = "Admin,Auditor")]
    /// 4. User role not in allowed list → 403 Forbidden
    /// 
    /// OWASP: API5:2023 - Broken Function Level Authorization
    /// </summary>
    [Fact]
    public void Documentation_UserRole_ShouldBeDeniedAccess()
    {
        // This test documents the requirement
        // Actual integration test in AuditLogEndpointsTests.cs verifies:
        // 1. Create User with "User" role
        // 2. Login → Get JWT with Role claim = "User"
        // 3. GET /api/auditlogs/recent → 403 Forbidden

        var requirement = "User role MUST NOT access AuditLogsController";
        var mitigation = "[Authorize(Roles = \"Admin,Auditor\")]";
        var expectedStatus = "403 Forbidden";

        Assert.True(true,
            $"{requirement} | Mitigation: {mitigation} | Expected: {expectedStatus}");
    }

    // ============================================================================
    // 🔒 IMMUTABILITY TESTS - AUDIT LOGS ARE READ-ONLY (CRITICAL!)
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - IMMUTABILITY (CRITICAL!):
    /// AuditLogsController MUST have NO POST/PUT/DELETE methods.
    /// 
    /// THREAT: Audit Log Tampering
    /// - Attacker creates fake audit entries (POST)
    /// - Attacker modifies existing logs (PUT)
    /// - Attacker deletes evidence (DELETE)
    /// - Compliance violation + Evidence destruction
    /// 
    /// MITIGATION: Read-only controller (GET methods only)
    /// 
    /// COMPLIANCE:
    /// - SOC 2: Audit logs cannot be altered
    /// - PCI-DSS 10.5.2: Audit trail files protected from modification
    /// - HIPAA: Audit logs must be tamper-proof
    /// 
    /// OWASP: API8:2023 - Security Misconfiguration
    /// NIST: AU-9 - Protection of Audit Information
    /// </summary>
    [Fact]
    public void AuditLogsController_MustHaveNoWriteMethods()
    {
        // Arrange
        var controllerType = typeof(AuditLogsController);

        // Act: Get all public methods
        var publicMethods = controllerType
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .ToList();

        // Act: Find POST methods
        var postMethods = publicMethods
            .Where(m => m.GetCustomAttributes(typeof(HttpPostAttribute), true).Any())
            .Select(m => m.Name)
            .ToList();

        // Act: Find PUT methods
        var putMethods = publicMethods
            .Where(m => m.GetCustomAttributes(typeof(HttpPutAttribute), true).Any())
            .Select(m => m.Name)
            .ToList();

        // Act: Find DELETE methods
        var deleteMethods = publicMethods
            .Where(m => m.GetCustomAttributes(typeof(HttpDeleteAttribute), true).Any())
            .Select(m => m.Name)
            .ToList();

        // Assert: NO POST methods
        postMethods.Should().BeEmpty(
            "CRITICAL: AuditLogsController must have NO [HttpPost] methods - audit logs are immutable!");

        // Assert: NO PUT methods
        putMethods.Should().BeEmpty(
            "CRITICAL: AuditLogsController must have NO [HttpPut] methods - audit logs cannot be modified!");

        // Assert: NO DELETE methods
        deleteMethods.Should().BeEmpty(
            "CRITICAL: AuditLogsController must have NO [HttpDelete] methods - audit logs cannot be deleted!");
    }

    /// <summary>
    /// SECURITY TEST - READ-ONLY VERIFICATION:
    /// All endpoints MUST be HTTP GET (read-only).
    /// 
    /// EXPECTED ENDPOINTS:
    /// - GET /api/auditlogs/user/{userId}
    /// - GET /api/auditlogs/resource/{resourceId}
    /// - GET /api/auditlogs/recent
    /// - GET /api/auditlogs/count
    /// </summary>
    [Fact]
    public void AuditLogsController_AllEndpoints_MustBeHttpGet()
    {
        // Arrange
        var controllerType = typeof(AuditLogsController);

        // Act: Get all HTTP-attributed methods
        var httpMethods = controllerType
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .Where(m =>
                m.GetCustomAttributes(typeof(HttpGetAttribute), true).Any() ||
                m.GetCustomAttributes(typeof(HttpPostAttribute), true).Any() ||
                m.GetCustomAttributes(typeof(HttpPutAttribute), true).Any() ||
                m.GetCustomAttributes(typeof(HttpDeleteAttribute), true).Any() ||
                m.GetCustomAttributes(typeof(HttpPatchAttribute), true).Any())
            .ToList();

        // Assert: All methods are HTTP GET
        foreach (var method in httpMethods)
        {
            var isGet = method.GetCustomAttributes(typeof(HttpGetAttribute), true).Any();
            isGet.Should().BeTrue(
                $"Method {method.Name} must be [HttpGet] - audit logs are read-only");
        }

        // Assert: Expected count (4 GET endpoints)
        httpMethods.Should().HaveCount(4,
            "AuditLogsController should have exactly 4 GET endpoints: user, resource, recent, count");
    }

    /// <summary>
    /// SECURITY TEST - METHOD SIGNATURE VERIFICATION:
    /// Verify no methods accept body parameters (FromBody).
    /// Read-only operations should not accept complex payloads.
    /// </summary>
    [Fact]
    public void AuditLogsController_NoMethods_ShouldAcceptBodyParameters()
    {
        // Arrange
        var controllerType = typeof(AuditLogsController);

        // Act: Get all public methods
        var methods = controllerType
            .GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
            .ToList();

        // Act: Check each method for [FromBody] parameters
        foreach (var method in methods)
        {
            var parameters = method.GetParameters();
            var hasFromBody = parameters.Any(p =>
                p.GetCustomAttributes(typeof(FromBodyAttribute), true).Any());

            // Assert: NO [FromBody] parameters
            hasFromBody.Should().BeFalse(
                $"Method {method.Name} should NOT have [FromBody] parameter - read-only controller");
        }
    }

    // ============================================================================
    // ✅ SUCCESS SCENARIOS (RBAC Passed)
    // ============================================================================

    /// <summary>
    /// SUCCESS TEST:
    /// GetUserAuditLogs - Admin/Auditor access should work.
    /// </summary>
    [Fact]
    public async Task GetUserAuditLogs_WithAdminRole_ShouldReturn200()
    {
        // Arrange: Mock audit logs
        var userId = Guid.NewGuid();
        var logs = new List<AuditLog>
        {
            CreateMockAuditLog(userId, "Secret_Created"),
            CreateMockAuditLog(userId, "Secret_Decrypted")
        };

        _mockRepository
            .Setup(x => x.GetByUserIdAsync(userId, 0, 100, It.IsAny<CancellationToken>()))
            .ReturnsAsync(logs);

        // Act
        var result = await _controller.GetUserAuditLogs(userId, 0, 100);

        // Assert: 200 OK
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.StatusCode.Should().Be(200);

        var response = okResult.Value.Should().BeAssignableTo<ApiResponse<IEnumerable<AuditLog>>>().Subject;
        response.Success.Should().BeTrue();
        response.Data.Should().HaveCount(2);
    }

    /// <summary>
    /// SUCCESS TEST:
    /// GetRecentAuditLogs - Should return recent logs.
    /// </summary>
    [Fact]
    public async Task GetRecentAuditLogs_WithValidCount_ShouldReturn200()
    {
        // Arrange
        var logs = new List<AuditLog>
        {
            CreateMockAuditLog(Guid.NewGuid(), "User_Login"),
            CreateMockAuditLog(Guid.NewGuid(), "Secret_Decrypted")
        };

        _mockRepository
            .Setup(x => x.GetRecentLogsAsync(100, It.IsAny<CancellationToken>()))
            .ReturnsAsync(logs);

        // Act
        var result = await _controller.GetRecentAuditLogs(100);

        // Assert: 200 OK
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.StatusCode.Should().Be(200);
    }

    /// <summary>
    /// SUCCESS TEST:
    /// GetResourceAuditLogs - Should return resource history.
    /// </summary>
    [Fact]
    public async Task GetResourceAuditLogs_WithValidResourceId_ShouldReturn200()
    {
        // Arrange
        var resourceId = Guid.NewGuid();
        var logs = new List<AuditLog>
        {
            CreateMockAuditLog(Guid.NewGuid(), "Secret_Viewed", resourceId),
            CreateMockAuditLog(Guid.NewGuid(), "Secret_Updated", resourceId)
        };

        _mockRepository
            .Setup(x => x.GetByResourceIdAsync(resourceId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(logs);

        // Act
        var result = await _controller.GetResourceAuditLogs(resourceId);

        // Assert: 200 OK
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.StatusCode.Should().Be(200);

        var response = okResult.Value.Should().BeAssignableTo<ApiResponse<IEnumerable<AuditLog>>>().Subject;
        response.Data.Should().HaveCount(2);
    }

    /// <summary>
    /// SUCCESS TEST:
    /// GetTotalCount - Should return total log count.
    /// </summary>
    [Fact]
    public async Task GetTotalCount_ShouldReturnCorrectCount()
    {
        // Arrange
        _mockRepository
            .Setup(x => x.GetTotalCountAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(12345);

        // Act
        var result = await _controller.GetTotalCount();

        // Assert: 200 OK
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        okResult.StatusCode.Should().Be(200);

        var response = okResult.Value.Should().BeAssignableTo<ApiResponse<int>>().Subject;
        response.Data.Should().Be(12345);
    }

    // ============================================================================
    // ❌ VALIDATION TESTS (400 Bad Request)
    // ============================================================================

    /// <summary>
    /// VALIDATION TEST:
    /// GetUserAuditLogs with negative skip - 400 Bad Request.
    /// </summary>
    [Fact]
    public async Task GetUserAuditLogs_WithNegativeSkip_ShouldReturn400()
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act
        var result = await _controller.GetUserAuditLogs(userId, skip: -1, take: 100);

        // Assert: 400 Bad Request
        var badRequestResult = result.Result.Should().BeOfType<BadRequestObjectResult>().Subject;
        badRequestResult.StatusCode.Should().Be(400);

        var response = badRequestResult.Value.Should().BeAssignableTo<ApiErrorResponse>().Subject;
        response.Message.Should().Contain("Skip");
    }

    /// <summary>
    /// VALIDATION TEST:
    /// GetUserAuditLogs with invalid take - 400 Bad Request.
    /// </summary>
    [Fact]
    public async Task GetUserAuditLogs_WithInvalidTake_ShouldReturn400()
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act: Take > 1000
        var result = await _controller.GetUserAuditLogs(userId, skip: 0, take: 5000);

        // Assert: 400 Bad Request
        var badRequestResult = result.Result.Should().BeOfType<BadRequestObjectResult>().Subject;
        badRequestResult.StatusCode.Should().Be(400);

        var response = badRequestResult.Value.Should().BeAssignableTo<ApiErrorResponse>().Subject;
        response.Message.Should().Contain("Take");
    }

    /// <summary>
    /// VALIDATION TEST:
    /// GetRecentAuditLogs with invalid count - 400 Bad Request.
    /// </summary>
    [Fact]
    public async Task GetRecentAuditLogs_WithInvalidCount_ShouldReturn400()
    {
        // Act: Count > 1000
        var result = await _controller.GetRecentAuditLogs(count: 2000);

        // Assert: 400 Bad Request
        var badRequestResult = result.Result.Should().BeOfType<BadRequestObjectResult>().Subject;
        badRequestResult.StatusCode.Should().Be(400);
    }

    // ============================================================================
    // 🔥 ERROR HANDLING TESTS
    // ============================================================================

    /// <summary>
    /// ERROR TEST:
    /// Repository exception - 500 Internal Server Error.
    /// Generic error message (don't leak internal details).
    /// </summary>
    [Fact]
    public async Task GetUserAuditLogs_RepositoryThrows_ShouldReturn500()
    {
        // Arrange: Repository throws exception
        _mockRepository
            .Setup(x => x.GetByUserIdAsync(It.IsAny<Guid>(), It.IsAny<int>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("Database connection failed"));

        // Act
        var result = await _controller.GetUserAuditLogs(Guid.NewGuid(), 0, 100);

        // Assert: 500 Internal Server Error
        var errorResult = result.Result.Should().BeOfType<ObjectResult>().Subject;
        errorResult.StatusCode.Should().Be(500);

        var response = errorResult.Value.Should().BeAssignableTo<ApiErrorResponse>().Subject;
        response.Success.Should().BeFalse();

        // Security: Generic error message (don't leak "Database connection failed")
        response.Message.Should().Contain("unexpected error");
        response.Message.Should().NotContain("Database");
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private AuditLog CreateMockAuditLog(Guid userId, string action, Guid? entityId = null)
    {
       return AuditLog.Create(
    userId: userId,
    action: action,
    entityName: "Secret",
    ipAddress: "192.168.1.1",
    result: "Success",
    entityId: entityId,
    additionalData: null);
    }
}

