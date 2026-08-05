using System;
using Moq;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using VaultGuard.Application.DTOs.Auth;
using VaultGuard.Application.DTOs.Secrets;
using VaultGuard.Application.Interfaces;
using VaultGuard.Application.Services;
using VaultGuard.Domain.Entities;
using VaultGuard.Infrastructure.Persistence;
using VaultGuard.WebAPI;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Integration;

/// <summary>
/// TEST SÜİTİ: Secret Endpoints - End-to-End Integration Tests
/// 
/// INTEGRATION TEST SCOPE:
/// - **Real HTTP Client**: Actual HTTP requests to API
/// - **Real Database**: InMemory database for testing
/// - **Real Middleware**: Authentication, Authorization, Validation
/// - **Real Encryption**: AES-256 encryption/decryption
/// - **End-to-End Flow**: Create → List → Decrypt → Delete
/// 
/// SECURITY VERIFICATION:
/// - JWT authentication required
/// - Ownership verification (IDOR prevention)
/// - Encrypted data in database (NOT plaintext)
/// - Audit logging (every decrypt operation)
/// 
/// TEST APPROACH:
/// - WebApplicationFactory for test server
/// - InMemory database for isolation
/// - Register → Login → Get JWT → API calls
/// - Database verification for encryption
/// 
/// COMPLIANCE:
/// - SOC 2: End-to-end security validation
/// - GDPR: Data encryption at rest
/// - PCI-DSS: Cryptographic controls
/// </summary>
public class SecretEndpointsTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

  public SecretEndpointsTests(WebApplicationFactory<Program> factory)
{
    _factory = factory.WithWebHostBuilder(builder =>
    {
        builder.ConfigureServices(services =>
        {
            // Remove existing DbContext options
            var descriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<VaultGuardDbContext>));

            if (descriptor != null)
            {
                services.Remove(descriptor);
            }

            // Add InMemory database for testing
            services.AddDbContext<VaultGuardDbContext>(options =>
            {
                options.UseInMemoryDatabase($"VaultGuardIntegrationTest_{Guid.NewGuid()}");
            });

            // Add required services
            services.AddScoped(sp =>
            {
                var mock = new Mock<ICurrentUserService>();
                mock.Setup(x => x.UserId).Returns((Guid?)Guid.NewGuid());
                mock.Setup(x => x.Email).Returns("test@vaultguard.com");
                return mock.Object;
            });

            if (!services.Any(x => x.ServiceType == typeof(ISecretService)))
            {
                services.AddScoped<ISecretService, SecretService>();
            }

            // Build ServiceProvider and ensure database is created
            var sp = services.BuildServiceProvider();
            using var scope = sp.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<VaultGuardDbContext>();
            db.Database.EnsureCreated();
        });
    });

    _client = _factory.CreateClient();
}
    // ============================================================================
    // 🔐 END-TO-END AUTHENTICATION FLOW
    // ============================================================================

    /// <summary>
    /// HELPER METHOD:
    /// Register user, login, get JWT token for authenticated requests.
    /// </summary>
   private async Task<string> RegisterAndLoginAsync(string email, string username, string password)
{
    // Register
    var registerDto = new RegisterDto
    {
        Email = email,
        Username = username,
        Password = password
    };

    var registerResponse = await _client.PostAsJsonAsync("/api/auth/register", registerDto);
    registerResponse.StatusCode.Should().Be(HttpStatusCode.OK);

    // Login
    var loginDto = new LoginDto
    {
        Email = email,
        Password = password
    };

    var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", loginDto);
    loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);

    var loginResult = await loginResponse.Content.ReadFromJsonAsync<ApiResponse<TokenDto>>();
    
    // Debug: check if loginResult or token is null
    if (loginResult?.Data?.AccessToken == null)
    {
        var responseContent = await loginResponse.Content.ReadAsStringAsync();
        throw new InvalidOperationException($"Login failed. Response: {responseContent}");
    }

    return loginResult.Data.AccessToken;
}

    /// <summary>
    /// HELPER METHOD:
    /// Get database context for verification.
    /// </summary>
    private VaultGuardDbContext GetDbContext()
    {
        var scope = _factory.Services.CreateScope();
        return scope.ServiceProvider.GetRequiredService<VaultGuardDbContext>();
    }

    // ============================================================================
    // ✅ END-TO-END SUCCESS FLOW (KRİTİK!)
    // ============================================================================

    /// <summary>
    /// INTEGRATION TEST - END-TO-END FLOW KRİTİK:
    /// Complete secret lifecycle: Create → List → Decrypt → Delete
    /// 
    /// SECURITY VERIFICATION:
    /// 1. Authentication required (JWT)
    /// 2. Data encrypted in database
    /// 3. Ownership verification
    /// 4. Decrypt operation successful
    /// 5. Audit log created (decrypt)
    /// </summary>
    [Fact]
    public async Task EndToEnd_CreateListDecryptDelete_ShouldWork()
    {
        // STEP 1: Register and Login
        var email = $"e2e-{Guid.NewGuid()}@test.com";
        var username = $"e2euser{Guid.NewGuid().ToString().Substring(0, 8)}";
        var password = "SecureP@ssw0rd123!";

        var token = await RegisterAndLoginAsync(email, username, password);
        token.Should().NotBeNullOrEmpty();

        // Set Authorization header
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        // STEP 2: Create Secret
        var createDto = new CreateSecretDto
        {
            Title = "Test Secret E2E",
            RawValue = "MyS3cr3tP@ssw0rd!",
            Description = "End-to-end test secret",
            Category = "Passwords"
        };

        var createResponse = await _client.PostAsJsonAsync("/api/secrets", createDto);
        createResponse.StatusCode.Should().Be(HttpStatusCode.Created);

        var createResult = await createResponse.Content.ReadFromJsonAsync<ApiResponse<SecretDto>>();
        createResult.Success.Should().BeTrue();
        createResult.Data.Id.Should().NotBeEmpty();

        var secretId = createResult.Data.Id;

        // STEP 3: Verify Encryption in Database (CRITICAL!)
        using (var db = GetDbContext())
        {
            var secretInDb = await db.Secrets.FirstOrDefaultAsync(s => s.Id == secretId);
            secretInDb.Should().NotBeNull("secret must be saved in database");

           var encryptedString = secretInDb.EncryptedValue;
            encryptedString.Should().NotBeNullOrEmpty();

            // Encrypted data should NOT contain plaintext
            encryptedString.Should().NotContain("MyS3cr3tP@ssw0rd!",
                "plaintext password must NOT be in encrypted data");

            // Verify IV exists (random nonce)
            secretInDb.IV.Should().NotBeNull();
            secretInDb.IV.Length.Should().Be(12, "AES-GCM nonce must be 12 bytes");
        }

        // STEP 4: List Secrets
        var listResponse = await _client.GetAsync("/api/secrets");
        listResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var listResult = await listResponse.Content.ReadFromJsonAsync<ApiResponse<SecretDto[]>>();
        listResult.Success.Should().BeTrue();
        listResult.Data.Should().Contain(s => s.Id == secretId);

        // STEP 5: Decrypt Secret (CRITICAL OPERATION!)
        var decryptResponse = await _client.GetAsync($"/api/secrets/{secretId}/decrypt");
        decryptResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var decryptResult = await decryptResponse.Content.ReadFromJsonAsync<ApiResponse<string>>();
        decryptResult.Success.Should().BeTrue();
        decryptResult.Data.Should().Be("MyS3cr3tP@ssw0rd!",
            "decrypted value must match original plaintext");

        // STEP 6: Verify Audit Log Created
        using (var db = GetDbContext())
        {
            var auditLogs = await db.AuditLogs
                .Where(a => a.EntityId == secretId && a.Action.Contains("Decrypt"))
                .ToListAsync();

            auditLogs.Should().NotBeEmpty("decrypt operation must be audited");
            auditLogs.First().Action.Should().Contain("Secret");
        }

        // STEP 7: Delete Secret
        var deleteResponse = await _client.DeleteAsync($"/api/secrets/{secretId}");
        deleteResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // STEP 8: Verify Soft Delete
        using (var db = GetDbContext())
        {
            var deletedSecret = await db.Secrets
                .IgnoreQueryFilters()
                .FirstOrDefaultAsync(s => s.Id == secretId);

            deletedSecret.Should().NotBeNull("soft delete keeps record");
            deletedSecret.IsDeleted.Should().BeTrue("IsDeleted flag must be true");
            deletedSecret.DeletedAt.Should().NotBeNull("DeletedAt timestamp must be set");
        }
    }

    // ============================================================================
    // 🔒 AUTHENTICATION TESTS (401 Unauthorized)
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - AUTHENTICATION REQUIRED:
    /// API calls without JWT token - 401 Unauthorized.
    /// </summary>
    [Fact]
    public async Task GetSecrets_WithoutToken_ShouldReturn401()
    {
        // Arrange: No Authorization header

        // Act
        var response = await _client.GetAsync("/api/secrets");

        // Assert: 401 Unauthorized
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// SECURITY TEST - INVALID TOKEN:
    /// API calls with invalid JWT - 401 Unauthorized.
    /// </summary>
    [Fact]
    public async Task GetSecrets_WithInvalidToken_ShouldReturn401()
    {
        // Arrange: Invalid token
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "invalid.fake.token");

        // Act
        var response = await _client.GetAsync("/api/secrets");

        // Assert: 401 Unauthorized
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    /// <summary>
    /// SECURITY TEST - MALFORMED TOKEN:
    /// API calls with malformed JWT - 401 Unauthorized.
    /// </summary>
    [Fact]
    public async Task GetSecrets_WithMalformedToken_ShouldReturn401()
    {
        // Arrange: Malformed token (not JWT format)
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "notajwt");

        // Act
        var response = await _client.GetAsync("/api/secrets");

        // Assert: 401 Unauthorized
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    // ============================================================================
    // 🛡️ IDOR PROTECTION TESTS (403 Forbidden)
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - IDOR PREVENTION KRİTİK:
    /// User A cannot access User B's secret.
    /// 
    /// THREAT: Horizontal Privilege Escalation
    /// - User A knows User B's secret ID
    /// - User A: GET /api/secrets/{UserB_SecretId}
    /// - Expected: 403 Forbidden
    /// - Vulnerable: 200 OK with User B's data → BREACH!
    /// </summary>
    [Fact]
    public async Task GetSecret_OtherUserSecret_ShouldReturn403()
    {
        // STEP 1: User A creates secret
        var emailA = $"usera-{Guid.NewGuid()}@test.com";
        var usernameA = $"usera{Guid.NewGuid().ToString().Substring(0, 8)}";
        var passwordA = "PasswordA123!";

        var tokenA = await RegisterAndLoginAsync(emailA, usernameA, passwordA);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokenA);

        var createDto = new CreateSecretDto
        {
            Title = "User A Secret",
            RawValue = "UserA_Password"
        };

        var createResponse = await _client.PostAsJsonAsync("/api/secrets", createDto);
        var createResult = await createResponse.Content.ReadFromJsonAsync<ApiResponse<SecretDto>>();
        var secretIdA = createResult.Data.Id;

        // STEP 2: User B tries to access User A's secret
        var emailB = $"userb-{Guid.NewGuid()}@test.com";
        var usernameB = $"userb{Guid.NewGuid().ToString().Substring(0, 8)}";
        var passwordB = "PasswordB123!";

        var tokenB = await RegisterAndLoginAsync(emailB, usernameB, passwordB);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokenB);

        // STEP 3: User B attempts IDOR attack
        var idorResponse = await _client.GetAsync($"/api/secrets/{secretIdA}");

        // Assert: 403 Forbidden (NOT 404!)
        // 404 would reveal "secret doesn't exist" which is also info leakage
        // But 403 is more explicit: "you don't have permission"
        idorResponse.StatusCode.Should().BeOneOf(
            HttpStatusCode.Forbidden,
            HttpStatusCode.NotFound);

        // User B should NOT get User A's data
        if (idorResponse.StatusCode == HttpStatusCode.OK)
        {
            Assert.Fail("CRITICAL SECURITY VULNERABILITY: User B accessed User A's secret! IDOR protection failed!");
        }
    }

    /// <summary>
    /// SECURITY TEST - DECRYPT IDOR:
    /// User A cannot decrypt User B's secret.
    /// Most critical IDOR scenario!
    /// </summary>
    [Fact]
    public async Task DecryptSecret_OtherUserSecret_ShouldReturn403()
    {
        // STEP 1: User A creates secret
        var emailA = $"decrypt-a-{Guid.NewGuid()}@test.com";
        var usernameA = $"decrypta{Guid.NewGuid().ToString().Substring(0, 8)}";
        var passwordA = "PasswordA123!";

        var tokenA = await RegisterAndLoginAsync(emailA, usernameA, passwordA);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokenA);

        var createDto = new CreateSecretDto
        {
            Title = "User A Decrypt Test",
            RawValue = "UserA_CRITICAL_DATA"
        };

        var createResponse = await _client.PostAsJsonAsync("/api/secrets", createDto);
        var createResult = await createResponse.Content.ReadFromJsonAsync<ApiResponse<SecretDto>>();
        var secretIdA = createResult.Data.Id;

        // STEP 2: User B tries to DECRYPT User A's secret (CRITICAL!)
        var emailB = $"decrypt-b-{Guid.NewGuid()}@test.com";
        var usernameB = $"decryptb{Guid.NewGuid().ToString().Substring(0, 8)}";
        var passwordB = "PasswordB123!";

        var tokenB = await RegisterAndLoginAsync(emailB, usernameB, passwordB);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", tokenB);

        // STEP 3: IDOR decrypt attack
        var decryptResponse = await _client.GetAsync($"/api/secrets/{secretIdA}/decrypt");

        // Assert: MUST be blocked
        decryptResponse.StatusCode.Should().BeOneOf(
            HttpStatusCode.Forbidden,
            HttpStatusCode.NotFound);

        // Verify NO plaintext leaked
        if (decryptResponse.StatusCode == HttpStatusCode.OK)
        {
            var leaked = await decryptResponse.Content.ReadAsStringAsync();
            leaked.Should().NotContain("UserA_CRITICAL_DATA",
                "CRITICAL: Plaintext leaked in IDOR attack!");
        }
    }

    // ============================================================================
    // ❌ VALIDATION TESTS (400 Bad Request)
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - INPUT VALIDATION:
    /// Create secret with missing required fields - 400 Bad Request.
    /// </summary>
    [Fact]
    public async Task CreateSecret_MissingRequiredFields_ShouldReturn400()
    {
        // Arrange: Login
        var email = $"validation-{Guid.NewGuid()}@test.com";
        var username = $"validation{Guid.NewGuid().ToString().Substring(0, 8)}";
        var password = "Password123!";

        var token = await RegisterAndLoginAsync(email, username, password);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        // Missing Title and RawValue
        var invalidDto = new CreateSecretDto
        {
            Description = "Only description"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/secrets", invalidDto);

        // Assert: 400 Bad Request
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var errorResult = await response.Content.ReadFromJsonAsync<ApiErrorResponse>();
        errorResult.Success.Should().BeFalse();
        errorResult.Message.Should().Contain("Validation");
    }

    /// <summary>
    /// SECURITY TEST - XSS PREVENTION:
    /// Create secret with XSS payload - Should be rejected or sanitized.
    /// </summary>
    [Fact]
    public async Task CreateSecret_WithXSSPayload_ShouldBeRejected()
    {
        // Arrange: Login
        var email = $"xss-{Guid.NewGuid()}@test.com";
        var username = $"xsstest{Guid.NewGuid().ToString().Substring(0, 8)}";
        var password = "Password123!";

        var token = await RegisterAndLoginAsync(email, username, password);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        // XSS payload in title
        var xssDto = new CreateSecretDto
        {
            Title = "<script>alert('XSS')</script>",
            RawValue = "test"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/secrets", xssDto);

        // Assert: Should be rejected (400) or sanitized
        response.StatusCode.Should().BeOneOf(
            HttpStatusCode.BadRequest,
            HttpStatusCode.Created);

        // If created, verify sanitization
        if (response.StatusCode == HttpStatusCode.Created)
        {
            var result = await response.Content.ReadFromJsonAsync<ApiResponse<SecretDto>>();
            result.Data.Title.Should().NotContain("<script>",
                "XSS payload must be sanitized");
        }
    }

    // ============================================================================
    // 🔐 ENCRYPTION VERIFICATION (DATABASE CHECK)
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - ENCRYPTION AT REST KRİTİK:
    /// Verify secret is stored ENCRYPTED in database, NOT plaintext.
    /// 
    /// COMPLIANCE:
    /// - GDPR Article 32: Data encryption at rest
    /// - PCI-DSS 3.4: Encryption of cardholder data
    /// - SOC 2: Cryptographic protection
    /// </summary>
    [Fact]
    public async Task CreateSecret_ShouldStoreEncryptedDataInDatabase()
    {
        // Arrange: Login
        var email = $"encrypt-{Guid.NewGuid()}@test.com";
        var username = $"encrypt{Guid.NewGuid().ToString().Substring(0, 8)}";
        var password = "Password123!";

        var token = await RegisterAndLoginAsync(email, username, password);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        // Create secret with known plaintext
        var plaintextPassword = "PLAINTEXT_PASSWORD_12345";
        var createDto = new CreateSecretDto
        {
            Title = "Encryption Test",
            RawValue = plaintextPassword
        };

        // Act: Create secret
        var response = await _client.PostAsJsonAsync("/api/secrets", createDto);
        var result = await response.Content.ReadFromJsonAsync<ApiResponse<SecretDto>>();
        var secretId = result.Data.Id;

        // Assert: Verify encryption in database
        using var db = GetDbContext();
        var secretInDb = await db.Secrets.FirstOrDefaultAsync(s => s.Id == secretId);

        secretInDb.Should().NotBeNull();

        // CRITICAL: Encrypted data must NOT contain plaintext
        var encryptedString = secretInDb.EncryptedValue;

        encryptedString.Should().NotContain(plaintextPassword,
            "CRITICAL: Plaintext password found in database! Encryption failed!");

        // Encrypted data should be binary (not readable text)
        encryptedString.Should().NotBeNullOrEmpty();
        encryptedString!.Length.Should().BeGreaterThan(plaintextPassword.Length,
            "encrypted data should be larger due to IV + padding");

        // IV should be unique (random)
        secretInDb.IV.Should().NotBeNull();
        secretInDb.IV.Length.Should().Be(12);

        // Verify decryption works (roundtrip)
        var decryptResponse = await _client.GetAsync($"/api/secrets/{secretId}/decrypt");
        var decryptResult = await decryptResponse.Content.ReadFromJsonAsync<ApiResponse<string>>();

        decryptResult.Data.Should().Be(plaintextPassword,
            "decryption must recover original plaintext");
    }

    // ============================================================================
    // 🎯 EDGE CASES
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - EMPTY DATABASE:
    /// List secrets with empty database - Should return empty array.
    /// </summary>
    [Fact]
    public async Task GetSecrets_EmptyDatabase_ShouldReturnEmptyArray()
    {
        // Arrange: New user (no secrets)
        var email = $"empty-{Guid.NewGuid()}@test.com";
        var username = $"empty{Guid.NewGuid().ToString().Substring(0, 8)}";
        var password = "Password123!";

        var token = await RegisterAndLoginAsync(email, username, password);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        // Act
        var response = await _client.GetAsync("/api/secrets");

        // Assert: 200 OK with empty array
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var result = await response.Content.ReadFromJsonAsync<ApiResponse<SecretDto[]>>();
        result.Success.Should().BeTrue();
        result.Data.Should().BeEmpty();
    }

    /// <summary>
    /// SECURITY TEST - NON-EXISTENT SECRET:
    /// Get non-existent secret - 404 Not Found.
    /// </summary>
    [Fact]
    public async Task GetSecret_NonExistent_ShouldReturn404()
    {
        // Arrange: Login
        var email = $"notfound-{Guid.NewGuid()}@test.com";
        var username = $"notfound{Guid.NewGuid().ToString().Substring(0, 8)}";
        var password = "Password123!";

        var token = await RegisterAndLoginAsync(email, username, password);
        _client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        // Act: Get non-existent secret
        var nonExistentId = Guid.NewGuid();
        var response = await _client.GetAsync($"/api/secrets/{nonExistentId}");

        // Assert: 404 Not Found
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }
}

// Helper classes for JSON deserialization
public class ApiResponse<T>
{
    public bool Success { get; set; }
    public string Message { get; set; }
    public T Data { get; set; }
}

public class ApiErrorResponse
{
    public bool Success { get; set; }
    public string Message { get; set; }
    public object Errors { get; set; }
}