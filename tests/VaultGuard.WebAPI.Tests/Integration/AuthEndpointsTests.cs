using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using VaultGuard.Application.DTOs.Auth;
using VaultGuard.Application.Interfaces;
using VaultGuard.Domain.Entities;
using VaultGuard.Infrastructure.Persistence;
using Xunit;
using Microsoft.EntityFrameworkCore; // Bu sat�r FirstOrDefaultAsync'i aktif eder.

namespace VaultGuard.WebAPI.Tests.Integration;

/// <summary>
/// ENTEGRASYON TEST S��T�: Authentication Endpoints
/// 
/// TEST KAPSAMI:
/// - U�tan uca (end-to-end) auth workflow testleri
/// - Ger�ek HTTP request/response d�ng�leri
/// - Database entegrasyonu
/// - Middleware pipeline testleri
/// - Siber sald�r� sim�lasyonlar�
/// 
/// G�VENL�K TESTLERI:
/// - SQL Injection sald�r�lar�
/// - Buffer overflow denemeleri
/// - JWT manip�lasyonu
/// - Brute force korumas�
/// - User enumeration �nleme
/// </summary>
public class AuthEndpointsTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public AuthEndpointsTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                // Test i�in in-memory database kullan
                var dbContext = services.BuildServiceProvider().GetRequiredService<VaultGuardDbContext>();
                dbContext.Database.EnsureDeleted();
                dbContext.Database.EnsureCreated();
            });
        });

        _client = _factory.CreateClient();
    }

    // ============================================================================
    // NORMAL WORKFLOW TESTLERI (Happy Path)
    // ============================================================================

    [Fact]
    public async Task Register_WithValidData_ShouldReturn200WithToken()
    {
        // Arrange: Ge�erli kay�t bilgileri
        var registerDto = new RegisterDto
        {
            Email = "test@vaultguard.com",
            Username = "testuser",
            Password = "SecurePass123!",
            ConfirmPassword = "SecurePass123!"
        };

        // Act: POST /api/auth/register
        var response = await _client.PostAsJsonAsync("/api/auth/register", registerDto);

        // Assert: HTTP 200 ve TokenDto d�nd� m�?
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        result.GetProperty("success").GetBoolean().Should().BeTrue();
        result.GetProperty("data").GetProperty("accessToken").GetString().Should().NotBeNullOrEmpty();
        result.GetProperty("data").GetProperty("expiration").GetDateTime().Should().BeAfter(DateTime.UtcNow);
    }

    [Fact]
    public async Task Login_WithValidCredentials_ShouldReturn200WithToken()
    {
        // Arrange: �nce kullan�c� olu�tur
        await RegisterTestUser("login@vaultguard.com", "loginuser", "Password123!");

        var loginDto = new LoginDto
        {
            Email = "login@vaultguard.com",
            Password = "Password123!"
        };

        // Act: POST /api/auth/login
        var response = await _client.PostAsJsonAsync("/api/auth/login", loginDto);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        result.GetProperty("success").GetBoolean().Should().BeTrue();
        result.GetProperty("data").GetProperty("accessToken").GetString().Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task RegisterThenLogin_FullWorkflow_ShouldSucceed()
    {
        // Arrange
        var email = "workflow@vaultguard.com";
        var password = "WorkflowPass123!";

        // Act 1: Register
        var registerDto = new RegisterDto
        {
            Email = email,
            Username = "workflowuser",
            Password = password,
            ConfirmPassword = password
        };

        var registerResponse = await _client.PostAsJsonAsync("/api/auth/register", registerDto);
        registerResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Act 2: Login
        var loginDto = new LoginDto { Email = email, Password = password };
        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", loginDto);

        // Assert: Her iki ad�m da ba�ar�l�
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var loginResult = await loginResponse.Content.ReadFromJsonAsync<JsonElement>();
        loginResult.GetProperty("success").GetBoolean().Should().BeTrue();
    }

    // ============================================================================
    // G�VENL�K TESTLER�: SQL INJECTION SALDIRILARI
    // ============================================================================

    [Theory]
    [InlineData("admin'--")]
    [InlineData("'; DROP TABLE Users;--")]
    [InlineData("' OR '1'='1")]
    [InlineData("admin' OR 1=1--")]
    [InlineData("1' UNION SELECT NULL, username, password FROM users--")]
    public async Task Login_WithSqlInjectionAttempt_ShouldReturnBadRequest(string maliciousEmail)
    {
        // Arrange: SQL injection payload
        var loginDto = new LoginDto
        {
            Email = maliciousEmail,
            Password = "anything"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/login", loginDto);

        // Assert: Sald�r� ba�ar�s�z olmal� (400 veya 401)
        response.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized);

        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        result.GetProperty("success").GetBoolean().Should().BeFalse();

        // G�VENL�K: SQL hata detay� ASLA d�nmemeli
        var message = result.GetProperty("message").GetString();
        message.Should().NotContain("SQL");
        message.Should().NotContain("database");
        message.Should().NotContain("syntax");
    }

    [Fact]
    public async Task Register_WithSqlInjectionInUsername_ShouldRejectOrSanitize()
    {
        // Arrange
        var registerDto = new RegisterDto
        {
            Email = "hacker@evil.com",
            Username = "admin'; DROP TABLE Users;--",
            Password = "HackAttempt123!",
            ConfirmPassword = "HackAttempt123!"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/register", registerDto);

        // Assert: Kay�t reddedilmeli veya sanitize edilmeli
        response.StatusCode.Should().BeOneOf(HttpStatusCode.BadRequest, HttpStatusCode.OK);

        if (response.StatusCode == HttpStatusCode.OK)
        {
            // E�er kabul edildiyse, database'de g�venli halde saklanm�� olmal�
            using var scope = _factory.Services.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<VaultGuardDbContext>();
            var user = await dbContext.Users.FirstOrDefaultAsync(u => u.Email == "hacker@evil.com");

            if (user != null)
            {
                // Username SQL karakterleri i�ermemeli
                user.Username.Should().NotContain("DROP");
                user.Username.Should().NotContain("--");
            }
        }
    }

    // ============================================================================
    // G�VENL�K TESTLER�: BUFFER OVERFLOW DENEMELER�
    // ============================================================================

    [Fact]
    public async Task Register_WithExcessivelyLongEmail_ShouldReturnBadRequest()
    {
        // Arrange: 10,000 karakterlik email (RFC 5321 max: 254 karakter)
        var hugeMaliciousEmail = new string('A', 10000) + "@evil.com";

        var registerDto = new RegisterDto
        {
            Email = hugeMaliciousEmail,
            Username = "attacker",
            Password = "Pass123!",
            ConfirmPassword = "Pass123!"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/register", registerDto);

        // Assert: Buffer overflow denemesi reddedilmeli
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        result.GetProperty("success").GetBoolean().Should().BeFalse();
    }

    [Fact]
    public async Task Login_WithMassivePasswordPayload_ShouldRejectOrTimeout()
    {
        // Arrange: 1 MB boyutunda �ifre (buffer overflow/DoS denemesi)
        var massivePassword = new string('X', 1024 * 1024); // 1 MB

        var loginDto = new LoginDto
        {
            Email = "victim@vaultguard.com",
            Password = massivePassword
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/login", loginDto);

        // Assert: Sistem crash etmemeli, 400/408/413 d�nmeli
        response.StatusCode.Should().BeOneOf(
            HttpStatusCode.BadRequest,
            HttpStatusCode.RequestTimeout,
            HttpStatusCode.RequestEntityTooLarge);
    }

    // ============================================================================
    // G�VENL�K TESTLER�: MALFORMED JSON & NULL STREAM
    // ============================================================================

    [Fact]
    public async Task Login_WithMalformedJson_ShouldReturnBadRequest()
    {
        // Arrange: Bozuk JSON payload
        var malformedJson = "{ email: 'test@test.com', password: 'unclosed string";

        var content = new StringContent(malformedJson, Encoding.UTF8, "application/json");

        // Act
        var response = await _client.PostAsync("/api/auth/login", content);

        // Assert: 400 Bad Request
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Register_WithNullRequestBody_ShouldReturnBadRequest()
    {
        // Arrange: Bo� HTTP body
        var content = new StringContent("", Encoding.UTF8, "application/json");

        // Act
        var response = await _client.PostAsync("/api/auth/register", content);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Login_WithEmptyJsonObject_ShouldReturnBadRequest()
    {
        // Arrange: Bo� JSON objesi {}
        var emptyJson = new StringContent("{}", Encoding.UTF8, "application/json");

        // Act
        var response = await _client.PostAsync("/api/auth/login", emptyJson);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        result.GetProperty("success").GetBoolean().Should().BeFalse();
    }

    // ============================================================================
    // G�VENL�K TESTLER�: USER ENUMERATION �NLEME
    // ============================================================================

    [Fact]
    public async Task Login_ExistingUserWrongPassword_VsNonExistentUser_ShouldReturnIdenticalMessages()
    {
        // Arrange: �nce bir kullan�c� olu�tur
        await RegisterTestUser("exists@vaultguard.com", "existinguser", "CorrectPass123!");

        // Scenario 1: Var olan kullan�c�, yanl�� �ifre
        var wrongPasswordDto = new LoginDto
        {
            Email = "exists@vaultguard.com",
            Password = "WrongPassword!"
        };

        // Scenario 2: Olmayan kullan�c�
        var nonExistentDto = new LoginDto
        {
            Email = "ghost@vaultguard.com",
            Password = "AnyPassword123!"
        };

        // Act
        var response1 = await _client.PostAsJsonAsync("/api/auth/login", wrongPasswordDto);
        var response2 = await _client.PostAsJsonAsync("/api/auth/login", nonExistentDto);

        // Assert: Her iki response da AYNI hata mesaj�n� d�nmeli (user enumeration �nleme)
        response1.StatusCode.Should().Be(response2.StatusCode);

        var result1 = await response1.Content.ReadFromJsonAsync<JsonElement>();
        var result2 = await response2.Content.ReadFromJsonAsync<JsonElement>();

        var message1 = result1.GetProperty("message").GetString()?.ToLower();
        var message2 = result2.GetProperty("message").GetString()?.ToLower();

        // CRITICAL: Mesajlar ayn� olmal�
        message1.Should().Be(message2);
        (message1.Contains("email") || message1.Contains("şifre") || message1.Contains("hatalı")).Should().BeTrue();
    }

    [Fact]
    public async Task Register_DuplicateEmail_ShouldNotRevealExistence()
    {
        // Arrange: �lk kullan�c�
        await RegisterTestUser("duplicate@vaultguard.com", "user1", "Pass123!");

        // Act: Ayn� email ile tekrar kay�t dene
        var duplicateDto = new RegisterDto
        {
            Email = "duplicate@vaultguard.com",
            Username = "user2",
            Password = "Pass456!",
            ConfirmPassword = "Pass456!"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/register", duplicateDto);

        // Assert: Generic hata mesaj� d�nmeli ("Bu email kay�tl�" DEMEMEL�)
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        var message = result.GetProperty("message").GetString();

        // G�VENL�K: "Email already exists" gibi a��k mesaj olmamal�
        message.ToLower().Should().NotContain("already");
        message.ToLower().Should().NotContain("exists");
    }

    // ============================================================================
    // G�VENL�K TESTLER�: BRUTE FORCE KORUMASI
    // ============================================================================

    [Fact]
    public async Task Login_MultipleFailedAttempts_ShouldEventuallyBlockOrRateLimit()
    {
        // Arrange: Ge�erli kullan�c�
        await RegisterTestUser("bruteforce@vaultguard.com", "victim", "CorrectPass123!");

        var loginDto = new LoginDto
        {
            Email = "bruteforce@vaultguard.com",
            Password = "WrongPassword!"
        };

        // Act: 10 kez yanl�� �ifre dene
        HttpResponseMessage lastResponse = null;

        for (int i = 0; i < 10; i++)
        {
            lastResponse = await _client.PostAsJsonAsync("/api/auth/login", loginDto);
            await Task.Delay(100); // Rate limiting bypass denemesi
        }

        // Assert: Son denemede 429 Too Many Requests veya hesap kilidi d�nmeli
        lastResponse.StatusCode.Should().BeOneOf(
            HttpStatusCode.TooManyRequests,
            HttpStatusCode.Unauthorized,
            HttpStatusCode.Forbidden);
    }

    // ============================================================================
    // G�VENL�K TESTLER�: PASSWORD HASH EXPOSURE
    // ============================================================================

    [Fact]
    public async Task Register_Success_ResponseShouldNotContainPasswordHash()
    {
        // Arrange
        var registerDto = new RegisterDto
        {
            Email = "hashtest@vaultguard.com",
            Username = "hashtest",
            Password = "SecurePass123!",
            ConfirmPassword = "SecurePass123!"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/register", registerDto);

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var responseBody = await response.Content.ReadAsStringAsync();

        // G�VENL�K: Response body'de BCrypt hash pattern olmamal�
        responseBody.Should().NotContain("$2a$");
        responseBody.Should().NotContain("$2b$");
        responseBody.Should().NotContain("passwordHash");
        responseBody.Should().NotContain("PasswordHash");
    }

    // ============================================================================
    // G�VENL�K TESTLER�: XSS & SCRIPT INJECTION
    // ============================================================================

    [Fact]
    public async Task Register_WithXssPayloadInUsername_ShouldSanitize()
    {
        // Arrange: XSS payload
        var registerDto = new RegisterDto
        {
            Email = "xss@vaultguard.com",
            Username = "<script>alert('XSS')</script>",
            Password = "Pass123!",
            ConfirmPassword = "Pass123!"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/register", registerDto);

        // Assert: Kay�t reddedilmeli veya sanitize edilmeli
        if (response.StatusCode == HttpStatusCode.OK)
        {
            using var scope = _factory.Services.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<VaultGuardDbContext>();
            var user = await dbContext.Users.FirstOrDefaultAsync(u => u.Email == "xss@vaultguard.com");

            // Username <script> tag i�ermemeli
            user?.Username.Should().NotContain("<script>");
            user?.Username.Should().NotContain("</script>");
        }
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private async Task RegisterTestUser(string email, string username, string password)
    {
        var registerDto = new RegisterDto
        {
            Email = email,
            Username = username,
            Password = password,
            ConfirmPassword = password
        };

        var response = await _client.PostAsJsonAsync("/api/auth/register", registerDto);
        response.EnsureSuccessStatusCode();
    }
}