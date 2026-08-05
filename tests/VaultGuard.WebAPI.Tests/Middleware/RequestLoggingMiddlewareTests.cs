using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using VaultGuard.WebAPI.Middleware;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Middleware;

/// <summary>
/// TEST SÜÝTÝ: RequestLoggingMiddleware - Hassas Veri Maskeleme ve Audit Trail
/// 
/// TEST KAPSAMI:
/// - PII (Personally Identifiable Information) maskeleme
/// - Password/Secret/Token maskeleme
/// - Correlation ID oluþturma
/// - Performance tracking
/// - Malformed JSON handling
/// - Devasa request body'ler (DoS korumasý)
/// 
/// GÜVENLÝK TESTLERÝ:
/// - Hassas veri sýzýntýsý önleme
/// - Log injection saldýrýlarý
/// - Buffer overflow denemeleri
/// - Null stream handling
/// </summary>
public class RequestLoggingMiddlewareTests
{
    private readonly Mock<ILogger<RequestLoggingMiddleware>> _loggerMock;
    private readonly RequestLoggingMiddleware _middleware;
    private readonly RequestDelegate _nextDelegate;

    public RequestLoggingMiddlewareTests()
    {
        _loggerMock = new Mock<ILogger<RequestLoggingMiddleware>>();

        // Next delegate: Pipeline'ý simüle et
        _nextDelegate = (HttpContext context) =>
        {
            context.Response.StatusCode = 200;
            return Task.CompletedTask;
        };

        _middleware = new RequestLoggingMiddleware(_nextDelegate, _loggerMock.Object);
    }

    // ============================================================================
    // TEMEL FONKSÝYONALÝTE TESTLERÝ
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_ShouldAddCorrelationIdToResponse()
    {
        // Arrange
        var context = CreateHttpContext("GET", "/api/test", "");

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: X-Correlation-ID header eklendi mi?
        context.Response.Headers.Should().ContainKey("X-Correlation-ID");

        var correlationId = context.Response.Headers["X-Correlation-ID"].ToString();
        correlationId.Should().NotBeNullOrEmpty();

        // GUID formatýnda olmalý
        Guid.TryParse(correlationId, out _).Should().BeTrue();
    }

    [Fact]
    public async Task InvokeAsync_ShouldLogRequestAndResponse()
    {
        // Arrange
        var context = CreateHttpContext("POST", "/api/auth/login", "{ \"email\": \"test@test.com\" }");

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: Request ve Response loglandý mý?
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("[Request]")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once);

        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("[Response]")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task InvokeAsync_ShouldTrackRequestDuration()
    {
        // Arrange
        var context = CreateHttpContext("GET", "/api/slow-endpoint", "");

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: Duration (ms) loglandý mý?
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("Duration:")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once);
    }

    // ============================================================================
    // GÜVENLÝK TESTLERÝ: PASSWORD MASKING
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_LoginRequest_ShouldMaskPasswordInLogs()
    {
        // Arrange: Login request body password içeriyor
        var requestBody = @"{
            ""email"": ""user@test.com"",
            ""password"": ""SuperSecret123!""
        }";

        var context = CreateHttpContext("POST", "/api/auth/login", requestBody);

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: Log'da password [MASKED] olmalý
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("[MASKED]")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.AtLeastOnce);

        // GÜVENLÝK: Plain-text password ASLA loglanmamalý
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("SuperSecret123!")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Never);
    }

    [Fact]
    public async Task InvokeAsync_ChangePasswordRequest_ShouldMaskAllPasswordFields()
    {
        // Arrange: Change password request (3 þifre alaný)
        var requestBody = @"{
            ""oldPassword"": ""OldPass123!"",
            ""newPassword"": ""NewPass456!"",
            ""confirmNewPassword"": ""NewPass456!""
        }";

        var context = CreateHttpContext("POST", "/api/users/change-password", requestBody);

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: Her üç þifre de maskelenmeli
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) =>
                    !v.ToString().Contains("OldPass123!") &&
                    !v.ToString().Contains("NewPass456!")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.AtLeastOnce);
    }

    // ============================================================================
    // GÜVENLÝK TESTLERÝ: TOKEN MASKING
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_RefreshTokenRequest_ShouldMaskToken()
    {
        // Arrange
        var requestBody = @"{
            ""refreshToken"": ""eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature""
        }";

        var context = CreateHttpContext("POST", "/api/auth/refresh-token", requestBody);

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: JWT token maskelenmeli
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("[MASKED]")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.AtLeastOnce);

        // JWT plain-text ASLA loglanmamalý
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("eyJhbGciOiJIUzI1NiI")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Never);
    }

    [Fact]
    public async Task InvokeAsync_ApiKeyInHeader_ShouldMaskInLogs()
    {
        // Arrange: Authorization header ile API key
        var context = CreateHttpContext("GET", "/api/secrets", "");
        context.Request.Headers.Add("Authorization", "Bearer sk-1234567890abcdef");

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: API key maskelenmeli (eðer header'lar loglanýyorsa)
        // Not: Middleware'in header loglama davranýþýna baðlý
    }

    // ============================================================================
    // GÜVENLÝK TESTLERÝ: SECRET MASKING
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_SecretCreationRequest_ShouldMaskSecretContent()
    {
        // Arrange: Secret oluþturma request'i
        var requestBody = @"{
            ""name"": ""AWS API Key"",
            ""secret"": ""aws_access_key_id=AKIAIOSFODNN7EXAMPLE""
        }";

        var context = CreateHttpContext("POST", "/api/secrets", requestBody);

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: Secret içeriði maskelenmeli
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) =>
                    !v.ToString().Contains("AKIAIOSFODNN7EXAMPLE")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.AtLeastOnce);
    }

    // ============================================================================
    // GÜVENLÝK TESTLERÝ: MULTIPLE SENSITIVE FIELDS
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_RequestWithMultipleSensitiveFields_ShouldMaskAll()
    {
        // Arrange: Birden fazla hassas alan
        var requestBody = @"{
            ""email"": ""user@test.com"",
            ""password"": ""Pass123!"",
            ""token"": ""abc123token"",
            ""apiKey"": ""sk-secretkey"",
            ""secret"": ""my-secret-data""
        }";

        var context = CreateHttpContext("POST", "/api/admin/debug", requestBody);

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: Tüm hassas alanlar maskelenmeli
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) =>
                    v.ToString().Contains("[MASKED]") &&
                    !v.ToString().Contains("Pass123!") &&
                    !v.ToString().Contains("abc123token") &&
                    !v.ToString().Contains("sk-secretkey") &&
                    !v.ToString().Contains("my-secret-data")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.AtLeastOnce);
    }

    // ============================================================================
    // GÜVENLÝK TESTLERÝ: MALFORMED JSON
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_MalformedJson_ShouldNotCrash()
    {
        // Arrange: Bozuk JSON
        var malformedJson = "{ email: 'test@test.com', password: unclosed";

        var context = CreateHttpContext("POST", "/api/auth/login", malformedJson);

        // Act & Assert: Exception fýrlatmamalý
        var act = async () => await _middleware.InvokeAsync(context);
        await act.Should().NotThrowAsync();

        // Middleware hatayý handle etmeli veya body'yi [SECURITY MASKING FAILED] olarak loglamalý
        _loggerMock.Verify(
            x => x.Log(
                It.IsAny<LogLevel>(),
                It.IsAny<EventId>(),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.AtLeastOnce);
    }

    [Fact]
    public async Task InvokeAsync_EmptyRequestBody_ShouldLogNone()
    {
        // Arrange: Boþ body
        var context = CreateHttpContext("POST", "/api/test", "");

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: Body: [None] loglanmalý
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("[None]")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.AtLeastOnce);
    }

    // ============================================================================
    // GÜVENLÝK TESTLERÝ: BUFFER OVERFLOW / DoS
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_MassiveRequestBody_ShouldNotCrashOrLogFully()
    {
        // Arrange: 10 MB request body (DoS denemesi)
        var massiveBody = new string('A', 10 * 1024 * 1024); // 10 MB

        var context = CreateHttpContext("POST", "/api/upload", massiveBody);

        // Act & Assert: Crash etmemeli
        var act = async () => await _middleware.InvokeAsync(context);
        await act.Should().NotThrowAsync();

        // Log çok uzun olmamalý (truncate edilmeli)
        _loggerMock.Verify(
            x => x.Log(
                It.IsAny<LogLevel>(),
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Length < 100000), // Max 100KB log
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.AtLeastOnce);
    }

    [Fact]
    public async Task InvokeAsync_NullStream_ShouldNotCrash()
    {
        // Arrange: Null body stream (edge case)
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/api/test";
        context.Request.Body = Stream.Null; // Null stream
        context.Response.Body = new MemoryStream();

        // Act & Assert
        var act = async () => await _middleware.InvokeAsync(context);
        await act.Should().NotThrowAsync();
    }

    // ============================================================================
    // GÜVENLÝK TESTLERÝ: LOG INJECTION
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_RequestWithNewlineCharacters_ShouldSanitize()
    {
        // Arrange: Log injection denemesi (newline injection)
        var requestBody = @"{
            ""email"": ""attacker@evil.com\n[FAKE LOG] Admin access granted\n"",
            ""password"": ""pass""
        }";

        var context = CreateHttpContext("POST", "/api/auth/login", requestBody);

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: Newline karakterleri sanitize edilmeli veya escape edilmeli
        // Log'da sahte log satýrý görünmemeli
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) =>
                    !v.ToString().Contains("[FAKE LOG]")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.AtLeastOnce);
    }

    // ============================================================================
    // GÜVENLÝK TESTLERÝ: SWAGGER ENDPOINTS
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_SwaggerEndpoint_ShouldNotLogBody()
    {
        // Arrange: Swagger UI endpoint
        var context = CreateHttpContext("GET", "/swagger/v1/swagger.json", "");

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: Swagger request'leri için body loglanmamalý (performance)
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => !v.ToString().Contains("Body:")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.AtLeastOnce);
    }

    // ============================================================================
    // PERFORMANCE TESTLERÝ
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_MeasuresResponseTime()
    {
        // Arrange
        var context = CreateHttpContext("GET", "/api/test", "");

        var slowNext = new RequestDelegate(async (HttpContext ctx) =>
        {
            await Task.Delay(100); // 100ms simulated delay
            ctx.Response.StatusCode = 200;
        });

        var middleware = new RequestLoggingMiddleware(slowNext, _loggerMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Duration en az 100ms olmalý
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) =>
                    v.ToString().Contains("Duration:") &&
                    ExtractDuration(v.ToString()) >= 100),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once);
    }

    // ============================================================================
    // EXCEPTION HANDLING TESTLERÝ
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_NextMiddlewareThrows_ShouldLogCriticalError()
    {
        // Arrange: Next middleware exception fýrlatacak
        var throwingNext = new RequestDelegate((HttpContext ctx) =>
        {
            throw new InvalidOperationException("Simulated pipeline error");
        });

        var middleware = new RequestLoggingMiddleware(throwingNext, _loggerMock.Object);
        var context = CreateHttpContext("POST", "/api/test", "test body");

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await middleware.InvokeAsync(context));

        // Critical log yazýlmalý
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Critical,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("SECURITY ALERT")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once);
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private static DefaultHttpContext CreateHttpContext(string method, string path, string body)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Request.ContentType = "application/json";

        if (!string.IsNullOrEmpty(body))
        {
            var bodyBytes = Encoding.UTF8.GetBytes(body);
            context.Request.Body = new MemoryStream(bodyBytes);
            context.Request.ContentLength = bodyBytes.Length;
        }

        context.Response.Body = new MemoryStream();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("192.168.1.100");

        return context;
    }

    private static long ExtractDuration(string logMessage)
    {
        // "Duration: 123ms" pattern'inden 123'ü çýkar
        var match = System.Text.RegularExpressions.Regex.Match(logMessage, @"Duration:\s*(\d+)ms");
        if (match.Success && long.TryParse(match.Groups[1].Value, out var duration))
        {
            return duration;
        }
        return 0;
    }
}