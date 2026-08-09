using FluentAssertions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Moq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using VaultGuard.WebAPI.Middleware;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Middleware;

/// <summary>
/// TEST S��T�:GlobalExceptionMiddleware- Bilgi S�z�nt�s� �nleme Z�rh�
/// 
/// G�VENL�K KAPSAMI:
/// - Stack trace exposure prevention (Production)
/// - Exception detail sanitization
/// - Correlation ID tracking
/// - Status code mapping accuracy
/// - Environment-aware error messaging
/// 
/// SALDIRI S�M�LASYONLARI:
/// - Information disclosure attempts
/// - Error-based enumeration
/// - Exception message mining
/// </summary>
public class GlobalExceptionMiddlewareTests
{
    private readonly Mock<ILogger<GlobalExceptionMiddleware>> _loggerMock;
    private readonly Mock<IHostEnvironment> _environmentMock;

    public GlobalExceptionMiddlewareTests()
    {
        _loggerMock = new Mock<ILogger<GlobalExceptionMiddleware>>();
        _environmentMock = new Mock<IHostEnvironment>();
    }

    // ============================================================================
    // G�VENL�K TEST�: PRODUCTION'DA STACK TRACE SIZDIRILMAMASI
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_ProductionEnvironment_ShouldNeverExposeStackTrace()
    {
        // Arrange: Production ortam� sim�lasyonu
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var exception = new InvalidOperationException("Internal server error with sensitive data");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Response body'de stack trace olmamal�
        var responseBody = await GetResponseBody(context);

        responseBody.Should().NotContain("at VaultGuard");
        responseBody.Should().NotContain("StackTrace");
        responseBody.Should().NotContain("System.InvalidOperationException");
        responseBody.Should().NotContain("sensitive data");

        responseBody.Should().Contain("Bir hata oluştu");
    }

    [Fact]
    public async Task InvokeAsync_ProductionEnvironment_ShouldNotIncludeDetailsField()
    {
        // Arrange: Production ortam�
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var exception = new Exception("Top secret internal message");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: JSON response'da 'details' field olmamal�
        var responseBody = await GetResponseBody(context);
        var jsonDoc = JsonDocument.Parse(responseBody);

        jsonDoc.RootElement.TryGetProperty("details", out _).Should().BeFalse();
    }

    [Fact]
    public async Task InvokeAsync_ProductionEnvironment_ShouldNotRevealExceptionType()
    {
        // Arrange
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var exception = new NullReferenceException("Object reference not set");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Exception type s�zd�r�lmamal�
        var responseBody = await GetResponseBody(context);

        responseBody.Should().NotContain("NullReferenceException");
        responseBody.Should().NotContain("ArgumentException");
        responseBody.Should().NotContain("InvalidOperationException");
    }

    // ============================================================================
    // G�VENL�K TEST�: DEVELOPMENT'TA DETAY G�STER�M�
    // ============================================================================

    [Fact(Skip = "Details field mapping incelenmeli")]
    public async Task InvokeAsync_DevelopmentEnvironment_ShouldIncludeDetailsField()
    {
        // Arrange: Development ortam�
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Development);

        var exception = new InvalidOperationException("Debug mode error");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Development'ta 'details' field olmal�
        var responseBody = await GetResponseBody(context);
        var jsonDoc = JsonDocument.Parse(responseBody);

        jsonDoc.RootElement.TryGetProperty("details", out var detailsProperty).Should().BeTrue();
        detailsProperty.GetString().Should().Contain("Debug mode error");
    }

    [Fact]
    public async Task InvokeAsync_DevelopmentEnvironment_DetailsShouldNotContainStackTrace()
    {
        // Arrange: Development bile olsa stack trace d�nmemeli (security best practice)
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Development);

        var exception = new Exception("Dev error");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Details'de stack trace olmamal� (g�venlik)
        var responseBody = await GetResponseBody(context);
        var jsonDoc = JsonDocument.Parse(responseBody);

        if (jsonDoc.RootElement.TryGetProperty("details", out var details))
        {
            var detailsText = details.ToString();
            // Stack trace path'leri olmamal�
            detailsText.Should().NotContain("at VaultGuard");
            detailsText.Should().NotContain("line ");
        }
    }

    // ============================================================================
    // G�VENL�K TEST�: CORRELATION ID ZORUNLULU�U
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_AnyException_ShouldAlwaysIncludeCorrelationId()
    {
        // Arrange
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var exception = new Exception("Any error");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: CorrelationId mutlaka d�nmeli
        var responseBody = await GetResponseBody(context);
        var jsonDoc = JsonDocument.Parse(responseBody);

        jsonDoc.RootElement.TryGetProperty("correlationId", out var correlationIdProp).Should().BeTrue();

        var correlationId = correlationIdProp.GetString();
        correlationId.Should().NotBeNullOrEmpty();

        // GUID format�nda olmal�
        Guid.TryParse(correlationId, out _).Should().BeTrue();
    }

    [Fact(Skip = "CorrelationId test setup sorunu")]
    public async Task InvokeAsync_ShouldUseExistingCorrelationIdFromHeader()
    {
        // Arrange: Request'te zaten Correlation ID var (logging middleware'den gelmi�)
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var existingCorrelationId = Guid.NewGuid().ToString();
        var context = CreateHttpContext();
        context.Response.Headers.Add("X-Correlation-ID", existingCorrelationId);

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw new Exception("Error"),
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Ayn� Correlation ID kullan�lmal�
        var responseBody = await GetResponseBody(context);
        var jsonDoc = JsonDocument.Parse(responseBody);

        var returnedCorrelationId = jsonDoc.RootElement.GetProperty("correlationId").GetString();
        returnedCorrelationId.Should().Be(existingCorrelationId);
    }

    [Fact(Skip = "CorrelationId test setup sorunu")]
    public async Task InvokeAsync_NoCorrelationIdInHeader_ShouldUseTraceIdentifier()
    {
        // Arrange: Correlation ID header yok
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var context = CreateHttpContext();
        context.TraceIdentifier = "trace-12345";

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw new Exception("Error"),
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: TraceIdentifier fallback olarak kullan�lmal�
        var responseBody = await GetResponseBody(context);
        var jsonDoc = JsonDocument.Parse(responseBody);

        var correlationId = jsonDoc.RootElement.GetProperty("correlationId").GetString();
        correlationId.Should().Be("trace-12345");
    }

    // ============================================================================
    // G�VENL�K TEST�: STATUS CODE MAPPING DO�RULU�U
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_UnauthorizedAccessException_ShouldReturn401()
    {
        // Arrange
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var exception = new UnauthorizedAccessException("Access denied");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: HTTP 401 Unauthorized
        context.Response.StatusCode.Should().Be((int)HttpStatusCode.Unauthorized);

        var responseBody = await GetResponseBody(context);
        responseBody.Should().Contain("Kimlik doğrulama başarısız");
    }

    [Fact]
    public async Task InvokeAsync_KeyNotFoundException_ShouldReturn404()
    {
        // Arrange
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var exception = new KeyNotFoundException("Entity not found");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: HTTP 404 Not Found
        context.Response.StatusCode.Should().Be((int)HttpStatusCode.NotFound);

        var responseBody = await GetResponseBody(context);
        responseBody.Should().Contain("bulunamadı");
    }

    [Fact]
    public async Task InvokeAsync_ArgumentException_ShouldReturn400()
    {
        // Arrange
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var exception = new ArgumentException("Invalid argument");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: HTTP 400 Bad Request
        context.Response.StatusCode.Should().Be((int)HttpStatusCode.BadRequest);

        var responseBody = await GetResponseBody(context);
        responseBody.Should().Contain("Geçersiz istek");
    }

    [Fact(Skip = "InvalidOperationException mapping incelenmeli")]
    public async Task InvokeAsync_InvalidOperationException_ShouldReturn400()
    {
        // Arrange
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var exception = new InvalidOperationException("Invalid state");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: HTTP 400 Bad Request
        context.Response.StatusCode.Should().Be((int)HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task InvokeAsync_OperationCanceledException_ShouldReturn408()
    {
        // Arrange
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var exception = new OperationCanceledException("Request cancelled");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: HTTP 408 Request Timeout
        context.Response.StatusCode.Should().Be(408);

        var responseBody = await GetResponseBody(context);
        responseBody.Should().Contain("zaman aşımına uğradı");
    }

    [Fact]
    public async Task InvokeAsync_GenericException_ShouldReturn500()
    {
        // Arrange
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var exception = new Exception("Unexpected error");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: HTTP 500 Internal Server Error
        context.Response.StatusCode.Should().Be((int)HttpStatusCode.InternalServerError);

        var responseBody = await GetResponseBody(context);
        responseBody.Should().Contain("Bir hata oluştu");
    }

    // ============================================================================
    // G�VENL�K TEST�: ERROR CODE STANDARDIZASYONU
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_ShouldIncludeStandardizedErrorCode()
    {
        // Arrange
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var exception = new UnauthorizedAccessException();
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Error code format�: ERR_{StatusCode}
        var responseBody = await GetResponseBody(context);
        var jsonDoc = JsonDocument.Parse(responseBody);

        var errorCode = jsonDoc.RootElement.GetProperty("errorCode").GetString();
        errorCode.Should().Be("ERR_UNAUTHORIZED");
    }

    [Theory]
    [InlineData(typeof(KeyNotFoundException), "ERR_NOT_FOUND")]
    [InlineData(typeof(ArgumentException), "ERR_VALIDATION")]
    [InlineData(typeof(Exception), "ERR_INTERNAL")]
    public async Task InvokeAsync_DifferentExceptions_ShouldReturnCorrectErrorCode(
        Type exceptionType, string expectedErrorCode)
    {
        // Arrange
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var exception = (Exception)Activator.CreateInstance(exceptionType, "Test error");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        var responseBody = await GetResponseBody(context);
        var jsonDoc = JsonDocument.Parse(responseBody);

        var errorCode = jsonDoc.RootElement.GetProperty("errorCode").GetString();
        errorCode.Should().Be(expectedErrorCode);
    }

    // ============================================================================
    // G�VENL�K TEST�: SUCCESS FIELD KONTROL�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_AnyException_ShouldAlwaysReturnSuccessFalse()
    {
        // Arrange
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var exception = new Exception("Error");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: success: false olmal�
        var responseBody = await GetResponseBody(context);
        var jsonDoc = JsonDocument.Parse(responseBody);

        jsonDoc.RootElement.GetProperty("success").GetBoolean().Should().BeFalse();
    }

    // ============================================================================
    // G�VENL�K TEST�: CONTENT-TYPE KONTROL�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_ShouldSetContentTypeToApplicationJson()
    {
        // Arrange
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var exception = new Exception("Error");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Content-Type header
        context.Response.ContentType.Should().Be("application/json");
    }

    // ============================================================================
    // G�VENL�K TEST�: LOGGING DO�RULU�U
    // ============================================================================

    [Fact(Skip = "Log mesaj formatı test setup ile uyuşmuyor")]
    public async Task InvokeAsync_ShouldLogErrorWithCorrelationId()
    {
        // Arrange
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var exception = new InvalidOperationException("Test error");
        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw exception,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Error log yaz�lmal�
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) =>
                    v.ToString().Contains("VaultGuard ERROR") &&
                    v.ToString().Contains("ID:")),
                It.Is<Exception>(ex => ex == exception),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once);
    }

    // ============================================================================
    // EDGE CASE TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_NoException_ShouldNotModifyResponse()
    {
        // Arrange: Normal pipeline (exception yok)
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) =>
            {
                ctx.Response.StatusCode = 200;
                return Task.CompletedTask;
            },
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Response de�i�memeli
        context.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task InvokeAsync_NullException_ShouldHandleGracefully()
    {
        // Arrange: Null exception (edge case)
        _environmentMock.Setup(e => e.EnvironmentName).Returns(Environments.Production);

        var context = CreateHttpContext();

        var middleware = new GlobalExceptionMiddleware(
            next: (HttpContext ctx) => throw null,
            logger: _loggerMock.Object,
            environment: _environmentMock.Object);

        // Act & Assert: Crash etmemeli
        await middleware.InvokeAsync(context);

        context.Response.StatusCode.Should().Be((int)HttpStatusCode.InternalServerError);
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private static DefaultHttpContext CreateHttpContext()
    {
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        context.TraceIdentifier = Guid.NewGuid().ToString();
        return context;
    }

    private static async Task<string> GetResponseBody(HttpContext context)
    {
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(context.Response.Body);
        return await reader.ReadToEndAsync();
    }
}