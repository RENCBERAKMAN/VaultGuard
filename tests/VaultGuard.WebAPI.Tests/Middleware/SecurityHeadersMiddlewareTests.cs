using System;
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using VaultGuard.WebAPI.Middleware;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Middleware;

/// <summary>
/// TEST S��T�: SecurityHeadersMiddleware - HTTP G�venlik Ba�l�klar� Z�rh�
/// 
/// G�VENL�K KAPSAMI:
/// - HSTS (HTTP Strict Transport Security) enforcement
/// - Clickjacking prevention (X-Frame-Options)
/// - MIME sniffing protection
/// - Content Security Policy (CSP)
/// - Permissions Policy (donan�m eri�im kontrol�)
/// - Server information masking
/// 
/// SALDIRI �NLEMES�:
/// - Clickjacking attacks
/// - Cross-site scripting (XSS)
/// - MIME type confusion attacks
/// - Information disclosure (server fingerprinting)
/// - Man-in-the-middle (MITM) attacks
/// </summary>
public class SecurityHeadersMiddlewareTests
{
    private readonly SecurityHeadersMiddleware _middleware;

    public SecurityHeadersMiddlewareTests()
    {
        // Next delegate: Pipeline'� sim�le et
        RequestDelegate next = (HttpContext context) =>
        {
            context.Response.StatusCode = 200;
            return Task.CompletedTask;
        };

        _middleware = new SecurityHeadersMiddleware(next);
    }

    // ============================================================================
    // G�VENL�K TEST�: HSTS (HTTP STRICT TRANSPORT SECURITY)
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_ShouldAddHstsHeader()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: HSTS header var m�?
        context.Response.Headers.Should().ContainKey("Strict-Transport-Security");
    }

    [Fact]
    public async Task InvokeAsync_HstsHeader_ShouldHaveCorrectValue()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: HSTS de�eri do�ru mu?
        var hstsValue = context.Response.Headers["Strict-Transport-Security"].ToString();

        hstsValue.Should().Contain("max-age=31536000"); // 1 y�l
        hstsValue.Should().Contain("includeSubDomains");
        hstsValue.Should().Contain("preload");
    }

    [Fact]
    public async Task InvokeAsync_HstsMaxAge_ShouldBeAtLeastOneYear()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: max-age >= 1 y�l (31536000 saniye)
        var hstsValue = context.Response.Headers["Strict-Transport-Security"].ToString();

        // max-age de�erini ��kar
        var maxAgeMatch = System.Text.RegularExpressions.Regex.Match(hstsValue, @"max-age=(\d+)");
        maxAgeMatch.Success.Should().BeTrue();

        var maxAge = int.Parse(maxAgeMatch.Groups[1].Value);
        maxAge.Should().BeGreaterThanOrEqualTo(31536000); // 1 y�l
    }

    // ============================================================================
    // G�VENL�K TEST�: CLICKJACKING KORUMALARI
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_ShouldAddXFrameOptionsHeader()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: X-Frame-Options header var m�?
        context.Response.Headers.Should().ContainKey("X-Frame-Options");
    }

    [Fact]
    public async Task InvokeAsync_XFrameOptions_ShouldBeDeny()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: DENY de�eri (iframe i�ine al�namaz)
        var xFrameOptions = context.Response.Headers["X-Frame-Options"].ToString();
        xFrameOptions.Should().Be("DENY");
    }

    // ============================================================================
    // G�VENL�K TEST�: MIME SNIFFING KORUMASI
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_ShouldAddXContentTypeOptionsHeader()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: X-Content-Type-Options header var m�?
        context.Response.Headers.Should().ContainKey("X-Content-Type-Options");
    }

    [Fact]
    public async Task InvokeAsync_XContentTypeOptions_ShouldBeNoSniff()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: nosniff de�eri
        var xContentTypeOptions = context.Response.Headers["X-Content-Type-Options"].ToString();
        xContentTypeOptions.Should().Be("nosniff");
    }

    // ============================================================================
    // G�VENL�K TEST�: REFERRER POLICY
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_ShouldAddReferrerPolicyHeader()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert
        context.Response.Headers.Should().ContainKey("Referrer-Policy");
    }

    [Fact]
    public async Task InvokeAsync_ReferrerPolicy_ShouldBeStrictOrigin()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert
        var referrerPolicy = context.Response.Headers["Referrer-Policy"].ToString();
        referrerPolicy.Should().Be("strict-origin-when-cross-origin");
    }

    // ============================================================================
    // G�VENL�K TEST�: XSS KORUMASI (LEGACY)
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_ShouldAddXXssProtectionHeader()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: X-XSS-Protection (eski taray�c�lar i�in)
        context.Response.Headers.Should().ContainKey("X-XSS-Protection");
    }

    [Fact]
    public async Task InvokeAsync_XXssProtection_ShouldBeEnabledWithBlock()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: 1; mode=block
        var xssProtection = context.Response.Headers["X-XSS-Protection"].ToString();
        xssProtection.Should().Be("1; mode=block");
    }

    // ============================================================================
    // G�VENL�K TEST�: PERMISSIONS POLICY (DONANIM ER���M KONTROL�)
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_ShouldAddPermissionsPolicyHeader()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert
        context.Response.Headers.Should().ContainKey("Permissions-Policy");
    }

    [Fact]
    public async Task InvokeAsync_PermissionsPolicy_ShouldDisableHardwareFeatures()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: Kamera, mikrofon, GPS vb. kapal�
        var permissionsPolicy = context.Response.Headers["Permissions-Policy"].ToString();

        permissionsPolicy.Should().Contain("camera=()");
        permissionsPolicy.Should().Contain("microphone=()");
        permissionsPolicy.Should().Contain("geolocation=()");
        permissionsPolicy.Should().Contain("payment=()");
        permissionsPolicy.Should().Contain("usb=()");
    }

    // ============================================================================
    // G�VENL�K TEST�: CONTENT SECURITY POLICY (CSP)
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_ShouldAddContentSecurityPolicyHeader()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: CSP header var m�?
        context.Response.Headers.Should().ContainKey("Content-Security-Policy");
    }

    [Fact]
    public async Task InvokeAsync_CspDefaultSrc_ShouldBeSelf()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: default-src 'self' (sadece kendi kaynaklar)
        var csp = context.Response.Headers["Content-Security-Policy"].ToString();
        csp.Should().Contain("default-src 'self'");
    }

    [Fact]
    public async Task InvokeAsync_CspScriptSrc_ShouldAllowSelfAndUnsafeInline()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: script-src 'self' 'unsafe-inline' (Swagger i�in)
        var csp = context.Response.Headers["Content-Security-Policy"].ToString();
        csp.Should().Contain("script-src 'self' 'unsafe-inline'");
    }

    [Fact]
    public async Task InvokeAsync_CspStyleSrc_ShouldAllowSelfAndUnsafeInline()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: style-src 'self' 'unsafe-inline'
        var csp = context.Response.Headers["Content-Security-Policy"].ToString();
        csp.Should().Contain("style-src 'self' 'unsafe-inline'");
    }

    [Fact]
    public async Task InvokeAsync_CspImgSrc_ShouldAllowSelfDataAndHttps()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: img-src 'self' data: https:
        var csp = context.Response.Headers["Content-Security-Policy"].ToString();
        csp.Should().Contain("img-src 'self' data: https:");
    }

    [Fact]
    public async Task InvokeAsync_CspFrameAncestors_ShouldBeNone()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: frame-ancestors 'none' (clickjacking �nleme)
        var csp = context.Response.Headers["Content-Security-Policy"].ToString();
        csp.Should().Contain("frame-ancestors 'none'");
    }

    [Fact]
    public async Task InvokeAsync_CspFormAction_ShouldBeSelf()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: form-action 'self'
        var csp = context.Response.Headers["Content-Security-Policy"].ToString();
        csp.Should().Contain("form-action 'self'");
    }

    // ============================================================================
    // G�VENL�K TEST�: SUNUCU B�LG�S� MASKELEME
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_ShouldRemoveServerHeader()
    {
        // Arrange
        var context = CreateHttpContext();
        context.Response.Headers.Add("Server", "Microsoft-IIS/10.0"); // Simulated

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: Server header silinmeli
        context.Response.Headers.Should().NotContainKey("Server");
    }

    [Fact]
    public async Task InvokeAsync_ShouldRemoveXPoweredByHeader()
    {
        // Arrange
        var context = CreateHttpContext();
        context.Response.Headers.Add("X-Powered-By", "ASP.NET"); // Simulated

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: X-Powered-By header silinmeli
        context.Response.Headers.Should().NotContainKey("X-Powered-By");
    }

    [Fact]
    public async Task InvokeAsync_ShouldRemoveXAspNetVersionHeader()
    {
        // Arrange
        var context = CreateHttpContext();
        context.Response.Headers.Add("X-AspNet-Version", "4.0.30319"); // Simulated

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: X-AspNet-Version header silinmeli
        context.Response.Headers.Should().NotContainKey("X-AspNet-Version");
    }

    [Fact]
    public async Task InvokeAsync_MultipleServerHeaders_ShouldRemoveAll()
    {
        // Arrange: Birden fazla server bilgisi header
        var context = CreateHttpContext();
        context.Response.Headers.Add("Server", "Kestrel");
        context.Response.Headers.Add("X-Powered-By", "ASP.NET Core");
        context.Response.Headers.Add("X-AspNet-Version", "5.0.0");
        context.Response.Headers.Add("X-AspNetMvc-Version", "5.2.7");

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: T�m server bilgisi header'lar� silinmeli
        context.Response.Headers.Should().NotContainKey("Server");
        context.Response.Headers.Should().NotContainKey("X-Powered-By");
        context.Response.Headers.Should().NotContainKey("X-AspNet-Version");
    }

    // ============================================================================
    // G�VENL�K TEST�: HEADER LIFECYCLE (OnStarting)
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_ShouldAddHeadersBeforeResponseStarts()
    {
        // Arrange
        var context = CreateHttpContext();
        var headersAddedInOnStarting = false;

        context.Response.OnStarting(() =>
        {
            // OnStarting callback i�inde header'lar eklenmi� olmal�
            headersAddedInOnStarting = context.Response.Headers.ContainsKey("Strict-Transport-Security");
            return Task.CompletedTask;
        });

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: Header'lar OnStarting'de eklendi
        headersAddedInOnStarting.Should().BeTrue();
    }

    [Fact]
    public async Task InvokeAsync_ShouldNotOverwriteExistingSecurityHeaders()
    {
        // Arrange: Baz� header'lar zaten var
        var context = CreateHttpContext();
        context.Response.Headers.Add("X-Frame-Options", "SAMEORIGIN"); // �nceden var

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: Mevcut header override edilmeli (DENY ile)
        var xFrameOptions = context.Response.Headers["X-Frame-Options"].ToString();
        xFrameOptions.Should().Be("DENY");
    }

    // ============================================================================
    // G�VENL�K TEST�: T�M HEADER'LAR B�RL�KTE
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_ShouldAddAllRequiredSecurityHeaders()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: T�m g�venlik header'lar� mevcut
        var requiredHeaders = new[]
        {
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "X-XSS-Protection",
            "Permissions-Policy",
            "Content-Security-Policy"
        };

        foreach (var header in requiredHeaders)
        {
            context.Response.Headers.Should().ContainKey(header,
                because: $"{header} is a critical security header");
        }
    }

    [Fact]
    public async Task InvokeAsync_ShouldNotContainAnyServerIdentificationHeaders()
    {
        // Arrange
        var context = CreateHttpContext();

        // Simulated server headers
        context.Response.Headers.Add("Server", "Kestrel");
        context.Response.Headers.Add("X-Powered-By", "ASP.NET");
        context.Response.Headers.Add("X-AspNet-Version", "5.0");

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: Sunucu kimlik header'lar� yok
        var forbiddenHeaders = new[]
        {
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-AspNetMvc-Version"
        };

        foreach (var header in forbiddenHeaders)
        {
            context.Response.Headers.Should().NotContainKey(header,
                because: $"{header} reveals server information");
        }
    }

    // ============================================================================
    // EDGE CASE TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_MultipleRequests_ShouldAddHeadersConsistently()
    {
        // Arrange: Birden fazla request
        var context1 = CreateHttpContext();
        var context2 = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context1);
        await _middleware.InvokeAsync(context2);

        // Assert: Her iki response da ayn� header'lara sahip
        var headers1 = context1.Response.Headers.Keys.OrderBy(k => k).ToList();
        var headers2 = context2.Response.Headers.Keys.OrderBy(k => k).ToList();

        headers1.Should().BeEquivalentTo(headers2);
    }

    [Fact]
    public async Task InvokeAsync_ResponseAlreadyStarted_ShouldNotCrash()
    {
        // Arrange: Response zaten ba�lam�� (edge case)
        var context = CreateHttpContext();

        // Next delegate response'u ba�lat�yor
        RequestDelegate startedNext = async (HttpContext ctx) =>
        {
            await ctx.Response.WriteAsync("Started");
        };

        var middleware = new SecurityHeadersMiddleware(startedNext);

        // Act & Assert: Crash etmemeli
        var act = async () => await middleware.InvokeAsync(context);
        await act.Should().NotThrowAsync();
    }

    // ============================================================================
    // COMPLIANCE TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_HeadersShouldComplywithOWASPStandards()
    {
        // Arrange
        var context = CreateHttpContext();

        // Act
        await _middleware.InvokeAsync(context);

        // Assert: OWASP Secure Headers Project uyumlulu�u
        // https://owasp.org/www-project-secure-headers/

        var headers = context.Response.Headers;

        // HSTS: max-age minimum 1 y�l
        var hsts = headers["Strict-Transport-Security"].ToString();
        hsts.Should().MatchRegex(@"max-age=\d{8,}"); // En az 8 basamak (>1 y�l)

        // X-Frame-Options: DENY veya SAMEORIGIN
        var xFrameOptions = headers["X-Frame-Options"].ToString();
        xFrameOptions.Should().BeOneOf("DENY", "SAMEORIGIN");

        // CSP: en az default-src ve script-src tan�ml�
        var csp = headers["Content-Security-Policy"].ToString();
        csp.Should().Contain("default-src");
        csp.Should().Contain("script-src");
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private static DefaultHttpContext CreateHttpContext()
    {
        var context = new DefaultHttpContext();
        return context;
    }
}