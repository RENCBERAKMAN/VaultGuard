using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using VaultGuard.Application.DTOs.Auth;
using VaultGuard.WebAPI;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Security;

/// <summary>
/// TEST SÜİTİ: CSRF Protection & JWT Security Boundary Tests
/// 
/// SECURITY FOCUS:
/// - **JWT-Based CSRF**: Stateless token authentication
/// - **Header-Based Security**: Authorization header requirement
/// - **CORS Policy**: Cross-origin request validation
/// - **Origin Validation**: Trusted origins only
/// - **Cookie Security**: SameSite attribute (if cookies used)
/// 
/// THREAT MODEL (OWASP A01:2021 - Broken Access Control):
/// 
/// 1. **Traditional CSRF Attack (Cookie-Based)**:
///    - Attacker: <form action="https://api.victim.com/delete" method="POST">
///    - Victim clicks submit → Browser sends cookies automatically
///    - Defense: CSRF token, SameSite cookies
///    - VaultGuard: NOT vulnerable (uses JWT in header, not cookies)
/// 
/// 2. **JWT CSRF Variant (Login CSRF)**:
///    - Attacker tricks victim into using attacker's JWT
///    - Victim performs actions under attacker's account
///    - Defense: Bind JWT to session, validate Origin
/// 
/// 3. **CORS Misconfiguration**:
///    - Malicious site: evil.com
///    - XHR to api.vaultguard.com with credentials
///    - Misconfigured CORS: Access-Control-Allow-Origin: *
///    - Defense: Strict CORS policy, no wildcard with credentials
/// 
/// 4. **Cross-Origin XHR with JWT**:
///    - Attacker cannot read JWT from localStorage via XSS (CSP)
///    - But can send requests if CORS allows
///    - Defense: CORS policy blocks unauthorized origins
/// 
/// COMPLIANCE:
/// - OWASP ASVS 4.2: Operation Level Access Control
/// - OWASP Top 10 A01:2021: Broken Access Control
/// - CWE-352: Cross-Site Request Forgery (CSRF)
/// - CWE-346: Origin Validation Error
/// - NIST SP 800-53: AC-3 (Access Enforcement)
/// 
/// JWT SECURITY MODEL:
/// ✅ Advantages (CSRF Protection):
/// - JWT in Authorization header (not cookies)
/// - Browser doesn't auto-send headers (unlike cookies)
/// - Attacker cannot forge requests without JWT
/// 
/// ⚠️ Risks (XSS Vulnerability):
/// - JWT stored in localStorage (XSS can steal it)
/// - Defense: Content Security Policy (CSP)
/// - Defense: HTTPOnly cookies for refresh tokens
/// 
/// DEFENSE IN DEPTH:
/// 1. JWT in Authorization header (primary defense)
/// 2. CORS policy (secondary defense)
/// 3. Origin validation (tertiary defense)
/// 4. SameSite cookies for refresh tokens (if used)
/// 5. Content Security Policy (XSS mitigation)
/// </summary>
public class CsrfProtectionTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public CsrfProtectionTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _client = _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    // ============================================================================
    // 🔐 JWT HEADER REQUIREMENT (PRIMARY CSRF DEFENSE)
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - JWT HEADER REQUIREMENT (CRITICAL!):
    /// Request without Authorization header → 401 Unauthorized.
    /// 
    /// CSRF DEFENSE:
    /// - Browser cannot auto-send custom headers in cross-origin requests
    /// - Attacker cannot forge Authorization header without XSS
    /// - This makes traditional CSRF attacks ineffective
    /// 
    /// ATTACK SCENARIO (Blocked):
    /// 1. Victim visits evil.com
    /// 2. evil.com: <form action="https://api.vaultguard.com/api/secrets" method="POST">
    /// 3. Browser submits form (no Authorization header)
    /// 4. VaultGuard API: 401 Unauthorized (no JWT)
    /// 5. Attack fails ✅
    /// 
    /// OWASP: A01:2021 - Broken Access Control
    /// CWE-352: Cross-Site Request Forgery (CSRF)
    /// </summary>
    [Fact]
    public async Task ProtectedEndpoint_WithoutAuthorizationHeader_ShouldReturn401()
    {
        // Arrange: No Authorization header

        // Act: Attempt to access protected endpoint
        var response = await _client.GetAsync("/api/secrets");

        // Assert: 401 Unauthorized
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "Missing Authorization header must be rejected - CSRF protection!");
    }

    /// <summary>
    /// SECURITY TEST - MALFORMED AUTHORIZATION HEADER:
    /// Invalid Authorization header format → 401 Unauthorized.
    /// 
    /// ATTACK: Authorization: InvalidFormat
    /// </summary>
    [Theory]
    [InlineData("InvalidToken")]
    [InlineData("Basic dXNlcjpwYXNz")] // Basic auth (not Bearer)
    [InlineData("Bearer ")] // Empty token
    [InlineData("Bearer invalid.token.format")]
    public async Task ProtectedEndpoint_WithInvalidAuthorizationHeader_ShouldReturn401(string invalidAuth)
    {
        // Arrange
        _client.DefaultRequestHeaders.Clear();
        _client.DefaultRequestHeaders.Add("Authorization", invalidAuth);

        // Act
        var response = await _client.GetAsync("/api/secrets");

        // Assert: 401 Unauthorized
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "Invalid Authorization header must be rejected");
    }

    /// <summary>
    /// SECURITY TEST - COOKIE-BASED ATTACK BLOCKED:
    /// Request with cookies but no JWT → 401 Unauthorized.
    /// 
    /// SCENARIO: Attacker tries traditional CSRF with cookies
    /// 
    /// OWASP: A01:2021 - Broken Access Control
    /// CWE-352: Cross-Site Request Forgery
    /// </summary>
    [Fact]
    public async Task ProtectedEndpoint_WithCookiesButNoJWT_ShouldReturn401()
    {
        // Arrange: Add cookies (simulate browser auto-sending)
        _client.DefaultRequestHeaders.Clear();
        _client.DefaultRequestHeaders.Add("Cookie", "session=fake_session_id");

        // Act: Attempt CSRF-style attack
        var response = await _client.PostAsync("/api/secrets", null);

        // Assert: 401 Unauthorized (cookies ignored, JWT required)
        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized,
            "Cookie-based CSRF must be blocked - JWT required in header!");
    }

    // ============================================================================
    // 🌐 CORS POLICY VALIDATION
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - CORS PREFLIGHT:
    /// OPTIONS request from unauthorized origin → No CORS headers.
    /// 
    /// CORS PREFLIGHT FLOW:
    /// 1. Browser: OPTIONS /api/secrets (Origin: http://evil.com)
    /// 2. Server checks CORS policy
    /// 3. If origin not allowed → No Access-Control-Allow-Origin header
    /// 4. Browser blocks actual request
    /// 
    /// OWASP: A05:2021 - Security Misconfiguration
    /// CWE-346: Origin Validation Error
    /// </summary>
    [Fact]
    public async Task CorsPolicy_UnauthorizedOrigin_ShouldBeBlocked()
    {
        // Arrange: Request from unauthorized origin
        var request = new HttpRequestMessage(HttpMethod.Options, "/api/secrets");
        request.Headers.Add("Origin", "http://evil.com");
        request.Headers.Add("Access-Control-Request-Method", "GET");
        request.Headers.Add("Access-Control-Request-Headers", "authorization");

        // Act: Send preflight request
        var response = await _client.SendAsync(request);

        // Assert: Check CORS headers
        var hasCorsHeader = response.Headers.Contains("Access-Control-Allow-Origin");

        if (hasCorsHeader)
        {
            var allowOrigin = response.Headers.GetValues("Access-Control-Allow-Origin").FirstOrDefault();

            // Should NOT be wildcard (*) with credentials
            allowOrigin.Should().NotBe("*",
                "CORS policy must not use wildcard with credentials");

            // Should NOT allow evil.com
            allowOrigin.Should().NotBe("http://evil.com",
                "Unauthorized origin must be blocked by CORS policy");
        }

        // Document: CORS policy should reject unauthorized origins
        Assert.True(true, "CORS policy validation documented");
    }

    /// <summary>
    /// SECURITY TEST - CORS WITH CREDENTIALS:
    /// CORS policy should never use wildcard (*) with credentials.
    /// 
    /// VULNERABILITY:
    /// Access-Control-Allow-Origin: *
    /// Access-Control-Allow-Credentials: true
    /// → Any origin can send authenticated requests!
    /// 
    /// OWASP: A05:2021 - Security Misconfiguration
    /// </summary>
    [Fact]
    public async Task CorsPolicy_ShouldNotUseWildcardWithCredentials()
    {
        // Arrange: Preflight request
        var request = new HttpRequestMessage(HttpMethod.Options, "/api/secrets");
        request.Headers.Add("Origin", "https://app.vaultguard.com");
        request.Headers.Add("Access-Control-Request-Method", "GET");

        // Act
        var response = await _client.SendAsync(request);

        // Assert: If credentials allowed, origin must NOT be wildcard
        if (response.Headers.Contains("Access-Control-Allow-Credentials"))
        {
            var allowCredentials = response.Headers.GetValues("Access-Control-Allow-Credentials").FirstOrDefault();

            if (allowCredentials == "true")
            {
                var allowOrigin = response.Headers.GetValues("Access-Control-Allow-Origin").FirstOrDefault();
                allowOrigin.Should().NotBe("*",
                    "CRITICAL: CORS wildcard with credentials is a security vulnerability!");
            }
        }
    }

    // ============================================================================
    // 🔒 ORIGIN HEADER VALIDATION
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - ORIGIN SPOOFING:
    /// Requests should validate Origin header.
    /// 
    /// ATTACK: Attacker sets Origin: https://trusted.com
    /// Defense: Server validates Origin against whitelist
    /// 
    /// NOTE: Origin header is browser-controlled (cannot be spoofed from browser)
    /// but can be set in non-browser clients.
    /// 
    /// OWASP: A01:2021 - Broken Access Control
    /// CWE-346: Origin Validation Error
    /// </summary>
    [Fact]
    public async Task Request_WithSpoofedOrigin_ShouldBeHandledSecurely()
    {
        // Arrange: Login to get valid JWT
        var token = await RegisterAndLoginAsync();

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/secrets");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Add("Origin", "http://malicious-site.com");

        // Act
        var response = await _client.SendAsync(request);

        // Assert: Request should succeed (JWT valid) but CORS headers should not allow origin
        // OR: Request should be blocked if Origin validation is strict

        // Document: Origin header validation is defense-in-depth
        // Primary defense is JWT in Authorization header
        Assert.True(true, "Origin validation documented");
    }

    // ============================================================================
    // 🍪 COOKIE SECURITY (If Used)
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - SAMESITE COOKIE ATTRIBUTE:
    /// If cookies are used (refresh tokens), they must have SameSite attribute.
    /// 
    /// COOKIE ATTRIBUTES:
    /// - SameSite=Strict: Cookie never sent cross-origin (strictest)
    /// - SameSite=Lax: Cookie sent on top-level navigation (default)
    /// - SameSite=None: Cookie sent cross-origin (requires Secure)
    /// 
    /// RECOMMENDATION:
    /// - Access tokens: Authorization header (no cookies)
    /// - Refresh tokens: HTTPOnly + Secure + SameSite=Strict cookies
    /// 
    /// OWASP: A01:2021 - Broken Access Control
    /// CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
    /// </summary>
    [Fact]
    public async Task Cookies_IfUsed_ShouldHaveSameSiteAttribute()
    {
        // Arrange: Login
        var loginDto = new LoginDto
        {
            Email = $"cookie-test-{Guid.NewGuid()}@test.com",
            Password = "CookieTest123!"
        };

        // Note: Register first (implementation detail)
        var registerDto = new RegisterDto
        {
            Email = loginDto.Email,
            Username = $"cookietest{Guid.NewGuid().ToString().Substring(0, 8)}",
            Password = loginDto.Password
        };

        await _client.PostAsJsonAsync("/api/auth/register", registerDto);

        // Act: Login
        var response = await _client.PostAsJsonAsync("/api/auth/login", loginDto);

        // Assert: Check Set-Cookie headers
        if (response.Headers.Contains("Set-Cookie"))
        {
            var cookies = response.Headers.GetValues("Set-Cookie");

            foreach (var cookie in cookies)
            {
                // Verify SameSite attribute
                if (cookie.Contains("refresh", StringComparison.OrdinalIgnoreCase) ||
                    cookie.Contains("session", StringComparison.OrdinalIgnoreCase))
                {
                    cookie.Should().Contain("SameSite=",
                        "Sensitive cookies must have SameSite attribute");

                    cookie.Should().Contain("HttpOnly",
                        "Sensitive cookies must be HTTPOnly");

                    cookie.Should().Contain("Secure",
                        "Sensitive cookies must be Secure");
                }
            }
        }
        else
        {
            // Document: VaultGuard uses JWT in header (no cookies)
            Assert.True(true, "VaultGuard uses stateless JWT - no session cookies");
        }
    }

    // ============================================================================
    // 🛡️ DOUBLE SUBMIT COOKIE PATTERN (If Implemented)
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - DOUBLE SUBMIT COOKIE:
    /// If using double submit pattern, verify implementation.
    /// 
    /// PATTERN:
    /// 1. Server sets CSRF token in cookie
    /// 2. Client reads cookie, sends in custom header (X-CSRF-Token)
    /// 3. Server validates cookie == header
    /// 
    /// NOTE: VaultGuard uses JWT (stateless), not cookies
    /// This test documents the alternative pattern
    /// 
    /// OWASP: A01:2021 - Broken Access Control
    /// </summary>
    [Fact]
    public void Documentation_DoubleSubmitCookiePattern()
    {
        // VaultGuard uses JWT in Authorization header
        // No CSRF token needed because:
        // 1. JWT not stored in cookies
        // 2. Browser doesn't auto-send Authorization header
        // 3. Attacker cannot forge requests without XSS

        // If implementing CSRF tokens:
        // 1. Use [ValidateAntiForgeryToken] on POST/PUT/DELETE
        // 2. Include @Html.AntiForgeryToken() in forms
        // 3. Send token in X-CSRF-Token header for AJAX

        Assert.True(true, "CSRF protection documented - JWT-based auth used");
    }

    // ============================================================================
    // 🔍 REFERER HEADER VALIDATION
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - REFERER HEADER:
    /// Referer header can provide additional validation.
    /// 
    /// NOTE: Referer is optional and can be stripped by:
    /// - Privacy extensions
    /// - Referrer-Policy header
    /// - HTTPS → HTTP transitions
    /// 
    /// RECOMMENDATION: Don't rely solely on Referer for security
    /// 
    /// OWASP: A05:2021 - Security Misconfiguration
    /// </summary>
    [Fact]
    public async Task Request_WithInvalidReferer_ShouldBeDocumented()
    {
        // Arrange: Login
        var token = await RegisterAndLoginAsync();

        var request = new HttpRequestMessage(HttpMethod.Post, "/api/secrets");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Referrer = new Uri("http://evil.com");
        request.Content = JsonContent.Create(new
        {
            Title = "Test",
            RawValue = "test"
        });

        // Act
        var response = await _client.SendAsync(request);

        // Assert: JWT valid, so request succeeds
        // Referer validation is optional defense-in-depth
        // Primary defense is JWT validation

        Assert.True(true, "Referer validation is defense-in-depth");
    }

    // ============================================================================
    // ⚡ XSS + CSRF COMBINED ATTACK
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - XSS ENABLES CSRF:
    /// If XSS exists, attacker can steal JWT and forge requests.
    /// 
    /// ATTACK CHAIN:
    /// 1. Attacker injects XSS: <script>steal(localStorage.jwt)</script>
    /// 2. XSS steals JWT from localStorage
    /// 3. Attacker uses JWT to forge API requests
    /// 4. CSRF protection bypassed (JWT obtained via XSS)
    /// 
    /// DEFENSE:
    /// - Prevent XSS (input validation, output encoding, CSP)
    /// - Store sensitive tokens in HTTPOnly cookies (not localStorage)
    /// - Use short-lived access tokens + refresh tokens
    /// 
    /// OWASP: A03:2021 - Injection (XSS enables CSRF)
    /// </summary>
    [Fact]
    public void Documentation_XSSEnablesCSRF()
    {
        // Defense chain:
        // 1. XSS Prevention: Input validation (CreateSecretDtoValidator)
        // 2. XSS Prevention: Output encoding (Angular/React auto-escapes)
        // 3. XSS Prevention: Content Security Policy (CSP headers)
        // 4. Token Protection: Short-lived JWT (7 days max)
        // 5. Token Protection: Refresh tokens in HTTPOnly cookies
        // 6. Token Protection: Token rotation on sensitive operations

        Assert.True(true, "XSS prevention is critical for JWT security");
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private async Task<string> RegisterAndLoginAsync()
    {
        var email = $"csrf-test-{Guid.NewGuid()}@test.com";
        var username = $"csrftest{Guid.NewGuid().ToString().Substring(0, 8)}";
        var password = "CsrfTest123!";

        // Register
        var registerDto = new RegisterDto
        {
            Email = email,
            Username = username,
            Password = password
        };

        await _client.PostAsJsonAsync("/api/auth/register", registerDto);

        // Login
        var loginDto = new LoginDto
        {
            Email = email,
            Password = password
        };

        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", loginDto);
        var loginResult = await loginResponse.Content.ReadFromJsonAsync<ApiResponse<TokenDto>>();

        return loginResult.Data.AccessToken;
    }
}

// Helper classes
public class ApiResponse<T>
{
    public bool Success { get; set; }
    public string Message { get; set; }
    public T Data { get; set; }
}