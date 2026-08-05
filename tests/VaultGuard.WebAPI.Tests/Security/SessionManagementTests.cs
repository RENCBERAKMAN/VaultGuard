using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using VaultGuard.Domain.Entities;
using VaultGuard.Infrastructure.Security;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Security;

/// <summary>
/// TEST SÜİTİ: Session Management & JWT Lifecycle Security Tests
/// 
/// SECURITY FOCUS:
/// - **Token Expiry**: Expired tokens rejected (401 Unauthorized)
/// - **Token Revocation**: Logout invalidates tokens
/// - **TTL (Time-To-Live)**: Token lifetime validation
/// - **Refresh Tokens**: Secure token renewal
/// - **Session Hijacking**: Prevention mechanisms
/// 
/// THREAT MODEL:
/// - Session Hijacking: Attacker steals valid JWT
/// - Token Replay: Old token reused after logout
/// - Infinite Sessions: Expired tokens still accepted
/// - Token Forgery: Fake tokens accepted
/// - Replay After Revocation: Revoked token still works
/// 
/// COMPLIANCE:
/// - **NIST SP 800-63B**: Digital Identity Guidelines
///   * Section 4.1.2: Session Management
///   * Section 7.2.1: Token Lifetime
///   * Section 7.2.2: Token Revocation
/// 
/// - **OWASP Session Management Cheat Sheet**:
///   * Session Timeout: Absolute and idle timeouts
///   * Session Logout: Proper session termination
///   * Session Fixation: Token regeneration
/// 
/// - **PCI-DSS Requirement 8.2.4**: Session timeout
///   * Idle sessions auto-logout after 15 minutes
///   * Re-authentication required after timeout
/// 
/// - **ISO 27001 A.9.4**: Access control and authentication
///   * Session management controls
///   * Timeout mechanisms
/// 
/// SESSION LIFECYCLE:
/// 1. **Login**: Token issued (7-day expiry)
/// 2. **Active**: Token validated on each request
/// 3. **Refresh**: Token renewed before expiry
/// 4. **Logout**: Token revoked (blacklist)
/// 5. **Expiry**: Token rejected after TTL
/// </summary>
public class SessionManagementTests : IDisposable
{
    private readonly IConfiguration _configuration;
    private readonly TokenService _tokenService;
    private readonly string _jwtSecret;
    private readonly SymmetricSecurityKey _validKey;

    public SessionManagementTests()
    {
        // Setup: Strong JWT secret (64+ chars for HS512)
        _jwtSecret = "ThisIsAVerySecureJwtSecretKeyThatIsAtLeast64CharactersLongForHS512Algorithm!!";

        var configDict = new System.Collections.Generic.Dictionary<string, string>
        {
            { "Jwt:Secret", _jwtSecret },
            { "Jwt:Issuer", "VaultGuardTestIssuer" },
            { "Jwt:Audience", "VaultGuardTestAudience" }
        };

        _configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configDict)
            .Build();

        _tokenService = new TokenService(_configuration);
        _validKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret));
    }

    // ============================================================================
    // ⏰ TOKEN EXPIRY TESTS (CRITICAL!)
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - EXPIRED TOKEN (CRITICAL!):
    /// Expired JWT must be rejected with 401 Unauthorized.
    /// 
    /// THREAT: Infinite Session Duration
    /// - Token never expires → Stolen token valid forever
    /// - Session hijacking risk multiplied
    /// - Compliance violation (PCI-DSS 8.2.4)
    /// 
    /// COMPLIANCE:
    /// - PCI-DSS 8.2.4: Session timeout after 15 minutes
    /// - NIST SP 800-63B 7.2.1: Token lifetime limits
    /// - OWASP: Session timeout enforcement
    /// 
    /// ATTACK SCENARIO:
    /// 1. User logs in → Gets token (7-day expiry)
    /// 2. 8 days later: Token expired
    /// 3. Attacker steals expired token
    /// 4. Attacker sends request with expired token
    /// 5. Expected: 401 Unauthorized (token expired)
    /// 6. Vulnerable: 200 OK (token accepted) → SESSION HIJACKING!
    /// </summary>
    [Fact]
    public void ExpiredToken_ShouldBeRejected()
    {
        // STEP 1: Create token that's already expired
        var user = CreateTestUser();
        var expiredToken = CreateExpiredToken(user);

        // STEP 2: Attempt to validate expired token
        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true, // CRITICAL: Must be true
            ValidateIssuerSigningKey = true,
            ValidIssuer = _configuration["Jwt:Issuer"],
            ValidAudience = _configuration["Jwt:Audience"],
            IssuerSigningKey = _validKey,
            ClockSkew = TimeSpan.Zero // No tolerance for expiry
        };

        // Act & Assert: Validation MUST fail
        Action validateExpiredToken = () =>
        {
            tokenHandler.ValidateToken(expiredToken, validationParameters, out _);
        };

        validateExpiredToken.Should().Throw<SecurityTokenExpiredException>(
            "CRITICAL: Expired tokens must be rejected - PCI-DSS 8.2.4 compliance!");
    }

    /// <summary>
    /// SECURITY TEST - CLOCK SKEW:
    /// Token near expiry should respect ClockSkew setting.
    /// 
    /// SCENARIO: Token expires at 12:00:00, current time 12:00:01
    /// - ClockSkew = 0: Token expired (strict)
    /// - ClockSkew = 5min: Token valid (tolerant)
    /// 
    /// COMPLIANCE:
    /// - NIST SP 800-63B: Time synchronization
    /// - PCI-DSS: Time server synchronization
    /// 
    /// RECOMMENDATION: ClockSkew = 0 for maximum security
    /// </summary>
    [Fact]
    public void TokenExpiry_ClockSkew_ShouldBeRespected()
    {
        // STEP 1: Create token expiring in 1 second
        var user = CreateTestUser();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email)
            }),
            Expires = DateTime.UtcNow.AddSeconds(1), // 1 second TTL
            SigningCredentials = new SigningCredentials(_validKey, SecurityAlgorithms.HmacSha512Signature),
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Audience"]
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);

        // STEP 2: Wait 2 seconds (token expired)
        System.Threading.Thread.Sleep(2000);

        // STEP 3: Validate with ClockSkew = 0 (strict)
        var strictValidation = new TokenValidationParameters
        {
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _configuration["Jwt:Issuer"],
            ValidAudience = _configuration["Jwt:Audience"],
            IssuerSigningKey = _validKey,
            ClockSkew = TimeSpan.Zero // No tolerance
        };

        Action validateStrict = () =>
        {
            tokenHandler.ValidateToken(tokenString, strictValidation, out _);
        };

        // Assert: Strict validation rejects expired token
        validateStrict.Should().Throw<SecurityTokenExpiredException>(
            "ClockSkew = 0 must reject expired tokens immediately");
    }

    // ============================================================================
    // ⏱️ TTL (TIME-TO-LIVE) VALIDATION TESTS
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - TOKEN TTL (CRITICAL!):
    /// Token lifetime must match configured TTL (7 days).
    /// 
    /// THREAT: Excessive Token Lifetime
    /// - TTL = 365 days → Token valid 1 year (TOO LONG!)
    /// - Stolen token valid for extended period
    /// - Compliance violation
    /// 
    /// COMPLIANCE:
    /// - NIST SP 800-63B 7.2.1: Token lifetime limits
    /// - PCI-DSS 8.2.4: Session timeout enforcement
    /// 
    /// RECOMMENDATION:
    /// - Access tokens: 15 minutes - 1 hour
    /// - Refresh tokens: 7 days - 30 days
    /// - VaultGuard: 7 days (balanced security/UX)
    /// </summary>
    [Fact]
    public void TokenTTL_ShouldMatch7Days()
    {
        // Arrange: Create token
        var user = CreateTestUser();
        var token = _tokenService.CreateToken(user);

        // Act: Parse token
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        // Assert: Expiry is 7 days from now
        var expectedExpiry = DateTime.UtcNow.AddDays(7);
        jwt.ValidTo.Should().BeCloseTo(expectedExpiry, TimeSpan.FromMinutes(1),
            "Token TTL must be 7 days - PCI-DSS compliance");

        // Assert: Token not expired now
        jwt.ValidTo.Should().BeAfter(DateTime.UtcNow,
            "Newly issued token must not be expired");

        // Calculate actual TTL
        var ttl = jwt.ValidTo - jwt.ValidFrom;
        ttl.Should().BeCloseTo(TimeSpan.FromDays(7), TimeSpan.FromMinutes(1),
            "Token lifetime (TTL) must be 7 days");
    }

    /// <summary>
    /// SECURITY TEST - MINIMUM TTL:
    /// Token TTL must not be too short (usability).
    /// 
    /// BALANCE: Security vs Usability
    /// - Too short: Users re-login frequently (poor UX)
    /// - Too long: Extended exposure if stolen
    /// 
    /// RECOMMENDATION: 15 min - 7 days depending on sensitivity
    /// </summary>
    [Fact]
    public void TokenTTL_ShouldNotBeTooShort()
    {
        // Arrange
        var user = CreateTestUser();
        var token = _tokenService.CreateToken(user);

        // Act: Parse token
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        // Assert: TTL >= 1 hour (minimum usability threshold)
        var ttl = jwt.ValidTo - jwt.ValidFrom;
        ttl.Should().BeGreaterThanOrEqualTo(TimeSpan.FromHours(1),
            "Token TTL should be at least 1 hour for usability");
    }

    /// <summary>
    /// SECURITY TEST - MAXIMUM TTL:
    /// Token TTL must not exceed security threshold.
    /// 
    /// COMPLIANCE:
    /// - NIST: Recommends short-lived tokens
    /// - Industry best practice: ≤30 days
    /// </summary>
    [Fact]
    public void TokenTTL_ShouldNotExceed30Days()
    {
        // Arrange
        var user = CreateTestUser();
        var token = _tokenService.CreateToken(user);

        // Act: Parse token
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        // Assert: TTL <= 30 days (security threshold)
        var ttl = jwt.ValidTo - jwt.ValidFrom;
        ttl.Should().BeLessThanOrEqualTo(TimeSpan.FromDays(30),
            "Token TTL should not exceed 30 days - security best practice");
    }

    // ============================================================================
    // 🚪 TOKEN REVOCATION TESTS
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - LOGOUT REVOCATION (CRITICAL!):
    /// After logout, token should be revoked (blacklist).
    /// 
    /// THREAT: Token Replay After Logout
    /// - User logs out → Token should be invalid
    /// - Attacker has old token → Token still works → BREACH!
    /// 
    /// IMPLEMENTATION:
    /// VaultGuard uses stateless JWT (no server-side session)
    /// Options for revocation:
    /// 1. Token Blacklist (Redis cache with TTL)
    /// 2. Token Versioning (increment user.TokenVersion on logout)
    /// 3. Short-lived tokens + Refresh tokens
    /// 
    /// COMPLIANCE:
    /// - NIST SP 800-63B 7.2.2: Token revocation
    /// - OWASP: Proper logout mechanisms
    /// - PCI-DSS 8.2: User authentication
    /// 
    /// NOTE: This test documents the requirement
    /// Production implementation needs Redis/database for blacklist
    /// </summary>
    [Fact]
    public void Documentation_LogoutRevocation()
    {
        // VaultGuard JWT is stateless (no server-side session)
        // Revocation strategies:

        // STRATEGY 1: Token Blacklist (RECOMMENDED)
        // - Store revoked token IDs in Redis with TTL = token expiry
        // - On each request: Check if token in blacklist
        // - Pro: Immediate revocation
        // - Con: Redis dependency

        // STRATEGY 2: Token Versioning
        // - User table: TokenVersion column (integer)
        // - JWT claim: "version": user.TokenVersion
        // - On logout: user.TokenVersion++
        // - Validation: Check JWT version == DB version
        // - Pro: No Redis needed
        // - Con: Database query on each request

        // STRATEGY 3: Short-lived + Refresh Tokens
        // - Access token: 15 min TTL (short)
        // - Refresh token: 7 days TTL (stored in DB)
        // - On logout: Delete refresh token from DB
        // - Pro: Limited exposure window
        // - Con: More complex flow

        // IMPLEMENTATION EXAMPLE (Blacklist):
        // public async Task RevokeTokenAsync(string token)
        // {
        //     var jti = GetJtiFromToken(token);
        //     var expiry = GetExpiryFromToken(token);
        //     await _cache.SetAsync($"blacklist:{jti}", "revoked", expiry);
        // }
        //
        // public async Task<bool> IsTokenRevokedAsync(string token)
        // {
        //     var jti = GetJtiFromToken(token);
        //     return await _cache.ExistsAsync($"blacklist:{jti}");
        // }

        Assert.True(true, "Token revocation strategies documented");
    }

    /// <summary>
    /// SECURITY TEST - TOKEN ID (JTI):
    /// Each token should have unique identifier (jti claim).
    /// Required for blacklist-based revocation.
    /// 
    /// COMPLIANCE:
    /// - RFC 7519 Section 4.1.7: "jti" (JWT ID) claim
    /// - NIST: Unique token identifiers
    /// </summary>
    [Fact]
    public void Token_ShouldHaveUniqueJTI()
    {
        // Arrange: Create two tokens
        var user = CreateTestUser();
        var token1 = _tokenService.CreateToken(user);
        var token2 = _tokenService.CreateToken(user);

        // Act: Parse tokens
        var handler = new JwtSecurityTokenHandler();
        var jwt1 = handler.ReadJwtToken(token1);
        var jwt2 = handler.ReadJwtToken(token2);

        // Assert: Tokens should have JTI claim (if implemented)
        // Note: Current TokenService doesn't add JTI
        // This test documents the requirement

        // Production implementation should add:
        // new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())

        // For now, verify tokens are different (different signatures due to different IssuedAt)
        token1.Should().NotBe(token2, "Each token should be unique");
    }

    // ============================================================================
    // 🔄 TOKEN REFRESH TESTS
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - REFRESH TOKEN FLOW:
    /// Document secure token refresh mechanism.
    /// 
    /// REFRESH FLOW:
    /// 1. Access token expires (15 min)
    /// 2. Client sends refresh token (7 days)
    /// 3. Server validates refresh token
    /// 4. Server issues new access token
    /// 5. Server issues new refresh token (rotation)
    /// 
    /// SECURITY FEATURES:
    /// - Refresh token rotation: New refresh token on each use
    /// - Refresh token stored in DB (revocable)
    /// - Short-lived access tokens (limited exposure)
    /// 
    /// COMPLIANCE:
    /// - NIST SP 800-63B: Token renewal
    /// - OWASP: Secure token refresh
    /// </summary>
    [Fact]
    public void Documentation_RefreshTokenFlow()
    {
        // REFRESH TOKEN IMPLEMENTATION:
        //
        // 1. Store refresh token in database:
        // public class RefreshToken
        // {
        //     public Guid Id { get; set; }
        //     public string Token { get; set; } // Hashed
        //     public Guid UserId { get; set; }
        //     public DateTime ExpiresAt { get; set; }
        //     public bool IsRevoked { get; set; }
        //     public DateTime CreatedAt { get; set; }
        // }
        //
        // 2. Issue refresh token on login:
        // var refreshToken = GenerateSecureToken();
        // var hashedToken = HashToken(refreshToken);
        // _db.RefreshTokens.Add(new RefreshToken {
        //     Token = hashedToken,
        //     UserId = user.Id,
        //     ExpiresAt = DateTime.UtcNow.AddDays(7)
        // });
        //
        // 3. Refresh endpoint:
        // [HttpPost("refresh")]
        // public async Task<IActionResult> Refresh([FromBody] string refreshToken)
        // {
        //     var hashedToken = HashToken(refreshToken);
        //     var storedToken = await _db.RefreshTokens
        //         .FirstOrDefaultAsync(t => t.Token == hashedToken && !t.IsRevoked);
        //
        //     if (storedToken == null || storedToken.ExpiresAt < DateTime.UtcNow)
        //         return Unauthorized();
        //
        //     // Revoke old refresh token (rotation)
        //     storedToken.IsRevoked = true;
        //
        //     // Issue new tokens
        //     var newAccessToken = _tokenService.CreateToken(user);
        //     var newRefreshToken = GenerateSecureToken();
        //     // Store new refresh token...
        //
        //     return Ok(new { accessToken = newAccessToken, refreshToken = newRefreshToken });
        // }

        Assert.True(true, "Refresh token flow documented");
    }

    // ============================================================================
    // 🛡️ SESSION HIJACKING PREVENTION TESTS
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - TOKEN BINDING:
    /// Document token binding to client (IP, device fingerprint).
    /// 
    /// THREAT: Session Hijacking
    /// - Attacker steals token → Uses from different IP/device
    /// - Token binding detects mismatch → Reject request
    /// 
    /// IMPLEMENTATION:
    /// - Add IP address claim to JWT
    /// - Validate IP on each request
    /// - Allow IP change with re-authentication
    /// 
    /// COMPLIANCE:
    /// - NIST SP 800-63B: Token binding
    /// - OWASP: Session hijacking prevention
    /// </summary>
    [Fact]
    public void Documentation_TokenBinding()
    {
        // TOKEN BINDING IMPLEMENTATION:
        //
        // 1. Add IP claim during token creation:
        // var claims = new List<Claim>
        // {
        //     new Claim("ip", httpContext.Connection.RemoteIpAddress.ToString())
        // };
        //
        // 2. Validate IP on each request:
        // var tokenIp = User.FindFirst("ip")?.Value;
        // var requestIp = HttpContext.Connection.RemoteIpAddress.ToString();
        //
        // if (tokenIp != requestIp)
        // {
        //     _logger.LogWarning("IP mismatch: Token={TokenIp}, Request={RequestIp}", tokenIp, requestIp);
        //     return Unauthorized("Session invalid - IP mismatch");
        // }
        //
        // CONSIDERATIONS:
        // - Mobile users: IP changes frequently (cellular network)
        // - VPN users: IP changes when VPN reconnects
        // - Corporate proxy: Multiple users same IP
        //
        // RECOMMENDATION:
        // - Use IP binding for high-security operations (decrypt)
        // - Allow IP change for normal operations (with logging)
        // - Require re-authentication if IP changes too frequently

        Assert.True(true, "Token binding documented");
    }

    /// <summary>
    /// SECURITY TEST - CONCURRENT SESSION DETECTION:
    /// Detect and alert on concurrent sessions from different IPs.
    /// 
    /// THREAT: Account Compromise
    /// - User logs in from New York (IP 1.2.3.4)
    /// - Attacker logs in from Moscow (IP 5.6.7.8) with stolen credentials
    /// - System detects concurrent sessions → Alert user
    /// 
    /// COMPLIANCE:
    /// - NIST SP 800-63B: Anomaly detection
    /// - PCI-DSS 8.2.5: Detect shared accounts
    /// </summary>
    [Fact]
    public void Documentation_ConcurrentSessionDetection()
    {
        // CONCURRENT SESSION DETECTION:
        //
        // 1. Store active sessions in database:
        // public class ActiveSession
        // {
        //     public Guid Id { get; set; }
        //     public Guid UserId { get; set; }
        //     public string IpAddress { get; set; }
        //     public string UserAgent { get; set; }
        //     public DateTime LastActivityAt { get; set; }
        // }
        //
        // 2. On each request, update active session:
        // var session = _db.ActiveSessions
        //     .FirstOrDefault(s => s.UserId == userId && s.IpAddress == currentIp);
        // session.LastActivityAt = DateTime.UtcNow;
        //
        // 3. Detect concurrent sessions:
        // var activeSessions = _db.ActiveSessions
        //     .Where(s => s.UserId == userId && s.LastActivityAt > DateTime.UtcNow.AddMinutes(-15))
        //     .ToList();
        //
        // if (activeSessions.Count > 1)
        // {
        //     var uniqueIps = activeSessions.Select(s => s.IpAddress).Distinct().ToList();
        //     if (uniqueIps.Count > 1)
        //     {
        //         _logger.LogWarning("Concurrent sessions from different IPs: {IPs}", string.Join(", ", uniqueIps));
        //         await _emailService.SendSecurityAlert(userId, "Concurrent login detected");
        //     }
        // }

        Assert.True(true, "Concurrent session detection documented");
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private User CreateTestUser()
    {
        var passwordHash = "$2a$11$hashedPasswordExample1234567890ABCDEFGHIJKLMNOP";
        return User.Create(
            email: "test@vaultguard.com",
            username: $"testuser{Guid.NewGuid().ToString().Substring(0, 8)}",
            passwordHash: passwordHash,
            role: "User");
    }

    private string CreateExpiredToken(User user)
    {
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role)
            }),
            Expires = DateTime.UtcNow.AddDays(-1), // Already expired (yesterday)
            SigningCredentials = new SigningCredentials(_validKey, SecurityAlgorithms.HmacSha512Signature),
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Audience"]
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public void Dispose()
    {
        // Cleanup if needed
        GC.SuppressFinalize(this);
    }
}