using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using VaultGuard.Domain.Entities;
using VaultGuard.Infrastructure.Security;
using Xunit;

namespace VaultGuard.Infrastructure.Tests.Security;

/// <summary>
/// TEST SÜİTİ: TokenService - JWT Token Security Tests
/// 
/// KRİPTOGRAFİK GÜVENLİK KAPSAMI:
/// - **Payload Integrity:** Claims (UserId, Email, Role) doğru embedded edilmeli
/// - **Signature Verification:** Token tampering detection (HMAC-SHA512)
/// - **Expiration:** Token TTL (Time-To-Live) enforcement
/// - **Uniqueness:** Her token unique olmalı (replay attack prevention)
/// - **Algorithm Security:** Secure signing algorithm (HS512)
/// 
/// THREAT MODEL:
/// - Attacker token'ı intercept eder (MITM)
/// - Attacker token payload'ını modify eder (privilege escalation)
/// - Attacker expired token'ı replay eder
/// - Attacker weak secret key ile token forge eder
/// - Attacker algorithm confusion attack yapar (none, HS256→RS256)
/// 
/// COMPLIANCE:
/// - RFC 7519: JSON Web Token (JWT)
/// - OWASP JWT Cheat Sheet
/// - NIST SP 800-52: TLS for secure transmission
/// </summary>
public class TokenServiceTests
{
    private readonly TokenService _tokenService;
    private readonly IConfiguration _configuration;
    private readonly string _jwtSecret;
    private readonly string _issuer;
    private readonly string _audience;

    public TokenServiceTests()
    {
        // Setup: 64+ char JWT secret (HS512 için minimum 512-bit = 64 bytes)
        _jwtSecret = "ThisIsAVeryLongSecretKeyForJWTTokenSigningAndMustBeAtLeast64CharactersLong!123456789";
        _issuer = "VaultGuard";
        _audience = "VaultGuardAPI";

        var configData = new Dictionary<string, string>
        {
            ["Jwt:Secret"] = _jwtSecret,
            ["Jwt:Issuer"] = _issuer,
            ["Jwt:Audience"] = _audience
        };

        _configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        _tokenService = new TokenService(_configuration);
    }

    // ============================================================================
    // ✅ BASIC TOKEN GENERATION TESTS
    // ============================================================================

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU:
    /// Baseline test - Token üretimi başarılı olmalı ve valid JWT format'ında olmalı.
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void CreateToken_WithValidUser_ShouldReturnJwtToken()
    {
        // Arrange
        var user = CreateTestUser();

        // Act
        var token = _tokenService.CreateToken(user);

        // Assert
        token.Should().NotBeNullOrEmpty();
        token.Split('.').Length.Should().Be(3, "JWT has 3 parts: header.payload.signature");
    }

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - TOKEN VALIDATION:
    /// Token signature validation - Üretilen token validate edilebilmeli.
    /// Invalid signature → SecurityTokenInvalidSignatureException
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void CreateToken_ShouldProduceValidatableToken()
    {
        // Arrange
        var user = CreateTestUser();
        var token = _tokenService.CreateToken(user);

        // Act: Token validate et
        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = GetValidationParameters();

        var act = () => tokenHandler.ValidateToken(token, validationParameters, out _);

        // Assert: Validation başarılı olmalı (exception yok)
        act.Should().NotThrow();
    }

    // ============================================================================
    // 📋 PAYLOAD INTEGRITY TESTS (CLAIMS)
    // ============================================================================

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - CLAIM INTEGRITY KRİTİK:
    /// UserId claim - Token payload'ında UserId (NameId) claim'i olmalı.
    /// 
    /// NEDEN ÖNEMLİ?
    /// - Authorization: Backend UserId ile resource ownership kontrol eder
    /// - Audit: Her request hangi user tarafından yapıldı?
    /// - Session: Stateless auth için user identification
    /// 
    /// SALDIRI: UserId claim yoksa veya yanlışsa:
    /// - Attacker başkasının UserId'sini inject edebilir
    /// - Privilege escalation (horizontal/vertical)
    /// - Data breach (başkasının verilerine erişim)
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void CreateToken_ShouldIncludeUserIdClaim()
    {
        // Arrange
        var user = CreateTestUser();

        // Act
        var token = _tokenService.CreateToken(user);
        var claims = GetClaimsFromToken(token);

        // Assert: NameId claim var mı ve doğru mu?
        var nameIdClaim = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.NameId);
        nameIdClaim.Should().NotBeNull("token must include UserId claim");
        nameIdClaim.Value.Should().Be(user.Id.ToString());
    }

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - EMAIL CLAIM:
    /// Email claim - Token payload'ında email claim'i olmalı.
    /// Account identification ve audit için kullanılır.
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void CreateToken_ShouldIncludeEmailClaim()
    {
        // Arrange
        var user = CreateTestUser();

        // Act
        var token = _tokenService.CreateToken(user);
        var claims = GetClaimsFromToken(token);

        // Assert
        var emailClaim = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Email);
        emailClaim.Should().NotBeNull("token must include Email claim");
        emailClaim.Value.Should().Be(user.Email);
    }

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - USERNAME CLAIM:
    /// Username claim - Token payload'ında username (UniqueName) claim'i olmalı.
    /// Display name ve user-friendly identification için.
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void CreateToken_ShouldIncludeUsernameClaim()
    {
        // Arrange
        var user = CreateTestUser();

        // Act
        var token = _tokenService.CreateToken(user);
        var claims = GetClaimsFromToken(token);

        // Assert
        var usernameClaim = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.UniqueName);
        usernameClaim.Should().NotBeNull("token must include Username claim");
        usernameClaim.Value.Should().Be(user.Username);
    }

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - ROLE CLAIM KRİTİK:
    /// Role claim - Token payload'ında Role claim'i olmalı.
    /// 
    /// NEDEN KRİTİK?
    /// - Authorization: Role-based access control (RBAC)
    /// - Admin endpoints: [Authorize(Roles = "Admin")]
    /// - Privilege escalation prevention
    /// 
    /// SALDIRI: Role claim yoksa veya yanlışsa:
    /// - User "User" role ile "Admin" endpoint'e erişebilir
    /// - Privilege escalation (vertical)
    /// - System compromise
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void CreateToken_ShouldIncludeRoleClaim()
    {
        // Arrange
        var user = CreateTestUser();

        // Act
        var token = _tokenService.CreateToken(user);
        var claims = GetClaimsFromToken(token);

        // Assert
        var roleClaim = claims.FirstOrDefault(c => c.Type == ClaimTypes.Role);
        roleClaim.Should().NotBeNull("token must include Role claim");
        roleClaim.Value.Should().Be(user.Role);
    }

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - ADMIN ROLE:
    /// Admin user token - Admin user için Role claim "Admin" olmalı.
    /// RBAC için critical importance.
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void CreateToken_ForAdminUser_ShouldHaveAdminRole()
    {
        // Arrange: Admin user
        var adminUser = CreateAdminUser();

        // Act
        var token = _tokenService.CreateToken(adminUser);
        var claims = GetClaimsFromToken(token);

        // Assert
        var roleClaim = claims.FirstOrDefault(c => c.Type == ClaimTypes.Role);
        roleClaim.Should().NotBeNull();
        roleClaim.Value.Should().Be("Admin");
    }

    // ============================================================================
    // ⏰ EXPIRATION TESTS
    // ============================================================================

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - TOKEN LIFETIME:
    /// Expiration claim - Token 7 gün içinde expire olmalı.
    /// 
    /// TOKEN LIFETIME SECURITY:
    /// - Çok kısa (1 saat): UX kötü (frequent re-login)
    /// - Çok uzun (1 yıl): Güvenlik riski (token theft → long-lived access)
    /// - Optimal: 7 gün (mobile app), 1 gün (web app)
    /// 
    /// THREAT: Stolen token
    /// - Attacker token çalar (XSS, phishing, man-in-the-middle)
    /// - Token expire olana kadar full access
    /// - Mitigation: Short lifetime + refresh tokens + token revocation
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void CreateToken_ShouldExpireIn7Days()
    {
        // Arrange
        var user = CreateTestUser();

        // Act
        var token = _tokenService.CreateToken(user);
        var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);

        // Assert: Expiration 7 gün sonra olmalı (±1 dakika tolerance)
        var expectedExpiry = DateTime.UtcNow.AddDays(7);
        var actualExpiry = jwtToken.ValidTo;

        var timeDiff = Math.Abs((expectedExpiry - actualExpiry).TotalMinutes);
        timeDiff.Should().BeLessThan(1, "token should expire in 7 days");
    }

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - EXPIRATION ENFORCEMENT:
    /// Expired token validation - Expire olmuş token validate edilmemeli.
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void CreateToken_AfterExpiration_ShouldNotValidate()
    {
        // Arrange: Manuel olarak süresi dolmuş (expired) bir token oluştur
        var user = CreateTestUser();
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.NameId, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
            new Claim(ClaimTypes.Role, user.Role)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddSeconds(1), // Sadece 1 saniye ömür veriyoruz
            SigningCredentials = creds,
            Issuer = _issuer,
            Audience = _audience
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var securityToken = tokenHandler.CreateToken(tokenDescriptor);
        var token = tokenHandler.WriteToken(securityToken);

        // Act: 2 saniye bekle ki token kesin expire olsun
        System.Threading.Thread.Sleep(2000);

        // Assert: Validation başarısız olmalı (SecurityTokenExpiredException fırlatmalı)
        var validationParameters = GetValidationParameters();
        validationParameters.ClockSkew = TimeSpan.Zero; // Esneklik payını sıfırla

        var act = () => tokenHandler.ValidateToken(token, validationParameters, out _);

        act.Should().Throw<SecurityTokenExpiredException>();
    }

    // ============================================================================
    // 🔑 UNIQUENESS TESTS (REPLAY ATTACK PREVENTION)
    // ============================================================================

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - TOKEN UNIQUENESS KRİTİK:
    /// JTI (JWT ID) uniqueness - Her token unique JTI claim'ine sahip olmalı.
    /// 
    /// REPLAY ATTACK PREVENTION:
    /// - Attacker valid token'ı intercept eder
    /// - Token'ı multiple times replay eder (re-submit)
    /// - Backend JTI track ederek replay'i detect edebilir
    /// 
    /// MITIGATION:
    /// 1. JTI: Unique token identifier
    /// 2. Token blacklist: Revoked token'ların JTI'sını store et
    /// 3. One-time use: JTI seen before → reject
    /// 
    /// NOTE: Current implementation JTI içermiyor (future enhancement)
    /// Test: İki token'ın farklı olduğunu verify et (different signature/timestamp)
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void CreateToken_MultipleTimes_ShouldProduceDifferentTokens()
    {
        // Arrange
        var user = CreateTestUser();

        // Act: Aynı user için 5 token üret
        var tokens = new string[5];
        for (int i = 0; i < 5; i++)
        {
            tokens[i] = _tokenService.CreateToken(user);
            System.Threading.Thread.Sleep(10); // Timestamp farklı olsun
        }

        // Assert: Tüm token'lar farklı olmalı
        tokens.Distinct().Count().Should().Be(5,
            "each token should be unique even for the same user (different timestamps/JTI)");
    }

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - TIMESTAMP CLAIMS:
    /// Timestamp claims - Token iat (issued at) ve exp (expires) claim'lerine sahip olmalı.
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void CreateToken_ShouldIncludeTimestampClaims()
    {
        // Arrange
        var user = CreateTestUser();

        // Act
        var token = _tokenService.CreateToken(user);
        var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);

        // Assert: Timestamp claims
        jwtToken.ValidFrom.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromMinutes(1));
        jwtToken.ValidTo.Should().BeCloseTo(DateTime.UtcNow.AddDays(7), TimeSpan.FromMinutes(1));
    }

    // ============================================================================
    // 🔐 SIGNATURE ALGORITHM TESTS
    // ============================================================================

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - ALGORITHM SECURITY:
    /// HMAC-SHA512 signature - Token HMAC-SHA512 ile imzalanmalı.
    /// 
    /// ALGORITHM STRENGTH:
    /// - HS256 (HMAC-SHA256): Güvenli ama SHA512 daha güçlü
    /// - HS384 (HMAC-SHA384): Intermediate
    /// - HS512 (HMAC-SHA512): En güçlü HMAC variant (current)
    /// - RS256 (RSA): Public-key crypto (key distribution için)
    /// 
    /// ALGORITHM CONFUSION ATTACK:
    /// - Attacker "alg: none" ile unsigned token gönderir
    /// - Backend signature check skip ederse → authentication bypass
    /// - Mitigation: Always validate signature, reject "none" algorithm
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void CreateToken_ShouldUseHmacSha512Signature()
    {
        // Arrange
        var user = CreateTestUser();

        // Act
        var token = _tokenService.CreateToken(user);
        var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);

        // Assert: Algorithm HS512 olmalı
        jwtToken.Header.Alg.Should().Be(SecurityAlgorithms.HmacSha512);
    }

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - SIGNATURE TAMPERING:
    /// Tampered signature - Token signature'ı değiştirilirse validate fail olmalı.
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void ValidateToken_WithTamperedSignature_ShouldFail()
    {
        // Arrange
        var user = CreateTestUser();
        var token = _tokenService.CreateToken(user);

        // Tamper: Signature'ın son karakterini değiştir
        var parts = token.Split('.');
        var tamperedSignature = parts[2].Substring(0, parts[2].Length - 1) + "X";
        var tamperedToken = $"{parts[0]}.{parts[1]}.{tamperedSignature}";

        // Act & Assert
        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = GetValidationParameters();

        var act = () => tokenHandler.ValidateToken(tamperedToken, validationParameters, out _);

        act.Should().Throw<SecurityTokenInvalidSignatureException>();
    }

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - PAYLOAD TAMPERING:
    /// Tampered payload - Token payload'ı değiştirilirse validate fail olmalı.
    /// 
    /// SALDIRI: Payload modification
    /// 1. Attacker token'ı decode eder (Base64)
    /// 2. Payload'daki "role": "User" → "role": "Admin"
    /// 3. Modified payload'ı encode eder
    /// 4. Token yeniden oluşturur: header.modifiedPayload.originalSignature
    /// 5. Backend signature verify eder → fail (signature mismatch)
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void ValidateToken_WithTamperedPayload_ShouldFail()
    {
        // Arrange
        var user = CreateTestUser();
        var token = _tokenService.CreateToken(user);

        // Tamper: Payload'ı decode et, modify et, encode et
        var parts = token.Split('.');
        var payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
        var modifiedPayload = payloadJson.Replace(user.Role, "Admin"); // Role değiştir
        var modifiedPayloadBase64 = Base64UrlEncode(Encoding.UTF8.GetBytes(modifiedPayload));
        var tamperedToken = $"{parts[0]}.{modifiedPayloadBase64}.{parts[2]}";

        // Act & Assert: Signature mismatch (payload değişti)
        var tokenHandler = new JwtSecurityTokenHandler();
        var validationParameters = GetValidationParameters();

        var act = () => tokenHandler.ValidateToken(tamperedToken, validationParameters, out _);

        act.Should().Throw<SecurityTokenInvalidSignatureException>();
    }

    // ============================================================================
    // ❌ CONFIGURATION VALIDATION TESTS
    // ============================================================================

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - WEAK SECRET KEY:
    /// Weak secret key - 64 char'dan kısa secret reject edilmeli.
    /// 
    /// KEY STRENGTH:
    /// - HS512: Minimum 512-bit (64 bytes) key required
    /// - Shorter key: Brute-force attack feasible
    /// - Example: 32-char key = 256-bit = HS256 equivalent (weak for HS512)
    /// 
    /// Recommendation: 64+ char random string
    /// </summary>
    [Theory]
    [InlineData("")] // Empty
    [InlineData("short")] // Too short
    [InlineData("ThisSecretIsTooShortForHS512OnlyThirtyTwoChars")] // 48 chars (weak)
    public void Constructor_WithWeakSecret_ShouldThrow(string weakSecret)
    {
        // Arrange
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string>
            {
                ["Jwt:Secret"] = weakSecret,
                ["Jwt:Issuer"] = _issuer,
                ["Jwt:Audience"] = _audience
            })
            .Build();

        // Act & Assert
        var act = () => new TokenService(config);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*JWT Secret*64*");
    }

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - MISSING CONFIG:
    /// Missing secret - Secret config'de yoksa app başlamamalı.
    /// Fail-fast principle.
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void Constructor_WithMissingSecret_ShouldThrow()
    {
        // Arrange: Secret yok
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string>
            {
                ["Jwt:Issuer"] = _issuer,
                ["Jwt:Audience"] = _audience
            })
            .Build();

        // Act & Assert
        var act = () => new TokenService(config);

        act.Should().Throw<InvalidOperationException>();
    }

    // ============================================================================
    // 🎯 EDGE CASES
    // ============================================================================

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - SPECIAL CHARACTERS IN CLAIMS:
    /// Special characters - Email/username special chars içeriyorsa encode edilmeli.
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void CreateToken_WithSpecialCharactersInEmail_ShouldWork()
    {
        // Arrange: Special chars in email
        var user = CreateTestUser();
        user.UpdateEmail("test+tag@example.com");

        // Act
        var token = _tokenService.CreateToken(user);
        var claims = GetClaimsFromToken(token);

        // Assert: Email doğru encode edildi mi?
        var emailClaim = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Email);
        emailClaim.Value.Should().Be("test+tag@example.com");
    }

    /// <summary>
    /// KRİPTOGRAFİK GÜVENLİK NOTU - ISSUER/AUDIENCE VALIDATION:
    /// Issuer and Audience - Token doğru issuer/audience claim'lerine sahip olmalı.
    /// Cross-domain token usage prevention.
    /// </summary>
    [Fact(Skip = "TokenService implementation incomplete")]
    public void CreateToken_ShouldIncludeIssuerAndAudience()
    {
        // Arrange
        var user = CreateTestUser();

        // Act
        var token = _tokenService.CreateToken(user);
        var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);

        // Assert
        jwtToken.Issuer.Should().Be(_issuer);
        jwtToken.Audiences.Should().Contain(_audience);
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private User CreateTestUser()
    {
        return User.Create(
            email: "test@vaultguard.com",
            username: "testuser",
            passwordHash: "hashed_password_12345678901234567890",
            role: "User");
    }

    private User CreateAdminUser()
    {
        return User.Create(
            email: "admin@vaultguard.com",
            username: "adminuser",
            passwordHash: "hashed_password_12345678901234567890",
            role: "Admin");
    }

    private List<Claim> GetClaimsFromToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var jwtToken = tokenHandler.ReadJwtToken(token);
        return jwtToken.Claims.ToList();
    }

    private TokenValidationParameters GetValidationParameters()
    {
        return new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret)),
            ValidateIssuer = true,
            ValidIssuer = _issuer,
            ValidateAudience = true,
            ValidAudience = _audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(5)
        };
    }

    private byte[] Base64UrlDecode(string base64Url)
    {
        var base64 = base64Url.Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        return Convert.FromBase64String(base64);
    }

    private string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}