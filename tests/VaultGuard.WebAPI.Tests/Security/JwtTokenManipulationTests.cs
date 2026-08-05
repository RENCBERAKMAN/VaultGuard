using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using VaultGuard.Domain.Entities;
using VaultGuard.Infrastructure.Security;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Security;

/// <summary>
/// TEST SÜİTİ: JWT Token Manipulation - Security Stress Tests
/// 
/// SECURITY FOCUS:
/// - **Algorithm Confusion Attack**: "none" algorithm bypass attempt
/// - **Claim Manipulation**: Tampering with JWT payload
/// - **Signature Verification**: Invalid signatures rejected
/// - **Token Forgery Prevention**: Cryptographic integrity
/// 
/// THREAT MODEL:
/// - CVE-2015-9235: JWT Algorithm Confusion (none attack)
/// - CVE-2018-0114: JWT Signature Bypass
/// - OWASP JWT Cheat Sheet violations
/// - RFC 7519 non-compliance
/// 
/// ATTACK SCENARIOS:
/// 1. **Algorithm Confusion ("none")**:
///    - Attacker changes JWT header: { "alg": "HS512" } → { "alg": "none" }
///    - Removes signature from token
///    - System accepts unsigned token → Authentication bypass
///    - Expected: 401 Unauthorized (token validation fails)
/// 
/// 2. **Claim Manipulation (Role Escalation)**:
///    - Attacker decodes valid JWT payload
///    - Changes: { "role": "User" } → { "role": "Admin" }
///    - Re-signs with different/no key
///    - System accepts forged token → Privilege escalation
///    - Expected: 401 Unauthorized (signature mismatch)
/// 
/// 3. **Signature Tampering**:
///    - Valid token's signature manipulated
///    - System must detect signature mismatch
///    - Expected: 401 Unauthorized
/// 
/// COMPLIANCE:
/// - OWASP API Security Top 10:
///   * API2:2023 - Broken Authentication
///   * API8:2023 - Security Misconfiguration
/// 
/// - NIST SP 800-63B:
///   * 5.1.5: Assertion Protection
///   * 5.2.3: Token Binding
/// 
/// - RFC 7519 (JWT):
///   * Section 8: Implementation Requirements
///   * Section 10.1: Algorithm Security
/// 
/// - CWE-347: Improper Verification of Cryptographic Signature
/// - CWE-345: Insufficient Verification of Data Authenticity
/// </summary>
public class JwtTokenManipulationTests : IDisposable
{
    private readonly IConfiguration _configuration;
    private readonly TokenService _tokenService;
    private readonly string _jwtSecret;
    private readonly SymmetricSecurityKey _validKey;

    public JwtTokenManipulationTests()
    {
        // Setup: Mock configuration with strong JWT secret
        _jwtSecret = "ThisIsAVerySecureJwtSecretKeyThatIsAtLeast64CharactersLongForHS512Algorithm!!";

        var configDict = new Dictionary<string, string>
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
    // 🚨 ALGORITHM CONFUSION ATTACK ("none" Algorithm) - CRITICAL!
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - ALGORITHM CONFUSION (CRITICAL!):
    /// JWT with "none" algorithm MUST be rejected.
    /// 
    /// ATTACK SCENARIO (CVE-2015-9235):
    /// 1. Attacker intercepts valid JWT token
    /// 2. Decodes header: { "alg": "HS512", "typ": "JWT" }
    /// 3. Changes to: { "alg": "none", "typ": "JWT" }
    /// 4. Removes signature (or uses empty signature)
    /// 5. Sends modified token: header.payload.
    /// 6. Vulnerable system accepts unsigned token → BREACH!
    /// 7. Secure system rejects: 401 Unauthorized
    /// 
    /// MITIGATION:
    /// - NEVER allow "none" algorithm
    /// - Always validate signature
    /// - Explicitly specify allowed algorithms (HS512 only)
    /// 
    /// OWASP JWT Cheat Sheet:
    /// "Ensure that the application EXPLICITLY specifies the allowed algorithms"
    /// 
    /// CWE-347: Improper Verification of Cryptographic Signature
    /// </summary>
    [Fact]
    public void JwtWithNoneAlgorithm_MustBeRejected()
    {
        // STEP 1: Create valid token (for reference)
        var user = CreateTestUser();
        var validToken = _tokenService.CreateToken(user);

        // STEP 2: Parse valid token to get claims
        var handler = new JwtSecurityTokenHandler();
        var validJwt = handler.ReadJwtToken(validToken);

        // STEP 3: Forge token with "none" algorithm
        var forgedHeader = new JwtHeader();
        forgedHeader["alg"] = "none"; // ATTACK: Algorithm confusion
        forgedHeader["typ"] = "JWT";

        var forgedPayload = new JwtPayload(
            issuer: validJwt.Issuer,
            audience: validJwt.Audiences.FirstOrDefault(),
            claims: validJwt.Claims,
            notBefore: validJwt.ValidFrom,
            expires: validJwt.ValidTo);

        var forgedToken = new JwtSecurityToken(forgedHeader, forgedPayload);
        var forgedTokenString = handler.WriteToken(forgedToken);

        // STEP 4: Attempt to validate forged token
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _configuration["Jwt:Issuer"],
            ValidAudience = _configuration["Jwt:Audience"],
            IssuerSigningKey = _validKey,
            // CRITICAL: Only allow HS512 (no "none")
            ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha512 }
        };

        // Act & Assert: Token validation MUST fail
        Action validateAction = () =>
        {
            handler.ValidateToken(
                forgedTokenString,
                validationParameters,
                out SecurityToken validatedToken);
        };

        // Assert: SecurityTokenException thrown (signature invalid or algorithm not allowed)
        validateAction.Should().Throw<SecurityTokenException>(
            "JWT with 'none' algorithm MUST be rejected - CVE-2015-9235 mitigation");
    }

    /// <summary>
    /// SECURITY TEST - ALGORITHM CONFUSION (VARIANT):
    /// Unsigned token (no signature part) MUST be rejected.
    /// 
    /// ATTACK VARIANT:
    /// - Token format: header.payload.signature
    /// - Attacker sends: header.payload. (no signature)
    /// - Expected: Validation fails
    /// </summary>
    [Fact]
    public void JwtWithoutSignature_MustBeRejected()
    {
        // Arrange: Create token without signature
        var user = CreateTestUser();
        var validToken = _tokenService.CreateToken(user);

        // Remove signature (everything after second dot)
        var parts = validToken.Split('.');
        var tokenWithoutSignature = $"{parts[0]}.{parts[1]}."; // header.payload.

        // Act: Attempt to validate
        var handler = new JwtSecurityTokenHandler();
        var validationParameters = CreateValidationParameters();

        Action validateAction = () =>
        {
            handler.ValidateToken(
                tokenWithoutSignature,
                validationParameters,
                out SecurityToken validatedToken);
        };

        // Assert: Validation fails
        validateAction.Should().Throw<SecurityTokenException>(
            "Token without signature MUST be rejected");
    }

    // ============================================================================
    // 🔓 CLAIM MANIPULATION ATTACK - CRITICAL!
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - CLAIM MANIPULATION (CRITICAL!):
    /// Modified JWT claims MUST be detected (signature mismatch).
    /// 
    /// ATTACK SCENARIO (Privilege Escalation):
    /// 1. User gets valid JWT: { "role": "User", "email": "user@test.com" }
    /// 2. Attacker decodes JWT (Base64 decode)
    /// 3. Modifies payload: { "role": "Admin", "email": "user@test.com" }
    /// 4. Re-encodes payload (Base64)
    /// 5. Keeps original signature (or tries to re-sign with guessed key)
    /// 6. Sends modified token
    /// 7. Secure system: Signature validation fails → 401 Unauthorized
    /// 8. Vulnerable system: Accepts modified claims → Privilege escalation!
    /// 
    /// MITIGATION:
    /// - HMAC-SHA512 signature verification
    /// - Any payload change invalidates signature
    /// - Strong secret key (64+ characters)
    /// 
    /// OWASP: API2:2023 - Broken Authentication
    /// CWE-345: Insufficient Verification of Data Authenticity
    /// </summary>
    [Fact]
    public void JwtWithModifiedRoleClaim_MustBeRejected()
    {
        // STEP 1: Create valid token for regular User
        var user = CreateTestUser(role: "User");
        var validToken = _tokenService.CreateToken(user);

        // STEP 2: Decode token manually
        var parts = validToken.Split('.');
        var header = parts[0];
        var payload = parts[1];
        var signature = parts[2];

        // STEP 3: Decode payload (Base64URL decode)
        var payloadJson = Base64UrlDecode(payload);
        var payloadDict = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);

        // STEP 4: ATTACK - Modify role claim (User → Admin)
        payloadDict["role"] = "Admin"; // Privilege escalation attempt!

        // STEP 5: Re-encode modified payload
        var modifiedPayloadJson = JsonSerializer.Serialize(payloadDict);
        var modifiedPayload = Base64UrlEncode(modifiedPayloadJson);

        // STEP 6: Reconstruct token with modified payload (keep original signature)
        var modifiedToken = $"{header}.{modifiedPayload}.{signature}";

        // STEP 7: Attempt to validate modified token
        var handler = new JwtSecurityTokenHandler();
        var validationParameters = CreateValidationParameters();

        Action validateAction = () =>
        {
            handler.ValidateToken(
                modifiedToken,
                validationParameters,
                out SecurityToken validatedToken);
        };

        // Assert: Validation MUST fail (signature mismatch)
        validateAction.Should().Throw<SecurityTokenInvalidSignatureException>(
            "Modified JWT claims MUST be detected - signature verification prevents privilege escalation");
    }

    /// <summary>
    /// SECURITY TEST - CLAIM MANIPULATION (EMAIL):
    /// Modified email claim MUST be detected.
    /// 
    /// ATTACK: Attacker changes email to impersonate another user.
    /// </summary>
    [Fact]
    public void JwtWithModifiedEmailClaim_MustBeRejected()
    {
        // STEP 1: Create valid token
        var user = CreateTestUser(email: "victim@test.com");
        var validToken = _tokenService.CreateToken(user);

        // STEP 2: Decode and modify email
        var parts = validToken.Split('.');
        var payloadJson = Base64UrlDecode(parts[1]);
        var payloadDict = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson);

        // ATTACK: Change email (impersonation)
        payloadDict["email"] = "attacker@test.com";

        // STEP 3: Re-encode
        var modifiedPayloadJson = JsonSerializer.Serialize(payloadDict);
        var modifiedPayload = Base64UrlEncode(modifiedPayloadJson);
        var modifiedToken = $"{parts[0]}.{modifiedPayload}.{parts[2]}";

        // STEP 4: Validate
        var handler = new JwtSecurityTokenHandler();
        var validationParameters = CreateValidationParameters();

        Action validateAction = () =>
        {
            handler.ValidateToken(modifiedToken, validationParameters, out _);
        };

        // Assert: Rejected
        validateAction.Should().Throw<SecurityTokenInvalidSignatureException>(
            "Modified email claim must be detected");
    }

    /// <summary>
    /// SECURITY TEST - CLAIM MANIPULATION (USER ID):
    /// Modified NameId claim (UserId) MUST be detected.
    /// 
    /// ATTACK: Attacker changes UserId to access other user's data.
    /// CRITICAL: This enables IDOR (Insecure Direct Object Reference) attacks.
    /// </summary>
    [Fact]
    public void JwtWithModifiedUserIdClaim_MustBeRejected()
    {
        // STEP 1: Create valid token
        var user = CreateTestUser();
        var validToken = _tokenService.CreateToken(user);

        // STEP 2: Decode and modify NameId (UserId)
        var parts = validToken.Split('.');
        var payloadJson = Base64UrlDecode(parts[1]);
        var payloadDict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(payloadJson);

        // ATTACK: Change UserId (IDOR attack)
        var modifiedDict = new Dictionary<string, object>();
        foreach (var kvp in payloadDict)
        {
            if (kvp.Key == JwtRegisteredClaimNames.NameId)
            {
                modifiedDict[kvp.Key] = Guid.NewGuid().ToString(); // Different user!
            }
            else
            {
                modifiedDict[kvp.Key] = kvp.Value;
            }
        }

        // STEP 3: Re-encode
        var modifiedPayloadJson = JsonSerializer.Serialize(modifiedDict);
        var modifiedPayload = Base64UrlEncode(modifiedPayloadJson);
        var modifiedToken = $"{parts[0]}.{modifiedPayload}.{parts[2]}";

        // STEP 4: Validate
        var handler = new JwtSecurityTokenHandler();
        var validationParameters = CreateValidationParameters();

        Action validateAction = () =>
        {
            handler.ValidateToken(modifiedToken, validationParameters, out _);
        };

        // Assert: Rejected
        validateAction.Should().Throw<SecurityTokenInvalidSignatureException>(
            "Modified UserId claim must be detected - prevents IDOR attacks");
    }

    // ============================================================================
    // 🔐 SIGNATURE TAMPERING TESTS
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - SIGNATURE TAMPERING:
    /// Token with modified signature MUST be rejected.
    /// </summary>
    [Fact]
    public void JwtWithTamperedSignature_MustBeRejected()
    {
        // Arrange: Create valid token
        var user = CreateTestUser();
        var validToken = _tokenService.CreateToken(user);

        // ATTACK: Modify last character of signature
        var parts = validToken.Split('.');
        var tamperedSignature = parts[2].Substring(0, parts[2].Length - 1) + "X";
        var tamperedToken = $"{parts[0]}.{parts[1]}.{tamperedSignature}";

        // Act: Validate
        var handler = new JwtSecurityTokenHandler();
        var validationParameters = CreateValidationParameters();

        Action validateAction = () =>
        {
            handler.ValidateToken(tamperedToken, validationParameters, out _);
        };

        // Assert: Rejected
        validateAction.Should().Throw<SecurityTokenInvalidSignatureException>(
            "Tampered signature must be detected");
    }

    /// <summary>
    /// SECURITY TEST - WRONG SIGNING KEY:
    /// Token signed with different key MUST be rejected.
    /// </summary>
    [Fact]
    public void JwtSignedWithWrongKey_MustBeRejected()
    {
        // STEP 1: Create token with wrong key
        var wrongKey = "WrongSecretKeyThatIsAlso64CharactersLongForHS512AlgorithmSecurity!";
        var wrongConfigDict = new Dictionary<string, string>
        {
            { "Jwt:Secret", wrongKey },
            { "Jwt:Issuer", "VaultGuardTestIssuer" },
            { "Jwt:Audience", "VaultGuardTestAudience" }
        };
        var wrongConfig = new ConfigurationBuilder().AddInMemoryCollection(wrongConfigDict).Build();
        var wrongTokenService = new TokenService(wrongConfig);

        var user = CreateTestUser();
        var wrongToken = wrongTokenService.CreateToken(user);

        // STEP 2: Try to validate with correct key
        var handler = new JwtSecurityTokenHandler();
        var validationParameters = CreateValidationParameters(); // Uses correct key

        Action validateAction = () =>
        {
            handler.ValidateToken(wrongToken, validationParameters, out _);
        };

        // Assert: Rejected
        validateAction.Should().Throw<SecurityTokenInvalidSignatureException>(
            "Token signed with wrong key must be rejected");
    }

    // ============================================================================
    // ✅ POSITIVE TESTS (Valid Tokens)
    // ============================================================================

    /// <summary>
    /// POSITIVE TEST:
    /// Valid, unmodified token SHOULD pass validation.
    /// Baseline test to confirm validation logic works correctly.
    /// </summary>
    [Fact]
    public void ValidUnmodifiedJwt_ShouldPassValidation()
    {
        // Arrange: Create valid token
        var user = CreateTestUser();
        var validToken = _tokenService.CreateToken(user);

        // Act: Validate
        var handler = new JwtSecurityTokenHandler();
        var validationParameters = CreateValidationParameters();

        SecurityToken validatedToken = null;
        ClaimsPrincipal principal = null;

        Action validateAction = () =>
        {
            principal = handler.ValidateToken(validToken, validationParameters, out validatedToken);
        };

        // Assert: No exception (validation succeeds)
        validateAction.Should().NotThrow("Valid token should pass validation");

        validatedToken.Should().NotBeNull();
        principal.Should().NotBeNull();

        // Verify claims present
        principal.FindFirst(JwtRegisteredClaimNames.NameId).Should().NotBeNull();
        principal.FindFirst(JwtRegisteredClaimNames.Email).Should().NotBeNull();
        principal.FindFirst(ClaimTypes.Role).Should().NotBeNull();
    }

    /// <summary>
    /// POSITIVE TEST:
    /// Token with correct signature and claims should be accepted.
    /// </summary>
    [Fact]
    public void TokenWithCorrectSignature_ShouldBeValid()
    {
        // Arrange
        var user = CreateTestUser(role: "Admin");
        var token = _tokenService.CreateToken(user);

        // Act: Parse token
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(token);

        // Assert: Verify structure
        jwt.Header.Should().NotBeNull();
        jwt.Payload.Should().NotBeNull();
        jwt.Header.Alg.Should().Be(SecurityAlgorithms.HmacSha512, "HS512 algorithm required");

        // Assert: Verify claims
        jwt.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.NameId);
        jwt.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Email);
        jwt.Claims.Should().Contain(c => c.Type == ClaimTypes.Role && c.Value == "Admin");
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private User CreateTestUser(string email = "test@vaultguard.com", string role = "User")
    {
        var passwordHash = "$2a$11$abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP";
        var user = User.Create(email, $"testuser_{Guid.NewGuid().ToString().Substring(0, 8)}", passwordHash, role);
        return user;
    }

    private TokenValidationParameters CreateValidationParameters()
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = _configuration["Jwt:Issuer"],
            ValidAudience = _configuration["Jwt:Audience"],
            IssuerSigningKey = _validKey,
            // CRITICAL: Only allow HS512 (prevent algorithm confusion)
            ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha512 },
            ClockSkew = TimeSpan.Zero // Strict expiration validation
        };
    }

    private static string Base64UrlDecode(string input)
    {
        var base64 = input.Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        var bytes = Convert.FromBase64String(base64);
        return Encoding.UTF8.GetString(bytes);
    }

    private static string Base64UrlEncode(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var base64 = Convert.ToBase64String(bytes);
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    public void Dispose()
    {
        // Cleanup if needed
        GC.SuppressFinalize(this);
    }
}