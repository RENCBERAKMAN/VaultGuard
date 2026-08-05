using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using FluentAssertions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using VaultGuard.WebAPI.Extensions;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Extensions;

/// <summary>
/// TEST SÜÝTÝ: JwtRegistration - JWT Configuration & Security Parameters
/// 
/// GÜVENLÝK KAPSAMI:
/// - Configuration validation (Issuer, Audience, SecretKey)
/// - Security parameter enforcement (ClockSkew, RequireExpirationTime)
/// - Token validation parameter correctness
/// - Fail-fast behavior (invalid config)
/// - Authentication scheme registration
/// 
/// MÝMARÝ FOKUSu:
/// - DI container integrity
/// - Configuration binding
/// - Security best practices
/// </summary>
public class JwtRegistrationTests
{
    // ============================================================================
    // CONFIGURATION VALIDATION TESTLERÝ - BAÞARILI SENARYOLAR
    // ============================================================================

    [Fact]
    public void AddJwtAuthentication_WithValidConfig_ShouldRegisterServices()
    {
        // Arrange: Geçerli JWT konfigürasyonu
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: JwtBearer authentication servisi kayýtlý mý?
        var serviceProvider = services.BuildServiceProvider();
        var authOptions = serviceProvider.GetService<IOptions<JwtBearerOptions>>();

        authOptions.Should().NotBeNull(
            because: "JwtBearer authentication servisi DI container'a kayýtlý olmalý");
    }

    [Fact]
    public void AddJwtAuthentication_ValidConfig_ShouldSetDefaultSchemes()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: Default authentication scheme'ler doðru set edildi mi?
        var serviceProvider = services.BuildServiceProvider();
        var authOptions = serviceProvider.GetRequiredService<IOptions<Microsoft.AspNetCore.Authentication.AuthenticationOptions>>();

        authOptions.Value.DefaultAuthenticateScheme.Should().Be(JwtBearerDefaults.AuthenticationScheme);
        authOptions.Value.DefaultChallengeScheme.Should().Be(JwtBearerDefaults.AuthenticationScheme);
        authOptions.Value.DefaultScheme.Should().Be(JwtBearerDefaults.AuthenticationScheme);
    }

    // ============================================================================
    // CONFIGURATION VALIDATION TESTLERÝ - BAÞARISIZ SENARYOLAR
    // ============================================================================

    [Fact]
    public void AddJwtAuthentication_MissingSecretKey_ShouldThrowException()
    {
        // Arrange: SecretKey eksik
        var services = new ServiceCollection();
        var configuration = CreateConfigurationWithMissingKey("Jwt:SecretKey");

        // Act & Assert: InvalidOperationException fýrlatmalý
        Action act = () => services.AddJwtAuthentication(configuration);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*SecretKey*");
    }

    [Fact]
    public void AddJwtAuthentication_MissingIssuer_ShouldThrowException()
    {
        // Arrange: Issuer eksik
        var services = new ServiceCollection();
        var configuration = CreateConfigurationWithMissingKey("Jwt:Issuer");

        // Act & Assert
        Action act = () => services.AddJwtAuthentication(configuration);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Issuer*");
    }

    [Fact]
    public void AddJwtAuthentication_MissingAudience_ShouldThrowException()
    {
        // Arrange: Audience eksik
        var services = new ServiceCollection();
        var configuration = CreateConfigurationWithMissingKey("Jwt:Audience");

        // Act & Assert
        Action act = () => services.AddJwtAuthentication(configuration);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Audience*");
    }

    [Fact]
    public void AddJwtAuthentication_MissingExpiryMinutes_ShouldThrowException()
    {
        // Arrange: ExpiryMinutes eksik
        var services = new ServiceCollection();
        var configuration = CreateConfigurationWithMissingKey("Jwt:ExpiryMinutes");

        // Act & Assert
        Action act = () => services.AddJwtAuthentication(configuration);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*ExpiryMinutes*");
    }

    [Fact]
    public void AddJwtAuthentication_WeakSecretKey_ShouldThrowException()
    {
        // Arrange: SecretKey çok kýsa (< 32 karakter)
        var services = new ServiceCollection();
        var configData = new Dictionary<string, string>
        {
            { "Jwt:SecretKey", "short_key" }, // 9 karakter (GÜVENLÝK: 32+ olmalý)
            { "Jwt:Issuer", "VaultGuardAPI" },
            { "Jwt:Audience", "VaultGuardClient" },
            { "Jwt:ExpiryMinutes", "60" }
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act & Assert: Weak key rejection
        Action act = () => services.AddJwtAuthentication(configuration);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*32*");
    }

    [Fact]
    public void AddJwtAuthentication_InvalidExpiryMinutesFormat_ShouldThrowException()
    {
        // Arrange: ExpiryMinutes numeric deðil
        var services = new ServiceCollection();
        var configData = new Dictionary<string, string>
        {
            { "Jwt:SecretKey", "VaultGuard_SuperSecret_Key_Minimum32Characters!" },
            { "Jwt:Issuer", "VaultGuardAPI" },
            { "Jwt:Audience", "VaultGuardClient" },
            { "Jwt:ExpiryMinutes", "not_a_number" }
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act & Assert
        Action act = () => services.AddJwtAuthentication(configuration);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*ExpiryMinutes*");
    }

    // ============================================================================
    // SECURITY PARAMETERS TESTLERÝ
    // ============================================================================

    [Fact]
    public void AddJwtAuthentication_ShouldEnforceIssuerValidation()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: ValidateIssuer = true
        var serviceProvider = services.BuildServiceProvider();
        var jwtOptions = serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        jwtOptions.TokenValidationParameters.ValidateIssuer.Should().BeTrue(
            because: "Token'ýn kim tarafýndan üretildiði doðrulanmalý");

        jwtOptions.TokenValidationParameters.ValidIssuer.Should().Be("VaultGuardAPI");
    }

    [Fact]
    public void AddJwtAuthentication_ShouldEnforceAudienceValidation()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: ValidateAudience = true
        var serviceProvider = services.BuildServiceProvider();
        var jwtOptions = serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        jwtOptions.TokenValidationParameters.ValidateAudience.Should().BeTrue(
            because: "Token'ýn kim için üretildiði doðrulanmalý");

        jwtOptions.TokenValidationParameters.ValidAudience.Should().Be("VaultGuardClient");
    }

    [Fact]
    public void AddJwtAuthentication_ShouldEnforceSignatureValidation()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: ValidateIssuerSigningKey = true
        var serviceProvider = services.BuildServiceProvider();
        var jwtOptions = serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        jwtOptions.TokenValidationParameters.ValidateIssuerSigningKey.Should().BeTrue(
            because: "Token'ýn dijital imzasý doðrulanmalý");

        jwtOptions.TokenValidationParameters.IssuerSigningKey.Should().NotBeNull();
    }

    [Fact]
    public void AddJwtAuthentication_ShouldEnforceLifetimeValidation()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: ValidateLifetime = true
        var serviceProvider = services.BuildServiceProvider();
        var jwtOptions = serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        jwtOptions.TokenValidationParameters.ValidateLifetime.Should().BeTrue(
            because: "Token'ýn süresi kontrol edilmeli");
    }

    [Fact]
    public void AddJwtAuthentication_ShouldSetClockSkewToZero()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: ClockSkew = 0 (GÜVENLÝK: Saat farký toleransý yok)
        var serviceProvider = services.BuildServiceProvider();
        var jwtOptions = serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        jwtOptions.TokenValidationParameters.ClockSkew.Should().Be(TimeSpan.Zero,
            because: "Token expiration için saat farký toleransý olmamalý (güvenlik)");
    }

    [Fact]
    public void AddJwtAuthentication_ShouldRequireExpirationTime()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: RequireExpirationTime = true
        var serviceProvider = services.BuildServiceProvider();
        var jwtOptions = serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        jwtOptions.TokenValidationParameters.RequireExpirationTime.Should().BeTrue(
            because: "Token'ýn expiration bilgisi ZORUNLU olmalý");
    }

    [Fact]
    public void AddJwtAuthentication_ShouldRequireSignedTokens()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: RequireSignedTokens = true
        var serviceProvider = services.BuildServiceProvider();
        var jwtOptions = serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        jwtOptions.TokenValidationParameters.RequireSignedTokens.Should().BeTrue(
            because: "Ýmzasýz token'lar kabul edilmemeli");
    }

    [Fact]
    public void AddJwtAuthentication_ShouldEnableHttpsMetadata()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: RequireHttpsMetadata = true (Production için HTTPS zorunlu)
        var serviceProvider = services.BuildServiceProvider();
        var jwtOptions = serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        jwtOptions.RequireHttpsMetadata.Should().BeTrue(
            because: "Production ortamýnda HTTPS zorunlu olmalý");
    }

    [Fact]
    public void AddJwtAuthentication_ShouldSaveTokenToHttpContext()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: SaveToken = true
        var serviceProvider = services.BuildServiceProvider();
        var jwtOptions = serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        jwtOptions.SaveToken.Should().BeTrue(
            because: "Token HttpContext'te saklanmalý (middleware'ler için)");
    }

    // ============================================================================
    // ISSUER SIGNING KEY TESTLERÝ
    // ============================================================================

    [Fact]
    public void AddJwtAuthentication_ShouldSetCorrectSigningKey()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();
        var expectedSecretKey = "VaultGuard_SuperSecret_Key_Minimum32Characters!";

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: Signing key doðru set edildi mi?
        var serviceProvider = services.BuildServiceProvider();
        var jwtOptions = serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        var signingKey = jwtOptions.TokenValidationParameters.IssuerSigningKey as SymmetricSecurityKey;
        signingKey.Should().NotBeNull();

        var keyBytes = Encoding.UTF8.GetBytes(expectedSecretKey);
        signingKey.Key.Should().BeEquivalentTo(keyBytes);
    }

    // ============================================================================
    // JWT EVENTS TESTLERÝ
    // ============================================================================

    [Fact]
    public void AddJwtAuthentication_ShouldConfigureOnAuthenticationFailedEvent()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: OnAuthenticationFailed event handler kayýtlý mý?
        var serviceProvider = services.BuildServiceProvider();
        var jwtOptions = serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        jwtOptions.Events.Should().NotBeNull();
        jwtOptions.Events.OnAuthenticationFailed.Should().NotBeNull(
            because: "Token doðrulama hatalarýný handle etmek için event handler gerekli");
    }

    [Fact]
    public void AddJwtAuthentication_ShouldConfigureOnChallengeEvent()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: OnChallenge event handler kayýtlý mý?
        var serviceProvider = services.BuildServiceProvider();
        var jwtOptions = serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        jwtOptions.Events.OnChallenge.Should().NotBeNull(
            because: "401 Unauthorized response'u özelleþtirmek için event handler gerekli");
    }

    [Fact]
    public void AddJwtAuthentication_ShouldConfigureOnForbiddenEvent()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: OnForbidden event handler kayýtlý mý?
        var serviceProvider = services.BuildServiceProvider();
        var jwtOptions = serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        jwtOptions.Events.OnForbidden.Should().NotBeNull(
            because: "403 Forbidden response'u özelleþtirmek için event handler gerekli");
    }

    // ============================================================================
    // CLAIM TYPE MAPPING TESTLERÝ
    // ============================================================================

    [Fact]
    public void AddJwtAuthentication_ShouldSetNameClaimType()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: NameClaimType doðru set edildi mi?
        var serviceProvider = services.BuildServiceProvider();
        var jwtOptions = serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        jwtOptions.TokenValidationParameters.NameClaimType.Should().Be(ClaimTypes.NameIdentifier,
            because: "JWT token'daki 'sub' claim'i User.Identity.Name ile eþleþmeli");
    }

    [Fact]
    public void AddJwtAuthentication_ShouldSetRoleClaimType()
    {
        // Arrange
        var services = new ServiceCollection();
        var configuration = CreateValidConfiguration();

        // Act
        services.AddJwtAuthentication(configuration);

        // Assert: RoleClaimType doðru set edildi mi?
        var serviceProvider = services.BuildServiceProvider();
        var jwtOptions = serviceProvider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        jwtOptions.TokenValidationParameters.RoleClaimType.Should().Be(ClaimTypes.Role,
            because: "JWT token'daki 'role' claim'i User.IsInRole ile eþleþmeli");
    }

    // ============================================================================
    // EDGE CASE TESTLERÝ
    // ============================================================================

    [Fact]
    public void AddJwtAuthentication_NullConfiguration_ShouldThrowException()
    {
        // Arrange
        var services = new ServiceCollection();
        IConfiguration nullConfiguration = null;

        // Act & Assert
        Action act = () => services.AddJwtAuthentication(nullConfiguration);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void AddJwtAuthentication_EmptySecretKey_ShouldThrowException()
    {
        // Arrange
        var services = new ServiceCollection();
        var configData = new Dictionary<string, string>
        {
            { "Jwt:SecretKey", "" }, // Boþ
            { "Jwt:Issuer", "VaultGuardAPI" },
            { "Jwt:Audience", "VaultGuardClient" },
            { "Jwt:ExpiryMinutes", "60" }
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Act & Assert
        Action act = () => services.AddJwtAuthentication(configuration);

        act.Should().Throw<InvalidOperationException>();
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private static IConfiguration CreateValidConfiguration()
    {
        var configData = new Dictionary<string, string>
        {
            { "Jwt:SecretKey", "VaultGuard_SuperSecret_Key_Minimum32Characters!" },
            { "Jwt:Issuer", "VaultGuardAPI" },
            { "Jwt:Audience", "VaultGuardClient" },
            { "Jwt:ExpiryMinutes", "60" }
        };

        return new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();
    }

    private static IConfiguration CreateConfigurationWithMissingKey(string missingKey)
    {
        var configData = new Dictionary<string, string>
        {
            { "Jwt:SecretKey", "VaultGuard_SuperSecret_Key_Minimum32Characters!" },
            { "Jwt:Issuer", "VaultGuardAPI" },
            { "Jwt:Audience", "VaultGuardClient" },
            { "Jwt:ExpiryMinutes", "60" }
        };

        // Belirtilen key'i kaldýr
        configData.Remove(missingKey);

        return new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();
    }
}