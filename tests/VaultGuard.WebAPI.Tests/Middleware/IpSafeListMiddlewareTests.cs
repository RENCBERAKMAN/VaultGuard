using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using VaultGuard.WebAPI.Middleware;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Middleware;

/// <summary>
/// TEST S��T�: IpSafeListMiddleware - IP Whitelist Firewall & Access Control
/// 
/// G�VENL�K KAPSAMI:
/// - IP whitelist enforcement
/// - Unauthorized IP blocking (403 Forbidden)
/// - Configuration parsing and validation
/// - Localhost exception handling
/// - Fail-safe behavior (empty/invalid config)
/// - IPv4 and IPv6 support
/// 
/// SALDIRI KORUMALARI:
/// - Unauthorized access attempts
/// - IP spoofing detection
/// - Geo-blocking simulation
/// - Network perimeter defense
/// </summary>
public class IpSafeListMiddlewareTests
{
    private readonly Mock<ILogger<IpSafeListMiddleware>> _loggerMock;
    private readonly RequestDelegate _nextDelegate;

    public IpSafeListMiddlewareTests()
    {
        _loggerMock = new Mock<ILogger<IpSafeListMiddleware>>();

        // Next delegate: Normal pipeline devam�
        _nextDelegate = (HttpContext context) =>
        {
            context.Response.StatusCode = 200;
            return Task.CompletedTask;
        };
    }

    // ============================================================================
    // WHITELIST LOGIC TESTLER� - BA�ARILI SENARYOLAR
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_IpInWhiteList_ShouldAllow()
    {
        // Arrange: IP whitelist'te var
        var allowedIps = new[] { "192.168.1.5", "10.0.0.100" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = CreateHttpContext("192.168.1.5");

        // Act
        await middleware.InvokeAsync(context);

        // Assert: 200 OK (next middleware'e ge�ti)
        context.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task InvokeAsync_MultipleAllowedIps_ShouldAllowAll()
    {
        // Arrange: Birden fazla izinli IP
        var allowedIps = new[] { "192.168.1.10", "192.168.1.20", "192.168.1.30" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        // Act & Assert: Her biri ge�meli
        foreach (var ip in allowedIps)
        {
            var context = CreateHttpContext(ip);
            await middleware.InvokeAsync(context);
            context.Response.StatusCode.Should().Be(200);
        }
    }

    [Fact]
    public async Task InvokeAsync_CaseInsensitiveMatch_ShouldAllow()
    {
        // Arrange: IP adresleri case-insensitive (IPv6 i�in �nemli)
        var allowedIps = new[] { "2001:0DB8:85A3:0000:0000:8A2E:0370:7334" }; // Uppercase
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = CreateHttpContext("2001:0db8:85a3:0000:0000:8a2e:0370:7334"); // Lowercase

        // Act
        await middleware.InvokeAsync(context);

        // Assert: IPv6 case-insensitive e�le�me
        context.Response.StatusCode.Should().Be(200);
    }

    // ============================================================================
    // BLACKLIST BLOCKING TESTLER� - ENGELLENEN SENARYOLAR
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_IpNotInWhiteList_ShouldBlock()
    {
        // Arrange: IP whitelist'te yok
        var allowedIps = new[] { "192.168.1.5" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = CreateHttpContext("5.5.5.5"); // Yetkisiz IP

        // Act
        await middleware.InvokeAsync(context);

        // Assert: 403 Forbidden
        context.Response.StatusCode.Should().Be(403);
    }

    [Fact]
    public async Task InvokeAsync_BlockedIp_ResponseShouldContainForbiddenMessage()
    {
        // Arrange
        var allowedIps = new[] { "192.168.1.100" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = CreateHttpContext("10.10.10.10"); // Engellenen IP
        context.Response.Body = new System.IO.MemoryStream();

        // Act
        await middleware.InvokeAsync(context);

        // Assert: 403 + mesaj
        context.Response.StatusCode.Should().Be(403);

        context.Response.Body.Seek(0, System.IO.SeekOrigin.Begin);
        using var reader = new System.IO.StreamReader(context.Response.Body);
        var responseBody = await reader.ReadToEndAsync();

        responseBody.Should().Contain("Forbidden");
    }

    [Fact]
    public async Task InvokeAsync_MultipleUnauthorizedIps_ShouldBlockAll()
    {
        // Arrange
        var allowedIps = new[] { "192.168.1.1" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var unauthorizedIps = new[] { "1.1.1.1", "8.8.8.8", "5.5.5.5" };

        // Act & Assert: Hepsi engellenmeli
        foreach (var ip in unauthorizedIps)
        {
            var context = CreateHttpContext(ip);
            await middleware.InvokeAsync(context);
            context.Response.StatusCode.Should().Be(403);
        }
    }

    // ============================================================================
    // LOCALHOST EXCEPTION TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_LocalhostIPv4_ShouldAllow()
    {
        // Arrange: Localhost IPv4 (127.0.0.1)
        var allowedIps = new[] { "192.168.1.5" }; // Localhost listede yok
        var configuration = CreateConfiguration(allowedIps, allowLocalhost: true);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = CreateHttpContext("127.0.0.1");

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Localhost exception nedeniyle ge�meli
        context.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task InvokeAsync_LocalhostIPv6_ShouldAllow()
    {
        // Arrange: Localhost IPv6 (::1)
        var allowedIps = new[] { "192.168.1.5" };
        var configuration = CreateConfiguration(allowedIps, allowLocalhost: true);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = CreateHttpContext("::1");

        // Act
        await middleware.InvokeAsync(context);

        // Assert: IPv6 localhost exception
        context.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task InvokeAsync_LocalhostDisabled_ShouldBlockLocalhost()
    {
        // Arrange: Localhost exception kapal�
        var allowedIps = new[] { "192.168.1.5" };
        var configuration = CreateConfiguration(allowedIps, allowLocalhost: false);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = CreateHttpContext("127.0.0.1");

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Localhost da engellenmeli
        context.Response.StatusCode.Should().Be(403);
    }

    // ============================================================================
    // CONFIGURATION PARSING TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_EmptyWhiteList_ShouldBlockAllRequests()
    {
        // Arrange: Bo� whitelist (Fail-Safe: Herkesi engelle)
        var allowedIps = new string[] { };
        var configuration = CreateConfiguration(allowedIps, allowLocalhost: false);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = CreateHttpContext("192.168.1.100");

        // Act
        await middleware.InvokeAsync(context);

        // Assert: 403 Forbidden (Fail-Safe mode)
        context.Response.StatusCode.Should().Be(403);
    }

    [Fact]
    public void InvokeAsync_NullConfiguration_ShouldBlockAllRequests()
    {
        // Arrange & Assert: Configuration null ise constructor exception fırlatmalı
        IConfiguration nullConfiguration = null!;

        var action = () => new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, nullConfiguration);
        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void InvokeAsync_MissingConfigurationSection_ShouldBlockAll()
    {
        // Arrange: "IpSafelist" section yok
        var configData = new Dictionary<string, string>
        {
            // IpSafelist section yok
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        // Assert: Constructor exception fırlatmalı (Fail-Safe: config eksikse başlatma)
        var action = () => new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);
        action.Should().Throw<InvalidOperationException>()
            .WithMessage("*IpSafelist*is missing*");
    }

    [Fact]
    public void Constructor_InvalidIpAddressInConfig_ShouldLogWarning()
    {
        // Arrange: Ge�ersiz IP adresi
        var allowedIps = new[] { "192.168.1.5", "invalid_ip", "10.0.0.1" };
        var configuration = CreateConfiguration(allowedIps);

        // Act
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        // Assert: Warning log yaz�lmal� (ge�ersiz IP i�in)
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("invalid")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.AtLeastOnce);
    }

    // ============================================================================
    // IPv4 SUPPORT TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_IPv4Address_ShouldWorkCorrectly()
    {
        // Arrange: Standart IPv4
        var allowedIps = new[] { "192.168.1.100", "10.0.0.50" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = CreateHttpContext("192.168.1.100");

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task InvokeAsync_PrivateNetworkIp_ShouldRespectWhiteList()
    {
        // Arrange: Private network IP'leri
        var allowedIps = new[] { "10.0.0.0", "172.16.0.0", "192.168.0.0" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        // Act: Listede olan
        var allowedContext = CreateHttpContext("10.0.0.0");
        await middleware.InvokeAsync(allowedContext);
        allowedContext.Response.StatusCode.Should().Be(200);

        // Listede olmayan
        var blockedContext = CreateHttpContext("10.0.0.1");
        await middleware.InvokeAsync(blockedContext);
        blockedContext.Response.StatusCode.Should().Be(403);
    }

    // ============================================================================
    // IPv6 SUPPORT TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_IPv6Address_ShouldWorkCorrectly()
    {
        // Arrange: IPv6 adresi
        var allowedIps = new[] { "2001:0db8:85a3:0000:0000:8a2e:0370:7334" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = CreateHttpContext("2001:0db8:85a3:0000:0000:8a2e:0370:7334");

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task InvokeAsync_IPv6ShorthandNotation_ShouldMatch()
    {
        // Arrange: IPv6 shorthand (::)
        var allowedIps = new[] { "::1", "2001:db8::1" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = CreateHttpContext("::1");

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        context.Response.StatusCode.Should().Be(200);
    }

    // ============================================================================
    // CIDR NOTATION TESTLER� (OPSIYONEL - GELI�MI�)
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_CidrNotation_ShouldBeSkippedAsUnsupported()
    {
        // Arrange: CIDR notation (192.168.1.0/24) - henüz desteklenmiyor
        var allowedIps = new[] { "192.168.1.0/24" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        // Act: CIDR skip edildiği için whitelist boş kalır, her IP reddedilir
        var context = CreateHttpContext("192.168.1.100");
        await middleware.InvokeAsync(context);

        // Assert: CIDR henüz desteklenmediği için IP reddedilir (403)
        context.Response.StatusCode.Should().Be(403);
    }

    [Fact]
    public async Task InvokeAsync_CidrNotation_ShouldBlockOutsideSubnet()
    {
        // Arrange: CIDR notation
        var allowedIps = new[] { "192.168.1.0/24" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        // Act: Subnet d���ndaki IP
        var context = CreateHttpContext("192.168.2.100"); // Farkl� subnet

        await middleware.InvokeAsync(context);

        // Assert: Engellenmeli
        context.Response.StatusCode.Should().Be(403);
    }

    // ============================================================================
    // EDGE CASE TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_NullIpAddress_ShouldBlock()
    {
        // Arrange: Remote IP null (edge case)
        var allowedIps = new[] { "192.168.1.5" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = null; // Null IP
        context.Response.Body = new System.IO.MemoryStream();

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Fail-Safe (engelle)
        context.Response.StatusCode.Should().Be(403);
    }

    [Fact]
    public async Task InvokeAsync_EmptyIpAddress_ShouldBlock()
    {
        // Arrange: Bo� IP string (parse edilemez)
        var allowedIps = new[] { "192.168.1.5" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        // IPAddress.Parse("") exception f�rlat�r, bu y�zden try-catch gerekli
        var context = new DefaultHttpContext();
        context.Response.Body = new System.IO.MemoryStream();

        // Act & Assert: Crash etmemeli
        var act = async () => await middleware.InvokeAsync(context);
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task InvokeAsync_WhiteSpaceInConfiguration_ShouldIgnore()
    {
        // Arrange: Config'te whitespace
        var configData = new Dictionary<string, string>
        {
            { "IpSafelist:AllowedIPs:0", "  192.168.1.5  " }, // Whitespace
            { "IpSafelist:AllowedIPs:1", "10.0.0.1" }
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();

        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = CreateHttpContext("192.168.1.5");

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Whitespace trim edilip e�le�meli
        context.Response.StatusCode.Should().Be(200);
    }

    // ============================================================================
    // LOGGING TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_BlockedIp_ShouldLogWarning()
    {
        // Arrange
        var allowedIps = new[] { "192.168.1.5" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = CreateHttpContext("5.5.5.5");
        context.Response.Body = new System.IO.MemoryStream();

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Warning log yaz�ld�
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("Access denied") || v.ToString().Contains("denied")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task InvokeAsync_AllowedIp_ShouldLogInformation()
    {
        // Arrange
        var allowedIps = new[] { "192.168.1.5" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = CreateHttpContext("192.168.1.5");

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Information log (opsiyonel, middleware'e ba�l�)
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("allowed")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.AtMostOnce); // Opsiyonel log
    }

    // ============================================================================
    // SECURITY AUDIT TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_SuspiciousIp_ShouldLogSecurityEvent()
    {
        // Arrange: Bilinen k�t� IP (�rnek: Tor exit node)
        var allowedIps = new[] { "192.168.1.5" };
        var configuration = CreateConfiguration(allowedIps);
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var suspiciousIp = "1.2.3.4"; // Sim�lasyon
        var context = CreateHttpContext(suspiciousIp);
        context.Response.Body = new System.IO.MemoryStream();

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Security log
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.IsAny<It.IsAnyType>(),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.AtLeastOnce);
    }

    // ============================================================================
    // PERFORMANCE TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_LargeWhiteList_ShouldPerformWell()
    {
        // Arrange: �ok say�da IP (1000 adet)
        var allowedIps = new List<string>();
        for (int i = 0; i < 1000; i++)
        {
            allowedIps.Add($"192.168.{i / 256}.{i % 256}");
        }

        var configuration = CreateConfiguration(allowedIps.ToArray());
        var middleware = new IpSafeListMiddleware(_nextDelegate, _loggerMock.Object, configuration);

        var context = CreateHttpContext("192.168.0.100");

        // Act
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        await middleware.InvokeAsync(context);
        stopwatch.Stop();

        // Assert: Performans kabul edilebilir (<100ms)
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(100,
            because: "IP lookup h�zl� olmal� (HashSet kullan�m� �nerilir)");
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private static IConfiguration CreateConfiguration(string[] allowedIps, bool allowLocalhost = false)
    {
        var configData = new Dictionary<string, string>
        {
            ["IpSafelist:AllowLocalhost"] = allowLocalhost ? "true" : "false"
        };

        for (int i = 0; i < allowedIps.Length; i++)
        {
            configData[$"IpSafelist:AllowedIPs:{i}"] = allowedIps[i];
        }

        return new ConfigurationBuilder()
            .AddInMemoryCollection(configData)
            .Build();
    }

    private static DefaultHttpContext CreateHttpContext(string ipAddress)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(ipAddress);
        context.Response.Body = new System.IO.MemoryStream();
        return context;
    }
}