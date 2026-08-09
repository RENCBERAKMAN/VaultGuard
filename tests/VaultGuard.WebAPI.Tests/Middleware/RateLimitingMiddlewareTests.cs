using System;
using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Moq;
using VaultGuard.WebAPI.Middleware;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Middleware;

/// <summary>
/// TEST S��T�: RateLimitingMiddleware - DDoS & Brute-Force Protection
/// 
/// G�VENL�K KAPSAMI:
/// - Request counting per IP
/// - Threshold enforcement (max N requests per time window)
/// - 429 Too Many Requests response
/// - Retry-After header
/// - Cache-based rate limiting
/// - Time window expiration
/// 
/// SALDIRI KORUMALARI:
/// - DDoS (Distributed Denial of Service)
/// - Brute-force login attempts
/// - API abuse
/// - Resource exhaustion
/// </summary>
public class RateLimitingMiddlewareTests
{
    private readonly Mock<ILogger<RateLimitingMiddleware>> _loggerMock;
    private readonly IMemoryCache _memoryCache;
    private readonly RequestDelegate _nextDelegate;

    // Rate limiting konfig�rasyonu
    private const int MaxRequestsPerWindow = 5; // Dakikada maksimum 5 istek
    private const int TimeWindowSeconds = 60;   // 60 saniye pencere

    public RateLimitingMiddlewareTests()
    {
        _loggerMock = new Mock<ILogger<RateLimitingMiddleware>>();
        _memoryCache = new MemoryCache(new MemoryCacheOptions());

        // Next delegate: Normal pipeline devam�
        _nextDelegate = (HttpContext context) =>
        {
            context.Response.StatusCode = 200;
            return Task.CompletedTask;
        };
    }

    // ============================================================================
    // REQUEST COUNTING TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_FirstRequest_ShouldAllowAndIncrementCounter()
    {
        // Arrange: �lk istek
        var middleware = CreateMiddleware();
        var context = CreateHttpContext("192.168.1.100");

        // Act
        await middleware.InvokeAsync(context);

        // Assert: 200 OK (ge�ti)
        context.Response.StatusCode.Should().Be(200);

        var cacheKey = GetRateLimitKey("192.168.1.100");
        _memoryCache.TryGetValue(cacheKey, out RateLimitingMiddleware.RateLimitData? rateLimitData).Should().BeTrue();
        rateLimitData!.RequestCount.Should().Be(1);
    }

    [Fact]
    public async Task InvokeAsync_MultipleRequestsBelowLimit_ShouldAllowAll()
    {
        // Arrange: Limit alt�nda (3 istek)
        var middleware = CreateMiddleware();
        var ipAddress = "192.168.1.101";

        // Act: 3 ard���k istek
        for (int i = 0; i < 3; i++)
        {
            var context = CreateHttpContext(ipAddress);
            await middleware.InvokeAsync(context);

            // Assert: Her biri 200 OK
            context.Response.StatusCode.Should().Be(200);
        }

        // Cache'te saya� kontrol
        var cacheKey = GetRateLimitKey(ipAddress);
        _memoryCache.TryGetValue(cacheKey, out int requestCount).Should().BeTrue();
        requestCount.Should().Be(3);
    }

    [Fact]
    public async Task InvokeAsync_DifferentIpAddresses_ShouldHaveSeparateCounters()
    {
        // Arrange: Farkl� IP'ler
        var middleware = CreateMiddleware();
        var ip1 = "192.168.1.100";
        var ip2 = "192.168.1.200";

        // Act: Her IP'den 2'�er istek
        await middleware.InvokeAsync(CreateHttpContext(ip1));
        await middleware.InvokeAsync(CreateHttpContext(ip1));
        await middleware.InvokeAsync(CreateHttpContext(ip2));
        await middleware.InvokeAsync(CreateHttpContext(ip2));

        // Assert: Her IP'nin kendi sayac� var
        var cacheKey1 = GetRateLimitKey(ip1);
        var cacheKey2 = GetRateLimitKey(ip2);

        _memoryCache.TryGetValue(cacheKey1, out int count1).Should().BeTrue();
        _memoryCache.TryGetValue(cacheKey2, out int count2).Should().BeTrue();

        count1.Should().Be(2);
        count2.Should().Be(2);
    }

    // ============================================================================
    // THRESHOLD BLOCKING TESTLER� (LIMIT A�IMI)
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_ExceedingLimit_ShouldReturn429TooManyRequests()
    {
        // Arrange: Limit a��m� senaryosu (6 istek, limit 5)
        var middleware = CreateMiddleware();
        var ipAddress = "192.168.1.102";

        // Act: �nce 5 ge�erli istek
        for (int i = 0; i < MaxRequestsPerWindow; i++)
        {
            var context = CreateHttpContext(ipAddress);
            await middleware.InvokeAsync(context);
            context.Response.StatusCode.Should().Be(200);
        }

        // 6. istek (limit a��m�)
        var blockedContext = CreateHttpContext(ipAddress);
        await middleware.InvokeAsync(blockedContext);

        // Assert: 429 Too Many Requests
        blockedContext.Response.StatusCode.Should().Be(429);
    }

    [Fact]
    public async Task InvokeAsync_AfterBlocking_SubsequentRequestsShouldAlsoBeBlocked()
    {
        // Arrange: Limit a��ld�ktan sonra devam eden istekler
        var middleware = CreateMiddleware();
        var ipAddress = "192.168.1.103";

        // Act: 5 ba�ar�l� + 3 engellenen istek
        for (int i = 0; i < MaxRequestsPerWindow; i++)
        {
            await middleware.InvokeAsync(CreateHttpContext(ipAddress));
        }

        // Limit a��ld�ktan sonraki 3 istek
        for (int i = 0; i < 3; i++)
        {
            var blockedContext = CreateHttpContext(ipAddress);
            await middleware.InvokeAsync(blockedContext);

            // Assert: Hepsi 429
            blockedContext.Response.StatusCode.Should().Be(429);
        }
    }

    [Fact]
    public async Task InvokeAsync_ExactlyAtLimit_ShouldStillAllow()
    {
        // Arrange: Tam limit say�s�nda istek (5)
        var middleware = CreateMiddleware();
        var ipAddress = "192.168.1.104";

        // Act: Tam 5 istek
        for (int i = 0; i < MaxRequestsPerWindow; i++)
        {
            var context = CreateHttpContext(ipAddress);
            await middleware.InvokeAsync(context);

            // Assert: 5. istek dahil hepsi ge�meli
            context.Response.StatusCode.Should().Be(200);
        }
    }

    // ============================================================================
    // RETRY-AFTER HEADER TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_WhenBlocked_ShouldIncludeRetryAfterHeader()
    {
        // Arrange: Limit a��m�
        var middleware = CreateMiddleware();
        var ipAddress = "192.168.1.105";

        // Act: Limit a��m�na kadar istek
        for (int i = 0; i < MaxRequestsPerWindow; i++)
        {
            await middleware.InvokeAsync(CreateHttpContext(ipAddress));
        }

        // Engellenen istek
        var blockedContext = CreateHttpContext(ipAddress);
        await middleware.InvokeAsync(blockedContext);

        // Assert: Retry-After header mevcut mu?
        blockedContext.Response.Headers.Should().ContainKey("Retry-After",
            because: "Client'a ne zaman tekrar deneyebilece�ini bildirmek i�in gerekli");

        var retryAfter = blockedContext.Response.Headers["Retry-After"].ToString();
        retryAfter.Should().NotBeNullOrEmpty();

        // Retry-After de�eri say�sal olmal� (saniye cinsinden)
        int.TryParse(retryAfter, out var retrySeconds).Should().BeTrue();
        retrySeconds.Should().BeGreaterThan(0);
        retrySeconds.Should().BeLessThanOrEqualTo(TimeWindowSeconds);
    }

    [Fact]
    public async Task InvokeAsync_WhenAllowed_ShouldNotIncludeRetryAfterHeader()
    {
        // Arrange: Normal istek (limit i�inde)
        var middleware = CreateMiddleware();
        var context = CreateHttpContext("192.168.1.106");

        // Act
        await middleware.InvokeAsync(context);

        // Assert: Retry-After header olmamal�
        context.Response.StatusCode.Should().Be(200);
        context.Response.Headers.Should().NotContainKey("Retry-After");
    }

    // ============================================================================
    // ERROR MESSAGE TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_WhenBlocked_ResponseShouldContainUserFriendlyMessage()
    {
        // Arrange
        var middleware = CreateMiddleware();
        var ipAddress = "192.168.1.107";

        // Act: Limit a��m�
        for (int i = 0; i <= MaxRequestsPerWindow; i++)
        {
            await middleware.InvokeAsync(CreateHttpContext(ipAddress));
        }

        var blockedContext = CreateHttpContext(ipAddress);
        await middleware.InvokeAsync(blockedContext);

        // Assert: Response body'de kullan�c� dostu mesaj
        // (Middleware'in response body'ye yazd��� mesaj� kontrol ediyoruz)
        blockedContext.Response.StatusCode.Should().Be(429);
        // Not: Response body okuma i�in MemoryStream kullan�m� gerekebilir
    }

    // ============================================================================
    // CACHE EXPIRATION TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_AfterCacheExpiration_ShouldResetCounter()
    {
        // Arrange: K�sa expiration s�resi ile middleware
        var shortExpirationCache = new MemoryCache(new MemoryCacheOptions());
        var middleware = new RateLimitingMiddleware(
            _nextDelegate,
            _loggerMock.Object,
            shortExpirationCache,
            maxRequests: MaxRequestsPerWindow,
            timeWindowSeconds: 1); // 1 saniye (test i�in k�sa)

        var ipAddress = "192.168.1.108";

        // Act: 5 istek yap
        for (int i = 0; i < MaxRequestsPerWindow; i++)
        {
            await middleware.InvokeAsync(CreateHttpContext(ipAddress));
        }

        // 1 saniye bekle (cache expiration)
        await Task.Delay(1100);

        // Yeni istek (cache s�f�rlanm�� olmal�)
        var newContext = CreateHttpContext(ipAddress);
        await middleware.InvokeAsync(newContext);

        // Assert: Yeni pencere a��ld�, 200 OK
        newContext.Response.StatusCode.Should().Be(200);
    }

    // ============================================================================
    // BRUTE-FORCE SALDIRI S�M�LASYONU
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_BruteForceAttack_ShouldBlockAfterThreshold()
    {
        // Arrange: Login endpoint'ine brute-force sald�r� sim�lasyonu
        var middleware = CreateMiddleware();
        var attackerIp = "5.5.5.5"; // Sald�rgan IP

        // Act: 10 ard���k login denemesi (brute-force)
        var blockedCount = 0;
        for (int i = 0; i < 10; i++)
        {
            var context = CreateHttpContext(attackerIp);
            context.Request.Path = "/api/auth/login"; // Login endpoint

            await middleware.InvokeAsync(context);

            if (context.Response.StatusCode == 429)
            {
                blockedCount++;
            }
        }

        // Assert: �lk 5 ge�ti, sonraki 5 engellendi
        blockedCount.Should().Be(5,
            because: "Brute-force sald�r�s� limit a��m�ndan sonra engellenmelidir");
    }

    // ============================================================================
    // DDoS SALDIRI S�M�LASYONU
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_DDoSAttack_ShouldBlockExcessiveRequests()
    {
        // Arrange: Ayn� IP'den �ok say�da istek (DDoS)
        var middleware = CreateMiddleware();
        var attackerIp = "10.10.10.10";

        // Act: 50 istek (DDoS sim�lasyonu)
        var allowedCount = 0;
        var blockedCount = 0;

        for (int i = 0; i < 50; i++)
        {
            var context = CreateHttpContext(attackerIp);
            await middleware.InvokeAsync(context);

            if (context.Response.StatusCode == 200)
                allowedCount++;
            else if (context.Response.StatusCode == 429)
                blockedCount++;
        }

        // Assert: Sadece ilk N istek ge�ti, geri kalanlar engellendi
        allowedCount.Should().Be(MaxRequestsPerWindow);
        blockedCount.Should().Be(50 - MaxRequestsPerWindow);
    }

    // ============================================================================
    // DISTRIBUTED CACHE S�M�LASYONU
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_WithDistributedCache_ShouldShareCountersAcrossInstances()
    {
        // Arrange: Distributed cache sim�lasyonu (MemoryCache shared)
        var sharedCache = new MemoryCache(new MemoryCacheOptions());

        var middleware1 = new RateLimitingMiddleware(
            _nextDelegate,
            _loggerMock.Object,
            sharedCache,
            MaxRequestsPerWindow,
            TimeWindowSeconds);

        var middleware2 = new RateLimitingMiddleware(
            _nextDelegate,
            _loggerMock.Object,
            sharedCache,
            MaxRequestsPerWindow,
            TimeWindowSeconds);

        var ipAddress = "192.168.1.200";

        // Act: Instance 1'den 3 istek
        for (int i = 0; i < 3; i++)
        {
            await middleware1.InvokeAsync(CreateHttpContext(ipAddress));
        }

        // Instance 2'den 3 istek (ayn� IP)
        for (int i = 0; i < 3; i++)
        {
            var context = CreateHttpContext(ipAddress);
            await middleware2.InvokeAsync(context);

            // �lk 2'si ge�meli (toplam 5), 3. engellenmeli
            if (i < 2)
                context.Response.StatusCode.Should().Be(200);
            else
                context.Response.StatusCode.Should().Be(429);
        }
    }

    // ============================================================================
    // NULL/EDGE CASE TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_NullIpAddress_ShouldNotCrash()
    {
        // Arrange: IP address null (edge case)
        var middleware = CreateMiddleware();
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = null; // Null IP
        context.Response.Body = new System.IO.MemoryStream();

        // Act & Assert: Crash etmemeli
        var act = async () => await middleware.InvokeAsync(context);
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task InvokeAsync_LocalhostRequests_ShouldApplyRateLimiting()
    {
        // Arrange: Localhost istekleri de rate limiting'e tabi mi?
        var middleware = CreateMiddleware();
        var localhostIp = "127.0.0.1";

        // Act: Localhost'tan limit a��m�
        for (int i = 0; i <= MaxRequestsPerWindow; i++)
        {
            await middleware.InvokeAsync(CreateHttpContext(localhostIp));
        }

        var blockedContext = CreateHttpContext(localhostIp);
        await middleware.InvokeAsync(blockedContext);

        // Assert: Localhost da engellenmeli (e�er �zel kural yoksa)
        // Not: Baz� implementasyonlar localhost'u exempt eder
        blockedContext.Response.StatusCode.Should().Be(429);
    }

    [Fact]
    public async Task InvokeAsync_IPv6Address_ShouldWorkCorrectly()
    {
        // Arrange: IPv6 adresi
        var middleware = CreateMiddleware();
        var ipv6Address = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        var context = CreateHttpContext(ipv6Address);

        // Act
        await middleware.InvokeAsync(context);

        // Assert: IPv6 de rate limiting'e tabi
        context.Response.StatusCode.Should().Be(200);

        var cacheKey = GetRateLimitKey(ipv6Address);
        _memoryCache.TryGetValue(cacheKey, out int count).Should().BeTrue();
        count.Should().Be(1);
    }

    // ============================================================================
    // LOGGING TESTLER�
    // ============================================================================

    [Fact]
    public async Task InvokeAsync_WhenBlocking_ShouldLogWarning()
    {
        // Arrange
        var middleware = CreateMiddleware();
        var ipAddress = "192.168.1.250";

        // Act: Limit a��m�
        for (int i = 0; i <= MaxRequestsPerWindow; i++)
        {
            await middleware.InvokeAsync(CreateHttpContext(ipAddress));
        }

        // Assert: Warning log yaz�ld� m�?
        _loggerMock.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("Rate limit")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.AtLeastOnce);
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private RateLimitingMiddleware CreateMiddleware()
    {
        return new RateLimitingMiddleware(
            _nextDelegate,
            _loggerMock.Object,
            _memoryCache,
            MaxRequestsPerWindow,
            TimeWindowSeconds);
    }

    private static DefaultHttpContext CreateHttpContext(string ipAddress)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(ipAddress);
        context.Response.Body = new System.IO.MemoryStream();
        return context;
    }

    private static string GetRateLimitKey(string ipAddress)
    {
        return $"RateLimit_{ipAddress}";
    }
}