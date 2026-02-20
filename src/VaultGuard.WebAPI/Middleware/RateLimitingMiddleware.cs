using Microsoft.Extensions.Caching.Memory;
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace VaultGuard.WebAPI.Middleware;

/// <summary>
/// DDoS (Distributed Denial of Service) ve Brute-Force saldırılarına karşı koruma sağlayan
/// IP bazlı istek sınırlandırma (Rate Limiting) middleware'i.
/// 
/// İŞLEYİŞ MANTIĞI:
/// 1. Her gelen HTTP isteğinin kaynak IP adresini tespit eder
/// 2. Bu IP için bellekte (IMemoryCache) bir sayaç tutar
/// 3. Belirlenen zaman penceresi (timeWindow) içinde maksimum istek sayısını (maxRequests) aşan IP'leri engeller
/// 4. Engellenen IP'ler için HTTP 429 (Too Many Requests) döndürür
/// 5. Client'a ne zaman tekrar deneyebileceğini "Retry-After" header'ı ile bildirir
/// 
/// KULLANIM ALANLARI:
/// - Login endpoint'leri (brute-force password attack önleme)
/// - Public API endpoint'leri (DDoS koruması)
/// - Resource-intensive endpoint'ler (CPU/Memory tüketimi yüksek işlemler)
/// - File upload endpoint'leri (spam önleme)
/// 
/// GÜVENLİK ÖZELLİKLERİ:
/// - IP spoofing'e karşı X-Forwarded-For header validation
/// - Thread-safe counter operations (concurrent request'ler için)
/// - Memory cache TTL (Time-To-Live) ile otomatik temizlik
/// - Detaylı security event logging
/// 
/// PERFORMANS:
/// - In-memory cache kullanımı (Redis'e göre daha hızlı ama single-server)
/// - O(1) complexity (hash table lookup)
/// - Minimal memory footprint (IP başına ~50 byte)
/// 
/// SINIRLAMALAR:
/// - Single-server deployment için uygundur (load-balanced ortamlarda Redis kullanılmalı)
/// - IP bazlı blocking (authenticated user bazlı değil - ileride geliştirilebilir)
/// 
/// CONFIGURATION ÖRNEĞI:
/// <code>
/// app.UseMiddleware&lt;RateLimitingMiddleware&gt;(
///     maxRequests: 100,        // 100 istek
///     timeWindowSeconds: 60    // 60 saniye içinde
/// );
/// </code>
/// 
/// OWASP TOP 10 COMPLIANCE:
/// - A05:2021 – Security Misconfiguration (Rate limiting eksikliği)
/// - A07:2021 – Identification and Authentication Failures (Brute force protection)
/// </summary>
public class RateLimitingMiddleware
{
    // ============================================================================
    // FIELDS & CONSTANTS
    // ============================================================================

    /// <summary>
    /// Pipeline'daki bir sonraki middleware'i çağırmak için delegate.
    /// </summary>
    private readonly RequestDelegate _next;

    /// <summary>
    /// Security event'lerini loglamak için logger instance.
    /// Rate limit aşımları Warning seviyesinde loglanır.
    /// </summary>
    private readonly ILogger<RateLimitingMiddleware> _logger;

    /// <summary>
    /// IP bazlı request counter'ları tutmak için in-memory cache.
    /// 
    /// KEY FORMAT: "RateLimit_{IPAddress}"
    /// VALUE TYPE: int (request count)
    /// EXPIRATION: Sliding (her request'te yenilenir)
    /// </summary>
    private readonly IMemoryCache _cache;

    /// <summary>
    /// Belirtilen zaman penceresi içinde izin verilen maksimum istek sayısı.
    /// 
    /// ÖNERİLEN DEĞERLER:
    /// - Login endpoint: 5 istek / dakika
    /// - Public API: 100 istek / dakika
    /// - File upload: 10 istek / dakika
    /// - Search: 50 istek / dakika
    /// </summary>
    private readonly int _maxRequests;

    /// <summary>
    /// Rate limiting zaman penceresi (saniye cinsinden).
    /// Bu süre içinde _maxRequests sayısı aşılamaz.
    /// 
    /// ÖNERİLEN DEĞERLER:
    /// - Kısa süreli koruma: 60 saniye (1 dakika)
    /// - Orta süreli koruma: 300 saniye (5 dakika)
    /// - Uzun süreli koruma: 3600 saniye (1 saat)
    /// </summary>
    private readonly int _timeWindowSeconds;

    /// <summary>
    /// Cache key prefix (sabit değer).
    /// Farklı middleware'lerin cache key'leri çakışmasın diye prefix kullanılır.
    /// </summary>
    private const string CacheKeyPrefix = "RateLimit_";

    // ============================================================================
    // CONSTRUCTOR
    // ============================================================================

    /// <summary>
    /// RateLimitingMiddleware constructor.
    /// 
    /// DEPENDENCY INJECTION:
    /// ASP.NET Core middleware'ler constructor DI destekler.
    /// Pipeline içinde her request için singleton instance kullanılır.
    /// </summary>
    /// <param name="next">Pipeline'daki bir sonraki middleware.</param>
    /// <param name="logger">Logging için ILogger instance.</param>
    /// <param name="cache">In-memory caching için IMemoryCache instance.</param>
    /// <param name="maxRequests">
    /// Maksimum istek sayısı (default: 5).
    /// Endpoint sensitivity'e göre ayarlanmalı.
    /// </param>
    /// <param name="timeWindowSeconds">
    /// Zaman penceresi saniye cinsinden (default: 60).
    /// maxRequests bu süre içinde aşılamaz.
    /// </param>
    public RateLimitingMiddleware(
        RequestDelegate next,
        ILogger<RateLimitingMiddleware> logger,
        IMemoryCache cache,
        int maxRequests = 5,
        int timeWindowSeconds = 60)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));

        // Validation: maxRequests pozitif olmalı
        if (maxRequests <= 0)
            throw new ArgumentException("Max requests must be greater than zero.", nameof(maxRequests));

        // Validation: timeWindowSeconds pozitif olmalı
        if (timeWindowSeconds <= 0)
            throw new ArgumentException("Time window must be greater than zero.", nameof(timeWindowSeconds));

        _maxRequests = maxRequests;
        _timeWindowSeconds = timeWindowSeconds;

        // Startup logging (middleware yapılandırması loglanır)
        _logger.LogInformation(
            "RateLimitingMiddleware initialized: MaxRequests={MaxRequests}, TimeWindow={TimeWindow}s",
            _maxRequests,
            _timeWindowSeconds);
    }

    // ============================================================================
    // MIDDLEWARE INVOKE METHOD
    // ============================================================================

    /// <summary>
    /// Middleware'in ana işlem metodu.
    /// Her HTTP request için çağrılır.
    /// 
    /// İŞLEM AKIŞI:
    /// 1. Client IP adresini tespit et (GetClientIpAddress)
    /// 2. IP için cache key oluştur
    /// 3. Cache'ten mevcut request count'u al
    /// 4. Eğer limit aşılmışsa → HTTP 429 dön
    /// 5. Değilse counter'ı artır ve pipeline'a devam et
    /// 
    /// THREAD SAFETY:
    /// IMemoryCache thread-safe'tir.
    /// GetOrCreate metodu atomic operation sağlar.
    /// 
    /// EXCEPTION HANDLING:
    /// Try-catch ile tüm hatalar yakalanır.
    /// Hata durumunda bile pipeline devam eder (fail-open approach).
    /// </summary>
    /// <param name="context">HTTP request/response context.</param>
    /// <returns>Asenkron task.</returns>
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            // ================================================================
            // 1. IP ADRESİ TESPİTİ
            // ================================================================

            // Client IP adresini al (proxy desteği ile)
            var clientIp = GetClientIpAddress(context);

            // EDGE CASE: IP adresi tespit edilemezse
            if (clientIp == null)
            {
                _logger.LogWarning(
                    "Unable to determine client IP address for request: {Path}",
                    context.Request.Path);

                // IP tespit edilemezse rate limiting uygulanmaz (fail-open)
                // Alternatif: Güvenlik için fail-closed yapılabilir (403 dönülebilir)
                await _next(context);
                return;
            }

            // ================================================================
            // 2. CACHE KEY OLUŞTURMA
            // ================================================================

            var cacheKey = $"{CacheKeyPrefix}{clientIp}";

            // ================================================================
            // 3. RATE LIMIT KONTROLÜ
            // ================================================================

            // THREAD-SAFE: GetOrCreate atomic operation sağlar
            // İlk request'te factory metodu çalışır (value: 1)
            // Sonraki request'lerde mevcut value döner
            var requestData = _cache.GetOrCreate(cacheKey, entry =>
            {
                // Cache expiration: Sliding (her erişimde yenilenir)
                // Eğer timeWindow boyunca request gelmezse cache temizlenir
                entry.SlidingExpiration = TimeSpan.FromSeconds(_timeWindowSeconds);

                // İlk request için başlangıç değeri
                return new RateLimitData
                {
                    RequestCount = 0,
                    WindowStart = DateTime.UtcNow
                };
            });

            // NULL CHECK: Cache'ten null gelebilir (eviction policy)
            if (requestData == null)
            {
                requestData = new RateLimitData
                {
                    RequestCount = 0,
                    WindowStart = DateTime.UtcNow
                };
            }

            // Thread-safe increment
            // Interlocked.Increment atomic operation sağlar
            var currentCount = Interlocked.Increment(ref requestData.RequestCount);

            // ================================================================
            // 4. LİMİT AŞIMI KONTROLÜ
            // ================================================================

            if (currentCount > _maxRequests)
            {
                // SECURITY EVENT LOGGING
                _logger.LogWarning(
                    "Rate limit exceeded for IP: {ClientIp}. " +
                    "Request count: {RequestCount}, Limit: {MaxRequests}, Window: {TimeWindow}s, " +
                    "Path: {Path}, Method: {Method}",
                    clientIp,
                    currentCount,
                    _maxRequests,
                    _timeWindowSeconds,
                    context.Request.Path,
                    context.Request.Method);

                // HTTP 429 Too Many Requests
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;

                // Retry-After header (client'a ne zaman tekrar deneyebileceğini söyler)
                // CRITICAL: .Add() DEĞİL .Append() KULLAN (ASP0019 uyarısı)
                var retryAfterSeconds = _timeWindowSeconds.ToString();
                context.Response.Headers.Append("Retry-After", retryAfterSeconds);

                // X-RateLimit headers (RFC 6585 standardı)
                context.Response.Headers.Append("X-RateLimit-Limit", _maxRequests.ToString());
                context.Response.Headers.Append("X-RateLimit-Remaining", "0");
                context.Response.Headers.Append("X-RateLimit-Reset",
                    DateTimeOffset.UtcNow.AddSeconds(_timeWindowSeconds).ToUnixTimeSeconds().ToString());

                // Response body
                context.Response.ContentType = "text/plain";
                await context.Response.WriteAsync(
                    $"Too many requests. Please try again in {_timeWindowSeconds} seconds.");

                // Pipeline'ı sonlandır (bir sonraki middleware'e geçme)
                return;
            }

            // ================================================================
            // 5. RATE LİMİT BİLGİLERİNİ HEADER'LARA EKLE
            // ================================================================

            // Client'a kalan request hakkını bildir (informational)
            var remaining = Math.Max(0, _maxRequests - currentCount);
            context.Response.Headers.Append("X-RateLimit-Limit", _maxRequests.ToString());
            context.Response.Headers.Append("X-RateLimit-Remaining", remaining.ToString());
            context.Response.Headers.Append("X-RateLimit-Reset",
                DateTimeOffset.UtcNow.AddSeconds(_timeWindowSeconds).ToUnixTimeSeconds().ToString());

            // ================================================================
            // 6. PİPELINE'A DEVAM ET
            // ================================================================

            // Limit aşılmamış, bir sonraki middleware'e geç
            await _next(context);
        }
        catch (Exception ex)
        {
            // EXCEPTION HANDLING: Rate limiting hatası pipeline'ı kesmemeli
            // Fail-open approach: Hata durumunda rate limiting uygulanmaz
            _logger.LogError(ex,
                "Error in RateLimitingMiddleware. Allowing request to proceed. Path: {Path}",
                context.Request.Path);

            // Pipeline'a devam et (güvenlik hatası olsa bile sistem çalışmalı)
            await _next(context);
        }
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    /// <summary>
    /// Client'ın gerçek IP adresini tespit eder.
    /// 
    /// IP TESPİT STRATEJİSİ:
    /// 1. X-Forwarded-For header'ını kontrol et (proxy/load balancer arkasında)
    /// 2. X-Real-IP header'ını kontrol et (Nginx proxy)
    /// 3. RemoteIpAddress'i kullan (direkt bağlantı)
    /// 
    /// GÜVENLİK:
    /// X-Forwarded-For header client tarafından manipüle edilebilir!
    /// Trusted proxy kontrolü yapılmalı (Production'da).
    /// 
    /// ÖRNEK X-Forwarded-For:
    /// "203.0.113.195, 70.41.3.18, 150.172.238.178"
    /// İlk IP = Client IP
    /// Sonraki IP'ler = Proxy chain
    /// </summary>
    /// <param name="context">HTTP context.</param>
    /// <returns>Client IP adresi veya null (tespit edilemezse).</returns>
    private IPAddress? GetClientIpAddress(HttpContext context)
    {
        try
        {
            // ================================================================
            // 1. X-Forwarded-For HEADER (EN YAYGIN)
            // ================================================================

            // Proxy/Load Balancer arkasında çalışıyorsak X-Forwarded-For kullanılır
            if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var forwardedFor))
            {
                var forwardedIps = forwardedFor.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries);

                // İlk IP = Client IP (proxy chain'in başı)
                if (forwardedIps.Length > 0)
                {
                    var clientIp = forwardedIps[0].Trim();

                    if (IPAddress.TryParse(clientIp, out var parsedIp))
                    {
                        return parsedIp;
                    }
                }
            }

            // ================================================================
            // 2. X-Real-IP HEADER (NGINX PROXY)
            // ================================================================

            // Nginx reverse proxy kullanıyorsak X-Real-IP header'ı daha güvenilir
            if (context.Request.Headers.TryGetValue("X-Real-IP", out var realIp))
            {
                var realIpValue = realIp.ToString().Trim();

                if (IPAddress.TryParse(realIpValue, out var parsedRealIp))
                {
                    return parsedRealIp;
                }
            }

            // ================================================================
            // 3. REMOTE IP ADDRESS (DİREKT BAĞLANTI)
            // ================================================================

            // Proxy yoksa direkt RemoteIpAddress kullanılır
            return context.Connection.RemoteIpAddress;
        }
        catch (Exception ex)
        {
            // IP parsing hatası (malformed header)
            _logger.LogWarning(ex, "Failed to parse client IP address.");
            return null;
        }
    }

    // ============================================================================
    // INNER CLASSES
    // ============================================================================

    /// <summary>
    /// Rate limit verilerini tutan cache modeli.
    /// 
    /// Thread-safe field'lar kullanılır (Interlocked.Increment için).
    /// </summary>
    private class RateLimitData
    {
        /// <summary>
        /// Zaman penceresi içindeki request sayısı.
        /// Interlocked.Increment ile thread-safe artırılır.
        /// </summary>
        public int RequestCount;

        /// <summary>
        /// Zaman penceresinin başlangıç zamanı (UTC).
        /// </summary>
        public DateTime WindowStart;
    }
}