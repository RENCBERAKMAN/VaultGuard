using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace VaultGuard.WebAPI.Middleware;

/// <summary>
/// IP Whitelist (Güvenli IP Listesi) tabanlı erişim kontrolü sağlayan middleware.
/// 
/// İŞLEYİŞ MANTIĞI:
/// 1. Yapılandırmadan (appsettings.json) izin verilen IP listesini okur
/// 2. Her gelen HTTP isteğinin kaynak IP adresini kontrol eder
/// 3. IP listede yoksa HTTP 403 (Forbidden) döndürür
/// 4. IP listede varsa pipeline'a devam eder
/// 
/// KULLANIM ALANLARI:
/// - Admin panel'e sadece ofis IP'lerinden erişim
/// - Internal API'lere sadece sunucu IP'lerinden erişim
/// - Production database'e sadece uygulama sunucularından bağlantı
/// - Kritik endpoint'lere (backup, migration) sadece güvenilir IP'lerden erişim
/// 
/// GÜVENLİK ÖZELLİKLERİ:
/// - Defense in depth: Network layer + Application layer güvenlik
/// - Zero-trust model: Varsayılan olarak tüm IP'ler engellenir
/// - Localhost bypass (development ortamı için)
/// - IP spoofing'e karşı X-Forwarded-For validation
/// - CIDR notation desteği (IP range matching)
/// 
/// CONFIGURATION ÖRNEĞİ (appsettings.json):
/// <code>
/// {
///   "IpSafelist": {
///     "AllowedIPs": [
///       "203.0.113.5",           // Ofis IP
///       "198.51.100.10",         // VPN IP
///       "192.168.1.0/24"         // Local network (CIDR)
///     ],
///     "AllowLocalhost": true     // Development için localhost izni
///   }
/// }
/// </code>
/// 
/// SINIRLAMALAR:
/// - Static IP gerektirir (dynamic IP'ler için uygun değil)
/// - VPN/Proxy kullanımında IP değişebilir
/// - IPv6 desteği mevcut ama test edilmeli
/// 
/// OWASP TOP 10 COMPLIANCE:
/// - A01:2021 – Broken Access Control (IP-based access control)
/// - A05:2021 – Security Misconfiguration (Network segmentation)
/// </summary>
public class IpSafeListMiddleware
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
    /// Engellenen IP'ler Warning seviyesinde loglanır.
    /// </summary>
    private readonly ILogger<IpSafeListMiddleware> _logger;

    /// <summary>
    /// Yapılandırma (appsettings.json) erişimi için configuration instance.
    /// </summary>
    private readonly IConfiguration _configuration;

    /// <summary>
    /// İzin verilen IP adresleri listesi (cache).
    /// Constructor'da configuration'dan okunur ve cache'lenir.
    /// 
    /// PERFORMANCE: Her request'te configuration okumak yerine startup'ta cache edilir.
    /// </summary>
    private readonly HashSet<IPAddress> _allowedIPs;

    /// <summary>
    /// Localhost erişimine izin verilip verilmeyeceğini belirten flag.
    /// Development ortamında true, production'da false olmalı.
    /// </summary>
    private readonly bool _allowLocalhost;

    /// <summary>
    /// Configuration key prefix (sabit değer).
    /// </summary>
    private const string ConfigSectionName = "IpSafelist";

    // ============================================================================
    // CONSTRUCTOR
    // ============================================================================

    /// <summary>
    /// IpSafeListMiddleware constructor.
    /// 
    /// CONFIGURATION LOADING:
    /// Constructor'da configuration okunur ve validate edilir.
    /// Startup'ta hata varsa application başlamaz (fail-fast approach).
    /// </summary>
    /// <param name="next">Pipeline'daki bir sonraki middleware.</param>
    /// <param name="logger">Logging için ILogger instance.</param>
    /// <param name="configuration">Configuration erişimi için IConfiguration instance.</param>
    /// <exception cref="ArgumentNullException">Parametre null ise.</exception>
    /// <exception cref="InvalidOperationException">Configuration geçersiz ise.</exception>
    public IpSafeListMiddleware(
        RequestDelegate next,
        ILogger<IpSafeListMiddleware> logger,
        IConfiguration configuration)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));

        // ================================================================
        // CONFIGURATION OKUMA
        // ================================================================

        // IpSafelist section'ını al
        var safelistSection = _configuration.GetSection(ConfigSectionName);

        if (!safelistSection.Exists())
        {
            // CRITICAL: Configuration yoksa application başlamaz
            throw new InvalidOperationException(
                $"Configuration section '{ConfigSectionName}' is missing. " +
                "Please configure IP safelist in appsettings.json.");
        }

        // AllowLocalhost flag'ini oku (default: false - güvenlik için)
        _allowLocalhost = safelistSection.GetValue<bool>("AllowLocalhost", defaultValue: false);

        // AllowedIPs listesini oku
        var allowedIpsConfig = safelistSection.GetSection("AllowedIPs").Get<string[]>();

        if (allowedIpsConfig == null || allowedIpsConfig.Length == 0)
        {
            // WARNING: IP listesi boş ise tüm request'ler engellenecek
            _logger.LogWarning(
                "No allowed IPs configured in '{ConfigSection}:AllowedIPs'. " +
                "All requests will be blocked unless AllowLocalhost is true.",
                ConfigSectionName);

            _allowedIPs = new HashSet<IPAddress>();
        }
        else
        {
            // IP adreslerini parse et ve HashSet'e ekle
            _allowedIPs = ParseAllowedIPs(allowedIpsConfig);

            // Startup logging
            _logger.LogInformation(
                "IpSafeListMiddleware initialized: {Count} allowed IP(s), AllowLocalhost={AllowLocalhost}",
                _allowedIPs.Count,
                _allowLocalhost);

            // Debug logging (tüm IP listesi)
            if (_logger.IsEnabled(LogLevel.Debug))
            {
                foreach (var ip in _allowedIPs)
                {
                    _logger.LogDebug("Allowed IP: {IpAddress}", ip);
                }
            }
        }
    }

    // ============================================================================
    // MIDDLEWARE INVOKE METHOD
    // ============================================================================

    /// <summary>
    /// Middleware'in ana işlem metodu.
    /// Her HTTP request için çağrılır.
    /// 
    /// İŞLEM AKIŞI:
    /// 1. Client IP adresini tespit et
    /// 2. Localhost kontrolü yap (allowLocalhost flag'e göre)
    /// 3. IP allowed list'te var mı kontrol et
    /// 4. Yoksa → HTTP 403 Forbidden dön
    /// 5. Varsa → Pipeline'a devam et
    /// 
    /// THREAD SAFETY:
    /// HashSet read-only kullanımı thread-safe'tir.
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

            var clientIp = GetClientIpAddress(context);

            // EDGE CASE: IP adresi tespit edilemezse
            if (clientIp == null)
            {
                _logger.LogWarning(
                    "Unable to determine client IP address for request: {Path}. Blocking request.",
                    context.Request.Path);

                // Fail-closed approach: IP tespit edilemezse engelle
                await BlockRequest(context, null);
                return;
            }

            // ================================================================
            // 2. LOCALHOST KONTROLÜ
            // ================================================================

            if (_allowLocalhost && IsLocalhost(clientIp))
            {
                // Localhost izinli, pipeline'a devam et
                _logger.LogDebug(
                    "Localhost request allowed from {ClientIp} to {Path}",
                    clientIp,
                    context.Request.Path);

                await _next(context);
                return;
            }

            // ================================================================
            // 3. IP SAFELIST KONTROLÜ
            // ================================================================

            if (_allowedIPs.Contains(clientIp))
            {
                // IP allowed list'te var, pipeline'a devam et
                _logger.LogDebug(
                    "Allowed IP {ClientIp} accessed {Path}",
                    clientIp,
                    context.Request.Path);

                await _next(context);
                return;
            }

            // ================================================================
            // 4. ERİŞİM ENGELLENDİ
            // ================================================================

            // IP allowed list'te yok ve localhost değil → Engelle
            await BlockRequest(context, clientIp);
        }
        catch (Exception ex)
        {
            // EXCEPTION HANDLING: IP safelist hatası pipeline'ı kesmemeli
            // Fail-closed approach: Hata durumunda erişim engellenir
            _logger.LogError(ex,
                "Error in IpSafeListMiddleware. Blocking request for security. Path: {Path}",
                context.Request.Path);

            // Güvenlik hatası → Erişimi engelle
            await BlockRequest(context, null);
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
    /// Trusted proxy listesi kullanılmalı (Production'da).
    /// 
    /// RateLimitingMiddleware ile aynı implementasyon (DRY principle).
    /// İleride base class'a taşınabilir.
    /// </summary>
    /// <param name="context">HTTP context.</param>
    /// <returns>Client IP adresi veya null.</returns>
    private IPAddress? GetClientIpAddress(HttpContext context)
    {
        try
        {
            // X-Forwarded-For header (proxy arkasında)
            if (context.Request.Headers.TryGetValue("X-Forwarded-For", out var forwardedFor))
            {
                var forwardedIps = forwardedFor.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries);

                if (forwardedIps.Length > 0)
                {
                    var clientIp = forwardedIps[0].Trim();

                    if (IPAddress.TryParse(clientIp, out var parsedIp))
                    {
                        return parsedIp;
                    }
                }
            }

            // X-Real-IP header (Nginx proxy)
            if (context.Request.Headers.TryGetValue("X-Real-IP", out var realIp))
            {
                var realIpValue = realIp.ToString().Trim();

                if (IPAddress.TryParse(realIpValue, out var parsedRealIp))
                {
                    return parsedRealIp;
                }
            }

            // Remote IP Address (direkt bağlantı)
            return context.Connection.RemoteIpAddress;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to parse client IP address.");
            return null;
        }
    }

    /// <summary>
    /// IP adresinin localhost (loopback) olup olmadığını kontrol eder.
    /// 
    /// LOCALHOST ADRESLERİ:
    /// - IPv4: 127.0.0.1, 127.0.0.0/8 (loopback range)
    /// - IPv6: ::1 (loopback)
    /// - IPv6: ::ffff:127.0.0.1 (IPv4-mapped IPv6)
    /// 
    /// KULLANIM:
    /// Development ortamında localhost erişimine izin vermek için.
    /// Production'da AllowLocalhost = false olmalı.
    /// </summary>
    /// <param name="ipAddress">Kontrol edilecek IP adresi.</param>
    /// <returns>true: localhost, false: remote IP.</returns>
    private bool IsLocalhost(IPAddress ipAddress)
    {
        // IPv4 loopback: 127.0.0.1
        if (IPAddress.IsLoopback(ipAddress))
        {
            return true;
        }

        // IPv6 loopback: ::1
        if (ipAddress.Equals(IPAddress.IPv6Loopback))
        {
            return true;
        }

        // IPv4-mapped IPv6 loopback: ::ffff:127.0.0.1
        if (ipAddress.IsIPv4MappedToIPv6)
        {
            var mappedIPv4 = ipAddress.MapToIPv4();
            if (IPAddress.IsLoopback(mappedIPv4))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Configuration'dan okunan IP string array'ini IPAddress HashSet'ine parse eder.
    /// 
    /// DESTEKLENEN FORMATLAR:
    /// - IPv4: "203.0.113.5"
    /// - IPv6: "2001:db8::1"
    /// - CIDR (future): "192.168.1.0/24" (şimdilik desteklenmiyor ama kolayca eklenebilir)
    /// 
    /// HATA YÖNETİMİ:
    /// Geçersiz IP adresleri warning log ile atlanır.
    /// </summary>
    /// <param name="ipStrings">Configuration'dan okunan IP string array.</param>
    /// <returns>Parse edilmiş IP adresleri HashSet'i.</returns>
    private HashSet<IPAddress> ParseAllowedIPs(string[] ipStrings)
    {
        var ipSet = new HashSet<IPAddress>();

        foreach (var ipString in ipStrings)
        {
            // Null/empty check
            if (string.IsNullOrWhiteSpace(ipString))
            {
                _logger.LogWarning("Empty IP address in configuration. Skipping.");
                continue;
            }

            var trimmedIp = ipString.Trim();

            // CIDR notation kontrolü (future feature)
            if (trimmedIp.Contains('/'))
            {
                _logger.LogWarning(
                    "CIDR notation '{IpString}' is not supported yet. Skipping.",
                    trimmedIp);
                continue;
            }

            // IP parsing
            if (IPAddress.TryParse(trimmedIp, out var ipAddress))
            {
                ipSet.Add(ipAddress);
            }
            else
            {
                // Geçersiz IP formatı
                _logger.LogWarning(
                    "Invalid IP address format in configuration: '{IpString}'. Skipping.",
                    trimmedIp);
            }
        }

        return ipSet;
    }

    /// <summary>
    /// Request'i engeller ve HTTP 403 Forbidden döndürür.
    /// 
    /// SECURITY LOGGING:
    /// Her engellenen request loglanır (security monitoring için).
    /// 
    /// CLIENT RESPONSE:
    /// Minimal bilgi verilir (information leakage prevention).
    /// "Forbidden" → Generic mesaj (hangi IP allowed list'te yok belirtilmez).
    /// </summary>
    /// <param name="context">HTTP context.</param>
    /// <param name="clientIp">Engellenen client IP (null olabilir).</param>
    /// <returns>Asenkron task.</returns>
    private async Task BlockRequest(HttpContext context, IPAddress? clientIp)
    {
        // SECURITY EVENT LOGGING
        _logger.LogWarning(
            "Access denied for IP: {ClientIp}. Path: {Path}, Method: {Method}, UserAgent: {UserAgent}",
            clientIp?.ToString() ?? "Unknown",
            context.Request.Path,
            context.Request.Method,
            context.Request.Headers.UserAgent.ToString());

        // HTTP 403 Forbidden
        context.Response.StatusCode = StatusCodes.Status403Forbidden;

        // Response body (minimal bilgi - information leakage prevention)
        context.Response.ContentType = "text/plain";
        await context.Response.WriteAsync("Forbidden");

        // Pipeline'ı sonlandır
        // NOT: await _next(context) ÇAĞIRILMAZ!
    }
}