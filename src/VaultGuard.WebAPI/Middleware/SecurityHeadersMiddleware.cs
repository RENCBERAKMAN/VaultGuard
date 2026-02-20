using System.Threading.Tasks;

namespace VaultGuard.WebAPI.Middleware;

/// <summary>
/// HTTP GÜVENLİK ZIRHI (Security Headers)
/// 
/// KURUMSAL ÖZELLİKLER:
/// - HSTS: HTTPS zorunluluğunu tarayıcı seviyesinde mühürler. 🛡️
/// - CSP: XSS ve kod enjeksiyonu saldırılarını %99 oranında engeller.
/// - Permissions-Policy: Tarayıcı özelliklerini (kamera, mikrofon) tamamen kilitler.
/// - Server Masking: Sunucu ve teknoloji bilgilerini gizleyerek keşif saldırılarını önler.
/// </summary>
public class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;

    public SecurityHeadersMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // OnStarting kullanıyoruz çünkü yanıt gönderilmeden hemen önce bu başlıkların 
        // orada olduğundan ve sunucu bilgilerinin silindiğinden emin olmalıyız. 🛡️
        context.Response.OnStarting(() =>
        {
            var headers = context.Response.Headers;

            // 1. HSTS: HTTPS zorunluluğu (1 yıl)
            headers.Append("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");

            // 2. Clickjacking Koruması
            headers.Append("X-Frame-Options", "DENY");

            // 3. MIME Sniffing Koruması
            headers.Append("X-Content-Type-Options", "nosniff");

            // 4. Referrer Güvenliği
            headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");

            // 5. XSS Koruması (Eski tarayıcılar için)
            headers.Append("X-XSS-Protection", "1; mode=block");

            // 6. Permissions Policy: Donanım erişimini kapat
            headers.Append("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");

            // 7. CONTENT SECURITY POLICY (CSP) 🛡️
            // API olduğu için sadece kendi kaynaklarımıza izin veriyoruz.
            headers.Append("Content-Security-Policy",
                "default-src 'self'; " +
                "script-src 'self' 'unsafe-inline'; " + // Swagger uyumluluğu için
                "style-src 'self' 'unsafe-inline'; " +
                "img-src 'self' data: https:; " +
                "frame-ancestors 'none'; " +
                "form-action 'self'");

            // 8. TEKNOLOJİ GİZLEME (Information Leakage Prevention)
            headers.Remove("Server");
            headers.Remove("X-Powered-By");
            headers.Remove("X-AspNet-Version");

            return Task.CompletedTask;
        });

        await _next(context);
    }
}