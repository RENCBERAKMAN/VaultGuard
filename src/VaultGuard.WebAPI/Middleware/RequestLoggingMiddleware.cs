using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace VaultGuard.WebAPI.Middleware;

/// <summary>
/// SİBER GÜVENLİK VE DENETİM (AUDIT) ARA YAZILIMI
/// 
/// KURUMSAL ÖZELLİKLER:
/// - Correlation ID: Her isteğe benzersiz bir kimlik atayarak tüm logları birbirine bağlar.
/// - PII Masking: Hassas verileri (Password, Secret, Token) loglara düşmeden zırhlar. 🛡️
/// - Performance Tracking: İstek süresini milisaniye bazında ölçer.
/// - Structured Logging: Logları analiz araçlarının (Splunk, ELK) okuyabileceği şekilde üretir.
/// </summary>
public class RequestLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestLoggingMiddleware> _logger;

    // SİBER GÜVENLİK: Loglarda asla açık halde görünmemesi gereken anahtar kelimeler
    private static readonly string[] SensitiveKeys = {
        "password", "oldPassword", "newPassword", "refreshToken",
        "accessToken", "secret", "token", "apiKey", "creditCard", "authorization"
    };

    public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var stopwatch = Stopwatch.StartNew();

        // --- [ENTERPRISE FEATURE] CORRELATION ID ---
        // Her isteğe bir "İlişki Kimliği" atıyoruz. Bu, hata anında tüm logları tek ID ile bulmamızı sağlar.
        var correlationId = Guid.NewGuid().ToString();
        context.Response.Headers.Add("X-Correlation-ID", correlationId);

        var request = context.Request;
        string maskedBody = await GetMaskedRequestBody(request);

        // --- YAPISAL REQUEST LOGLAMA ---
        _logger.LogInformation(
            "VaultGuard Audit [Request] | ID: {CorrelationId} | {Method} {Path} | User: {User} | IP: {IP} | Body: {Body}",
            correlationId,
            request.Method,
            request.Path,
            context.User?.Identity?.Name ?? "Anonymous",
            context.Connection.RemoteIpAddress?.ToString() ?? "Unknown",
            string.IsNullOrEmpty(maskedBody) ? "[None]" : maskedBody);

        var originalBodyStream = context.Response.Body;

        using (var responseBody = new MemoryStream())
        {
            context.Response.Body = responseBody;

            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                // Hata durumunda siber güvenlik logu oluştur
                _logger.LogCritical(ex, "VaultGuard SECURITY ALERT | ID: {CorrelationId} | İstek sırasında kritik hata!", correlationId);
                throw; // ExceptionHandlingMiddleware bunu yakalayacaktır
            }
            finally
            {
                stopwatch.Stop();

                // --- YAPISAL RESPONSE LOGLAMA ---
                _logger.LogInformation(
                    "VaultGuard Audit [Response] | ID: {CorrelationId} | Status: {StatusCode} | Duration: {ElapsedMs}ms",
                    correlationId,
                    context.Response.StatusCode,
                    stopwatch.ElapsedMilliseconds);

                await responseBody.CopyToAsync(originalBodyStream);
            }
        }
    }

    /// <summary>
    /// Request body'sini okur ve siber güvenlik zırhından (Masking) geçirir.
    /// </summary>
    private async Task<string> GetMaskedRequestBody(HttpRequest request)
    {
        if (!request.Body.CanRead || request.Path.Value?.Contains("swagger") == true)
            return string.Empty;

        request.EnableBuffering();

        using var reader = new StreamReader(request.Body, Encoding.UTF8, true, 1024, true);
        var body = await reader.ReadToEndAsync();
        request.Body.Position = 0; // Stream'i sıfırla ki Controller da okuyabilsin

        return MaskSensitiveData(body);
    }

    /// <summary>
    /// Regex kullanarak JSON içindeki hassas alanları bulur ve [MASKED] ile değiştirir.
    /// </summary>
    private static string MaskSensitiveData(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return body;

        try
        {
            foreach (var key in SensitiveKeys)
            {
                // Regex: "anahtar": "değer" kalıbını bulur ve değeri gizler 🛡️
                var pattern = $@"(""{key}""\s*:\s*"")([^""]*)("")";
                body = Regex.Replace(body, pattern, "$1[MASKED]$3", RegexOptions.IgnoreCase);
            }
            return body;
        }
        catch
        {
            return "[SECURITY MASKING FAILED - DATA HIDDEN]";
        }
    }
}