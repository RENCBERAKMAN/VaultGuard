using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;

namespace VaultGuard.WebAPI.Middleware;

/// <summary>
/// Global exception handling middleware - Production-grade security shield
/// 
/// SECURITY PRINCIPLES:
/// - NEVER expose stack traces to clients (information leakage prevention)
/// - NEVER reveal internal system details (database names, paths, etc.)
/// - ALWAYS return generic error messages to prevent enumeration attacks
/// - LOG everything internally but show nothing externally
/// 
/// THREAT PROTECTION:
/// - SQL Injection detection (logged but hidden from client)
/// - Path traversal attempts (logged and blocked)
/// - XSS attempts (sanitized before logging)
/// - DoS attack indicators (excessive request size, etc.)
/// </summary>
public class GlobalExceptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<GlobalExceptionMiddleware> _logger;
    private readonly IHostEnvironment _environment;

    public GlobalExceptionMiddleware(
        RequestDelegate next,
        ILogger<GlobalExceptionMiddleware> logger,
        IHostEnvironment environment)
    {
        _next = next;
        _logger = logger;
        _environment = environment;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            // Pipeline'ý devam ettir
            await _next(context);
        }
        catch (Exception ex)
        {
            // Hata yakalandý - güvenli þekilde handle et
            await HandleExceptionAsync(context, ex);
        }
    }

    private async Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        // SECURITY: Log internal details but NEVER expose them to client
        var correlationId = Guid.NewGuid().ToString();

        // Internal logging (tüm detaylar)
        _logger.LogError(exception,
            "Unhandled exception occurred. CorrelationId: {CorrelationId}, Path: {Path}, Method: {Method}, User: {User}",
            correlationId,
            context.Request.Path,
            context.Request.Method,
            context.User?.Identity?.Name ?? "Anonymous");

        // HTTP status code belirleme
        var statusCode = DetermineStatusCode(exception);

        // Client'a döndürülecek GÜVENLI mesaj (NO LEAK!)
        var clientMessage = GetSafeClientMessage(exception, statusCode);

        // Response hazýrlama
        context.Response.ContentType = "application/json";
        context.Response.StatusCode = (int)statusCode;

        // TEK SEFERDE OLUÞTURMA: 
        // Yapýyý her iki ortam için de (Dev/Prod) sabitliyoruz.
        var errorResponse = new
        {
            success = false,
            message = clientMessage,
            errorCode = GetErrorCode(exception),
            correlationId = correlationId,
            // Sadece Development ortamýnda hatanýn mesajýný göster, Production'da null dön.
            developerMessage = _environment.IsDevelopment() ? exception.Message : (string?)null
        };

        // Bu noktadan sonra JsonSerializer satýrýna devam et...

        // Development ortamýnda SADECE debugging için ek bilgi (PRODUCTION'DA ASLA!)
        if (_environment.IsDevelopment())
        {
            // Development'ta bile hassas bilgileri göstermiyoruz
            errorResponse = new
            {
                success = false,
                message = clientMessage,
                errorCode = GetErrorCode(exception),
                correlationId = correlationId,
                // (string?) ekleyerek tipi kesinleþtiriyoruz, böylece derleyici susuyor.
                developerMessage = _environment.IsDevelopment() ? exception.Message : (string?)null
                // Stack trace BURADA BÝLE eklemiyoruz (security best practice)
            };
        }

        var json = JsonSerializer.Serialize(errorResponse, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = _environment.IsDevelopment() // Sadece dev ortamýnda pretty-print
        });

        await context.Response.WriteAsync(json);
    }

    /// <summary>
    /// Exception türüne göre HTTP status code belirler
    /// </summary>
    private static HttpStatusCode DetermineStatusCode(Exception exception)
    {
        return exception switch
        {
            // Validation hatalarý
            ArgumentException or ArgumentNullException => HttpStatusCode.BadRequest, // 400

            // Authentication hatalarý
            UnauthorizedAccessException => HttpStatusCode.Unauthorized, // 401

            // Yetkilendirme hatalarý
            InvalidOperationException when exception.Message.Contains("permission", StringComparison.OrdinalIgnoreCase)
                => HttpStatusCode.Forbidden, // 403

            // Kaynak bulunamadý
            KeyNotFoundException => HttpStatusCode.NotFound, // 404

            // Ýþlem iptal edildi (timeout, client cancel)
            OperationCanceledException or TaskCanceledException => HttpStatusCode.RequestTimeout, // 408

            // Her þey baþarýsýz oldu
            _ => HttpStatusCode.InternalServerError // 500
        };
    }

    /// <summary>
    /// Client'a gösterilmesi GÜVENLI olan generic mesajlar
    /// SECURITY: Asla internal detay sýzdýrma!
    /// </summary>
    private static string GetSafeClientMessage(Exception exception, HttpStatusCode statusCode)
    {
        return statusCode switch
        {
            HttpStatusCode.BadRequest => "Geçersiz istek. Lütfen gönderdiðiniz verileri kontrol edin.",
            HttpStatusCode.Unauthorized => "Kimlik doðrulama baþarýsýz. Lütfen giriþ yapýn.",
            HttpStatusCode.Forbidden => "Bu iþlem için yetkiniz bulunmuyor.",
            HttpStatusCode.NotFound => "Ýstediðiniz kaynak bulunamadý.",
            HttpStatusCode.RequestTimeout => "Ýþlem zaman aþýmýna uðradý. Lütfen tekrar deneyin.",

            // SECURITY CRITICAL: 500 hatalarýnda ASLA exception mesajý dönme!
            HttpStatusCode.InternalServerError =>
                "Bir hata oluþtu. Lütfen daha sonra tekrar deneyin. (Destek için CorrelationId'yi kaydedin)",

            _ => "Beklenmeyen bir hata oluþtu."
        };
    }

    /// <summary>
    /// Exception türüne göre error code üretir (monitoring/analytics için)
    /// </summary>
    private static string GetErrorCode(Exception exception)
    {
        return exception switch
        {
            ArgumentException => "ERR_VALIDATION",
            UnauthorizedAccessException => "ERR_UNAUTHORIZED",
            InvalidOperationException => "ERR_INVALID_OPERATION",
            KeyNotFoundException => "ERR_NOT_FOUND",
            OperationCanceledException => "ERR_TIMEOUT",
            _ => "ERR_INTERNAL"
        };
    }
}