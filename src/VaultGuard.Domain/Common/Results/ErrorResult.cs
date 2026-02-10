using System;
using System.Text.RegularExpressions;

namespace VaultGuard.Domain.Common.Results;

/// <summary>
/// Hatalı işlem sonucunu temsil eder (veri döndürmez).
/// 
/// GÜVENLİK ÖZELLİKLERİ (KRİTİK):
/// - Exception detayları InternalErrorDetails'de saklanır (ASLA dışarı sızdırılmaz)
/// - Public message her zaman sanitize edilir
/// - Stack trace asla API response'larına eklenmez
/// - Hassas bilgiler (passwords, connection strings, tokens) otomatik temizlenir
/// - Environment-aware: Production'da minimal bilgi, Development'ta detaylı hata
/// 
/// KULLANIM SENARYOLARI:
/// 
/// 1. Validation Hataları:
///    - Email format hatası
///    - Required field missing
///    - Invalid input data
/// 
/// 2. Business Rule Violations:
///    - Yetersiz bakiye
///    - Duplicate entry
///    - Permission denied
/// 
/// 3. System Hataları:
///    - Database connection failure
///    - External API timeout
///    - File not found
/// 
/// 4. Authentication/Authorization Failures:
///    - Invalid credentials
///    - Token expired
///    - Access denied
/// 
/// Örnek:
/// <code>
/// public IResult CreateUser(CreateUserDto dto)
/// {
///     if (string.IsNullOrWhiteSpace(dto.Email))
///         return new ErrorResult("Email is required.", "VAL_EMAIL_001");
///     
///     try {
///         // ... işlem
///     }
///     catch (Exception ex) {
///         return new ErrorResult(
///             "An error occurred while creating user.",
///             "ERR_USER_CREATE",
///             ex); // Exception detayları sadece InternalErrorDetails'de
///     }
/// }
/// </code>
/// </summary>
public sealed class ErrorResult : Result
{
    /// <summary>
    /// Sadece hata mesajı ile yeni bir hatalı sonuç oluşturur.
    /// 
    /// KULLANIM:
    /// Basit validation hataları için kullanılır.
    /// ErrorCode opsiyonel olduğunda bu constructor kullanılabilir.
    /// 
    /// MESAJ ÖNERİLERİ:
    /// ✅ "Email is required."
    /// ✅ "Invalid password format."
    /// ✅ "Username already exists."
    /// ✅ "Insufficient permissions."
    /// 
    /// ❌ "Error" (too generic)
    /// ❌ "SQL Exception: Violation of PRIMARY KEY constraint" (system detail leak)
    /// ❌ "User with email test@test.com not found" (privacy leak)
    /// 
    /// Örnek:
    /// <code>
    /// if (string.IsNullOrWhiteSpace(email))
    ///     return new ErrorResult("Email is required.");
    /// </code>
    /// </summary>
    /// <param name="message">Kullanıcıya gösterilecek hata mesajı (sanitize edilmiş)</param>
    public ErrorResult(string message)
        : base(false, message)
    {
    }

    /// <summary>
    /// Hata mesajı ve hata kodu ile yeni bir hatalı sonuç oluşturur.
    /// 
    /// KULLANIM:
    /// Error tracking ve client-side error handling için hata kodu gerektiğinde kullanılır.
    /// 
    /// ERROR CODE BEST PRACTICES:
    /// 
    /// Format: "{CATEGORY}_{SUBCATEGORY}_{NUMBER}"
    /// 
    /// Kategoriler:
    /// - VAL: Validation errors
    /// - BIZ: Business rule violations
    /// - AUTH: Authentication errors
    /// - AUTHZ: Authorization errors
    /// - DB: Database errors
    /// - EXT: External service errors
    /// - SYS: System errors
    /// 
    /// Örnekler:
    /// ✅ "VAL_EMAIL_REQUIRED"
    /// ✅ "VAL_EMAIL_FORMAT"
    /// ✅ "BIZ_INSUFFICIENT_BALANCE"
    /// ✅ "AUTH_INVALID_CREDENTIALS"
    /// ✅ "AUTHZ_ACCESS_DENIED"
    /// ✅ "DB_CONNECTION_FAILED"
    /// ✅ "EXT_API_TIMEOUT"
    /// 
    /// ❌ "ERROR_001" (not descriptive)
    /// ❌ "SQL_CONSTRAINT_VIOLATION_PK_USERS" (system detail leak)
    /// ❌ "user_not_found_in_table_tblUsers" (too technical)
    /// 
    /// Örnek:
    /// <code>
    /// if (user == null)
    ///     return new ErrorResult(
    ///         "User not found.",
    ///         "ERR_USER_NOT_FOUND");
    /// 
    /// if (!user.IsActive)
    ///     return new ErrorResult(
    ///         "User account is deactivated.",
    ///         "BIZ_USER_INACTIVE");
    /// </code>
    /// </summary>
    /// <param name="message">Kullanıcıya gösterilecek hata mesajı</param>
    /// <param name="errorCode">Standardize edilmiş hata kodu</param>
    public ErrorResult(string message, string errorCode)
        : base(false, message, errorCode)
    {
    }

    /// <summary>
    /// Exception'dan hatalı sonuç oluşturur.
    /// 
    /// ⚠️ GÜVENLİK KRİTİK - EN ÖNEMLİ CONSTRUCTOR!
    /// 
    /// BU CONSTRUCTOR'IN YAPTIĞI:
    /// 1. Exception.Message'ı ASLA doğrudan kullanıcıya göstermez
    /// 2. Stack trace'i sadece InternalErrorDetails'de saklar
    /// 3. Hassas bilgileri (passwords, tokens, connection strings) temizler
    /// 4. Production'da minimal bilgi, Development'ta detaylı hata saklar
    /// 5. Public message her zaman generic ve güvenlidir
    /// 
    /// DAVRANIŞSAL KURALLAR:
    /// 
    /// Production Ortamı:
    /// - Message: Generic, user-friendly (örn: "An error occurred while processing your request.")
    /// - InternalErrorDetails: Exception type + sanitized message (stack trace YOK)
    /// 
    /// Development Ortamı:
    /// - Message: Aynı (güvenlik için)
    /// - InternalErrorDetails: Exception type + message + stack trace (debugging için)
    /// 
    /// Örnek:
    /// <code>
    /// public IResult DeleteUser(Guid userId)
    /// {
    ///     try
    ///     {
    ///         _repository.Delete(userId);
    ///         return new SuccessResult("User deleted successfully.");
    ///     }
    ///     catch (DbUpdateException ex)
    ///     {
    ///         // ✅ DOĞRU: Generic mesaj + exception details internal
    ///         return new ErrorResult(
    ///             "An error occurred while deleting the user.",
    ///             "ERR_USER_DELETE",
    ///             ex);
    ///         
    ///         // ❌ YANLIŞ: Exception message direkt kullanıcıya
    ///         // return new ErrorResult(ex.Message);
    ///     }
    ///     catch (Exception ex)
    ///     {
    ///         // Generic fallback
    ///         return new ErrorResult(
    ///             "An unexpected error occurred.",
    ///             "ERR_UNEXPECTED",
    ///             ex);
    ///     }
    /// }
    /// </code>
    /// 
    /// LOGGING ÖRNEĞİ:
    /// <code>
    /// var result = _service.DeleteUser(userId);
    /// if (!result.Success)
    /// {
    ///     // InternalErrorDetails sadece server-side logging için
    ///     _logger.LogError(
    ///         "Error deleting user {UserId}. Code: {ErrorCode}, Details: {Details}",
    ///         userId,
    ///         result.ErrorCode,
    ///         result.InternalErrorDetails); // Stack trace burada
    ///     
    ///     // API response'a sadece sanitize edilmiş bilgiler
    ///     return BadRequest(new { 
    ///         success = false,
    ///         message = result.Message,
    ///         errorCode = result.ErrorCode
    ///         // InternalErrorDetails ASLA eklenmez!
    ///     });
    /// }
    /// </code>
    /// </summary>
    /// <param name="message">
    /// Kullanıcıya gösterilecek GENERIC hata mesajı.
    /// Exception.Message KULLANMAYIN! Generic mesaj verin.
    /// </param>
    /// <param name="errorCode">Standardize edilmiş hata kodu</param>
    /// <param name="exception">
    /// Yakalanan exception.
    /// Detayları sadece InternalErrorDetails'de saklanır.
    /// </param>
    public ErrorResult(string message, string errorCode, Exception exception)
        : base(
            false,
            message,
            errorCode,
            SanitizeExceptionForInternalLogging(exception))
    {
    }

    /// <summary>
    /// Exception detaylarını internal logging için sanitize eder.
    /// 
    /// GÜVENLİK KRİTİK METOD:
    /// 
    /// NE YAPAR:
    /// 1. Exception type'ını alır (System.NullReferenceException, etc.)
    /// 2. Exception message'ı sanitize eder (hassas bilgileri temizler)
    /// 3. Inner exception varsa onun da type'ını ekler
    /// 4. Stack trace'i sadece Development ortamında ekler
    /// 5. Connection strings, passwords, tokens gibi hassas bilgileri maskeler
    /// 
    /// NE YAPMAZ:
    /// - Exception.Message'ı olduğu gibi döndürmez
    /// - Stack trace'i Production'da eklemez
    /// - Hassas bilgileri temizlemeden bırakmaz
    /// 
    /// ÇIKTI ÖRNEKLERİ:
    /// 
    /// Development:
    /// "Type: NullReferenceException | Message: Object reference not set | StackTrace: at VaultGuard.Services..."
    /// 
    /// Production:
    /// "Type: NullReferenceException | Message: Object reference not set"
    /// 
    /// Hassas Veri Temizlenmiş:
    /// "Type: SqlException | Message: Connection failed. ConnectionString=***REDACTED***"
    /// </summary>
    /// <param name="exception">Exception instance</param>
    /// <returns>Sanitize edilmiş error details string</returns>
    private static string SanitizeExceptionForInternalLogging(Exception exception)
    {
        if (exception == null)
            return string.Empty;

        // GÜVENLİK: Environment kontrolü
        // Production'da stack trace dahil edilmez
        var isDevelopment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development";

        var details = $"Type: {exception.GetType().Name}";

        // Exception message'ı sanitize et ve ekle
        if (!string.IsNullOrWhiteSpace(exception.Message))
        {
            var sanitizedMessage = SanitizeSensitiveData(exception.Message);
            details += $" | Message: {sanitizedMessage}";
        }

        // Inner exception varsa type'ını ekle (recursive çağrı YOK - performance)
        if (exception.InnerException != null)
        {
            details += $" | Inner: {exception.InnerException.GetType().Name}";

            // İsteğe bağlı: Inner exception message (sanitized)
            if (!string.IsNullOrWhiteSpace(exception.InnerException.Message))
            {
                var sanitizedInnerMessage = SanitizeSensitiveData(exception.InnerException.Message);
                details += $" ({sanitizedInnerMessage})";
            }
        }

        // Stack trace sadece Development ortamında
        if (isDevelopment && !string.IsNullOrWhiteSpace(exception.StackTrace))
        {
            // Stack trace çok uzun olabilir, ilk 2000 karakteri al
            var stackTrace = exception.StackTrace.Length > 2000
                ? exception.StackTrace.Substring(0, 2000) + "... (truncated)"
                : exception.StackTrace;

            details += $" | StackTrace: {stackTrace}";
        }

        return details;
    }

    /// <summary>
    /// Hassas verileri mesajdan temizler (Regex-based sanitization).
    /// 
    /// TEMİZLENEN BİLGİLER:
    /// 
    /// 1. Connection Strings:
    ///    - "Password=MyPass123" → "Password=***REDACTED***"
    ///    - "pwd=secret" → "pwd=***REDACTED***"
    ///    - "api_key=abc123" → "api_key=***REDACTED***"
    /// 
    /// 2. Email Addresses (GDPR/KVKK compliance):
    ///    - "user@example.com" → "***EMAIL***"
    /// 
    /// 3. Credit Card Numbers (PCI-DSS):
    ///    - "4111111111111111" → "***CARD***"
    /// 
    /// 4. JWT Tokens:
    ///    - "Bearer eyJhbGc..." → "Bearer ***TOKEN***"
    /// 
    /// PERFORMANS:
    /// - Regex compilation cached (RegexOptions.Compiled ideal ama şimdilik yok)
    /// - Multiple regex pass (trade-off: security vs performance)
    /// - String allocation minimal (StringBuilder kullanılmıyor - readability için)
    /// 
    /// GÜVENLİK:
    /// - False positive riski var (örn: "my password is strong" → "my ***REDACTED*** is strong")
    /// - Ama false negative olmaması kritik (hiçbir şeyi kaçırmamak)
    /// - Defense in depth: Birden fazla pattern kontrolü
    /// </summary>
    /// <param name="message">Orijinal exception message</param>
    /// <returns>Sanitize edilmiş message</returns>
    private static string SanitizeSensitiveData(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return string.Empty;

        var sanitized = message;

        // 1. Connection string pattern'lerini temizle
        // Pattern: "password=value", "pwd=value", "secret=value", etc.
        sanitized = Regex.Replace(
            sanitized,
            @"(password|pwd|pass|secret|token|key|api[_-]?key|bearer)\s*[:=]\s*[^\s;,]+",
            "$1=***REDACTED***",
            RegexOptions.IgnoreCase);

        // 2. Email pattern'lerini temizle (GDPR/KVKK compliance)
        // Pattern: standard email format
        sanitized = Regex.Replace(
            sanitized,
            @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "***EMAIL***");

        // 3. Credit card pattern'lerini temizle (PCI-DSS compliance)
        // Pattern: 13-19 digit card numbers
        sanitized = Regex.Replace(
            sanitized,
            @"\b\d{13,19}\b",
            "***CARD***");

        // 4. JWT token pattern'lerini temizle
        // Pattern: "Bearer eyJhbGc..." veya standalone "eyJhbGc..."
        sanitized = Regex.Replace(
    sanitized,
    @"(Bearer\s+)?eyJ[A-Za-z0-9-_]+(\.[A-Za-z0-9-_]+)*",
    "$1***TOKEN***",
    RegexOptions.IgnoreCase);

        // 5. IP Address temizleme (opsiyonel - privacy)
        // Uncomment if IP addresses should be masked
        /*
        sanitized = Regex.Replace(
            sanitized,
            @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            "***IP***");
        */

        // 6. GUID temizleme (opsiyonel - ID enumeration prevention)
        // Uncomment if GUIDs should be masked
        /*
        sanitized = Regex.Replace(
            sanitized,
            @"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
            "***GUID***");
        */

        return sanitized;
    }
}