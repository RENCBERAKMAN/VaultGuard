using System;
using System.Text.RegularExpressions;

namespace VaultGuard.Domain.Common.Results;

/// <summary>
/// Hatalı işlem sonucunu temsil eder (veri döndürür - genellikle null veya default).
/// 
/// GÜVENLİK:
/// ErrorResult'tan tüm güvenlik özelliklerini miras alır:
/// - Exception sanitization
/// - Sensitive data redaction
/// - Environment-aware logging
/// - Zero information leakage
/// 
/// KULLANIM SENARYOLARI:
/// 
/// 1. Get İşlemlerinde Bulunamama:
///    - GetUser(invalidId) → ErrorDataResult&lt;User&gt; with null data
///    - FindProduct(sku) → ErrorDataResult&lt;Product&gt; with null data
/// 
/// 2. Partial Success Scenarios:
///    - GetCachedData() → ErrorDataResult with fallback data
///    - LoadConfiguration() → ErrorDataResult with default config
/// 
/// 3. Fallback Data ile Hata:
///    - SearchProducts(query) → ErrorDataResult with empty list
///    - GetUserPreferences() → ErrorDataResult with default preferences
/// 
/// 4. Conditional Returns:
///    - Validation failed ama partial data döndürmek istiyorsanız
/// 
/// Örnek:
/// <code>
/// public IDataResult&lt;User&gt; GetUser(Guid userId)
/// {
///     var user = _repository.GetById(userId);
///     
///     if (user == null)
///         return new ErrorDataResult&lt;User&gt;(
///             "User not found.",
///             "ERR_USER_NOT_FOUND");
///     
///     return new SuccessDataResult&lt;User&gt;(user);
/// }
/// </code>
/// </summary>
/// <typeparam name="T">
/// Döndürülecek veri tipi.
/// 
/// NULL SAFETY:
/// - ErrorDataResult için Data genellikle null veya default(T)
/// - Fallback scenario'larında valid data içerebilir
/// - Reference type için T? kullanılmalı
/// </typeparam>
public sealed class ErrorDataResult<T> : DataResult<T>
{
    /// <summary>
    /// Sadece hata mesajı ile yeni bir hatalı sonuç oluşturur (data = default).
    /// 
    /// KULLANIM:
    /// Basit "not found" veya validation hataları için.
    /// Data null/default olacağı kesin olan durumlar.
    /// 
    /// MESAJ ÖNERİLERİ:
    /// ✅ "User not found."
    /// ✅ "Product not found."
    /// ✅ "Invalid search query."
    /// ✅ "No results found."
    /// 
    /// ❌ "null" (not user-friendly)
    /// ❌ "SELECT returned 0 rows" (SQL leak)
    /// ❌ "User with ID {guid} not found in table Users" (too technical)
    /// 
    /// Örnek:
    /// <code>
    /// public IDataResult&lt;User&gt; GetUser(Guid userId)
    /// {
    ///     var user = _repository.GetById(userId);
    ///     
    ///     if (user == null)
    ///         return new ErrorDataResult&lt;User&gt;("User not found.");
    ///     
    ///     return new SuccessDataResult&lt;User&gt;(user);
    /// }
    /// </code>
    /// </summary>
    /// <param name="message">Kullanıcıya gösterilecek hata mesajı</param>
    public ErrorDataResult(string message)
        : base(false, default, message)
    {
    }

    /// <summary>
    /// Hata mesajı ve hata kodu ile yeni bir hatalı sonuç oluşturur (data = default).
    /// 
    /// KULLANIM:
    /// Error tracking ve client-side handling için error code gerektiğinde.
    /// 
    /// ERROR CODE BEST PRACTICES:
    /// 
    /// Not Found Errors:
    /// - "ERR_USER_NOT_FOUND"
    /// - "ERR_PRODUCT_NOT_FOUND"
    /// - "ERR_SECRET_NOT_FOUND"
    /// 
    /// Validation Errors:
    /// - "VAL_INVALID_QUERY"
    /// - "VAL_EMPTY_SEARCH"
    /// 
    /// Business Errors:
    /// - "BIZ_NO_RESULTS"
    /// - "BIZ_SEARCH_LIMIT_EXCEEDED"
    /// 
    /// Örnek:
    /// <code>
    /// public IDataResult&lt;Secret&gt; GetSecret(Guid secretId, Guid userId)
    /// {
    ///     var secret = _repository.GetById(secretId);
    ///     
    ///     if (secret == null)
    ///         return new ErrorDataResult&lt;Secret&gt;(
    ///             "Secret not found.",
    ///             "ERR_SECRET_NOT_FOUND");
    ///     
    ///     if (secret.OwnerId != userId)
    ///         return new ErrorDataResult&lt;Secret&gt;(
    ///             "Access denied.",
    ///             "AUTHZ_SECRET_ACCESS_DENIED");
    ///     
    ///     return new SuccessDataResult&lt;Secret&gt;(secret);
    /// }
    /// </code>
    /// </summary>
    /// <param name="message">Kullanıcıya gösterilecek hata mesajı</param>
    /// <param name="errorCode">Standardize edilmiş hata kodu</param>
    public ErrorDataResult(string message, string errorCode)
        : base(false, default, message, errorCode)
    {
    }

    /// <summary>
    /// Exception'dan hatalı sonuç oluşturur (data = default).
    /// 
    /// ⚠️ GÜVENLİK KRİTİK:
    /// ErrorResult ile aynı sanitization logic'i kullanır:
    /// - Exception.Message asla direkt kullanıcıya gösterilmez
    /// - Stack trace sadece InternalErrorDetails'de
    /// - Hassas bilgiler temizlenir
    /// - Environment-aware logging
    /// 
    /// KULLANIM:
    /// Try-catch block'larında exception yakalandığında.
    /// 
    /// Örnek:
    /// <code>
    /// public IDataResult&lt;List&lt;Product&gt;&gt; GetProducts()
    /// {
    ///     try
    ///     {
    ///         var products = _repository.GetAll().ToList();
    ///         return new SuccessDataResult&lt;List&lt;Product&gt;&gt;(products);
    ///     }
    ///     catch (DbException ex)
    ///     {
    ///         // ✅ DOĞRU: Generic mesaj + exception details internal
    ///         return new ErrorDataResult&lt;List&lt;Product&gt;&gt;(
    ///             "An error occurred while retrieving products.",
    ///             "ERR_PRODUCTS_GET",
    ///             ex);
    ///         
    ///         // ❌ YANLIŞ: Exception message direkt
    ///         // return new ErrorDataResult&lt;List&lt;Product&gt;&gt;(ex.Message);
    ///     }
    /// }
    /// </code>
    /// </summary>
    /// <param name="message">Kullanıcıya gösterilecek GENERIC hata mesajı</param>
    /// <param name="errorCode">Standardize edilmiş hata kodu</param>
    /// <param name="exception">Yakalanan exception (detayları internal logging için)</param>
    public ErrorDataResult(string message, string errorCode, Exception exception)
        : base(
            false,
            default,
            message,
            errorCode,
            SanitizeExceptionForInternalLogging(exception))
    {
    }

    /// <summary>
    /// Fallback data ile hatalı sonuç oluşturur.
    /// 
    /// KULLANIM SENARYOLARI:
    /// 
    /// 1. Cache Miss ile Fallback:
    ///    - Cache'te bulunamadı ama default config döndür
    ///    - Örnek: GetSettings() → ErrorDataResult with default settings
    /// 
    /// 2. Partial Success:
    ///    - Bazı veriler alınamadı ama boş liste döndür
    ///    - Örnek: SearchProducts() → ErrorDataResult with empty list
    /// 
    /// 3. Graceful Degradation:
    ///    - Primary source failed, secondary source kullan
    ///    - Örnek: GetExchangeRate() → ErrorDataResult with cached rate
    /// 
    /// BEST PRACTICE:
    /// Fallback data kullanırken mesajda bunu belirt:
    /// ✅ "Cache miss. Using default configuration."
    /// ✅ "Search failed. Showing cached results."
    /// ✅ "Live data unavailable. Using last known value."
    /// 
    /// Örnek:
    /// <code>
    /// public IDataResult&lt;List&lt;Product&gt;&gt; GetProducts()
    /// {
    ///     try
    ///     {
    ///         var products = _cache.Get&lt;List&lt;Product&gt;&gt;("products");
    ///         
    ///         if (products == null)
    ///         {
    ///             products = _repository.GetAll().ToList();
    ///             
    ///             if (!products.Any())
    ///             {
    ///                 // Boş liste döndür ama hata mesajı ekle
    ///                 return new ErrorDataResult&lt;List&lt;Product&gt;&gt;(
    ///                     new List&lt;Product&gt;(),
    ///                     "No products found.",
    ///                     "INFO_NO_PRODUCTS");
    ///             }
    ///         }
    ///         
    ///         return new SuccessDataResult&lt;List&lt;Product&gt;&gt;(products);
    ///     }
    ///     catch (Exception ex)
    ///     {
    ///         // Boş liste döndür ve hatayı logla
    ///         return new ErrorDataResult&lt;List&lt;Product&gt;&gt;(
    ///             new List&lt;Product&gt;(),
    ///             "An error occurred while retrieving products.",
    ///             "ERR_PRODUCTS_GET",
    ///             ex);
    ///     }
    /// }
    /// 
    /// public IDataResult&lt;AppSettings&gt; GetSettings()
    /// {
    ///     try
    ///     {
    ///         var settings = _repository.GetSettings();
    ///         if (settings == null)
    ///         {
    ///             // Default settings döndür
    ///             return new ErrorDataResult&lt;AppSettings&gt;(
    ///                 AppSettings.Default,
    ///                 "Settings not found. Using default configuration.",
    ///                 "INFO_DEFAULT_SETTINGS");
    ///         }
    ///         
    ///         return new SuccessDataResult&lt;AppSettings&gt;(settings);
    ///     }
    ///     catch (Exception ex)
    ///     {
    ///         return new ErrorDataResult&lt;AppSettings&gt;(
    ///             AppSettings.Default,
    ///             "An error occurred while loading settings.",
    ///             "ERR_SETTINGS_LOAD",
    ///             ex);
    ///     }
    /// }
    /// </code>
    /// </summary>
    /// <param name="data">Fallback data (null olmayabilir)</param>
    /// <param name="message">Hata mesajı (fallback kullanıldığını belirt)</param>
    /// <param name="errorCode">Hata kodu</param>
    public ErrorDataResult(T? data, string message, string errorCode)
        : base(false, data, message, errorCode)
    {
    }

    /// <summary>
    /// Exception detaylarını internal logging için sanitize eder.
    /// ErrorResult'taki implementasyonun kopyası (code reuse için static helper ideal ama şimdilik duplicate).
    /// 
    /// TODO: SanitizationHelper static class'ına taşınabilir (DRY principle).
    /// </summary>
    private static string SanitizeExceptionForInternalLogging(Exception exception)
    {
        if (exception == null)
            return string.Empty;

        var isDevelopment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development";

        var details = $"Type: {exception.GetType().Name}";

        if (!string.IsNullOrWhiteSpace(exception.Message))
        {
            var sanitizedMessage = SanitizeSensitiveData(exception.Message);
            details += $" | Message: {sanitizedMessage}";
        }

        if (exception.InnerException != null)
        {
            details += $" | Inner: {exception.InnerException.GetType().Name}";

            if (!string.IsNullOrWhiteSpace(exception.InnerException.Message))
            {
                var sanitizedInnerMessage = SanitizeSensitiveData(exception.InnerException.Message);
                details += $" ({sanitizedInnerMessage})";
            }
        }

        if (isDevelopment && !string.IsNullOrWhiteSpace(exception.StackTrace))
        {
            var stackTrace = exception.StackTrace.Length > 2000
                ? exception.StackTrace.Substring(0, 2000) + "... (truncated)"
                : exception.StackTrace;

            details += $" | StackTrace: {stackTrace}";
        }

        return details;
    }

    /// <summary>
    /// Hassas verileri mesajdan temizler.
    /// ErrorResult'taki implementasyonun kopyası.
    /// 
    /// TODO: SanitizationHelper static class'ına taşınabilir (DRY principle).
    /// </summary>
    private static string SanitizeSensitiveData(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return string.Empty;

        var sanitized = message;

        sanitized = Regex.Replace(
            sanitized,
            @"(password|pwd|pass|secret|token|key|api[_-]?key|bearer)\s*[:=]\s*[^\s;,]+",
            "$1=***REDACTED***",
            RegexOptions.IgnoreCase);

        sanitized = Regex.Replace(
            sanitized,
            @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "***EMAIL***");

        sanitized = Regex.Replace(
            sanitized,
            @"\b\d{13,19}\b",
            "***CARD***");

        sanitized = Regex.Replace(
            sanitized,
            @"(Bearer\s+)?eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*",
            "$1***TOKEN***",
            RegexOptions.IgnoreCase);

        return sanitized;
    }
}