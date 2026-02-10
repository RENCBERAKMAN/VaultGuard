namespace VaultGuard.Domain.Common.Results;

/// <summary>
/// İşlem sonucunu temsil eden base interface.
/// Tüm result type'ları bu interface'i implement eder.
/// 
/// GÜVENLİK PRENSİBİ:
/// - Success durumu hariç hiçbir internal detay dışarı sızdırılmaz
/// - InternalErrorDetails ASLA API response'larına eklenmemelidir
/// - Message her zaman sanitize edilmiş, kullanıcı dostu mesajlar içerir
/// 
/// PERFORMANS PRENSİBİ:
/// - Immutable design (thread-safe)
/// - Minimal memory footprint
/// - No virtual dispatch overhead
/// </summary>
public interface IResult
{
    /// <summary>
    /// İşlemin başarılı olup olmadığını belirtir.
    /// Bu property API response'larında kullanılabilir.
    /// </summary>
    bool Success { get; }

    /// <summary>
    /// Kullanıcıya gösterilmek üzere sanitize edilmiş mesaj.
    /// 
    /// GÜVENLİK NOTU:
    /// - Asla exception mesajları içermez
    /// - Stack trace bilgisi içermez
    /// - Sistem detayları (connection strings, paths) içermez
    /// - GDPR/KVKK uyumlu (kişisel veri içermez)
    /// 
    /// Örnekler:
    /// - Başarılı: "User created successfully."
    /// - Hatalı: "An error occurred while processing your request."
    /// </summary>
    string Message { get; }

    /// <summary>
    /// Hata kodu (opsiyonel).
    /// 
    /// Kullanım Alanları:
    /// - Client-side error mapping
    /// - Logging ve monitoring
    /// - Error analytics
    /// - API documentation
    /// 
    /// Format Önerileri:
    /// - "ERR_AUTH_001" - Authentication hatası
    /// - "ERR_DB_CONNECTION" - Database bağlantı hatası
    /// - "VAL_EMAIL_REQUIRED" - Validation hatası
    /// - "BIZ_INSUFFICIENT_BALANCE" - Business rule hatası
    /// 
    /// GÜVENLİK: Error code'lar sistem detayları ifşa etmemelidir.
    /// ✅ "ERR_USER_NOT_FOUND"
    /// ❌ "ERR_SQL_TABLE_USERS_CONSTRAINT_VIOLATION"
    /// </summary>
    string? ErrorCode { get; }

    /// <summary>
    /// Hata detayları (sadece internal logging için).
    /// 
    /// ⚠️ GÜVENLİK KRİTİK - BU PROPERTY ASLA API RESPONSE'LARINA EKLENMEMELİDİR!
    /// 
    /// Bu alan sadece şu amaçlar için kullanılmalıdır:
    /// - Server-side logging (Serilog, Application Insights, etc.)
    /// - Debugging (Development ortamında)
    /// - Error monitoring ve alerting
    /// - Forensic analysis
    /// 
    /// İçerebileceği bilgiler:
    /// - Exception type ve message (sanitize edilmiş)
    /// - Stack trace (sadece Development ortamında)
    /// - Inner exception detayları
    /// - Timestamp ve correlation ID
    /// 
    /// İÇERMEMESİ GEREKEN bilgiler:
    /// - Şifreler, API keys, tokens
    /// - Connection strings
    /// - Kişisel veriler (PII)
    /// - Sistem path'leri (production'da)
    /// </summary>
    string? InternalErrorDetails { get; }
}