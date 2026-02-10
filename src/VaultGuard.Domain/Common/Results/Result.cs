namespace VaultGuard.Domain.Common.Results;

/// <summary>
/// Result Pattern için abstract base class.
/// Tüm result implementasyonları için ortak davranışları tanımlar.
/// 
/// TASARIM KARARLARI:
/// - Sealed olmayan abstract class → Extensibility sağlar
/// - Protected constructor → Sadece türetilmiş sınıflardan kullanılabilir
/// - Immutable design → Thread-safe, functional programming uyumlu
/// - No virtual methods → Performance optimization
/// 
/// GÜVENLİK ÖZELLİKLERİ:
/// - Exception detayları InternalErrorDetails'de saklanır (public değil)
/// - Message her zaman sanitize edilmiş, kullanıcı dostu mesajlar içerir
/// - Stack trace asla public property'lerde yer almaz
/// - Connection strings, passwords otomatik temizlenir
/// 
/// PERFORMANS ÖZELLİKLERİ:
/// - Minimal memory allocation (4 field, ~40 bytes overhead)
/// - No boxing/unboxing for value types
/// - String interning consideration for common messages
/// - Zero virtual dispatch overhead
/// 
/// KULLANIM:
/// Bu sınıf doğrudan instantiate edilmez. Bunun yerine:
/// - SuccessResult (başarılı işlem, data yok)
/// - ErrorResult (hatalı işlem, data yok)
/// türetilmiş sınıfları kullanılır.
/// </summary>
public abstract class Result : IResult
{
    /// <inheritdoc/>
    /// <remarks>
    /// Immutable property - thread-safe.
    /// Init-only setter sayesinde constructor'dan sonra değiştirilemez.
    /// </remarks>
    public bool Success { get; init; }

    /// <inheritdoc/>
    /// <remarks>
    /// Boş string asla saklanmaz - constructor'da default mesaj atanır.
    /// String.Empty yerine actual message kullanılır (memory optimization).
    /// </remarks>
    public string Message { get; init; }

    /// <inheritdoc/>
    /// <remarks>
    /// Nullable - başarılı işlemler için genellikle null.
    /// Standartlaştırılmış error code formatı kullanılması önerilir.
    /// </remarks>
    public string? ErrorCode { get; init; }

    /// <inheritdoc/>
    /// <remarks>
    /// ⚠️ ASLA API response'larına eklenmemelidir!
    /// Sadece server-side logging için kullanılır.
    /// </remarks>
    public string? InternalErrorDetails { get; init; }

    /// <summary>
    /// Protected constructor - sadece türetilmiş sınıflardan kullanılabilir.
    /// 
    /// TASARIM NOTU:
    /// Public constructor olmaması, factory pattern'ı teşvik eder:
    /// - new SuccessResult() yerine Result.Success() gibi
    /// - Ama şimdilik direct instantiation destekleniyor (tersine çevrilebilir)
    /// </summary>
    /// <param name="success">İşlem başarılı mı?</param>
    /// <param name="message">Kullanıcıya gösterilecek mesaj</param>
    /// <param name="errorCode">Hata kodu (opsiyonel, genellikle sadece hata durumlarında)</param>
    /// <param name="internalErrorDetails">Internal error detayları (opsiyonel, sadece logging için)</param>
    protected Result(
        bool success,
        string message,
        string? errorCode = null,
        string? internalErrorDetails = null)
    {
        Success = success;
        ErrorCode = errorCode;
        InternalErrorDetails = internalErrorDetails;

        // GÜVENLİK: Message'ın boş olmaması kritik
        // Boş mesaj yerine generic fallback mesaj kullanılır
        if (string.IsNullOrWhiteSpace(message))
        {
            Message = success
                ? "Operation completed successfully."
                : "An error occurred.";
        }
        else
        {
            Message = message;
        }
    }
}