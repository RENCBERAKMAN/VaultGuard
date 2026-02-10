namespace VaultGuard.Domain.Common.Results;

/// <summary>
/// Veri döndüren işlemler için abstract base class.
/// Generic type parameter ile strongly-typed data access sağlar.
/// 
/// TASARIM KARARLARI:
/// - Result'tan inherit eder → Code reuse, polymorphism
/// - Generic type parameter (T) → Compile-time type safety
/// - Covariance (out T değil, mutable property olduğu için) → Flexibility
/// - Protected constructor → Controlled instantiation
/// 
/// GÜVENLİK:
/// Base Result'tan tüm güvenlik özelliklerini miras alır:
/// - Message sanitization
/// - Exception detail hiding
/// - No stack trace exposure
/// 
/// PERFORMANS:
/// - Generic specialization → JIT optimization
/// - No boxing for value types
/// - Minimal overhead (1 extra field, ~8 bytes)
/// 
/// KULLANIM:
/// Bu sınıf doğrudan instantiate edilmez. Bunun yerine:
/// - SuccessDataResult&lt;T&gt; (başarılı işlem, data var)
/// - ErrorDataResult&lt;T&gt; (hatalı işlem, data nullable)
/// türetilmiş sınıfları kullanılır.
/// </summary>
/// <typeparam name="T">
/// Döndürülecek veri tipi.
/// 
/// Type Constraints:
/// - Şu an için constraint yok (maximum flexibility)
/// - İleride class, struct, new() gibi constraints eklenebilir
/// 
/// Yaygın Kullanımlar:
/// - Entity types: DataResult&lt;User&gt;, DataResult&lt;Order&gt;
/// - Collections: DataResult&lt;List&lt;Product&gt;&gt;
/// - Value types: DataResult&lt;int&gt;, DataResult&lt;decimal&gt;
/// - DTOs: DataResult&lt;UserDto&gt;
/// - Tuples: DataResult&lt;(int Count, decimal Total)&gt;
/// </typeparam>
public abstract class DataResult<T> : Result, IDataResult<T>
{
    /// <inheritdoc/>
    /// <remarks>
    /// Nullable property:
    /// - Reference type'lar için null olabilir
    /// - Value type'lar için Nullable&lt;T&gt; kullanılabilir
    /// - Success = false durumunda genellikle null veya default
    /// - Success = true durumunda geçerli veri beklenir
    /// 
    /// PERFORMANS NOTU:
    /// - Large object heap (LOH) consideration for big collections
    /// - Lazy loading pattern kullanılabilir (ileride)
    /// </remarks>
    public T? Data { get; init; }

    /// <summary>
    /// Protected constructor - sadece türetilmiş sınıflardan kullanılabilir.
    /// 
    /// DAVRANIŞSAL KURALLAR:
    /// 
    /// 1. Başarılı İşlem:
    ///    - success = true
    ///    - data = valid value (not null for reference types, ideally)
    ///    - message = "Operation completed successfully."
    ///    - errorCode = null
    /// 
    /// 2. Başarısız İşlem:
    ///    - success = false
    ///    - data = null veya default(T)
    ///    - message = user-friendly error message
    ///    - errorCode = standardized error code
    /// 
    /// 3. Partial Success (rare):
    ///    - success = false
    ///    - data = fallback data (örn: empty list, default configuration)
    ///    - message = warning message
    ///    - errorCode = warning code
    /// </summary>
    /// <param name="success">İşlem başarılı mı?</param>
    /// <param name="data">Döndürülecek veri (nullable)</param>
    /// <param name="message">Kullanıcıya gösterilecek mesaj</param>
    /// <param name="errorCode">Hata kodu (opsiyonel)</param>
    /// <param name="internalErrorDetails">Internal error detayları (opsiyonel)</param>
    protected DataResult(
        bool success,
        T? data,
        string message,
        string? errorCode = null,
        string? internalErrorDetails = null)
        : base(success, message, errorCode, internalErrorDetails)
    {
        Data = data;
    }
}