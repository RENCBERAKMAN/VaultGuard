namespace VaultGuard.Domain.Common.Results;

/// <summary>
/// Veri döndüren işlem sonucunu temsil eden interface.
/// Generic type parameter ile compile-time type safety sağlar.
/// 
/// GÜVENLİK:
/// - Başarısız işlemlerde Data null veya default(T) olabilir
/// - Data property'si API response'larına güvenle eklenebilir
/// - Hassas verilerin maskelenmesi Application katmanında yapılmalıdır
/// 
/// PERFORMANS:
/// - Covariance (out T) kullanarak type safety sağlanır
/// - Boxing/unboxing overhead'i yoktur
/// - Value type'lar için optimal performance
/// </summary>
/// <typeparam name="T">
/// Döndürülecek veri tipi.
/// 
/// Örnekler:
/// - IDataResult&lt;User&gt; - Tekil entity
/// - IDataResult&lt;List&lt;Product&gt;&gt; - Collection
/// - IDataResult&lt;int&gt; - Value type
/// - IDataResult&lt;bool&gt; - Boolean result
/// - IDataResult&lt;PagedResult&lt;Order&gt;&gt; - Sayfalanmış veri
/// </typeparam>
public interface IDataResult<out T> : IResult
{
    /// <summary>
    /// İşlem sonucunda döndürülen veri.
    /// 
    /// Davranış Senaryoları:
    /// 
    /// 1. Başarılı İşlem (Success = true):
    ///    - Data null olmayan geçerli veri içerir
    ///    - Örnek: GetUser(id) → User entity
    /// 
    /// 2. Başarısız İşlem (Success = false):
    ///    - Data null veya default(T) olabilir
    ///    - Örnek: GetUser(invalidId) → null
    /// 
    /// 3. Partial Success:
    ///    - Success = false ama Data fallback değeri içerebilir
    ///    - Örnek: Cache miss → default list döndür
    /// 
    /// GÜVENLİK NOTU:
    /// Hassas verilerin (şifreler, token'lar) Data içinde olması durumunda,
    /// API response mapping katmanında maskeleme yapılmalıdır.
    /// 
    /// PERFORMANS NOTU:
    /// - Reference type'lar için null check maliyetlidir
    /// - Value type'lar için HasValue pattern kullanılabilir
    /// - Collection'lar için Count kontrolü yapılmalıdır
    /// </summary>
    T? Data { get; }
}