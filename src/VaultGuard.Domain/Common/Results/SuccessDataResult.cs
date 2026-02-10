namespace VaultGuard.Domain.Common.Results;

/// <summary>
/// Başarılı işlem sonucunu temsil eder (veri döndürür).
/// 
/// KULLANIM SENARYOLARI:
/// 
/// 1. Get İşlemleri:
///    - GetUser(userId) → SuccessDataResult&lt;User&gt;
///    - GetAllProducts() → SuccessDataResult&lt;List&lt;Product&gt;&gt;
/// 
/// 2. Search/Query Sonuçları:
///    - SearchUsers(query) → SuccessDataResult&lt;List&lt;User&gt;&gt;
///    - GetPagedOrders(pageIndex, pageSize) → SuccessDataResult&lt;PagedResult&lt;Order&gt;&gt;
/// 
/// 3. Hesaplama Sonuçları:
///    - CalculateTotal(items) → SuccessDataResult&lt;decimal&gt;
///    - GetStatistics() → SuccessDataResult&lt;DashboardStats&gt;
/// 
/// 4. Transformation İşlemleri:
///    - DecryptSecret(secretId) → SuccessDataResult&lt;string&gt;
///    - ExportToExcel(data) → SuccessDataResult&lt;byte[]&gt;
/// 
/// PERFORMANS:
/// - Sealed class → JIT devirtualization
/// - Generic specialization → Type-specific optimization
/// - No boxing for value types
/// - Memory: Base class overhead + sizeof(T) for value types, pointer size for reference types
/// 
/// THREAD SAFETY:
/// Immutable olduğu için thread-safe.
/// Data property'si mutable ise, Data'nın kendisi thread-safe olmayabilir.
/// 
/// Örnek:
/// <code>
/// public IDataResult&lt;User&gt; GetUser(Guid userId)
/// {
///     var user = _repository.GetById(userId);
///     return new SuccessDataResult&lt;User&gt;(user, "User retrieved successfully.");
/// }
/// </code>
/// </summary>
/// <typeparam name="T">
/// Döndürülecek veri tipi.
/// 
/// NULL SAFETY:
/// - Reference type için T? kullanılmalı (nullable reference types)
/// - Value type için Nullable&lt;T&gt; kullanılmalı
/// - Başarılı işlemde Data null olmamalı (best practice)
/// </typeparam>
public sealed class SuccessDataResult<T> : DataResult<T>
{
    /// <summary>
    /// Sadece veri ile yeni bir başarılı sonuç oluşturur.
    /// Mesaj otomatik olarak "Operation completed successfully." atanır.
    /// 
    /// KULLANIM:
    /// Generic mesajın yeterli olduğu basit Get işlemlerinde kullanılır.
    /// 
    /// Örnek:
    /// <code>
    /// public IDataResult&lt;List&lt;Product&gt;&gt; GetAllProducts()
    /// {
    ///     var products = _repository.GetAll().ToList();
    ///     return new SuccessDataResult&lt;List&lt;Product&gt;&gt;(products);
    /// }
    /// </code>
    /// 
    /// PERFORMANS NOTU:
    /// Constructor parameter'ı by-value geçilir (value type için copy, reference type için pointer).
    /// Large value type'lar için ref keyword kullanılabilir (ama şimdilik gerek yok).
    /// </summary>
    /// <param name="data">
    /// Döndürülecek veri.
    /// 
    /// NULL KONTROLÜ:
    /// Constructor null kontrolü yapmaz (performance).
    /// Caller'ın sorumluluğunda başarılı işlemde valid data göndermek.
    /// Null data gerekliyse ErrorDataResult kullanılmalı.
    /// </param>
    public SuccessDataResult(T data)
        : base(true, data, "Operation completed successfully.")
    {
    }

    /// <summary>
    /// Veri ve özel mesaj ile yeni bir başarılı sonuç oluşturur.
    /// 
    /// KULLANIM:
    /// Kullanıcıya anlamlı feedback vermek istendiğinde kullanılır.
    /// 
    /// MESAJ ÖNERİLERİ:
    /// ✅ "User retrieved successfully."
    /// ✅ "Products loaded successfully."
    /// ✅ "Search completed. Found {count} results."
    /// ✅ "Secret decrypted successfully."
    /// 
    /// ❌ "Success" (too generic)
    /// ❌ "Data: {data.ToString()}" (data leak risk)
    /// ❌ "SELECT * FROM Users WHERE Id=123 returned 1 row" (SQL injection info leak)
    /// 
    /// Örnek:
    /// <code>
    /// public IDataResult&lt;User&gt; GetUser(Guid userId)
    /// {
    ///     var user = _repository.GetById(userId);
    ///     return new SuccessDataResult&lt;User&gt;(user, "User retrieved successfully.");
    /// }
    /// 
    /// public IDataResult&lt;List&lt;Product&gt;&gt; SearchProducts(string query)
    /// {
    ///     var products = _repository.Search(query).ToList();
    ///     return new SuccessDataResult&lt;List&lt;Product&gt;&gt;(
    ///         products,
    ///         $"Search completed. Found {products.Count} products.");
    /// }
    /// </code>
    /// 
    /// GÜVENLİK UYARISI:
    /// Message içinde Data'dan bilgi göstermek istiyorsanız:
    /// ✅ Sanitize et: $"Found {data.Count} items"
    /// ❌ Raw data: $"User: {user.Email}" (privacy leak)
    /// </summary>
    /// <param name="data">Döndürülecek veri</param>
    /// <param name="message">Başarı mesajı</param>
    public SuccessDataResult(T data, string message)
        : base(true, data, message)
    {
    }
}