namespace VaultGuard.Domain.Common.Results;

/// <summary>
/// Başarılı işlem sonucunu temsil eder (veri döndürmez).
/// 
/// KULLANIM SENARYOLARI:
/// 
/// 1. Void İşlemler:
///    - Create, Update, Delete operations
///    - Örnek: DeleteUser(userId) → SuccessResult
/// 
/// 2. Validation Sonuçları:
///    - ValidateEmail(email) → SuccessResult
///    - CheckPermission(userId, resource) → SuccessResult
/// 
/// 3. Fire-and-Forget Operations:
///    - SendEmail(to, subject, body) → SuccessResult
///    - QueueBackgroundJob(jobData) → SuccessResult
/// 
/// 4. Boolean Operasyonlar (Data döndürmeyen):
///    - IsEmailUnique(email) → SuccessResult
///    - CanUserAccessResource(userId, resourceId) → SuccessResult
/// 
/// PERFORMANS:
/// - Sealed class → JIT devirtualization optimization
/// - No additional fields → Minimal memory footprint (~40 bytes total)
/// - Immutable → Thread-safe, can be cached
/// 
/// THREAD SAFETY:
/// SuccessResult instance'ları immutable olduğu için thread-safe'tir.
/// Birden fazla thread aynı instance'ı güvenle okuyabilir.
/// 
/// Örnek:
/// <code>
/// public IResult DeleteUser(Guid userId)
/// {
///     _repository.Delete(userId);
///     return new SuccessResult("User deleted successfully.");
/// }
/// </code>
/// </summary>
public sealed class SuccessResult : Result
{
    /// <summary>
    /// Varsayılan başarı mesajı ile yeni bir başarılı sonuç oluşturur.
    /// 
    /// Varsayılan Mesaj: "Operation completed successfully."
    /// 
    /// KULLANIM:
    /// Generic başarı mesajının yeterli olduğu durumlarda kullanılır.
    /// 
    /// Örnek:
    /// <code>
    /// public IResult MarkAsRead(Guid notificationId)
    /// {
    ///     _repository.Update(notificationId, n => n.IsRead = true);
    ///     return new SuccessResult(); // "Operation completed successfully."
    /// }
    /// </code>
    /// 
    /// PERFORMANS NOTU:
    /// Frequently used message'lar için static instance caching düşünülebilir:
    /// public static readonly SuccessResult DefaultSuccess = new();
    /// (Ama şimdilik over-optimization, gerekirse sonra ekle)
    /// </summary>
    public SuccessResult()
        : base(true, "Operation completed successfully.")
    {
    }

    /// <summary>
    /// Özel mesaj ile yeni bir başarılı sonuç oluşturur.
    /// 
    /// KULLANIM:
    /// Kullanıcıya anlamlı feedback vermek istendiğinde kullanılır.
    /// 
    /// MESAJ ÖNERİLERİ:
    /// ✅ "User created successfully."
    /// ✅ "Password changed successfully."
    /// ✅ "Email verification sent."
    /// ✅ "Secret deleted successfully."
    /// 
    /// ❌ "Success" (too generic)
    /// ❌ "OK" (not user-friendly)
    /// ❌ "User with ID 123 has been created" (too technical)
    /// 
    /// Örnek:
    /// <code>
    /// public IResult CreateUser(CreateUserDto dto)
    /// {
    ///     var user = User.Create(dto.Email, dto.Username, dto.PasswordHash);
    ///     _repository.Add(user);
    ///     return new SuccessResult("User created successfully.");
    /// }
    /// </code>
    /// 
    /// LOCALIZATION NOTU:
    /// Çok dilli uygulamalarda message string yerine resource key kullanılabilir:
    /// return new SuccessResult(_localizer["UserCreatedSuccess"]);
    /// </summary>
    /// <param name="message">
    /// Başarı mesajı.
    /// Null veya boş olması durumunda varsayılan mesaj kullanılır.
    /// </param>
    public SuccessResult(string message)
        : base(true, message)
    {
    }
}