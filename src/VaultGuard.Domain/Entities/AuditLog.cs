using System;
using System.Linq;

namespace VaultGuard.Domain.Entities;

/// <summary>
/// Sistemdeki tüm kritik işlemlerin değiştirilemez (immutable) denetim kaydını tutar.
/// Sealed olarak tanımlanmıştır çünkü audit log'ların domain kuralları kesinlikle korunmalıdır.
/// Bu entity GDPR, SOC2, HIPAA gibi compliance standartları için kritik öneme sahiptir.
/// 
/// Immutability prensibi: Bir kez oluşturulduktan sonra hiçbir özellik değiştirilemez.
/// Bu sayede denetim kayıtlarının güvenilirliği garanti edilir.
/// </summary>
public sealed class AuditLog
{
    /// <summary>
    /// Benzersiz denetim kaydı kimliği (Primary Key).
    /// init ile oluşturulduktan sonra değiştirilemez.
    /// Distributed sistemlerde çakışma riski olmayan Guid tercih edilmiştir.
    /// </summary>
    public Guid Id { get; init; }

    /// <summary>
    /// İşlemi gerçekleştiren kullanıcının kimliği.
    /// Foreign Key: User.Id
    /// NOT: System tarafından yapılan işlemler için özel bir UserId kullanılabilir.
    /// Örnek: Guid.Empty veya önceden tanımlanmış bir "System User" ID'si.
    /// </summary>
    public Guid UserId { get; init; }

    /// <summary>
    /// Gerçekleştirilen işlemin türü.
    /// Standart format: "{EntityName}_{OperationType}"
    /// 
    /// Örnekler:
    /// - "Secret_Created" - Yeni secret oluşturuldu
    /// - "Secret_Viewed" - Secret görüntülendi
    /// - "Secret_Deleted" - Secret silindi
    /// - "User_Login_Success" - Başarılı giriş
    /// - "User_Login_Failed" - Başarısız giriş
    /// - "User_Password_Changed" - Şifre değiştirildi
    /// - "User_Role_Changed" - Rol değiştirildi
    /// - "System_Backup_Completed" - Yedekleme tamamlandı
    /// 
    /// Maksimum uzunluk: 100 karakter
    /// Format: Snake_Case (tutarlılık için)
    /// </summary>
    public string Action { get; init; } = string.Empty;

    /// <summary>
    /// İşlemin yapıldığı entity'nin adı (tablo adı).
    /// 
    /// Geçerli değerler:
    /// - "Secret" - Hassas veri işlemleri
    /// - "User" - Kullanıcı işlemleri
    /// - "AuditLog" - Audit log sorgulama işlemleri
    /// - "System" - Sistem seviyesi işlemler
    /// 
    /// NOT: Bu alan ileride enum'a dönüştürülebilir (EntityType enum).
    /// Maksimum uzunluk: 50 karakter
    /// </summary>
    public string EntityName { get; init; } = string.Empty;

    /// <summary>
    /// İşlemden etkilenen kaydın kimliği (opsiyonel).
    /// Nullable olmasının nedeni: Bazı işlemler belirli bir kayda bağlı olmayabilir.
    /// 
    /// Örnekler:
    /// - Secret görüntülendiğinde: Secret.Id
    /// - Kullanıcı giriş yaptığında: User.Id
    /// - Toplu silme işleminde: null (çünkü birden fazla kayıt etkilenir)
    /// - Sistem yedekleme işleminde: null (genel bir işlem)
    /// </summary>
    public Guid? EntityId { get; init; }

    /// <summary>
    /// İşlemin gerçekleştirildiği tarih ve saat (UTC).
    /// Her zaman UTC kullanılır çünkü:
    /// 1. Timezone karmaşasını önler
    /// 2. Global sistemlerde tutarlılık sağlar
    /// 3. Forensic analiz için standart zaman referansı sağlar
    /// 
    /// init ile oluşturulduktan sonra değiştirilemez.
    /// </summary>
    public DateTime Timestamp { get; init; }

    /// <summary>
    /// İşlemin başlatıldığı IP adresi.
    /// 
    /// Format:
    /// - IPv4: "192.168.1.100"
    /// - IPv6: "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    /// 
    /// Kullanım alanları:
    /// 1. Güvenlik: Anormal lokasyon tespiti
    /// 2. Forensics: Saldırı kaynağı belirleme
    /// 3. Compliance: Erişim kaynağı raporlama
    /// 
    /// NOT: Proxy/Load Balancer kullanımında X-Forwarded-For header'ından alınmalıdır.
    /// Maksimum uzunluk: 45 karakter (IPv6 için)
    /// </summary>
    public string IpAddress { get; init; } = string.Empty;

    /// <summary>
    /// İşlem hakkında ek teknik detaylar (opsiyonel, JSON formatında saklanabilir).
    /// Nullable olmasının nedeni: Her işlem için detay gerekmeyebilir.
    /// 
    /// Kullanım senaryoları:
    /// - Hata detayları (exception message, stack trace)
    /// - İşlem parametreleri (eski değer → yeni değer)
    /// - Request/Response payload (民感 veri HARİÇ!)
    /// - Browser/User-Agent bilgisi
    /// - Geolocation bilgisi
    /// 
    /// Örnek JSON formatı:
    /// {
    ///   "OldValue": "User",
    ///   "NewValue": "Admin",
    ///   "ChangedBy": "system-admin@vaultguard.com",
    ///   "Reason": "Promotion to administrator"
    /// }
    /// 
    /// GÜVENLİK UYARISI: Hassas veri (şifre, secret içeriği vb.) asla Details'e yazılmamalı!
    /// Maksimum uzunluk: 2000 karakter
    /// </summary>
    public string? Details { get; init; }

    // ============================================================================
    // CONSTRUCTOR
    // ============================================================================

    /// <summary>
    /// Private parameterless constructor.
    /// EF Core tarafından audit log'ları veritabanından yüklerken kullanılır.
    /// İş mantığında kullanılmamalıdır; bunun yerine static factory method (Create) kullanılır.
    /// </summary>
    private AuditLog()
    {
        // EF Core için gerekli
    }

    /// <summary>
    /// Yeni bir audit log kaydı oluşturmak için static factory method.
    /// 
    /// Immutability garantisi: Tüm özellikler init ile tanımlandığı için,
    /// oluşturulduktan sonra değiştirilemez.
    /// 
    /// Bu pattern kullanılmasının nedenleri:
    /// 1. Validation logic'i merkezi bir yerde toplanır
    /// 2. Invalid state'te audit log oluşturulması engellenir
    /// 3. Timestamp otomatik olarak UTC'de atanır
    /// 4. Forensic analiz için güvenilir kayıt garantisi
    /// </summary>
    /// <param name="userId">İşlemi yapan kullanıcının ID'si</param>
    /// <param name="action">İşlem türü (örn: "Secret_Viewed")</param>
    /// <param name="entityName">İşlemin yapıldığı entity adı (örn: "Secret")</param>
    /// <param name="ipAddress">İşlemin başlatıldığı IP adresi</param>
    /// <param name="entityId">İşlemden etkilenen kaydın ID'si (opsiyonel)</param>
    /// <param name="details">Ek teknik detaylar (opsiyonel, JSON formatında)</param>
    /// <returns>Yeni AuditLog instance'ı</returns>
    /// <exception cref="ArgumentException">Parametreler geçersizse fırlatılır</exception>
    public static AuditLog Create(
        Guid userId,
        string action,
        string entityName,
        string ipAddress,
        Guid? entityId = null,
        string? details = null)
    {
        // UserId validation
        if (userId == Guid.Empty)
            throw new ArgumentException(
                "User ID cannot be empty. Use a valid user ID or a special system user ID.",
                nameof(userId));

        // Action validation
        if (string.IsNullOrWhiteSpace(action))
            throw new ArgumentException("Action cannot be empty.", nameof(action));

        var trimmedAction = action.Trim();

        if (trimmedAction.Length > 100)
            throw new ArgumentException(
                "Action is too long (max 100 characters).",
                nameof(action));

        // Action format kontrolü (opsiyonel ama önerilen)
        if (!trimmedAction.Contains('_'))
            throw new ArgumentException(
                "Action should follow the format: '{EntityName}_{OperationType}' (e.g., 'Secret_Viewed').",
                nameof(action));

        // EntityName validation
        if (string.IsNullOrWhiteSpace(entityName))
            throw new ArgumentException("Entity name cannot be empty.", nameof(entityName));

        var trimmedEntityName = entityName.Trim();

        if (trimmedEntityName.Length > 50)
            throw new ArgumentException(
                "Entity name is too long (max 50 characters).",
                nameof(entityName));

        // EntityName geçerli değerler kontrolü (opsiyonel)
        var validEntityNames = new[] { "Secret", "User", "AuditLog", "System" };
        if (!validEntityNames.Contains(trimmedEntityName, StringComparer.OrdinalIgnoreCase))
            throw new ArgumentException(
                $"Invalid entity name. Valid values: {string.Join(", ", validEntityNames)}",
                nameof(entityName));

        // IpAddress validation
        if (string.IsNullOrWhiteSpace(ipAddress))
            throw new ArgumentException("IP address cannot be empty.", nameof(ipAddress));

        var trimmedIpAddress = ipAddress.Trim();

        if (trimmedIpAddress.Length > 45)
            throw new ArgumentException(
                "IP address is too long (max 45 characters for IPv6).",
                nameof(ipAddress));

        // Basit IP format kontrolü (detaylı regex Infrastructure katmanında olabilir)
        var hasValidIpFormat = trimmedIpAddress.Contains('.') || trimmedIpAddress.Contains(':');
        if (!hasValidIpFormat)
            throw new ArgumentException(
                "Invalid IP address format. Expected IPv4 or IPv6.",
                nameof(ipAddress));

        // Details validation (opsiyonel ama uzunluk kontrolü önemli)
        if (details != null && details.Length > 2000)
            throw new ArgumentException(
                "Details are too long (max 2000 characters).",
                nameof(details));

        // GÜVENLİK KONTROLÜ: Details'de hassas kelime kontrolü
        if (details != null)
        {
            var sensitiveKeywords = new[] { "password", "secret", "token", "key" };
            var lowerDetails = details.ToLower();

            foreach (var keyword in sensitiveKeywords)
            {
                if (lowerDetails.Contains(keyword))
                    throw new ArgumentException(
                        $"Details contain sensitive keyword '{keyword}'. Never log sensitive data!",
                        nameof(details));
            }
        }

        return new AuditLog
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            Action = trimmedAction,
            EntityName = trimmedEntityName,
            EntityId = entityId,
            Timestamp = DateTime.UtcNow, // Her zaman UTC!
            IpAddress = trimmedIpAddress,
            Details = details?.Trim()
        };
    }

    // ============================================================================
    // QUERY HELPER METHODS (Değişiklik yapmıyor, sadece sorgulamaya yardımcı)
    // ============================================================================

    /// <summary>
    /// Bu audit log kaydının başarılı bir işlemi temsil edip etmediğini kontrol eder.
    /// Başarılı işlemler genellikle "Success" kelimesini içerir veya "Failed" içermez.
    /// </summary>
    /// <returns>Başarılı işlem ise true, değilse false</returns>
    public bool IsSuccessfulOperation()
    {
        return !Action.Contains("Failed", StringComparison.OrdinalIgnoreCase) &&
               !Action.Contains("Error", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Bu audit log kaydının güvenlik ile ilgili bir işlemi temsil edip etmediğini kontrol eder.
    /// Güvenlik işlemleri: Login, Password change, Role change vb.
    /// </summary>
    /// <returns>Güvenlik işlemi ise true, değilse false</returns>
    public bool IsSecurityRelated()
    {
        var securityKeywords = new[] { "Login", "Password", "Role", "Permission", "Access" };
        return securityKeywords.Any(keyword =>
            Action.Contains(keyword, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Bu audit log kaydının belirli bir entity'ye ait olup olmadığını kontrol eder.
    /// </summary>
    /// <param name="entityName">Kontrol edilecek entity adı</param>
    /// <returns>Belirtilen entity'ye aitse true, değilse false</returns>
    public bool BelongsToEntity(string entityName)
    {
        if (string.IsNullOrWhiteSpace(entityName))
            return false;

        return EntityName.Equals(entityName.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Bu audit log kaydının belirli bir kullanıcıya ait olup olmadığını kontrol eder.
    /// </summary>
    /// <param name="userId">Kontrol edilecek kullanıcı ID'si</param>
    /// <returns>Belirtilen kullanıcıya aitse true, değilse false</returns>
    public bool BelongsToUser(Guid userId)
    {
        return UserId == userId;
    }

    /// <summary>
    /// Bu audit log kaydının belirli bir zaman aralığında oluşturulup oluşturulmadığını kontrol eder.
    /// Forensic analiz ve compliance raporlaması için kullanılır.
    /// </summary>
    /// <param name="startDate">Başlangıç tarihi (UTC)</param>
    /// <param name="endDate">Bitiş tarihi (UTC)</param>
    /// <returns>Belirtilen aralıkta ise true, değilse false</returns>
    public bool IsWithinDateRange(DateTime startDate, DateTime endDate)
    {
        return Timestamp >= startDate && Timestamp <= endDate;
    }
}