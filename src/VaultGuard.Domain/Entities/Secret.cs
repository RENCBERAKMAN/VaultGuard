using System;

namespace VaultGuard.Domain.Entities;

/// <summary>
/// Þifrelenmiþ hassas veriyi temsil eden core entity.
/// Sealed olarak tanýmlanmýþtýr çünkü iþ kurallarýmýzý korumak istiyoruz.
/// Geniþletme ihtiyacý durumunda kalýtým yerine composition pattern kullanýlacaktýr.
/// </summary>
public sealed class Secret
{
    /// <summary>
    /// Benzersiz tanýmlayýcý (Primary Key).
    /// init kullanýlarak oluþturulduktan sonra deðiþtirilemez hale getirilmiþtir.
    /// Guid tercih edilmiþtir çünkü distributed sistemlerde çakýþma riski yoktur.
    /// </summary>
    public Guid Id { get; init; }

    /// <summary>
    /// Kullanýcýnýn bu secret'a verdiði anlamlý isim.
    /// Örnek: "Gmail Þifrem", "AWS API Key", "Banka Kartý PIN"
    /// Maksimum uzunluk: 200 karakter (Infrastructure'da validation yapýlacak)
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// AES-256 algoritmasý ile þifrelenmiþ ham veri.
    /// byte[] kullanýlmasýnýn nedenleri:
    /// 1. Þifreleme bit seviyesinde bir iþlemdir
    /// 2. String encoding (UTF-8, ASCII) hatalarý engellenir
    /// 3. Binary data'yý doðrudan saklayabiliriz
    /// NOT: Asla plain text olarak saklanmaz!
    /// </summary>
    public byte[] EncryptedData { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Initialization Vector (Baþlatma Vektörü).
    /// Her þifreleme iþleminde rastgele üretilir ve EncryptedData ile birlikte saklanýr.
    /// IV'nin amacý: Ayný plain text'i iki kez þifrelediðinizde farklý sonuçlar elde etmek.
    /// Güvenlik notu: IV'nin gizli kalmasý gerekmez, ama benzersiz olmasý ZORUNLUDUR.
    /// AES-256 için IV boyutu: 16 byte (128 bit)
    /// </summary>
    public byte[] IV { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Bu secret'ýn sahibi olan kullanýcýnýn ID'si.
    /// Navigation property yerine sadece ID kullanýlmasýnýn nedeni:
    /// - Domain katmanýný saf tutmak (EF Core baðýmlýlýðýndan kaçýnmak)
    /// - Aggregate boundary'leri net tutmak
    /// Ýliþki: Infrastructure katmanýnda Foreign Key olarak tanýmlanacak
    /// </summary>
    public Guid OwnerId { get; set; }

    /// <summary>
    /// Secret'ýn sisteme eklendiði tarih ve saat (UTC).
    /// init kullanýlarak oluþturulduktan sonra deðiþtirilemez.
    /// Audit trail için kritik öneme sahiptir.
    /// </summary>
    public DateTime CreatedAt { get; init; }

    /// <summary>
    /// Secret'a en son eriþilme zamaný (UTC).
    /// Nullable olmasýnýn nedeni: Ýlk oluþturulduðunda henüz eriþilmemiþtir.
    /// Kullaným alanlarý:
    /// 1. Compliance raporlarý (GDPR, SOC2)
    /// 2. Kullanýlmayan secret'larýn temizlenmesi
    /// 3. Þüpheli aktivite tespiti (anormal eriþim patternleri)
    /// </summary>
    public DateTime? LastAccessedAt { get; set; }

    /// <summary>
    /// Soft delete bayraðý (yumuþak silme).
    /// true ise secret "silinmiþ" olarak iþaretlenir ancak veritabanýndan fiziksel olarak silinmez.
    /// Kullaným senaryolarý:
    /// - GDPR uyumluluðu (kullanýcý verilerini geri yükleme hakký)
    /// - Yanlýþlýkla silme durumlarýnda kurtarma
    /// - Compliance gereksinimleri (30 gün saklama politikasý)
    /// </summary>
    public bool IsDeleted { get; set; } = false;

    /// <summary>
    /// Secret'ýn silindiði tarih ve saat (UTC).
    /// Nullable olmasýnýn nedeni: Aktif secret'lar için null olacak.
    /// Kullaným alanlarý:
    /// - Saklama politikasý (30 gün sonra hard delete)
    /// - Audit raporlarý
    /// - Kurtarma iþlemleri için zaman damgasý
    /// </summary>
    public DateTime? DeletedAt { get; set; }

    // ============================================================================
    // CONSTRUCTOR
    // ============================================================================

    /// <summary>
    /// Private parameterless constructor.
    /// EF Core tarafýndan entity'leri veritabanýndan yüklerken kullanýlýr.
    /// Ýþ mantýðýnda kullanýlmamalýdýr; bunun yerine static factory method kullanýlýr.
    /// </summary>
    private Secret()
    {
        // EF Core için gerekli
    }

    /// <summary>
    /// Secret oluþturmak için static factory method.
    /// Bu pattern kullanýlmasýnýn nedenleri:
    /// 1. Validation logic'i merkezi bir yerde toplanýr
    /// 2. Invalid state'te obje oluþturulmasý engellenir
    /// 3. Constructor overload kargaþasý önlenir
    /// </summary>
    /// <param name="name">Secret'ýn kullanýcý dostu adý</param>
    /// <param name="encryptedData">AES-256 ile þifrelenmiþ veri</param>
    /// <param name="iv">Þifreleme için kullanýlan IV</param>
    /// <param name="ownerId">Secret'ýn sahibi olan kullanýcý ID</param>
    /// <returns>Yeni Secret instance'ý</returns>
    /// <exception cref="ArgumentException">Parametreler geçersizse fýrlatýlýr</exception>
    public static Secret Create(
        string name,
        byte[] encryptedData,
        byte[] iv,
        Guid ownerId)
    {
        // Domain-level validation (iþ kurallarý)
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Secret name cannot be empty.", nameof(name));

        if (encryptedData == null || encryptedData.Length == 0)
            throw new ArgumentException("Encrypted data cannot be empty.", nameof(encryptedData));

        if (iv == null || iv.Length != 16) // AES-256 IV size = 16 bytes
            throw new ArgumentException("IV must be exactly 16 bytes for AES-256.", nameof(iv));

        if (ownerId == Guid.Empty)
            throw new ArgumentException("Owner ID cannot be empty.", nameof(ownerId));

        return new Secret
        {
            Id = Guid.NewGuid(),
            Name = name.Trim(),
            EncryptedData = encryptedData,
            IV = iv,
            OwnerId = ownerId,
            CreatedAt = DateTime.UtcNow,
            LastAccessedAt = null,
            IsDeleted = false,
            DeletedAt = null
        };
    }

    // ============================================================================
    // BUSINESS METHODS
    // ============================================================================

    /// <summary>
    /// Secret'a eriþildiðini kaydet.
    /// Bu method her Get/Decrypt iþleminde çaðrýlmalýdýr.
    /// Kullaným: auditService.LogAccess(secret.MarkAsAccessed());
    /// </summary>
    public void MarkAsAccessed()
    {
        LastAccessedAt = DateTime.UtcNow;
    }

    /// <summary>
    /// Secret'ýn adýný güncelle.
    /// Domain event tetiklemek için kullanýlabilir (ileride).
    /// </summary>
    /// <param name="newName">Yeni secret adý</param>
    public void UpdateName(string newName)
    {
        if (string.IsNullOrWhiteSpace(newName))
            throw new ArgumentException("Secret name cannot be empty.", nameof(newName));

        Name = newName.Trim();
    }

    /// <summary>
    /// Secret'ýn þifrelenmiþ verisini yeniden þifrele (key rotation senaryosu).
    /// Key rotation iþlemi sýrasýnda bu method kullanýlýr.
    /// </summary>
    /// <param name="newEncryptedData">Yeni þifrelenmiþ veri</param>
    /// <param name="newIV">Yeni IV</param>
    public void ReEncrypt(byte[] newEncryptedData, byte[] newIV)
    {
        if (newEncryptedData == null || newEncryptedData.Length == 0)
            throw new ArgumentException("Encrypted data cannot be empty.", nameof(newEncryptedData));

        if (newIV == null || newIV.Length != 16)
            throw new ArgumentException("IV must be exactly 16 bytes.", nameof(newIV));

        EncryptedData = newEncryptedData;
        IV = newIV;
    }

    /// <summary>
    /// Secret'ý soft delete ile iþaretle.
    /// Fiziksel olarak veritabanýndan silinmez, sadece IsDeleted = true olur.
    /// </summary>
    public void MarkAsDeleted()
    {
        IsDeleted = true;
        DeletedAt = DateTime.UtcNow;

        // TODO: Domain Event - SecretDeletedEvent
    }

    /// <summary>
    /// Soft delete edilmiþ secret'ý geri yükle.
    /// </summary>
    public void Restore()
    {
        IsDeleted = false;
        DeletedAt = null;

        // TODO: Domain Event - SecretRestoredEvent
    }
}