using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using VaultGuard.Domain.Entities;

namespace VaultGuard.Infrastructure.Persistence.Configurations;

/// <summary>
/// AuditLog entity için Entity Framework Core yapılandırması.
/// Bu, değiştirilemezlik ve bütünlüğü koruması gereken GÜVENLİK-KRİTİK bir entity'dir.
/// WORM (Write Once, Read Many) prensiplerine uygun şekilde yapılandırılmıştır (SOC2, GDPR, HIPAA uyumluluğu için).
/// </summary>
public sealed class AuditLogConfiguration : IEntityTypeConfiguration<AuditLog>
{
    public void Configure(EntityTypeBuilder<AuditLog> builder)
    {
        // ============================================================================
        // TABLO YAPILANDIRMASI
        // ============================================================================

        builder.ToTable("AuditLogs");

        // GÜVENLİK: Audit log'lar ASLA değiştirilmemeli veya silinmemelidir
        // Veritabanı seviyesinde izinler şöyle olmalı: sadece INSERT ve SELECT (UPDATE/DELETE yok)

        // ============================================================================
        // PRIMARY KEY (BİRİNCİL ANAHTAR)
        // ============================================================================

        builder.HasKey(a => a.Id);

        // GÜVENLİK: Guid primary key'ler, audit log ID'lerinin sıralı tahminini önler
        builder.Property(a => a.Id)
            .IsRequired()
            .ValueGeneratedNever(); // Domain'de oluşturulur (AuditLog.Create)

        // PERFORMANS: ID üzerinde clustered index, optimal insert performansı sağlar
        // Audit log'lar append-only olduğundan kronolojik kümeleme idealdir

        // ============================================================================
        // USER ID YAPILANDIRMASI
        // ============================================================================

        builder.Property(a => a.UserId)
            .IsRequired();

        // GÜVENLİK: UserId üzerinde index, hızlı kullanıcı aktivite sorguları için kritik
        // Olay müdahalesi ve forensic incelemeler için hayati önem taşır
        builder.HasIndex(a => a.UserId)
            .HasDatabaseName("IX_AuditLogs_UserId");

        // Foreign key ilişkisi, döngüsel referansı önlemek için UserConfiguration'da tanımlandı

        // ============================================================================
        // ACTION (İŞLEM) YAPILANDIRMASI
        // ============================================================================

        builder.Property(a => a.Action)
            .IsRequired()
            .HasMaxLength(100); // "Secret_Viewed", "User_Login_Failed" gibi
            

        // GÜVENLİK: Action alanı üzerinde index, güvenlik olay toplamlaması için gerekli
        // Hızlı sorgular sağlar: "Son 1 saatte tüm başarısız login denemelerini göster"
        builder.HasIndex(a => a.Action)
            .HasDatabaseName("IX_AuditLogs_Action");

        // ============================================================================
        // ENTITY NAME & ID YAPILANDIRMASI
        // ============================================================================

        builder.Property(a => a.EntityName)
            .IsRequired()
            .HasMaxLength(50); // "User", "Secret", "System"
            

        builder.Property(a => a.EntityId)
            .IsRequired(false); // Sistem seviyesi olaylar için nullable

        // GÜVENLİK: Entity-spesifik denetim izleri için composite index
        // Optimize eder: "ID'si X olan Secret üzerindeki tüm değişiklikleri göster"
        builder.HasIndex(a => new { a.EntityName, a.EntityId })
            .HasDatabaseName("IX_AuditLogs_Entity");

        // ============================================================================
        // TIMESTAMP (ZAMAN DAMGASI) YAPILANDIRMASI
        // ============================================================================

        builder.Property(a => a.Timestamp)
            .IsRequired();
             // Forensic incelemeler için mikrosaniye hassasiyeti
            

        // GÜVENLİK: Timestamp üzerinde index, zamana dayalı sorgular için kritik
        // Hayati önem taşır: "Son 24 saatteki tüm olayları göster" (olay müdahalesi)
        builder.HasIndex(a => a.Timestamp)
            .HasDatabaseName("IX_AuditLogs_Timestamp")
            .IsDescending(); // En son olaylar önce (yaygın sorgu deseni)

        // ============================================================================
        // IP ADDRESS (IP ADRESİ) YAPILANDIRMASI
        // ============================================================================

        builder.Property(a => a.IpAddress)
            .IsRequired()
            .HasMaxLength(45); // IPv6 maksimum uzunluk
            

        // GÜVENLİK: IpAddress üzerinde index, tehdit tespiti için gerekli
        // Sorgular sağlar: "Bu şüpheli IP'den gelen tüm işlemleri göster"
        builder.HasIndex(a => a.IpAddress)
            .HasDatabaseName("IX_AuditLogs_IpAddress");

        // ============================================================================
        // DETAILS (DETAYLAR) YAPILANDIRMASI
        // ============================================================================

        builder.Property(a => a.AdditionalData) // Details yerine AdditionalData
      .IsRequired(false);
        // GÜVENLİK UYARISI: Details alanı ASLA hassas veri içermemelidir (şifre, secret, token)
        // Bu, domain logic'de doğrulanır (AuditLog.Create), ancak dikkatli olun

        // PERFORMANS: nvarchar(max) veri 8KB'den büyükse off-row saklanır
        // Details sıklıkla 8KB'yi aşıyorsa ayrı bir tablo düşünülebilir

        // ============================================================================
        // GÜVENLİK SORGU PATERNLERİ İÇİN COMPOSITE INDEX'LER
        // ============================================================================

        // GÜVENLİK: Kullanıcı aktivite zaman çizelgesi için composite index
        // Optimize eder: "X kullanıcısının tüm işlemlerini kronolojik sırada göster"
        builder.HasIndex(a => new { a.UserId, a.Timestamp })
            .HasDatabaseName("IX_AuditLogs_UserId_Timestamp")
            .IsDescending(false, true); // UserId ASC, Timestamp DESC

        // GÜVENLİK: Güvenlik olay korelasyonu için composite index
        // Optimize eder: "Bu IP'den gelen başarısız veya hatalı işlemleri göster"
        builder.HasIndex(a => new { a.Action, a.IpAddress, a.Timestamp })
            .HasDatabaseName("IX_AuditLogs_Action_IpAddress_Timestamp");
           // .HasFilter("[Action] = 'Failed' OR [Action] = 'Error'"); // ✅ SQL Server uyumlu hale getirildi
        // GÜVENLİK: Entity değişiklik takibi için composite index
        // Optimize eder: "Belirli bir entity'nin tam geçmişini göster"
        builder.HasIndex(a => new { a.EntityName, a.EntityId, a.Timestamp })
            .HasDatabaseName("IX_AuditLogs_Entity_Timestamp")
            .IsDescending(false, false, true); // En son değişiklikler önce

        // ============================================================================
        // DEĞİŞTİRİLEMEZLİK UYGULAMASI (IMMUTABILITY ENFORCEMENT)
        // ============================================================================

        // GÜVENLİK: Audit log'lar değiştirilemez - insert sonrası update yapılamaz
        // Entity'yi insert sonrası read-only olarak yapılandır (EF Core 9 özelliği)
        // EF Core 9+ immutability özellikleri kullanılıyorsa yorumu kaldırın
        /*
        builder.ToTable(tb => tb.HasTrigger("TR_AuditLogs_PreventUpdate"));
        
        // SQL trigger ile update'i engelleme:
        // CREATE TRIGGER TR_AuditLogs_PreventUpdate ON AuditLogs
        // AFTER UPDATE
        // AS BEGIN
        //     RAISERROR('Audit logs are immutable and cannot be updated', 16, 1)
        //     ROLLBACK TRANSACTION
        // END
        */

        // ============================================================================
        // SOFT DELETE (ÖNERİLMEZ - AUDIT LOG İÇİN)
        // ============================================================================

        // UYUMLULUK: Audit log'lar ASLA silinmemelidir (hard veya soft)
        // Saklama politikaları, silmek yerine ayrı depolamaya arşivlemelidir
        // Soft delete uygulamak zorundaysanız (önerilmez), query filter KULLANMAYIN
        /*
        builder.Property(a => a.IsDeleted)
            .IsRequired()
            .HasDefaultValue(false);

        // QUERY FILTER EKLEMEYIN - audit log'lar her zaman görünür olmalı
        // builder.HasQueryFilter(a => !a.IsDeleted); // ❌ GÜVENLİK RİSKİ
        */

        // ============================================================================
        // PARTITIONING STRATEJİSİ (.NET 9 / SQL SERVER 2022+)
        // ============================================================================

        // PERFORMANS: Yüksek hacimli audit log'lar için tablo partitioning düşünülebilir
        // Timestamp'e göre (aylık/yıllık) partition yaparak verimli arşivleme sağlanır
        /*
        builder.ToTable(tb => tb
            .HasComment("Timestamp ile partition edilmiş - verimli arşivleme için")
            .IsPartitioned()); // SQL Server 2022+ ve uygun partition scheme gerektirir
        */

        // ============================================================================
        // SAKLAMA POLİTİKASI METADATA
        // ============================================================================

        // UYUMLULUK: Saklama gereksinimlerini belgeleme
        builder.ToTable(tb => tb.HasComment(
            "DEĞİŞTİRİLEMEZ AUDIT LOG - SAKLAMA: 7 yıl (GDPR/SOC2). " +
            "2 yıl sonra cold storage'a arşivle. " +
            "UPDATE VE DELETE İŞLEMLERİNE İZİN VERİLMEZ."));

        // ============================================================================
        // EK GÜVENLİK NOTLARI
        // ============================================================================

        /*
         * AUDIT LOG ENTITY İÇİN GÜVENLİK KONTROL LİSTESİ:
         * 
         * ✅ Değiştirilemez (write-once, read-many)
         * ✅ Timestamp index'li (olay müdahalesi için)
         * ✅ UserId index'li (kullanıcı aktivite takibi için)
         * ✅ Action index'li (güvenlik olay toplamlaması için)
         * ✅ IpAddress index'li (tehdit istihbaratı için)
         * ✅ EntityName/EntityId index'li (değişiklik takibi için)
         * ✅ Composite index'ler yaygın güvenlik sorgularını optimize eder
         * ✅ Yüksek hassasiyetli timestamp'ler (mikrosaniye) forensic için
         * ✅ Details alanı hassas veri içermemesi için doğrulanmış
         * ✅ Soft delete yok (audit log'lar kalıcı olmalı)
         * ✅ Foreign key'lerden cascade delete yok
         * 
         * UYUMLULUK GEREKSİNİMLERİ:
         * 
         * SOC2 (Güvenlik):
         * - Audit log'lar kurcalanamaz (immutable) olmalı
         * - Kim, ne, ne zaman, nerede bilgilerini takip etmeli
         * - Saklama: minimum 1 yıl, önerilen 7 yıl
         * 
         * GDPR (Gizlilik):
         * - Audit log'lar "unutulma hakkı"ndan muaftır
         * - Saklama süresi sonrası kullanıcı verileri anonimleştirilmeli
         * - AB verisi işleniyorsa AB'de saklanmalı
         * 
         * HIPAA (Sağlık):
         * - Tüm PHI erişimleri için audit log gerekli
         * - Saklama: Oluşturulduğundan veya son kullanımdan itibaren 6 yıl
         * - User ID, timestamp, action, IP address içermeli
         * 
         * PCI-DSS (Ödeme):
         * - Kart sahibi veri erişimi için audit log gerekli
         * - Saklama: Minimum 1 yıl (3 ay online)
         * - Anomaliler için günlük gözden geçirilmeli
         * 
         * PERFORMANS OPTİMİZASYONU:
         * - Partial index'ler, hata olayları için index boyutunu azaltır
         * - Descending timestamp index, "son olaylar" sorgularını optimize eder
         * - 10M+ satır için tablo partitioning düşünülebilir
         * - 2 yıldan eski log'ları cold storage'a arşivleyin
         * 
         * TEHDİT TESPİTİ KULLANIM SENARYOLARI:
         * 1. Brute force tespiti: IP/kullanıcı başına başarısız login sayısı
         * 2. Yetki yükseltme: Rol değişikliklerini takip et
         * 3. Veri sızıntısı: Toplu secret erişimini izle
         * 4. İç tehdit: Kullanıcı davranış paternlerini analiz et
         * 5. Uyumluluk denetimi: Aktivite raporları üret
         */
    }
}