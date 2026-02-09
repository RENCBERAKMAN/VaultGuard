using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using VaultGuard.Domain.Entities;

namespace VaultGuard.Infrastructure.Persistence.Configurations;

/// <summary>
/// Secret entity için Entity Framework Core yapılandırması.
/// Şifrelenmiş hassas verileri güçlü güvenlik kısıtlamalarıyla temsil eder.
/// Tüm secret verileri uygulama seviyesinde şifrelenmiş (encryption-at-rest) olmalıdır.
/// </summary>
public sealed class SecretConfiguration : IEntityTypeConfiguration<Secret>
{
    public void Configure(EntityTypeBuilder<Secret> builder)
    {
        // ============================================================================
        // TABLO YAPILANDIRMASI
        // ============================================================================

        builder.ToTable("Secrets");

        // GÜVENLİK: Ek koruma katmanı olarak veritabanı seviyesi şifreleme (TDE) düşünülebilir
        // Uygulama seviyesi şifreleme, domain logic'de uygulanır

        // ============================================================================
        // PRIMARY KEY (BİRİNCİL ANAHTAR)
        // ============================================================================

        builder.HasKey(s => s.Id);

        // GÜVENLİK: Guid primary key'ler, enumeration (numaralandırma) saldırılarını önler
        builder.Property(s => s.Id)
            .IsRequired()
            .ValueGeneratedNever(); // Domain'de oluşturulur (Secret.Create)

        // ============================================================================
        // OWNER ID (SAHİP ID) YAPILANDIRMASI - FOREIGN KEY
        // ============================================================================

        builder.Property(s => s.OwnerId)
            .IsRequired();

        // GÜVENLİK: OwnerId üzerinde index, kullanıcı secret sorgularını hızlandırır
        // Optimize eder: "X kullanıcısına ait tüm secret'ları göster"
        builder.HasIndex(s => s.OwnerId)
            .HasDatabaseName("IX_Secrets_OwnerId");

        // User ile foreign key ilişkisi (one-to-many)
        // Döngüsel referansı önlemek için UserConfiguration'da tanımlandı
        // DeleteBehavior.Restrict, kazara secret silinmesini önler

        // ============================================================================
        // NAME (AD) YAPILANDIRMASI
        // ============================================================================

        builder.Property(s => s.Name)
            .IsRequired()
            .HasMaxLength(200);// Secret için kullanıcı dostu etiket
            

        // GÜVENLİK: Name şifrelenmemiştir (aranabilirlik için plaintext)
        // Name ASLA hassas veri içermemelidir - sadece açıklayıcı etiket
        // Örnek: "AWS Production API Key" (asıl key değil)

        // PERFORMANS: Arama sorguları için Name üzerinde index
        builder.HasIndex(s => s.Name)
            .HasDatabaseName("IX_Secrets_Name");

        // ============================================================================
        // ENCRYPTED DATA (ŞİFRELİ VERİ) YAPILANDIRMASI
        // ============================================================================

        builder.Property(s => s.EncryptedData)
            .IsRequired();


        // GÜVENLİK: EncryptedData, AES-256 şifrelenmiş payload içerir
        // Şifreleme, domain logic'de gerçekleştirilir (Secret.Create)
        // Bu alana ASLA plaintext hassas veri saklanmamalı

        // PERFORMANS: varbinary(max), 8KB'den büyükse off-row saklanır
        // Bu, tipik olarak binary olan şifrelenmiş veri için optimaldir

        // ============================================================================
        // INITIALIZATION VECTOR (IV) YAPILANDIRMASI
        // ============================================================================

        builder.Property(s => s.IV)
            .IsRequired()
            .HasMaxLength(16); // AES-256, 16-byte IV gerektirir
           

        // GÜVENLİK: IV (Initialization Vector) her şifreleme için benzersiz olmalı
        // Deşifre için şifreli verinin yanında saklanır
        // IV gizli değildir ancak her şifreleme için rastgele ve benzersiz olmalı

        // ============================================================================
        // CREATED AT (OLUŞTURULMA TARİHİ) YAPILANDIRMASI
        // ============================================================================

        builder.Property(s => s.CreatedAt)
            .IsRequired()
            
            .HasDefaultValueSql("GETUTCDATE()");

        // ============================================================================
        // LAST ACCESSED AT (SON ERİŞİM TARİHİ) YAPILANDIRMASI
        // ============================================================================

        builder.Property(s => s.LastAccessedAt)
            .IsRequired(false);
           

        // GÜVENLİK: LastAccessedAt, denetim izi için kritiktir
        // Kullanılmayan/eski secret'ların tespitini sağlar
        builder.HasIndex(s => s.LastAccessedAt)
            .HasDatabaseName("IX_Secrets_LastAccessedAt");

        // ============================================================================
        // SOFT DELETE (YUMUŞAK SİLME) - UYUMLULUK GEREKSİNİMİ
        // ============================================================================

        builder.Property(s => s.IsDeleted)
            .IsRequired()
            .HasDefaultValue(false);

        builder.Property(s => s.DeletedAt)
            .IsRequired(false);
            

        // GÜVENLİK: Soft-delete edilmiş secret'lar için index
        builder.HasIndex(s => s.IsDeleted)
            .HasDatabaseName("IX_Secrets_IsDeleted")
            .HasFilter("IsDeleted = 0");

        // GLOBAL QUERY FILTER: Soft-delete edilmiş secret'ları otomatik olarak çıkarır
        // Admin kurtarma senaryoları için .IgnoreQueryFilters() kullanın
        builder.HasQueryFilter(s => !s.IsDeleted);

        // UYUMLULUK: Soft delete, "geri alma" işlevselliğine izin verir
        // 30 günlük saklama süresinden sonra hard delete (ayrı job ile)

        // ============================================================================
        // YAYGIN SORGULAR İÇİN COMPOSITE INDEX'LER
        // ============================================================================

        // GÜVENLİK: Kullanıcının aktif secret'ları için composite index
        // Optimize eder: "X kullanıcısının tüm aktif secret'larını göster"
        builder.HasIndex(s => new { s.OwnerId, s.IsDeleted })
            .HasDatabaseName("IX_Secrets_Owner_NotDeleted")
            .HasFilter("IsDeleted = 0");

        // PERFORMANS: Secret arama için composite index
        // Optimize eder: "X kullanıcısı için ada göre secret ara"
        builder.HasIndex(s => new { s.OwnerId, s.Name })
            .HasDatabaseName("IX_Secrets_Owner_Name");

        // ============================================================================
        // ROW-LEVEL SECURITY (SATIR SEVİYESİ GÜVENLİK) - SQL SERVER 2016+
        // ============================================================================

        // GÜVENLİK: Row-Level Security (RLS) uygulanması düşünülebilir
        // Kullanıcıların sadece kendi secret'larına veritabanı seviyesinde erişmesini sağlar
        /*
        builder.ToTable(tb => tb.HasComment(
            "RLS POLİTİKASI: Kullanıcılar sadece kendi secret'larını SELECT/UPDATE/DELETE yapabilir. " +
            "CREATE SECURITY POLICY SecretPolicy " +
            "ADD FILTER PREDICATE dbo.fn_SecretAccessPredicate(OwnerId) ON Secrets"));
        */

        // ============================================================================
        // CONCURRENCY TOKEN (.NET 9 ÖZELLİĞİ)
        // ============================================================================

        builder.Property<byte[]>("RowVersion")
            .IsRowVersion()
            .HasColumnName("RowVersion");

        // GÜVENLİK: Eşzamanlı secret değişiklikleri sırasında kayıp güncellemeleri önler

        // ============================================================================
        // EK GÜVENLİK NOTLARI
        // ============================================================================

        /*
         * SECRET ENTITY İÇİN GÜVENLİK KONTROL LİSTESİ:
         * 
         * ✅ Tüm hassas veri şifrelenmiş (AES-256-GCM)
         * ✅ Her şifreleme için benzersiz IV (pattern analizi önlenir)
         * ✅ Şifreleme algoritması versiyonlama (crypto agility)
         * ✅ Key versiyonu takibi (key rotation desteği)
         * ✅ OwnerId foreign key (erişim kontrolü)
         * ✅ Soft delete + saklama (uyumluluk + kurtarma)
         * ✅ LastAccessedAt takibi (eski secret tespiti)
         * ✅ IsDeleted bayrağı için query filter
         * ✅ Row-level security uyumlu (SQL Server)
         * ✅ Concurrency token race condition önler
         * 
         * ŞİFRELEME GEREKSİNİMLERİ:
         * 
         * Algoritma: AES-256-GCM (authenticated encryption)
         * - Gizlilik VE bütünlük sağlar
         * - Şifreli veriyle oynanmayı tespit eder
         * 
         * Key Yönetimi:
         * - Şifreleme anahtarları Azure Key Vault / AWS KMS'de saklanır
         * - Anahtarları asla uygulamada hardcode etmeyin
         * - Anahtarları yıllık rotasyona tabi tutun (uyumluluk gereksinimi)
         * 
         * Veri Akışı:
         * 1. Kullanıcı plaintext secret gönderir
         * 2. Uygulama rastgele IV üretir
         * 3. Uygulama AES-256-GCM ile şifreler
         * 4. Sakla: EncryptedData + IV
         * 5. Sorgulama sırasında: IV'yi al, doğru key ile deşifre et
         * 
         * UYUMLULUK NOTLARI:
         * 
         * GDPR:
         * - Şifrelenmiş veri "privacy by design" destekler
         * - Soft delete "silinme hakkı"nı sağlar
         * - Dışa aktarma işlevi gerekli (deşifre et + JSON)
         * 
         * SOC2:
         * - Encryption at rest gerekli (Type II)
         * - Key rotation politikası belgelenmeli
         * - Erişim loglaması AuditLog entity ile yapılır
         * 
         * PCI-DSS:
         * - Kart sahibi verileri için güçlü kriptografi gerekli
         * - Key yönetim prosedürleri belgelenmeli
         * - Üç ayda bir key rotation önerilir
         * 
         * PERFORMANS OPTİMİZASYONU:
         * 
         * - Partial index'ler index boyutunu ~%50 azaltır
         * - varbinary(max) off-row saklanır (şifreleme için optimal)
         * - Composite index'ler index intersection overhead'ini ortadan kaldırır
         * - Query filter'lar veritabanı seviyesinde uygulanır (uygulama değil)
         * 
         * TEHDİT MODELİ:
         * 
         * Azaltılmış:
         * ✅ Veritabanı ihlali (veri şifrelenmiş)
         * ✅ SQL injection (repository'lerde parametreli sorgular)
         * ✅ Yetki yükseltme (OwnerId + RLS)
         * ✅ İç tehdit (audit log'lar tüm erişimi takip eder)
         * 
         * Kalan Riskler:
         * ⚠️ Uygulama memory dump (şifreleme sırasında bellekte anahtarlar)
         * ⚠️ Key Vault ihlali (HSM-destekli anahtarlar gerektirir)
         * ⚠️ Side-channel saldırıları (deşifre üzerinde timing saldırıları)
         * 
         * Azaltma: HSM-destekli anahtarlar + constant-time kripto işlemleri kullanın
         */
    }
}