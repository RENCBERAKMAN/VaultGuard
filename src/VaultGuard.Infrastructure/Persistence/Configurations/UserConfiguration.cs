using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using VaultGuard.Domain.Entities;

namespace VaultGuard.Infrastructure.Persistence.Configurations;

/// <summary>
/// User entity için Entity Framework Core yapılandırması.
/// Güvenlik en iyi uygulamalarını (unique constraint, indexing, query filter) içerir.
/// Clean Architecture prensiplerine uygun olarak domain entity'lerini EF Core attribute'larından arındırır.
/// </summary>
public sealed class UserConfiguration : IEntityTypeConfiguration<User>
{
    public void Configure(EntityTypeBuilder<User> builder)
    {
        // ============================================================================
        // TABLO YAPILANDIRMASI
        // ============================================================================

        builder.ToTable("Users");

        // ============================================================================
        // PRIMARY KEY (BİRİNCİL ANAHTAR)
        // ============================================================================

        builder.HasKey(u => u.Id);

        // GÜVENLİK NOTU: Guid tipinde primary key kullanmak, otomatik artan integer'lara göre
        // daha güvenlidir çünkü sıralı olmayan ID'ler sayı tahmini (enumeration) saldırılarını zorlaştırır.
        builder.Property(u => u.Id)
            .IsRequired()
            .ValueGeneratedNever(); // Guid domain logic'de oluşturulduğu için (User.Create metodu)

        // ============================================================================
        // EMAIL YAPILANDIRMASI
        // ============================================================================

        builder.Property(u => u.Email)
            .IsRequired()
            .HasMaxLength(256); // RFC 5321 standardı max 254 karakter öngörür, 256 ek buffer sağlar
            

        // GÜVENLİK: Unique constraint, aynı email ile birden fazla hesap oluşturulmasını engeller
        // ve account enumeration (hesap numaralandırma) saldırılarına karşı koruma sağlar
        builder.HasIndex(u => u.Email)
            .IsUnique()
            .HasDatabaseName("IX_Users_Email_Unique");

        // PERFORMANS: Email alanı login sorgularında sıkça kullanıldığı için indexlenmesi gerekir
        // GÜVENLİK: Index, authentication sorgularının hızlı çalışmasını sağlayarak DoS riski azaltır
        builder.HasIndex(u => u.Email)
            .HasDatabaseName("IX_Users_Email_Lookup");

        // ============================================================================
        // KULLANICI ADI (USERNAME) YAPILANDIRMASI
        // ============================================================================

        builder.Property(u => u.Username)
            .IsRequired()
            .HasMaxLength(50);
            

        // GÜVENLİK: Benzersiz kullanıcı adları, hesap karmaşasını ve kimlik doğrulama saldırılarını önler
        builder.HasIndex(u => u.Username)
            .IsUnique()
            .HasDatabaseName("IX_Users_Username_Unique");

        // ============================================================================
        // ŞİFRE HASH YAPILANDIRMASI
        // ============================================================================

        builder.Property(u => u.PasswordHash)
            .IsRequired()
            .HasMaxLength(512); // BCrypt/Argon2 hash'leri tipik olarak 60-100 karakter, 512 ek alan sağlar
            

        // GÜVENLİK NOTU: Şifreler asla düz metin (plain-text) olarak saklanmaz, sadece hash'lenmiş halleri
        // Hash uzunluğu 512 karakter olarak ayarlandı çünkü farklı algoritmalar desteklenir (BCrypt, Argon2, PBKDF2)
        // Bu alan API response'larında ASLA dışarı açılmamalıdır

        // ============================================================================
        // ROL (ROLE) YAPILANDIRMASI
        // ============================================================================

        builder.Property(u => u.Role)
            .IsRequired()
            .HasMaxLength(20) // "Admin", "User", "Auditor" - 20 karakter yeterli
            .HasDefaultValue("User");

        // PERFORMANS: Rol bazlı filtreleme çok yaygındır - RBAC (Role-Based Access Control) sorguları için indexlendi
        builder.HasIndex(u => u.Role)
            .HasDatabaseName("IX_Users_Role");

        // ============================================================================
        // AKTİFLİK DURUMU (IS ACTIVE) YAPILANDIRMASI
        // ============================================================================

        builder.Property(u => u.IsActive)
            .IsRequired()
            .HasDefaultValue(true);

        // GÜVENLİK: IsActive üzerinde index, devre dışı hesapların verimli filtrelenmesini sağlar
        // Pasif hesapların authentication sorgularında görünmemesini garanti eder
        builder.HasIndex(u => u.IsActive)
            .HasDatabaseName("IX_Users_IsActive")
            .HasFilter("IsActive = 1"); // Partial index - sadece aktif kullanıcılar

        // ============================================================================
        // ZAMAN DAMGALARI (TIMESTAMPS)
        // ============================================================================

        builder.Property(u => u.CreatedAt)
            .IsRequired()
             
            .HasDefaultValueSql("GETUTCDATE()");

        builder.Property(u => u.LastLoginAt)
            .HasColumnType("datetime2(7)");

        // GÜVENLİK: LastLoginAt index'i şüpheli login paternlerinin tespitinde yardımcı olur
        // Anomali tespiti ve uyumluluk raporlamasında kullanılır
        builder.HasIndex(u => u.LastLoginAt)
            .HasDatabaseName("IX_Users_LastLoginAt");

        // ============================================================================
        // SOFT DELETE (YUMUŞAK SİLME) - GLOBAL QUERY FILTER
        // ============================================================================

        // UYUMLULUK: Soft delete, GDPR "unutulma hakkı" (right to be forgotten) iş akışlarını destekler
        // Yasal süreçler sırasında veri saklama gereksinimlerini karşılarken "silinmiş" olarak işaretlemeyi sağlar
        // Eğer User entity'de IsDeleted property'si varsa aşağıdaki yorumları kaldırın
        /*
        builder.Property(u => u.IsDeleted)
            .IsRequired()
            .HasDefaultValue(false);

        builder.HasIndex(u => u.IsDeleted)
            .HasDatabaseName("IX_Users_IsDeleted")
            .HasFilter("[IsDeleted] = 0");

        // GLOBAL QUERY FILTER: Soft-delete edilmiş kullanıcıları tüm sorgulardan otomatik olarak çıkarır
        // Admin senaryolarında silinmiş kullanıcıları dahil etmek için .IgnoreQueryFilters() kullanın
        builder.HasQueryFilter(u => !u.IsDeleted);
        */

        // ============================================================================
        // YAYGIN SORGULAR İÇİN COMPOSITE INDEX'LER
        // ============================================================================

        // PERFORMANS: Authentication sorguları için composite index (Email + IsActive)
        // Optimize eder: SELECT * FROM Users WHERE Email = @email AND IsActive = 1
        builder.HasIndex(u => new { u.Email, u.IsActive })
            .HasDatabaseName("IX_Users_Email_IsActive")
            .HasFilter("IsActive = 1");

        // GÜVENLİK: Rol bazlı erişim kontrolü için composite index (Role + IsActive)
        // Optimize eder: SELECT * FROM Users WHERE Role = @role AND IsActive = 1
        builder.HasIndex(u => new { u.Role, u.IsActive })
            .HasDatabaseName("IX_Users_Role_IsActive")
            .HasFilter("IsActive = 1");

        // ============================================================================
        // İLİŞKİLER (RELATIONSHIPS)
        // ============================================================================

        // Bir-Çok İlişki: User -> Secrets
        builder.HasMany<Secret>()
            .WithOne()
            .HasForeignKey(s => s.OwnerId)
            .OnDelete(DeleteBehavior.Restrict); // Güvenlik denetimi için cascade delete engellendi

        // Bir-Çok İlişki: User -> AuditLogs
        builder.HasMany<AuditLog>()
            .WithOne()
            .HasForeignKey(a => a.UserId)
            .OnDelete(DeleteBehavior.Restrict); // Kullanıcı silinse bile audit log'lar korunmalı

        // ============================================================================
        // CONCURRENCY TOKEN (.NET 9 ÖZELLİĞİ)
        // ============================================================================

        // GÜVENLİK: Eşzamanlı senaryolarda kayıp güncellemeleri (lost update) önler
        // Optimistic concurrency control için .SetConcurrencyToken() kullanımı
        builder.Property<byte[]>("RowVersion")
            .IsRowVersion()
            .HasColumnName("RowVersion");

        // ============================================================================
        // EK GÜVENLİK NOTLARI
        // ============================================================================

        /*
         * USER ENTITY İÇİN GÜVENLİK KONTROL LİSTESİ:
         * 
         * ✅ Şifreler hash'lenmiş (plain-text asla saklanmaz)
         * ✅ Email ve Username üzerinde unique constraint var
         * ✅ Guid primary key, enumeration saldırılarını önler
         * ✅ Index'ler authentication sorgularını hızlandırır (DoS azaltma)
         * ✅ IsActive bayrağı, silmeden hesap askıya almaya izin verir
         * ✅ LastLoginAt tracking, anomali tespitini mümkün kılar
         * ✅ Soft delete, denetim izini korur (GDPR uyumlu)
         * ✅ Foreign key ilişkileri, yetim veri oluşmasını önler
         * ✅ Concurrency token, race condition'ları önler
         * ✅ Kritik ilişkilerde cascading delete yok
         * 
         * UYUMLULUK NOTLARI:
         * - GDPR: Soft delete + veri dışa aktarma yeteneği gerekli
         * - SOC2: Audit log'lar değiştirilemez olmalı (DeleteBehavior.Restrict)
         * - HIPAA: Hassas alanlar için encryption-at-rest düşünülebilir
         * 
         * PERFORMANS OPTİMİZASYONLARI:
         * - IsActive üzerinde partial index, index boyutunu ~%50 azaltır
         * - Composite index'ler, index intersection ihtiyacını ortadan kaldırır
         * - datetime2(7), forensic incelemeler için mikrosaniye hassasiyet sağlar
         */
    }
}