using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using System;
using System.Linq;
using System.Threading.Tasks;
using VaultGuard.Domain.Entities;
using VaultGuard.Infrastructure.Persistence;
using Xunit;

namespace VaultGuard.Infrastructure.Tests.Persistence;

/// <summary>
/// TEST SÜİTİ: AuditLogRepository - Audit Trail Integrity Tests
/// 
/// SECURITY FOCUS:
/// - **Traceability**: Her işlem eksiksiz log edilmeli (who, what, when, where)
/// - **Immutability**: Audit logs ASLA değiştirilemez/silinemez
/// - **Chronological Order**: Logs timestamp'e göre sıralanmalı
/// - **Completeness**: IP, User, Action, Timestamp eksik OLMAMALI
/// 
/// COMPLIANCE:
/// - SOC 2 Type II: Immutable audit trail
/// - GDPR Article 30: Records of processing activities
/// - PCI-DSS Requirement 10: Audit trail
/// - HIPAA §164.312(b): Audit controls
/// 
/// THREAT MODEL:
/// - Log tampering: Attacker audit log'u modify eder
/// - Log deletion: Attacker evidence destroy eder
/// - Incomplete logs: Missing critical information
/// </summary>
public class AuditLogRepositoryTests : RepositoryTestBase
{
    private readonly AuditLogRepository _repository;

    public AuditLogRepositoryTests()
    {
        _repository = new AuditLogRepository(Context);
    }

    // ============================================================================
    // ✅ CREATE TESTS - TRACEABILITY (AddAsync)
    // ============================================================================

    /// <summary>
    /// COMPLIANCE TEST - TRACEABILITY KRİTİK:
    /// AddAsync - Audit log tüm gerekli field'larla eksiksiz kaydedilmeli.
    /// 
    /// REQUIRED FIELDS (Eksik olamaz):
    /// - UserId: WHO performed the action
    /// - Action: WHAT was done
    /// - EntityName: WHERE (which table/entity)
    /// - Timestamp: WHEN it happened
    /// - IpAddress: FROM WHERE (client IP)
    /// 
    /// COMPLIANCE: SOC 2 - Complete audit trail
    /// </summary>
    [Fact]
    public async Task AddAsync_WithCompleteAuditLog_ShouldSaveAllFields()
    {
        // Arrange: Complete audit log
        var userId = Guid.NewGuid();
        var entityId = Guid.NewGuid(); // Bu bir GUID nesnesi

        // 🔴 HATA BURADAYDI: .ToString() yaparak string'e çevirmişsin 
        // ama Domain katmanındaki AuditLog.Create 6. parametrede Guid? bekliyor.
        var auditLog = AuditLog.Create(
            userId: userId,
            ipAddress: "192.168.1.100",
            action: "Secret_Decrypted",
            entityName: "Secret",
            result: "Success",
            entityId: entityId, // ✅ DÜZELDİ: .ToString() kaldırıldı, doğrudan Guid nesnesi verildi
            additionalData: "User decrypted credential via API"
        );

        // Act
        await _repository.AddAsync(auditLog);
        await Context.SaveChangesAsync();

        // Assert
        var savedLog = await Context.AuditLogs.FirstOrDefaultAsync(a => a.Id == auditLog.Id);

        savedLog.Should().NotBeNull();
        savedLog!.UserId.Should().Be(userId);
        savedLog.Action.Should().Be("Secret_Decrypted");

        // ✅ DÜZELDİ: Modeldeki EntityId Guid? olduğu için Guid ile karşılaştırmalıyız
        savedLog.EntityId.Should().Be(entityId);

        savedLog.Result.Should().Be("Success");
        savedLog.AdditionalData.Should().Be("User decrypted credential via API");
        savedLog.Timestamp.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    /// <summary>
    /// COMPLIANCE TEST - MANDATORY FIELDS:
    /// AddAsync - UserId, Action, IP eksik OLMAMALI.
    /// Domain entity validation bu kontrolü yapar.
    /// </summary>
    [Fact]
    public void Create_WithMissingUserId_ShouldThrowException()
    {
        // Arrange & Act
        // ✅ DÜZELDİ: Action delegesi kullanıldı ve tüm güncel parametreler eklendi
        Action act = () => AuditLog.Create(
            userId: Guid.Empty,          // HATA FIRLATMASI BEKLENEN KISIM!
            ipAddress: "192.168.1.1",
            action: "Secret_Viewed",
            entityName: "Secret",
            result: "Success",
            entityId: null,              // YENİ: Açıkça null geçildi
            additionalData: null         // YENİ: Details yerine additionalData kullanıldı
        );

        // Assert: Boş GUID gönderildiği için ArgumentException fırlatmalı
        act.Should().Throw<ArgumentException>()
            .WithMessage("*User ID cannot be Guid.Empty*");
    }

    /// <summary>
    /// COMPLIANCE TEST - IP ADDRESS:
    /// IP address traceability - Her log IP address içermeli.
    /// </summary>
    [Fact]
    public async Task AddAsync_WithIpAddress_ShouldSaveIpCorrectly()
    {
        // Arrange: IPv4 and IPv6
        var userId = Guid.NewGuid();

        // ✅ DÜZELDİ: .ToString() kaldırıldı, doğrudan Guid gönderiliyor
        var log1 = AuditLog.Create(
            userId: userId,
            ipAddress: "203.0.113.42",
            action: "User_Login",
            entityName: "User",
            result: "Success",
            entityId: userId, // 👈 Burası string değil, Guid olmalı!
            additionalData: null
        );

        var log2 = AuditLog.Create(
            userId: userId,
            ipAddress: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            action: "User_Logout",
            entityName: "User",
            result: "Success",
            entityId: userId, // 👈 Burası string değil, Guid olmalı!
            additionalData: null
        );

        // Act
        await _repository.AddAsync(log1);
        await _repository.AddAsync(log2);
        await Context.SaveChangesAsync();

        // Assert
        var logs = await Context.AuditLogs.Where(a => a.UserId == userId).ToListAsync();
        logs.Should().HaveCount(2);
        logs.Should().Contain(l => l.IpAddress == "203.0.113.42");
        logs.Should().Contain(l => l.IpAddress.Contains("2001:0db8"));
    }

    // ============================================================================
    // 🔍 READ TESTS - USER SPECIFIC LOGS
    // ============================================================================

    /// <summary>
    /// QUERY ACCURACY TEST:
    /// GetByUserIdAsync - Belirli user'ın log'ları doğru dönmeli.
    /// </summary>
    [Fact]
    public async Task GetByUserIdAsync_ShouldReturnUserLogs()
    {
        // Arrange: 2 user, her biri 2 log
        var user1 = Guid.NewGuid();
        var user2 = Guid.NewGuid();

        // User 1 logs
        await _repository.AddAsync(CreateLog(user1, "Secret_Created"));
        await _repository.AddAsync(CreateLog(user1, "Secret_Viewed"));

        // User 2 logs
        await _repository.AddAsync(CreateLog(user2, "User_Login"));
        await _repository.AddAsync(CreateLog(user2, "User_Logout"));

        await Context.SaveChangesAsync();

        // Act: User 1'in log'ları
        var user1Logs = await _repository.GetByUserIdAsync(user1);

        // Assert: SADECE User 1'in log'ları
        user1Logs.Should().HaveCount(2);
        user1Logs.Should().OnlyContain(l => l.UserId == user1);
        user1Logs.Should().Contain(l => l.Action == "Secret_Created");
        user1Logs.Should().Contain(l => l.Action == "Secret_Viewed");

        // User 2'nin log'ları GELMEMELİ
        user1Logs.Should().NotContain(l => l.UserId == user2);
    }

    /// <summary>
    /// COMPLIANCE TEST - CHRONOLOGICAL ORDER KRİTİK:
    /// GetByUserIdAsync - Log'lar tarih sırasına göre (DESC) dönmeli.
    /// 
    /// FORENSIC ANALYSIS: En yeni event'ler önce gelir (investigation kolaylığı)
    /// </summary>
    [Fact]
    public async Task GetByUserIdAsync_ShouldReturnNewestFirst()
    {
        // Arrange
        var userId = Guid.NewGuid();

        // 3 log farklı zamanlarda (CreateLog helper'ı tüm güncel parametreleri hallediyor)
        var log1 = CreateLog(userId, "Action_1");
        await _repository.AddAsync(log1);
        await Context.SaveChangesAsync();

        await Task.Delay(100); // Timestamp farklı olsun (Gerçekçi senaryo)

        var log2 = CreateLog(userId, "Action_2");
        await _repository.AddAsync(log2);
        await Context.SaveChangesAsync();

        await Task.Delay(100);

        var log3 = CreateLog(userId, "Action_3");
        await _repository.AddAsync(log3);
        await Context.SaveChangesAsync();

        // Act: Son 10 log (Sayfalama - Pagination)
        var logs = (await _repository.GetByUserIdAsync(userId, skip: 0, take: 10)).ToList();

        // Assert: En yeni önce (DESC order)
        logs.Should().HaveCount(3);
        logs[0].Action.Should().Be("Action_3"); // Newest
        logs[1].Action.Should().Be("Action_2");
        logs[2].Action.Should().Be("Action_1"); // Oldest
    }

    /// <summary>
    /// QUERY ACCURACY TEST - PAGINATION:
    /// GetByUserIdAsync with pagination - Skip/Take doğru çalışmalı.
    /// </summary>
    [Fact]
    public async Task GetByUserIdAsync_WithPagination_ShouldReturnCorrectPage()
    {
        // Arrange: 5 log
        var userId = Guid.NewGuid();

        for (int i = 1; i <= 5; i++)
        {
            // ✅ DÜZELDİ: Güncel CreateLog helper metodu kullanılarak tüm parametre sorunları aşıldı
            var log = CreateLog(userId, $"Action_{i}");
            await _repository.AddAsync(log);
            await Context.SaveChangesAsync();

            await Task.Delay(50); // Timestamps farklı olsun diye kısa bir duraklama
        }

        // Act: Skip 2, Take 2 (2. sayfa, sayfada 2 eleman)
        var logs = (await _repository.GetByUserIdAsync(userId, skip: 2, take: 2)).ToList();

        // Assert: 3. ve 4. log'lar (DESC sırada - En yeniden en eskiye)
        logs.Should().HaveCount(2);

        // Newest: Action_5, Action_4, [Action_3, Action_2], Action_1
        logs[0].Action.Should().Be("Action_3");
        logs[1].Action.Should().Be("Action_2");
    }

    // ============================================================================
    // 📊 BULK FETCH TESTS - RECENT LOGS
    // ============================================================================

    /// <summary>
    /// COMPLIANCE TEST - RECENT LOGS:
    /// GetRecentLogsAsync - En son 10 log doğru sırada dönmeli.
    /// Admin dashboard için kullanılır.
    /// </summary>
    [Fact]
    public async Task GetRecentLogsAsync_ShouldReturnLatestLogs()
    {
        // Arrange: 15 log farklı user'lardan
        for (int i = 1; i <= 15; i++)
        {
            // ✅ DÜZELDİ: CreateLog helper'ı tüm güncel parametreleri hallediyor
            var log = CreateLog(Guid.NewGuid(), $"Action_{i}");
            await _repository.AddAsync(log);
            await Context.SaveChangesAsync();
            await Task.Delay(50); // Timestamps farklı (Gerçekçi sıralama için)
        }

        // Act: Son 10 log (Count parametresi ile)
        var recentLogs = (await _repository.GetRecentLogsAsync(count: 10)).ToList();

        // Assert: 10 log, newest first (En yeni ilk sırada)
        recentLogs.Should().HaveCount(10);
        recentLogs[0].Action.Should().Be("Action_15"); // Newest
        recentLogs[9].Action.Should().Be("Action_6");  // Oldest of the newest 10
    }

    /// <summary>
    /// QUERY ACCURACY TEST:
    /// GetRecentLogsAsync with custom count - İstenen sayıda log dönmeli.
    /// </summary>
    [Fact]
    public async Task GetRecentLogsAsync_WithCustomCount_ShouldReturnRequestedNumber()
    {
        // Arrange: 20 log
        for (int i = 1; i <= 20; i++)
        {
            // ✅ DÜZELDİ: Helper metodumuz (CreateLog) sayesinde burası tertemiz
            var log = CreateLog(Guid.NewGuid(), $"Action_{i}");
            await _repository.AddAsync(log);
        }
        await Context.SaveChangesAsync();

        // Act: Son 5 log
        var recentLogs = await _repository.GetRecentLogsAsync(count: 5);

        // Assert
        recentLogs.Should().HaveCount(5);
    }

    // ============================================================================
    // 🎯 RESOURCE-SPECIFIC LOGS
    // ============================================================================

    /// <summary>
    /// COMPLIANCE TEST - RESOURCE TRACEABILITY:
    /// GetByResourceIdAsync - Belirli resource'a ait tüm log'lar dönmeli.
    /// 
    /// USE CASE: "Secret X'e kim erişti?" forensic investigation
    /// </summary>
    [Fact]
    public async Task GetByResourceIdAsync_ShouldReturnResourceLogs()
    {
        // Arrange: 1 secret, 3 farklı user erişti
        var secretId = Guid.NewGuid();
        var user1 = Guid.NewGuid();
        var user2 = Guid.NewGuid();
        var user3 = Guid.NewGuid();

        // CreateLog helper'ı zaten Guid? bekliyor, secretId'yi doğrudan veriyoruz
        await _repository.AddAsync(CreateLog(user1, "Secret_Viewed", secretId));
        await _repository.AddAsync(CreateLog(user2, "Secret_Decrypted", secretId));
        await _repository.AddAsync(CreateLog(user3, "Secret_Updated", secretId));

        // Control group
        await _repository.AddAsync(CreateLog(user1, "Secret_Viewed", Guid.NewGuid()));

        await Context.SaveChangesAsync();

        // Act: 
        // 🔴 DÜZELTİLDİ: Repository Guid bekliyorsa .ToString() SİLİNMELİ
        var resourceLogs = await _repository.GetByResourceIdAsync(secretId);

        // Assert
        resourceLogs.Should().HaveCount(3);

        // 🔴 DÜZELTİLDİ: EntityId Guid? olduğu için karşılaştırma doğrudan Guid ile yapılır
        resourceLogs.Should().OnlyContain(l => l.EntityId == secretId);

        resourceLogs.Should().Contain(l => l.Action == "Secret_Viewed");
        resourceLogs.Should().Contain(l => l.Action == "Secret_Decrypted");
        resourceLogs.Should().Contain(l => l.Action == "Secret_Updated");
    }

    /// <summary>
    /// COMPLIANCE TEST - CHRONOLOGICAL ORDER:
    /// GetByResourceIdAsync - Resource log'ları tarih sırasında (DESC).
    /// </summary>
    [Fact]
    public async Task GetByResourceIdAsync_ShouldReturnNewestFirst()
    {
        // Arrange
        var resourceId = Guid.NewGuid();
        var userId = Guid.NewGuid();

        // CreateLog helper'ına doğrudan Guid (resourceId) veriyoruz
        var log1 = CreateLog(userId, "Action_1", resourceId);
        await _repository.AddAsync(log1);
        await Context.SaveChangesAsync();

        await Task.Delay(100);

        var log2 = CreateLog(userId, "Action_2", resourceId);
        await _repository.AddAsync(log2);
        await Context.SaveChangesAsync();

        // Act
        // 🔴 DÜZELTİLDİ: .ToString() SİLİNDİ! Repository Guid bekliyor.
        var logs = (await _repository.GetByResourceIdAsync(resourceId)).ToList();

        // Assert: En yeni önce (DESC order)
        logs.Should().HaveCount(2);
        logs[0].Action.Should().Be("Action_2"); // En yeni
        logs[1].Action.Should().Be("Action_1"); // En eski
    }

    // ============================================================================
    // 📈 COUNT TESTS
    // ============================================================================

    /// <summary>
    /// QUERY ACCURACY TEST:
    /// GetTotalCountAsync - Toplam audit log sayısı doğru dönmeli.
    /// </summary>
    [Fact]
    public async Task GetTotalCountAsync_ShouldReturnCorrectCount()
    {
        // Arrange: 7 adet log oluşturuluyor
        for (int i = 1; i <= 7; i++)
        {
            // ✅ DÜZELDİ: Güncel CreateLog helper'ı tüm yeni Domain kurallarını (result, string ID) uyguluyor
            var log = CreateLog(Guid.NewGuid(), $"Action_{i}");
            await _repository.AddAsync(log);
        }
        await Context.SaveChangesAsync();

        // Act: Toplam sayıyı getir
        var count = await _repository.GetTotalCountAsync();

        // Assert: Kaydedilen sayı ile dönen sayı eşleşmeli
        count.Should().Be(7);
    }
    /// <summary>
    /// QUERY ACCURACY TEST:
    /// GetTotalCountAsync with empty database - 0 dönmeli.
    /// </summary>
    [Fact]
    public async Task GetTotalCountAsync_WithEmptyDatabase_ShouldReturnZero()
    {
        // Arrange: Veritabanı boş (RepositoryTestBase sayesinde her test sıfır DB ile başlar)

        // Act: Sayım işlemini tetikle
        var count = await _repository.GetTotalCountAsync();

        // Assert: Sonuç tam olarak 0 olmalı
        count.Should().Be(0);
    }
    // ============================================================================
    // 🔐 IMMUTABILITY TESTS (NO UPDATE/DELETE)
    // ============================================================================

    /// <summary>
    /// COMPLIANCE TEST - IMMUTABILITY:
    /// Audit logs ASLA update edilemez (repository'de update method yok).
    /// 
    /// THREAT: Log tampering
    /// - Attacker audit log'u modify eder (evidence destroy)
    /// - Compliance violation (SOC 2, PCI-DSS)
    /// 
    /// MITIGATION: No UpdateAsync method in repository
    /// </summary>
    [Fact]
    public void Repository_ShouldNotHaveUpdateMethod()
    {
        // Arrange & Act: Reflection kullanarak AuditLogRepository sınıfını inceliyoruz
        var updateMethod = typeof(AuditLogRepository)
            .GetMethod("UpdateAsync");

        // Assert: Audit loglar "Immutable" (değiştirilemez) olmalıdır. 
        // Eğer biri yanlışlıkla repository'ye UpdateAsync eklerse bu test patlayacak ve güvenliği koruyacaktır.
        updateMethod.Should().BeNull("audit logs are immutable, no update allowed for integrity and compliance");
    }

    /// <summary>
    /// COMPLIANCE TEST - IMMUTABILITY:
    /// Audit logs ASLA delete edilemez (repository'de delete method yok).
    /// 
    /// RETENTION POLICY: Background job handles archival (not repository)
    /// </summary>
    [Fact]
    public void Repository_ShouldNotHaveDeleteMethod()
    {
        // Arrange & Act: Reflection ile DeleteAsync metodunun varlığını kontrol ediyoruz
        var deleteMethod = typeof(AuditLogRepository)
            .GetMethod("DeleteAsync");

        // Assert: Audit loglar silinemez (Immutable). 
        // Kanuni uyumluluk (GDPR/SOC2) gereği iz kayıtları yok edilemez olmalıdır.
        deleteMethod.Should().BeNull("audit logs are immutable, no delete allowed to preserve forensic evidence");
    }

    // ============================================================================
    // 🎯 EDGE CASES
    // ============================================================================

    /// <summary>
    /// DATABASE INTEGRITY TEST:
    /// Timestamp auto-set - Timestamp yoksa otomatik UTC now set edilmeli.
    /// </summary>
    [Fact]
    public async Task AddAsync_WithoutTimestamp_ShouldSetUtcNow()
    {
        // Arrange
        var userId = Guid.NewGuid();

        // ✅ DÜZELDİ: entityName geçerli bir değer ("System") yapıldı
        var log = AuditLog.Create(
            userId: userId,
            ipAddress: "127.0.0.1",
            action: "System_Diagnostic", // "Action_Name" formatı korundu
            entityName: "System",        // 👈 Burası "Test" olamaz!
            result: "Success",
            entityId: null,
            additionalData: null
        );

        // Act
        await _repository.AddAsync(log);
        await Context.SaveChangesAsync();

        // Assert
        var savedLog = await Context.AuditLogs.FirstOrDefaultAsync(a => a.Id == log.Id);

        savedLog.Should().NotBeNull();
        // Zamanın doğruluğunu kontrol ediyoruz
        savedLog!.Timestamp.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    /// <summary>
    /// QUERY ACCURACY TEST:
    /// GetByUserIdAsync with no logs - Boş liste dönmeli.
    /// </summary>
    [Fact]
    public async Task GetByUserIdAsync_WithNoLogs_ShouldReturnEmpty()
    {
        // Arrange: Rastgele, veritabanında kaydı olmayan bir User ID
        var randomUserId = Guid.NewGuid();

        // Act: Bu hayalet kullanıcı için logları çekmeye çalış
        var logs = await _repository.GetByUserIdAsync(randomUserId);

        // Assert: Sonuç null değil, boş bir koleksiyon olmalı
        logs.Should().NotBeNull();
        logs.Should().BeEmpty();
    }

    /// <summary>
    /// DATABASE INTEGRITY TEST:
    /// Optional fields (Details, EntityId) - Null olabilir.
    /// </summary>
    [Fact]
    public async Task AddAsync_WithOptionalFields_ShouldSaveCorrectly()
    {
        // Arrange: EntityId ve AdditionalData null senaryosu
        var userId = Guid.NewGuid();

        // ✅ DÜZELDİ: Eksik result parametresi eklendi, 'details' yerine 'additionalData' kullanıldı
        var log = AuditLog.Create(
            userId: userId,
            ipAddress: "10.0.0.1",
            action: "System_Backup",
            entityName: "System",
            result: "Success",          // YENİ: Zorunlu alan eklendi
            entityId: null,             // Optional
            additionalData: null        // YENİ: Domain isimlendirmesiyle eşleşti
        );

        // Act
        await _repository.AddAsync(log);
        await Context.SaveChangesAsync();

        // Assert
        var savedLog = await Context.AuditLogs.FirstOrDefaultAsync(a => a.Id == log.Id);

        // ✅ DÜZELDİ: Null-forgiving (!) operatörü ve doğru property isimleri kullanıldı
        savedLog.Should().NotBeNull();
        savedLog!.EntityId.Should().BeNull();
        savedLog.AdditionalData.Should().BeNull(); // 'Details' artık 'AdditionalData'
        savedLog.Result.Should().Be("Success");
    }

    /// <summary>
    /// COMPLIANCE TEST - DETAILS FIELD:
    /// Details field - Additional context kaydedilmeli.
    /// </summary>
    [Fact]
    public async Task AddAsync_WithDetails_ShouldSaveJsonMetadata()
    {
        // Arrange: JSON metadata
        var userId = Guid.NewGuid();
        var jsonDetails = "{\"OldValue\":\"User\",\"NewValue\":\"Admin\",\"Reason\":\"Promotion\"}";

        // ✅ DÜZELDİ: entityId artık string değil, doğrudan Guid nesnesi!
        var log = AuditLog.Create(
            userId: userId,
            ipAddress: "192.168.1.1",
            action: "User_RoleChanged",
            entityName: "User",
            result: "Success",
            entityId: userId,           // 👈 .ToString() SİLİNDİ!
            additionalData: jsonDetails
        );

        // Act
        await _repository.AddAsync(log);
        await Context.SaveChangesAsync();

        // Assert
        var savedLog = await Context.AuditLogs.FirstOrDefaultAsync(a => a.Id == log.Id);

        savedLog.Should().NotBeNull();
        savedLog!.AdditionalData.Should().Be(jsonDetails);
        savedLog.AdditionalData.Should().Contain("Promotion");
    }
    // ============================================================================
    // 🛠️ HELPER METHODS
    // ============================================================================

    private AuditLog CreateLog(Guid userId, string action, Guid? entityId = null)
    {
        // ✅ DÜZELDİ: .ToString() SİLİNDİ! 
        // Domain'deki AuditLog.Create 6. parametrede Guid? bekliyor.
        // entityId zaten bir Guid? olduğu için doğrudan paslıyoruz.

        return AuditLog.Create(
            userId: userId,
            ipAddress: "192.168.1.1",
            action: action,
            entityName: "Secret",           // İzin verilen bir entity ismi
            result: "Success",              // İzin verilen bir result değeri
            entityId: entityId,             // 👈 DOĞRU: Doğrudan Guid? gönderildi
            additionalData: null
        );
    }
}