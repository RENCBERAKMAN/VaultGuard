using Microsoft.Extensions.Diagnostics.HealthChecks;
using VaultGuard.Infrastructure.Persistence; // DOĞRU ADRES: DbContext burada
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace VaultGuard.WebAPI; // Namespace'i projenin ana diziniyle eşledik

/// <summary>
/// Veritabanının sağlık durumunu kontrol eden siber güvenlik odaklı health check sınıfı.
/// GÜVENLİK: Bağlantı hatalarında veritabanı türünü veya iç yapısını dışarı sızdırmaz.
/// </summary>
public class DatabaseHealthCheck : IHealthCheck
{
    // Arayüz (Interface) bulunamadığı için doğrudan gerçek sınıfı mühürlüyoruz
    private readonly VaultGuardDbContext _dbContext;
    private readonly ILogger<DatabaseHealthCheck> _logger;

    public const string HealthCheckName = "database";

    public DatabaseHealthCheck(
        VaultGuardDbContext dbContext,
        ILogger<DatabaseHealthCheck> logger)
    {
        _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // SİBER GÜVENLİK: 5 saniyelik agresif bir timeout ile DoS riskini azaltıyoruz
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));

            // Veritabanına gerçekten dokunabiliyor muyuz? (Connection Check)
            var canConnect = await _dbContext.Database.CanConnectAsync(cts.Token);

            if (!canConnect)
            {
                _logger.LogError("VaultGuard Health: Veritabanı bağlantısı kurulamadı.");
                return HealthCheckResult.Unhealthy("Sistem şu anda taleplere cevap veremiyor.");
            }

            _logger.LogInformation("VaultGuard Health: Veritabanı bağlantısı stabil.");
            return HealthCheckResult.Healthy("Veritabanı erişilebilir.");
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("VaultGuard Health: Veritabanı yanıt vermedi (Timeout).");
            return HealthCheckResult.Unhealthy("Sistem zaman aşımına uğradı.");
        }
        catch (Exception ex)
        {
            // SİBER GÜVENLİK: Hata detaylarını (StackTrace vb.) asla dışarı sızdırma!
            _logger.LogCritical(ex, "VaultGuard Health: Beklenmeyen bir veritabanı hatası oluştu.");
            return HealthCheckResult.Unhealthy("Sistem sağlığı kontrol edilirken bir hata oluştu.");
        }
    }
}

/// <summary>
/// Health Check yapılandırmasını DI container'a mühürleyen extension.
/// </summary>
public static class HealthCheckExtensions
{
    public static IHealthChecksBuilder AddDatabaseHealthCheck(this IHealthChecksBuilder builder)
    {
        return builder.AddCheck<DatabaseHealthCheck>(
            name: DatabaseHealthCheck.HealthCheckName,
            timeout: TimeSpan.FromSeconds(10), // Toplam kontrol süresi
            tags: new[] { "database", "ready" });
    }
}