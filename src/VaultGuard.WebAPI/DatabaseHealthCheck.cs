using Microsoft.Extensions.Diagnostics.HealthChecks;
using System;
using System.Threading;
using System.Threading.Tasks;
using VaultGuard.Infrastructure.Persistence;

namespace VaultGuard.WebAPI;

public class DatabaseHealthCheck : IHealthCheck
{
    private readonly VaultGuardDbContext _context;

    public DatabaseHealthCheck(VaultGuardDbContext context)
    {
        _context = context;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            // Veritabanına basit bir bağlantı testi yapar
            var canConnect = await _context.Database.CanConnectAsync(cancellationToken);

            return canConnect
                ? HealthCheckResult.Healthy("Veritabanı bağlantısı aktif! 🛡️")
                : HealthCheckResult.Unhealthy("Veritabanı bağlantısı başarısız.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy($"Veritabanı hatası: {ex.Message}");
        }
    }
}