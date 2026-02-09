using Microsoft.EntityFrameworkCore;
using System;
using VaultGuard.Domain.Entities;
using VaultGuard.Infrastructure.Persistence.Configurations;

namespace VaultGuard.Infrastructure.Persistence;

/// <summary>
/// VaultGuard veritabaný context'i.
/// Tüm entity yapýlandýrmalarýný uygular ve güvenlik en iyi uygulamalarýný implement eder.
/// </summary>
public class VaultGuardDbContext : DbContext
{
    public VaultGuardDbContext(DbContextOptions<VaultGuardDbContext> options)
        : base(options)
    {
    }

    // DbSet'ler
    public DbSet<User> Users => Set<User>();
    public DbSet<Secret> Secrets => Set<Secret>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Tüm entity yapýlandýrmalarýný uygula
        modelBuilder.ApplyConfiguration(new UserConfiguration());
        modelBuilder.ApplyConfiguration(new SecretConfiguration());
        modelBuilder.ApplyConfiguration(new AuditLogConfiguration());

        // GÜVENLÝK: Soft delete için global query filter'lar
        // Bireysel yapýlandýrmalarda zaten tanýmlanmýþ

        // PERFORMANS: Varsayýlan string uzunluðunu yapýlandýr
        foreach (var entityType in modelBuilder.Model.GetEntityTypes())
        {
            foreach (var property in entityType.GetProperties())
            {
                if (property.ClrType == typeof(string) && property.GetMaxLength() == null)
                {
                    property.SetMaxLength(256); // Listelenmemiþ string'ler için varsayýlan max uzunluk
                }
            }
        }
    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        base.OnConfiguring(optionsBuilder);

        // GÜVENLÝK: Hassas veri loglamasýný SADECE development ortamýnda etkinleþtir
        if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
        {
            optionsBuilder.EnableSensitiveDataLogging();
            optionsBuilder.EnableDetailedErrors();
        }

        // NOT: UseQuerySplittingBehavior artýk burada deðil,
        // UseSqlServer içinde yapýlandýrýlacak (aþaðýda örnek var)
    }
}