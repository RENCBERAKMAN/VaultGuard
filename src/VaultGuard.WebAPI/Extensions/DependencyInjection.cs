using VaultGuard.Application.Interfaces;
using VaultGuard.Application.Services;
using VaultGuard.Infrastructure.Persistence; // DOÐRU ADRES: Repositories yerine Persistence
using VaultGuard.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using VaultGuard.WebAPI; // DatabaseHealthCheck'in bulunduðu yer

namespace VaultGuard.WebAPI.Extensions;

public static class DependencyInjection
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services)
    {
        // Business Logic Servisleri
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<IUserService, UserService>();

        return services;
    }

    public static IServiceCollection AddInfrastructureServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // ---------------------------------------------------------
        // SÝBER GÜVENLÝK MOTORLARI (Encryption & Hashing)
        // ---------------------------------------------------------
        services.AddSingleton<IEncryptionService, AesEncryptionService>();
        services.AddSingleton<IPasswordHasher, BCryptPasswordHasher>();

        // ---------------------------------------------------------
        // VERÝTABANI YAPILANDIRMASI (SQL Server)
        // ---------------------------------------------------------
        services.AddDbContext<VaultGuardDbContext>(options =>
        {
            var connectionString = configuration.GetConnectionString("DefaultConnection");

            if (string.IsNullOrWhiteSpace(connectionString))
                throw new InvalidOperationException("Database connection string is missing!");

            options.UseSqlServer(connectionString, sqlOptions =>
            {
                // MigrationsAssembly ismine dikkat et: Proje adýnla birebir ayný olmalý
                sqlOptions.MigrationsAssembly("VaultGuard.Infrastructure");
                sqlOptions.CommandTimeout(30); // DoS korumasý
            });

            // Performans ve Güvenlik: Veri okurken gereksiz tracking yapma
            options.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking);
        });

        // Repository Kayýtlarý (Persistence klasöründen çekiliyor)
        services.AddScoped<IUserRepository, UserRepository>();

        return services;
    }

    public static IServiceCollection AddCorsPolicy(this IServiceCollection services)
    {
        services.AddCors(options =>
        {
            options.AddPolicy("VaultGuardPolicy", builder =>
            {
                builder
                    .WithOrigins("http://localhost:3000", "http://localhost:5173") // Sadece güvenilir frontend adresleri
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials(); // Güvenli çerezler (HTTP-Only) için zorunlu
            });
        });

        return services;
    }

    public static IServiceCollection AddHealthChecks(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // Altyapý ve Veritabaný saðlýk denetimi
        services.AddHealthChecks()
            .AddDbContextCheck<VaultGuardDbContext>("database")
            .AddCheck<DatabaseHealthCheck>("database_detailed");

        return services;
    }
}