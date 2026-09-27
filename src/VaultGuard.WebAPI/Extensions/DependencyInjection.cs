using VaultGuard.Application.Interfaces;
using VaultGuard.Application.Services;
using VaultGuard.Infrastructure.Persistence;
using VaultGuard.Infrastructure.Security;
using VaultGuard.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using VaultGuard.WebAPI;
using VaultGuard.Application.Validators;
using FluentValidation;

namespace VaultGuard.WebAPI.Extensions;

public static class DependencyInjection
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services)
    {
        // Business Logic Servisleri
        services.AddScoped<IAuthService, AuthService>();
        services.AddScoped<IUserService, UserService>();
        services.AddScoped<ISecretService, SecretService>();
        services.AddScoped<IAuditLogService, AuditLogService>();

        // FluentValidation'ı Application katmanındaki assembly üzerinden kaydediyoruz:
        services.AddValidatorsFromAssembly(typeof(VaultGuard.Application.DTOs.Secrets.CreateSecretDto).Assembly);
        return services;
    }

    public static IServiceCollection AddInfrastructureServices(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddSingleton<IEncryptionService, AesEncryptionService>();
        services.AddSingleton<IPasswordHasher, BCryptPasswordHasher>();
        services.AddScoped<ITokenService, TokenService>();
        services.AddHttpContextAccessor();
        services.AddScoped<ICurrentUserService, CurrentUserService>();
        services.AddJwtAuthentication(configuration);

        // ---------------------------------------------------------
        // VERİTABANI YAPILANDIRMASI (SQL Server)
        // ---------------------------------------------------------
        services.AddDbContext<VaultGuardDbContext>(options =>
        {
            var connectionString = configuration.GetConnectionString("DefaultConnection");

            if (string.IsNullOrWhiteSpace(connectionString))
                throw new InvalidOperationException("Database connection string is missing!");

            options.UseSqlServer(connectionString, sqlOptions =>
            {
                sqlOptions.MigrationsAssembly("VaultGuard.Infrastructure");
                sqlOptions.CommandTimeout(30);
            });

            options.UseQueryTrackingBehavior(QueryTrackingBehavior.NoTracking);
        });

        // Repository Kayıtları
        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<ISecretRepository, SecretRepository>();
        services.AddScoped<IAuditLogRepository, AuditLogRepository>();

        return services;
    }

    public static IServiceCollection AddCorsPolicy(this IServiceCollection services)
    {
        services.AddCors(options =>
        {
            options.AddPolicy("VaultGuardPolicy", builder =>
            {
                builder
                    .WithOrigins("http://localhost:3000", "http://localhost:5173")
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials();
            });
        });

        return services;
    }

    public static IServiceCollection AddHealthChecks(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddHealthChecks()
            .AddDbContextCheck<VaultGuardDbContext>("database")
            .AddCheck<DatabaseHealthCheck>("database_detailed");

        return services;
    }
}