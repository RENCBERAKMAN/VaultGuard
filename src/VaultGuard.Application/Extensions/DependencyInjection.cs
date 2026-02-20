using FluentValidation;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;
using VaultGuard.Application.Interfaces;
using VaultGuard.Application.Services;

namespace VaultGuard.Application.Extensions;

public static class DependencyInjection
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services)
    {
        // AutoMapper
        services.AddAutoMapper(Assembly.GetExecutingAssembly());

        // FluentValidation
        services.AddValidatorsFromAssembly(Assembly.GetExecutingAssembly());

        // Application Services
        services.AddScoped<ISecretService, SecretService>();
        services.AddScoped<IAuditLogService, AuditLogService>();

        return services;
    }
}