using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Claims;
using System.Text;

namespace VaultGuard.WebAPI.Extensions;

public static class JwtRegistration
{
    public static IServiceCollection AddJwtAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var jwtSettings = configuration.GetSection("Jwt");

        var secretKey = jwtSettings["SecretKey"];
        var issuer = jwtSettings["Issuer"];
        var audience = jwtSettings["Audience"];
        var expiryMinutes = jwtSettings["ExpiryMinutes"];

        // GÜVENLÝK DOÐRULAMASI: Eksik ayarla uygulama baþlamasýn (Fail-Fast)
        ValidateJwtSettings(secretKey, issuer, audience, expiryMinutes);

        var key = Encoding.UTF8.GetBytes(secretKey!);

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.SaveToken = true;
            options.RequireHttpsMetadata = true; // Üretim ortamýnda HTTPS zorunlu

            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),

                ValidateIssuer = true,
                ValidIssuer = issuer,

                ValidateAudience = true,
                ValidAudience = audience,

                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero, // Tolerans süresini 0 yaparak güvenliði maksimize ediyoruz

                // SÝBER GÜVENLÝK: Claim eþleþmelerini garanti altýna alýyoruz
                NameClaimType = ClaimTypes.NameIdentifier,
                RoleClaimType = ClaimTypes.Role,

                RequireExpirationTime = true,
                RequireSignedTokens = true
            };

            options.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = context =>
                {
                    if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                    {
                        context.Response.Headers.Add("Token-Expired", "true");
                    }
                    return Task.CompletedTask;
                },

                OnChallenge = context =>
                {
                    // 401 Unauthorized - IResult formatýnda standardize edildi
                    context.HandleResponse();
                    context.Response.StatusCode = 401;
                    context.Response.ContentType = "application/json";

                    var result = System.Text.Json.JsonSerializer.Serialize(new
                    {
                        success = false,
                        message = "Eriþim reddedildi. Geçerli bir kimlik doðrulamasý gerekiyor.",
                        errorCode = "ERR_UNAUTHORIZED"
                    });

                    return context.Response.WriteAsync(result);
                },

                OnForbidden = context =>
                {
                    // 403 Forbidden - Yetki hatasý standardize edildi
                    context.Response.StatusCode = 403;
                    context.Response.ContentType = "application/json";

                    var result = System.Text.Json.JsonSerializer.Serialize(new
                    {
                        success = false,
                        message = "Bu iþlem için gerekli yetkiye sahip deðilsiniz.",
                        errorCode = "ERR_FORBIDDEN"
                    });

                    return context.Response.WriteAsync(result);
                }
            };
        });

        return services;
    }

    private static void ValidateJwtSettings(
        string? secretKey,
        string? issuer,
        string? audience,
        string? expiryMinutes)
    {
        if (string.IsNullOrWhiteSpace(secretKey) || secretKey.Length < 32)
            throw new InvalidOperationException("HATA: JWT SecretKey eksik veya çok kýsa (Min 32 karakter olmalý)!");

        if (string.IsNullOrWhiteSpace(issuer))
            throw new InvalidOperationException("HATA: JWT Issuer ayarý eksik!");

        if (string.IsNullOrWhiteSpace(audience))
            throw new InvalidOperationException("HATA: JWT Audience ayarý eksik!");

        if (!int.TryParse(expiryMinutes, out _))
            throw new InvalidOperationException("HATA: JWT ExpiryMinutes geçersiz!");
    }
}