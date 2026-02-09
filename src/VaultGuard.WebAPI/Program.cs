using Microsoft.EntityFrameworkCore;
using VaultGuard.Infrastructure.Persistence;
using Microsoft.Extensions.Diagnostics.HealthChecks;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<VaultGuardDbContext>(options =>
{
    options.UseSqlServer(connectionString, sqlOptions =>
    {
        sqlOptions.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery);
        sqlOptions.MigrationsAssembly("VaultGuard.Infrastructure");
        sqlOptions.CommandTimeout(30);
        sqlOptions.EnableRetryOnFailure(5, TimeSpan.FromSeconds(10), null);
    });

    if (builder.Environment.IsDevelopment())
    {
        options.EnableSensitiveDataLogging();
        options.EnableDetailedErrors();
    }
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        if (builder.Environment.IsDevelopment())
        {
            policy.WithOrigins("http://localhost:3000", "http://localhost:5173")
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();
        }
        else
        {
            policy.WithOrigins("https://yourdomain.com")
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();
        }
    });
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddHealthChecks();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseCors("AllowFrontend");

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapControllers();
app.MapHealthChecks("/health");

if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var dbContext = scope.ServiceProvider.GetRequiredService<VaultGuardDbContext>();
    try
    {
        await dbContext.Database.MigrateAsync();
        app.Logger.LogInformation("✅ Database migration completed.");
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "❌ Migration failed.");
    }
}

app.MapGet("/api/ping", () => Results.Ok(new { Message = "VaultGuard API running 🛡️", Timestamp = DateTime.UtcNow }));

app.MapGet("/api/db-test", async (VaultGuardDbContext dbContext) =>
{
    try
    {
        var canConnect = await dbContext.Database.CanConnectAsync();
        return Results.Ok(new { DatabaseConnected = canConnect, Message = canConnect ? "✅ Database OK" : "❌ Database failed" });
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message);
    }
});

app.Run();