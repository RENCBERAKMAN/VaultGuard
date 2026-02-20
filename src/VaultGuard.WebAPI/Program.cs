using VaultGuard.WebAPI.Middleware;
using VaultGuard.WebAPI.Extensions;
using VaultGuard.Infrastructure.Persistence; // Migration ve DbContext için
using Microsoft.EntityFrameworkCore; // Migrate() metodu için gerekli

var builder = WebApplication.CreateBuilder(args);

// ============================================
// 1. SERVICES REGISTRATION (DI Katmanı)
// ============================================
// Profesyonel Dokunuş: Tüm karmaşık ayarları Extension dosyalarımızdan çekiyoruz.
// Böylece Program.cs tertemiz kalıyor ve hata yapma riskimiz sıfıra iniyor.

// Auth, User ve Token servislerini yükler
builder.Services.AddApplicationServices();

// Veritabanı, JWT, Hashleme ve Şifreleme (AES) servislerini yükler
// SQL Connection String ayarı burada otomatik yapılır!
builder.Services.AddInfrastructureServices(builder.Configuration);

// CORS Politikalarını yükler ("VaultGuardPolicy")
builder.Services.AddCorsPolicy();

// Sağlık kontrolü servislerini yükler
builder.Services.AddHealthChecks(builder.Configuration);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(); // Temel Swagger

var app = builder.Build();

// ============================================
// 2. MIDDLEWARE PIPELINE (Sıralama Kritik!)
// ============================================

// 1. Adım: Gelen isteği logla (RequestLoggingMiddleware)
app.UseMiddleware<RequestLoggingMiddleware>();

// 2. Adım: Hataları yakala ve gizle (GlobalExceptionMiddleware)
app.UseMiddleware<GlobalExceptionMiddleware>();

// Development ortamındaysak Swagger'ı aç
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// CORS Politikası: DependencyInjection.cs içinde tanımladığımız isimle aynı olmalı
app.UseCors("VaultGuardPolicy");

// Kimlik ve Yetki
app.UseAuthentication();
app.UseAuthorization();

// Endpoint'leri eşle
app.MapControllers();
app.MapHealthChecks("/health");

// ============================================
// 3. OTOMATİK VERİTABANI MIGRATION
// ============================================
// Uygulama her başladığında veritabanı yoksa oluşturur, varsa günceller.
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<VaultGuardDbContext>();
        context.Database.Migrate(); // Sihirli komut: Update-Database işlemini otomatik yapar
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "Kritik Hata: Veritabanı migration işlemi yapılamadı.");
    }
}

app.Run();

// ============================================
// 4. TEST ROBOTU İÇİN GİRİŞ KAPISI
// ============================================
// Bu satır sayesinde Integration Test projesi API'yi ayağa kaldırabilir.
public partial class Program { }