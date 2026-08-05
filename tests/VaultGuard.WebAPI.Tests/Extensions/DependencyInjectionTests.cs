using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;
using VaultGuard.Infrastructure.Persistence;
using VaultGuard.Application.Interfaces;
using Xunit;

namespace VaultGuard.WebAPI.Tests.Extensions;

/// <summary>
/// Dependency Injection (DI) container'ının doğru yapılandırıldığını test eden kapsamlı test sınıfı.
/// 
/// TEST KAPSAMI:
/// 1. Service Lifetime Validation (Scoped, Singleton, Transient)
/// 2. Service Resolution (GetRequiredService ile gerçek çözümleme)
/// 3. Dependency Graph Integrity (eksik/kırık bağımlılık tespiti)
/// 4. Options Pattern Validation (IOptions<T> yapılandırması)
/// 5. DbContext Configuration (connection string, migrations)
/// 6. Cross-Layer Dependencies (Application → Infrastructure → Domain)
/// 
/// NEDEN ÖNEMLİ?
/// DI container yanlış yapılandırılırsa:
/// - Runtime'da MissingMethodException
/// - Circular dependency hatası
/// - Memory leak (yanlış lifetime)
/// - Configuration hatası (options null)
/// - Database connection hatası
/// 
/// Bu testler Production'a çıkmadan önce bu sorunları yakalar.
/// 
/// TASARIM KARARLARI:
/// - Mock kullanılmaz (gerçek DI container test edilir)
/// - Her test izole edilmiştir (kendi ServiceProvider'ı var)
/// - Configuration In-Memory olarak sağlanır (appsettings.json gerektirmez)
/// - Dispose pattern doğru uygulanır (ServiceProvider dispose edilir)
/// 
/// GÜVENLİK:
/// - Test ortamında sensitive data yok (connection string in-memory)
/// - Production secrets test edilmez (mock configuration kullanılır)
/// </summary>
public class DependencyInjectionTests : IDisposable
{
    // ============================================================================
    // FIELDS & SETUP
    // ============================================================================

    /// <summary>
    /// Test için kullanılan ServiceProvider.
    /// Her test kendi provider'ını oluşturur ama class-level field de tutulur.
    /// Dispose pattern için gerekli.
    /// </summary>
    private ServiceProvider? _serviceProvider;

    /// <summary>
    /// Test configuration (in-memory).
    /// appsettings.json yerine kod içinde yapılandırma.
    /// </summary>
    private IConfiguration _configuration;

    public DependencyInjectionTests()
    {
        // In-memory configuration oluştur
        _configuration = BuildTestConfiguration();
    }

    /// <summary>
    /// Test sonunda ServiceProvider'ı dispose et.
    /// Memory leak önleme.
    /// </summary>
    public void Dispose()
    {
        _serviceProvider?.Dispose();
    }

    // ============================================================================
    // CONFIGURATION BUILDER
    // ============================================================================

    /// <summary>
    /// Test için in-memory configuration oluşturur.
    /// 
    /// İÇERİK:
    /// - ConnectionStrings: Test database (SQLite in-memory)
    /// - JwtSettings: Test JWT yapılandırması
    /// - Logging: Test log seviyeleri
    /// 
    /// NEDEN IN-MEMORY?
    /// - appsettings.json'a bağımlı olmaz
    /// - Test ortamında kolayca override edilebilir
    /// - CI/CD pipeline'da sorun çıkarmaz
    /// </summary>
    private static IConfiguration BuildTestConfiguration()
    {
        var configDictionary = new Dictionary<string, string?>
        {
            // Database connection (SQLite in-memory)
            ["ConnectionStrings:DefaultConnection"] = "DataSource=:memory:",

            // JWT settings
            ["JwtSettings:Issuer"] = "VaultGuard.Test",
            ["JwtSettings:Audience"] = "VaultGuard.Test.Users",
            ["JwtSettings:SecretKey"] = "ThisIsATestSecretKeyForJwtTokenGeneration123!",
            ["JwtSettings:ExpirationMinutes"] = "60",
            ["JwtSettings:RefreshTokenExpirationDays"] = "7",

            // Logging
            ["Logging:LogLevel:Default"] = "Warning",
            ["Logging:LogLevel:Microsoft"] = "Warning",

            // Feature flags (optional)
            ["Features:EnableCaching"] = "false",
            ["Features:EnableRateLimiting"] = "false",
        };

        return new ConfigurationBuilder()
            .AddInMemoryCollection(configDictionary)
            .Build();
    }

    /// <summary>
    /// Tam yapılandırılmış bir ServiceCollection oluşturur.
    /// 
    /// KATMANLAR:
    /// 1. Infrastructure (DbContext, Repositories, External Services)
    /// 2. Application (Services, Business Logic)
    /// 3. WebAPI (Controllers, Middleware - opsiyonel)
    /// 
    /// DI EXTENSION METOD ÇAĞRILARI:
    /// - services.AddInfrastructure(configuration)
    /// - services.AddApplication()
    /// 
    /// NOT: Bu extension metodlar henüz yazılmadıysa bu test FAIL olacak.
    /// Bu da TDD yaklaşımı - test önce yazılır, sonra implementasyon.
    /// </summary>
    private ServiceCollection BuildTestServiceCollection()
    {
        var services = new ServiceCollection();

        // Configuration'ı DI'a ekle (IConfiguration inject edilebilsin)
        services.AddSingleton(_configuration);

        // NOT: Aşağıdaki extension metodlar proje kapsamında yazılmalı
        // Eğer yoksa bu testler compile hatası verecek - bu istenen davranış!

        // Infrastructure layer DI
        // services.AddInfrastructure(_configuration);

        // Application layer DI
        // services.AddApplication();

        // ÇOK ÖNEMLİ: Gerçek proje yapısına göre bu satırları uncomment et!
        // Şimdilik mock/dummy registrations yapıyoruz test amaçlı

        // === DUMMY REGISTRATIONS (GERÇEK PROJE İÇİN KALDIRILACAK) ===

        // DbContext (test için in-memory SQLite)
        services.AddDbContext<VaultGuardDbContext>(options =>
            options.UseSqlite(_configuration.GetConnectionString("DefaultConnection")));

        // Options Pattern
        // services.Configure<JwtSettings>(_configuration.GetSection("JwtSettings"));

        // Repositories (dummy - gerçekte AddInfrastructure içinde olmalı)
        // services.AddScoped<IUserRepository, UserRepository>();

        // Services (dummy - gerçekte AddApplication içinde olmalı)
        // services.AddScoped<IUserService, UserService>();
        // services.AddScoped<IAuthService, AuthService>();

        return services;
    }

    // ============================================================================
    // LIFETIME VALIDATION TESTS
    // ============================================================================

    /// <summary>
    /// DbContext'in Scoped lifetime ile kaydedildiğini doğrular.
    /// 
    /// NEDEN SCOPED?
    /// - DbContext thread-safe değildir
    /// - Her HTTP request için yeni instance gerekir
    /// - Singleton olursa concurrency sorunları çıkar
    /// - Transient olursa çok fazla instance oluşur (performans)
    /// 
    /// TEST MANTIĞI:
    /// ServiceDescriptor'dan lifetime bilgisini okur.
    /// ServiceLifetime.Scoped olduğunu assert eder.
    /// 
    /// BAŞARISIZ OLMA DURUMU:
    /// DbContext Singleton veya Transient olarak kayıtlıysa FAIL.
    /// </summary>
    [Fact]
    public void DbContext_ShouldBeRegistered_WithScopedLifetime()
    {
        // Arrange
        var services = BuildTestServiceCollection();

        // Act
        var descriptor = services.FirstOrDefault(d =>
            d.ServiceType == typeof(VaultGuardDbContext));

        // Assert
        Assert.NotNull(descriptor);
        Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);
    }

    /// <summary>
    /// Repository'lerin Scoped lifetime ile kaydedildiğini doğrular.
    /// 
    /// NEDEN SCOPED?
    /// - Repository pattern DbContext'e bağımlıdır
    /// - DbContext Scoped ise Repository de Scoped olmalı
    /// - Unit of Work pattern için aynı DbContext instance paylaşılmalı
    /// 
    /// TEST EDİLEN REPOSITORY'LER:
    /// - IUserRepository
    /// - ISecretRepository
    /// - IAuditLogRepository
    /// 
    /// NOT: Bu interfaceler henüz yazılmadıysa test skip edilebilir veya
    /// interface'ler yazılana kadar bu test FAIL olur (TDD yaklaşımı).
    /// </summary>
    [Fact(Skip = "Repositories not implemented yet - TDD placeholder")]
    public void Repositories_ShouldBeRegistered_WithScopedLifetime()
    {
        // Arrange
        var services = BuildTestServiceCollection();
        var repositoryTypes = new[]
    {
    typeof(IUserRepository),
    typeof(ISecretRepository),
    typeof(IAuditLogRepository)
    };

        // Act & Assert
        foreach (var repositoryType in repositoryTypes)
        {
            var descriptor = services.FirstOrDefault(d => d.ServiceType == repositoryType);

            Assert.NotNull(descriptor);
            Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);
        }
    }

    /// <summary>
    /// Application layer servislerinin Scoped lifetime ile kaydedildiğini doğrular.
    /// 
    /// NEDEN SCOPED?
    /// - Servisler Repository'lere bağımlıdır
    /// - Repository Scoped ise servis de Scoped olmalı
    /// - Her HTTP request için yeni instance (clean state)
    /// 
    /// TEST EDİLEN SERVİSLER:
    /// - IUserService
    /// - IAuthService
    /// - ISecretService (ileride)
    /// </summary>
    [Fact(Skip = "Services not implemented yet - TDD placeholder")]
    public void ApplicationServices_ShouldBeRegistered_WithScopedLifetime()
    {
        // Arrange
        var services = BuildTestServiceCollection();
        var serviceTypes = new[]
        {
             typeof(IUserService),
             typeof(IAuthService)
        };

        // Act & Assert
        foreach (var serviceType in serviceTypes)
        {
            var descriptor = services.FirstOrDefault(d => d.ServiceType == serviceType);

            Assert.NotNull(descriptor);
            Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);
        }
    }

    /// <summary>
    /// Stateless serislerin Singleton lifetime ile kaydedildiğini doğrular.
    /// 
    /// NEDEN SINGLETON?
    /// - State tutmayan servisler her instance için aynıdır
    /// - Memory efficiency (tek instance tüm request'ler için)
    /// - Thread-safe implementation gereklidir
    /// 
    /// TEST EDİLEN SERVİSLER:
    /// - IPasswordHasher (BCrypt hashing - stateless)
    /// - IJwtProvider (JWT token generation - stateless)
    /// - IEncryptionService (AES encryption - stateless)
    /// - IDateTimeProvider (time abstraction - stateless)
    /// 
    /// GÜVENLİK NOTU:
    /// Bu servisler thread-safe olmalıdır (concurrent kullanım için).
    /// </summary>
    [Fact(Skip = "Infrastructure services not implemented yet - TDD placeholder")]
    public void StatelessServices_ShouldBeRegistered_WithSingletonLifetime()
    {
        // Arrange
        var services = BuildTestServiceCollection();
        var singletonServiceTypes = new[]
        {
            typeof(IPasswordHasher),
            typeof(IEncryptionService)
        };

        // Act & Assert
        foreach (var serviceType in singletonServiceTypes)
        {
            var descriptor = services.FirstOrDefault(d => d.ServiceType == serviceType);

            Assert.NotNull(descriptor);
            Assert.Equal(ServiceLifetime.Singleton, descriptor.Lifetime);
        }
    }

    // ============================================================================
    // SERVICE RESOLUTION TESTS (GERÇEK ÇÖZÜMLEME)
    // ============================================================================

    /// <summary>
    /// DbContext'in DI container'dan başarıyla çözümlendiğini test eder.
    /// 
    /// TEST MANTIĞI:
    /// 1. ServiceProvider oluştur (BuildServiceProvider)
    /// 2. Scope oluştur (CreateScope - Scoped services için gerekli)
    /// 3. GetRequiredService ile DbContext çözümle
    /// 4. Null olmadığını ve doğru tip olduğunu assert et
    /// 
    /// BAŞARISIZ OLMA DURUMU:
    /// - DbContext kayıtlı değilse → InvalidOperationException
    /// - Constructor dependency eksikse → InvalidOperationException
    /// - Configuration hatalıysa → Exception
    /// 
    /// GÜVENLİK:
    /// Connection string test configuration'dan gelir (production secrets yok).
    /// </summary>
    [Fact]
    public void DbContext_ShouldResolve_Successfully()
    {
        // Arrange
        var services = BuildTestServiceCollection();
        _serviceProvider = services.BuildServiceProvider();

        // Act
        using var scope = _serviceProvider.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<VaultGuardDbContext>();

        // Assert
        Assert.NotNull(dbContext);
        Assert.IsType<VaultGuardDbContext>(dbContext);

        // BONUS: Database connection doğrulama
        // Not: In-memory SQLite için CanConnect her zaman true döner
        // Assert.True(dbContext.Database.CanConnect());
    }

    /// <summary>
    /// Repository'lerin DI container'dan başarıyla çözümlendiğini test eder.
    /// 
    /// TEST MANTIĞI:
    /// Her repository için:
    /// 1. GetRequiredService ile çözümle
    /// 2. Null olmadığını assert et
    /// 3. Doğru concrete type olduğunu assert et
    /// 
    /// DEPENDENCY GRAPH TEST:
    /// Repository → DbContext bağımlılığı otomatik çözümlenir.
    /// Eğer DbContext kayıtlı değilse bu test FAIL olur.
    /// </summary>
    [Fact(Skip = "Repositories not implemented yet - TDD placeholder")]
    public void Repositories_ShouldResolve_Successfully()
    {
        // Arrange
        var services = BuildTestServiceCollection();
        _serviceProvider = services.BuildServiceProvider();

        // Act & Assert
        using var scope = _serviceProvider.CreateScope();
        var serviceProvider = scope.ServiceProvider;

        // IUserRepository
        // var userRepository = serviceProvider.GetRequiredService<IUserRepository>();
        // Assert.NotNull(userRepository);
        // Assert.IsAssignableFrom<IUserRepository>(userRepository);

        // ISecretRepository
        // var secretRepository = serviceProvider.GetRequiredService<ISecretRepository>();
        // Assert.NotNull(secretRepository);

        // IAuditLogRepository
        // var auditLogRepository = serviceProvider.GetRequiredService<IAuditLogRepository>();
        // Assert.NotNull(auditLogRepository);
    }

    /// <summary>
    /// Application servislerinin DI container'dan başarıyla çözümlendiğini test eder.
    /// 
    /// DEPENDENCY CHAIN TEST:
    /// Service → Repository → DbContext
    /// 
    /// Tüm dependency chain otomatik çözümlenir.
    /// Herhangi bir bağımlılık eksikse InvalidOperationException.
    /// </summary>
    [Fact(Skip = "Services not implemented yet - TDD placeholder")]
    public void ApplicationServices_ShouldResolve_Successfully()
    {
        // Arrange
        var services = BuildTestServiceCollection();
        _serviceProvider = services.BuildServiceProvider();

        // Act & Assert
        using var scope = _serviceProvider.CreateScope();
        var serviceProvider = scope.ServiceProvider;

        // IUserService
        // var userService = serviceProvider.GetRequiredService<IUserService>();
        // Assert.NotNull(userService);

        // IAuthService
        // var authService = serviceProvider.GetRequiredService<IAuthService>();
        // Assert.NotNull(authService);
    }

    /// <summary>
    /// Infrastructure servislerinin (stateless) DI container'dan başarıyla çözümlendiğini test eder.
    /// 
    /// SINGLETON RESOLUTION:
    /// Singleton servisler scope'a ihtiyaç duymaz.
    /// Direkt ServiceProvider'dan çözümlenebilir.
    /// 
    /// THREAD SAFETY:
    /// Bu servisler concurrent kullanım için thread-safe olmalı.
    /// Test bunu doğrulamaz (ayrı concurrency testleri gerekir).
    /// </summary>
    [Fact(Skip = "Infrastructure services not implemented yet - TDD placeholder")]
    public void InfrastructureServices_ShouldResolve_Successfully()
    {
        // Arrange
        var services = BuildTestServiceCollection();
        _serviceProvider = services.BuildServiceProvider();

        // Act & Assert - Singleton servisler scope gerektirmez

        // IPasswordHasher
        // var passwordHasher = _serviceProvider.GetRequiredService<IPasswordHasher>();
        // Assert.NotNull(passwordHasher);

        // IJwtProvider
        // var jwtProvider = _serviceProvider.GetRequiredService<IJwtProvider>();
        // Assert.NotNull(jwtProvider);
    }

    // ============================================================================
    // CIRCULAR DEPENDENCY DETECTION
    // ============================================================================

    /// <summary>
    /// Circular dependency (döngüsel bağımlılık) olmadığını test eder.
    /// 
    /// CIRCULAR DEPENDENCY NEDİR?
    /// A → B → C → A gibi bir döngü varsa, DI container çözümleyemez.
    /// 
    /// TEST MANTIĞI:
    /// BuildServiceProvider çağrısı Exception fırlatmamalı.
    /// Eğer circular dependency varsa InvalidOperationException fırlatılır.
    /// 
    /// ÖRNEK CIRCULAR DEPENDENCY:
    /// UserService → IUserRepository → UserService (YANLIŞ!)
    /// 
    /// NOT: Bu test sadece basic circular dependency'leri yakalar.
    /// Complex döngüler için daha gelişmiş analiz gerekebilir.
    /// </summary>
    [Fact]
    public void DI_Container_ShouldNotHave_CircularDependencies()
    {
        // Arrange
        var services = BuildTestServiceCollection();

        // Act
        var buildAction = () => services.BuildServiceProvider(
            new ServiceProviderOptions
            {
                // ValidateOnBuild: Build sırasında tüm servisleri resolve etmeyi dener
                // Circular dependency varsa build aşamasında exception fırlatır
                ValidateOnBuild = true,

                // ValidateScopes: Scoped servisin Singleton'dan çözümlenmesini engeller
                ValidateScopes = true
            });

        // Assert - Exception fırlatmamalı
        var exception = Record.Exception(buildAction);
        Assert.Null(exception);
    }

    // ============================================================================
    // OPTIONS PATTERN TESTS
    // ============================================================================

    /// <summary>
    /// IOptions<T> pattern'inin doğru çalıştığını test eder.
    /// 
    /// OPTIONS PATTERN NEDİR?
    /// appsettings.json'daki yapılandırmaların strongly-typed class'lara bind edilmesi.
    /// 
    /// ÖRNEK:
    /// appsettings.json:
    /// {
    ///   "JwtSettings": {
    ///     "Issuer": "VaultGuard",
    ///     "SecretKey": "..."
    ///   }
    /// }
    /// 
    /// Code:
    /// services.Configure<JwtSettings>(configuration.GetSection("JwtSettings"));
    /// 
    /// Kullanım:
    /// var jwtSettings = options.Value;
    /// 
    /// TEST:
    /// IOptions<JwtSettings> çözümlenir ve değerler doğrulanır.
    /// </summary>
    [Fact(Skip = "JwtSettings not implemented yet - TDD placeholder")]
    public void JwtSettings_ShouldBind_FromConfiguration()
    {
        // Arrange
        var services = BuildTestServiceCollection();

        // JwtSettings configuration binding (gerçek projede extension method içinde)
        // services.Configure<JwtSettings>(_configuration.GetSection("JwtSettings"));

        _serviceProvider = services.BuildServiceProvider();

        // Act
        // var jwtOptions = _serviceProvider.GetRequiredService<IOptions<JwtSettings>>();
        // var jwtSettings = jwtOptions.Value;

        // Assert
        // Assert.NotNull(jwtSettings);
        // Assert.Equal("VaultGuard.Test", jwtSettings.Issuer);
        // Assert.Equal("VaultGuard.Test.Users", jwtSettings.Audience);
        // Assert.NotEmpty(jwtSettings.SecretKey);
        // Assert.Equal(60, jwtSettings.ExpirationMinutes);
    }

    /// <summary>
    /// IOptions<T> validation'ın çalıştığını test eder.
    /// 
    /// OPTIONS VALIDATION:
    /// DataAnnotations ile options class'ı validate edilebilir.
    /// 
    /// ÖRNEK:
    /// public class JwtSettings
    /// {
    ///     [Required]
    ///     public string Issuer { get; set; }
    ///     
    ///     [Range(1, 1440)]
    ///     public int ExpirationMinutes { get; set; }
    /// }
    /// 
    /// Registration:
    /// services.AddOptions<JwtSettings>()
    ///     .Bind(configuration.GetSection("JwtSettings"))
    ///     .ValidateDataAnnotations()
    ///     .ValidateOnStart();
    /// 
    /// TEST:
    /// Geçersiz yapılandırma ile options çözümlendiğinde exception fırlatılır.
    /// </summary>
    [Fact(Skip = "Options validation not implemented yet")]
    public void JwtSettings_WithInvalidConfiguration_ShouldThrowException()
    {
        // Arrange - Geçersiz configuration
        var invalidConfig = new Dictionary<string, string?>
        {
            ["JwtSettings:Issuer"] = "", // Required but empty - INVALID
            ["JwtSettings:SecretKey"] = "short", // Too short - INVALID
            ["JwtSettings:ExpirationMinutes"] = "0" // Out of range - INVALID
        };

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(invalidConfig)
            .Build();

        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);

        // Options registration with validation
        // services.AddOptions<JwtSettings>()
        //     .Bind(configuration.GetSection("JwtSettings"))
        //     .ValidateDataAnnotations()
        //     .ValidateOnStart(); // Validation on app start

        // Act
        var buildAction = () => services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true });

        // Assert - OptionsValidationException beklenir
        // var exception = Assert.Throws<OptionsValidationException>(buildAction);
        // Assert.Contains("Issuer", exception.Message);
    }

    // ============================================================================
    // SCOPE ISOLATION TESTS
    // ============================================================================

    /// <summary>
    /// Scoped servislerin farklı scope'larda farklı instance olduğunu test eder.
    /// 
    /// SCOPED LIFETIME:
    /// - Aynı scope içinde aynı instance
    /// - Farklı scope'larda farklı instance
    /// 
    /// TEST:
    /// 1. Scope1 oluştur → DbContext1 çözümle
    /// 2. Scope2 oluştur → DbContext2 çözümle
    /// 3. DbContext1 != DbContext2 (farklı instance'lar)
    /// 
    /// NEDEN ÖNEMLİ?
    /// Eğer Singleton olarak kayıtlıysa tüm scope'lar aynı instance kullanır.
    /// Bu DbContext için ciddi concurrency sorunlarına yol açar.
    /// </summary>
    [Fact]
    public void ScopedServices_ShouldBe_DifferentInstances_InDifferentScopes()
    {
        // Arrange
        var services = BuildTestServiceCollection();
        _serviceProvider = services.BuildServiceProvider();

        // Act
        VaultGuardDbContext dbContext1;
        VaultGuardDbContext dbContext2;

        using (var scope1 = _serviceProvider.CreateScope())
        {
            dbContext1 = scope1.ServiceProvider.GetRequiredService<VaultGuardDbContext>();
        }

        using (var scope2 = _serviceProvider.CreateScope())
        {
            dbContext2 = scope2.ServiceProvider.GetRequiredService<VaultGuardDbContext>();
        }

        // Assert - Farklı instance'lar olmalı
        Assert.NotSame(dbContext1, dbContext2);
    }

    /// <summary>
    /// Scoped servislerin aynı scope içinde aynı instance olduğunu test eder.
    /// 
    /// TEST:
    /// 1. Scope oluştur
    /// 2. DbContext1 çözümle
    /// 3. DbContext2 çözümle (aynı scope'ta)
    /// 4. DbContext1 == DbContext2 (aynı instance)
    /// 
    /// NEDEN ÖNEMLİ?
    /// Unit of Work pattern için aynı DbContext instance paylaşılmalı.
    /// Farklı instance'lar change tracking'i bozar.
    /// </summary>
    [Fact]
    public void ScopedServices_ShouldBe_SameInstance_InSameScope()
    {
        // Arrange
        var services = BuildTestServiceCollection();
        _serviceProvider = services.BuildServiceProvider();

        // Act & Assert
        using var scope = _serviceProvider.CreateScope();
        var dbContext1 = scope.ServiceProvider.GetRequiredService<VaultGuardDbContext>();
        var dbContext2 = scope.ServiceProvider.GetRequiredService<VaultGuardDbContext>();

        // Aynı instance olmalı
        Assert.Same(dbContext1, dbContext2);
    }

    /// <summary>
    /// Singleton servislerin her scope'ta aynı instance olduğunu test eder.
    /// 
    /// SINGLETON LIFETIME:
    /// Uygulama boyunca tek instance (application lifetime).
    /// 
    /// TEST:
    /// 1. Scope1 → Service1 çözümle
    /// 2. Scope2 → Service2 çözümle
    /// 3. Service1 == Service2 (aynı instance)
    /// 
    /// GÜVENLİK:
    /// Singleton servisler thread-safe olmalı (concurrent access).
    /// </summary>
    [Fact(Skip = "Singleton services not implemented yet")]
    public void SingletonServices_ShouldBe_SameInstance_AcrossScopes()
    {
        // Arrange
        var services = BuildTestServiceCollection();
        _serviceProvider = services.BuildServiceProvider();

        // Act
        object service1;
        object service2;

        using (var scope1 = _serviceProvider.CreateScope())
        {
            // service1 = scope1.ServiceProvider.GetRequiredService<IPasswordHasher>();
        }

        using (var scope2 = _serviceProvider.CreateScope())
        {
            // service2 = scope2.ServiceProvider.GetRequiredService<IPasswordHasher>();
        }

        // Assert - Aynı instance olmalı
        // Assert.Same(service1, service2);
    }

    // ============================================================================
    // CONFIGURATION VALIDATION TESTS
    // ============================================================================

    /// <summary>
    /// Connection string'in yapılandırmadan doğru okunduğunu test eder.
    /// 
    /// TEST:
    /// Configuration'dan connection string oku ve validate et.
    /// 
    /// GÜVENLİK:
    /// Production'da connection string User Secrets veya Key Vault'tan gelir.
    /// Test ortamında in-memory configuration kullanılır.
    /// </summary>
    [Fact]
    public void ConnectionString_ShouldBe_ConfiguredCorrectly()
    {
        // Arrange & Act
        var connectionString = _configuration.GetConnectionString("DefaultConnection");

        // Assert
        Assert.NotNull(connectionString);
        Assert.NotEmpty(connectionString);

        // Test ortamında SQLite in-memory kullanıyoruz
        Assert.Contains(":memory:", connectionString);
    }

    /// <summary>
    /// Tüm required configuration key'lerinin mevcut olduğunu test eder.
    /// 
    /// REQUIRED KEYS:
    /// - ConnectionStrings:DefaultConnection
    /// - JwtSettings:Issuer
    /// - JwtSettings:SecretKey
    /// - JwtSettings:ExpirationMinutes
    /// 
    /// TEST:
    /// Her key için configuration'dan oku, null/empty değil assert et.
    /// </summary>
    [Fact]
    public void RequiredConfigurationKeys_ShouldExist()
    {
        // Arrange
        var requiredKeys = new[]
        {
            "ConnectionStrings:DefaultConnection",
            "JwtSettings:Issuer",
            "JwtSettings:Audience",
            "JwtSettings:SecretKey",
            "JwtSettings:ExpirationMinutes"
        };

        // Act & Assert
        foreach (var key in requiredKeys)
        {
            var value = _configuration[key];
            Assert.False(string.IsNullOrEmpty(value),
                $"Configuration key '{key}' is missing or empty.");
        }
    }
}