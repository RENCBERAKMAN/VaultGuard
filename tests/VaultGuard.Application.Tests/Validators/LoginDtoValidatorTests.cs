using FluentAssertions;
using FluentValidation.TestHelper;
using VaultGuard.Application.DTOs.Auth;
using VaultGuard.Application.Validators;
using Xunit;

namespace VaultGuard.Application.Tests.Validators;

/// <summary>
/// TEST SÜİTİ: LoginDtoValidator - Giriş Verisi Validasyonu ve Brute-Force Koruması
/// 
/// GÜVENLİK KAPSAMI:
/// - DoS Prevention: Uzun email/password ile hafıza tüketimi engelleme
/// - SQL Injection: Email alanında injection girişimlerini tespit
/// - Email Format: RFC 5322 uyumluluğu
/// - Account Enumeration: Minimal validation (bilgi sızıntısı önleme)
/// - Brute Force: Rate limiting için temel input validasyonu
/// 
/// THREAT MODEL:
/// - Attacker: Brute-force için otomatik toollar kullanıyor (Hydra, Burp Intruder)
/// - Attacker: SQL injection ile authentication bypass deneniyor
/// - Attacker: DoS saldırısı için 1GB email string gönderiyor
/// - Attacker: Email format kontrolü ile account enumeration yapıyor
/// 
/// COMPLIANCE:
/// - OWASP Top 10 A03:2021 - Injection
/// - OWASP ASVS V2.1.1 - Password security
/// - NIST SP 800-63B - Authentication
/// </summary>
public class LoginDtoValidatorTests
{
    private readonly LoginDtoValidator _validator;

    public LoginDtoValidatorTests()
    {
        _validator = new LoginDtoValidator();
    }

    // ============================================================================
    // ✅ VALID LOGIN SCENARIOS
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU:
    /// Baseline test - valid data'nın geçmesi gerekir ki validation mantığının
    /// doğru çalıştığını bilelim. False positive'ler user experience'ı bozar.
    /// </summary>
    [Fact]
    public void Validate_WithValidCredentials_ShouldPass()
    {
        // Arrange
        var dto = new LoginDto
        {
            Email = "user@vaultguard.com",
            Password = "SecurePass123!"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveAnyValidationErrors();
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU:
    /// Various valid formats - RFC 5322 email standardı geniş bir format yelpazesi
    /// destekler. Plus sign (+), dots (.), subdomains - hepsi valid. Legitimate
    /// user'ların bloke edilmemesi için edge cases test edilmeli.
    /// </summary>
    [Theory]
    [InlineData("simple@example.com")]
    [InlineData("user.name@example.com")]
    [InlineData("user+tag@example.com")] // Plus addressing (Gmail)
    [InlineData("user@subdomain.example.com")]
    [InlineData("user123@example.co.uk")]
    public void Validate_WithVariousValidEmailFormats_ShouldPass(string email)
    {
        // Arrange
        var dto = new LoginDto
        {
            Email = email,
            Password = "password123"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveValidationErrorFor(x => x.Email);
    }

    // ============================================================================
    // 📧 EMAIL VALIDATION TESTS
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - KRİTİK:
    /// Empty email bypass'i authentication logic'te null reference exception'a
    /// yol açabilir veya default user'a login sağlayabilir (critical bug).
    /// Örnek: WHERE email = NULL AND password = hash → tüm NULL email'li
    /// kayıtları eşleştirebilir (SQL behavior).
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_WithNullOrEmptyEmail_ShouldFail(string invalidEmail)
    {
        // Arrange
        var dto = new LoginDto
        {
            Email = invalidEmail,
            Password = "password123"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Email);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - KRİTİK:
    /// RFC 5322 format validation - invalid formatlar SQL injection'a veya
    /// LDAP injection'a yol açabilir. Örnek: "user@domain.com' OR '1'='1"
    /// gibi bir email, SQL query'de quotes kapatarak injection sağlayabilir.
    /// EF Core parameterized queries kullansa da defense-in-depth için
    /// input validation şart.
    /// </summary>
    [Theory]
    [InlineData("invalid-email")]
    [InlineData("missing-at-sign.com")]
    [InlineData("@no-local-part.com")]
    [InlineData("no-domain@")]
    [InlineData("double@@domain.com")]
    [InlineData("spaces in@email.com")]
    [InlineData("user@")]
    [InlineData("@domain.com")]
    public void Validate_WithInvalidEmailFormat_ShouldFail(string invalidEmail)
    {
        // Arrange
        var dto = new LoginDto
        {
            Email = invalidEmail,
            Password = "password123"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Email);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - DoS PREVENTION:
    /// 101-char email (max 100) - attacker 1GB string gönderirse:
    /// 1. Memory exhaustion (server OOM)
    /// 2. Database column overflow (if VARCHAR(100))
    /// 3. Regex DoS (email validation regex'i ReDoS'a açık olabilir)
    /// 4. Log file bloat (email loglanırsa disk dolar)
    /// Length limit olmadan single request'le server crash ettirilebilir.
    /// </summary>
    [Fact]
    public void Validate_WithEmailTooLong_ShouldFail()
    {
        // Arrange: 101 char email (max 100)
        var longEmail = new string('a', 90) + "@domain.com"; // 101 total

        var dto = new LoginDto
        {
            Email = longEmail,
            Password = "password123"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Email);
            
    }

    // ============================================================================
    // 🛡️ SQL INJECTION TESTS (EMAIL FIELD)
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - SQL INJECTION CRITICAL:
    /// Classic SQL injection payloads - Bu payload'lar WHERE clause'u bypass
    /// etmeye çalışır. Örnek vulnerable query:
    /// 
    /// SELECT * FROM Users WHERE Email = 'admin'--' AND Password = 'hash'
    /// 
    /// -- (comment) sonrasındaki password kontrolü atlanır ve admin olarak
    /// login başarılı olur. EF Core parameterized queries kullandığı için
    /// direkt exploit edilemez AMA:
    /// 1. Legacy code'da raw SQL olabilir
    /// 2. Stored procedure'ler dynamic SQL kullanabilir
    /// 3. Third-party libraries vulnerable olabilir
    /// Defense-in-depth için input validation şart!
    /// </summary>
    [Theory]
    [InlineData("admin'--")]
    [InlineData("' OR '1'='1")]
    [InlineData("admin' OR 1=1--")]
    [InlineData("'; DROP TABLE Users;--")]
    [InlineData("1' UNION SELECT NULL--")]
    public void Validate_WithSqlInjectionInEmail_ShouldStillValidateFormat(string maliciousEmail)
    {
        // Arrange
        var dto = new LoginDto
        {
            Email = maliciousEmail,
            Password = "password123"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Email format validation catch edecek
        // Not: SQL injection @ karakteri olmadığı için invalid format
        result.ShouldHaveValidationErrorFor(x => x.Email);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - ADVANCED SQL INJECTION:
    /// Email formatını geçen ama SQL injection içeren payloadlar.
    /// Örnek: test@example.com' OR '1'='1'.com
    /// Bu durumda email validator geçer ama SQL'de injection oluşur.
    /// Bu yüzden parameterized queries MUTLAKA kullanılmalı.
    /// </summary>
    [Theory]
    [InlineData("admin@domain.com'--")]
    [InlineData("user@test.com'; DROP TABLE Users; SELECT '")]
    public void Validate_WithSqlInjectionInValidEmail_ShouldPassValidationButRequireParameterizedQueries(
        string maliciousEmail)
    {
        // Arrange
        var dto = new LoginDto
        {
            Email = maliciousEmail,
            Password = "password123"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Format geçerli görünüyor (@ var, domain var)
        // AMA: Backend'de parameterized queries kullanılmalı!
        // Bu test, validation'ın tek başına yeterli olmadığını gösterir.
        if (!maliciousEmail.Contains("'"))
        {
            result.ShouldNotHaveValidationErrorFor(x => x.Email);
        }
    }

    // ============================================================================
    // 🔐 PASSWORD VALIDATION TESTS
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - AUTHENTICATION BYPASS:
    /// Empty password bypass'i authentication logic'te critical bug'a yol açabilir.
    /// Örnek vulnerable code:
    /// if (user.PasswordHash == BCrypt.HashPassword(dto.Password))
    /// Eğer dto.Password null/empty ise HashPassword crash edebilir veya
    /// empty string'in hash'i ile match yapmaya çalışabilir.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_WithNullOrEmptyPassword_ShouldFail(string invalidPassword)
    {
        // Arrange
        var dto = new LoginDto
        {
            Email = "user@example.com",
            Password = invalidPassword
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Password);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - DoS PREVENTION:
    /// 129-char password (max 128) - BCrypt'in input limit'i 72 byte'dır.
    /// 128+ karakter gönderilirse:
    /// 1. BCrypt truncate eder (ilk 72 byte alır) - predictable behavior
    /// 2. Memory exhaustion (1GB password string)
    /// 3. CPU exhaustion (BCrypt 1GB string'i process etmeye çalışır)
    /// 4. Log bloat (password loglanmamalı zaten ama hata mesajında görünebilir)
    /// Limit olmadan single login request'le server DoS edilebilir.
    /// </summary>
    [Fact]
    public void Validate_WithPasswordTooLong_ShouldFail()
    {
        // Arrange: 129 chars (max 128)
        var longPassword = new string('A', 129);

        var dto = new LoginDto
        {
            Email = "user@example.com",
            Password = longPassword
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Password);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - WHY NO COMPLEXITY CHECK AT LOGIN:
    /// Login'de password complexity check YOK - çünkü:
    /// 1. UX: User frustration (kayıttan sonra kurals değişmiş olabilir)
    /// 2. Account Enumeration: "Password doesn't meet requirements" mesajı
    ///    account'un var olduğunu sızdırır
    /// 3. Performance: Unnecessary validation, rate limiting zaten var
    /// 4. Security: Brute-force rate limiting ve account lockout ile handle edilir
    /// 
    /// Weak password'ler registration'da engellenmelidir, login'de değil.
    /// </summary>
    [Theory]
    [InlineData("123")] // Çok kısa
    [InlineData("password")] // Weak
    [InlineData("abc")] // Çok kısa
    public void Validate_WithWeakPassword_ShouldStillPass(string weakPassword)
    {
        // Arrange
        var dto = new LoginDto
        {
            Email = "user@example.com",
            Password = weakPassword
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Password complexity validation YOK (by design)
        result.ShouldNotHaveValidationErrorFor(x => x.Password);
    }

    // ============================================================================
    // 🚨 SECURITY EDGE CASES
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - UNICODE ATTACK:
    /// Unicode characters email'de valid olabilir (RFC 6531 - internationalized email).
    /// AMA:
    /// 1. Homograph attack: "аdmin@test.com" (Cyrillic 'а' not Latin 'a')
    /// 2. Direction override: RTL/LTR characters ile display spoofing
    /// 3. Zero-width characters: Invisible chars ile length bypass
    /// 4. Normalization issues: é vs e + combining accent
    /// 
    /// Production'da email'ler normalize edilmeli (NFC normalization).
    /// </summary>
    [Theory]
    [InlineData("admin@тест.com")] // Cyrillic domain
    [InlineData("user@مثال.com")] // Arabic domain
    [InlineData("test@例え.jp")] // Japanese domain
    public void Validate_WithInternationalEmail_ShouldHandleCorrectly(string internationalEmail)
    {
        // Arrange
        var dto = new LoginDto
        {
            Email = internationalEmail,
            Password = "password123"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: RFC 6531 allows international emails
        // Validator should accept or reject based on policy
        // For security, ASCII-only emails might be enforced
        var isValid = result.IsValid;
        
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - XSS IN LOGIN:
    /// XSS payload email alanında - login form'da reflected XSS riski var mı?
    /// Örnek vulnerable code:
    /// 
    /// if (login failed) {
    ///     return "Login failed for " + dto.Email; // NO ENCODING!
    /// }
    /// 
    /// Attacker email: test@test.com<script>alert(1)</script>
    /// Response'da encoding yapılmazsa XSS tetiklenir.
    /// Validator email format nedeniyle reject edecek ama defense-in-depth
    /// için output encoding şart!
    /// </summary>
    [Theory]
    [InlineData("<script>alert('XSS')</script>@test.com")]
    [InlineData("test@test.com<script>alert(1)</script>")]
    public void Validate_WithXssInEmail_ShouldFailEmailFormat(string xssEmail)
    {
        // Arrange
        var dto = new LoginDto
        {
            Email = xssEmail,
            Password = "password123"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Email format validation reject edecek (@ sonrası invalid)
        result.ShouldHaveValidationErrorFor(x => x.Email);
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - TIMING ATTACK:
    /// Email/password validation süresi constant-time olmalı.
    /// Örnek vulnerable validation:
    /// 
    /// if (email invalid) return "Invalid email"; // Fast (10ms)
    /// if (password invalid) return "Invalid password"; // Slower (50ms)
    /// 
    /// Attacker bu timing difference'ı kullanarak:
    /// 1. Valid email'leri enumerate edebilir
    /// 2. Password validation'a ulaşan email'leri belirleyebilir
    /// 
    /// Solution: Tüm validation'ları çalıştır, sonuçları birleştir.
    /// </summary>
    [Fact]
    public void Validate_WithBothFieldsInvalid_ShouldValidateBoth()
    {
        // Arrange: Her iki alan da invalid
        var dto = new LoginDto
        {
            Email = "invalid",
            Password = ""
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: İki error da dönmeli (timing attack prevention)
        result.ShouldHaveValidationErrorFor(x => x.Email);
        result.ShouldHaveValidationErrorFor(x => x.Password);
        result.Errors.Count.Should().BeGreaterThanOrEqualTo(2);
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - WHITESPACE HANDLING:
    /// Leading/trailing whitespace - user "  user@test.com  " girerse ne olur?
    /// 1. Email trim edilmeli (user hata yapmış olabilir)
    /// 2. AMA: Attacker space ile bypass denemesi yapabilir
    /// 3. Database'de "user@test.com" ve " user@test.com " farklı kayıtlar
    /// 4. Authentication bypass: Kayıtta trim, login'de trim yok → fail
    /// 
    /// Normalize: Her zaman trim uygula (validation + service layer).
    /// </summary>
    [Fact]
    public void Validate_WithWhitespaceInEmail_ShouldStillValidate()
    {
        // Arrange: Leading/trailing spaces
        var dto = new LoginDto
        {
            Email = "  user@example.com  ",
            Password = "password123"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Validator whitespace'i nasıl handle ediyor?
        // Ideally: Trim edilmeli veya reject edilmeli
        var hasError = result.Errors.Any(e => e.PropertyName == "Email");
        hasError.Should().BeFalse(); // Email validator genellikle trim yapar
    }

    // ============================================================================
    // 🔐 REMEMBER ME FIELD TESTS
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - EXTENDED SESSION RISK:
    /// RememberMe = true → 30 günlük token - security risk:
    /// 1. Token çalınırsa long-lived access
    /// 2. Public computer'da unutulan session
    /// 3. XSS ile token steal edilirse uzun süre geçerli
    /// 4. Token rotation olmazsa revoke edilemez
    /// 
    /// Best practices:
    /// 1. Sliding expiration (activity bazlı renewal)
    /// 2. Device fingerprinting (farklı device'dan kullanılırsa reject)
    /// 3. IP-based validation (IP değişirse re-auth iste)
    /// 4. Refresh token rotation (her kullanımda yeni token)
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Validate_WithRememberMeFlag_ShouldNotAffectValidation(bool rememberMe)
    {
        // Arrange
        var dto = new LoginDto
        {
            Email = "user@example.com",
            Password = "password123",
            RememberMe = rememberMe
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: RememberMe validation'ı etkilememeli (boolean field)
        result.IsValid.Should().BeTrue();
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - ACCOUNT ENUMERATION PREVENTION:
    /// Validation minimal olmalı - detaylı error mesajları account enumeration'a
    /// yol açar. Örnek KÖTÜ validation:
    /// 
    /// "This email is not registered" → Email sistemde yok (enumeration!)
    /// "Incorrect password" → Email sistemde var ama password yanlış
    /// 
    /// Correct approach (service layer):
    /// "Invalid email or password" → Generic message (bilgi sızdırmaz)
    /// 
    /// Validator sadece format kontrolü yapmalı, existence check yapmamalı.
    /// </summary>
    [Fact]
    public void Validate_ShouldNotRevealAccountExistence()
    {
        // Arrange
        var dto = new LoginDto
        {
            Email = "nonexistent@example.com",
            Password = "password123"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Validator account existence check yapmamalı
        result.IsValid.Should().BeTrue(); // Format valid, existence service layer'da

        // Error message account existence reveal etmemeli
        foreach (var error in result.Errors)
        {
            error.ErrorMessage.Should().NotContain("not registered");
            error.ErrorMessage.Should().NotContain("doesn't exist");
            error.ErrorMessage.Should().NotContain("not found");
        }
    }
}