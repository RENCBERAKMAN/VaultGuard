using System.Linq;
using FluentAssertions;
using FluentValidation.TestHelper;
using VaultGuard.Application.DTOs.Auth;
using VaultGuard.Application.Validators;
using Xunit;

namespace VaultGuard.Application.Tests.Validators;

/// <summary>
/// TEST SÜİTİ: RegisterDtoValidator - Input Validation & Security Guards
/// 
/// GÜVENLİK KAPSAMI:
/// - XSS (Cross-Site Scripting) prevention
/// - SQL Injection prevention
/// - Path Traversal prevention
/// - OWASP Password Guidelines enforcement
/// - Reserved keyword blocking (privilege escalation prevention)
/// - DoS prevention (length limits)
/// - Unicode attack mitigation
/// 
/// VALIDATION KAPSAMI:
/// - Email format (RFC 5322)
/// - Username pattern (alphanumeric + underscore)
/// - Password complexity (8+ chars, uppercase, lowercase, digit, special)
/// - Password confirmation match
/// - Length limits (min/max)
/// 
/// THREAT MODEL:
/// - Attacker trying to inject malicious scripts via username/email
/// - Attacker trying SQL injection in input fields
/// - Attacker creating "admin" username for privilege escalation
/// - Attacker using weak/common passwords
/// - Attacker using password spraying attacks
/// </summary>
public class RegisterDtoValidatorTests
{
    private readonly RegisterDtoValidator _validator;

    public RegisterDtoValidatorTests()
    {
        _validator = new RegisterDtoValidator();
    }

    // ============================================================================
    // ✅ VALID REGISTRATION SCENARIOS
    // ============================================================================

    [Fact]
    public void Validate_WithValidData_ShouldNotHaveErrors()
    {
        // Arrange: Tüm kuralları geçen geçerli bir kayıt
        var dto = new RegisterDto
        {
            Email = "john.doe@vaultguard.com",
            Username = "john_doe123",
            Password = "SecureP@ssw0rd!",
            ConfirmPassword = "SecureP@ssw0rd!"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Hiç hata olmamalı
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Theory]
    [InlineData("user@example.com", "validuser", "ValidPass123!", "ValidPass123!")]
    [InlineData("test.user+tag@domain.co.uk", "test_user", "MyP@ssword99", "MyP@ssword99")]
    [InlineData("admin@company.org", "company_admin", "C0mplex!Pass", "C0mplex!Pass")]
    public void Validate_WithVariousValidInputs_ShouldPass(
        string email, string username, string password, string confirmPassword)
    {
        // Arrange
        var dto = new RegisterDto
        {
            Email = email,
            Username = username,
            Password = password,
            ConfirmPassword = confirmPassword
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveAnyValidationErrors();
    }

    // ============================================================================
    // 📧 EMAIL VALIDATION TESTS
    // ============================================================================

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_WithNullOrEmptyEmail_ShouldHaveError(string invalidEmail)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Email = invalidEmail };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Email);
            
    }

    [Theory]
    [InlineData("invalid-email")]
    [InlineData("missing-at-sign.com")]
    [InlineData("@no-local-part.com")]
    [InlineData("no-domain@")]
    [InlineData("double@@domain.com")]
    [InlineData("spaces in@email.com")]
    public void Validate_WithInvalidEmailFormat_ShouldHaveError(string invalidEmail)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Email = invalidEmail };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Email);
            
    }

    [Fact]
    public void Validate_WithEmailTooLong_ShouldHaveError()
    {
        // Arrange: 101 char email (max 100)
        var longEmail = new string('a', 90) + "@domain.com"; // 101 chars total

        var dto = CreateValidDto();
        dto = dto with { Email = longEmail };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Email);
            
    }

    // ============================================================================
    // 🚨 XSS PREVENTION TESTS (EMAIL)
    // ============================================================================

    [Theory]
    [InlineData("<script>alert('XSS')</script>@evil.com")]
    [InlineData("user@domain.com<script>")]
    [InlineData("<img src=x onerror=alert('XSS')>@test.com")]
    [InlineData("javascript:alert('XSS')@domain.com")]
    [InlineData("<iframe src='evil.com'>@test.com")]
    public void Validate_WithXssInEmail_ShouldHaveError(string maliciousEmail)
    {
        // Arrange: XSS saldırı girişimi
        var dto = CreateValidDto();
        dto = dto with { Email = maliciousEmail };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: XSS prevention mesajı
        result.ShouldHaveValidationErrorFor(x => x.Email);
            
    }

    // ============================================================================
    // 👤 USERNAME VALIDATION TESTS
    // ============================================================================

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_WithNullOrEmptyUsername_ShouldHaveError(string invalidUsername)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Username = invalidUsername };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Username);
            
    }

    [Theory]
    [InlineData("ab")] // 2 chars (min 3)
    [InlineData("a")] // 1 char
    public void Validate_WithUsernameTooShort_ShouldHaveError(string shortUsername)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Username = shortUsername };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Username);
            
    }

    [Fact]
    public void Validate_WithUsernameTooLong_ShouldHaveError()
    {
        // Arrange: 51 chars (max 50)
        var longUsername = new string('a', 51);

        var dto = CreateValidDto();
        dto = dto with { Username = longUsername };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Username);
            
    }

    [Theory]
    [InlineData("user name")] // Space
    [InlineData("user@name")] // @
    [InlineData("user#name")] // #
    [InlineData("user$name")] // $
    [InlineData("user%name")] // %
    [InlineData("user&name")] // &
    [InlineData("user*name")] // *
    [InlineData("user(name)")] // Parentheses
    [InlineData("user+name")] // Plus
    [InlineData("user=name")] // Equals
    [InlineData("user[name]")] // Brackets
    [InlineData("user{name}")] // Curly braces
    [InlineData("user|name")] // Pipe
    [InlineData("user\\name")] // Backslash
    [InlineData("user/name")] // Forward slash
    [InlineData("user:name")] // Colon
    [InlineData("user;name")] // Semicolon
    [InlineData("user\"name")] // Quote
    [InlineData("user'name")] // Single quote
    [InlineData("user<name>")] // Angle brackets
    [InlineData("user,name")] // Comma
    [InlineData("user?name")] // Question mark
    public void Validate_WithSpecialCharactersInUsername_ShouldHaveError(string invalidUsername)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Username = invalidUsername };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Username);
            
    }

    [Theory]
    [InlineData("valid_username123")] // Valid: underscore
    [InlineData("user.name")] // Valid: dot
    [InlineData("user-name")] // Valid: hyphen
    [InlineData("User123")] // Valid: mixed case + numbers
    [InlineData("user_name.123-test")] // Valid: all allowed chars
    public void Validate_WithValidUsernamePatterns_ShouldPass(string validUsername)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Username = validUsername };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Username için hata olmamalı
        result.ShouldNotHaveValidationErrorFor(x => x.Username);
    }

    // ============================================================================
    // 🚨 XSS PREVENTION TESTS (USERNAME)
    // ============================================================================

    [Theory]
    [InlineData("<script>alert('XSS')</script>")]
    [InlineData("user<script>")]
    [InlineData("<img src=x onerror=alert(1)>")]
    [InlineData("javascript:alert(1)")]
    public void Validate_WithXssInUsername_ShouldHaveError(string maliciousUsername)
    {
        // Arrange: XSS saldırı girişimi
        var dto = CreateValidDto();
        dto = dto with { Username = maliciousUsername };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Special characters nedeniyle reddedilir
        result.ShouldHaveValidationErrorFor(x => x.Username);
            
    }

    // ============================================================================
    // 🛡️ PATH TRAVERSAL PREVENTION
    // ============================================================================

    [Theory]
    [InlineData(".username")] // Starts with dot
    [InlineData("username.")] // Ends with dot
    public void Validate_WithDotsAtBoundaries_ShouldHaveError(string invalidUsername)
    {
        // Arrange: Path traversal prevention
        var dto = CreateValidDto();
        dto = dto with { Username = invalidUsername };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Username);
            
    }

    [Theory]
    [InlineData("user..name")] // Consecutive dots
    [InlineData("test...name")] // Triple dots
    public void Validate_WithConsecutiveDots_ShouldHaveError(string invalidUsername)
    {
        // Arrange: Path traversal prevention (..)
        var dto = CreateValidDto();
        dto = dto with { Username = invalidUsername };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Username);
            
    }

    // ============================================================================
    // 🔐 RESERVED KEYWORDS PREVENTION (PRIVILEGE ESCALATION)
    // ============================================================================

    [Theory]
    [InlineData("admin")]
    [InlineData("Admin")]
    [InlineData("ADMIN")]
    [InlineData("AdMiN")] // Case-insensitive
    [InlineData("administrator")]
    [InlineData("Administrator")]
    [InlineData("root")]
    [InlineData("ROOT")]
    [InlineData("system")]
    [InlineData("System")]
    [InlineData("superuser")]
    [InlineData("sysadmin")]
    [InlineData("moderator")]
    [InlineData("support")]
    [InlineData("helpdesk")]
    [InlineData("vaultguard")]
    [InlineData("VaultGuard")]
    public void Validate_WithReservedKeyword_ShouldHaveError(string reservedUsername)
    {
        // Arrange: Privilege escalation attempt
        var dto = CreateValidDto();
        dto = dto with { Username = reservedUsername };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Username);
            
    }

    [Theory]
    [InlineData("admin123")] // Contains "admin"
    [InlineData("user_admin")] // Contains "admin"
    [InlineData("rootuser")] // Contains "root"
    [InlineData("system_user")] // Contains "system"
    public void Validate_WithUsernameContainingReservedKeyword_ShouldHaveError(string invalidUsername)
    {
        // Arrange: Partial reserved keyword (still dangerous)
        var dto = CreateValidDto();
        dto = dto with { Username = invalidUsername };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Username);
            
    }

    // ============================================================================
    // 🔒 PASSWORD VALIDATION TESTS
    // ============================================================================

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_WithNullOrEmptyPassword_ShouldHaveError(string invalidPassword)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Password = invalidPassword, ConfirmPassword = invalidPassword };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Password);
            
    }

    [Theory]
    [InlineData("Short1!")] // 7 chars (min 8)
    [InlineData("Abc12!@")] // 7 chars
    [InlineData("1234567")] // 7 chars
    public void Validate_WithPasswordTooShort_ShouldHaveError(string shortPassword)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Password = shortPassword, ConfirmPassword = shortPassword };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Password);
            
    }

    [Fact]
    public void Validate_WithPasswordTooLong_ShouldHaveError()
    {
        // Arrange: 129 chars (max 128)
        var longPassword = new string('A', 129);

        var dto = CreateValidDto();
        dto = dto with { Password = longPassword, ConfirmPassword = longPassword };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Password);
            
    }

    // ============================================================================
    // 💪 PASSWORD COMPLEXITY TESTS (OWASP)
    // ============================================================================

    [Theory]
    [InlineData("alllowercase123!")] // No uppercase
    [InlineData("alllowercase!@#")]
    public void Validate_WithoutUppercase_ShouldHaveError(string weakPassword)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Password = weakPassword, ConfirmPassword = weakPassword };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Password);
            
    }

    [Theory]
    [InlineData("ALLUPPERCASE123!")] // No lowercase
    [InlineData("ALLUPPERCASE!@#")]
    public void Validate_WithoutLowercase_ShouldHaveError(string weakPassword)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Password = weakPassword, ConfirmPassword = weakPassword };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Password);
            
    }

    [Theory]
    [InlineData("NoDigitsHere!")] // No digit
    [InlineData("Password!@#")]
    public void Validate_WithoutDigit_ShouldHaveError(string weakPassword)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Password = weakPassword, ConfirmPassword = weakPassword };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Password);
            
    }

    [Theory]
    [InlineData("NoSpecialChars123")] // No special char
    [InlineData("Password123")]
    public void Validate_WithoutSpecialCharacter_ShouldHaveError(string weakPassword)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Password = weakPassword, ConfirmPassword = weakPassword };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Password);
            
    }

    [Theory]
    [InlineData("ComplexP@ss1")] // Has all requirements
    [InlineData("MyS3cur3P@ssword!")]
    [InlineData("Tr0ub4dor&3")]
    public void Validate_WithComplexPassword_ShouldPass(string complexPassword)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { Password = complexPassword, ConfirmPassword = complexPassword };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Password complexity için hata olmamalı
        result.ShouldNotHaveValidationErrorFor(x => x.Password);
    }

    // ============================================================================
    // 📜 WEAK PASSWORD BLACKLIST TESTS
    // ============================================================================

    [Theory]
    [InlineData("password")]
    [InlineData("Password")]
    [InlineData("PASSWORD")]
    [InlineData("Password1!")]
    [InlineData("12345678")]
    [InlineData("Qwerty123!")]
    [InlineData("Admin123!")]
    [InlineData("Welcome1!")]
    [InlineData("Passw0rd!")]
    [InlineData("P@ssw0rd")]
    [InlineData("Password123!")]
    [InlineData("Abcd1234!")]
    public void Validate_WithCommonWeakPassword_ShouldHaveError(string weakPassword)
    {
        // Arrange: Common password spraying attack list
        var dto = CreateValidDto();
        dto = dto with { Password = weakPassword, ConfirmPassword = weakPassword };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Password);
            
    }

    // ============================================================================
    // 🚫 PASSWORD PREDICTABILITY TESTS
    // ============================================================================

    [Fact]
    public void Validate_WithPasswordContainingUsername_ShouldHaveError()
    {
        // Arrange: Password contains username (predictable!)
        var dto = CreateValidDto();
        dto = dto with
        {
            Username = "johndoe",
            Password = "JohnDoe123!",
            ConfirmPassword = "JohnDoe123!"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Password);
            
    }

    [Fact]
    public void Validate_WithPasswordContainingEmailPrefix_ShouldHaveError()
    {
        // Arrange: Password contains email local part (predictable!)
        var dto = CreateValidDto();
        dto = dto with
        {
            Email = "johndoe@example.com",
            Password = "JohnDoe123!",
            ConfirmPassword = "JohnDoe123!"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Password);
            
    }

    // ============================================================================
    // 🔄 CONFIRM PASSWORD TESTS
    // ============================================================================

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_WithNullOrEmptyConfirmPassword_ShouldHaveError(string invalidConfirm)
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with { ConfirmPassword = invalidConfirm };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.ConfirmPassword);
            
    }

    [Fact]
    public void Validate_WithMismatchedPasswords_ShouldHaveError()
    {
        // Arrange: Password != ConfirmPassword
        var dto = CreateValidDto();
        dto = dto with
        {
            Password = "CorrectP@ss1",
            ConfirmPassword = "WrongP@ss2"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.ConfirmPassword);
            
    }

    [Fact]
    public void Validate_WithMatchingPasswords_ShouldPass()
    {
        // Arrange
        var dto = CreateValidDto();
        dto = dto with
        {
            Password = "MatchingP@ss1",
            ConfirmPassword = "MatchingP@ss1"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: ConfirmPassword için hata olmamalı
        result.ShouldNotHaveValidationErrorFor(x => x.ConfirmPassword);
    }

    // ============================================================================
    // 🌐 UNICODE & INTERNATIONAL CHARACTERS
    // ============================================================================

    [Theory]
    [InlineData("用户名")] // Chinese
    [InlineData("ユーザー")] // Japanese
    [InlineData("사용자")] // Korean
    [InlineData("пользователь")] // Russian
    [InlineData("المستخدم")] // Arabic
    public void Validate_WithUnicodeUsername_ShouldHaveError(string unicodeUsername)
    {
        // Arrange: Unicode characters not allowed (security: ASCII only)
        var dto = CreateValidDto();
        dto = dto with { Username = unicodeUsername };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldHaveValidationErrorFor(x => x.Username);
            
    }

    // ============================================================================
    // 🧪 EDGE CASES & BOUNDARY TESTS
    // ============================================================================

    [Fact]
    public void Validate_WithExactly3CharUsername_ShouldPass()
    {
        // Arrange: Minimum length (3 chars)
        var dto = CreateValidDto();
        dto = dto with { Username = "abc" };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveValidationErrorFor(x => x.Username);
    }

    [Fact]
    public void Validate_WithExactly50CharUsername_ShouldPass()
    {
        // Arrange: Maximum length (50 chars)
        var dto = CreateValidDto();
        dto = dto with { Username = new string('a', 50) };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveValidationErrorFor(x => x.Username);
    }

    [Fact]
    public void Validate_WithExactly8CharPassword_ShouldPass()
    {
        // Arrange: Minimum length (8 chars) with complexity
        var dto = CreateValidDto();
        dto = dto with
        {
            Password = "Abcd123!",
            ConfirmPassword = "Abcd123!"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert
        result.ShouldNotHaveValidationErrorFor(x => x.Password);
    }

    [Fact]
    public void Validate_WithAllFieldsInvalid_ShouldHaveMultipleErrors()
    {
        // Arrange: Tüm alanlar geçersiz
        var dto = new RegisterDto
        {
            Email = "invalid",
            Username = "ab", // Too short
            Password = "weak", // No uppercase, digit, special char
            ConfirmPassword = "different"
        };

        // Act
        var result = _validator.TestValidate(dto);

        // Assert: Birden fazla validation error
        result.ShouldHaveValidationErrorFor(x => x.Email);
        result.ShouldHaveValidationErrorFor(x => x.Username);
        result.ShouldHaveValidationErrorFor(x => x.Password);
        result.ShouldHaveValidationErrorFor(x => x.ConfirmPassword);

        result.Errors.Count.Should().BeGreaterThan(3);
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private RegisterDto CreateValidDto()
    {
        return new RegisterDto
        {
            Email = "test@vaultguard.com",
            Username = "testuser123",
            Password = "SecureP@ss1",
            ConfirmPassword = "SecureP@ss1"
        };
    }
}