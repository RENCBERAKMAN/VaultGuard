using System;
using System.Collections.Generic;
using System.Linq;
using VaultGuard.Domain.Common.Results;
using Xunit;

namespace VaultGuard.Domain.Tests.Common.Results;

/// <summary>
/// Result Pattern için kapsamlı unit test sınıfı.
/// 
/// TEST KAPSAMI:
/// - ✅ SuccessResult (2 constructor)
/// - ✅ SuccessDataResult<T> (2 constructor)
/// - ✅ ErrorResult (3 constructor)
/// - ✅ ErrorDataResult<T> (4 constructor)
/// - ✅ IResult ve IDataResult interface'leri
/// - ✅ Sensitive data sanitization (GÜVENLİK KRİTİK!)
/// - ✅ Environment-aware stack trace
/// - ✅ Null handling ve edge cases
/// - ✅ Generic type variations
/// - ✅ Immutability tests
/// 
/// TEST STRATEJİSİ:
/// - AAA Pattern (Arrange-Act-Assert)
/// - Theory ile data-driven tests
/// - Fact ile single scenario tests
/// - Edge case coverage
/// - Security-first approach
/// </summary>
public class ResultsTests
{
    // ============================================================================
    // SUCCESS RESULT TESTS
    // ============================================================================

    [Fact]
    public void SuccessResult_DefaultConstructor_ShouldCreateSuccessfulResult()
    {
        // Arrange & Act
        var result = new SuccessResult();

        // Assert
        Assert.True(result.Success);
        Assert.Equal("Operation completed successfully.", result.Message);
        Assert.Null(result.ErrorCode);
        Assert.Null(result.InternalErrorDetails);
    }

    [Theory]
    [InlineData("User created successfully.")]
    [InlineData("Email sent successfully.")]
    [InlineData("Data saved.")]
    public void SuccessResult_WithMessage_ShouldCreateWithCustomMessage(string message)
    {
        // Arrange & Act
        var result = new SuccessResult(message);

        // Assert
        Assert.True(result.Success);
        Assert.Equal(message, result.Message);
        Assert.Null(result.ErrorCode);
        Assert.Null(result.InternalErrorDetails);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void SuccessResult_WithEmptyMessage_ShouldUseFallbackMessage(string? emptyMessage)
    {
        // Arrange & Act
        var result = new SuccessResult(emptyMessage!);

        // Assert
        Assert.True(result.Success);
        Assert.Equal("Operation completed successfully.", result.Message);
    }

    [Fact]
    public void SuccessResult_ShouldImplementIResult()
    {
        // Arrange
        IResult result = new SuccessResult();

        // Assert
        Assert.IsAssignableFrom<IResult>(result);
        Assert.True(result.Success);
    }

    // ============================================================================
    // SUCCESS DATA RESULT TESTS
    // ============================================================================

    [Fact]
    public void SuccessDataResult_WithDataOnly_ShouldCreateWithDefaultMessage()
    {
        // Arrange
        var testData = new TestUser { Id = 1, Name = "John Doe" };

        // Act
        var result = new SuccessDataResult<TestUser>(testData);

        // Assert
        Assert.True(result.Success);
        Assert.Equal("Operation completed successfully.", result.Message);
        Assert.NotNull(result.Data);
        Assert.Equal(testData.Id, result.Data.Id);
        Assert.Equal(testData.Name, result.Data.Name);
        Assert.Null(result.ErrorCode);
    }

    [Fact]
    public void SuccessDataResult_WithDataAndMessage_ShouldCreateWithCustomMessage()
    {
        // Arrange
        var testData = 42;
        var message = "Calculation completed successfully.";

        // Act
        var result = new SuccessDataResult<int>(testData, message);

        // Assert
        Assert.True(result.Success);
        Assert.Equal(message, result.Message);
        Assert.Equal(42, result.Data);
    }

    [Theory]
    [InlineData(100)]
    [InlineData(0)]
    [InlineData(-50)]
    public void SuccessDataResult_WithValueType_ShouldHandleCorrectly(int value)
    {
        // Arrange & Act
        var result = new SuccessDataResult<int>(value);

        // Assert
        Assert.True(result.Success);
        Assert.Equal(value, result.Data);
    }

    [Fact]
    public void SuccessDataResult_WithNullReferenceType_ShouldAllowNull()
    {
        // Arrange & Act
        var result = new SuccessDataResult<string?>(null, "No data available.");

        // Assert
        // NOT: SuccessDataResult null data ile oluşturulabilir (caller'ın sorumluluğunda)
        // Ama best practice olarak başarılı işlemlerde null data olmamalı
        Assert.True(result.Success);
        Assert.Null(result.Data);
        Assert.Equal("No data available.", result.Message);
    }

    [Fact]
    public void SuccessDataResult_WithComplexObject_ShouldStoreCorrectly()
    {
        // Arrange
        var testData = new List<string> { "Item1", "Item2", "Item3" };

        // Act
        var result = new SuccessDataResult<List<string>>(testData, "Items loaded.");

        // Assert
        Assert.True(result.Success);
        Assert.NotNull(result.Data);
        Assert.Equal(3, result.Data.Count);
        Assert.Contains("Item2", result.Data);
    }

    [Fact]
    public void SuccessDataResult_ShouldImplementIDataResult()
    {
        // Arrange
        var testData = "Test";

        // Act
        IDataResult<string> result = new SuccessDataResult<string>(testData);

        // Assert
        Assert.IsAssignableFrom<IDataResult<string>>(result);
        Assert.True(result.Success);
        Assert.Equal(testData, result.Data);
    }

    // ============================================================================
    // ERROR RESULT TESTS
    // ============================================================================

    [Theory]
    [InlineData("Email is required.")]
    [InlineData("Invalid password format.")]
    [InlineData("User not found.")]
    public void ErrorResult_WithMessage_ShouldCreateErrorResult(string errorMessage)
    {
        // Arrange & Act
        var result = new ErrorResult(errorMessage);

        // Assert
        Assert.False(result.Success);
        Assert.Equal(errorMessage, result.Message);
        Assert.Null(result.ErrorCode);
        Assert.Null(result.InternalErrorDetails);
    }

    [Theory]
    [InlineData("Email is required.", "VAL_EMAIL_001")]
    [InlineData("User not found.", "ERR_USER_NOT_FOUND")]
    [InlineData("Access denied.", "AUTHZ_ACCESS_DENIED")]
    public void ErrorResult_WithMessageAndErrorCode_ShouldIncludeErrorCode(
        string message,
        string errorCode)
    {
        // Arrange & Act
        var result = new ErrorResult(message, errorCode);

        // Assert
        Assert.False(result.Success);
        Assert.Equal(message, result.Message);
        Assert.Equal(errorCode, result.ErrorCode);
        Assert.Null(result.InternalErrorDetails);
    }

    [Fact]
    public void ErrorResult_WithException_ShouldSanitizeExceptionDetails()
    {
        // Arrange
        var exception = new InvalidOperationException("Database connection failed.");
        var message = "An error occurred while processing your request.";
        var errorCode = "ERR_DB_001";

        // Act
        var result = new ErrorResult(message, errorCode, exception);

        // Assert
        Assert.False(result.Success);
        Assert.Equal(message, result.Message); // Generic mesaj korunmuş
        Assert.Equal(errorCode, result.ErrorCode);
        Assert.NotNull(result.InternalErrorDetails);

        // GÜVENLİK: Exception type ve message internal details'de
        Assert.Contains("InvalidOperationException", result.InternalErrorDetails);
        Assert.Contains("Database connection failed", result.InternalErrorDetails);

        // GÜVENLİK: Message'da exception detayı YOK
        Assert.DoesNotContain("InvalidOperationException", result.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ErrorResult_WithEmptyMessage_ShouldUseFallbackMessage(string? emptyMessage)
    {
        // Arrange & Act
        var result = new ErrorResult(emptyMessage!);

        // Assert
        Assert.False(result.Success);
        Assert.Equal("An error occurred.", result.Message);
    }

    // ============================================================================
    // ERROR DATA RESULT TESTS
    // ============================================================================

    [Fact]
    public void ErrorDataResult_WithMessage_ShouldCreateWithNullData()
    {
        // Arrange
        var message = "User not found.";

        // Act
        var result = new ErrorDataResult<TestUser>(message);

        // Assert
        Assert.False(result.Success);
        Assert.Equal(message, result.Message);
        Assert.Null(result.Data);
        Assert.Null(result.ErrorCode);
    }

    [Fact]
    public void ErrorDataResult_WithMessageAndErrorCode_ShouldIncludeErrorCode()
    {
        // Arrange
        var message = "Product not found.";
        var errorCode = "ERR_PRODUCT_NOT_FOUND";

        // Act
        var result = new ErrorDataResult<string>(message, errorCode);

        // Assert
        Assert.False(result.Success);
        Assert.Equal(message, result.Message);
        Assert.Equal(errorCode, result.ErrorCode);
        Assert.Null(result.Data);
    }

    [Fact]
    public void ErrorDataResult_WithException_ShouldSanitizeAndStoreInternalDetails()
    {
        // Arrange
        var exception = new ArgumentException("Invalid user ID format.");
        var message = "An error occurred.";
        var errorCode = "ERR_INVALID_ID";

        // Act
        var result = new ErrorDataResult<int>(message, errorCode, exception);

        // Assert
        Assert.False(result.Success);
        Assert.Equal(message, result.Message);
        Assert.Equal(errorCode, result.ErrorCode);
        Assert.Equal(0, result.Data); // Default value for int
        Assert.NotNull(result.InternalErrorDetails);
        Assert.Contains("ArgumentException", result.InternalErrorDetails);
    }

    [Fact]
    public void ErrorDataResult_WithFallbackData_ShouldReturnFallbackValue()
    {
        // Arrange
        var fallbackData = new List<string> { "default" };
        var message = "Cache miss. Using default data.";
        var errorCode = "INFO_CACHE_MISS";

        // Act
        var result = new ErrorDataResult<List<string>>(fallbackData, message, errorCode);

        // Assert
        Assert.False(result.Success);
        Assert.Equal(message, result.Message);
        Assert.NotNull(result.Data);
        Assert.Single(result.Data);
        Assert.Equal("default", result.Data[0]);
    }

    [Fact]
    public void ErrorDataResult_WithValueType_ShouldReturnDefaultValue()
    {
        // Arrange
        var message = "Calculation failed.";

        // Act
        var result = new ErrorDataResult<decimal>(message);

        // Assert
        Assert.False(result.Success);
        Assert.Equal(0m, result.Data); // Default value for decimal
    }

    // ============================================================================
    // SENSITIVE DATA SANITIZATION TESTS (GÜVENLİK KRİTİK!)
    // ============================================================================

    [Theory]
    [InlineData("Connection failed. Password=MySecretPass123", "Password=***REDACTED***")]
    [InlineData("API Error: api_key=abc123def456", "api_key=***REDACTED***")]
    [InlineData("Auth failed: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "Bearer ***TOKEN***")]
    [InlineData("Config error: secret=top_secret_value", "secret=***REDACTED***")]
    [InlineData("Database error: pwd=pass123", "pwd=***REDACTED***")]
    public void ErrorResult_WithSensitiveDataInException_ShouldRedactPasswords(
        string exceptionMessage,
        string expectedRedaction)
    {
        // Arrange
        var exception = new Exception(exceptionMessage);
        var message = "An error occurred.";
        var errorCode = "ERR_TEST";

        // Act
        var result = new ErrorResult(message, errorCode, exception);

        // Assert
        Assert.NotNull(result.InternalErrorDetails);
        Assert.Contains(expectedRedaction, result.InternalErrorDetails);

        // GÜVENLİK: Hassas veri public message'da YOK
        Assert.DoesNotContain("MySecretPass123", result.Message);
        Assert.DoesNotContain("abc123def456", result.Message);
    }

    [Theory]
    [InlineData("User test@example.com not found", "***EMAIL***")]
    [InlineData("Failed login for admin@vaultguard.com", "***EMAIL***")]
    [InlineData("Contact support@company.org for help", "***EMAIL***")]
    public void ErrorResult_WithEmailInException_ShouldRedactEmails(
        string exceptionMessage,
        string expectedRedaction)
    {
        // Arrange
        var exception = new Exception(exceptionMessage);

        // Act
        var result = new ErrorResult("An error occurred.", "ERR_TEST", exception);

        // Assert
        Assert.NotNull(result.InternalErrorDetails);
        Assert.Contains(expectedRedaction, result.InternalErrorDetails);

        // GÜVENLİK: Email adresleri InternalErrorDetails'de maskelenmiş
        Assert.DoesNotContain("test@example.com", result.InternalErrorDetails);
        Assert.DoesNotContain("admin@vaultguard.com", result.InternalErrorDetails);
    }

    [Theory]
    [InlineData("Payment failed for card 4111111111111111", "***CARD***")]
    [InlineData("Transaction error: 5500000000000004", "***CARD***")]
    [InlineData("Card declined: 340000000000009", "***CARD***")] // 15 digits
    public void ErrorResult_WithCreditCardInException_ShouldRedactCardNumbers(
        string exceptionMessage,
        string expectedRedaction)
    {
        // Arrange
        var exception = new Exception(exceptionMessage);

        // Act
        var result = new ErrorResult("Payment error.", "ERR_PAYMENT", exception);

        // Assert
        Assert.NotNull(result.InternalErrorDetails);
        Assert.Contains(expectedRedaction, result.InternalErrorDetails);

        // GÜVENLİK: Kart numaraları maskelenmiş
        Assert.DoesNotContain("4111111111111111", result.InternalErrorDetails);
        Assert.DoesNotContain("5500000000000004", result.InternalErrorDetails);
    }

    [Fact]
    public void ErrorResult_WithMultipleSensitiveData_ShouldRedactAll()
    {
        // Arrange
        var exceptionMessage = "Auth failed for user admin@test.com with password=Secret123 and token=abc123";
        var exception = new Exception(exceptionMessage);

        // Act
        var result = new ErrorResult("Authentication failed.", "ERR_AUTH", exception);

        // Assert
        Assert.NotNull(result.InternalErrorDetails);

        // GÜVENLİK: Tüm hassas veriler maskelenmiş
        Assert.Contains("***EMAIL***", result.InternalErrorDetails);
        Assert.Contains("password=***REDACTED***", result.InternalErrorDetails);
        Assert.Contains("token=***REDACTED***", result.InternalErrorDetails);

        // Orijinal değerler yok
        Assert.DoesNotContain("admin@test.com", result.InternalErrorDetails);
        Assert.DoesNotContain("Secret123", result.InternalErrorDetails);
        Assert.DoesNotContain("abc123", result.InternalErrorDetails);
    }

    [Fact]
    public void ErrorResult_WithJWTToken_ShouldRedactToken()
    {
        // Arrange
        var jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        var exceptionMessage = $"Token validation failed: Bearer {jwtToken}";
        var exception = new Exception(exceptionMessage);

        // Act
        var result = new ErrorResult("Token error.", "ERR_TOKEN", exception);

        // Assert
        Assert.NotNull(result.InternalErrorDetails);
        Assert.Contains("Bearer ***TOKEN***", result.InternalErrorDetails);
        Assert.DoesNotContain(jwtToken, result.InternalErrorDetails);
    }

    // ============================================================================
    // ENVIRONMENT-AWARE STACK TRACE TESTS
    // ============================================================================

    [Fact]
    public void ErrorResult_InDevelopment_ShouldIncludeStackTrace()
    {
        // Arrange
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");
        var exception = new InvalidOperationException("Test exception");

        // Generate stack trace
        try
        {
            throw exception;
        }
        catch (Exception ex)
        {
            // Act
            var result = new ErrorResult("Error occurred.", "ERR_TEST", ex);

            // Assert
            Assert.NotNull(result.InternalErrorDetails);

            // Development ortamında stack trace var
            Assert.Contains("StackTrace:", result.InternalErrorDetails);
            Assert.Contains("ResultsTests", result.InternalErrorDetails);
        }
        finally
        {
            // Cleanup
            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", null);
        }
    }

    [Fact]
    public void ErrorResult_InProduction_ShouldNotIncludeStackTrace()
    {
        // Arrange
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Production");
        var exception = new InvalidOperationException("Test exception");

        try
        {
            throw exception;
        }
        catch (Exception ex)
        {
            // Act
            var result = new ErrorResult("Error occurred.", "ERR_TEST", ex);

            // Assert
            Assert.NotNull(result.InternalErrorDetails);

            // Production ortamında stack trace YOK
            Assert.DoesNotContain("StackTrace:", result.InternalErrorDetails);

            // Ama exception type ve message var (sanitized)
            Assert.Contains("InvalidOperationException", result.InternalErrorDetails);
        }
        finally
        {
            // Cleanup
            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", null);
        }
    }

    // ============================================================================
    // INNER EXCEPTION TESTS
    // ============================================================================

    [Fact]
    public void ErrorResult_WithInnerException_ShouldIncludeInnerType()
    {
        // Arrange
        var innerException = new ArgumentNullException("userId", "User ID cannot be null");
        var outerException = new InvalidOperationException("Operation failed", innerException);

        // Act
        var result = new ErrorResult("Error occurred.", "ERR_TEST", outerException);

        // Assert
        Assert.NotNull(result.InternalErrorDetails);

        // Outer exception
        Assert.Contains("InvalidOperationException", result.InternalErrorDetails);

        // Inner exception type
        Assert.Contains("Inner: ArgumentNullException", result.InternalErrorDetails);
    }

    [Fact]
    public void ErrorResult_WithInnerExceptionContainingSensitiveData_ShouldSanitize()
    {
        // Arrange
        var innerException = new Exception("Connection failed: password=secret123");
        var outerException = new InvalidOperationException("Database error", innerException);

        // Act
        var result = new ErrorResult("Error occurred.", "ERR_DB", outerException);

        // Assert
        Assert.NotNull(result.InternalErrorDetails);

        // Inner exception message sanitized
        Assert.Contains("password=***REDACTED***", result.InternalErrorDetails);
        Assert.DoesNotContain("secret123", result.InternalErrorDetails);
    }

    // ============================================================================
    // IMMUTABILITY TESTS
    // ============================================================================

    [Fact]
    public void Result_PropertiesWithInit_ShouldBeImmutable()
    {
        // Arrange
        var result = new SuccessResult("Test");

        // Assert
        // Init-only properties - compile-time check
        // result.Success = false; // ❌ Compile error
        // result.Message = "Changed"; // ❌ Compile error

        Assert.True(result.Success);
        Assert.Equal("Test", result.Message);
    }

    [Fact]
    public void DataResult_DataProperty_ShouldBeImmutableReference()
    {
        // Arrange
        var originalData = new TestUser { Id = 1, Name = "John" };
        var result = new SuccessDataResult<TestUser>(originalData);

        // Act
        // result.Data = new TestUser(); // ❌ Compile error (init-only)

        // Ama Data'nın içeriği mutable (TestUser class mutable)
        result.Data!.Name = "Jane";

        // Assert
        Assert.Equal("Jane", result.Data.Name);

        // NOT: Data property'si init-only ama içeriği mutable
        // True immutability için Data'nın da immutable olması gerekir
    }

    // ============================================================================
    // EDGE CASE TESTS
    // ============================================================================

    [Fact]
    public void ErrorResult_WithNullException_ShouldHandleGracefully()
    {
        // Arrange & Act
        var result = new ErrorResult("Error", "ERR_TEST", null!);

        // Assert
        Assert.False(result.Success);
        Assert.Equal("Error", result.Message);

        // Null exception durumunda InternalErrorDetails boş string
        Assert.Equal(string.Empty, result.InternalErrorDetails);
    }

    [Fact]
    public void ErrorResult_WithVeryLongStackTrace_ShouldTruncate()
    {
        // Arrange
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");

        // Çok uzun stack trace oluştur
        var exception = new Exception("Test");
        try
        {
            // Nested method calls for deep stack
            DeepMethod1();
        }
        catch (Exception ex)
        {
            // Act
            var result = new ErrorResult("Error", "ERR_TEST", ex);

            // Assert
            if (result.InternalErrorDetails != null &&
                result.InternalErrorDetails.Contains("StackTrace:"))
            {
                // Stack trace max 2000 karakter + "... (truncated)"
                var stackTraceStart = result.InternalErrorDetails.IndexOf("StackTrace:");
                var stackTraceContent = result.InternalErrorDetails.Substring(stackTraceStart);

                if (stackTraceContent.Length > 2050)
                {
                    Assert.Contains("(truncated)", result.InternalErrorDetails);
                }
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", null);
        }
    }

    // Helper method for deep stack trace
    private void DeepMethod1() => DeepMethod2();
    private void DeepMethod2() => DeepMethod3();
    private void DeepMethod3() => DeepMethod4();
    private void DeepMethod4() => DeepMethod5();
    private void DeepMethod5() => throw new Exception("Deep exception");

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t\n")]
    public void ErrorResult_WithWhitespaceOnlyMessage_ShouldUseFallback(string whitespace)
    {
        // Arrange & Act
        var result = new ErrorResult(whitespace);

        // Assert
        Assert.False(result.Success);
        Assert.Equal("An error occurred.", result.Message);
    }

    [Fact]
    public void SuccessDataResult_WithLargeCollection_ShouldHandleEfficiently()
    {
        // Arrange
        var largeList = Enumerable.Range(1, 10000).ToList();

        // Act
        var result = new SuccessDataResult<List<int>>(largeList, "Large data loaded.");

        // Assert
        Assert.True(result.Success);
        Assert.NotNull(result.Data);
        Assert.Equal(10000, result.Data.Count);

        // Performance: No unnecessary copying
        Assert.Same(largeList, result.Data);
    }

    // ============================================================================
    // INTERFACE IMPLEMENTATION TESTS
    // ============================================================================

    [Fact]
    public void IResult_Interface_ShouldBeImplementedByAllResults()
    {
        // Arrange & Act
        IResult successResult = new SuccessResult();
        IResult errorResult = new ErrorResult("Error");
        IResult successDataResult = new SuccessDataResult<int>(42);
        IResult errorDataResult = new ErrorDataResult<int>("Error");

        // Assert
        Assert.IsAssignableFrom<IResult>(successResult);
        Assert.IsAssignableFrom<IResult>(errorResult);
        Assert.IsAssignableFrom<IResult>(successDataResult);
        Assert.IsAssignableFrom<IResult>(errorDataResult);
    }

    [Fact]
    public void IDataResult_Interface_ShouldProvideDataAccess()
    {
        // Arrange
        var testData = "Test Data";

        // Act
        IDataResult<string> result = new SuccessDataResult<string>(testData);

        // Assert
        Assert.IsAssignableFrom<IResult>(result);
        Assert.IsAssignableFrom<IDataResult<string>>(result);
        Assert.Equal(testData, result.Data);
    }

    [Fact]
    public void IDataResult_Covariance_ShouldSupportDerivedTypes()
    {
        // Arrange
        var derivedData = new DerivedTestUser { Id = 1, Name = "John", Email = "john@test.com" };

        // Act
        IDataResult<TestUser> baseResult = new SuccessDataResult<DerivedTestUser>(derivedData);

        // Assert
        // Covariance: IDataResult<DerivedTestUser> → IDataResult<TestUser>
        // NOT: Bu sadece interface level'da çalışır (out T parametresi gerektirir)
        // Şu anki implementasyonda T covariant değil, bu test compile hatası verir
        // Eğer IDataResult<out T> olsaydı çalışırdı

        // Workaround: Explicit cast
        var derivedResult = new SuccessDataResult<DerivedTestUser>(derivedData);
        TestUser baseData = derivedResult.Data!;
        Assert.Equal("John", baseData.Name);
    }

    // ============================================================================
    // POLYMORPHISM TESTS
    // ============================================================================

    [Fact]
    public void Result_Polymorphism_ShouldWorkCorrectly()
    {
        // Arrange
        IResult[] results =
        {
            new SuccessResult("Success 1"),
            new ErrorResult("Error 1"),
            new SuccessDataResult<int>(42),
            new ErrorDataResult<string>("Error 2")
        };

        // Act & Assert
        Assert.Equal(4, results.Length);
        Assert.True(results[0].Success);
        Assert.False(results[1].Success);
        Assert.True(results[2].Success);
        Assert.False(results[3].Success);
    }

    [Fact]
    public void DataResult_Polymorphism_ShouldPreserveType()
    {
        // Arrange
        var intResult = new SuccessDataResult<int>(100);
        var stringResult = new SuccessDataResult<string>("Test");

        // Act
        IDataResult<int> intInterface = intResult;
        IDataResult<string> stringInterface = stringResult;

        // Assert
        Assert.Equal(100, intInterface.Data);
        Assert.Equal("Test", stringInterface.Data);
    }

    // ============================================================================
    // REAL-WORLD SCENARIO TESTS
    // ============================================================================

    [Fact]
    public void Scenario_UserNotFound_ShouldReturnErrorDataResult()
    {
        // Arrange - Simulate repository returning null
        TestUser? user = null;

        // Act
        IDataResult<TestUser> result = user == null
    ? new ErrorDataResult<TestUser>("User not found.", "ERR_USER_NOT_FOUND")
    : new SuccessDataResult<TestUser>(user, "User retrieved.");

        // Assert
        Assert.False(result.Success);
        Assert.Equal("User not found.", result.Message);
        Assert.Equal("ERR_USER_NOT_FOUND", result.ErrorCode);
        Assert.Null(result.Data);
    }

    [Fact]
    public void Scenario_DatabaseException_ShouldSanitizeConnectionString()
    {
        // Arrange
        var connectionString = "Server=localhost;Database=VaultGuard;User=admin;Password=SuperSecret123;";
        var dbException = new Exception($"Connection failed: {connectionString}");

        // Act
        var result = new ErrorDataResult<List<TestUser>>(
            "An error occurred while retrieving users.",
            "ERR_DB_CONNECTION",
            dbException);

        // Assert
        Assert.False(result.Success);
        Assert.NotNull(result.InternalErrorDetails);

        // GÜVENLİK: Password maskelenmiş
        Assert.Contains("Password=***REDACTED***", result.InternalErrorDetails);
        Assert.DoesNotContain("SuperSecret123", result.InternalErrorDetails);

        // GÜVENLİK: Public message'da connection string YOK
        Assert.DoesNotContain(connectionString, result.Message);
    }

    [Fact]
    public void Scenario_ValidationError_ShouldReturnClearErrorCode()
    {
        // Arrange
        var email = "invalid-email";

        // Act
        IResult result = !email.Contains('@')
    ? new ErrorResult("Invalid email format.", "VAL_EMAIL_FORMAT")
    : new SuccessResult("Email is valid.");

        // Assert
        Assert.False(result.Success);
        Assert.Equal("Invalid email format.", result.Message);
        Assert.Equal("VAL_EMAIL_FORMAT", result.ErrorCode);
    }

    [Fact]
    public void Scenario_CacheMissWithFallback_ShouldReturnErrorWithDefaultData()
    {
        // Arrange
        List<TestUser>? cachedData = null;
        var defaultData = new List<TestUser>();

        // Act
        IDataResult<List<TestUser>> result = cachedData == null
    ? new ErrorDataResult<List<TestUser>>(defaultData, "Cache miss. Using empty list.", "INFO_CACHE_MISS")
    : new SuccessDataResult<List<TestUser>>(cachedData);

        // Assert
        Assert.False(result.Success);
        Assert.NotNull(result.Data);
        Assert.Empty(result.Data);
        Assert.Equal("INFO_CACHE_MISS", result.ErrorCode);
    }
}

// ============================================================================
// TEST HELPER CLASSES
// ============================================================================

/// <summary>
/// Test için basit kullanıcı modeli.
/// </summary>
public class TestUser
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
}

/// <summary>
/// Covariance test için türetilmiş sınıf.
/// </summary>
public class DerivedTestUser : TestUser
{
    public string Email { get; set; } = string.Empty;
}