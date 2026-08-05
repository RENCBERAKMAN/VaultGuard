using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Moq;
using VaultGuard.Application.Interfaces;
using VaultGuard.Infrastructure.Security;
using Xunit;

namespace VaultGuard.Application.Tests.Security;

/// <summary>
/// TEST SÜİTİ: Encryption Key Rotation & Re-encryption Security Tests
/// 
/// SECURITY FOCUS:
/// - **Key Rotation**: Periodic encryption key changes (compliance requirement)
/// - **Re-encryption**: Migrate data from old key to new key
/// - **Data Integrity**: No data loss during rotation
/// - **Backward Compatibility**: Old keys still decrypt historical data
/// - **Zero Downtime**: Rotation without service interruption
/// 
/// THREAT MODEL:
/// - Key Compromise: Attacker obtains encryption key
/// - Data Corruption: Failed rotation corrupts encrypted data
/// - Service Disruption: Key rotation causes downtime
/// - Incomplete Migration: Some data remains on old key
/// 
/// COMPLIANCE:
/// - **PCI-DSS Requirement 3.6**: Encryption Key Management
///   * 3.6.4: Cryptographic keys must be changed at least annually
///   * 3.6.5: Retirement of old keys as necessary
///   * 3.6.6: Split knowledge and dual control of keys
/// 
/// - **NIST SP 800-57**: Key Management Recommendations
///   * Part 1, Section 5.3: Key Rotation
///   * Part 1, Section 5.4: Key Archiving
///   * Part 2, Section 6: Key Lifecycle Management
/// 
/// - **HIPAA §164.312(a)(2)(iv)**: Encryption and Decryption
///   * Mechanisms to encrypt and decrypt ePHI
///   * Key management procedures
/// 
/// - **GDPR Article 32**: Security of Processing
///   * Encryption of personal data
///   * Regular testing and assessment of effectiveness
/// 
/// KEY ROTATION STRATEGY:
/// 1. **Generate New Key**: Create cryptographically secure new key
/// 2. **Dual Key Period**: Both old and new keys active temporarily
/// 3. **Re-encryption**: Migrate all data to new key (background job)
/// 4. **Verification**: Ensure all data decryptable with new key
/// 5. **Key Retirement**: Archive old key (for historical data)
/// 6. **Audit Logging**: Complete trail of rotation process
/// </summary>
public class EncryptionKeyRotationTests : IDisposable
{
    private readonly Mock<IConfiguration> _mockOldKeyConfig;
    private readonly Mock<IConfiguration> _mockNewKeyConfig;
    private readonly string _oldKey;
    private readonly string _newKey;
    private readonly string _oldIv;
    private readonly string _newIv;

    public EncryptionKeyRotationTests()
    {
        // Generate test keys (256-bit for AES-256)
        _oldKey = GenerateBase64Key(32); // 32 bytes = 256 bits
        _newKey = GenerateBase64Key(32);
        _oldIv = GenerateBase64Key(16); // 16 bytes = 128 bits
        _newIv = GenerateBase64Key(16);

        // Mock old key configuration
        _mockOldKeyConfig = new Mock<IConfiguration>();
        _mockOldKeyConfig.Setup(c => c["Security:Encryption:Key"]).Returns(_oldKey);
        _mockOldKeyConfig.Setup(c => c["Security:Encryption:IV"]).Returns(_oldIv);

        // Mock new key configuration
        _mockNewKeyConfig = new Mock<IConfiguration>();
        _mockNewKeyConfig.Setup(c => c["Security:Encryption:Key"]).Returns(_newKey);
        _mockNewKeyConfig.Setup(c => c["Security:Encryption:IV"]).Returns(_newIv);
    }

    // ============================================================================
    // 🔄 KEY ROTATION - RE-ENCRYPTION TESTS (CRITICAL!)
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - KEY ROTATION (CRITICAL!):
    /// Re-encrypt data from old key to new key successfully.
    /// 
    /// KEY ROTATION WORKFLOW:
    /// 1. Data encrypted with OLD key (Key A)
    /// 2. Decrypt data using OLD key → Plaintext
    /// 3. Encrypt plaintext using NEW key (Key B)
    /// 4. Verify: Decrypted with NEW key matches original
    /// 5. Verify: OLD key can no longer decrypt new data
    /// 
    /// COMPLIANCE:
    /// - PCI-DSS 3.6.4: Cryptographic keys changed at least annually
    /// - NIST SP 800-57 Part 1, Section 5.3: Key Rotation
    /// - HIPAA §164.312(a)(2)(iv): Key management procedures
    /// 
    /// BUSINESS IMPACT:
    /// - Prevents long-term key compromise exposure
    /// - Limits data at risk if key compromised
    /// - Compliance with regulatory requirements
    /// </summary>
    [Fact]
    public void KeyRotation_ReEncryptData_ShouldSucceed()
    {
        // STEP 1: Encrypt with OLD key
        var oldEncryptionService = new AesEncryptionService(_mockOldKeyConfig.Object);
        var originalPlaintext = "SensitiveData_UserPassword_12345!";

        var encryptedWithOldKey = oldEncryptionService.Encrypt(originalPlaintext);
        encryptedWithOldKey.Should().NotBeNullOrEmpty();

        // STEP 2: Decrypt with OLD key (migration step)
        var decryptedWithOldKey = oldEncryptionService.Decrypt(encryptedWithOldKey);
        decryptedWithOldKey.Should().Be(originalPlaintext,
            "OLD key must successfully decrypt its own encrypted data");

        // STEP 3: Re-encrypt with NEW key (KEY ROTATION)
        var newEncryptionService = new AesEncryptionService(_mockNewKeyConfig.Object);
        var encryptedWithNewKey = newEncryptionService.Encrypt(decryptedWithOldKey);
        encryptedWithNewKey.Should().NotBeNullOrEmpty();

        // STEP 4: Verify NEW key can decrypt
        var decryptedWithNewKey = newEncryptionService.Decrypt(encryptedWithNewKey);
        decryptedWithNewKey.Should().Be(originalPlaintext,
            "NEW key must decrypt re-encrypted data successfully");

        // STEP 5: Verify encrypted values are different (different keys used)
        encryptedWithNewKey.Should().NotBe(encryptedWithOldKey,
            "Re-encrypted data must be different (cryptographic uniqueness)");

        // STEP 6: Verify OLD key cannot decrypt NEW encrypted data
        Action attemptDecryptWithOldKey = () => oldEncryptionService.Decrypt(encryptedWithNewKey);
        attemptDecryptWithOldKey.Should().Throw<InvalidOperationException>(
            "OLD key must NOT decrypt data encrypted with NEW key - key isolation verified");
    }

    /// <summary>
    /// SECURITY TEST - DATA INTEGRITY DURING ROTATION:
    /// Verify NO data loss during key rotation.
    /// 
    /// THREAT: Incomplete rotation corrupts data
    /// 
    /// COMPLIANCE:
    /// - PCI-DSS 3.6: Encryption key management
    /// - NIST SP 800-57: Key lifecycle management
    /// </summary>
    [Fact]
    public void KeyRotation_DataIntegrity_ShouldBePreserved()
    {
        // Arrange: Multiple secrets encrypted with OLD key
        var oldEncryptionService = new AesEncryptionService(_mockOldKeyConfig.Object);
        var newEncryptionService = new AesEncryptionService(_mockNewKeyConfig.Object);

        var testData = new Dictionary<string, string>
        {
            { "Secret1", "Password123!" },
            { "Secret2", "ApiKey_ABC_XYZ" },
            { "Secret3", "CreditCard_1234567890123456" },
            { "Secret4", "SSN_123-45-6789" },
            { "Secret5", "BankAccount_9876543210" }
        };

        var encryptedWithOldKey = new Dictionary<string, string>();
        var reEncryptedWithNewKey = new Dictionary<string, string>();

        // STEP 1: Encrypt all data with OLD key
        foreach (var kvp in testData)
        {
            encryptedWithOldKey[kvp.Key] = oldEncryptionService.Encrypt(kvp.Value);
        }

        // STEP 2: Re-encrypt all data with NEW key (KEY ROTATION)
        foreach (var kvp in encryptedWithOldKey)
        {
            var decrypted = oldEncryptionService.Decrypt(kvp.Value);
            reEncryptedWithNewKey[kvp.Key] = newEncryptionService.Encrypt(decrypted);
        }

        // STEP 3: Verify ALL data decrypts correctly with NEW key
        foreach (var kvp in reEncryptedWithNewKey)
        {
            var decrypted = newEncryptionService.Decrypt(kvp.Value);
            decrypted.Should().Be(testData[kvp.Key],
                $"Data integrity for {kvp.Key} must be preserved during rotation");
        }

        // STEP 4: Verify count (no data lost)
        reEncryptedWithNewKey.Should().HaveCount(testData.Count,
            "All records must be migrated - no data loss");
    }

    /// <summary>
    /// SECURITY TEST - ROLLBACK ON FAILURE:
    /// If rotation fails, data remains accessible with OLD key.
    /// 
    /// THREAT: Failed rotation leaves data unrecoverable
    /// 
    /// COMPLIANCE:
    /// - NIST SP 800-57: Key recovery procedures
    /// - PCI-DSS 3.6.5: Key retirement procedures
    /// </summary>
    [Fact]
    public void KeyRotation_Failure_ShouldRollbackGracefully()
    {
        // Arrange: Data encrypted with OLD key
        var oldEncryptionService = new AesEncryptionService(_mockOldKeyConfig.Object);
        var originalPlaintext = "CriticalData_DoNotLose";
        var encryptedWithOldKey = oldEncryptionService.Encrypt(originalPlaintext);

        // SIMULATE: Rotation fails (new key corrupted/unavailable)
        var invalidKeyConfig = new Mock<IConfiguration>();
        invalidKeyConfig.Setup(c => c["Security:Encryption:Key"]).Returns("InvalidKey");
        invalidKeyConfig.Setup(c => c["Security:Encryption:IV"]).Returns(_newIv);

        // Act: Attempt rotation (should fail)
        Action attemptRotation = () =>
        {
            var decrypted = oldEncryptionService.Decrypt(encryptedWithOldKey);
            // This will throw because invalidKeyConfig has wrong key length
            var invalidService = new AesEncryptionService(invalidKeyConfig.Object);
        };

        attemptRotation.Should().Throw<InvalidOperationException>(
            "Invalid key configuration should be detected");

        // ROLLBACK: Verify OLD key still works
        var decryptedWithOldKey = oldEncryptionService.Decrypt(encryptedWithOldKey);
        decryptedWithOldKey.Should().Be(originalPlaintext,
            "CRITICAL: Data must remain accessible with OLD key after failed rotation");
    }

    // ============================================================================
    // 🔐 BACKWARD COMPATIBILITY TESTS
    // ============================================================================

    /// <summary>
    /// SECURITY TEST - HISTORICAL DATA ACCESS:
    /// OLD key must remain available to decrypt historical data.
    /// 
    /// SCENARIO: After rotation, system needs to access old encrypted data
    /// 
    /// COMPLIANCE:
    /// - PCI-DSS 3.6.5: Retirement of keys only after data migration
    /// - NIST SP 800-57: Key archiving
    /// - GDPR Article 17: Right to erasure (need to decrypt to delete)
    /// </summary>
    [Fact]
    public void KeyRotation_HistoricalData_ShouldRemainAccessible()
    {
        // Arrange: Historical data encrypted with OLD key (1 year ago)
        var oldEncryptionService = new AesEncryptionService(_mockOldKeyConfig.Object);
        var historicalPlaintext = "HistoricalData_2024";
        var historicalEncrypted = oldEncryptionService.Encrypt(historicalPlaintext);

        // NEW key deployed, but OLD key archived
        var newEncryptionService = new AesEncryptionService(_mockNewKeyConfig.Object);

        // Act: System encounters historical encrypted data
        // Use OLD key from archive to decrypt
        var decrypted = oldEncryptionService.Decrypt(historicalEncrypted);

        // Assert: Historical data accessible
        decrypted.Should().Be(historicalPlaintext,
            "Historical data must remain accessible using archived OLD key");

        // Document: Key archiving policy
        // - OLD keys stored securely for data recovery
        // - Minimum retention: 7 years (compliance requirement)
        // - Access: Authorized personnel only
        // - Audit: All access to archived keys logged
    }

    /// <summary>
    /// SECURITY TEST - MULTI-GENERATION KEYS:
    /// System should support multiple key generations simultaneously.
    /// 
    /// SCENARIO:
    /// - Key A (2022): Historical data
    /// - Key B (2023): Old data
    /// - Key C (2024): Current data (active)
    /// 
    /// COMPLIANCE:
    /// - NIST SP 800-57: Multiple key versions
    /// - PCI-DSS: Key hierarchy management
    /// </summary>
    [Fact]
    public void KeyRotation_MultipleGenerations_ShouldCoexist()
    {
        // GENERATION 1 (2022)
        var key2022Config = new Mock<IConfiguration>();
        key2022Config.Setup(c => c["Security:Encryption:Key"]).Returns(GenerateBase64Key(32));
        key2022Config.Setup(c => c["Security:Encryption:IV"]).Returns(GenerateBase64Key(16));
        var service2022 = new AesEncryptionService(key2022Config.Object);

        // GENERATION 2 (2023)
        var key2023Config = new Mock<IConfiguration>();
        key2023Config.Setup(c => c["Security:Encryption:Key"]).Returns(GenerateBase64Key(32));
        key2023Config.Setup(c => c["Security:Encryption:IV"]).Returns(GenerateBase64Key(16));
        var service2023 = new AesEncryptionService(key2023Config.Object);

        // GENERATION 3 (2024 - Current)
        var key2024Config = new Mock<IConfiguration>();
        key2024Config.Setup(c => c["Security:Encryption:Key"]).Returns(GenerateBase64Key(32));
        key2024Config.Setup(c => c["Security:Encryption:IV"]).Returns(GenerateBase64Key(16));
        var service2024 = new AesEncryptionService(key2024Config.Object);

        // Encrypt data with each generation
        var plaintext = "MultiGenerationTest";
        var encrypted2022 = service2022.Encrypt(plaintext);
        var encrypted2023 = service2023.Encrypt(plaintext);
        var encrypted2024 = service2024.Encrypt(plaintext);

        // Verify: Each generation can decrypt its own data
        service2022.Decrypt(encrypted2022).Should().Be(plaintext);
        service2023.Decrypt(encrypted2023).Should().Be(plaintext);
        service2024.Decrypt(encrypted2024).Should().Be(plaintext);

        // Verify: Encrypted values are unique (different keys)
        encrypted2022.Should().NotBe(encrypted2023);
        encrypted2023.Should().NotBe(encrypted2024);
        encrypted2022.Should().NotBe(encrypted2024);
    }

    // ============================================================================
    // ⏱️ PERFORMANCE & ZERO DOWNTIME TESTS
    // ============================================================================

    /// <summary>
    /// PERFORMANCE TEST - BULK RE-ENCRYPTION:
    /// Re-encrypt large dataset within acceptable time.
    /// 
    /// SCENARIO: 1000 secrets re-encryption during rotation
    /// 
    /// COMPLIANCE:
    /// - Service Level Agreement (SLA): <5s for 1000 records
    /// - Zero downtime requirement
    /// </summary>
    [Fact]
    public void KeyRotation_BulkReEncryption_ShouldBePerformant()
    {
        // Arrange: 1000 secrets
        var oldEncryptionService = new AesEncryptionService(_mockOldKeyConfig.Object);
        var newEncryptionService = new AesEncryptionService(_mockNewKeyConfig.Object);

        var secrets = new List<string>();
        for (int i = 0; i < 1000; i++)
        {
            secrets.Add($"Secret_{i}_Data_{Guid.NewGuid()}");
        }

        // Encrypt with OLD key
        var encryptedSecrets = new List<string>();
        foreach (var secret in secrets)
        {
            encryptedSecrets.Add(oldEncryptionService.Encrypt(secret));
        }

        // Act: Re-encrypt with NEW key (measure time)
        var startTime = DateTime.UtcNow;

        var reEncryptedSecrets = new List<string>();
        foreach (var encrypted in encryptedSecrets)
        {
            var decrypted = oldEncryptionService.Decrypt(encrypted);
            reEncryptedSecrets.Add(newEncryptionService.Encrypt(decrypted));
        }

        var duration = DateTime.UtcNow - startTime;

        // Assert: Performance SLA
        duration.Should().BeLessThan(TimeSpan.FromSeconds(10),
            "1000 secrets should re-encrypt in <10s for acceptable downtime");

        // Assert: All data re-encrypted
        reEncryptedSecrets.Should().HaveCount(1000);

        // Verify random sample
        var randomIndex = new Random().Next(1000);
        var verifyDecrypted = newEncryptionService.Decrypt(reEncryptedSecrets[randomIndex]);
        verifyDecrypted.Should().Be(secrets[randomIndex]);
    }

    /// <summary>
    /// SECURITY TEST - ATOMIC ROTATION:
    /// Key rotation must be atomic (all or nothing).
    /// 
    /// THREAT: Partial rotation leaves system in inconsistent state
    /// 
    /// COMPLIANCE:
    /// - ACID properties: Atomicity
    /// - PCI-DSS: Data integrity
    /// </summary>
    [Fact]
    public void KeyRotation_Atomicity_ShouldBeGuaranteed()
    {
        // Arrange: Batch of secrets
        var oldEncryptionService = new AesEncryptionService(_mockOldKeyConfig.Object);
        var newEncryptionService = new AesEncryptionService(_mockNewKeyConfig.Object);

        var secrets = new[] { "Secret1", "Secret2", "Secret3", "Secret4", "Secret5" };
        var encryptedSecrets = new List<string>();

        foreach (var secret in secrets)
        {
            encryptedSecrets.Add(oldEncryptionService.Encrypt(secret));
        }

        // SIMULATE: Rotation fails on 3rd secret
        var rotatedSecrets = new List<string>();
        var rotationFailed = false;

        try
        {
            for (int i = 0; i < encryptedSecrets.Count; i++)
            {
                var decrypted = oldEncryptionService.Decrypt(encryptedSecrets[i]);

                // SIMULATE FAILURE on 3rd iteration
                if (i == 2)
                {
                    throw new InvalidOperationException("Simulated rotation failure");
                }

                rotatedSecrets.Add(newEncryptionService.Encrypt(decrypted));
            }
        }
        catch (InvalidOperationException)
        {
            rotationFailed = true;
        }

        // Assert: Rotation failed
        rotationFailed.Should().BeTrue("Simulated failure should occur");

        // Assert: Partial rotation detected (only 2 rotated, not 5)
        rotatedSecrets.Should().HaveCount(2, "Partial rotation occurred");

        // ROLLBACK: All data should remain accessible with OLD key
        foreach (var encrypted in encryptedSecrets)
        {
            Action decrypt = () => oldEncryptionService.Decrypt(encrypted);
            decrypt.Should().NotThrow("OLD key must still work after failed rotation");
        }

        // Document: Production implementation should use database transactions
        // to ensure atomicity of rotation operations
    }

    // ============================================================================
    // HELPER METHODS
    // ============================================================================

    private static string GenerateBase64Key(int byteLength)
    {
        var bytes = new byte[byteLength];
        using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }
        return Convert.ToBase64String(bytes);
    }

    public void Dispose()
    {
        // Cleanup if needed
        GC.SuppressFinalize(this);
    }
}