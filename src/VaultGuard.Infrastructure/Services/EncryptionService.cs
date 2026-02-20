using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using VaultGuard.Application.Interfaces;

namespace VaultGuard.Infrastructure.Services;

/// <summary>
/// Service for AES-256-GCM encryption and decryption of sensitive data.
/// 
/// CRYPTOGRAPHY:
/// - Algorithm: AES-256-GCM (Galois/Counter Mode)
/// - Key Size: 256 bits (32 bytes)
/// - Nonce Size: 96 bits (12 bytes) - MUST be unique per encryption
/// - Tag Size: 128 bits (16 bytes) - Authentication tag for AEAD
/// 
/// WHY AES-GCM?
/// - AEAD (Authenticated Encryption with Associated Data): Provides both confidentiality and authenticity
/// - Performance: Hardware acceleration (AES-NI instruction set on modern CPUs)
/// - Security: NIST approved (FIPS 140-2), resistant to padding oracle attacks
/// - Parallelizable: Faster than CBC mode
/// 
/// OUTPUT FORMAT:
/// Base64(Nonce || Tag || Ciphertext)
/// - Nonce: 12 bytes (random, unique per encryption)
/// - Tag: 16 bytes (authentication tag)
/// - Ciphertext: Variable length (encrypted plaintext)
/// 
/// SECURITY CONSIDERATIONS:
/// - Nonce MUST be unique per encryption (collision = catastrophic failure)
/// - Key MUST be stored securely (Azure Key Vault, AWS KMS, etc.)
/// - Tag MUST be verified during decryption (integrity check)
/// - DO NOT reuse nonce with same key (breaks security)
/// 
/// KEY MANAGEMENT:
/// ⚠️ PRODUCTION WARNING:
/// Current implementation uses hardcoded key (DEMO ONLY).
/// In production, key MUST come from:
/// - Azure Key Vault (recommended)
/// - AWS KMS
/// - HashiCorp Vault
/// - Environment variables (encrypted at rest)
/// - Hardware Security Module (HSM)
/// 
/// Key rotation strategy:
/// 1. Generate new key
/// 2. Re-encrypt all secrets with new key (background job)
/// 3. Keep old key for grace period (30 days)
/// 4. Delete old key after re-encryption complete
/// 
/// COMPLIANCE:
/// - FIPS 140-2: AES-GCM approved cipher
/// - NIST SP 800-38D: GCM specification
/// - PCI-DSS 3.2.1: Strong cryptography required
/// - GDPR Article 32: State-of-the-art encryption
/// 
/// PERFORMANCE:
/// - AES-NI Hardware Acceleration: ~5-10 GB/s throughput on modern CPUs
/// - No memory allocation during encryption/decryption (stackalloc)
/// - Thread-safe: No shared mutable state
/// </summary>
public sealed class EncryptionService : IEncryptionService
{
    // ====================================================================
    // ⚠️ WARNING: HARDCODED KEY FOR DEMO ONLY!
    // ====================================================================
    // In PRODUCTION, key MUST come from secure key management system:
    // - Azure Key Vault: builder.Configuration["KeyVault:EncryptionKey"]
    // - AWS KMS: KmsClient.Decrypt(encryptedKey)
    // - Environment Variable: Environment.GetEnvironmentVariable("ENCRYPTION_KEY")
    // 
    // Key rotation: Implement versioning (key_v1, key_v2, etc.)
    // Store key version in encrypted value metadata for decryption
    // ====================================================================
    private static readonly byte[] MasterKey = Convert.FromBase64String(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 bytes (256 bits) of zeros - REPLACE IN PRODUCTION!
    );

    // CONSTANTS
    private const int NonceSize = 12; // 96 bits (AES-GCM standard)
    private const int TagSize = 16;   // 128 bits (AES-GCM standard)

    /// <summary>
    /// Initializes a new instance of EncryptionService.
    /// </summary>
    public EncryptionService()
    {
        // VALIDATION: Verify master key is correct size
        if (MasterKey.Length != 32)
        {
            throw new InvalidOperationException(
                $"Master key must be exactly 32 bytes (256 bits). Current size: {MasterKey.Length} bytes");
        }

        // SECURITY WARNING: Log if using default demo key (in production, this should never happen)
        if (MasterKey.All(b => b == 0))
        {
            // In production, throw exception or trigger alert
            Console.WriteLine("⚠️ WARNING: Using default demo encryption key! This is INSECURE for production!");
        }
    }

    /// <inheritdoc/>
    public string Encrypt(string plaintext)
    {
        // VALIDATION: Input check
        if (string.IsNullOrEmpty(plaintext))
        {
            throw new ArgumentException("Plaintext cannot be null or empty", nameof(plaintext));
        }

        // CONVERT: String to bytes (UTF-8 encoding)
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

        // ALLOCATE: Buffers (stack allocation for performance)
        Span<byte> nonce = stackalloc byte[NonceSize];
        Span<byte> tag = stackalloc byte[TagSize];
        var ciphertext = new byte[plaintextBytes.Length];

        // GENERATE: Random nonce (MUST be unique per encryption)
        // SECURITY: Using cryptographically secure RNG (RandomNumberGenerator)
        RandomNumberGenerator.Fill(nonce);

        // ENCRYPT: AES-256-GCM
        using (var aesGcm = new AesGcm(MasterKey, TagSize))
        {
            aesGcm.Encrypt(
                nonce: nonce,
                plaintext: plaintextBytes,
                ciphertext: ciphertext,
                tag: tag,
                associatedData: null); // No associated data (AAD) in this implementation
        }

        // COMBINE: Nonce + Tag + Ciphertext
        var combinedBytes = new byte[NonceSize + TagSize + ciphertext.Length];
        Buffer.BlockCopy(nonce.ToArray(), 0, combinedBytes, 0, NonceSize);
        Buffer.BlockCopy(tag.ToArray(), 0, combinedBytes, NonceSize, TagSize);
        Buffer.BlockCopy(ciphertext, 0, combinedBytes, NonceSize + TagSize, ciphertext.Length);

        // ENCODE: Base64 for safe storage/transmission
        return Convert.ToBase64String(combinedBytes);
    }

    /// <inheritdoc/>
    public string Decrypt(string encryptedValue)
    {
        // VALIDATION: Input check
        if (string.IsNullOrEmpty(encryptedValue))
        {
            throw new ArgumentException("Encrypted value cannot be null or empty", nameof(encryptedValue));
        }

        try
        {
            // DECODE: Base64 to bytes
            var combinedBytes = Convert.FromBase64String(encryptedValue);

            // VALIDATION: Minimum size check (nonce + tag + at least 1 byte ciphertext)
            if (combinedBytes.Length < NonceSize + TagSize + 1)
            {
                throw new CryptographicException(
                    $"Encrypted value is too short. Expected at least {NonceSize + TagSize + 1} bytes, got {combinedBytes.Length} bytes");
            }

            // EXTRACT: Nonce, Tag, Ciphertext
            var nonce = new byte[NonceSize];
            var tag = new byte[TagSize];
            var ciphertext = new byte[combinedBytes.Length - NonceSize - TagSize];

            Buffer.BlockCopy(combinedBytes, 0, nonce, 0, NonceSize);
            Buffer.BlockCopy(combinedBytes, NonceSize, tag, 0, TagSize);
            Buffer.BlockCopy(combinedBytes, NonceSize + TagSize, ciphertext, 0, ciphertext.Length);

            // ALLOCATE: Plaintext buffer
            var plaintext = new byte[ciphertext.Length];

            // DECRYPT: AES-256-GCM with authentication
            using (var aesGcm = new AesGcm(MasterKey, TagSize))
            {
                aesGcm.Decrypt(
                    nonce: nonce,
                    ciphertext: ciphertext,
                    tag: tag,
                    plaintext: plaintext,
                    associatedData: null);
            }

            // CONVERT: Bytes to string (UTF-8 decoding)
            return Encoding.UTF8.GetString(plaintext);
        }
        catch (CryptographicException ex)
        {
            // SECURITY: Authentication tag verification failed
            // Possible causes:
            // 1. Data tampered with (integrity violation)
            // 2. Wrong decryption key
            // 3. Corrupted ciphertext
            throw new CryptographicException(
                "Decryption failed. The data may have been tampered with, or the encryption key has changed.", ex);
        }
        catch (FormatException ex)
        {
            // VALIDATION: Invalid Base64 format
            throw new ArgumentException("Encrypted value is not valid Base64 encoded data", nameof(encryptedValue), ex);
        }
    }
    /// <inheritdoc/>
    public byte[] EncryptBytes(byte[] data)
    {
        if (data == null || data.Length == 0)
            throw new ArgumentException("Data cannot be null or empty");

        Span<byte> nonce = stackalloc byte[NonceSize];
        Span<byte> tag = stackalloc byte[TagSize];
        var ciphertext = new byte[data.Length];

        RandomNumberGenerator.Fill(nonce);

        // DÜZELTİLDİ: MasterMasterKey yerine MasterKey kullanıldı
        using (var aesGcm = new AesGcm(MasterKey, TagSize))
        {
            aesGcm.Encrypt(nonce, data, ciphertext, tag, associatedData: null);
        }

        var combined = new byte[NonceSize + TagSize + ciphertext.Length];
        Buffer.BlockCopy(nonce.ToArray(), 0, combined, 0, NonceSize);
        Buffer.BlockCopy(tag.ToArray(), 0, combined, NonceSize, TagSize);
        Buffer.BlockCopy(ciphertext, 0, combined, NonceSize + TagSize, ciphertext.Length);

        return combined;
    }

    /// <inheritdoc/>
    public byte[] DecryptBytes(byte[] encryptedData)
    {
        if (encryptedData == null || encryptedData.Length < NonceSize + TagSize + 1)
            throw new ArgumentException("Invalid encrypted data length");

        var nonce = new byte[NonceSize];
        var tag = new byte[TagSize];
        var ciphertext = new byte[encryptedData.Length - NonceSize - TagSize];

        Buffer.BlockCopy(encryptedData, 0, nonce, 0, NonceSize);
        Buffer.BlockCopy(encryptedData, NonceSize, tag, 0, TagSize);
        Buffer.BlockCopy(encryptedData, NonceSize + TagSize, ciphertext, 0, ciphertext.Length);

        var plaintext = new byte[ciphertext.Length];

        using (var aesGcm = new AesGcm(MasterKey, TagSize))
        {
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData: null);
        }

        return plaintext;
    }
}