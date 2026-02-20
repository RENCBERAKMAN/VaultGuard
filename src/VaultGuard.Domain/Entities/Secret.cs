using System;
using VaultGuard.Domain.Common;

namespace VaultGuard.Domain.Entities;

/// <summary>
/// SECRET ENTITY: Elite Domain-Driven Design Implementation
/// </summary>
public sealed class Secret : BaseEntity
{
    // ============================================================================
    // PUBLIC PROPERTIES (Encapsulation via private set)
    // ============================================================================

    public string Title { get; private set; } = string.Empty;
    public string Description { get; private set; } = string.Empty;
    public string EncryptedValue { get; private set; } = string.Empty;
    public byte[] IV { get; private set; } = Array.Empty<byte>();
    public string Category { get; private set; } = "Other";
    public Guid UserId { get; private set; }
    public DateTime? ExpiresAt { get; private set; }
    public int AccessCount { get; private set; }
    public DateTime? LastAccessedAt { get; private set; }

    // ============================================================================
    // ALIAS PROPERTIES (Test Compatibility)
    // ============================================================================

    public string Name => Title;
    public string EncryptedData => EncryptedValue;

    // ============================================================================
    // QUERY PROPERTIES (Business Logic)
    // ============================================================================

    public bool IsExpired => ExpiresAt.HasValue && ExpiresAt.Value < DateTime.UtcNow;
    public bool IsAccessible => !IsDeleted && !IsExpired;

    // ============================================================================
    // PRIVATE CONSTRUCTOR (EF Core)
    // ============================================================================

    private Secret() : base()
    {
        // EF Core requires parameterless constructor
    }

    // ============================================================================
    // FACTORY METHOD (DDD Pattern)
    // ============================================================================

    public static Secret Create(
        string title,
        string encryptedValue,
        byte[] iv,
        Guid userId,
        string category = "Other",
        string? description = null,
        DateTime? expiresAt = null)
    {
        var validatedTitle = ValidateTitle(title);
        var validatedEncryptedValue = ValidateEncryptedValue(encryptedValue);
        var validatedIV = ValidateIV(iv);
        var validatedUserId = ValidateUserId(userId);
        var validatedCategory = ValidateCategory(category);
        var validatedDescription = ValidateDescription(description);
        var validatedExpiresAt = ValidateExpiresAt(expiresAt);

        return new Secret
        {
            Id = Guid.NewGuid(),
            Title = validatedTitle,
            Description = validatedDescription,
            EncryptedValue = validatedEncryptedValue,
            IV = validatedIV,
            Category = validatedCategory,
            UserId = validatedUserId,
            ExpiresAt = validatedExpiresAt,
            AccessCount = 0,
            LastAccessedAt = null,
            CreatedAt = DateTime.UtcNow
            // UpdatedAt KALDIRILDI - BaseEntity constructor'ı halleder!
        };
    }

    // ============================================================================
    // BUSINESS METHODS (Rich Domain Model)
    // ============================================================================

    public void UpdateTitle(string newTitle)
    {
        var validatedTitle = ValidateTitle(newTitle);
        if (Title == validatedTitle) return;
        Title = validatedTitle;
        UpdateTimestamp();
    }

    public void UpdateDescription(string? newDescription)
    {
        var validatedDescription = ValidateDescription(newDescription);
        if (Description == validatedDescription) return;
        Description = validatedDescription;
        UpdateTimestamp();
    }

    public void UpdateCategory(string newCategory)
    {
        var validatedCategory = ValidateCategory(newCategory);
        if (Category == validatedCategory) return;
        Category = validatedCategory;
        UpdateTimestamp();
    }

    public void ReEncrypt(string newEncryptedValue, byte[] newIV)
    {
        var validatedEncryptedValue = ValidateEncryptedValue(newEncryptedValue);
        var validatedIV = ValidateIV(newIV);
        EncryptedValue = validatedEncryptedValue;
        IV = validatedIV;
        UpdateTimestamp();
    }

    public void SetExpiration(DateTime? expiresAt)
    {
        var validatedExpiresAt = ValidateExpiresAt(expiresAt);
        if (ExpiresAt == validatedExpiresAt) return;
        ExpiresAt = validatedExpiresAt;
        UpdateTimestamp();
    }

    public void RecordAccess()
    {
        AccessCount++;
        LastAccessedAt = DateTime.UtcNow;
        UpdateTimestamp();
    }

    public void ExtendExpiration(int days)
    {
        if (days <= 0)
            throw new ArgumentException("Days must be positive", nameof(days));
        if (!ExpiresAt.HasValue)
            throw new InvalidOperationException("Cannot extend secret without expiration");
        if (IsExpired)
            throw new InvalidOperationException("Cannot extend expired secret");

        ExpiresAt = ExpiresAt.Value.AddDays(days);
        UpdateTimestamp();
    }

    // ============================================================================
    // QUERY METHODS (Business Rules)
    // ============================================================================

    public bool CanDecrypt() => !IsDeleted && !IsExpired;
    public bool IsOwnedBy(Guid userId) => UserId == userId;

    public int? DaysUntilExpiration
    {
        get
        {
            if (!ExpiresAt.HasValue) return null;
            var timeSpan = ExpiresAt.Value - DateTime.UtcNow;
            return (int)Math.Ceiling(timeSpan.TotalDays);
        }
    }

    // ============================================================================
    // PRIVATE VALIDATION METHODS
    // ============================================================================

    private static string ValidateTitle(string title)
    {
        if (string.IsNullOrWhiteSpace(title))
            throw new ArgumentException("Secret title cannot be empty", nameof(title));

        var trimmed = title.Trim();
        if (trimmed.Length > 200)
            throw new ArgumentException("Secret title too long (max 200 characters)", nameof(title));

        return trimmed;
    }

    private static string ValidateDescription(string? description)
    {
        if (string.IsNullOrWhiteSpace(description))
            return string.Empty;

        var trimmed = description.Trim();
        if (trimmed.Length > 500)
            throw new ArgumentException("Secret description too long (max 500 characters)", nameof(description));

        return trimmed;
    }

    private static string ValidateEncryptedValue(string encryptedValue)
    {
        if (string.IsNullOrWhiteSpace(encryptedValue))
            throw new ArgumentException("Encrypted value cannot be empty", nameof(encryptedValue));

        var trimmed = encryptedValue.Trim();
        if (trimmed.Length % 4 != 0)
            throw new ArgumentException("Invalid encrypted value format (not Base64)", nameof(encryptedValue));
        if (trimmed.Length < 44)
            throw new ArgumentException("Encrypted value too short - must be AES-256-GCM ciphertext", nameof(encryptedValue));

        return trimmed;
    }

    private static byte[] ValidateIV(byte[] iv)
    {
        if (iv == null || iv.Length == 0)
            throw new ArgumentException("IV cannot be null or empty", nameof(iv));
        if (iv.Length != 12)
            throw new ArgumentException("IV must be exactly 12 bytes (96 bits) for AES-GCM", nameof(iv));

        return iv;
    }

    private static Guid ValidateUserId(Guid userId)
    {
        if (userId == Guid.Empty)
            throw new ArgumentException("User ID cannot be empty", nameof(userId));

        return userId;
    }

    private static string ValidateCategory(string category)
    {
        if (string.IsNullOrWhiteSpace(category))
            return "Other";

        var trimmed = category.Trim();
        var validCategories = new[] { "Password", "ApiKey", "CreditCard", "Note", "Other" };
        var matched = Array.Find(validCategories, c => c.Equals(trimmed, StringComparison.OrdinalIgnoreCase));

        if (matched == null)
            throw new ArgumentException($"Invalid category. Valid categories: {string.Join(", ", validCategories)}", nameof(category));

        return matched;
    }

    private static DateTime? ValidateExpiresAt(DateTime? expiresAt)
    {
        if (!expiresAt.HasValue)
            return null;

        if (expiresAt.Value <= DateTime.UtcNow)
            throw new ArgumentException("Expiration date must be in the future", nameof(expiresAt));
        if (expiresAt.Value > DateTime.UtcNow.AddYears(10))
            throw new ArgumentException("Expiration date too far in future (max 10 years)", nameof(expiresAt));

        return expiresAt.Value;
    }
}