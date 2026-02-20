using FluentValidation;
using System;
using System.Linq;
using System.Text.RegularExpressions;
using VaultGuard.Application.DTOs.Secrets;

namespace VaultGuard.Application.Validators;

/// <summary>
/// Validator for secret creation DTO with comprehensive security checks.
/// 
/// SECURITY ARCHITECTURE:
/// - XSS Prevention: No HTML/Script tags in title/description
/// - DoS Prevention: Max 10KB for secret value (RawValue)
/// - Injection Prevention: Sanitize inputs (EF Core handles SQL, but defense in depth)
/// - Data Validation: Expiration date must be future, not past
/// 
/// THREAT MODEL MITIGATION:
/// - Storage Exhaustion: 10KB limit per secret, 1000 secrets per user
/// - XSS Attacks: HTML tag detection in user-provided text
/// - Memory DoS: Length limits on all string fields
/// - Time Manipulation: Expiration date validation
/// 
/// COMPLIANCE:
/// - OWASP Top 10 A03:2021 - Injection
/// - OWASP Top 10 A07:2021 - XSS
/// - PCI-DSS 6.5.1: Injection flaws
/// </summary>
public sealed class CreateSecretDtoValidator : AbstractValidator<CreateSecretDto>
{
    // XSS detection pattern (more comprehensive than RegisterDto)
    private static readonly Regex HtmlScriptPattern = new(
        @"<script|</script>|javascript:|onerror=|onload=|<iframe|<object|<embed|<img|<svg|<link|<meta|<style",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    public CreateSecretDtoValidator()
    {
        // ====================================================================
        // TITLE VALIDATION
        // ====================================================================
        RuleFor(x => x.Title)
            .NotEmpty()
            .WithMessage("Secret title is required for organization and identification")
            .Length(3, 200)
            .WithMessage("Secret title must be between 3 and 200 characters (security: prevent abuse + ensure usability)")
            .Must(title => !HtmlScriptPattern.IsMatch(title))
            .WithMessage("Secret title contains potentially dangerous HTML or script tags (security: XSS prevention). " +
                        "Please use plain text only")
            .Must(title => !ContainsSqlKeywords(title))
            .WithMessage("Secret title contains SQL keywords that could indicate an injection attempt (security: defense in depth)")
            .Must(title => title.Trim() == title)
            .WithMessage("Secret title cannot start or end with whitespace (data quality: prevent accidental spaces)");

        // ====================================================================
        // RAW VALUE VALIDATION (PLAINTEXT SECRET)
        // ====================================================================
        RuleFor(x => x.RawValue)
            .NotEmpty()
            .WithMessage("Secret value is required (this is the sensitive data you want to protect)")
            .MaximumLength(10000)
            .WithMessage("Secret value cannot exceed 10,000 characters (10KB limit). " +
                        "This limit prevents storage exhaustion and memory-based DoS attacks. " +
                        "For larger secrets, consider splitting into multiple entries")
            .Must(rawValue => rawValue.Trim().Length > 0)
            .WithMessage("Secret value cannot be empty or consist only of whitespace");

        // ====================================================================
        // DESCRIPTION VALIDATION (Optional)
        // ====================================================================
        RuleFor(x => x.Description)
            .MaximumLength(1000)
            .WithMessage("Secret description cannot exceed 1,000 characters (security: DoS prevention)")
            .Must(desc => string.IsNullOrWhiteSpace(desc) || !HtmlScriptPattern.IsMatch(desc))
            .WithMessage("Secret description contains potentially dangerous HTML or script tags (security: XSS prevention)")
            .When(x => !string.IsNullOrWhiteSpace(x.Description));

        // ====================================================================
        // CATEGORY VALIDATION (Optional)
        // ====================================================================
        RuleFor(x => x.Category)
            .MaximumLength(50)
            .WithMessage("Secret category cannot exceed 50 characters (security: DoS prevention)")
            .Must(cat => string.IsNullOrWhiteSpace(cat) || IsValidCategory(cat))
            .WithMessage("Secret category contains invalid characters. Only letters, numbers, spaces, and hyphens allowed")
            .When(x => !string.IsNullOrWhiteSpace(x.Category));

        // ====================================================================
        // EXPIRATION DATE VALIDATION (Optional)
        // ====================================================================
        RuleFor(x => x.ExpiresAt)
            .Must(expiresAt => expiresAt > DateTime.UtcNow)
.WithMessage($"Secret expiration date must be in the future. Current UTC time: {DateTime.UtcNow:O}")
            .Must(expiresAt => expiresAt <= DateTime.UtcNow.AddYears(10))
            .WithMessage("Secret expiration date cannot be more than 10 years in the future " +
                        "(security: prevent unrealistic dates)")
            .When(x => x.ExpiresAt.HasValue);
    }

    /// <summary>
    /// Checks if input contains common SQL keywords (defense in depth).
    /// Note: EF Core uses parameterized queries (safe), but this adds extra protection.
    /// </summary>
    private static bool ContainsSqlKeywords(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return false;

        var sqlKeywords = new[]
        {
            "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ", "CREATE ",
            "ALTER ", "EXEC ", "EXECUTE ", "SCRIPT ", "UNION ", "OR 1=1",
            "'; ", "--", "/*", "*/", "xp_", "sp_"
        };

        return sqlKeywords.Any(keyword =>
            input.Contains(keyword, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Validates category format (alphanumeric + spaces + hyphens only).
    /// </summary>
    private static bool IsValidCategory(string category)
    {
        // Allow: letters, numbers, spaces, hyphens, underscores
        return Regex.IsMatch(category, @"^[a-zA-Z0-9\s\-_]+$", RegexOptions.None, TimeSpan.FromMilliseconds(100));
    }
}