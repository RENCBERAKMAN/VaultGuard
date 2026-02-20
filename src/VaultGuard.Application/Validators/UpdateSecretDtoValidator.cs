using FluentValidation;
using System;
using System.Linq;
using System.Text.RegularExpressions;
using VaultGuard.Application.DTOs.Secrets;

namespace VaultGuard.Application.Validators;

/// <summary>
/// Validator for secret update DTO with partial update support.
/// 
/// SECURITY ARCHITECTURE:
/// - Partial Validation: Only validate fields that are provided (non-null)
/// - Same Rules: Apply same security checks as CreateSecretDto
/// - ID Validation: Ensure valid Guid (not empty)
/// 
/// PARTIAL UPDATE PATTERN:
/// - Null values = no change (field not updated)
/// - Non-null values = validated and updated
/// - Example: { Id: "...", Title: "New Title" } → Only title validated/updated
/// 
/// THREAT MODEL:
/// - Same as CreateSecretDto (XSS, DoS, Injection)
/// - Additional: ID manipulation (ensure valid Guid)
/// 
/// COMPLIANCE:
/// - OWASP Top 10 A03:2021 - Injection
/// - OWASP Top 10 A07:2021 - XSS
/// </summary>
public sealed class UpdateSecretDtoValidator : AbstractValidator<UpdateSecretDto>
{
    // XSS detection pattern (reused from CreateSecretDtoValidator)
    private static readonly Regex HtmlScriptPattern = new(
        @"<script|</script>|javascript:|onerror=|onload=|<iframe|<object|<embed|<img|<svg|<link|<meta|<style",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    public UpdateSecretDtoValidator()
    {
        // ====================================================================
        // ID VALIDATION (Required)
        // ====================================================================
        RuleFor(x => x.Id)
            .NotEmpty()
            .WithMessage("Secret ID is required to identify which secret to update")
            .NotEqual(Guid.Empty)
            .WithMessage("Secret ID cannot be an empty GUID (security: prevent invalid operations)");

        // ====================================================================
        // TITLE VALIDATION (Optional - only if provided)
        // ====================================================================
        RuleFor(x => x.Title)
            .Length(3, 200)
            .WithMessage("Secret title must be between 3 and 200 characters (security: prevent abuse + ensure usability)")
            .Must(title => !HtmlScriptPattern.IsMatch(title!))
            .WithMessage("Secret title contains potentially dangerous HTML or script tags (security: XSS prevention). " +
                        "Please use plain text only")
            .Must(title => !ContainsSqlKeywords(title!))
            .WithMessage("Secret title contains SQL keywords that could indicate an injection attempt (security: defense in depth)")
            .Must(title => title!.Trim() == title)
            .WithMessage("Secret title cannot start or end with whitespace (data quality: prevent accidental spaces)")
            .When(x => !string.IsNullOrWhiteSpace(x.Title)); // Only validate if Title is provided

        // ====================================================================
        // DESCRIPTION VALIDATION (Optional - only if provided)
        // ====================================================================
        RuleFor(x => x.Description)
            .MaximumLength(1000)
            .WithMessage("Secret description cannot exceed 1,000 characters (security: DoS prevention)")
            .Must(desc => !HtmlScriptPattern.IsMatch(desc!))
            .WithMessage("Secret description contains potentially dangerous HTML or script tags (security: XSS prevention)")
            .When(x => x.Description != null); // Only validate if Description is explicitly set (even if empty string)

        // ====================================================================
        // NEW RAW VALUE VALIDATION (Optional - only if provided)
        // ====================================================================
        RuleFor(x => x.NewRawValue)
            .NotEmpty()
            .WithMessage("New secret value cannot be empty if provided. To keep existing value, omit this field")
            .MaximumLength(10000)
            .WithMessage("New secret value cannot exceed 10,000 characters (10KB limit). " +
                        "This limit prevents storage exhaustion and memory-based DoS attacks")
            .Must(rawValue => rawValue!.Trim().Length > 0)
            .WithMessage("New secret value cannot consist only of whitespace")
            .When(x => !string.IsNullOrWhiteSpace(x.NewRawValue)); // Only validate if NewRawValue is provided

        // ====================================================================
        // CATEGORY VALIDATION (Optional - only if provided)
        // ====================================================================
        RuleFor(x => x.Category)
            .MaximumLength(50)
            .WithMessage("Secret category cannot exceed 50 characters (security: DoS prevention)")
            .Must(cat => IsValidCategory(cat!))
            .WithMessage("Secret category contains invalid characters. Only letters, numbers, spaces, and hyphens allowed")
            .When(x => x.Category != null); // Only validate if Category is explicitly set

        // ====================================================================
        // EXPIRATION DATE VALIDATION (Optional - only if provided)
        // ====================================================================
        RuleFor(x => x.ExpiresAt)
            .Must(expiresAt => expiresAt > DateTime.UtcNow)
            .WithMessage($"Secret expiration date must be in the future. " +
            $"Current UTC time: {DateTime.UtcNow:O}. " +
            "(security: prevent backdating attacks)")
            .Must(expiresAt => expiresAt <= DateTime.UtcNow.AddYears(10))
            .WithMessage("Secret expiration date cannot be more than 10 years in the future " +
                        "(security: prevent unrealistic dates)")
            .When(x => x.ExpiresAt.HasValue);

        // ====================================================================
        // BUSINESS RULE: At least one field must be updated
        // ====================================================================
        RuleFor(x => x)
            .Must(dto => HasAtLeastOneFieldToUpdate(dto))
            .WithMessage("At least one field must be provided for update. " +
                        "Available fields: Title, Description, NewRawValue, Category, ExpiresAt")
            .OverridePropertyName("UpdateSecretDto"); // Show error at root level, not specific property
    }

    /// <summary>
    /// Checks if at least one field is provided for update.
    /// </summary>
    private static bool HasAtLeastOneFieldToUpdate(UpdateSecretDto dto)
    {
        return !string.IsNullOrWhiteSpace(dto.Title) ||
               dto.Description != null ||
               !string.IsNullOrWhiteSpace(dto.NewRawValue) ||
               dto.Category != null ||
               dto.ExpiresAt.HasValue;
    }

    /// <summary>
    /// Checks if input contains common SQL keywords (defense in depth).
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