using FluentValidation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using VaultGuard.Application.DTOs.Auth;

namespace VaultGuard.Application.Validators;

/// <summary>
/// Validator for user registration DTO with comprehensive security checks.
/// 
/// SECURITY ARCHITECTURE:
/// - OWASP Password Guidelines: 8+ chars, complexity requirements
/// - XSS Prevention: Username sanitization (no special HTML chars)
/// - DoS Prevention: Length limits on all fields
/// - SQL Injection: Parameterized queries (handled by EF Core, validation adds defense)
/// - Email Validation: RFC 5322 compliant format
/// 
/// THREAT MODEL MITIGATION:
/// - Account Enumeration: Generic error messages (implemented at service layer)
/// - Brute Force: Rate limiting (implemented at middleware layer)
/// - Password Spraying: Complexity requirements + lockout policy
/// - Unicode Attacks: Restrict to ASCII alphanumeric for username
/// 
/// COMPLIANCE:
/// - NIST SP 800-63B: Password length and complexity
/// - OWASP ASVS 4.0: Authentication verification requirements
/// - PCI-DSS 8.2.3: Strong password requirements
/// </summary>
public sealed class RegisterDtoValidator : AbstractValidator<RegisterDto>
{
    // Security patterns
    private static readonly Regex UsernamePattern = new(
        @"^[a-zA-Z0-9._-]+$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100)); // Timeout to prevent ReDoS attacks

    private static readonly Regex PasswordComplexityPattern = new(
        @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(100));

    // Common weak passwords blacklist (subset for demo, expand in production)
    private static readonly HashSet<string> WeakPasswords = new(StringComparer.OrdinalIgnoreCase)
    {
        "password", "Password1!", "12345678", "Qwerty123!", "Admin123!",
        "Welcome1!", "Passw0rd!", "P@ssw0rd", "Password123!", "Abcd1234!"
    };

    public RegisterDtoValidator()
    {
        // ====================================================================
        // EMAIL VALIDATION
        // ====================================================================
        RuleFor(x => x.Email)
            .NotEmpty()
            .WithMessage("Email address is required for account creation")
            .EmailAddress()
            .WithMessage("Invalid email address format. Please provide a valid email (e.g., user@example.com)")
            .Must(email => string.IsNullOrEmpty(email) || !email.Trim().Contains(' '))
            .WithMessage("Email address cannot contain spaces")
            .MaximumLength(100)
            .WithMessage("Email address cannot exceed 100 characters (security: DoS prevention)")
            .Must(email => !string.IsNullOrEmpty(email) && !ContainsScriptTags(email))
            .WithMessage("Email address contains invalid characters (security: XSS prevention)");

        // ====================================================================
        // USERNAME VALIDATION
        // ====================================================================
        RuleFor(x => x.Username)
            .NotEmpty()
            .WithMessage("Username is required for account creation")
            .Length(3, 50)
            .WithMessage("Username must be between 3 and 50 characters (security: prevent enumeration + DoS)")
            .Must(username => !string.IsNullOrEmpty(username) && UsernamePattern.IsMatch(username))
            .WithMessage("Username can only contain letters (a-z, A-Z), numbers (0-9), dots (.), underscores (_), and hyphens (-). " +
                        "No spaces or special characters allowed (security: injection prevention)")
            .Must(username => string.IsNullOrEmpty(username) || (!username.StartsWith(".") && !username.EndsWith(".")))
            .WithMessage("Username cannot start or end with a dot (security: path traversal prevention)")
            .Must(username => string.IsNullOrEmpty(username) || !username.Contains(".."))
            .WithMessage("Username cannot contain consecutive dots (security: path traversal prevention)")
            .Must(username => string.IsNullOrEmpty(username) || !ContainsReservedKeywords(username))
            .WithMessage("Username contains reserved system keywords and cannot be used (security: privilege escalation prevention)");

        // ====================================================================
        // PASSWORD VALIDATION (OWASP + NIST Guidelines)
        // ====================================================================
        RuleFor(x => x.Password)
            .NotEmpty()
            .WithMessage("Password is required for account security")
            .MinimumLength(8)
            .WithMessage("Password must be at least 8 characters long (security: OWASP/NIST recommendation is 12+, but 8 minimum)")
            .MaximumLength(128)
            .WithMessage("Password cannot exceed 128 characters (security: DoS prevention)")
            .Must(password => !string.IsNullOrEmpty(password) && PasswordComplexityPattern.IsMatch(password))
            .WithMessage("Password must contain at least: " +
                        "1 uppercase letter (A-Z), " +
                        "1 lowercase letter (a-z), " +
                        "1 digit (0-9), " +
                        "1 special character (!@#$%^&*()-_=+[]{}|;:,.<>?) " +
                        "(security: OWASP complexity requirements)")
            .Must(password => string.IsNullOrEmpty(password) || !WeakPasswords.Contains(password))
            .WithMessage("Password is too common and easily guessable. Please choose a stronger password " +
                        "(security: prevent password spraying attacks)")
            .Must((dto, password) => string.IsNullOrEmpty(password) || string.IsNullOrEmpty(dto.Username) || !password.Contains(dto.Username, StringComparison.OrdinalIgnoreCase))
            .WithMessage("Password cannot contain your username (security: prevent predictable passwords)")
            .Must((dto, password) => string.IsNullOrEmpty(password) || string.IsNullOrEmpty(dto.Email) || !password.Contains(dto.Email.Split('@')[0], StringComparison.OrdinalIgnoreCase))
            .WithMessage("Password cannot contain parts of your email address (security: prevent predictable passwords)");

        // ====================================================================
        // CONFIRM PASSWORD VALIDATION
        // ====================================================================
        RuleFor(x => x.ConfirmPassword)
            .NotEmpty()
            .WithMessage("Password confirmation is required to prevent typos")
            .Equal(x => x.Password)
            .WithMessage("Password and confirmation password do not match. Please re-enter your password")
            .When(x => !string.IsNullOrEmpty(x.Password)); // Only check if Password is provided
    }

    /// <summary>
    /// Checks if input contains HTML/Script tags (XSS prevention).
    /// </summary>
    private static bool ContainsScriptTags(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return false;

        // Detect common XSS patterns (case-insensitive)
        var xssPatterns = new[]
        {
            "<script", "</script>", "javascript:", "onerror=", "onload=",
            "<iframe", "<object", "<embed", "<img", "src=", "href="
        };

        return xssPatterns.Any(pattern =>
            input.Contains(pattern, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Checks if username contains reserved system keywords (privilege escalation prevention).
    /// </summary>
    private static bool ContainsReservedKeywords(string username)
    {
        var reservedKeywords = new[]
        {
            "admin", "administrator", "root", "system", "superuser",
            "sysadmin", "moderator", "support", "helpdesk", "vaultguard"
        };

        return reservedKeywords.Any(keyword =>
            username.Equals(keyword, StringComparison.OrdinalIgnoreCase) ||
            username.Contains(keyword, StringComparison.OrdinalIgnoreCase));
    }
}