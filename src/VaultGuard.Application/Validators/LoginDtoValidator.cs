using FluentValidation;
using VaultGuard.Application.DTOs.Auth;

namespace VaultGuard.Application.Validators;

/// <summary>
/// Validator for user login DTO with minimal validation rules.
/// 
/// SECURITY ARCHITECTURE:
/// - Minimal Validation: Only check for non-empty fields (avoid information leakage)
/// - No Complexity Check: Password complexity checked at registration, not login
/// - Generic Errors: Don't reveal if email exists (prevent account enumeration)
/// - Rate Limiting: Handled at middleware/service layer (not validation)
/// 
/// WHY MINIMAL VALIDATION AT LOGIN?
/// 1. User Experience: Don't frustrate users with complex rules at login
/// 2. Security: Avoid information disclosure (e.g., "Invalid email format" reveals email exists)
/// 3. Performance: Faster validation = faster login response
/// 4. Brute Force: Rate limiting is more effective than complex validation
/// 
/// THREAT MODEL:
/// - Brute Force: Mitigated by rate limiting middleware (100 attempts/hour per IP)
/// - Account Enumeration: Generic error messages at service layer
/// - Credential Stuffing: CAPTCHA after 3 failed attempts (implemented at controller)
/// - SQL Injection: Parameterized queries (EF Core) + basic sanitization
/// 
/// COMPLIANCE:
/// - OWASP ASVS 4.0 V2.1: Authentication mechanisms
/// - NIST SP 800-63B: Memorized secret authenticators
/// </summary>
public sealed class LoginDtoValidator : AbstractValidator<LoginDto>
{
    public LoginDtoValidator()
    {
        // ====================================================================
        // EMAIL VALIDATION (Minimal)
        // ====================================================================
        RuleFor(x => x.Email)
            .NotEmpty()
            .WithMessage("Email address is required")
            .EmailAddress()
            .WithMessage("Please provide a valid email address")
            .Must(email => string.IsNullOrEmpty(email) || !email.Trim().Contains(' '))
            .WithMessage("Email address cannot contain spaces")
            .Must(email => string.IsNullOrEmpty(email) || !email.Contains('<') && !email.Contains('>'))
            .WithMessage("Email address contains invalid characters (security: XSS prevention)")
            .MaximumLength(100)
            .WithMessage("Email address is too long (security: DoS prevention)");

        // ====================================================================
        // PASSWORD VALIDATION (Minimal)
        // ====================================================================
        RuleFor(x => x.Password)
            .NotEmpty()
            .WithMessage("Password is required")
            .MaximumLength(128)
            .WithMessage("Password is too long (security: DoS prevention)");

        // NOTE: No password complexity validation at login
        // - Complexity enforced at registration
        // - Users may have accounts created before complexity rules changed
        // - Avoid frustration: "Your password doesn't meet requirements" at login is bad UX
        // - Security handled by: rate limiting, account lockout, CAPTCHA
    }
}