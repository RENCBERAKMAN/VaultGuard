using System;
using System.Linq;
using System.Text.RegularExpressions;
using VaultGuard.Domain.Common;

namespace VaultGuard.Domain.Entities;

/// <summary>
/// USER ENTITY: Elite Domain-Driven Design Implementation
/// </summary>
public sealed class User : BaseEntity
{
    // ============================================================================
    // PUBLIC PROPERTIES (Encapsulation via private set)
    // ============================================================================

    public string Email { get; private set; } = string.Empty;
    public string Username { get; private set; } = string.Empty;
    public string PasswordHash { get; private set; } = string.Empty;
    public string FirstName { get; private set; } = string.Empty;
    public string LastName { get; private set; } = string.Empty;
    public string PhoneNumber { get; private set; } = string.Empty;
    public string Role { get; private set; } = "User";
    public string SecurityStamp { get; private set; } = Guid.NewGuid().ToString();
    public bool IsActive { get; private set; } = true;
    public DateTime? LastLoginAt { get; private set; }
    public string? RefreshToken { get; private set; }
    public DateTime? RefreshTokenExpiryTime { get; private set; }

    // ============================================================================
    // PRIVATE CONSTRUCTOR (EF Core)
    // ============================================================================

    private User() : base()
    {
        // EF Core requires parameterless constructor
    }

    // ============================================================================
    // FACTORY METHOD (DDD Pattern)
    // ============================================================================

    public static User Create(string email, string username, string passwordHash, string role = "User")
    {
        var normalizedEmail = ValidateAndNormalizeEmail(email);
        var validatedUsername = ValidateUsername(username);
        var validatedPasswordHash = ValidatePasswordHash(passwordHash);
        var validatedRole = ValidateRole(role);

        return new User
        {
            Id = Guid.NewGuid(),
            Email = normalizedEmail,
            Username = validatedUsername,
            PasswordHash = validatedPasswordHash,
            Role = validatedRole,
            SecurityStamp = Guid.NewGuid().ToString(),
            IsActive = true,
            CreatedAt = DateTime.UtcNow
            // UpdatedAt KALDIRILDI - BaseEntity constructor'ı halleder!
        };
    }

    // ============================================================================
    // BUSINESS METHODS (Rich Domain Model)
    // ============================================================================

    public void UpdateEmail(string newEmail)
    {
        var normalizedEmail = ValidateAndNormalizeEmail(newEmail);
        if (Email == normalizedEmail) return;
        Email = normalizedEmail;
        UpdateTimestamp();
    }

    public void UpdateUsername(string newUsername)
    {
        var validatedUsername = ValidateUsername(newUsername);
        if (Username == validatedUsername) return;
        Username = validatedUsername;
        UpdateTimestamp();
    }

    public void ChangePassword(string newPasswordHash)
    {
        var validatedPasswordHash = ValidatePasswordHash(newPasswordHash);
        PasswordHash = validatedPasswordHash;
        SecurityStamp = Guid.NewGuid().ToString();
        RefreshToken = null;
        RefreshTokenExpiryTime = null;
        UpdateTimestamp();
    }

    public void UpdateProfile(string? firstName = null, string? lastName = null, string? phoneNumber = null)
    {
        if (firstName != null)
        {
            var trimmed = firstName.Trim();
            if (trimmed.Length > 100)
                throw new ArgumentException("First name too long (max 100 characters)", nameof(firstName));
            FirstName = trimmed;
        }

        if (lastName != null)
        {
            var trimmed = lastName.Trim();
            if (trimmed.Length > 100)
                throw new ArgumentException("Last name too long (max 100 characters)", nameof(lastName));
            LastName = trimmed;
        }

        if (phoneNumber != null)
        {
            var trimmed = phoneNumber.Trim();
            if (trimmed.Length > 20)
                throw new ArgumentException("Phone number too long (max 20 characters)", nameof(phoneNumber));
            PhoneNumber = trimmed;
        }

        UpdateTimestamp();
    }

    public void ChangeRole(string newRole)
    {
        var validatedRole = ValidateRole(newRole);
        if (Role == validatedRole) return;
        Role = validatedRole;
        SecurityStamp = Guid.NewGuid().ToString();
        RefreshToken = null;
        RefreshTokenExpiryTime = null;
        UpdateTimestamp();
    }

    public void Deactivate()
    {
        if (!IsActive)
            throw new InvalidOperationException("User already deactivated");
        IsActive = false;
        SecurityStamp = Guid.NewGuid().ToString();
        RefreshToken = null;
        RefreshTokenExpiryTime = null;
        UpdateTimestamp();
    }

    public void Activate()
    {
        if (IsActive)
            throw new InvalidOperationException("User already active");
        IsActive = true;
        UpdateTimestamp();
    }

    public void RecordLogin()
    {
        LastLoginAt = DateTime.UtcNow;
        UpdateTimestamp();
    }

    public void UpdateRefreshToken(string? token, DateTime? expiryTime)
    {
        RefreshToken = token;
        RefreshTokenExpiryTime = expiryTime;
        UpdateTimestamp();
    }

    public void UpdateSecurityStamp()
    {
        SecurityStamp = Guid.NewGuid().ToString();
        RefreshToken = null;
        RefreshTokenExpiryTime = null;
        UpdateTimestamp();
    }

    // ============================================================================
    // QUERY METHODS
    // ============================================================================

    public bool IsAdmin() => Role.Equals("Admin", StringComparison.OrdinalIgnoreCase);
    public bool IsAuditor() => Role.Equals("Auditor", StringComparison.OrdinalIgnoreCase);
    public bool CanLogin() => IsActive && !IsDeleted;

    // ============================================================================
    // PRIVATE VALIDATION METHODS
    // ============================================================================

    private static string ValidateAndNormalizeEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            throw new ArgumentException("Email cannot be empty", nameof(email));

        var normalized = email.Trim().ToLowerInvariant();
        var emailRegex = new Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.Compiled);
        if (!emailRegex.IsMatch(normalized))
            throw new ArgumentException("Invalid email format", nameof(email));

        if (normalized.Length > 254)
            throw new ArgumentException("Email too long (max 254 characters)", nameof(email));

        return normalized;
    }

    private static string ValidateUsername(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            throw new ArgumentException("Username cannot be empty", nameof(username));

        var trimmed = username.Trim();
        if (trimmed.Length < 3)
            throw new ArgumentException("Username too short (min 3 characters)", nameof(username));
        if (trimmed.Length > 50)
            throw new ArgumentException("Username too long (max 50 characters)", nameof(username));

        var usernameRegex = new Regex(@"^[a-zA-Z0-9_]+$", RegexOptions.Compiled);
        if (!usernameRegex.IsMatch(trimmed))
            throw new ArgumentException("Username can only contain letters, numbers, and underscores", nameof(username));

        return trimmed;
    }

    private static string ValidatePasswordHash(string passwordHash)
    {
        if (string.IsNullOrWhiteSpace(passwordHash))
            throw new ArgumentException("Password hash cannot be empty", nameof(passwordHash));

        if (passwordHash.Length < 20)
            throw new ArgumentException("Invalid password hash - must be pre-hashed with BCrypt/Argon2", nameof(passwordHash));

        return passwordHash;
    }

    private static string ValidateRole(string role)
    {
        if (string.IsNullOrWhiteSpace(role))
            throw new ArgumentException("Role cannot be empty", nameof(role));

        var validRoles = new[] { "Admin", "User", "Auditor" };
        var matched = validRoles.FirstOrDefault(r => r.Equals(role, StringComparison.OrdinalIgnoreCase));

        if (matched == null)
            throw new ArgumentException($"Invalid role. Valid roles: {string.Join(", ", validRoles)}", nameof(role));

        return matched;
    }
}