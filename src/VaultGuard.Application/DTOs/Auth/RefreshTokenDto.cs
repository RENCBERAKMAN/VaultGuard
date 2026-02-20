using System.ComponentModel.DataAnnotations;

namespace VaultGuard.Application.DTOs.Auth;

public record RefreshTokenDto
{
    [Required]
    public string RefreshToken { get; init; } = string.Empty;
}