using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace VaultGuard.WebAPI.Controllers;

/// <summary>
/// Standard API response wrapper for successful operations with data.
/// </summary>
/// <typeparam name="T">Type of data being returned</typeparam>
public class ApiResponse<T>
{
    /// <summary>
    /// Indicates if the operation was successful.
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Human-readable message describing the result.
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Actual data payload (null if error).
    /// </summary>
    public T? Data { get; set; }
}

/// <summary>
/// Standard API error response wrapper.
/// </summary>
public class ApiErrorResponse
{
    /// <summary>
    /// Always false for error responses.
    /// </summary>
    public bool Success { get; set; } = false;

    /// <summary>
    /// Human-readable error message.
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Optional validation errors (for 400 Bad Request).
    /// </summary>
    public Dictionary<string, string[]>? Errors { get; set; }
}